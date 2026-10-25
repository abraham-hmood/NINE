#include "AotCompiler.h"
#include "AotImage.h"
#include "../translator/X86Decoder.h"
#include "../translator/Arm64Emitter.h"
#include "../runtime/CtxLayout.h"
#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <sstream>

namespace nexus {
namespace aot {

using namespace ctx_off;

namespace {

inline uint64_t maskOf(int bits) {
    if (bits >= 64) return ~0ull;
    if (bits <= 0) return 0xFFFFFFFFull;
    return (1ull << bits) - 1ull;
}

// Register convention inside a compiled block:
//   x23 = GuestContext* (callee saved, never clobbered by helpers)
//   x9..x15 scratch
// Guest GPRs live in GuestContext memory; guest RIP/RFLAGS are memory fields.
constexpr int R_CTX = 23;
constexpr int R_A = 9;
constexpr int R_EA = 10;
constexpr int R_B = 11;
constexpr int R_T0 = 12;
constexpr int R_T1 = 13;
constexpr int R_T2 = 14;
constexpr int R_T3 = 15;
constexpr int R_T4 = 16;   // helper address only — never holds a guest value
// Every x9..x16 is caller-saved, so a helper call destroys all of R_A..R_T4.
// Value-producing helpers therefore return their result in x0, and any value
// that has to outlive a memory access is parked on the stack around the call
// (see park/releasePark) — otherwise `add rax, [rbx]` would lose the rax half
// when the load helper clobbered x9.

Sym loadSym(int bits) {
    switch (bits) {
        case 8: return Sym::Load8;
        case 16: return Sym::Load16;
        case 32: return Sym::Load32;
        default: return Sym::Load64;
    }
}

Sym storeSym(int bits) {
    switch (bits) {
        case 8: return Sym::Store8;
        case 16: return Sym::Store16;
        case 32: return Sym::Store32;
        default: return Sym::Store64;
    }
}

int exitKindOf(BlockExitReason r) { return static_cast<int>(r); }

} // namespace

class Compiler {
public:
    AotResult run(const uint8_t* code, size_t len, uint64_t base, uint64_t entry);

private:
    // ---- discovery ----
    bool discover();
    bool emitBlock(uint64_t start);
    bool emitInsn(const Insn& in);
    void noteUnsupported(const Insn& in);

    // ---- primitives ----
    void movImm(int rd, uint64_t v);
    void maskReg(int r, int bits, int tmp);
    void signExtend(int r, int from_bits);
    void loadGuest(int guest, int rd);
    void storeGuest(int guest, int rs);
    void loadOperand(const Operand& op, int rd, int bits, const Insn& in);
    void storeOperand(const Operand& op, int rs, int bits, const Insn& in);
    void park();     // push the R_A/R_B pair across a helper call
    void releasePark();
    void eaInto(const Operand& op, const Insn& in, int rd);
    void helperAddr(int rd, Sym sym);
    void callHelper(Sym sym);   // x0 = ctx already set by caller where needed
    void emitFlags(int kind, int res, int a, int b, int bits, int keep);
    void emitCond(int cc);      // 0/1 into x9
    void emitExit(uint64_t rip, BlockExitReason reason);
    void emitExitReg(int ripreg, BlockExitReason reason);
    void emitPushValue(int value_reg);
    void emitPopInto(int dst_reg, int bits);

    struct Stub { int patch; uint64_t target; };

    const uint8_t* code_ = nullptr;
    size_t len_ = 0;
    uint64_t base_ = 0;
    std::map<uint64_t, Insn> insns_;
    std::set<uint64_t> starts_;
    std::vector<uint8_t> image_;
    std::vector<aot::Block> blocks_;
    std::vector<uint32_t> words_;
    std::vector<aot::Reloc> relocs_;
    std::vector<std::string> unsupported_;
    Arm64Emitter e_;
    std::vector<Stub> stubs_;
    // Unconditional transfer (direct JMP/CALL): the block's primary exit goes
    // to the target instead of the fallthrough.
    bool direct_exit_ = false;
    uint64_t direct_target_ = 0;
};

void Compiler::noteUnsupported(const Insn& in) {
    std::string name = in.mnemonic.empty() ? "unknown" : in.mnemonic;
    std::ostringstream oss;
    oss << name << " (0x" << std::hex << in.address << ")";
    // Deduplicate by mnemonic so a hot unsupported op does not flood the list.
    for (const auto& s : unsupported_)
        if (s.rfind(name + " ", 0) == 0) return;
    unsupported_.push_back(oss.str());
    if (unsupported_.size() > 64) unsupported_.resize(64);
}

void Compiler::movImm(int rd, uint64_t v) {
    if (v == 0) e_.movz(rd, 0, 0, true);
    else e_.mov_imm64(rd, v);
}

void Compiler::maskReg(int r, int bits, int tmp) {
    if (bits >= 64 || bits <= 0) return;
    e_.mov_imm32(tmp, static_cast<uint32_t>(maskOf(bits)));
    e_.and_reg(r, r, tmp, true);
}

void Compiler::signExtend(int r, int from_bits) {
    if (from_bits >= 64 || from_bits <= 0) return;
    e_.lsl_imm(r, r, static_cast<unsigned>(64 - from_bits));
    e_.asr_imm(r, r, static_cast<unsigned>(64 - from_bits));
}

void Compiler::loadGuest(int guest, int rd) {
    e_.ldr_x(rd, R_CTX, gpr(guest));
}

void Compiler::storeGuest(int guest, int rs) {
    e_.str_x(rs, R_CTX, gpr(guest));
}

void Compiler::helperAddr(int rd, Sym sym) {
    aot::Reloc r{};
    r.code_off = static_cast<uint32_t>(e_.size() * 4);
    r.kind = static_cast<uint32_t>(aot::RelocKind::Helper);
    r.target = static_cast<uint64_t>(sym);
    relocs_.push_back(r);
    e_.movz(rd, 0, 0, true);
    e_.movk(rd, 0, 1, true);
    e_.movk(rd, 0, 2, true);
    e_.movk(rd, 0, 3, true);
}

void Compiler::callHelper(Sym sym) {
    e_.mov_reg(0, R_CTX);
    helperAddr(R_T4, sym);
    e_.blr(R_T4);
}

// A memory operand is serviced by a C helper, and a call clobbers x0..x18 —
// which includes every register a guest value can be parked in. Anything the
// instruction already computed (the first half of `add rax, [rbx]`, the
// condition flag for CMOVcc, the pair in xchg) therefore goes to the stack
// around the call. 16 bytes keeps SP 16-byte aligned for the callee.
void Compiler::park() {
    e_.stp_pre(R_A, R_B, -2);
}

void Compiler::releasePark() {
    e_.ldp_post(R_A, R_B, 2);
}

void Compiler::eaInto(const Operand& op, const Insn& in, int rd) {
    const MemOp& m = op.mem;
    if (m.rip_relative) {
        movImm(rd, in.address + in.length + static_cast<uint64_t>(m.disp));
    } else {
        if (m.base >= 0) loadGuest(m.base, rd);
        else movImm(rd, 0);
        if (m.disp) {
            if (m.disp > 0 && m.disp < 4096) e_.add_imm(rd, rd, static_cast<unsigned>(m.disp), true);
            else if (m.disp < 0 && -m.disp < 4096) e_.sub_imm(rd, rd, static_cast<unsigned>(-m.disp), true);
            else { movImm(R_T3, static_cast<uint64_t>(m.disp)); e_.add_reg(rd, rd, R_T3, true); }
        }
    }
    if (m.index >= 0) {
        loadGuest(m.index, R_T0);
        if (m.scale == 2) e_.lsl_imm(R_T0, R_T0, 1);
        else if (m.scale == 4) e_.lsl_imm(R_T0, R_T0, 2);
        else if (m.scale == 8) e_.lsl_imm(R_T0, R_T0, 3);
        e_.add_reg(rd, rd, R_T0, true);
    }
    if (m.seg == 1 || m.seg == 2) {
        e_.ldr_x(R_T1, R_CTX, m.seg == 1 ? fs_base() : gs_base());
        e_.add_reg(rd, rd, R_T1, true);
    }
}

void Compiler::loadOperand(const Operand& op, int rd, int bits, const Insn& in) {
    switch (op.kind) {
        case OperandKind::REG:
            loadGuest(op.reg, rd);
            maskReg(rd, bits, R_T2);
            return;
        case OperandKind::IMM:
            movImm(rd, static_cast<uint64_t>(op.imm) & maskOf(bits));
            return;
        case OperandKind::MEM: {
            park();
            eaInto(op, in, R_EA);
            e_.mov_reg(1, R_EA);
            callHelper(loadSym(bits));
            releasePark();
            e_.mov_reg(rd, 0);   // the helper's result survives the pops
            return;
        }
        default:
            movImm(rd, 0);
            return;
    }
}

void Compiler::storeOperand(const Operand& op, int rs, int bits, const Insn& in) {
    switch (op.kind) {
        case OperandKind::REG: {
            if (bits >= 32) {
                storeGuest(op.reg, rs);
            } else {
                // 8/16-bit writes replace only the low bits of the GPR.
                maskReg(rs, bits, R_T2);
                loadGuest(op.reg, R_T0);
                movImm(R_T1, ~maskOf(bits));
                e_.and_reg(R_T0, R_T0, R_T1, true);
                e_.orr_reg(R_T0, R_T0, rs, true);
                storeGuest(op.reg, R_T0);
            }
            return;
        }
        case OperandKind::MEM: {
            park();
            maskReg(rs, bits, R_T2);
            eaInto(op, in, R_EA);
            e_.mov_reg(1, R_EA);
            e_.mov_reg(2, rs);
            callHelper(storeSym(bits));
            releasePark();
            return;
        }
        default:
            return;
    }
}

void Compiler::emitFlags(int kind, int res, int a, int b, int bits, int keep) {
    e_.mov_reg(0, R_CTX);
    e_.mov_imm32(1, static_cast<uint32_t>(kind));
    e_.mov_reg(2, res);
    e_.mov_reg(3, a);
    e_.mov_reg(4, b);
    e_.mov_imm32(5, static_cast<uint32_t>(bits));
    e_.mov_imm32(6, static_cast<uint32_t>(keep));
    helperAddr(R_T4, Sym::Flags);
    e_.blr(R_T4);   // returns the masked result in x0
}

void Compiler::emitCond(int cc) {
    auto bit = [&](int b, int dst) {
        e_.ldr_x(dst, R_CTX, rflags());
        if (b) e_.lsr_imm(dst, dst, static_cast<unsigned>(b));
        e_.mov_imm32(R_T2, 1);
        e_.and_reg(dst, dst, R_T2, true);
    };
    auto invert = [&](int r) {
        e_.mov_imm32(R_T2, 1);
        e_.eor_reg(r, r, R_T2, true);
    };
    switch (cc & 0xF) {
        case 0x0: bit(11, R_A); break;                       // O
        case 0x1: bit(11, R_A); invert(R_A); break;           // NO
        case 0x2: bit(0, R_A); break;                         // B/C
        case 0x3: bit(0, R_A); invert(R_A); break;            // AE/NC
        case 0x4: bit(6, R_A); break;                         // E/Z
        case 0x5: bit(6, R_A); invert(R_A); break;            // NE/NZ
        case 0x6: bit(0, R_A); bit(6, R_T1); e_.orr_reg(R_A, R_A, R_T1, true); break;      // BE
        case 0x7: bit(0, R_A); bit(6, R_T1); e_.orr_reg(R_A, R_A, R_T1, true); invert(R_A); break; // A
        case 0x8: bit(7, R_A); break;                         // S
        case 0x9: bit(7, R_A); invert(R_A); break;            // NS
        case 0xA: bit(2, R_A); break;                         // P
        case 0xB: bit(2, R_A); invert(R_A); break;            // NP
        case 0xC: bit(7, R_A); bit(11, R_T1); e_.eor_reg(R_A, R_A, R_T1, true); break;     // L
        case 0xD: bit(7, R_A); bit(11, R_T1); e_.eor_reg(R_A, R_A, R_T1, true); invert(R_A); break; // GE
        case 0xE: bit(7, R_A); bit(11, R_T1); e_.eor_reg(R_A, R_A, R_T1, true);
                  bit(6, R_T3); e_.orr_reg(R_A, R_A, R_T3, true); break;                   // LE
        default:  bit(7, R_A); bit(11, R_T1); e_.eor_reg(R_A, R_A, R_T1, true);
                  bit(6, R_T3); e_.orr_reg(R_A, R_A, R_T3, true); invert(R_A); break;      // G
    }
}

void Compiler::emitExit(uint64_t rip, BlockExitReason reason) {
    movImm(R_T3, rip);
    e_.str_x(R_T3, R_CTX, ctx_off::rip());
    e_.mov_imm32(R_T2, static_cast<uint32_t>(exitKindOf(reason)));
    e_.str_w(R_T2, R_CTX, exit_reason());
    e_.ldp_post(23, 24, 2);
    e_.ldp_post(29, 30, 2);
    e_.ret();
}

void Compiler::emitExitReg(int ripreg, BlockExitReason reason) {
    e_.str_x(ripreg, R_CTX, ctx_off::rip());
    e_.mov_imm32(R_T2, static_cast<uint32_t>(exitKindOf(reason)));
    e_.str_w(R_T2, R_CTX, exit_reason());
    e_.ldp_post(23, 24, 2);
    e_.ldp_post(29, 30, 2);
    e_.ret();
}

void Compiler::emitPushValue(int value_reg) {
    loadGuest(4, R_T0);                       // rsp
    e_.sub_imm(R_T0, R_T0, 8, true);
    storeGuest(4, R_T0);
    e_.mov_reg(1, R_T0);
    e_.mov_reg(2, value_reg);
    callHelper(Sym::Store64);
}

void Compiler::emitPopInto(int dst_reg, int bits) {
    loadGuest(4, R_T0);
    e_.mov_reg(1, R_T0);
    callHelper(Sym::Load64);
    loadGuest(4, R_T0);
    e_.add_imm(R_T0, R_T0, 8, true);
    storeGuest(4, R_T0);
    maskReg(0, bits, R_T2);
    e_.mov_reg(dst_reg, 0);
}

bool Compiler::emitInsn(const Insn& in) {
    const int bits = in.dst.size ? in.dst.size
                                 : (in.o16 ? 16 : (in.rex_w ? 64 : 32));
    switch (in.op) {
        case X86Op::NOP:
        case X86Op::ENDBR:   // CET landing pad: no architectural effect
            return true;

        case X86Op::MOV: {
            loadOperand(in.src, R_A, bits, in);
            storeOperand(in.dst, R_A, bits, in);
            return true;
        }

        case X86Op::XCHG: {
            // xchg has no flag effect, and both halves are written at the
            // operand's own width (so 32-bit forms zero-extend the GPR).
            loadOperand(in.dst, R_A, bits, in);   // r/m value
            loadOperand(in.src, R_B, bits, in);   // register value
            storeOperand(in.dst, R_B, bits, in);  // r/m <- reg
            storeOperand(in.src, R_A, bits, in);  // reg <- r/m
            return true;
        }

        case X86Op::MOVZX: {
            const int sb = in.src.size ? in.src.size : 8;
            loadOperand(in.src, R_A, sb, in);
            storeOperand(in.dst, R_A, bits, in);
            return true;
        }

        case X86Op::MOVSX: {
            const int sb = in.src.size ? in.src.size : 8;
            loadOperand(in.src, R_A, sb, in);
            signExtend(R_A, sb);
            storeOperand(in.dst, R_A, bits, in);
            return true;
        }

        case X86Op::LEA: {
            if (in.src.kind != OperandKind::MEM || in.dst.kind != OperandKind::REG) return false;
            eaInto(in.src, in, R_A);
            storeOperand(in.dst, R_A, bits, in);
            return true;
        }

        case X86Op::PUSH: {
            const Operand& v = in.dst.kind != OperandKind::NONE ? in.dst : in.src;
            loadOperand(v, R_A, 64, in);
            emitPushValue(R_A);
            return true;
        }

        case X86Op::POP: {
            emitPopInto(R_A, 64);
            storeOperand(in.dst, R_A, 64, in);
            return true;
        }

        case X86Op::LEAVE: {
            loadGuest(5, R_A);        // rsp = rbp
            storeGuest(4, R_A);
            emitPopInto(R_A, 64);     // rbp = [rsp]; rsp += 8
            storeGuest(5, R_A);
            return true;
        }

        case X86Op::ADD: case X86Op::SUB: case X86Op::AND:
        case X86Op::OR: case X86Op::XOR: case X86Op::CMP: case X86Op::TEST: {
            loadOperand(in.dst, R_A, bits, in);
            loadOperand(in.src, R_B, bits, in);
            int kind = 0;
            switch (in.op) {
                case X86Op::ADD:  e_.add_reg(R_A, R_A, R_B, true); kind = 0; break;
                case X86Op::CMP:
                case X86Op::SUB:  e_.sub_reg(R_A, R_A, R_B, true); kind = 1; break;
                case X86Op::AND:
                case X86Op::TEST: e_.and_reg(R_A, R_A, R_B, true); kind = 2; break;
                case X86Op::OR:   e_.orr_reg(R_A, R_A, R_B, true); kind = 2; break;
                default:          e_.eor_reg(R_A, R_A, R_B, true); kind = 2; break;
            }
            maskReg(R_A, bits, R_T2);
            emitFlags(kind, R_A, R_A, R_B, bits, 0);
            if (in.op != X86Op::CMP && in.op != X86Op::TEST)
                storeOperand(in.dst, 0, bits, in);   // result returned in x0
            return true;
        }

        case X86Op::INC:
        case X86Op::DEC: {
            loadOperand(in.dst, R_A, bits, in);
            movImm(R_B, 1);
            if (in.op == X86Op::INC) e_.add_reg(R_A, R_A, R_B, true);
            else e_.sub_reg(R_A, R_A, R_B, true);
            maskReg(R_A, bits, R_T2);
            emitFlags(3, R_A, R_A, R_B, bits, 1);
            storeOperand(in.dst, 0, bits, in);
            return true;
        }

        case X86Op::NEG: {
            loadOperand(in.dst, R_B, bits, in);
            movImm(R_A, 0);
            e_.sub_reg(R_A, R_A, R_B, true);
            maskReg(R_A, bits, R_T2);
            emitFlags(1, R_A, R_A, R_B, bits, 0);
            storeOperand(in.dst, 0, bits, in);
            return true;
        }

        case X86Op::NOT: {
            loadOperand(in.dst, R_A, bits, in);
            e_.mvn_reg(R_A, R_A, true);
            maskReg(R_A, bits, R_T2);
            storeOperand(in.dst, R_A, bits, in);
            return true;
        }

        case X86Op::SHL: case X86Op::SHR: case X86Op::SAR:
        case X86Op::ROL: case X86Op::ROR: {
            int kind = 0;
            switch (in.op) {
                case X86Op::SHL: kind = 0; break;
                case X86Op::SHR: kind = 1; break;
                case X86Op::SAR: kind = 2; break;
                case X86Op::ROL: kind = 3; break;
                default:         kind = 4; break;
            }
            loadOperand(in.dst, R_A, bits, in);   // value
            e_.mov_reg(R_B, R_A);                  // original, for the flag helper
            if (in.src.kind == OperandKind::IMM)
                movImm(R_T0, static_cast<uint64_t>(in.src.imm) & (bits == 64 ? 63u : 31u));
            else {
                loadOperand(in.src, R_T0, bits, in);
                movImm(R_T1, bits == 64 ? 63 : 31);
                e_.and_reg(R_T0, R_T0, R_T1, true);
            }
            switch (in.op) {
                case X86Op::SHL: e_.lsl_reg(R_A, R_A, R_T0); break;
                case X86Op::SHR: e_.lsr_reg(R_A, R_A, R_T0); break;
                case X86Op::SAR: e_.asr_reg(R_A, R_A, R_T0); break;
                case X86Op::ROR: e_.ror_reg(R_A, R_A, R_T0, true); break;
                default:
                    // ROL by c == ROR by (bits - c); count 0 stays 0
                    movImm(R_T1, static_cast<uint64_t>(bits));
                    e_.sub_reg(R_T1, R_T1, R_T0, true);
                    e_.ror_reg(R_A, R_A, R_T1, true);
                    break;
            }
            maskReg(R_A, bits, R_T2);
            // Flags first: the helper call destroys every scratch register the
            // value could be parked in, and it hands the result back in x0.
            e_.mov_reg(0, R_CTX);
            e_.mov_reg(1, R_A);    // res
            e_.mov_reg(2, R_B);    // source value
            e_.mov_reg(3, R_T0);   // count
            e_.mov_imm32(4, static_cast<uint32_t>(bits));
            e_.mov_imm32(5, static_cast<uint32_t>(kind));
            helperAddr(R_T4, Sym::ShiftFlags);
            e_.blr(R_T4);
            storeOperand(in.dst, 0, bits, in);
            return true;
        }

        case X86Op::CMOV: {
            emitCond(in.cc);                    // x9 = 0/1
            loadOperand(in.src, R_B, bits, in);
            loadOperand(in.dst, R_T0, bits, in);
            e_.cmp_imm(R_A, 0, true);
            e_.csel(R_B, R_B, R_T0, NE, true);  // cond ? src : dst
            storeOperand(in.dst, R_B, bits, in);
            return true;
        }

        case X86Op::SETCC: {
            emitCond(in.cc);
            storeOperand(in.dst, R_A, 8, in);
            return true;
        }

        case X86Op::BSWAP: {
            loadOperand(in.dst, R_A, bits, in);
            if (bits == 64) e_.rev_x(R_A, R_A);
            else if (bits == 16) e_.rev16_w(R_A, R_A);
            else e_.rev_w(R_A, R_A);
            maskReg(R_A, bits, R_T2);
            storeOperand(in.dst, R_A, bits, in);
            return true;
        }

        case X86Op::CBW: {
            loadGuest(0, R_A);
            e_.lsl_imm(R_A, R_A, 56);
            e_.asr_imm(R_A, R_A, 56);
            movImm(R_T0, 0xFFFFull);
            e_.and_reg(R_A, R_A, R_T0, true);
            loadGuest(0, R_T1);
            movImm(R_T2, ~0xFFFFull);
            e_.and_reg(R_T1, R_T1, R_T2, true);
            e_.orr_reg(R_A, R_A, R_T1, true);
            storeGuest(0, R_A);
            return true;
        }

        case X86Op::CWDE: {
            loadGuest(0, R_A);
            e_.lsl_imm(R_A, R_A, 48);
            e_.asr_imm(R_A, R_A, 48);
            maskReg(R_A, 32, R_T2);
            storeGuest(0, R_A);
            return true;
        }

        case X86Op::CDQE: {
            loadGuest(0, R_A);
            signExtend(R_A, 32);
            storeGuest(0, R_A);
            return true;
        }

        case X86Op::CDQ: {
            // 0x99: CWD (16) / CDQ (32) / CQO (REX.W) — DX/EDX/RDX = sign of A
            loadGuest(0, R_A);
            if (bits == 64) {
                e_.asr_imm(R_A, R_A, 63);
            } else if (bits == 16) {
                signExtend(R_A, 16);
                maskReg(R_A, 16, R_T2);
            } else {
                signExtend(R_A, 32);
                maskReg(R_A, 32, R_T2);
            }
            storeGuest(2, R_A);
            return true;
        }

        case X86Op::CLC: case X86Op::STC:
        case X86Op::CLI: case X86Op::STI:
        case X86Op::CLD: case X86Op::STD:
        case X86Op::CLAC: case X86Op::STAC: {
            int bit = 0;
            bool set = true;
            switch (in.op) {
                case X86Op::CLC: bit = 0; set = false; break;
                case X86Op::STC: bit = 0; break;
                case X86Op::CLI: bit = 9; set = false; break;
                case X86Op::STI: bit = 9; break;
                case X86Op::CLD: bit = 10; set = false; break;
                case X86Op::STD: bit = 10; break;
                case X86Op::CLAC: bit = 18; set = false; break;
                default: bit = 18; break;
            }
            e_.ldr_x(R_A, R_CTX, rflags());
            movImm(R_T0, 1ull << bit);
            if (set) e_.orr_reg(R_A, R_A, R_T0, true);
            else {
                e_.mvn_reg(R_T0, R_T0, true);
                e_.and_reg(R_A, R_A, R_T0, true);
            }
            e_.str_x(R_A, R_CTX, rflags());
            return true;
        }

        case X86Op::JMP: {
            const Operand& t = in.src.kind != OperandKind::NONE ? in.src : in.dst;
            if (t.kind == OperandKind::REL || t.kind == OperandKind::IMM) {
                direct_exit_ = true;
                direct_target_ = static_cast<uint64_t>(t.imm);
                return true;
            }
            loadOperand(t, R_A, 64, in);
            e_.str_x(R_A, R_CTX, ctx_off::rip());
            e_.mov_imm32(R_T2, static_cast<uint32_t>(BlockExitReason::INDIRECT));
            e_.str_w(R_T2, R_CTX, exit_reason());
            e_.ldp_post(23, 24, 2);
            e_.ldp_post(29, 30, 2);
            e_.ret();
            return true;
        }

        case X86Op::CALL: {
            uint64_t ret = in.address + in.length;
            movImm(R_A, ret);
            emitPushValue(R_A);
            const Operand& t = in.src.kind != OperandKind::NONE ? in.src : in.dst;
            if (t.kind == OperandKind::REL || t.kind == OperandKind::IMM) {
                direct_exit_ = true;
                direct_target_ = static_cast<uint64_t>(t.imm);
                return true;
            }
            loadOperand(t, R_A, 64, in);
            e_.str_x(R_A, R_CTX, ctx_off::rip());
            e_.mov_imm32(R_T2, static_cast<uint32_t>(BlockExitReason::INDIRECT));
            e_.str_w(R_T2, R_CTX, exit_reason());
            e_.ldp_post(23, 24, 2);
            e_.ldp_post(29, 30, 2);
            e_.ret();
            return true;
        }

        case X86Op::RET: {
            emitPopInto(R_A, 64);
            emitExitReg(R_A, BlockExitReason::CONTINUE);
            return true;
        }

        case X86Op::SYSCALL:
            return true;  // terminator handled by emitBlock

        case X86Op::INT3:
        case X86Op::UD2:
            return true;  // terminator handled by emitBlock

        case X86Op::JE: case X86Op::JNE: case X86Op::JL: case X86Op::JLE:
        case X86Op::JG: case X86Op::JGE: case X86Op::JB: case X86Op::JBE:
        case X86Op::JA: case X86Op::JAE: case X86Op::JS: case X86Op::JNS:
        case X86Op::JO: case X86Op::JNO: {
            int cc = 4;
            switch (in.op) {
                case X86Op::JO: cc = 0; break;
                case X86Op::JNO: cc = 1; break;
                case X86Op::JB: cc = 2; break;
                case X86Op::JAE: cc = 3; break;
                case X86Op::JE: cc = 4; break;
                case X86Op::JNE: cc = 5; break;
                case X86Op::JBE: cc = 6; break;
                case X86Op::JA: cc = 7; break;
                case X86Op::JS: cc = 8; break;
                case X86Op::JNS: cc = 9; break;
                case X86Op::JL: cc = 12; break;
                case X86Op::JGE: cc = 13; break;
                case X86Op::JLE: cc = 14; break;
                default: cc = 15; break;
            }
            const Operand& t = in.src.kind != OperandKind::NONE ? in.src : in.dst;
            if (t.kind != OperandKind::REL && t.kind != OperandKind::IMM) return false;
            emitCond(cc);
            e_.cbnz(R_A, 0);
            stubs_.push_back(Stub{ static_cast<int>(e_.size()) - 1,
                                   static_cast<uint64_t>(t.imm) });
            return true;
        }

        default:
            noteUnsupported(in);
            return false;
    }
}

bool Compiler::emitBlock(uint64_t start) {
    e_.clear();
    stubs_.clear();
    direct_exit_ = false;
    direct_target_ = 0;
    const size_t block_base_words = words_.size();
    const size_t reloc_base = relocs_.size();

    e_.stp_pre(29, 30, -2);   // frame record
    e_.stp_pre(23, 24, -2);   // x23 = GuestContext*, callee-saved
    e_.mov_reg(R_CTX, 0);

    uint64_t pc = start;
    uint64_t next = start;
    uint64_t term_pc = start;
    BlockExitReason exit_reason_out = BlockExitReason::CONTINUE;

    while (pc < base_ + len_) {
        auto it = insns_.find(pc);
        if (it == insns_.end()) break;
        const Insn& in = it->second;
        if (pc != start && starts_.count(pc)) break;   // next block begins here

        if (!emitInsn(in)) {
            stubs_.clear();
            return false;
        }
        next = pc + in.length;
        term_pc = pc;

        if (in.op == X86Op::JMP || in.op == X86Op::RET || in.op == X86Op::SYSCALL ||
            in.op == X86Op::INT3 || in.op == X86Op::UD2 || in.op == X86Op::CALL) {
            if (in.op == X86Op::SYSCALL) exit_reason_out = BlockExitReason::SYSCALL;
            else if (in.op == X86Op::INT3 || in.op == X86Op::UD2) exit_reason_out = BlockExitReason::EXCEPTION;
            pc = next;
            break;
        }
        pc = next;
    }

    // ---- fallthrough / terminal exit ----
    if (exit_reason_out == BlockExitReason::SYSCALL)
        emitExit(next, BlockExitReason::SYSCALL);
    else if (exit_reason_out == BlockExitReason::EXCEPTION)
        emitExit(term_pc, BlockExitReason::EXCEPTION);
    else if (direct_exit_)
        emitExit(direct_target_, BlockExitReason::CONTINUE);
    else
        emitExit(next, BlockExitReason::CONTINUE);

    // ---- taken stubs for Jcc / CALL / JMP targets ----
    if (!stubs_.empty()) {
        const int skip_at = static_cast<int>(e_.size());
        e_.b(0);
        std::map<uint64_t, int> emitted;
        for (const Stub& s : stubs_) {
            auto found = emitted.find(s.target);
            int idx;
            if (found == emitted.end()) {
                idx = static_cast<int>(e_.size());
                emitExit(s.target, BlockExitReason::CONTINUE);
                emitted[s.target] = idx;
            } else {
                idx = found->second;
            }
            uint32_t& w = e_.at(static_cast<size_t>(s.patch));
            const uint32_t off = static_cast<uint32_t>(idx - s.patch) & 0x7FFFFu;
            w = (w & ~(0x7FFFFu << 5)) | (off << 5);
        }
        uint32_t& skip = e_.at(static_cast<size_t>(skip_at));
        skip = 0x14000000u | (static_cast<uint32_t>(e_.size() - skip_at) & 0x03FFFFFFu);
    }

    // ---- record the block ----
    aot::Block b{};
    b.guest_pc = start;
    b.guest_end = next;
    b.code_off = static_cast<uint32_t>(block_base_words * 4);
    b.code_len = static_cast<uint32_t>(e_.size() * 4);
    b.exit_kind = static_cast<uint32_t>(exit_reason_out == BlockExitReason::SYSCALL
                                        ? BlockExitReason::SYSCALL : BlockExitReason::CONTINUE);
    blocks_.push_back(b);

    const auto& w = e_.code();
    words_.insert(words_.end(), w.begin(), w.end());
    // Block-relative reloc offsets -> image offsets.
    const uint32_t shift = static_cast<uint32_t>(block_base_words * 4);
    for (size_t i = reloc_base; i < relocs_.size(); ++i) relocs_[i].code_off += shift;
    return true;
}

bool Compiler::discover() {
    uint64_t pc = base_;
    starts_.insert(base_);
    while (pc < base_ + len_) {
        const size_t avail = static_cast<size_t>(base_ + len_ - pc);
        auto in = X86Decoder::decode(code_ + (pc - base_), avail, pc);
        if (!in || in->length == 0) {
            unsupported_.push_back("decode failure at 0x" + std::to_string(pc));
            return false;
        }
        insns_[pc] = *in;
        uint64_t tgt = 0;
        bool has_target = false;
        if (in->op == X86Op::JMP || in->op == X86Op::CALL ||
            (in->op >= X86Op::JE && in->op <= X86Op::JNO)) {
            const Operand& t = in->src.kind != OperandKind::NONE ? in->src : in->dst;
            if (t.kind == OperandKind::REL || t.kind == OperandKind::IMM) {
                tgt = static_cast<uint64_t>(t.imm);
                has_target = true;
            }
        }
        const uint64_t next = pc + in->length;
        if (has_target && tgt >= base_ && tgt < base_ + len_) starts_.insert(tgt);
        if (in->op == X86Op::JMP || in->op == X86Op::CALL || in->op == X86Op::RET ||
            in->op == X86Op::SYSCALL || in->op == X86Op::INT3 || in->op == X86Op::UD2)
            starts_.insert(next);
        pc = next;
    }
    return true;
}

AotResult Compiler::run(const uint8_t* code, size_t len, uint64_t base, uint64_t entry) {
    AotResult res;
    code_ = code;
    len_ = len;
    base_ = base;
    if (!code || !len) {
        res.error = "empty code range";
        return res;
    }
    if (!discover()) {
        res.error = "decode failure";
        res.unsupported = unsupported_;
        return res;
    }

    for (uint64_t start : starts_) {
        if (!insns_.count(start)) continue;
        if (!emitBlock(start)) {
            res.error = "unsupported instruction";
            res.unsupported = unsupported_;
            return res;
        }
    }
    if (blocks_.empty()) {
        res.error = "no blocks emitted";
        res.unsupported = unsupported_;
        return res;
    }

    res.image = aot::serialize(blocks_, words_, relocs_, entry);
    res.block_count = static_cast<uint32_t>(blocks_.size());
    res.code_bytes = static_cast<uint32_t>(words_.size() * 4);
    res.reloc_count = static_cast<uint32_t>(relocs_.size());
    res.ok = true;
    return res;
}

AotResult compile(const uint8_t* code, size_t len, uint64_t base, uint64_t entry) {
    Compiler c;
    return c.run(code, len, base, entry);
}

const std::vector<std::string>& supportedOpcodes() {
    static const std::vector<std::string> ops = {
        "NOP", "ENDBR", "MOV", "MOVZX", "MOVSX", "LEA", "PUSH", "POP", "LEAVE",
        "ADD", "SUB", "AND", "OR", "XOR", "CMP", "TEST", "INC", "DEC",
        "NEG", "NOT", "SHL", "SHR", "SAR", "ROL", "ROR", "SETCC", "BSWAP", "XCHG",
        "CBW", "CWDE", "CDQE", "CDQ", "CLC", "STC", "CLI", "STI", "CLD",
        "STD", "CLAC", "STAC", "Jcc", "JMP", "CALL", "RET", "SYSCALL",
        "INT3", "UD2"
    };
    return ops;
}

} // namespace aot
} // namespace nexus
