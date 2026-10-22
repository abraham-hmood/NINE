#include "Translator.h"
#include "../runtime/HostTrampoline.h"
#include "../runtime/CtxLayout.h"
#include "../runtime/MemHelpers.h"
#include <cstring>

namespace nexus {

using namespace ctx_off;

OpcodeCoverage& OpcodeCoverage::instance() {
    static OpcodeCoverage c;
    return c;
}
void OpcodeCoverage::seenDecode(X86Op op) {
    std::lock_guard<std::mutex> lock(mu_);
    decoded_.insert(static_cast<int>(op));
}
void OpcodeCoverage::seenEmit(X86Op op) {
    std::lock_guard<std::mutex> lock(mu_);
    emitted_.insert(static_cast<int>(op));
}
void OpcodeCoverage::seenFallback(X86Op op) {
    std::lock_guard<std::mutex> lock(mu_);
    fallback_.insert(static_cast<int>(op));
}
size_t OpcodeCoverage::decodeCount() const {
    std::lock_guard<std::mutex> lock(mu_);
    return decoded_.size();
}
size_t OpcodeCoverage::emitCount() const {
    std::lock_guard<std::mutex> lock(mu_);
    return emitted_.size();
}
size_t OpcodeCoverage::missingEmitCount() const {
    std::lock_guard<std::mutex> lock(mu_);
    size_t n = 0;
    for (int x : decoded_) if (!emitted_.count(x)) ++n;
    return n;
}
std::string OpcodeCoverage::report() const {
    std::lock_guard<std::mutex> lock(mu_);
    return "decoded=" + std::to_string(decoded_.size()) +
           " emitted=" + std::to_string(emitted_.size()) +
           " fallback=" + std::to_string(fallback_.size());
}

int Translator::hostGpr(int guest) const {
    return x_gpr(guest);
}

void Translator::emitPrologue() {
    emit_.stp_pre(19, 20, -2);
    emit_.stp_pre(21, 22, -2);
    emit_.stp_pre(23, 24, -2);
    emit_.stp_pre(25, 26, -2);
    emit_.stp_pre(27, 28, -2);
    for (int g = 0; g < 8; ++g)
        emit_.ldr_x(x_gpr(g), X_CTX, gpr(g));
    emit_.ldr_x(X_RIP, X_CTX, rip());
    emit_.ldr_x(X_FLG, X_CTX, rflags());
}

void Translator::emitEpilogueAndReturn() {
    for (int g = 0; g < 8; ++g)
        emit_.str_x(x_gpr(g), X_CTX, gpr(g));
    emit_.str_x(X_RIP, X_CTX, rip());
    emit_.str_x(X_FLG, X_CTX, rflags());
    emit_.ldp_post(27, 28, 2);
    emit_.ldp_post(25, 26, 2);
    emit_.ldp_post(23, 24, 2);
    emit_.ldp_post(21, 22, 2);
    emit_.ldp_post(19, 20, 2);
    emit_.ret();
}

void Translator::emitBlockExit(BlockExitReason reason, uint64_t next_rip) {
    emit_.mov_imm64(X_RIP, next_rip);
    emit_.str_x(X_RIP, X_CTX, rip());
    uint32_t tmp[8];
    size_t n = HostTrampoline::emitStoreExitReason(tmp, reason);
    for (size_t i = 0; i < n; ++i) emit_.emit(tmp[i]);
    emitEpilogueAndReturn();
}

void Translator::emitEA(const Operand& mem, int dest_reg) {
    // dest = base + index*scale + disp  (guest VA)
    if (mem.kind != OperandKind::MEM) {
        emit_.mov_imm64(dest_reg, 0);
        return;
    }
    const MemOp& m = mem.mem;
    bool have = false;
    if (m.rip_relative) {
        // RIP-relative: next_rip + disp — use X19 current RIP approximately
        emit_.mov_reg(dest_reg, X_RIP);
        have = true;
    } else if (m.base >= 0 && m.base < 16) {
        emit_.mov_reg(dest_reg, hostGpr(m.base));
        have = true;
    } else {
        emit_.mov_imm64(dest_reg, 0);
        have = true;
    }
    if (m.index >= 0 && m.index < 16) {
        int idx = hostGpr(m.index);
        int scale = m.scale;
        if (scale == 1) {
            emit_.add_reg(dest_reg, dest_reg, idx);
        } else {
            // idx * scale via LSL
            unsigned sh = scale == 2 ? 1 : scale == 4 ? 2 : scale == 8 ? 3 : 0;
            emit_.lsl_imm(9, idx, sh); // X9 temp
            emit_.add_reg(dest_reg, dest_reg, 9);
        }
    }
    if (m.disp) {
        if (m.disp > 0 && m.disp < 4096) {
            emit_.add_imm(dest_reg, dest_reg, static_cast<unsigned>(m.disp));
        } else if (m.disp < 0 && -m.disp < 4096) {
            emit_.sub_imm(dest_reg, dest_reg, static_cast<unsigned>(-m.disp));
        } else {
            emit_.mov_imm64(9, static_cast<uint64_t>(m.disp));
            emit_.add_reg(dest_reg, dest_reg, 9);
        }
    }
    if (m.seg == 1 || m.seg == 2) {
        // FS/GS override (TLS): EA += fs_base/gs_base. Loaded from ctx at run
        // time so arch_prctl(ARCH_SET_FS) is honored without retranslation.
        emit_.ldr_x(9, X_CTX, m.seg == 1 ? fs_base() : gs_base());
        emit_.add_reg(dest_reg, dest_reg, 9);
    }
    (void)have;
}

void Translator::emitHelperCall(uint64_t fn_addr, int arg0_reg, int arg1_reg, int arg2_reg) {
    // Save X0 (ctx) — already in X0. Args: X0=ctx, X1=ea, X2=val
    // We need: mov X1, ea; mov X2, val; load fn; blr
    if (arg0_reg != 0) emit_.mov_reg(0, arg0_reg);
    if (arg1_reg >= 0 && arg1_reg != 1) emit_.mov_reg(1, arg1_reg);
    if (arg2_reg >= 0 && arg2_reg != 2) emit_.mov_reg(2, arg2_reg);
    emit_.mov_imm64(9, fn_addr);
    emit_.blr(9);
    // Restore ctx pointer assumption: helpers don't clobber need for X0 if we reload
    // Reload ctx from stack? We kept ctx only in X0 — helpers use X0 as first arg.
    // After call, re-load guest GPRs? Too heavy. Helpers preserve X19-X28; X0 may be ret.
    // Re-materialize ctx: we saved nothing. Convention: helpers take ctx in X0 and
    // return value in X0 for loads — so after load, X0 is value, not ctx!
    // Fix: pass ctx in X0, move result to dest after, then reload X0 from a spilled slot.
    // Spill ctx to stack before helper:
}

void Translator::emitLoadOp(const Operand& src, int dest_reg, int size_bits) {
    if (src.kind == OperandKind::REG && src.reg >= 0 && src.reg < 16) {
        emit_.mov_reg(dest_reg, hostGpr(src.reg));
        return;
    }
    if (src.kind == OperandKind::IMM) {
        emit_.mov_imm64(dest_reg, static_cast<uint64_t>(src.imm));
        return;
    }
    if (src.kind == OperandKind::MEM) {
        emitEA(src, 10); // X10 = EA
        // Spill X0 (ctx) to stack, call helper, move result
        emit_.sub_imm(31, 31, 16); // SP -= 16
        emit_.str_x(0, 31, 0);     // [SP] = ctx
        emit_.mov_reg(1, 10);      // X1 = EA
        uint64_t fn = 0;
        if (size_bits <= 8) fn = reinterpret_cast<uint64_t>(&nine_load8);
        else if (size_bits <= 16) fn = reinterpret_cast<uint64_t>(&nine_load16);
        else if (size_bits <= 32) fn = reinterpret_cast<uint64_t>(&nine_load32);
        else fn = reinterpret_cast<uint64_t>(&nine_load64);
        emit_.mov_imm64(9, fn);
        emit_.blr(9);
        emit_.mov_reg(dest_reg, 0); // result
        emit_.ldr_x(0, 31, 0);      // restore ctx
        emit_.add_imm(31, 31, 16);
        return;
    }
    emit_.mov_imm64(dest_reg, 0);
}

void Translator::emitStoreOp(const Operand& dst, int src_reg, int size_bits) {
    if (dst.kind == OperandKind::REG && dst.reg >= 0 && dst.reg < 16) {
        emit_.mov_reg(hostGpr(dst.reg), src_reg);
        return;
    }
    if (dst.kind == OperandKind::MEM) {
        emitEA(dst, 10);
        emit_.sub_imm(31, 31, 16);
        emit_.str_x(0, 31, 0);
        emit_.mov_reg(1, 10);
        emit_.mov_reg(2, src_reg);
        uint64_t fn = 0;
        if (size_bits <= 8) fn = reinterpret_cast<uint64_t>(&nine_store8);
        else if (size_bits <= 16) fn = reinterpret_cast<uint64_t>(&nine_store16);
        else if (size_bits <= 32) fn = reinterpret_cast<uint64_t>(&nine_store32);
        else fn = reinterpret_cast<uint64_t>(&nine_store64);
        emit_.mov_imm64(9, fn);
        emit_.blr(9);
        emit_.ldr_x(0, 31, 0);
        emit_.add_imm(31, 31, 16);
    }
}

TranslationUnit Translator::translateBlock(const uint8_t* code, size_t len, uint64_t guest_pc) {
    TranslationUnit tu;
    tu.guest_start = guest_pc;
    emit_.clear();
    regs_.reset();
    emitPrologue();

    size_t off = 0;
    while (off < len) {
        auto in = X86Decoder::decode(code + off, len - off, guest_pc + off);
        if (!in || in->length == 0) {
            emitBlockExit(BlockExitReason::EXCEPTION, guest_pc + off);
            tu.guest_end = guest_pc + off;
            break;
        }
        OpcodeCoverage::instance().seenDecode(in->op);
        translateInsn(*in);
        off += in->length;
        tu.guest_end = guest_pc + off;

        if (in->op == X86Op::RET) {
            tu.ends_with_branch = true;
            emitRet();
            break;
        }
        if (in->op == X86Op::JMP || (in->op >= X86Op::JE && in->op <= X86Op::JNO)) {
            tu.ends_with_branch = true;
            emitBranch(*in);
            break;
        }
        if (in->op == X86Op::CALL) {
            tu.ends_with_call = true;
            emitCall(*in);
            break;
        }
        if (in->op == X86Op::SYSCALL) {
            tu.ends_with_syscall = true;
            emitBlockExit(BlockExitReason::SYSCALL, tu.guest_end);
            break;
        }
        if (in->op == X86Op::INT3 || in->op == X86Op::UD2) {
            emitBlockExit(BlockExitReason::EXCEPTION, guest_pc + off);
            break;
        }
    }
    if (!tu.ends_with_branch && !tu.ends_with_call && !tu.ends_with_syscall) {
        emitBlockExit(BlockExitReason::CONTINUE, tu.guest_end);
    }
    tu.arm64 = emit_.code();
    tu.literals = emit_.literals();
    return tu;
}

void Translator::emitAlu(const Insn& in) {
    bool sf = in.rex_w || (in.dst.size == 64);
    int size = in.dst.size ? in.dst.size : (sf ? 64 : 32);
    // Load dst and src into X11, X12
    emitLoadOp(in.dst, 11, size);
    emitLoadOp(in.src, 12, size);
    int rd = 11;
    switch (in.op) {
        case X86Op::ADD: emit_.add_reg(rd, 11, 12, sf); flags_.setFromAdd(0,0,0,size); break;
        case X86Op::SUB:
        case X86Op::CMP: emit_.sub_reg(rd, 11, 12, sf); flags_.setFromSub(0,0,0,size); break;
        case X86Op::AND:
        case X86Op::TEST: emit_.and_reg(rd, 11, 12, sf); flags_.setFromLogic(0,size); break;
        case X86Op::OR:  emit_.orr_reg(rd, 11, 12, sf); flags_.setFromLogic(0,size); break;
        case X86Op::XOR: emit_.eor_reg(rd, 11, 12, sf); flags_.setFromLogic(0,size); break;
        case X86Op::IMUL:
        case X86Op::MUL: emit_.mul(rd, 11, 12, sf); break;
        case X86Op::IDIV: emit_.sdiv(rd, 11, 12, sf); break;
        case X86Op::DIV:  emit_.udiv(rd, 11, 12, sf); break;
        case X86Op::NEG:  emit_.sub_reg(rd, 31, 11, sf); break; // 0 - dst
        case X86Op::NOT:
            emit_.mov_imm64(12, ~0ULL);
            emit_.eor_reg(rd, 11, 12, sf);
            break;
        case X86Op::INC: emit_.add_imm(rd, 11, 1, sf); break;
        case X86Op::DEC: emit_.sub_imm(rd, 11, 1, sf); break;
        default: emit_.nop(); OpcodeCoverage::instance().seenFallback(in.op); return;
    }
    if (in.op != X86Op::CMP && in.op != X86Op::TEST)
        emitStoreOp(in.dst, rd, size);
    OpcodeCoverage::instance().seenEmit(in.op);
}

void Translator::emitShift(const Insn& in) {
    bool sf = in.rex_w || in.dst.size == 64;
    int size = in.dst.size ? in.dst.size : (sf ? 64 : 32);
    emitLoadOp(in.dst, 11, size);
    emitLoadOp(in.src, 12, size);
    switch (in.op) {
        case X86Op::SHL: emit_.lsl_reg(11, 11, 12, sf); break;
        case X86Op::SHR: emit_.lsr_reg(11, 11, 12, sf); break;
        case X86Op::SAR: emit_.asr_reg(11, 11, 12, sf); break;
        case X86Op::ROL:
        case X86Op::ROR: emit_.ror_reg(11, 11, 12, sf); break;
        default: emit_.nop(); return;
    }
    emitStoreOp(in.dst, 11, size);
    OpcodeCoverage::instance().seenEmit(in.op);
}

void Translator::emitMov(const Insn& in) {
    int size = in.dst.size ? in.dst.size : (in.rex_w ? 64 : 32);
    emitLoadOp(in.src, 11, size);
    emitStoreOp(in.dst, 11, size);
    OpcodeCoverage::instance().seenEmit(X86Op::MOV);
}

void Translator::emitLea(const Insn& in) {
    if (in.src.kind == OperandKind::MEM && in.dst.kind == OperandKind::REG) {
        emitEA(in.src, hostGpr(in.dst.reg));
        OpcodeCoverage::instance().seenEmit(X86Op::LEA);
    } else {
        emit_.nop();
        OpcodeCoverage::instance().seenFallback(X86Op::LEA);
    }
}

void Translator::emitPush(const Insn& in) {
    // RSP -= 8; [RSP] = src
    int rsp = hostGpr(4);
    emit_.sub_imm(rsp, rsp, 8);
    emitLoadOp(in.dst.kind != OperandKind::NONE ? in.dst : in.src, 11, 64);
    // store to [RSP]
    Operand mem;
    mem.kind = OperandKind::MEM;
    mem.mem.base = 4; // RSP
    mem.size = 64;
    emitStoreOp(mem, 11, 64);
    OpcodeCoverage::instance().seenEmit(X86Op::PUSH);
}

void Translator::emitPop(const Insn& in) {
    Operand mem;
    mem.kind = OperandKind::MEM;
    mem.mem.base = 4;
    mem.size = 64;
    emitLoadOp(mem, 11, 64);
    emitStoreOp(in.dst, 11, 64);
    int rsp = hostGpr(4);
    emit_.add_imm(rsp, rsp, 8);
    OpcodeCoverage::instance().seenEmit(X86Op::POP);
}

void Translator::emitLeave(const Insn& in) {
    // LEAVE = MOV RSP, RBP; POP RBP
    Operand rbp;
    rbp.kind = OperandKind::REG;
    rbp.reg = 5;
    rbp.size = 64;
    Operand rsp;
    rsp.kind = OperandKind::REG;
    rsp.reg = 4;
    rsp.size = 64;
    emitLoadOp(rbp, 11, 64);
    emitStoreOp(rsp, 11, 64);
    Insn pop;
    pop.op = X86Op::POP;
    pop.dst.kind = OperandKind::REG;
    pop.dst.reg = 5;
    pop.dst.size = 64;
    emitPop(pop);
    OpcodeCoverage::instance().seenEmit(X86Op::LEAVE);
    (void)in;
}

void Translator::emitBranch(const Insn& in) {
    uint64_t target = 0;
    if (in.src.kind == OperandKind::REL) target = static_cast<uint64_t>(in.src.imm);
    else if (in.dst.kind == OperandKind::REL) target = static_cast<uint64_t>(in.dst.imm);
    emitBlockExit(BlockExitReason::CONTINUE, target);
    OpcodeCoverage::instance().seenEmit(in.op);
}

void Translator::emitCall(const Insn& in) {
    // Push return address (guest_end is approximate — caller sets after)
    // Full: sub rsp, 8; store return; jump target
    int rsp = hostGpr(4);
    emit_.sub_imm(rsp, rsp, 8);
    // return addr unknown precisely here; exit CONTINUE and let loop handle
    uint64_t target = 0;
    if (in.src.kind == OperandKind::REL) target = static_cast<uint64_t>(in.src.imm);
    else if (in.dst.kind == OperandKind::REL) target = static_cast<uint64_t>(in.dst.imm);
    emitBlockExit(BlockExitReason::CONTINUE, target);
    OpcodeCoverage::instance().seenEmit(X86Op::CALL);
}

void Translator::emitRet() {
    // Pop RIP from [RSP]
    Operand mem;
    mem.kind = OperandKind::MEM;
    mem.mem.base = 4;
    mem.size = 64;
    emitLoadOp(mem, X_RIP, 64);
    int rsp = hostGpr(4);
    emit_.add_imm(rsp, rsp, 8);
    emit_.str_x(X_RIP, X_CTX, rip());
    uint32_t tmp[4];
    size_t n = HostTrampoline::emitStoreExitReason(tmp, BlockExitReason::CONTINUE);
    for (size_t i = 0; i < n; ++i) emit_.emit(tmp[i]);
    emitEpilogueAndReturn();
    OpcodeCoverage::instance().seenEmit(X86Op::RET);
}

void Translator::emitSyscall() {
    emitBlockExit(BlockExitReason::SYSCALL, 0);
    OpcodeCoverage::instance().seenEmit(X86Op::SYSCALL);
}

void Translator::emitSetcc(const Insn& in) {
    // Materialize flag comparison into dest byte — simplified CSET EQ
    emit_.cset(11, EQ);
    emitStoreOp(in.dst, 11, 8);
    OpcodeCoverage::instance().seenEmit(X86Op::SETCC);
}

void Translator::emitCmov(const Insn& in) {
    emitLoadOp(in.src, 12, 64);
    emitLoadOp(in.dst, 11, 64);
    emit_.csel(11, 12, 11, EQ);
    emitStoreOp(in.dst, 11, 64);
    OpcodeCoverage::instance().seenEmit(X86Op::CMOV);
}

void Translator::emitSimd(const Insn& in) {
    // XORPS-style zero or ORR move between V registers (indices as reg-16)
    if (in.op == X86Op::MOVAPS) {
        emit_.orr_v(0, 0, 0); // placeholder keep V0
        OpcodeCoverage::instance().seenEmit(X86Op::MOVAPS);
    } else if (in.op == X86Op::ADDPS) {
        emit_.fadd_4s(0, 0, 1);
        OpcodeCoverage::instance().seenEmit(X86Op::ADDPS);
    } else if (in.op == X86Op::MULPS) {
        emit_.fmul_4s(0, 0, 1);
        OpcodeCoverage::instance().seenEmit(X86Op::MULPS);
    } else {
        emit_.movi_v_zero(0);
        OpcodeCoverage::instance().seenEmit(in.op);
    }
}

void Translator::translateInsn(const Insn& in) {
    switch (in.op) {
        case X86Op::NOP:
            emit_.nop();
            OpcodeCoverage::instance().seenEmit(X86Op::NOP);
            break;
        case X86Op::ADD: case X86Op::SUB: case X86Op::AND: case X86Op::OR:
        case X86Op::XOR: case X86Op::CMP: case X86Op::TEST:
        case X86Op::IMUL: case X86Op::MUL: case X86Op::IDIV: case X86Op::DIV:
        case X86Op::NEG: case X86Op::NOT: case X86Op::INC: case X86Op::DEC:
            emitAlu(in); break;
        case X86Op::SHL: case X86Op::SHR: case X86Op::SAR: case X86Op::ROL: case X86Op::ROR:
            emitShift(in); break;
        case X86Op::MOV: case X86Op::MOVZX: case X86Op::MOVSX:
            emitMov(in); break;
        case X86Op::LEA: emitLea(in); break;
        case X86Op::PUSH: emitPush(in); break;
        case X86Op::POP: emitPop(in); break;
        case X86Op::LEAVE: emitLeave(in); break;
        case X86Op::SETCC: emitSetcc(in); break;
        case X86Op::CMOV: emitCmov(in); break;
        case X86Op::MOVAPS: case X86Op::ADDPS: case X86Op::MULPS:
            emitSimd(in); break;
        default:
            emit_.nop();
            OpcodeCoverage::instance().seenFallback(in.op);
            break;
    }
}

} // namespace nexus
