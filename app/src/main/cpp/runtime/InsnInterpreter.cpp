#include "InsnInterpreter.h"
#include "AesPrimitives.h"
#include "../diagnostics/Logger.h"
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>

namespace nexus {

namespace {

// 32-bit rotates used by the SHA extensions (count is always < 32 here).
inline uint32_t rotl32(uint32_t v, int n) {
    n &= 31;
    return n ? (v << n) | (v >> (32 - n)) : v;
}
inline uint32_t rotr32(uint32_t v, int n) {
    n &= 31;
    return n ? (v >> n) | (v << (32 - n)) : v;
}

// SHA-256's small/large sigma functions.
inline uint32_t sha256Sig0(uint32_t x) { return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3); }
inline uint32_t sha256Sig1(uint32_t x) { return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10); }
inline uint32_t sha256Sum0(uint32_t x) { return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22); }
inline uint32_t sha256Sum1(uint32_t x) { return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25); }

// A free-running, monotonic time-stamp counter. Real TSC counts core clock
// cycles; NINE has no fixed clock domain, so it counts 2.5 GHz-equivalent
// nanoseconds from the first RDTSC. Monotonic across threads and cheap.
// SSE4.1 ROUND*: imm8[1:0] picks the rounding mode. The default MXCSR mode
// (nearest-even) is also what mode 0 requests explicitly, so this is
// independent of the ambient floating-point environment.
inline double roundByMode(double x, int mode) {
    if (!std::isfinite(x)) return x;
    switch (mode & 3) {
        case 0: {
            const double f = std::floor(x);
            const double d = x - f;
            if (d < 0.5) return f;
            if (d > 0.5) return f + 1.0;
            return (std::fmod(f, 2.0) == 0.0) ? f : f + 1.0;
        }
        case 1: return std::floor(x);
        case 2: return std::ceil(x);
        default: return std::trunc(x);
    }
}

inline uint64_t readTsc() {
    using namespace std::chrono;
    static const steady_clock::time_point t0 = steady_clock::now();
    const auto ns = duration_cast<nanoseconds>(steady_clock::now() - t0).count();
    return static_cast<uint64_t>(ns) * 5 / 2 + 0x1000;
}

// x86's default MXCSR rounding mode is round-to-nearest-even. MXCSR is not
// modelled yet (no LDMXCSR/STMXCSR), so every rounding conversion uses it.
double roundHalfEven(double x) {
    if (!std::isfinite(x)) return x;
    const double f = std::floor(x);
    if (f == x) return x;
    const double d = x - f;
    if (d < 0.5) return f;
    if (d > 0.5) return std::ceil(x);
    return (std::fmod(f, 2.0) == 0.0) ? f : std::ceil(x); // exact tie -> even
}

// Packed/scalar conversion to a signed integer. False means "integer
// indefinite": x86 returns the 0x8000… pattern and sets CF.
bool toI32(double x, uint32_t& out) {
    if (!std::isfinite(x) || x >= 2147483648.0 || x < -2147483648.0) return false;
    out = static_cast<uint32_t>(static_cast<int32_t>(x));
    return true;
}

bool toI64(double x, uint64_t& out) {
    // 2^63 is exactly representable, so the upper bound is exclusive.
    if (!std::isfinite(x) || x >= 9223372036854775808.0 || x < -9223372036854775808.0)
        return false;
    out = static_cast<uint64_t>(static_cast<int64_t>(x));
    return true;
}

// Little-endian lane access for the packed-integer SIMD ops. Lane widths are
// 1/2/4/8 bytes; the compiler folds these into single loads/stores.
uint64_t loadLeBytes(const uint8_t* p, int n) {
    uint64_t v = 0;
    for (int k = 0; k < n; ++k) v |= static_cast<uint64_t>(p[k]) << (8 * k);
    return v;
}

void storeLeBytes(uint8_t* p, uint64_t v, int n) {
    for (int k = 0; k < n; ++k) p[k] = static_cast<uint8_t>(v >> (8 * k));
}

// Sign-extend `bits` of v into a signed 64-bit value.
int64_t sextBits(uint64_t v, int bits) {
    if (bits >= 64) return static_cast<int64_t>(v);
    const uint64_t sign = 1ULL << (bits - 1);
    const uint64_t masked = v & ((1ULL << bits) - 1);
    return static_cast<int64_t>((masked & sign) ? (masked | (~0ULL << bits)) : masked);
}

// Saturate a signed value into `bits` (signed clamp), and an arbitrary value
// into an unsigned `bits` field (used by the PACK* and PADD{S,US} families).
int64_t satSigned(int64_t v, int bits) {
    const int64_t lo = -(1LL << (bits - 1));
    const int64_t hi = (1LL << (bits - 1)) - 1;
    return v < lo ? lo : (v > hi ? hi : v);
}

uint64_t satUnsigned(int64_t v, int bits) {
    const int64_t hi = (1LL << bits) - 1;
    if (v < 0) return 0;
    return static_cast<uint64_t>(v > hi ? hi : v);
}

// One byte of the reflected CRC-32C (Castagnoli) polynomial used by CRC32.
uint32_t crc32cUpdate(uint32_t crc, uint8_t b) {
    crc ^= b;
    for (int k = 0; k < 8; ++k)
        crc = (crc >> 1) ^ (0x82F63B78u & (0u - (crc & 1u)));
    return crc;
}

// SSE compare-with-predicate, imm8[2:0]. The signalling/quiet and SAE
// distinctions are not modelled (NINE raises no FP exceptions), so only the
// lane result is computed.
bool cmpPredicate(int pred, bool unordered, bool lt, bool le, bool eq) {
    switch (pred & 7) {
        case 0: return !unordered && eq;    // EQ_OQ
        case 1: return !unordered && lt;    // LT_OS
        case 2: return !unordered && le;    // LE_OS
        case 3: return unordered;           // UNORD_Q
        case 4: return unordered || !eq;    // NEQ_UQ
        case 5: return unordered || !lt;    // NLT_US
        case 6: return unordered || !le;    // NLE_US
        default: return !unordered;         // ORD_Q
    }
}

// Deterministic CPUID model. Never forwards the host's leaves: guest behaviour
// must be identical on every device, and only advertised features may appear
// here — a guest that sees AVX/AVX2 will run VEX code NINE cannot execute.
void synthCpuid(uint32_t leaf, uint32_t, uint32_t out[4]) {
    out[0] = out[1] = out[2] = out[3] = 0;
    switch (leaf) {
        case 0x00000000:
            out[0] = 7;             // highest basic leaf
            out[1] = 0x756E6547;    // "Genu"
            out[2] = 0x6C65746E;    // "ntel"
            out[3] = 0x49656E69;    // "ineI"
            break;
        case 0x00000001:
            out[0] = 0x000006F6;                      // family 6, model 0x0F, step 6
            out[1] = (1u << 16) | (8u << 8);          // 1 logical CPU, 64 B CLFLUSH line
            out[2] = 0;                               // no SSE3/SSSE3/SSE4/AES/AVX
            // FPU DE PSE TSC MSR PAE MCE CX8 MTRR PGE MCA CMOV PAT PSE36 CLFSH
            // FXSR SSE SSE2 — the integer/SSE2 baseline NINE actually runs.
            out[3] = 0x070BF1FDu;
            break;
        case 0x00000007:
            break;                                    // no AVX2/BMI/ERMS advertised
        case 0x80000000:
            out[0] = 0x80000001;                      // highest extended leaf
            break;
        case 0x80000001:
            out[3] = 0x20100800;                      // SYSCALL, NX, LM
            break;
        default:
            break;
    }
}

} // namespace

void InsnInterpreter::syncFlags(GuestContext& ctx) {
    // Arithmetic flags plus the ones flag-control instructions (CLC/STC/CLI/
    // STI/CLD/STD/STAC/CLAC) own: CF PF AF ZF SF OF | IF DF AC.
    constexpr uint64_t kOwned = 0x8D5ULL | (1ULL << 9) | (1ULL << 10) | (1ULL << 18);
    ctx.rflags = (ctx.rflags & ~kOwned) | (flags_.materialize() & kOwned);
}

bool InsnInterpreter::loadMem(uint64_t addr, void* out, size_t n) {
    if (!mm_) { mem_fault_ = true; mem_fault_addr_ = addr; mem_fault_what_ = "no memory manager"; return false; }
    if (!mm_->isRangeAccessible(addr, n, PagePerm::READ)) {
        mem_fault_ = true; mem_fault_addr_ = addr; mem_fault_what_ = "read of unmapped page";
        return false;
    }
    void* host = mm_->guestToHost(addr);
    if (!host) {
        mem_fault_ = true; mem_fault_addr_ = addr; mem_fault_what_ = "load mapping";
        return false;
    }
    std::memcpy(out, host, n);
    return true;
}

bool InsnInterpreter::storeMem(uint64_t addr, const void* in, size_t n) {
    if (!mm_) { mem_fault_ = true; mem_fault_addr_ = addr; mem_fault_what_ = "no memory manager"; return false; }
    if (!mm_->isRangeAccessible(addr, n, PagePerm::WRITE)) {
        mem_fault_ = true; mem_fault_addr_ = addr; mem_fault_what_ = "write to non-writable page";
        return false;
    }
    void* host = mm_->guestToHost(addr);
    if (!host) {
        mem_fault_ = true; mem_fault_addr_ = addr; mem_fault_what_ = "store mapping";
        return false;
    }
    std::memcpy(host, in, n);
    if (smc_) smc_->onStore(addr, n);
    return true;
}

uint64_t InsnInterpreter::effectiveAddress(GuestContext& ctx, const MemOp& mem,
                                           uint64_t rip, int insn_len) {
    int64_t addr = mem.disp;
    if (mem.rip_relative) {
        addr += static_cast<int64_t>(rip + insn_len);
    } else {
        if (mem.base >= 0 && mem.base < 16)
            addr += static_cast<int64_t>(ctx.gpr[mem.base]);
        if (mem.index >= 0 && mem.index < 16)
            addr += static_cast<int64_t>(ctx.gpr[mem.index]) * mem.scale;
    }
    // Segment bases (TLS via FS, TCB head / vvar via GS in Linux guests)
    if (mem.seg == 1) addr += static_cast<int64_t>(ctx.fs_base);
    else if (mem.seg == 2) addr += static_cast<int64_t>(ctx.gs_base);
    return static_cast<uint64_t>(addr);
}

uint64_t InsnInterpreter::readOperand(GuestContext& ctx, const Operand& op, int size_bits) {
    if (size_bits <= 0) size_bits = op.size ? op.size : 64;
    switch (op.kind) {
        case OperandKind::REG:
            if (op.reg >= 0 && op.reg < 16) {
                if (op.high8 && size_bits == 8)
                    return (ctx.gpr[op.reg] >> 8) & 0xFF;
                return maskSize(ctx.gpr[op.reg], size_bits);
            }
            if (op.reg >= 16 && op.reg < 32) {
                uint64_t v = 0;
                std::memcpy(&v, ctx.ymm[op.reg - 16], std::min<size_t>(8, size_bits / 8));
                return v;
            }
            return 0;
        case OperandKind::IMM:
            return maskSize(static_cast<uint64_t>(op.imm), size_bits);
        case OperandKind::REL:
            return static_cast<uint64_t>(static_cast<int64_t>(ctx.rip) + op.imm);
        case OperandKind::K:
            if (op.reg >= 0 && op.reg < 8) return maskSize(ctx.kmask[op.reg], size_bits);
            return 0;
        case OperandKind::MEM: {
            uint64_t ea = effectiveAddress(ctx, op.mem, ctx.rip, cur_insn_len_);
            uint64_t v = 0;
            size_t n = static_cast<size_t>((size_bits + 7) / 8);
            if (!loadMem(ea, &v, n)) return 0;
            return maskSize(v, size_bits);
        }
        default:
            return 0;
    }
}

void InsnInterpreter::writeOperand(GuestContext& ctx, const Operand& op,
                                   uint64_t value, int size_bits) {
    if (size_bits <= 0) size_bits = op.size ? op.size : 64;
    value = maskSize(value, size_bits);
    switch (op.kind) {
        case OperandKind::REG:
            if (op.reg >= 0 && op.reg < 16) {
                if (size_bits == 32)
                    ctx.gpr[op.reg] = value & 0xFFFFFFFFu;
                else if (size_bits == 64)
                    ctx.gpr[op.reg] = value;
                else if (size_bits == 16)
                    ctx.gpr[op.reg] = (ctx.gpr[op.reg] & ~0xFFFFu) | (value & 0xFFFFu);
                else if (size_bits == 8) {
                    if (op.high8)
                        ctx.gpr[op.reg] = (ctx.gpr[op.reg] & ~0xFF00u) | ((value & 0xFFu) << 8);
                    else
                        ctx.gpr[op.reg] = (ctx.gpr[op.reg] & ~0xFFu) | (value & 0xFFu);
                }
            } else if (op.reg >= 16 && op.reg < 32) {
                std::memcpy(ctx.ymm[op.reg - 16], &value,
                            std::min<size_t>(8, size_bits / 8));
            }
            break;
        case OperandKind::K:
            if (op.reg >= 0 && op.reg < 8)
                ctx.kmask[op.reg] = maskSize(value, size_bits);
            break;
        case OperandKind::MEM: {
            uint64_t ea = effectiveAddress(ctx, op.mem, ctx.rip, cur_insn_len_);
            size_t n = static_cast<size_t>((size_bits + 7) / 8);
            storeMem(ea, &value, n);
            break;
        }
        default:
            break;
    }
}

void InsnInterpreter::readXmm(GuestContext& ctx, int reg, uint8_t out[16]) const {
    int n = reg - 16;
    if (n < 0 || n > 15) { std::memset(out, 0, 16); return; }
    std::memcpy(out, ctx.ymm[n], 16);
}

void InsnInterpreter::writeXmm(GuestContext& ctx, int reg, const uint8_t in[16]) {
    int n = reg - 16;
    if (n < 0 || n > 15) return;
    std::memcpy(ctx.ymm[n], in, 16);
}

bool InsnInterpreter::loadSseSource(GuestContext& ctx, const Operand& src,
                                    uint8_t out[16], int bytes) {
    std::memset(out, 0, 16);
    if (bytes <= 0) bytes = 16;
    if (src.kind == OperandKind::REG) {
        uint8_t full[16];
        readXmm(ctx, src.reg, full);
        std::memcpy(out, full, static_cast<size_t>(bytes > 16 ? 16 : bytes));
        return true;
    }
    if (src.kind == OperandKind::MEM) {
        uint64_t ea = effectiveAddress(ctx, src.mem, ctx.rip, cur_insn_len_);
        return loadMem(ea, out, static_cast<size_t>(bytes));
    }
    return true; // IMM/NONE: zero-filled operand
}

void InsnInterpreter::setSz(GuestContext& ctx, uint64_t value, int bits) {
    if (bits <= 0) bits = 32;
    uint64_t v = maskSize(value, bits);
    uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
    rf &= ~((1ULL << 7) | (1ULL << 6));
    if (v == 0) rf |= 1ULL << 6;
    if ((v >> (bits - 1)) & 1) rf |= 1ULL << 7;
    flags_.setRaw(rf);
    syncFlags(ctx);
}

void InsnInterpreter::setFlagsMasked(GuestContext& ctx, uint64_t clear, uint64_t set) {
    uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
    rf = (rf & ~clear) | set;
    flags_.setRaw(rf);
    syncFlags(ctx);
}

InterpResult InsnInterpreter::raiseBoundRange(InterpResult r) const {
    r.exit = InterpExit::EXCEPTION;
    r.exception_code = 0xC0000085; // STATUS_BOUND_RANGE_EXCEEDED (#BR)
    r.exception_msg = "#BR bound range exceeded";
    return r;
}

void InsnInterpreter::setSzp(GuestContext& ctx, uint8_t value) {
    uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
    rf &= ~((1ULL << 7) | (1ULL << 6) | (1ULL << 2)); // SF ZF PF
    if (value == 0) rf |= 1ULL << 6;
    if (value & 0x80) rf |= 1ULL << 7;
    uint8_t v = value;
    v ^= static_cast<uint8_t>(v >> 4);
    v ^= static_cast<uint8_t>(v >> 2);
    v ^= static_cast<uint8_t>(v >> 1);
    if ((~v) & 1) rf |= 1ULL << 2; // even parity
    flags_.setRaw(rf);
    syncFlags(ctx);
}

bool InsnInterpreter::evalCc(GuestContext& ctx, uint8_t c) {
    uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
    bool pf = (rf >> 2) & 1;
    bool cf = (rf >> 0) & 1;
    bool zf = (rf >> 6) & 1;
    bool sf = (rf >> 7) & 1;
    bool of = (rf >> 11) & 1;
    switch (c & 0xF) {
        case 0:  return of;               // O
        case 1:  return !of;              // NO
        case 2:  return cf;               // B
        case 3:  return !cf;              // AE
        case 4:  return zf;               // E
        case 5:  return !zf;              // NE
        case 6:  return cf || zf;         // BE
        case 7:  return !cf && !zf;       // A
        case 8:  return sf;               // S
        case 9:  return !sf;              // NS
        case 10: return pf;               // P
        case 11: return !pf;              // NP
        case 12: return sf != of;         // L
        case 13: return sf == of;         // GE
        case 14: return zf || (sf != of); // LE
        default: return !zf && (sf == of);// G
    }
}

bool InsnInterpreter::evalCondition(GuestContext& ctx, X86Op op) {
    switch (op) {
        case X86Op::JO:  return evalCc(ctx, 0);
        case X86Op::JNO: return evalCc(ctx, 1);
        case X86Op::JB:  return evalCc(ctx, 2);
        case X86Op::JAE: return evalCc(ctx, 3);
        case X86Op::JE:  return evalCc(ctx, 4);
        case X86Op::JNE: return evalCc(ctx, 5);
        case X86Op::JBE: return evalCc(ctx, 6);
        case X86Op::JA:  return evalCc(ctx, 7);
        case X86Op::JS:  return evalCc(ctx, 8);
        case X86Op::JNS: return evalCc(ctx, 9);
        case X86Op::JL:  return evalCc(ctx, 12);
        case X86Op::JGE: return evalCc(ctx, 13);
        case X86Op::JLE: return evalCc(ctx, 14);
        case X86Op::JG:  return evalCc(ctx, 15);
        default: return evalCc(ctx, 5);
    }
}

InterpResult InsnInterpreter::execute(GuestContext& ctx, const Insn& in) {
    InterpResult r;
    r.next_pc = ctx.rip + in.length;
    cur_insn_len_ = in.length;
    int bits = in.dst.size ? in.dst.size : (in.rex_w ? 64 : 32);
    if (bits <= 0) bits = 64;

    {
        trace_.emplace_back(ctx.rip, in.mnemonic);
        if (trace_.size() > kTraceCap) trace_.erase(trace_.begin());
    }

    switch (in.op) {
        case X86Op::VEC:
            return executeVec(ctx, in);

        case X86Op::ENCLS: case X86Op::ENCLU: case X86Op::ENCLV:
            return executeSgx(ctx, in);

        case X86Op::NOP:
            ctx.rip = r.next_pc;
            return r;

        case X86Op::MOV: {
            uint64_t v = readOperand(ctx, in.src, bits);
            writeOperand(ctx, in.dst, v, bits);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::MOVZX: {
            int src_bits = in.src.size ? in.src.size : 8;
            uint64_t v = readOperand(ctx, in.src, src_bits);
            writeOperand(ctx, in.dst, v, bits);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::MOVSX: {
            int src_bits = in.src.size ? in.src.size : 8;
            uint64_t v = signExtend(readOperand(ctx, in.src, src_bits), src_bits);
            writeOperand(ctx, in.dst, v, bits);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::LEA: {
            uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, in.length);
            writeOperand(ctx, in.dst, ea, 64);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::ADD: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t res = maskSize(a + b, bits);
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromAdd(res, a, b, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::ADC: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t c = (flags_.isLazy() ? flags_.materialize() : ctx.rflags) & 1;
            unsigned __int128 full =
                (unsigned __int128)a + b + c;
            uint64_t res = maskSize(static_cast<uint64_t>(full), bits);
            uint64_t cf = static_cast<uint64_t>(full >> bits) & 1;
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromAdd(res, a, b, static_cast<uint8_t>(bits));
            uint64_t rf = flags_.materialize();
            rf &= ~1ULL;
            if (cf) rf |= 1;
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SBB: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t c = (flags_.isLazy() ? flags_.materialize() : ctx.rflags) & 1;
            int64_t sa = static_cast<int64_t>(signExtend(a, bits));
            int64_t sb = static_cast<int64_t>(signExtend(b, bits));
            int64_t full = sa - sb - static_cast<int64_t>(c);
            uint64_t res = maskSize(static_cast<uint64_t>(full), bits);
            uint64_t cf = full < 0 ? 1 : 0;
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromSub(res, a, b, static_cast<uint8_t>(bits));
            uint64_t rf = flags_.materialize();
            rf &= ~1ULL;
            if (cf) rf |= 1;
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SUB:
        case X86Op::CMP: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t res = maskSize(a - b, bits);
            if (in.op == X86Op::SUB) writeOperand(ctx, in.dst, res, bits);
            flags_.setFromSub(res, a, b, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::AND:
        case X86Op::TEST: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t res = maskSize(a & b, bits);
            if (in.op == X86Op::AND) writeOperand(ctx, in.dst, res, bits);
            flags_.setFromLogic(res, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::OR: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t res = maskSize(a | b, bits);
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromLogic(res, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::XOR: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t res = maskSize(a ^ b, bits);
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromLogic(res, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::INC: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t res = maskSize(a + 1, bits);
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromAdd(res, a, 1, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::DEC: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t res = maskSize(a - 1, bits);
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromSub(res, a, 1, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::NEG: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t res = maskSize(~a + 1, bits);
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromSub(res, 0, a, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::NOT: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            writeOperand(ctx, in.dst, maskSize(~a, bits), bits);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SHL: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t c = readOperand(ctx, in.src, 8) & (bits == 64 ? 63u : 31u);
            uint64_t res = maskSize(a << c, bits);
            writeOperand(ctx, in.dst, res, bits);
            if (c) { flags_.setFromLogic(res, static_cast<uint8_t>(bits)); syncFlags(ctx); }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SHR: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t c = readOperand(ctx, in.src, 8) & (bits == 64 ? 63u : 31u);
            uint64_t res = maskSize(a >> c, bits);
            writeOperand(ctx, in.dst, res, bits);
            if (c) { flags_.setFromLogic(res, static_cast<uint8_t>(bits)); syncFlags(ctx); }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SAR: {
            int64_t a = static_cast<int64_t>(signExtend(readOperand(ctx, in.dst, bits), bits));
            uint64_t c = readOperand(ctx, in.src, 8) & (bits == 64 ? 63u : 31u);
            uint64_t res = maskSize(static_cast<uint64_t>(a >> static_cast<int>(c)), bits);
            writeOperand(ctx, in.dst, res, bits);
            if (c) { flags_.setFromLogic(res, static_cast<uint8_t>(bits)); syncFlags(ctx); }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::MUL: case X86Op::IMUL: {
            if (in.src.kind != OperandKind::NONE) {
                int64_t a, b;
                if (in.src2.kind == OperandKind::IMM) {
                    // IMUL r, r/m, imm (69/6B): dest register NOT multiplied in
                    a = static_cast<int64_t>(signExtend(readOperand(ctx, in.src, bits), bits));
                    b = in.src2.imm;
                } else {
                    // IMUL r, r/m (0F AF): signed multiply
                    a = static_cast<int64_t>(signExtend(readOperand(ctx, in.dst, bits), bits));
                    b = static_cast<int64_t>(signExtend(readOperand(ctx, in.src, bits), bits));
                }
                int64_t res = a * b;
                writeOperand(ctx, in.dst, static_cast<uint64_t>(res), bits);
                flags_.setFromLogic(static_cast<uint64_t>(res), static_cast<uint8_t>(bits));
            } else {
                // one-operand form (F7 /4 MUL, /5 IMUL): RDX:RAX = RAX * r/m
                unsigned __int128 prod;
                if (in.op == X86Op::MUL) {
                    unsigned __int128 a = maskSize(ctx.rax(), bits);
                    unsigned __int128 b = maskSize(readOperand(ctx, in.dst, bits), bits);
                    prod = a * b;
                } else {
                    __int128 a = static_cast<__int128>(static_cast<int64_t>(signExtend(ctx.rax(), bits)));
                    __int128 b = static_cast<__int128>(static_cast<int64_t>(signExtend(readOperand(ctx, in.dst, bits), bits)));
                    prod = static_cast<unsigned __int128>(a * b);
                }
                uint64_t lo = static_cast<uint64_t>(prod);
                uint64_t hi = static_cast<uint64_t>(prod >> 64);
                if (bits == 8) {
                    ctx.rax() = (ctx.rax() & ~0xFFFFull) | (lo & 0xFF) | ((hi & 0xFF) << 8);
                } else if (bits == 16) {
                    ctx.rax() = (ctx.rax() & ~0xFFFFull) | (lo & 0xFFFF);
                    ctx.rdx() = (ctx.rdx() & ~0xFFFFull) | (hi & 0xFFFF);
                } else if (bits == 32) {
                    ctx.rax() = static_cast<uint32_t>(lo);
                    ctx.rdx() = static_cast<uint32_t>(hi);
                } else {
                    ctx.rax() = lo;
                    ctx.rdx() = hi;
                }
            }
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::DIV: case X86Op::IDIV: {
            // one-operand: (RDX:RAX) / r/m -> quotient RAX, remainder RDX
            const bool sgnd = (in.op == X86Op::IDIV);
            uint64_t den = maskSize(readOperand(ctx, in.dst, bits), bits);
            if (den == 0) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000094;
                r.exception_msg = sgnd ? "idiv: divide by zero" : "div: divide by zero";
                return r;
            }
            if (bits == 8) {
                uint16_t n = static_cast<uint16_t>(ctx.rax() & 0xFFFF);
                if (sgnd) {
                    int16_t ns = static_cast<int8_t>(n & 0xFF);
                    int16_t ds = static_cast<int8_t>(den);
                    int16_t q = static_cast<int16_t>(ns / ds);
                    int16_t rem = static_cast<int16_t>(ns % ds);
                    if (q < -128 || q > 127) {
                        r.exit = InterpExit::EXCEPTION;
                        r.exception_code = 0xC0000094;
                        r.exception_msg = "idiv: quotient overflow";
                        return r;
                    }
                    ctx.rax() = (ctx.rax() & ~0xFFFFull) |
                                static_cast<uint16_t>(static_cast<uint8_t>(q)) |
                                (static_cast<uint16_t>(static_cast<uint8_t>(rem)) << 8);
                } else {
                    uint16_t q = static_cast<uint16_t>(n / den);
                    uint16_t rem = static_cast<uint16_t>(n % den);
                    if (q > 0xFF) {
                        r.exit = InterpExit::EXCEPTION;
                        r.exception_code = 0xC0000094;
                        r.exception_msg = "div: quotient overflow";
                        return r;
                    }
                    ctx.rax() = (ctx.rax() & ~0xFFFFull) | q | (rem << 8);
                }
            } else {
                uint64_t mask = (bits == 16) ? 0xFFFFull : (bits == 32) ? 0xFFFFFFFFull : ~0ull;
                uint64_t hi = ctx.rdx() & mask;
                uint64_t lo = ctx.rax() & mask;
                auto sext = [&](uint64_t v) -> __int128 {
                    int shift = 64 - bits;
                    return static_cast<__int128>(static_cast<int64_t>(v << shift) >> shift);
                };
                if (sgnd) {
                    __int128 n = (sext(hi) << bits) | static_cast<__int128>(lo);
                    __int128 d = sext(den);
                    __int128 q = n / d;
                    __int128 rem = n % d;
                    __int128 qmin = static_cast<__int128>(1) << (bits - 1);
                    if (q < -qmin || q >= qmin) {
                        r.exit = InterpExit::EXCEPTION;
                        r.exception_code = 0xC0000094;
                        r.exception_msg = "idiv: quotient overflow";
                        return r;
                    }
                    ctx.rax() = static_cast<uint64_t>(q) & mask;
                    ctx.rdx() = static_cast<uint64_t>(rem) & mask;
                } else {
                    unsigned __int128 n = (static_cast<unsigned __int128>(hi) << bits) | lo;
                    unsigned __int128 d = den;
                    unsigned __int128 q = n / d;
                    if (q > static_cast<unsigned __int128>(mask)) {
                        r.exit = InterpExit::EXCEPTION;
                        r.exception_code = 0xC0000094;
                        r.exception_msg = "div: quotient overflow";
                        return r;
                    }
                    ctx.rax() = static_cast<uint64_t>(q) & mask;
                    ctx.rdx() = static_cast<uint64_t>(n % d) & mask;
                }
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::PUSH: {
            const Operand& src = in.src.kind != OperandKind::NONE ? in.src : in.dst;
            uint64_t v = readOperand(ctx, src, 64);
            ctx.rsp() -= 8;
            if (!storeMem(ctx.rsp(), &v, 8)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "push: stack fault";
                return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::POP: {
            uint64_t v = 0;
            if (!loadMem(ctx.rsp(), &v, 8)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "pop: stack fault";
                return r;
            }
            ctx.rsp() += 8;
            const Operand& dst = in.dst.kind != OperandKind::NONE ? in.dst : in.src;
            writeOperand(ctx, dst, v, 64);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::LEAVE: {
            ctx.rsp() = ctx.rbp();
            uint64_t v = 0;
            if (!loadMem(ctx.rsp(), &v, 8)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "leave: stack fault";
                return r;
            }
            ctx.rsp() += 8;
            ctx.rbp() = v;
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::JMP: {
            if (in.src.kind == OperandKind::REL || in.dst.kind == OperandKind::REL) {
                // Decoder stores absolute target in .imm
                const Operand& rel = in.src.kind == OperandKind::REL ? in.src : in.dst;
                r.next_pc = static_cast<uint64_t>(rel.imm);
            } else {
                const Operand& t = in.src.kind != OperandKind::NONE ? in.src : in.dst;
                r.next_pc = readOperand(ctx, t, 64);
            }
            ctx.rip = r.next_pc;
            r.exit = InterpExit::BLOCK_END;
            return r;
        }

        case X86Op::JE: case X86Op::JNE: case X86Op::JL: case X86Op::JLE:
        case X86Op::JG: case X86Op::JGE: case X86Op::JB: case X86Op::JBE:
        case X86Op::JA: case X86Op::JAE: case X86Op::JS: case X86Op::JNS:
        case X86Op::JO: case X86Op::JNO: {
            const Operand& rel = in.src.kind == OperandKind::REL ? in.src :
                                 (in.dst.kind == OperandKind::REL ? in.dst : in.src);
            if (evalCondition(ctx, in.op)) {
                r.next_pc = static_cast<uint64_t>(rel.imm); // absolute target from decoder
            } else {
                r.next_pc = ctx.rip + in.length;
            }
            ctx.rip = r.next_pc;
            r.exit = InterpExit::BLOCK_END;
            return r;
        }

        case X86Op::CALL: {
            uint64_t ret_addr = ctx.rip + in.length;
            ctx.rsp() -= 8;
            if (!storeMem(ctx.rsp(), &ret_addr, 8)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "call: stack fault";
                return r;
            }
            if (in.src.kind == OperandKind::REL || in.dst.kind == OperandKind::REL) {
                const Operand& rel = in.src.kind == OperandKind::REL ? in.src : in.dst;
                r.next_pc = static_cast<uint64_t>(rel.imm); // absolute
            } else {
                const Operand& t = in.src.kind != OperandKind::NONE ? in.src : in.dst;
                r.next_pc = readOperand(ctx, t, 64);
            }
            ctx.rip = r.next_pc;
            r.exit = InterpExit::BLOCK_END;
            return r;
        }

        case X86Op::RET: {
            uint64_t ret = 0;
            if (!loadMem(ctx.rsp(), &ret, 8)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "ret: stack fault";
                return r;
            }
            ctx.rsp() += 8;
            if (in.src.kind == OperandKind::IMM)
                ctx.rsp() += static_cast<uint64_t>(in.src.imm);
            ctx.rip = ret;
            r.next_pc = ret;
            r.exit = InterpExit::BLOCK_END;
            return r;
        }


        case X86Op::STOS: {
            // STOSB/W/D/Q: store AL/AX/EAX/RAX to [RDI], ±1/2/4/8 RDI; REP uses RCX
            int size = (in.dst.size == 8) ? 1 : (in.dst.size == 16) ? 2 : (in.dst.size == 32) ? 4 : 8;
            auto do_one = [&]() {
                // `size` is a byte count; maskSize works in bits.
                uint64_t val = (size == 8) ? ctx.rax() : maskSize(ctx.rax(), size * 8);
                uint64_t di = ctx.rdi();
                if (!storeMem(di, &val, static_cast<size_t>(size))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "stos fault";
                    return false;
                }
                bool df = (ctx.rflags & (1ULL << 10)) != 0;
                ctx.rdi() = di + (df ? -size : size);
                return true;
            };
            if (in.rep) {
                while (ctx.rcx() != 0) {
                    if (!do_one()) return r;
                    ctx.rcx() -= 1;
                }
            } else {
                if (!do_one()) return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }
        case X86Op::LODS: {
            int size = (in.dst.size == 8) ? 1 : (in.dst.size == 16) ? 2 : (in.dst.size == 32 ? 4 : 8);
            auto do_one = [&]() {
                uint64_t val = 0;
                uint64_t si = ctx.rsi();
                if (!loadMem(si, &val, static_cast<size_t>(size))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "lods fault";
                    return false;
                }
                writeOperand(ctx, in.dst, val, size * 8);
                bool df = (ctx.rflags & (1ULL << 10)) != 0;
                ctx.rsi() = si + (df ? -size : size);
                return true;
            };
            if (in.rep) {
                while (ctx.rcx() != 0) {
                    if (!do_one()) return r;
                    ctx.rcx() -= 1;
                }
            } else {
                if (!do_one()) return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }
        case X86Op::MOVS: {
            int size = (in.dst.size == 8) ? 1 : (in.dst.size == 16) ? 2 : (in.dst.size == 32 ? 4 : 8);
            auto do_one = [&]() {
                uint64_t val = 0;
                uint64_t si = ctx.rsi();
                uint64_t di = ctx.rdi();
                if (!loadMem(si, &val, static_cast<size_t>(size))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "movs load fault";
                    return false;
                }
                if (!storeMem(di, &val, static_cast<size_t>(size))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "movs store fault";
                    return false;
                }
                bool df = (ctx.rflags & (1ULL << 10)) != 0;
                ctx.rsi() = si + (df ? -size : size);
                ctx.rdi() = di + (df ? -size : size);
                return true;
            };
            if (in.rep) {
                while (ctx.rcx() != 0) {
                    if (!do_one()) return r;
                    ctx.rcx() -= 1;
                }
            } else {
                if (!do_one()) return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }
        case X86Op::SCAS: {
            int size = (in.dst.size == 8) ? 1 : (in.dst.size == 16) ? 2 : (in.dst.size == 32 ? 4 : 8);
            auto do_one = [&]() {
                uint64_t val = 0;
                uint64_t di = ctx.rdi();
                if (!loadMem(di, &val, static_cast<size_t>(size))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "scas fault";
                    return false;
                }
                const int bits = size * 8;
                uint64_t al = readOperand(ctx, in.src, bits);
                uint64_t res = maskSize(al - val, bits);
                flags_.setFromSub(res, al, val, static_cast<uint8_t>(bits));
                syncFlags(ctx);
                bool df = (ctx.rflags & (1ULL << 10)) != 0;
                ctx.rdi() = di + (df ? -size : size);
                return true;
            };
            // REPE/REPZ (F3) repeats while ZF=1, REPNE/REPNZ (F2) while ZF=0;
            // either way RCX counts down once per iteration.
            if (in.rep || in.repne) {
                while (ctx.rcx() != 0) {
                    if (!do_one()) return r;
                    ctx.rcx() -= 1;
                    const bool zf = flags_.isZero();
                    if (in.repne ? zf : !zf) break;
                }
            } else {
                if (!do_one()) return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::XCHG: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            writeOperand(ctx, in.dst, b, bits);
            writeOperand(ctx, in.src, a, bits);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CMPXCHG: {
            // cmpxchg r/m, r: compare acc (AL/AX/EAX/RAX) with r/m
            Operand acc_op;
            acc_op.kind = OperandKind::REG;
            acc_op.reg = 0;
            acc_op.size = bits;
            uint64_t acc = readOperand(ctx, acc_op, bits);
            uint64_t rm = readOperand(ctx, in.dst, bits);
            uint64_t res = maskSize(rm - acc, bits);
            flags_.setFromSub(res, rm, acc, static_cast<uint8_t>(bits));
            if (res == 0) {
                writeOperand(ctx, in.dst, readOperand(ctx, in.src, bits), bits);
            } else {
                writeOperand(ctx, in.src, rm, bits);
            }
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::XADD: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t res = maskSize(a + b, bits);
            writeOperand(ctx, in.dst, res, bits);
            writeOperand(ctx, in.src, a, bits);
            flags_.setFromAdd(res, a, b, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CDQ: {
            // CDQ/CQO: RDX = sign fill of RAX at src width
            int w = in.src.size ? in.src.size : 32;
            uint64_t v = maskSize(ctx.rax(), w);
            if (w == 32)
                ctx.rdx() = (v & 0x80000000ULL) ? 0xFFFFFFFFULL : 0;
            else if (w == 64)
                ctx.rdx() = (v & (1ULL << 63)) ? ~0ULL : 0;
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- ADX carry-chain additions (ADCX / ADOX) ----
        // ADCX updates only CF, ADOX only OF; every other arithmetic flag is
        // architecturally unmodified.
        case X86Op::ADCX:
        case X86Op::ADOX: {
            int bits = in.dst.size ? in.dst.size : 32;
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            uint64_t carry = (in.op == X86Op::ADCX) ? (rf & 1ULL) : ((rf >> 11) & 1ULL);
            unsigned __int128 full = static_cast<unsigned __int128>(a) + b + carry;
            uint64_t res = maskSize(static_cast<uint64_t>(full), bits);
            uint64_t carryOut = static_cast<uint64_t>((full >> bits) & 1ULL);
            if (in.op == X86Op::ADCX)
                rf = (rf & ~1ULL) | carryOut;
            else
                rf = (rf & ~(1ULL << 11)) | (carryOut << 11);
            writeOperand(ctx, in.dst, res, bits);
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- Legacy ASCII/BCD adjust ----
        case X86Op::AAA:
        case X86Op::AAS: {
            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            uint16_t ax = static_cast<uint16_t>(ctx.rax() & 0xFFFF);
            uint8_t al = static_cast<uint8_t>(ax & 0xFF);
            uint8_t ah = static_cast<uint8_t>((ax >> 8) & 0xFF);
            bool adjust = ((al & 0x0F) > 9) || ((rf & (1ULL << 4)) != 0);
            if (adjust) {
                // AAx adjust AH and AL independently, both as 8-bit values:
                // an AL wrap must not also feed the carry into AH.
                if (in.op == X86Op::AAA) { al = static_cast<uint8_t>(al + 6); ah = static_cast<uint8_t>(ah + 1); }
                else                      { al = static_cast<uint8_t>(al - 6); ah = static_cast<uint8_t>(ah - 1); }
                rf |= (1ULL << 0) | (1ULL << 4); // CF AF
            } else {
                rf &= ~((1ULL << 0) | (1ULL << 4));
            }
            al = static_cast<uint8_t>(al & 0x0F);
            ctx.rax() = (ctx.rax() & ~0xFFFFULL) |
                        (static_cast<uint64_t>(ah) << 8) | al;
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::AAD: {
            uint8_t al = static_cast<uint8_t>(ctx.rax() & 0xFF);
            uint8_t ah = static_cast<uint8_t>((ctx.rax() >> 8) & 0xFF);
            uint8_t base = static_cast<uint8_t>(in.src.imm & 0xFF);
            uint8_t res = static_cast<uint8_t>(al + ah * base);
            ctx.rax() = (ctx.rax() & ~0xFFFFULL) | res;
            setSzp(ctx, res);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::AAM: {
            uint8_t al = static_cast<uint8_t>(ctx.rax() & 0xFF);
            uint8_t base = static_cast<uint8_t>(in.src.imm & 0xFF);
            if (base == 0) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000094;
                r.exception_msg = "aam: divide by zero";
                return r;
            }
            uint8_t ah = static_cast<uint8_t>(al / base);
            uint8_t newAl = static_cast<uint8_t>(al % base);
            ctx.rax() = (ctx.rax() & ~0xFFFFULL) |
                        static_cast<uint64_t>(newAl) | (static_cast<uint64_t>(ah) << 8);
            setSzp(ctx, newAl);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- SSE/SSE2 packed & scalar floating-point add ----
        case X86Op::ADDPS:
        case X86Op::ADDPD: {
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "sse add: source load fault";
                return r;
            }
            if (in.op == X86Op::ADDPS) {
                for (int k = 0; k < 4; ++k) {
                    float x, y;
                    std::memcpy(&x, a + 4 * k, 4);
                    std::memcpy(&y, b + 4 * k, 4);
                    float s = x + y;
                    std::memcpy(a + 4 * k, &s, 4);
                }
            } else {
                for (int k = 0; k < 2; ++k) {
                    double x, y;
                    std::memcpy(&x, a + 8 * k, 8);
                    std::memcpy(&y, b + 8 * k, 8);
                    double s = x + y;
                    std::memcpy(a + 8 * k, &s, 8);
                }
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::ADDSS:
        case X86Op::ADDSD: {
            const bool single = (in.op == X86Op::ADDSS);
            const int nbytes = single ? 4 : 8;
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, nbytes)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "sse add scalar: source load fault";
                return r;
            }
            if (single) {
                float x, y;
                std::memcpy(&x, a, 4);
                std::memcpy(&y, b, 4);
                float s = x + y;
                std::memcpy(a, &s, 4); // upper 96 bits unmodified (legacy SSE)
            } else {
                double x, y;
                std::memcpy(&x, a, 8);
                std::memcpy(&y, b, 8);
                double s = x + y;
                std::memcpy(a, &s, 8); // upper 64 bits unmodified
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::ADDSUBPD:
        case X86Op::ADDSUBPS: {
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "addsub: source load fault";
                return r;
            }
            if (in.op == X86Op::ADDSUBPS) {
                for (int k = 0; k < 4; ++k) {
                    float x, y;
                    std::memcpy(&x, a + 4 * k, 4);
                    std::memcpy(&y, b + 4 * k, 4);
                    float res = (k & 1) ? (x + y) : (x - y);
                    std::memcpy(a + 4 * k, &res, 4);
                }
            } else {
                for (int k = 0; k < 2; ++k) {
                    double x, y;
                    std::memcpy(&x, a + 8 * k, 8);
                    std::memcpy(&y, b + 8 * k, 8);
                    double res = (k & 1) ? (x + y) : (x - y);
                    std::memcpy(a + 8 * k, &res, 8);
                }
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- AES-NI round primitives ----
        case X86Op::AESENC:
        case X86Op::AESENCLAST:
        case X86Op::AESDEC:
        case X86Op::AESDECLAST: {
            uint8_t state[16], key[16];
            readXmm(ctx, in.dst.reg, state);
            if (!loadSseSource(ctx, in.src, key, 16)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "aes: round key load fault";
                return r;
            }
            switch (in.op) {
                case X86Op::AESENC:     aes::roundEnc(state, key); break;
                case X86Op::AESENCLAST: aes::roundEncLast(state, key); break;
                case X86Op::AESDEC:     aes::roundDec(state, key); break;
                default:                aes::roundDecLast(state, key); break;
            }
            writeXmm(ctx, in.dst.reg, state);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::AESIMC: {
            uint8_t srcb[16];
            if (!loadSseSource(ctx, in.src, srcb, 16)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "aesimc: source load fault";
                return r;
            }
            aes::invMixColumns(srcb);
            writeXmm(ctx, in.dst.reg, srcb);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::AESKEYGENASSIST: {
            uint8_t srcb[16];
            if (!loadSseSource(ctx, in.src, srcb, 16)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "aeskeygenassist: source load fault";
                return r;
            }
            uint32_t x1 = static_cast<uint32_t>(srcb[4]) |
                          (static_cast<uint32_t>(srcb[5]) << 8) |
                          (static_cast<uint32_t>(srcb[6]) << 16) |
                          (static_cast<uint32_t>(srcb[7]) << 24);
            uint32_t x3 = static_cast<uint32_t>(srcb[12]) |
                          (static_cast<uint32_t>(srcb[13]) << 8) |
                          (static_cast<uint32_t>(srcb[14]) << 16) |
                          (static_cast<uint32_t>(srcb[15]) << 24);
            uint32_t rcon = static_cast<uint32_t>(in.src2.imm & 0xFF);
            uint32_t sub1 = aes::subWord(x1);
            uint32_t sub3 = aes::subWord(x3);
            uint32_t words[4] = {
                sub1,
                aes::rotWord(sub1) ^ rcon,
                sub3,
                aes::rotWord(sub3) ^ rcon
            };
            uint8_t out[16];
            for (int k = 0; k < 4; ++k) {
                out[4 * k + 0] = static_cast<uint8_t>(words[k]);
                out[4 * k + 1] = static_cast<uint8_t>(words[k] >> 8);
                out[4 * k + 2] = static_cast<uint8_t>(words[k] >> 16);
                out[4 * k + 3] = static_cast<uint8_t>(words[k] >> 24);
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- Key Locker bulk AES (128/256-bit keys, single block + WIDE) ----
        case X86Op::AESENC128KL: case X86Op::AESDEC128KL:
        case X86Op::AESENC256KL: case X86Op::AESDEC256KL:
        case X86Op::AESENCWIDE128KL: case X86Op::AESDECWIDE128KL:
        case X86Op::AESENCWIDE256KL: case X86Op::AESDECWIDE256KL: {
            const bool wide = in.op == X86Op::AESENCWIDE128KL ||
                              in.op == X86Op::AESDECWIDE128KL ||
                              in.op == X86Op::AESENCWIDE256KL ||
                              in.op == X86Op::AESDECWIDE256KL;
            const bool encrypt = in.op == X86Op::AESENC128KL ||
                                 in.op == X86Op::AESENC256KL ||
                                 in.op == X86Op::AESENCWIDE128KL ||
                                 in.op == X86Op::AESENCWIDE256KL;
            const int keyBytes = (in.op == X86Op::AESENC128KL ||
                                  in.op == X86Op::AESDEC128KL ||
                                  in.op == X86Op::AESENCWIDE128KL ||
                                  in.op == X86Op::AESDECWIDE128KL) ? 16 : 32;
            const size_t handleBytes = (keyBytes == 16) ? 48 : 64;

            uint8_t handle[64]{};
            uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, in.length);
            if (!loadMem(ea, handle, handleBytes)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "aes*kl: key handle load fault";
                return r;
            }
            const uint8_t* key = nullptr;
            bool authentic = aes::parseNineHandle(handle, handleBytes, keyBytes, key);

            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            rf &= ~((1ULL << 0) | (1ULL << 2) | (1ULL << 4) | (1ULL << 6) |
                    (1ULL << 7) | (1ULL << 11));
            if (!authentic) rf |= 1ULL << 6; // ZF=1 handle violation
            flags_.setRaw(rf);
            syncFlags(ctx);

            if (authentic) {
                aes::RoundKeys keys;
                aes::expandKey(key, keyBytes, keys);
                const int blocks = wide ? 8 : 1;
                for (int b = 0; b < blocks; ++b) {
                    int reg = wide ? (16 + b) : in.dst.reg;
                    uint8_t block[16];
                    readXmm(ctx, reg, block);
                    if (encrypt) aes::encryptBlock(block, keys);
                    else aes::decryptBlock(block, keys);
                    writeXmm(ctx, reg, block);
                }
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- Bitwise SIMD logical ops (legacy two-operand form) ----
        case X86Op::ANDPS: case X86Op::ANDPD:
        case X86Op::ANDNPS: case X86Op::ANDNPD: {
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "simd logical: source load fault";
                return r;
            }
            const bool invert = in.op == X86Op::ANDNPS || in.op == X86Op::ANDNPD;
            for (int k = 0; k < 16; ++k)
                a[k] = static_cast<uint8_t>((invert ? static_cast<uint8_t>(~a[k]) : a[k]) & b[k]);
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- SSE4.1 blends ----
        case X86Op::BLENDPS: case X86Op::BLENDPD:
        case X86Op::BLENDVPS: case X86Op::BLENDVPD: {
            const bool single = in.op == X86Op::BLENDPS || in.op == X86Op::BLENDVPS;
            const int lanes = single ? 4 : 2;
            const int laneBytes = 16 / lanes;
            uint8_t a[16], b[16], mask[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "blend: source load fault";
                return r;
            }
            const bool variable = in.op == X86Op::BLENDVPS || in.op == X86Op::BLENDVPD;
            if (variable) {
                readXmm(ctx, 16, mask); // implicit XMM0
            } else {
                std::memset(mask, 0, sizeof(mask));
            }
            const uint8_t imm = static_cast<uint8_t>(in.src2.imm & 0xFF);
            for (int k = 0; k < lanes; ++k) {
                const bool take_src = variable
                    ? (mask[k * laneBytes + laneBytes - 1] & 0x80) != 0
                    : ((imm >> k) & 1) != 0;
                if (take_src)
                    std::memcpy(a + k * laneBytes, b + k * laneBytes,
                                static_cast<size_t>(laneBytes));
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- BMI1: ANDN (dst = ~vvvv & r/m) ----
        case X86Op::ANDN: {
            const int bits = in.dst.size ? in.dst.size : 32;
            const uint64_t s1 = readOperand(ctx, in.src, bits);
            const uint64_t s2 = readOperand(ctx, in.src2, bits);
            const uint64_t res = maskSize(~s1 & s2, bits);
            writeOperand(ctx, in.dst, res, bits);
            setFlagsMasked(ctx, (1ULL << 0) | (1ULL << 11), 0); // CF=OF=0
            setSz(ctx, res, bits);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- BMI1: BLSI / BLSMSK / BLSR (destination is VEX.vvvv) ----
        case X86Op::BLSI:
        case X86Op::BLSMSK:
        case X86Op::BLSR: {
            const int bits = in.dst.size ? in.dst.size : 32;
            const uint64_t src = readOperand(ctx, in.src, bits);
            uint64_t res = 0;
            bool cf = false;
            if (in.op == X86Op::BLSI) {
                res = maskSize(0 - src, bits) & src;
                cf = src != 0;
            } else if (in.op == X86Op::BLSMSK) {
                res = maskSize((src - 1) ^ src, bits);
                cf = src == 0;
            } else {
                res = maskSize((src - 1) & src, bits);
                cf = src == 0;
            }
            writeOperand(ctx, in.dst, res, bits);
            setSz(ctx, res, bits);
            if (in.op == X86Op::BLSMSK) setFlagsMasked(ctx, 1ULL << 6, 0); // ZF=0 always
            setFlagsMasked(ctx, (1ULL << 0) | (1ULL << 11), cf ? 1ULL : 0ULL);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- BMI1: BEXTR / BZHI (control operand in VEX.vvvv) ----
        case X86Op::BEXTR: {
            const int bits = in.dst.size ? in.dst.size : 32;
            const uint64_t src = readOperand(ctx, in.src, bits);
            const uint64_t ctrl = readOperand(ctx, in.src2, bits);
            const unsigned start = static_cast<unsigned>(ctrl & 0xFF);
            unsigned len = static_cast<unsigned>((ctrl >> 8) & 0xFF);
            uint64_t res = 0;
            if (start < static_cast<unsigned>(bits)) {
                if (len > static_cast<unsigned>(bits) - start) len = static_cast<unsigned>(bits) - start;
                const uint64_t field = (len >= 64) ? ~0ULL : ((1ULL << len) - 1);
                res = maskSize((src >> start) & field, bits);
            }
            writeOperand(ctx, in.dst, res, bits);
            setFlagsMasked(ctx, (1ULL << 0) | (1ULL << 11), 0);
            setFlagsMasked(ctx, 1ULL << 6, res == 0 ? (1ULL << 6) : 0ULL);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::BZHI: {
            const int bits = in.dst.size ? in.dst.size : 32;
            const uint64_t src = readOperand(ctx, in.src, bits);
            const unsigned index = static_cast<unsigned>(readOperand(ctx, in.src2, bits) & 0xFF);
            uint64_t res;
            bool cf;
            if (index >= static_cast<unsigned>(bits)) {
                res = maskSize(src, bits);
                cf = true;
            } else {
                const uint64_t field = (index >= 64) ? ~0ULL : ((1ULL << index) - 1);
                res = maskSize(src & field, bits);
                cf = false;
            }
            writeOperand(ctx, in.dst, res, bits);
            setFlagsMasked(ctx, (1ULL << 0) | (1ULL << 11), cf ? 1ULL : 0ULL);
            setSz(ctx, res, bits);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- Bit scans / byte swap ----
        case X86Op::BSF:
        case X86Op::BSR:
        case X86Op::TZCNT:
        case X86Op::LZCNT: {
            const int bits = in.dst.size ? in.dst.size : 32;
            const uint64_t src = readOperand(ctx, in.src, bits);
            if (in.op == X86Op::BSF || in.op == X86Op::BSR) {
                if (src == 0) {
                    setFlagsMasked(ctx, 0, 1ULL << 6); // ZF=1, destination undefined
                } else {
                    unsigned idx = 0;
                    if (in.op == X86Op::BSF) {
                        while (((src >> idx) & 1) == 0) ++idx;
                    } else {
                        idx = static_cast<unsigned>(bits) - 1;
                        while (((src >> idx) & 1) == 0) --idx;
                    }
                    writeOperand(ctx, in.dst, idx, bits);
                    setFlagsMasked(ctx, 1ULL << 6, 0);
                }
            } else {
                unsigned count;
                if (in.op == X86Op::TZCNT) {
                    count = 0;
                    if (src == 0) count = static_cast<unsigned>(bits);
                    else while (((src >> count) & 1) == 0) ++count;
                } else {
                    count = 0;
                    if (src == 0) count = static_cast<unsigned>(bits);
                    else {
                        count = static_cast<unsigned>(bits);
                        while (count > 0 && ((src >> (count - 1)) & 1) == 0) --count;
                        count = static_cast<unsigned>(bits) - count;
                    }
                }
                writeOperand(ctx, in.dst, count, bits);
                setFlagsMasked(ctx, (1ULL << 0) | (1ULL << 6),
                               (src == 0 ? 1ULL : 0ULL) | (count == 0 ? (1ULL << 6) : 0ULL));
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::BSWAP: {
            const int bits = in.dst.size ? in.dst.size : 32;
            const uint64_t v = readOperand(ctx, in.dst, bits);
            uint64_t res;
            if (bits == 64) res = __builtin_bswap64(v);
            else if (bits == 16) res = static_cast<uint16_t>((v << 8) | (v >> 8));
            else res = __builtin_bswap32(static_cast<uint32_t>(v));
            writeOperand(ctx, in.dst, res, bits);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- BT / BTS / BTR / BTC (bit-string addressing for memory) ----
        case X86Op::BT:
        case X86Op::BTS:
        case X86Op::BTR:
        case X86Op::BTC: {
            const int bits = in.dst.size ? in.dst.size : 32;
            uint64_t idx = readOperand(ctx, in.src, bits);
            const bool mem = in.dst.kind == OperandKind::MEM;
            uint64_t ea = 0;
            uint64_t value = 0;
            if (mem) {
                ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, cur_insn_len_);
                const unsigned per = static_cast<unsigned>(bits / 8);
                ea += static_cast<uint64_t>(idx / static_cast<unsigned>(bits)) * per;
                idx &= static_cast<uint64_t>(bits - 1);
                if (!loadMem(ea, &value, per)) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "bit test: read fault";
                    return r;
                }
            } else {
                idx &= static_cast<uint64_t>(bits - 1);
                value = readOperand(ctx, in.dst, bits);
            }
            const bool bit = ((value >> idx) & 1) != 0;
            setFlagsMasked(ctx, 1ULL << 0, bit ? 1ULL : 0ULL);
            if (in.op != X86Op::BT) {
                const uint64_t mask = 1ULL << idx;
                if (in.op == X86Op::BTS) value |= mask;
                else if (in.op == X86Op::BTR) value &= ~mask;
                else value ^= mask;
                if (mem) {
                    value = maskSize(value, bits);
                    if (!storeMem(ea, &value, static_cast<size_t>(bits / 8))) {
                        r.exit = InterpExit::EXCEPTION;
                        r.exception_code = 0xC0000005;
                        r.exception_msg = "bit test: write fault";
                        return r;
                    }
                } else {
                    writeOperand(ctx, in.dst, value, bits);
                }
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- ARPL (compat mode only) ----
        case X86Op::ARPL: {
            uint64_t d = readOperand(ctx, in.dst, 16);
            const uint64_t s = readOperand(ctx, in.src, 16);
            if ((d & 3) < (s & 3)) {
                d = (d & ~3ULL) | (s & 3);
                writeOperand(ctx, in.dst, d, 16);
                setFlagsMasked(ctx, 0, 1ULL << 6);
            } else {
                setFlagsMasked(ctx, 1ULL << 6, 0);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- BOUND (compat mode only) ----
        case X86Op::BOUND: {
            const int bits = in.dst.size ? in.dst.size : 32;
            const int64_t v = static_cast<int64_t>(readOperand(ctx, in.dst, bits));
            if (in.src.kind == OperandKind::MEM) {
                const uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, cur_insn_len_);
                const size_t half = static_cast<size_t>(bits / 8);
                int64_t lo = 0, hi = 0;
                if (!loadMem(ea, &lo, half) || !loadMem(ea + half, &hi, half)) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "bound: read fault";
                    return r;
                }
                if (bits == 16) {
                    lo = static_cast<int16_t>(lo);
                    hi = static_cast<int16_t>(hi);
                } else {
                    lo = static_cast<int32_t>(lo);
                    hi = static_cast<int32_t>(hi);
                }
                if (v < lo || v > hi) return raiseBoundRange(r);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- MPX bound-register operations ----
        case X86Op::BNDMK: {
            if (in.src.kind == OperandKind::MEM) {
                const int b = in.dst.reg & 3;
                const uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, cur_insn_len_);
                ctx.bnd[b][0] = in.src.mem.base >= 0 ? ctx.gpr[in.src.mem.base] : 0;
                ctx.bnd[b][1] = ~ea;
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::BNDMOV_LOAD: {
            const int b = in.dst.reg & 3;
            if (in.src.kind == OperandKind::REG) {
                const int sb = in.src.reg & 3;
                ctx.bnd[b][0] = ctx.bnd[sb][0];
                ctx.bnd[b][1] = ctx.bnd[sb][1];
            } else if (in.src.kind == OperandKind::MEM) {
                const uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, cur_insn_len_);
                uint64_t pair[2] = {0, 0};
                if (!loadMem(ea, pair, 16)) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "bndmov: load fault";
                    return r;
                }
                ctx.bnd[b][0] = pair[0];
                ctx.bnd[b][1] = pair[1];
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::BNDMOV_STORE: {
            const int b = in.src.reg & 3;
            if (in.dst.kind == OperandKind::REG) {
                const int db = in.dst.reg & 3;
                ctx.bnd[db][0] = ctx.bnd[b][0];
                ctx.bnd[db][1] = ctx.bnd[b][1];
            } else if (in.dst.kind == OperandKind::MEM) {
                const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, cur_insn_len_);
                uint64_t pair[2] = { ctx.bnd[b][0], ctx.bnd[b][1] };
                if (!storeMem(ea, pair, 16)) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "bndmov: store fault";
                    return r;
                }
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::BNDCL:
        case X86Op::BNDCU:
        case X86Op::BNDCN: {
            const int b = in.dst.reg & 3;
            uint64_t addr;
            if (in.src.kind == OperandKind::MEM)
                addr = effectiveAddress(ctx, in.src.mem, ctx.rip, cur_insn_len_);
            else if (in.src.kind == OperandKind::REG)
                addr = readOperand(ctx, in.src, in.rex_w ? 64 : 32);
            else
                addr = 0;
            if (in.op == X86Op::BNDCL) {
                if (addr < ctx.bnd[b][0]) return raiseBoundRange(r);
            } else if (in.op == X86Op::BNDCU) {
                if (addr > ~ctx.bnd[b][1]) return raiseBoundRange(r);
            } else {
                if (addr > ctx.bnd[b][1]) return raiseBoundRange(r);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::BNDLDX: {
            // No bound tables are modelled: an absent/mismatched BTE yields the
            // architectural INIT bounds {LB=0, UB=0} (the 0 UB admits all
            // addresses once complemented).
            const int b = in.dst.reg & 3;
            ctx.bnd[b][0] = 0;
            ctx.bnd[b][1] = 0;
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::BNDSTX: {
            // Bound-table store: nothing to write without tables.
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- Flag control ----
        case X86Op::CLC:
        case X86Op::STC:
        case X86Op::CLI:
        case X86Op::STI:
        case X86Op::CLD:
        case X86Op::STD:
        case X86Op::CLAC:
        case X86Op::STAC: {
            uint64_t bit = 0;
            bool set = true;
            switch (in.op) {
                case X86Op::CLC:  bit = 1ULL << 0;  set = false; break;
                case X86Op::STC:  bit = 1ULL << 0;  break;
                case X86Op::CLI:  bit = 1ULL << 9;  set = false; break;
                case X86Op::STI:  bit = 1ULL << 9;  break;
                case X86Op::CLD:  bit = 1ULL << 10; set = false; break;
                case X86Op::STD:  bit = 1ULL << 10; break;
                case X86Op::CLAC: bit = 1ULL << 18; set = false; break;
                default:          bit = 1ULL << 18; break; // STAC
            }
            setFlagsMasked(ctx, set ? 0 : bit, set ? bit : 0);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- Cache hints: no architectural state ----
        case X86Op::CLDEMOTE:
        case X86Op::CLFLUSH:
        case X86Op::CLFLUSHOPT:
        case X86Op::CLWB: {
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- Sign-extension idioms ----
        case X86Op::CBW: {
            const int8_t v = static_cast<int8_t>(ctx.rax() & 0xFF);
            ctx.rax() = (ctx.rax() & ~0xFFFFULL) | static_cast<uint16_t>(static_cast<int16_t>(v));
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CWDE: {
            const int16_t v = static_cast<int16_t>(ctx.rax() & 0xFFFF);
            ctx.rax() = (ctx.rax() & ~0xFFFFFFFFULL) | static_cast<uint32_t>(static_cast<int32_t>(v));
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CDQE: {
            ctx.rax() = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(ctx.rax())));
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::ROL: case X86Op::ROR: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t c = readOperand(ctx, in.src, 8) & (bits == 64 ? 63u : 31u);
            if (c) {
                int sh = static_cast<int>(c % static_cast<uint64_t>(bits));
                uint64_t res;
                if (in.op == X86Op::ROL)
                    res = maskSize((a << sh) | (a >> (bits - sh)), bits);
                else
                    res = maskSize((a >> sh) | (a << (bits - sh)), bits);
                writeOperand(ctx, in.dst, res, bits);
                // CF/OF per rotate definition; keep other flags
                uint64_t rf = flags_.materialize();
                uint64_t cf = (in.op == X86Op::ROL) ? (res & 1)
                                                    : ((res >> (bits - 1)) & 1);
                uint64_t of = (in.op == X86Op::ROL)
                    ? ((res >> (bits - 1)) & 1) ^ cf
                    : (((res >> (bits - 1)) ^ (res >> (bits - 2))) & 1);
                rf &= ~(1ULL << 0);
                if (cf) rf |= 1ULL << 0;
                rf &= ~(1ULL << 11);
                if (of) rf |= 1ULL << 11;
                flags_.setRaw(rf);
                syncFlags(ctx);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CMOV: {
            if (evalCc(ctx, in.cc)) {
                uint64_t v = readOperand(ctx, in.src, bits);
                writeOperand(ctx, in.dst, v, bits);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SETCC: {
            writeOperand(ctx, in.dst, evalCc(ctx, in.cc) ? 1 : 0, 8);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::MOVD: {
            // Decoder encodes direction via operand sizes/kinds:
            // reg(16+) dst + imm/mem/reg src = load; mem dst = store.
            int n = in.dst.size ? in.dst.size : 64;
            auto set_xmm = [&](int reg, uint64_t v) {
                uint64_t z = 0;
                std::memcpy(ctx.ymm[reg - 16], &z, 8);   // MOVD clears upper bits
                std::memcpy(ctx.ymm[reg - 16], &v, n / 8);
            };
            if (in.dst.kind == OperandKind::REG && in.dst.reg >= 16) {
                uint64_t v;
                if (in.src.kind == OperandKind::REG && in.src.reg >= 16) {
                    std::memcpy(&v, ctx.ymm[in.src.reg - 16], n / 8);
                } else {
                    v = readOperand(ctx, in.src, n);
                }
                set_xmm(in.dst.reg, v);
            } else {
                // store: dst = mem/gpr, src = xmm
                uint64_t v = 0;
                std::memcpy(&v, ctx.ymm[in.src.reg - 16], n / 8);
                writeOperand(ctx, in.dst, v, n);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SSE_MOV: {
            // 128-bit move: xmm <-> mem, or xmm <-> xmm
            if (in.dst.kind == OperandKind::REG && in.dst.reg >= 16) {
                if (in.src.kind == OperandKind::MEM) {
                    uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, in.length);
                    uint8_t buf[16]{};
                    if (!loadMem(ea, buf, 16)) {
                        r.exit = InterpExit::EXCEPTION;
                        r.exception_code = 0xC0000005;
                        r.exception_msg = "sse load fault";
                        return r;
                    }
                    std::memcpy(ctx.ymm[in.dst.reg - 16], buf, 16);
                } else if (in.src.kind == OperandKind::REG && in.src.reg >= 16) {
                    std::memcpy(ctx.ymm[in.dst.reg - 16], ctx.ymm[in.src.reg - 16], 16);
                }
            } else {
                // 0F 11/29/7F are the full 128-bit stores. The narrower
                // MOVLPS/MOVHPS/MOVQ stores have their own opcodes, so the
                // memory operand's decoder size (a GPR default of 32 bits)
                // must not shrink this store to four bytes.
                size_t n = 16;
                if (in.dst.kind == OperandKind::MEM) {
                    uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
                    if (!storeMem(ea, ctx.ymm[in.src.reg - 16], n)) {
                        r.exit = InterpExit::EXCEPTION;
                        r.exception_code = 0xC0000005;
                        r.exception_msg = "sse store fault";
                        return r;
                    }
                } else if (in.dst.kind == OperandKind::REG && in.dst.reg >= 16) {
                    int d = in.dst.reg - 16, s = in.src.reg - 16;
                    if (d != s) std::memcpy(ctx.ymm[d], ctx.ymm[s], 16);
                }
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::PXOR: {
            // dst ^= src over all 128 bits
            int dreg = in.dst.reg - 16, sreg = in.src.reg - 16;
            if (dreg != sreg) {
                uint64_t tmp[2];
                std::memcpy(tmp, ctx.ymm[sreg], 16);
                uint64_t* d = reinterpret_cast<uint64_t*>(ctx.ymm[dreg]);
                d[0] ^= tmp[0];
                d[1] ^= tmp[1];
            } else {
                std::memset(ctx.ymm[dreg], 0, 16);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::PUNPCKLDQ: {
            // PUNPCKLDQ: preserves dwords 0/1 of dst, interleaves src low dwords
            int dreg = in.dst.reg - 16, sreg = in.src.reg - 16;
            uint64_t dst0, dst1, src0, src1;
            std::memcpy(&dst0, &ctx.ymm[dreg], 8);
            std::memcpy(&dst1, &ctx.ymm[dreg] + 8, 8);
            std::memcpy(&src0, &ctx.ymm[sreg], 8);
            std::memcpy(&src1, &ctx.ymm[sreg] + 8, 8);
            uint64_t lo = (src0 & 0xFFFFFFFF) << 32 | (dst0 & 0xFFFFFFFF);
            uint64_t hi = (src1 & 0xFFFFFFFF) << 32 | (dst1 & 0xFFFFFFFF);
            std::memcpy(ctx.ymm[dreg], &lo, 8);
            std::memcpy(ctx.ymm[dreg] + 8, &hi, 8);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::PUNPCKLQDQ: case X86Op::PUNPCKHQDQ: {
            int dreg = in.dst.reg - 16, sreg = in.src.reg - 16;
            uint64_t dst0, dst1, src0, src1;
            std::memcpy(&dst0, &ctx.ymm[dreg], 8);
            std::memcpy(&dst1, ctx.ymm[dreg] + 8, 8);
            std::memcpy(&src0, &ctx.ymm[sreg], 8);
            std::memcpy(&src1, ctx.ymm[sreg] + 8, 8);
            uint64_t lo, hi;
            if (in.op == X86Op::PUNPCKLQDQ) { lo = dst0; hi = src0; }
            else { lo = dst1; hi = src1; }
            std::memcpy(ctx.ymm[dreg], &lo, 8);
            std::memcpy(ctx.ymm[dreg] + 8, &hi, 8);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::MOVLPS_LOAD: case X86Op::MOVHPS_LOAD: {
            int d = in.dst.reg - 16;
            uint8_t tmp[8];
            int off = (in.op == X86Op::MOVHPS_LOAD) ? 8 : 0;
            if (in.src.kind == OperandKind::MEM) {
                uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, in.length);
                if (!loadMem(ea, tmp, 8)) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "fault";
                    return r;
                }
            } else if (in.src.kind == OperandKind::REG && in.src.reg >= 16) {
                std::memcpy(tmp, ctx.ymm[in.src.reg - 16] + off, 8);
            } else {
                return InterpResult{};
            }
            std::memcpy(ctx.ymm[d] + off, tmp, 8);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::MOVLPS_STORE: case X86Op::MOVHPS_STORE: {
            int s = in.src.reg - 16;
            int off = (in.op == X86Op::MOVHPS_STORE) ? 8 : 0;
            uint8_t tmp[8];
            std::memcpy(tmp, ctx.ymm[s] + off, 8);
            if (in.dst.kind == OperandKind::MEM) {
                uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
                if (!storeMem(ea, tmp, 8)) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "fault";
                    return r;
                }
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // ================= compare / convert / system batch =================

        case X86Op::CMC: {
            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            flags_.setRaw(rf ^ 1ULL);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        // Privileged / OS-only instructions. NINE runs guests at CPL 3 with
        // CR4 = 0x668 (no CET, no UINTR), so these raise exactly the fault the
        // hardware would: CLTS #GP(0), CLUI/CLRSSBSY #UD (feature disabled).
        case X86Op::CLTS: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC0000096; // STATUS_PRIVILEGED_INSTRUCTION
            r.exception_msg = "clts: #GP(0) — CR0.TS is kernel state at CPL 3";
            return r;
        }

        case X86Op::CLUI: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D; // #UD
            r.exception_msg = "clui: #UD — CR4.UINTR is clear in this CPU model";
            return r;
        }

        case X86Op::CLRSSBSY: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D; // #UD
            r.exception_msg = "clrssbsy: #UD — CR4.CET is clear in this CPU model";
            return r;
        }

        // CMPS m8/m16/m32/m64: [RSI] - [RDI], both pointers advanced by DF.
        // F3 (REPE) repeats while equal, F2 (REPNE) while unequal.
        case X86Op::CMPS: {
            const int size_bits = in.dst.size ? in.dst.size : 8;
            const int nbytes = size_bits / 8;
            auto do_one = [&]() -> bool {
                const uint64_t si = ctx.rsi();
                const uint64_t di = ctx.rdi();
                uint64_t a = 0, b = 0;
                if (!loadMem(si, &a, static_cast<size_t>(nbytes))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "cmps: source read fault";
                    return false;
                }
                if (!loadMem(di, &b, static_cast<size_t>(nbytes))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "cmps: destination read fault";
                    return false;
                }
                a = maskSize(a, size_bits);
                b = maskSize(b, size_bits);
                flags_.setFromSub(maskSize(a - b, size_bits), a, b,
                                  static_cast<uint8_t>(size_bits));
                syncFlags(ctx);
                const bool df = (ctx.rflags & (1ULL << 10)) != 0;
                ctx.rsi() = si + (df ? -nbytes : nbytes);
                ctx.rdi() = di + (df ? -nbytes : nbytes);
                return true;
            };
            if (in.rep || in.repne) {
                while (ctx.rcx() != 0) {
                    if (!do_one()) return r;
                    ctx.rcx() -= 1;
                    if (in.repne ? flags_.isZero() : !flags_.isZero()) break;
                }
            } else if (!do_one()) {
                return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // 0F C2 /r ib — packed/scalar FP compare; result lanes are all-ones
        // (true) or all-zeros (false). Scalar forms leave the upper lanes alone.
        case X86Op::CMPPS:
        case X86Op::CMPPD:
        case X86Op::CMPSS:
        case X86Op::CMPSD_SSE: {
            const bool single = (in.op == X86Op::CMPPS || in.op == X86Op::CMPSS);
            const bool scalar = (in.op == X86Op::CMPSS || in.op == X86Op::CMPSD_SSE);
            const int lane_bytes = single ? 4 : 8;
            const int lanes = scalar ? 1 : (single ? 4 : 2);
            const int pred = static_cast<int>(in.src2.imm & 7);
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, scalar ? lane_bytes : 16))
                return sseFault("cmp");
            for (int k = 0; k < lanes; ++k) {
                if (single) {
                    float x, y;
                    std::memcpy(&x, a + 4 * k, 4);
                    std::memcpy(&y, b + 4 * k, 4);
                    const bool unord = std::isnan(x) || std::isnan(y);
                    const uint32_t mask = cmpPredicate(pred, unord, x < y, x <= y, x == y)
                                              ? 0xFFFFFFFFu : 0u;
                    std::memcpy(a + 4 * k, &mask, 4);
                } else {
                    double x, y;
                    std::memcpy(&x, a + 8 * k, 8);
                    std::memcpy(&y, b + 8 * k, 8);
                    const bool unord = std::isnan(x) || std::isnan(y);
                    const uint64_t mask = cmpPredicate(pred, unord, x < y, x <= y, x == y)
                                              ? ~0ULL : 0ULL;
                    std::memcpy(a + 8 * k, &mask, 8);
                }
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // COMISS/COMISD — ordered compare into ZF/PF/CF, every other flag
        // cleared. NaN => unordered => ZF=PF=CF=1 (+ #IA on real hardware,
        // which NINE does not model).
        case X86Op::COMISS:
        case X86Op::COMISD:
        case X86Op::UCOMISS:
        case X86Op::UCOMISD: {
            const bool single = (in.op == X86Op::COMISS || in.op == X86Op::UCOMISS);
            const int nbytes = single ? 4 : 8;
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, nbytes)) return sseFault("comi");
            double x, y;
            if (single) {
                float fx, fy;
                std::memcpy(&fx, a, 4);
                std::memcpy(&fy, b, 4);
                x = fx;
                y = fy;
            } else {
                std::memcpy(&x, a, 8);
                std::memcpy(&y, b, 8);
            }
            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            rf &= ~((1ULL << 0) | (1ULL << 2) | (1ULL << 4) | (1ULL << 6) |
                    (1ULL << 7) | (1ULL << 11));
            if (std::isnan(x) || std::isnan(y)) rf |= (1ULL << 0) | (1ULL << 2) | (1ULL << 6);
            else if (x < y) rf |= 1ULL << 0;
            else if (x == y) rf |= 1ULL << 6;
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        // CMPXCHG8B/CMPXCHG16B — EDX:EAX (RDX:RAX) against one memory block.
        // Equal: ZF=1 and RCX:RBX is stored; otherwise the memory value is
        // loaded back into the accumulator pair and ZF=0.
        case X86Op::CMPXCHG8B:
        case X86Op::CMPXCHG16B: {
            const int nbytes = (in.op == X86Op::CMPXCHG16B) ? 16 : 8;
            if (in.dst.kind != OperandKind::MEM) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC000001D;
                r.exception_msg = "cmpxchg: register operand is #UD";
                return r;
            }
            const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
            if (nbytes == 16 && (ea & 15)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "cmpxchg16b: unaligned block (#GP)";
                return r;
            }
            using U128 = unsigned __int128;
            U128 blk = 0;
            if (!loadMem(ea, &blk, static_cast<size_t>(nbytes))) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "cmpxchg: block read fault";
                return r;
            }
            // The accumulator pair is EDX:EAX (32-bit) or RDX:RAX (64-bit);
            // the memory block is the same shape in little-endian order.
            const int half_bits = nbytes * 4;
            const U128 half_mask = (nbytes == 16) ? ~static_cast<U128>(0)
                                                  : static_cast<U128>(0xFFFFFFFFu);
            Operand acc_lo;
            acc_lo.kind = OperandKind::REG;
            acc_lo.reg = 0;              // EAX / RAX
            acc_lo.size = half_bits;
            Operand acc_hi;
            acc_hi.kind = OperandKind::REG;
            acc_hi.reg = 2;              // EDX / RDX
            acc_hi.size = half_bits;
            const U128 acc = (static_cast<U128>(readOperand(ctx, acc_hi, half_bits)) << half_bits) |
                             readOperand(ctx, acc_lo, half_bits);
            const U128 mem_lo = blk & half_mask;
            const U128 mem_hi = (blk >> half_bits) & half_mask;
            if (acc == blk) {
                const U128 out = ((static_cast<U128>(maskSize(ctx.rcx(), half_bits)) << half_bits) |
                                  maskSize(ctx.rbx(), half_bits));
                if (!storeMem(ea, &out, static_cast<size_t>(nbytes))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "cmpxchg: block write fault";
                    return r;
                }
                setFlagsMasked(ctx, (1ULL << 6), (1ULL << 6));
            } else {
                writeOperand(ctx, acc_lo, static_cast<uint64_t>(mem_lo), half_bits);
                writeOperand(ctx, acc_hi, static_cast<uint64_t>(mem_hi), half_bits);
                setFlagsMasked(ctx, (1ULL << 6), 0);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CPUID: {
            uint32_t out[4];
            synthCpuid(static_cast<uint32_t>(ctx.rax()),
                       static_cast<uint32_t>(ctx.rcx()), out);
            ctx.rax() = out[0];
            ctx.rbx() = out[1];
            ctx.rcx() = out[2];
            ctx.rdx() = out[3];
            ctx.rip = r.next_pc;
            return r;
        }

        // CRC32 r32/r64, r/m8|16|32|64 — CRC-32C update seeded by the
        // destination. The 32-bit result zero-extends into a 64-bit register.
        case X86Op::CRC32: {
            const int src_bits = in.src.size ? in.src.size : 8;
            const uint64_t v = readOperand(ctx, in.src, src_bits);
            if (in.src.kind == OperandKind::MEM && mem_fault_) return sseFault("crc32");
            uint32_t crc = static_cast<uint32_t>(readOperand(ctx, in.dst, 32));
            for (int k = 0; k < src_bits / 8; ++k)
                crc = crc32cUpdate(crc, static_cast<uint8_t>((v >> (8 * k)) & 0xFF));
            writeOperand(ctx, in.dst, crc, in.dst.size ? in.dst.size : 32);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CVTDQ2PD: {
            uint8_t s[16], out[16];
            if (!loadSseSource(ctx, in.src, s, 8)) return sseFault("cvtdq2pd");
            for (int k = 0; k < 2; ++k) {
                int32_t v;
                std::memcpy(&v, s + 4 * k, 4);
                const double d = static_cast<double>(v);
                std::memcpy(out + 8 * k, &d, 8);
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CVTDQ2PS: {
            uint8_t s[16], out[16];
            if (!loadSseSource(ctx, in.src, s, 16)) return sseFault("cvtdq2ps");
            for (int k = 0; k < 4; ++k) {
                int32_t v;
                std::memcpy(&v, s + 4 * k, 4);
                const float f = static_cast<float>(v);
                std::memcpy(out + 4 * k, &f, 4);
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CVTPS2DQ: {
            uint8_t s[16], out[16];
            if (!loadSseSource(ctx, in.src, s, 16)) return sseFault("cvtps2dq");
            bool bad = false;
            for (int k = 0; k < 4; ++k) {
                float f;
                std::memcpy(&f, s + 4 * k, 4);
                uint32_t v = 0;
                if (!toI32(roundHalfEven(static_cast<double>(f)), v)) {
                    v = 0x80000000u;
                    bad = true;
                }
                std::memcpy(out + 4 * k, &v, 4);
            }
            writeXmm(ctx, in.dst.reg, out);
            setFlagsMasked(ctx, 1ULL, bad ? 1ULL : 0ULL);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CVTTPD2DQ: {
            uint8_t s[16], out[16] = {0};
            if (!loadSseSource(ctx, in.src, s, 16)) return sseFault("cvttpd2dq");
            bool bad = false;
            for (int k = 0; k < 2; ++k) {
                double d;
                std::memcpy(&d, s + 8 * k, 8);
                uint32_t v = 0;
                if (!toI32(std::trunc(d), v)) {
                    v = 0x80000000u;
                    bad = true;
                }
                std::memcpy(out + 4 * k, &v, 4);
            }
            writeXmm(ctx, in.dst.reg, out);
            setFlagsMasked(ctx, 1ULL, bad ? 1ULL : 0ULL);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CVTPS2PD: {
            uint8_t s[16], out[16];
            if (!loadSseSource(ctx, in.src, s, 8)) return sseFault("cvtps2pd");
            for (int k = 0; k < 2; ++k) {
                float f;
                std::memcpy(&f, s + 4 * k, 4);
                const double d = static_cast<double>(f);
                std::memcpy(out + 8 * k, &d, 8);
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CVTSD2SS: {
            uint8_t s[16], a[16];
            if (!loadSseSource(ctx, in.src, s, 8)) return sseFault("cvtsd2ss");
            double d;
            std::memcpy(&d, s, 8);
            const float f = static_cast<float>(d);
            readXmm(ctx, in.dst.reg, a);
            std::memcpy(a, &f, 4); // upper 96 bits unchanged (legacy SSE)
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CVTSS2SD: {
            uint8_t s[16], a[16];
            if (!loadSseSource(ctx, in.src, s, 4)) return sseFault("cvtss2sd");
            float f;
            std::memcpy(&f, s, 4);
            const double d = static_cast<double>(f);
            readXmm(ctx, in.dst.reg, a);
            std::memcpy(a, &d, 8); // upper 64 bits unchanged (legacy SSE)
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CVTSD2SI:
        case X86Op::CVTSS2SI: {
            const bool single = (in.op == X86Op::CVTSS2SI);
            uint8_t s[16];
            if (!loadSseSource(ctx, in.src, s, single ? 4 : 8)) return sseFault("cvt2si");
            double x;
            if (single) {
                float f;
                std::memcpy(&f, s, 4);
                x = f;
            } else {
                std::memcpy(&x, s, 8);
            }
            const int bits_dst = in.dst.size ? in.dst.size : 32;
            bool ok;
            uint64_t v;
            if (bits_dst == 64) {
                ok = toI64(roundHalfEven(x), v);
                if (!ok) v = 0x8000000000000000ULL;
            } else {
                uint32_t v32;
                ok = toI32(roundHalfEven(x), v32);
                v = ok ? v32 : 0x80000000ULL;
            }
            writeOperand(ctx, in.dst, v, bits_dst);
            setFlagsMasked(ctx, 1ULL, ok ? 0ULL : 1ULL);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CVTSI2SD: {
            const int src_bits = in.src.size ? in.src.size : 32;
            const uint64_t raw = readOperand(ctx, in.src, src_bits);
            if (in.src.kind == OperandKind::MEM && mem_fault_) return sseFault("cvtsi2sd");
            const int64_t sv = (src_bits == 64) ? static_cast<int64_t>(raw)
                                                : static_cast<int64_t>(static_cast<int32_t>(raw));
            const double d = static_cast<double>(sv);
            uint8_t a[16];
            readXmm(ctx, in.dst.reg, a);
            std::memcpy(a, &d, 8); // upper 64 bits unchanged
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CVTSI2SS: {
            const int src_bits = in.src.size ? in.src.size : 32;
            const uint64_t raw = readOperand(ctx, in.src, src_bits);
            if (in.src.kind == OperandKind::MEM && mem_fault_) return sseFault("cvtsi2ss");
            const int64_t sv = (src_bits == 64) ? static_cast<int64_t>(raw)
                                                : static_cast<int64_t>(static_cast<int32_t>(raw));
            const float f = static_cast<float>(sv);
            uint8_t a[16];
            readXmm(ctx, in.dst.reg, a);
            std::memcpy(a, &f, 4); // upper 96 bits unchanged
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- x87 escape group -------------------------------------------
        case X86Op::X87:
            return executeX87(ctx, in);

        // EMMS empties the x87/MMX tag word (the values stay in the registers).
        case X86Op::EMMS: {
            ctx.fpu.tw = 0xFFFF;
            ctx.rip = r.next_pc;
            return r;
        }

        // CET landing pads are architectural no-ops.
        case X86Op::ENDBR: {
            ctx.rip = r.next_pc;
            return r;
        }

        // HLT stops the guest cleanly instead of faulting: the sandbox is the
        // only code running, and BlockExitReason::HALT is what the loop wants.
        case X86Op::HLT: {
            ctx.rip = r.next_pc;
            r.exit = InterpExit::HALT;
            return r;
        }

        // ---- DAA / DAS (legacy BCD adjust) -------------------------------
        case X86Op::DAA:
        case X86Op::DAS: {
            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            const bool sub = (in.op == X86Op::DAS);
            const uint8_t old_al = static_cast<uint8_t>(ctx.rax() & 0xFF);
            const bool old_cf = ((rf >> 0) & 1) != 0;
            const bool old_af = ((rf >> 4) & 1) != 0;
            uint8_t al = old_al;
            bool cf = false;
            bool af = false;
            if ((al & 0x0F) > 9 || old_af) {
                if (sub) { cf = old_cf || al < 6; al = static_cast<uint8_t>(al - 6); }
                else     { cf = old_cf || al > 0xF9; al = static_cast<uint8_t>(al + 6); }
                af = true;
            }
            if (old_al > 0x99 || old_cf) {
                al = static_cast<uint8_t>(sub ? (al - 0x60) : (al + 0x60));
                cf = true;
            }
            ctx.rax() = (ctx.rax() & ~0xFFULL) | al;
            rf &= ~((1ULL << 0) | (1ULL << 2) | (1ULL << 4) | (1ULL << 6) |
                    (1ULL << 7) | (1ULL << 11));
            if (cf) rf |= 1ULL << 0;
            if (af) rf |= 1ULL << 4;
            if (al == 0) rf |= 1ULL << 6;
            if (al & 0x80) rf |= 1ULL << 7;
            uint8_t p = al;
            p ^= static_cast<uint8_t>(p >> 4);
            p ^= static_cast<uint8_t>(p >> 2);
            p ^= static_cast<uint8_t>(p >> 1);
            if (!(p & 1)) rf |= 1ULL << 2;
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- ENTER imm16, imm8 ------------------------------------------
        case X86Op::ENTER: {
            const uint64_t frame = static_cast<uint64_t>(in.src.imm) & 0xFFFF;
            const unsigned level = static_cast<unsigned>(in.src2.imm) & 0x1F;
            auto push64 = [&](uint64_t v) {
                ctx.rsp() -= 8;
                storeMem(ctx.rsp(), &v, 8);
            };
            if (level != 0) {
                push64(ctx.rbp());
                const uint64_t frame_temp = ctx.rsp();
                for (unsigned lvl = 1; lvl < level; ++lvl) {
                    ctx.rbp() -= 8;
                    uint64_t v = 0;
                    loadMem(ctx.rbp(), &v, 8);
                    push64(v);
                }
                push64(frame_temp);
                ctx.rbp() = frame_temp;
            }
            ctx.rsp() -= frame;
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- SSE/SSE2 divides -------------------------------------------
        case X86Op::DIVPS:
        case X86Op::DIVPD:
        case X86Op::DIVSS:
        case X86Op::DIVSD: {
            const bool single = (in.op == X86Op::DIVPS || in.op == X86Op::DIVSS);
            const bool scalar = (in.op == X86Op::DIVSS || in.op == X86Op::DIVSD);
            const int lane = single ? 4 : 8;
            const int lanes = scalar ? 1 : (single ? 4 : 2);
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, scalar ? lane : 16)) return sseFault("div");
            for (int k = 0; k < lanes; ++k) {
                if (single) {
                    float x, y;
                    std::memcpy(&x, a + 4 * k, 4);
                    std::memcpy(&y, b + 4 * k, 4);
                    const float z = x / y;
                    std::memcpy(a + 4 * k, &z, 4);
                } else {
                    double x, y;
                    std::memcpy(&x, a + 8 * k, 8);
                    std::memcpy(&y, b + 8 * k, 8);
                    const double z = x / y;
                    std::memcpy(a + 8 * k, &z, 8);
                }
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- horizontal add / subtract ----------------------------------
        case X86Op::HADDPS:
        case X86Op::HSUBPS:
        case X86Op::HADDPD:
        case X86Op::HSUBPD: {
            const bool single = (in.op == X86Op::HADDPS || in.op == X86Op::HSUBPS);
            const bool sub = (in.op == X86Op::HSUBPS || in.op == X86Op::HSUBPD);
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("hadd");
            uint8_t out[16] = {};
            if (single) {
                float x[8];
                std::memcpy(x, a, 16);
                std::memcpy(x + 4, b, 16);
                for (int k = 0; k < 4; ++k) {
                    const float v = sub ? (x[2 * k] - x[2 * k + 1]) : (x[2 * k] + x[2 * k + 1]);
                    std::memcpy(out + 4 * k, &v, 4);
                }
            } else {
                double x[4];
                std::memcpy(x, a, 16);
                std::memcpy(x + 2, b, 16);
                for (int k = 0; k < 2; ++k) {
                    const double v = sub ? (x[2 * k] - x[2 * k + 1]) : (x[2 * k] + x[2 * k + 1]);
                    std::memcpy(out + 8 * k, &v, 8);
                }
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- DPPS / DPPD -------------------------------------------------
        case X86Op::DPPS:
        case X86Op::DPPD: {
            const bool single = (in.op == X86Op::DPPS);
            const int lanes = single ? 4 : 2;
            const uint8_t imm = static_cast<uint8_t>(in.src2.imm);
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("dpp");
            if (single) {
                float sum = 0.0f;
                for (int k = 0; k < lanes; ++k) {
                    if (!((imm >> k) & 1)) continue;
                    float x, y;
                    std::memcpy(&x, a + 4 * k, 4);
                    std::memcpy(&y, b + 4 * k, 4);
                    sum += x * y;
                }
                uint8_t out[16] = {};
                for (int k = 0; k < lanes; ++k) {
                    const float v = ((imm >> (4 + k)) & 1) ? sum : 0.0f;
                    std::memcpy(out + 4 * k, &v, 4);
                }
                writeXmm(ctx, in.dst.reg, out);
            } else {
                double sum = 0.0;
                for (int k = 0; k < lanes; ++k) {
                    if (!((imm >> k) & 1)) continue;
                    double x, y;
                    std::memcpy(&x, a + 8 * k, 8);
                    std::memcpy(&y, b + 8 * k, 8);
                    sum += x * y;
                }
                uint8_t out[16] = {};
                for (int k = 0; k < lanes; ++k) {
                    const double v = ((imm >> (4 + k)) & 1) ? sum : 0.0;
                    std::memcpy(out + 8 * k, &v, 8);
                }
                writeXmm(ctx, in.dst.reg, out);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- EXTRACTPS ---------------------------------------------------
        case X86Op::EXTRACTPS: {
            uint8_t a[16];
            readXmm(ctx, in.src.reg, a);
            const int idx = static_cast<int>(in.src2.imm) & 3;
            uint32_t v = 0;
            std::memcpy(&v, a + 4 * idx, 4);
            writeOperand(ctx, in.dst, v, 32);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- GFNI --------------------------------------------------------
        case X86Op::GF2P8MULB:
        case X86Op::GF2P8AFFINEQB:
        case X86Op::GF2P8AFFINEINVQB: {
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("gfni");
            auto gfMul = [](uint8_t x, uint8_t y) {
                unsigned p = 0;
                for (int i = 0; i < 8; ++i) {
                    if ((y >> i) & 1) p ^= static_cast<unsigned>(x) << i;
                }
                for (int i = 14; i >= 8; --i) {
                    if ((p >> i) & 1) p ^= 0x11Bu << (i - 8);
                }
                return static_cast<uint8_t>(p & 0xFF);
            };
            if (in.op == X86Op::GF2P8MULB) {
                for (int k = 0; k < 16; ++k) a[k] = gfMul(a[k], b[k]);
                writeXmm(ctx, in.dst.reg, a);
                ctx.rip = r.next_pc;
                return r;
            }
            // Affine transform: row i of the matrix is byte (7-i) of the
            // selected qword of the second source; imm8[7] is the addend bit.
            const int q = static_cast<int>(in.src2.imm & 1);
            uint64_t matrix = 0;
            std::memcpy(&matrix, b + 8 * q, 8);
            const uint8_t addend = static_cast<uint8_t>((in.src2.imm >> 7) & 1);
            auto inv = [&](uint8_t x) -> uint8_t {
                if (x == 0) return 0;
                for (unsigned y = 1; y < 256; ++y)
                    if (gfMul(x, static_cast<uint8_t>(y)) == 1) return static_cast<uint8_t>(y);
                return 0;
            };
            uint8_t out[16];
            for (int k = 0; k < 16; ++k) {
                uint8_t x = a[k];
                if (in.op == X86Op::GF2P8AFFINEINVQB) x = inv(x);
                uint8_t res = 0;
                for (int i = 0; i < 8; ++i) {
                    const uint8_t row = static_cast<uint8_t>(matrix >> (8 * (7 - i)));
                    uint8_t t = static_cast<uint8_t>(row & x);
                    t ^= static_cast<uint8_t>(t >> 4);
                    t ^= static_cast<uint8_t>(t >> 2);
                    t ^= static_cast<uint8_t>(t >> 1);
                    const uint8_t bit = static_cast<uint8_t>((t & 1) ^ addend);
                    res = static_cast<uint8_t>(res | (bit << i));
                }
                out[k] = res;
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- enqueue-command / Key Locker / history reset ----------------
        case X86Op::ENQCMD:
        case X86Op::ENQCMDS:
        case X86Op::ENCODEKEY128:
        case X86Op::ENCODEKEY256: {
            // These need CR4.ENQCMD / CR4.KL. NINE never sets those bits, so
            // the guest gets the same #UD real silicon raises without them.
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D;
            r.exception_msg = in.mnemonic + ": CR4 feature bit is clear (#UD)";
            return r;
        }

        case X86Op::HRESET: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC0000005;
            r.exception_msg = "hreset: #GP(0) without CR4.HRESET / CPL 0";
            return r;
        }

        // ---- truncating scalar converts ---------------------------------
        case X86Op::CVTTSS2SI:
        case X86Op::CVTTSD2SI: {
            const bool single = (in.op == X86Op::CVTTSS2SI);
            const int nbytes = single ? 4 : 8;
            uint8_t src[16];
            if (!loadSseSource(ctx, in.src, src, nbytes)) return sseFault("cvtt");
            const int bits = in.dst.size ? in.dst.size : 32;
            bool ok = true;
            if (single) {
                float x;
                std::memcpy(&x, src, 4);
                if (!std::isfinite(x) || x >= 2147483648.0f || x < -2147483648.0f) ok = false;
                else {
                    const int32_t v = static_cast<int32_t>(x);   // truncation
                    if (bits == 64) writeOperand(ctx, in.dst, static_cast<uint64_t>(static_cast<int64_t>(v)), 64);
                    else writeOperand(ctx, in.dst, static_cast<uint32_t>(v), 32);
                }
            } else {
                double x;
                std::memcpy(&x, src, 8);
                if (bits == 64) {
                    if (!std::isfinite(x) || x >= 9223372036854775808.0 || x < -9223372036854775808.0)
                        ok = false;
                    else
                        writeOperand(ctx, in.dst,
                                     static_cast<uint64_t>(static_cast<int64_t>(x)), 64);
                } else {
                    if (!std::isfinite(x) || x >= 2147483648.0 || x < -2147483648.0) ok = false;
                    else writeOperand(ctx, in.dst, static_cast<uint32_t>(static_cast<int32_t>(x)), 32);
                }
            }
            if (!ok) {
                // Integer indefinite pattern plus CF, exactly like CVTSS2SI.
                const uint64_t ind = (bits == 64) ? 0x8000000000000000ULL : 0x80000000ULL;
                writeOperand(ctx, in.dst, ind, bits);
                uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
                flags_.setRaw(rf | 1ULL);
                syncFlags(ctx);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- FXSAVE / FXRSTOR (512-byte x87 + SSE image) -----------------
        case X86Op::FXSAVE: {
            const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
            uint8_t img[512];
            std::memset(img, 0, sizeof(img));
            std::memcpy(img + 0, &ctx.fpu.cw, 2);
            std::memcpy(img + 2, &ctx.fpu.sw, 2);
            uint8_t abridged = 0;
            for (int i = 0; i < 8; ++i)
                if (ctx.fpu.tagOfSt(i) != x87::TAG_EMPTY) abridged |= static_cast<uint8_t>(1u << i);
            img[4] = abridged;
            // MXCSR is live (LDMXCSR/FXRSTOR can change it), but FTZ/DAZ and
            // the exception masks are not applied to SSE arithmetic yet.
            const uint32_t mxmask = 0xFFFF;
            std::memcpy(img + 24, &ctx.mxcsr, 4);
            std::memcpy(img + 28, &mxmask, 4);
            for (int i = 0; i < 8; ++i) {
                const x87::Val& v = ctx.fpu.sti(i);
                std::memcpy(img + 32 + 16 * i, &v.sig, 8);
                std::memcpy(img + 32 + 16 * i + 8, &v.se, 2);
            }
            for (int i = 0; i < 16; ++i) std::memcpy(img + 160 + 16 * i, ctx.ymm[i], 16);
            if (!storeMem(ea, img, sizeof(img))) return sseFault("fxsave");
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::FXRSTOR: {
            const uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, in.length);
            uint8_t img[512];
            if (!loadMem(ea, img, sizeof(img))) return sseFault("fxrstor");
            std::memcpy(&ctx.fpu.cw, img + 0, 2);
            std::memcpy(&ctx.fpu.sw, img + 2, 2);
            const uint8_t abridged = img[4];
            for (int i = 0; i < 8; ++i) {
                std::memcpy(&ctx.fpu.sti(i).sig, img + 32 + 16 * i, 8);
                std::memcpy(&ctx.fpu.sti(i).se, img + 32 + 16 * i + 8, 2);
                ctx.fpu.setTagSt(i, ((abridged >> i) & 1) ? x87::TAG_VALID : x87::TAG_EMPTY);
                if ((abridged >> i) & 1) ctx.fpu.refreshTag((ctx.fpu.top() + i) & 7);
            }
            std::memcpy(&ctx.mxcsr, img + 24, 4);
            for (int i = 0; i < 16; ++i) std::memcpy(ctx.ymm[i], img + 160 + 16 * i, 16);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::MMX_OP: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D;
            r.exception_msg = "unimplemented: " + in.mnemonic +
                              " (no MMX register file; decoded for stream alignment only)";
            return r;
        }

        case X86Op::SYSCALL: {
            r.exit = InterpExit::SYSCALL;
            r.syscall_nr = static_cast<int64_t>(ctx.rax());
            r.next_pc = ctx.rip + in.length;
            return r;
        }

        case X86Op::INT3:
        case X86Op::UD2: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0x80000003;
            r.exception_msg = in.op == X86Op::INT3 ? "int3" : "ud2";
            return r;
        }

        // ================= AVX-512 mask-register group ==================
        case X86Op::KAND:
        case X86Op::KANDN:
        case X86Op::KOR:
        case X86Op::KXOR:
        case X86Op::KXNOR:
        case X86Op::KADD: {
            const int w = in.dst.size ? in.dst.size : 16;
            if (in.dst.reg <= 0) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC000001D;
                r.exception_msg = in.mnemonic + ": k0 is not a legal destination (#UD)";
                return r;
            }
            const uint64_t a = readOperand(ctx, in.src, w);
            const uint64_t b = readOperand(ctx, in.src2, w);
            uint64_t v = 0;
            switch (in.op) {
                case X86Op::KAND:  v = a & b; break;
                case X86Op::KANDN: v = ~a & b; break;
                case X86Op::KOR:   v = a | b; break;
                case X86Op::KXOR:  v = a ^ b; break;
                case X86Op::KXNOR: v = ~(a ^ b); break;
                default:           v = a + b; break;   // KADD: no carry out
            }
            writeOperand(ctx, in.dst, v, w);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::KNOT: {
            const int w = in.dst.size ? in.dst.size : 16;
            if (in.dst.reg <= 0) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC000001D;
                r.exception_msg = "knot: k0 is not a legal destination (#UD)";
                return r;
            }
            writeOperand(ctx, in.dst, ~readOperand(ctx, in.src, w), w);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::KUNPCK: {
            // DEST[lo] := SRC1 (vvvv), DEST[hi] := SRC2 (r/m)
            const int sb = in.src.size ? in.src.size : 8;
            const uint64_t a = readOperand(ctx, in.src, sb);
            const uint64_t b = readOperand(ctx, in.src2, sb);
            writeOperand(ctx, in.dst, (b << sb) | a, sb * 2);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::KTEST:
        case X86Op::KORTEST: {
            const int w = in.dst.size ? in.dst.size : 16;
            const uint64_t a = readOperand(ctx, in.dst, w);
            const uint64_t b = readOperand(ctx, in.src, w);
            uint64_t zf, cf;
            if (in.op == X86Op::KTEST) {
                zf = (a & b) == 0;
                cf = (a & ~b) == 0;
            } else {
                const uint64_t o = a | b;
                const uint64_t all = (w >= 64) ? ~0ULL : ((1ULL << w) - 1);
                zf = o == 0;
                cf = o == all;
            }
            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            rf &= ~((1ULL << 0) | (1ULL << 6));
            if (cf) rf |= 1ULL << 0;
            if (zf) rf |= 1ULL << 6;
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::KSHIFTL:
        case X86Op::KSHIFTR: {
            const int w = in.dst.size ? in.dst.size : 16;
            const uint64_t v = readOperand(ctx, in.src, w);
            const unsigned n = static_cast<unsigned>(in.src2.imm) & 0xFFu;
            uint64_t res;
            if (static_cast<int>(n) >= w) res = 0;
            else if (in.op == X86Op::KSHIFTL) res = v << n;
            else res = v >> n;
            writeOperand(ctx, in.dst, res, w);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::KMOV: {
            const int w = in.dst.size ? in.dst.size : 16;
            if (in.dst.kind == OperandKind::K && in.dst.reg <= 0) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC000001D;
                r.exception_msg = in.mnemonic + ": k0 is not a legal destination (#UD)";
                return r;
            }
            writeOperand(ctx, in.dst, readOperand(ctx, in.src, w), w);
            ctx.rip = r.next_pc;
            return r;
        }

        // ================= misc scalar / system =========================
        case X86Op::LAHF: {
            // AH <- SF:ZF:0:AF:0:PF:1:CF
            const uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            const uint64_t ah = (rf & 0xD5ULL) | 0x02ULL;
            ctx.rax() = (ctx.rax() & ~0xFF00ULL) | (ah << 8);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::LAR: {
            // Segment access rights. NINE runs a flat model, so the selectors
            // a 64-bit guest really uses map onto the canonical long-mode
            // descriptors; anything else reports "not usable" through ZF=0.
            const uint16_t sel = static_cast<uint16_t>(readOperand(ctx, in.src, 16));
            uint32_t rights = 0;
            bool ok = true;
            switch (sel & 0xFFF8u) {
                case 0x0028: rights = 0x00CFF300; break;  // user data, DPL 3, 4K-G
                case 0x0030: rights = 0x00AFFB00; break;  // user code, L=1, DPL 3
                case 0x0010: rights = 0x00CF9200; break;  // kernel data
                case 0x0008: rights = 0x00AF9A00; break;  // kernel code, L=1
                default: ok = false; break;
            }
            if (ok) writeOperand(ctx, in.dst, rights, in.dst.size ? in.dst.size : 32);
            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            rf &= ~(1ULL << 6);
            if (ok) rf |= 1ULL << 6;
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::LDS: {
            // Compat-mode far pointer load. Every non-FS/GS segment base is 0
            // in the flat model, so only the offset half has an effect.
            const int w = in.dst.size ? in.dst.size : 32;
            const uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, in.length);
            uint64_t off = 0;
            if (!loadMem(ea, &off, static_cast<size_t>(w / 8))) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "lds: far pointer load fault";
                return r;
            }
            writeOperand(ctx, in.dst, off, w);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::LDDQU: {
            uint8_t v[16];
            if (!loadSseSource(ctx, in.src, v, 16)) return sseFault(in.mnemonic.c_str());
            writeXmm(ctx, in.dst.reg, v);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::LDMXCSR: {
            ctx.mxcsr = static_cast<uint32_t>(readOperand(ctx, in.src, 32));
            if (mem_fault_) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "ldmxcsr: source load fault";
                return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::INSERTPS: {
            uint8_t d[16], s[16];
            readXmm(ctx, in.dst.reg, d);
            const bool from_mem = in.src.kind == OperandKind::MEM;
            if (!loadSseSource(ctx, in.src, s, from_mem ? 4 : 16))
                return sseFault("insertps");
            const int imm = static_cast<int>(in.src2.imm) & 0xFF;
            const int src_lane = from_mem ? 0 : ((imm >> 6) & 3);
            const int dst_lane = (imm >> 4) & 3;
            for (int i = 0; i < 4; ++i)
                if (imm & (1 << i)) std::memset(d + i * 4, 0, 4);
            std::memcpy(d + dst_lane * 4, s + src_lane * 4, 4);
            writeXmm(ctx, in.dst.reg, d);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- instructions a CPL-3 guest may never execute ----------------
        case X86Op::IN:
        case X86Op::INS: {
            // Port I/O is gated by IOPL, which is 0 at CPL 3.
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC0000005;
            r.exception_msg = in.mnemonic + ": #GP(0) — IOPL is 0 at CPL 3";
            return r;
        }

        case X86Op::INVD:
        case X86Op::INVLPG:
        case X86Op::INVPCID: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC0000005;
            r.exception_msg = in.mnemonic + ": #GP(0) — privileged instruction at CPL 3";
            return r;
        }

        case X86Op::INCSSP: {
            // CET shadow-stack pointer adjustment; CR4.CET is clear in NINE's
            // CPU model, so the instruction is #UD exactly as on such silicon.
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D;
            r.exception_msg = in.mnemonic + ": #UD — CR4.CET is clear in this CPU model";
            return r;
        }

        case X86Op::LDTILECFG: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D;
            r.exception_msg = "ldtilecfg: #UD — AMX is not part of this CPU model";
            return r;
        }

        case X86Op::INTN: {
            const int vec = static_cast<int>(in.src.imm) & 0xFF;
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC0000005;
            r.exception_msg = "int " + std::to_string(vec) +
                              ": #GP(0) — no interrupt gate is reachable at CPL 3";
            return r;
        }

        case X86Op::INT1:
        case X86Op::INTO: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC0000005;
            r.exception_msg = in.mnemonic + ": #GP(0) — no interrupt gate is reachable at CPL 3";
            return r;
        }

        case X86Op::IRET: {
            // NINE models no IDT, so there is never an interrupt frame to pop.
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC0000005;
            r.exception_msg = in.mnemonic + ": #GP(0) — no interrupt-return frame (no IDT model)";
            return r;
        }

        // ================= §2.17 batch =================

        // ---- LOOP/LOOPE/LOOPNE/JRCXZ (E0-E3) ----
        case X86Op::LOOP: {
            const uint64_t target = static_cast<uint64_t>(in.dst.imm);
            bool taken;
            if (in.cc == 3) {                        // JRCXZ: no decrement
                taken = (ctx.rcx() == 0);
            } else {
                ctx.rcx() -= 1;
                taken = (ctx.rcx() != 0);
                if (taken && in.cc != 0) {
                    const uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
                    const bool zf = ((rf >> 6) & 1) != 0;
                    taken = (in.cc == 1) ? zf : !zf;  // LOOPE / LOOPNE
                }
            }
            r.next_pc = taken ? target : ctx.rip + in.length;
            ctx.rip = r.next_pc;
            r.exit = InterpExit::BLOCK_END;
            return r;
        }

        // ---- port output: IOPL is 0 at CPL 3 ----
        case X86Op::OUT:
        case X86Op::OUTS: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC0000005; // #GP(0), like IN/INS
            r.exception_msg = in.mnemonic + ": #GP(0) — IOPL is 0 at CPL 3";
            return r;
        }

        // ---- descriptor-table / task-register / monitor loads ----
        case X86Op::LGDT: case X86Op::LIDT: case X86Op::LLDT:
        case X86Op::LTR: case X86Op::LMSW:
        case X86Op::MONITOR: case X86Op::MWAIT:
        case X86Op::MOVCR: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC0000005;
            r.exception_msg = in.mnemonic + ": #GP(0) — CPL 0 operation at CPL 3";
            return r;
        }

        case X86Op::LOADIWKEY: {
            // The SDM's operation section starts with `IF CPL > 0 THEN #GP(0)`:
            // installing the internal wrapping key is ring-0 only.
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC0000005; // #GP(0)
            r.exception_msg = "loadiwkey: #GP(0) — ring-0 only at CPL 3";
            return r;
        }

        // ---- LES/LFS/LGS/LSS: far pointer, offset half is all that survives
        // the flat segment model (the selector is read for its length only).
        case X86Op::LES: case X86Op::LFS: case X86Op::LGS: case X86Op::LSS: {
            const int obits = in.dst.size ? in.dst.size : 32;
            const size_t n = static_cast<size_t>((obits / 8) + 2);
            if (in.src.kind != OperandKind::MEM) return InterpResult{};
            const uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, cur_insn_len_);
            uint8_t buf[10] = {};
            if (!loadMem(ea, buf, n)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = in.mnemonic + ": load fault";
                return r;
            }
            uint64_t off = 0;
            for (int k = 0; k < obits / 8; ++k) off |= static_cast<uint64_t>(buf[k]) << (8 * k);
            writeOperand(ctx, in.dst, off, obits);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- LSL: segment limit, same selector rules as LAR ----
        case X86Op::LSL: {
            const uint64_t sel = maskSize(readOperand(ctx, in.src, 16), 16);
            bool ok = ((sel & 4) == 0);            // TI=0 means the GDT
            if (ok && (sel & 3) == 3 && (sel >> 3) == 0) ok = false; // null selector
            // ZF=1 when the selector is usable, like LAR.
            setFlagsMasked(ctx, 1ULL << 6, ok ? (1ULL << 6) : 0);
            if (ok) writeOperand(ctx, in.dst, 0xFFFFF, in.dst.size ? in.dst.size : 32);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- MULX: RDX * r/m -> {reg = low, vvvv = high}, flags untouched ----
        case X86Op::MULX: {
            const int w = in.dst.size ? in.dst.size : 64;
            const uint64_t a = maskSize(ctx.rdx(), w);
            const uint64_t b = maskSize(readOperand(ctx, in.src, w), w);
            const unsigned __int128 p = static_cast<unsigned __int128>(a) * b;
            writeOperand(ctx, in.dst, static_cast<uint64_t>(p), w);
            writeOperand(ctx, in.src2, static_cast<uint64_t>(p >> w), w);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- MOVBE: byte-swapping load/store ----
        case X86Op::MOVBE: {
            const int w = in.dst.size ? in.dst.size : 32;
            const int n = w / 8;
            if (in.dst.kind == OperandKind::MEM) {
                const uint64_t v = maskSize(readOperand(ctx, in.src, w), w);
                uint8_t buf[8];
                for (int k = 0; k < n; ++k) buf[k] = static_cast<uint8_t>(v >> (8 * (n - 1 - k)));
                const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, cur_insn_len_);
                if (!storeMem(ea, buf, static_cast<size_t>(n))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "movbe: store fault";
                    return r;
                }
            } else {
                uint8_t buf[8] = {};
                const uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, cur_insn_len_);
                if (!loadMem(ea, buf, static_cast<size_t>(n))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "movbe: load fault";
                    return r;
                }
                uint64_t v = 0;
                for (int k = 0; k < n; ++k) v |= static_cast<uint64_t>(buf[k]) << (8 * (n - 1 - k));
                writeOperand(ctx, in.dst, v, w);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- MOVDIRI / MOVNTI: plain stores at the architectural level ----
        case X86Op::MOVDIRI: case X86Op::MOVNTI: {
            const int w = in.src.size ? in.src.size : 32;
            const uint64_t v = maskSize(readOperand(ctx, in.src, w), w);
            const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, cur_insn_len_);
            if (!storeMem(ea, &v, static_cast<size_t>(w / 8))) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = in.mnemonic + ": store fault";
                return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- MOVDIR64B: 64-byte direct store to [reg] from [rm] ----
        case X86Op::MOVDIR64B: {
            uint8_t buf[64];
            const uint64_t src = effectiveAddress(ctx, in.src.mem, ctx.rip, cur_insn_len_);
            const uint64_t dst = ctx.gpr[in.dst.reg];
            if (!loadMem(src, buf, 64)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "movdir64b: source fault";
                return r;
            }
            if (!storeMem(dst, buf, 64)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "movdir64b: destination fault";
                return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- non-temporal stores / load ----
        case X86Op::MOVNTPS: case X86Op::MOVNTPD:
        case X86Op::MOVNTDQ: case X86Op::MOVNTQ: {
            const size_t n = (in.op == X86Op::MOVNTQ) ? 8 : 16;
            const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, cur_insn_len_);
            if (!storeMem(ea, ctx.ymm[in.src.reg - 16], n)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = in.mnemonic + ": store fault";
                return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::MOVNTDQA: {
            uint8_t buf[16];
            const uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, cur_insn_len_);
            if (!loadMem(ea, buf, 16)) return sseFault("movntdqa");
            writeXmm(ctx, in.dst.reg, buf);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- MASKMOVDQU: byte store to [RDI] selected by the mask MSBs ----
        case X86Op::MASKMOVDQU: {
            uint8_t mask[16], data[16];
            readXmm(ctx, in.src.reg, mask);
            readXmm(ctx, in.dst.reg, data);
            const uint64_t addr = ctx.rdi();
            for (int k = 0; k < 16; ++k) {
                if ((mask[k] & 0x80) == 0) continue;
                if (!storeMem(addr + static_cast<uint64_t>(k), data + k, 1)) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "maskmovdqu: store fault";
                    return r;
                }
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- MOVSS/MOVSD: scalar move; reg form merges, mem form zeroes ----
        case X86Op::MOVSS:
        case X86Op::MOVSD_SSE: {
            const int bytes = (in.op == X86Op::MOVSS) ? 4 : 8;
            if (in.dst.kind == OperandKind::REG && in.dst.reg >= 16) {
                uint8_t src[16] = {};
                if (in.src.kind == OperandKind::MEM) {
                    const uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, cur_insn_len_);
                    if (!loadMem(ea, src, static_cast<size_t>(bytes))) {
                        return sseFault(in.mnemonic.c_str());
                    }
                    writeXmm(ctx, in.dst.reg, src);      // upper lanes zeroed
                } else if (in.src.kind == OperandKind::REG && in.src.reg >= 16) {
                    uint8_t d[16];
                    readXmm(ctx, in.dst.reg, d);
                    readXmm(ctx, in.src.reg, src);
                    std::memcpy(d, src, static_cast<size_t>(bytes));
                    writeXmm(ctx, in.dst.reg, d);        // merge
                }
            } else if (in.dst.kind == OperandKind::MEM && in.src.reg >= 16) {
                uint8_t d[16];
                readXmm(ctx, in.src.reg, d);
                const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, cur_insn_len_);
                if (!storeMem(ea, d, static_cast<size_t>(bytes))) {
                    return sseFault(in.mnemonic.c_str());
                }
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- MOVHLPS/MOVLHPS: half-register shuffles ----
        case X86Op::MOVHLPS: case X86Op::MOVLHPS: {
            uint8_t s[16], d[16];
            readXmm(ctx, in.src.reg, s);
            readXmm(ctx, in.dst.reg, d);
            if (in.op == X86Op::MOVHLPS) std::memcpy(d, s + 8, 8);
            else std::memcpy(d + 8, s, 8);
            writeXmm(ctx, in.dst.reg, d);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- MOVDDUP/MOVSHDUP/MOVSLDUP: lane replication ----
        case X86Op::MOVDDUP: case X86Op::MOVSHDUP: case X86Op::MOVSLDUP: {
            uint8_t s[16], out[16];
            const int nbytes = (in.src.kind == OperandKind::MEM && in.src.size > 0)
                             ? in.src.size / 8 : 16;
            if (!loadSseSource(ctx, in.src, s, nbytes)) return sseFault(in.mnemonic.c_str());
            if (in.op == X86Op::MOVDDUP) {
                std::memcpy(out, s, 8);
                std::memcpy(out + 8, s, 8);
            } else if (in.op == X86Op::MOVSHDUP) {
                std::memcpy(out, s + 4, 4);
                std::memcpy(out + 4, s + 4, 4);
                std::memcpy(out + 8, s + 12, 4);
                std::memcpy(out + 12, s + 12, 4);
            } else {
                std::memcpy(out, s, 4);
                std::memcpy(out + 4, s, 4);
                std::memcpy(out + 8, s + 8, 4);
                std::memcpy(out + 12, s + 8, 4);
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- MOVMSKPS/MOVMSKPD: gather element sign bits ----
        case X86Op::MOVMSKPS: case X86Op::MOVMSKPD: {
            uint8_t s[16];
            readXmm(ctx, in.src.reg, s);
            const bool single = (in.op == X86Op::MOVMSKPS);
            const int lanes = single ? 4 : 2;
            const int step = single ? 4 : 8;
            uint32_t mask = 0;
            for (int k = 0; k < lanes; ++k)
                mask |= static_cast<uint32_t>((s[k * step + step - 1] >> 7) & 1) << k;
            writeOperand(ctx, in.dst, mask, in.dst.size ? in.dst.size : 32);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- ORPS/ORPD ----
        case X86Op::ORPS: case X86Op::ORPD: {
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("orps/orpd");
            for (int k = 0; k < 16; ++k) a[k] |= b[k];
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- MULPS/MULPD/MULSS/MULSD, MAX*, MIN* ----
        case X86Op::MULPS: case X86Op::MULPD: case X86Op::MULSS: case X86Op::MULSD:
        case X86Op::MAXPS: case X86Op::MAXPD: case X86Op::MAXSS: case X86Op::MAXSD:
        case X86Op::MINPS: case X86Op::MINPD: case X86Op::MINSS: case X86Op::MINSD: {
            const bool isMul = (in.op == X86Op::MULPS || in.op == X86Op::MULPD ||
                                in.op == X86Op::MULSS || in.op == X86Op::MULSD);
            const bool isMax = (in.op == X86Op::MAXPS || in.op == X86Op::MAXPD ||
                                in.op == X86Op::MAXSS || in.op == X86Op::MAXSD);
            const bool scalar = (in.op == X86Op::MULSS || in.op == X86Op::MULSD ||
                                 in.op == X86Op::MAXSS || in.op == X86Op::MAXSD ||
                                 in.op == X86Op::MINSS || in.op == X86Op::MINSD);
            const bool single = (in.op == X86Op::MULPS || in.op == X86Op::MAXPS ||
                                 in.op == X86Op::MINPS || in.op == X86Op::MULSS ||
                                 in.op == X86Op::MAXSS || in.op == X86Op::MINSS);
            const int lanes = scalar ? 1 : (single ? 4 : 2);
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            // A scalar memory operand is 4/8 bytes wide; only the packed forms
            // touch the full 128 bits, so do not over-read a page boundary.
            if (!loadSseSource(ctx, in.src, b, scalar ? (single ? 4 : 8) : 16))
                return sseFault(in.mnemonic.c_str());
            for (int k = 0; k < lanes; ++k) {
                if (single) {
                    float x, y;
                    std::memcpy(&x, a + 4 * k, 4);
                    std::memcpy(&y, b + 4 * k, 4);
                    float res;
                    if (isMul) {
                        res = x * y;
                    } else if (std::isnan(x) || std::isnan(y) || (x == 0.0f && y == 0.0f)) {
                        res = y;   // x86 returns the second source on NaN / equal zeros
                    } else {
                        res = isMax ? ((x > y) ? x : y) : ((x < y) ? x : y);
                    }
                    std::memcpy(a + 4 * k, &res, 4);
                } else {
                    double x, y;
                    std::memcpy(&x, a + 8 * k, 8);
                    std::memcpy(&y, b + 8 * k, 8);
                    double res;
                    if (isMul) {
                        res = x * y;
                    } else if (std::isnan(x) || std::isnan(y) || (x == 0.0 && y == 0.0)) {
                        res = y;
                    } else {
                        res = isMax ? ((x > y) ? x : y) : ((x < y) ? x : y);
                    }
                    std::memcpy(a + 8 * k, &res, 8);
                }
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PADD/PADDS/PADDUS ----
        case X86Op::PADD: case X86Op::PADDS: case X86Op::PADDUS: {
            const int ebits = in.dst.size ? in.dst.size : 8;
            const int n = ebits / 8;
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());
            for (int off = 0; off < 16; off += n) {
                const uint64_t x = loadLeBytes(a + off, n);
                const uint64_t y = loadLeBytes(b + off, n);
                uint64_t res;
                if (in.op == X86Op::PADD) {
                    res = maskSize(x + y, ebits);
                } else if (in.op == X86Op::PADDS) {
                    res = static_cast<uint64_t>(satSigned(sextBits(x, ebits) + sextBits(y, ebits), ebits));
                } else {
                    res = satUnsigned(static_cast<int64_t>(x) + static_cast<int64_t>(y), ebits);
                }
                storeLeBytes(a + off, res, n);
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PAND/PANDN ----
        case X86Op::PAND: case X86Op::PANDN: {
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());
            for (int k = 0; k < 16; ++k)
                a[k] = (in.op == X86Op::PAND) ? static_cast<uint8_t>(a[k] & b[k])
                                              : static_cast<uint8_t>((~a[k]) & b[k]);
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PAVGB/PAVGW: (a + b + 1) >> 1 per element ----
        case X86Op::PAVG: {
            const int ebits = in.dst.size ? in.dst.size : 8;
            const int n = ebits / 8;
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());
            for (int off = 0; off < 16; off += n) {
                const uint64_t x = loadLeBytes(a + off, n);
                const uint64_t y = loadLeBytes(b + off, n);
                storeLeBytes(a + off, (x + y + 1) >> 1, n);
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PCMPEQB/W/D ----
        case X86Op::PCMPEQ: {
            const int ebits = in.dst.size ? in.dst.size : 8;
            const int n = ebits / 8;
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());
            for (int off = 0; off < 16; off += n) {
                const bool eq = std::memcmp(a + off, b + off, static_cast<size_t>(n)) == 0;
                std::memset(a + off, eq ? 0xFF : 0x00, static_cast<size_t>(n));
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PABS ----
        case X86Op::PABS: {
            const int ebits = in.dst.size ? in.dst.size : 8;
            const int n = ebits / 8;
            uint8_t a[16];
            readXmm(ctx, in.dst.reg, a);
            for (int off = 0; off < 16; off += n) {
                const int64_t v = sextBits(loadLeBytes(a + off, n), ebits);
                const uint64_t res = v < 0 ? maskSize(static_cast<uint64_t>(-v), ebits)
                                           : static_cast<uint64_t>(v);
                storeLeBytes(a + off, res, n);
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PACKSS/PACKUS ----
        case X86Op::PACKSS: case X86Op::PACKUS: {
            const int ebits = in.dst.size ? in.dst.size : 16;  // 16 or 32
            const int outBits = ebits / 2;
            const int nIn = 128 / ebits;
            uint8_t a[16], b[16], out[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());
            for (int k = 0; k < nIn * 2; ++k) {
                const uint8_t* p = (k < nIn) ? a : b;
                const int idx = (k < nIn) ? k : k - nIn;
                const int64_t v = sextBits(loadLeBytes(p + idx * (ebits / 8), ebits / 8), ebits);
                const uint64_t res = (in.op == X86Op::PACKSS)
                                   ? static_cast<uint64_t>(satSigned(v, outBits))
                                   : satUnsigned(v, outBits);
                storeLeBytes(out + k * (outBits / 8), res, outBits / 8);
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PALIGNR: (dst:src) >> imm8 bytes ----
        case X86Op::PALIGNR: {
            int imm = static_cast<int>(in.src2.imm & 0xFF);
            if (imm > 32) imm = 32;
            uint8_t a[16], b[16], cat[32], out[16] = {};
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("palignr");
            std::memcpy(cat, b, 16);       // low half = source
            std::memcpy(cat + 16, a, 16);  // high half = destination
            for (int k = 0; k + imm < 32; ++k) out[k] = cat[k + imm];
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PBLENDVB (implicit XMM0 mask) / PBLENDW (imm8 mask) ----
        case X86Op::PBLENDVB: {
            uint8_t a[16], b[16], mask[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("pblendvb");
            readXmm(ctx, 16, mask);        // XMM0
            for (int k = 0; k < 16; ++k)
                if (mask[k] & 0x80) a[k] = b[k];
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::PBLENDW: {
            const uint32_t imm = static_cast<uint32_t>(in.src2.imm & 0xFF);
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("pblendw");
            for (int k = 0; k < 8; ++k)
                if ((imm >> k) & 1) std::memcpy(a + 2 * k, b + 2 * k, 2);
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PCLMULQDQ: carry-less multiply of the selected qwords ----
        case X86Op::PCLMULQDQ: {
            const uint32_t imm = static_cast<uint32_t>(in.src2.imm & 0xFF);
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("pclmulqdq");
            const uint64_t x = loadLeBytes(a + ((imm & 1) ? 8 : 0), 8);
            const uint64_t y = loadLeBytes(b + ((imm & 0x10) ? 8 : 0), 8);
            unsigned __int128 p = 0;
            for (int k = 0; k < 64; ++k)
                if ((y >> k) & 1) p ^= static_cast<unsigned __int128>(x) << k;
            storeLeBytes(a, static_cast<uint64_t>(p), 8);
            storeLeBytes(a + 8, static_cast<uint64_t>(p >> 64), 8);
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- MPSADBW: eight sliding 4-byte SADs within one lane ----
        case X86Op::MPSADBW: {
            const uint32_t imm = static_cast<uint32_t>(in.src2.imm & 0xFF);
            const int blk1 = (imm & 4) ? 4 : 0;        // imm8[2] selects dst dword
            const int blk2 = static_cast<int>(imm & 3) * 4;
            uint8_t a[16], b[16], out[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("mpsadbw");
            for (int i = 0; i < 8; ++i) {
                int sum = 0;
                for (int k = 0; k < 4; ++k) {
                    const int d = static_cast<int>(a[blk1 + i + k]) - static_cast<int>(b[blk2 + k]);
                    sum += d < 0 ? -d : d;
                }
                out[2 * i] = static_cast<uint8_t>(sum & 0xFF);
                out[2 * i + 1] = static_cast<uint8_t>((sum >> 8) & 0xFF);
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // =====================================================================
        // §2.18 — packed integer, part 1: compares, subtract, interleave
        // =====================================================================

        // ---- PCMPGT: signed packed compare (element width in dst.size) -----
        case X86Op::PCMPGT: {
            const int ebits = in.dst.size ? in.dst.size : 8;
            const int n = ebits / 8;
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());
            for (int off = 0; off < 16; off += n) {
                const int64_t x = sextBits(loadLeBytes(a + off, n), ebits);
                const int64_t y = sextBits(loadLeBytes(b + off, n), ebits);
                std::memset(a + off, x > y ? 0xFF : 0x00, static_cast<size_t>(n));
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PSUB / PSUBS / PSUBUS -----------------------------------------
        case X86Op::PSUB: case X86Op::PSUBS: case X86Op::PSUBUS: {
            const int ebits = in.dst.size ? in.dst.size : 8;
            const int n = ebits / 8;
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());
            for (int off = 0; off < 16; off += n) {
                const uint64_t x = loadLeBytes(a + off, n);
                const uint64_t y = loadLeBytes(b + off, n);
                uint64_t res;
                if (in.op == X86Op::PSUB) {
                    res = maskSize(x - y, ebits);
                } else if (in.op == X86Op::PSUBS) {
                    res = static_cast<uint64_t>(satSigned(sextBits(x, ebits) - sextBits(y, ebits), ebits));
                } else {
                    res = satUnsigned(static_cast<int64_t>(x) - static_cast<int64_t>(y), ebits);
                }
                storeLeBytes(a + off, res, n);
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PUNPCK{L,H}*: interleave two registers by element ----------------
        case X86Op::PUNPCK: {
            const int ebits = in.dst.size ? in.dst.size : 8;
            const int n = ebits / 8;
            const int lanes = 16 / n;
            uint8_t a[16], b[16], out[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());
            const bool high = in.cc != 0;
            for (int i = 0; i < lanes; ++i) {
                const int idx = high ? (lanes / 2 + i) : i;
                std::memcpy(out + 2 * i * n, a + idx * n, static_cast<size_t>(n));
                std::memcpy(out + (2 * i + 1) * n, b + idx * n, static_cast<size_t>(n));
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PSHUFD / PSHUFHW / PSHUFLW / PSHUFW -----------------------------
        case X86Op::PSHUF: {
            const uint32_t imm = static_cast<uint32_t>(in.src2.imm & 0xFF);
            uint8_t a[16], b[16], out[16] = {};
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());
            if (in.cc == 0) {                       // dword shuffle of the source
                for (int k = 0; k < 4; ++k)
                    std::memcpy(out + 4 * k, b + 4 * ((imm >> (2 * k)) & 3), 4);
            } else if (in.cc == 1) {                // high words
                std::memcpy(out, a, 8);
                for (int k = 0; k < 4; ++k)
                    std::memcpy(out + 8 + 2 * k, b + 8 + 2 * ((imm >> (2 * k)) & 3), 2);
            } else if (in.cc == 2) {                // low words
                for (int k = 0; k < 4; ++k)
                    std::memcpy(out + 2 * k, b + 2 * ((imm >> (2 * k)) & 3), 2);
                std::memcpy(out + 8, a + 8, 8);
            } else {                                // PSHUFW: low half, duplicated
                for (int k = 0; k < 4; ++k)
                    std::memcpy(out + 2 * k, b + 2 * ((imm >> (2 * k)) & 3), 2);
                std::memcpy(out + 8, out, 8);
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PSHUFB: per-byte table lookup, MSB selects zeroing ----------------
        case X86Op::PSHUFB: {
            uint8_t a[16], b[16], out[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("pshufb");
            for (int i = 0; i < 16; ++i)
                out[i] = (b[i] & 0x80) ? 0 : a[b[i] & 0x0F];
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // =====================================================================
        // §2.18 — packed integer, part 2: shifts, multiply, min/max, extends
        // =====================================================================

        // ---- PSLL/PSRL/PSRA by imm8 or by the low qword of the source ------
        case X86Op::PSHIFT: {
            const int ebits = in.dst.size ? in.dst.size : 16;
            const int n = ebits / 8;
            uint64_t count = 0;
            if (in.src2.kind == OperandKind::IMM) {
                count = static_cast<uint64_t>(in.src2.imm) & 0xFF;
            } else {
                uint8_t cnt[16];
                if (!loadSseSource(ctx, in.src, cnt, 16)) return sseFault(in.mnemonic.c_str());
                count = loadLeBytes(cnt, 8);
            }
            uint8_t a[16];
            readXmm(ctx, in.dst.reg, a);
            for (int off = 0; off < 16; off += n) {
                const uint64_t v = loadLeBytes(a + off, n);
                uint64_t res;
                if (count >= static_cast<uint64_t>(ebits)) {
                    if (in.cc == 2) {   // arithmetic right: sign fill
                        const int64_t s = sextBits(v, ebits);
                        res = maskSize(static_cast<uint64_t>(s) >> (ebits - 1), ebits);
                    } else {
                        res = 0;
                    }
                } else if (in.cc == 0) {
                    res = maskSize(v << count, ebits);
                } else if (in.cc == 1) {
                    res = maskSize(v >> count, ebits);
                } else {
                    res = maskSize(static_cast<uint64_t>(sextBits(v, ebits)) >> count, ebits);
                }
                storeLeBytes(a + off, res, n);
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PSLLDQ / PSRLDQ: shift the whole 128-bit value by bytes -------
        case X86Op::PSHIFTDQ: {
            uint32_t imm = static_cast<uint32_t>(in.src2.imm & 0xFF);
            if (imm > 16) imm = 16;
            uint8_t a[16], out[16] = {};
            readXmm(ctx, in.dst.reg, a);
            if (in.cc == 0) {
                for (int k = 0; k + static_cast<int>(imm) < 16; ++k)
                    out[k + imm] = a[k];
            } else {
                for (int k = 0; k + static_cast<int>(imm) < 16; ++k)
                    out[k] = a[k + imm];
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PMUL family (variant in cc, element width in dst.size) --------
        case X86Op::PMUL: {
            const int ew = in.dst.size ? in.dst.size : 16;
            const int n = ew / 8;
            uint8_t a[16], b[16], out[16] = {};
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());
            switch (in.cc) {
                case 0:   // PMULLW
                    for (int off = 0; off < 16; off += n)
                        storeLeBytes(out + off,
                                     maskSize(loadLeBytes(a + off, n) * loadLeBytes(b + off, n), ew), n);
                    break;
                case 1:   // PMULHW (signed high half)
                    for (int off = 0; off < 16; off += n) {
                        const int64_t p = sextBits(loadLeBytes(a + off, n), ew) *
                                          sextBits(loadLeBytes(b + off, n), ew);
                        storeLeBytes(out + off, static_cast<uint64_t>(p) >> ew, n);
                    }
                    break;
                case 2:   // PMULHUW (unsigned high half)
                    for (int off = 0; off < 16; off += n)
                        storeLeBytes(out + off,
                                     (loadLeBytes(a + off, n) * loadLeBytes(b + off, n)) >> ew, n);
                    break;
                case 3:   // PMULLD
                    for (int off = 0; off < 16; off += 4)
                        storeLeBytes(out + off,
                                     loadLeBytes(a + off, 4) * loadLeBytes(b + off, 4), 4);
                    break;
                case 4:   // PMULLQ
                    for (int off = 0; off < 16; off += 8)
                        storeLeBytes(out + off,
                                     loadLeBytes(a + off, 8) * loadLeBytes(b + off, 8), 8);
                    break;
                case 5:   // PMULUDQ: even dwords -> qword products
                    for (int k = 0; k < 2; ++k) {
                        const uint64_t x = loadLeBytes(a + 8 * k, 4);
                        const uint64_t y = loadLeBytes(b + 8 * k, 4);
                        storeLeBytes(out + 8 * k, x * y, 8);
                    }
                    break;
                case 6:   // PMULDQ: signed even dwords -> qword products
                    for (int k = 0; k < 2; ++k) {
                        const int64_t x = sextBits(loadLeBytes(a + 8 * k, 4), 32);
                        const int64_t y = sextBits(loadLeBytes(b + 8 * k, 4), 32);
                        storeLeBytes(out + 8 * k, static_cast<uint64_t>(x * y), 8);
                    }
                    break;
                case 7:   // PMULHRSW: (a*b >> 14 + 1) >> 1
                    for (int off = 0; off < 16; off += 2) {
                        const int32_t p = static_cast<int32_t>(sextBits(loadLeBytes(a + off, 2), 16) *
                                                               sextBits(loadLeBytes(b + off, 2), 16));
                        const int32_t res = ((p >> 14) + 1) >> 1;
                        storeLeBytes(out + off, static_cast<uint64_t>(res) & 0xFFFF, 2);
                    }
                    break;
                case 8:   // PMADDWD: (a0*b0 + a1*b1) per dword
                    for (int k = 0; k < 4; ++k) {
                        const int32_t p0 = static_cast<int32_t>(sextBits(loadLeBytes(a + 4 * k, 2), 16) *
                                                                sextBits(loadLeBytes(b + 4 * k, 2), 16));
                        const int32_t p1 = static_cast<int32_t>(sextBits(loadLeBytes(a + 4 * k + 2, 2), 16) *
                                                                sextBits(loadLeBytes(b + 4 * k + 2, 2), 16));
                        storeLeBytes(out + 4 * k,
                                     static_cast<uint64_t>(static_cast<uint32_t>(p0 + p1)), 4);
                    }
                    break;
                default:  // 9 — PMADDUBSW: unsigned byte * signed byte, saturated
                    for (int off = 0; off < 16; off += 2) {
                        const int32_t p0 = static_cast<int32_t>(a[off]) *
                                           static_cast<int32_t>(sextBits(b[off], 8));
                        const int32_t p1 = static_cast<int32_t>(a[off + 1]) *
                                           static_cast<int32_t>(sextBits(b[off + 1], 8));
                        storeLeBytes(out + off,
                                     static_cast<uint64_t>(satSigned(p0 + p1, 16)) & 0xFFFF, 2);
                    }
                    break;
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PMIN/MAX, signed or unsigned (cc bit0 = max, bit1 = unsigned) --
        case X86Op::PMINMAX: {
            const int ebits = in.dst.size ? in.dst.size : 8;
            const int n = ebits / 8;
            const bool want_max = (in.cc & 1) != 0;
            const bool is_unsigned = (in.cc & 2) != 0;
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());
            for (int off = 0; off < 16; off += n) {
                const uint64_t x = loadLeBytes(a + off, n);
                const uint64_t y = loadLeBytes(b + off, n);
                bool take_y;
                if (is_unsigned) take_y = want_max ? (y > x) : (y < x);
                else take_y = want_max ? (sextBits(y, ebits) > sextBits(x, ebits))
                                       : (sextBits(y, ebits) < sextBits(x, ebits));
                if (take_y) storeLeBytes(a + off, y, n);
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PMOVMSKB: one bit per source byte, taken from its MSB ---------
        case X86Op::PMOVMSKB: {
            uint8_t b[16];
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("pmovmskb");
            uint32_t mask = 0;
            for (int i = 0; i < 16; ++i)
                if (b[i] & 0x80) mask |= (1u << i);
            writeOperand(ctx, in.dst, mask, in.dst.size ? in.dst.size : 32);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PMOVSX/PMOVZX: widen narrowing lanes --------------------------
        case X86Op::PMOVX: {
            const int dew = in.dst.size ? in.dst.size : 16;   // destination element
            const int sew = in.src.size ? in.src.size : 8;    // source element
            const int lanes = 128 / dew;
            const int sbytes = lanes * sew / 8;
            uint8_t b[16] = {};
            if (!loadSseSource(ctx, in.src, b, sbytes)) return sseFault(in.mnemonic.c_str());
            uint8_t out[16] = {};
            for (int i = 0; i < lanes; ++i) {
                uint64_t v = loadLeBytes(b + i * sew / 8, sew / 8);
                if (in.cc == 0) v = static_cast<uint64_t>(sextBits(v, sew));
                storeLeBytes(out + i * dew / 8, v, dew / 8);
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PSIGN: apply the sign of the second operand --------------------
        case X86Op::PSIGN: {
            const int ebits = in.dst.size ? in.dst.size : 8;
            const int n = ebits / 8;
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());
            for (int off = 0; off < 16; off += n) {
                const int64_t sign = sextBits(loadLeBytes(b + off, n), ebits);
                const int64_t v = sextBits(loadLeBytes(a + off, n), ebits);
                const int64_t res = sign < 0 ? -v : (sign == 0 ? 0 : v);
                storeLeBytes(a + off, static_cast<uint64_t>(res), n);
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PSADBW: sum of absolute byte differences per qword lane --------
        case X86Op::PSADBW: {
            uint8_t a[16], b[16], out[16] = {};
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("psadbw");
            for (int lane = 0; lane < 2; ++lane) {
                uint32_t sum = 0;
                for (int k = 0; k < 8; ++k) {
                    const int d = static_cast<int>(a[8 * lane + k]) - static_cast<int>(b[8 * lane + k]);
                    sum += static_cast<uint32_t>(d < 0 ? -d : d);
                }
                std::memcpy(out + 8 * lane, &sum, 4);
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // =====================================================================
        // §2.18 — packed integer, part 3: horizontal ops, extract/insert, test
        // =====================================================================

        // ---- PHADDW/PHADDD/PHADDSW/PHSUBW/PHSUBD/PHSUBSW -------------------
        case X86Op::PHADDSUB: {
            uint8_t a[16], b[16], out[16] = {};
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());
            const bool sub = in.cc >= 3;
            const int kind = sub ? in.cc - 3 : in.cc;   // 0 = word, 1 = dword, 2 = sat word
            const int n = (kind == 1) ? 4 : 2;
            const int lanes = 16 / n;
            int oi = 0;
            for (int s = 0; s < 2; ++s) {
                const uint8_t* p = s ? b : a;
                for (int i = 0; i < lanes; i += 2) {
                    const int64_t x = sextBits(loadLeBytes(p + i * n, n), n * 8);
                    const int64_t y = sextBits(loadLeBytes(p + (i + 1) * n, n), n * 8);
                    int64_t res = sub ? x - y : x + y;
                    if (kind == 2) res = satSigned(res, 16);
                    storeLeBytes(out + oi * n, static_cast<uint64_t>(res), n);
                    ++oi;
                }
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PHMINPOSUW: minimum unsigned word and its index ----------------
        case X86Op::PHMINPOSUW: {
            uint8_t b[16], out[16] = {};
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("phminposuw");
            uint16_t best = 0xFFFF;
            int best_idx = 0;
            for (int i = 0; i < 8; ++i) {
                const uint16_t v = static_cast<uint16_t>(loadLeBytes(b + 2 * i, 2));
                if (v < best) { best = v; best_idx = i; }
            }
            storeLeBytes(out, best, 2);
            storeLeBytes(out + 2, static_cast<uint64_t>(best_idx), 2);
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PTEST: ZF = no common bits, CF = all bits of dst are in src ----
        case X86Op::PTEST: {
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("ptest");
            bool any_common = false, all_in = true;
            for (int i = 0; i < 16; ++i) {
                if (a[i] & b[i]) any_common = true;
                if (a[i] & static_cast<uint8_t>(~b[i])) all_in = false;
            }
            const uint64_t clear = (1ULL << 0) | (1ULL << 2) | (1ULL << 4) |
                                   (1ULL << 6) | (1ULL << 7) | (1ULL << 11);
            uint64_t set = 0;
            if (!any_common) set |= (1ULL << 6);   // ZF
            if (all_in) set |= (1ULL << 0);        // CF
            setFlagsMasked(ctx, clear, set);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PEXTRB/W/D/Q and PEXTRW (0F C5): element -> GPR/memory --------
        case X86Op::PEXTR: {
            const int ew = in.dst.size ? in.dst.size : 16;
            const int n = ew / 8;
            uint8_t a[16];
            readXmm(ctx, in.src.reg, a);
            const int lanes = 16 / n;
            const int idx = static_cast<int>(in.src2.imm) & (lanes - 1);
            const uint64_t v = loadLeBytes(a + idx * n, n);
            writeOperand(ctx, in.dst, v, ew);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PINSRB/W/D/Q: GPR/memory element -> one lane ------------------
        case X86Op::PINS: {
            const int ew = in.dst.size ? in.dst.size : 16;
            const int n = ew / 8;
            uint8_t a[16];
            readXmm(ctx, in.dst.reg, a);
            const uint64_t v = readOperand(ctx, in.src, ew);
            const int lanes = 16 / n;
            const int idx = static_cast<int>(in.src2.imm) & (lanes - 1);
            storeLeBytes(a + idx * n, v, n);
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // =====================================================================
        // §2.18 — SSE4.2 string compare (PCMPISTRI/M, PCMPESTRI/M)
        // =====================================================================
        case X86Op::PCMPSTR: {
            const uint32_t imm = static_cast<uint32_t>(in.src2.imm & 0xFF);
            const bool word = (imm & 0x40) != 0;
            const int esz = word ? 2 : 1;
            const int lanes = 16 / esz;
            const bool explicit_len = (in.cc >= 2);

            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());

            auto elem = [&](const uint8_t* p, int i) -> uint32_t {
                return word ? static_cast<uint32_t>(loadLeBytes(p + 2 * i, 2)) : p[i];
            };

            int len1, len2;
            if (explicit_len) {
                len1 = static_cast<int>(ctx.rax() & 0xFFFFFFFF);
                len2 = static_cast<int>(ctx.rdx() & 0xFFFFFFFF);
                if (len1 > lanes) len1 = lanes;
                if (len2 > lanes) len2 = lanes;
            } else {
                len1 = 0; while (len1 < lanes && elem(a, len1) != 0) ++len1;
                len2 = 0; while (len2 < lanes && elem(b, len2) != 0) ++len2;
            }

            const int agg = imm & 3;
            uint32_t r1 = 0;
            if (agg == 0) {                    // equal any
                for (int i = 0; i < len1; ++i) {
                    const uint32_t x = elem(a, i);
                    for (int j = 0; j < len2; ++j)
                        if (x == elem(b, j)) { r1 |= (1u << i); break; }
                }
            } else if (agg == 1) {             // ranges
                for (int i = 0; i < len1; ++i) {
                    const uint32_t x = elem(a, i);
                    for (int j = 0; j + 1 < len2; j += 2) {
                        const uint32_t lo = elem(b, j), hi = elem(b, j + 1);
                        if (x >= lo && x <= hi) { r1 |= (1u << i); break; }
                    }
                }
            } else if (agg == 2) {             // equal each
                for (int i = 0; i < len1 && i < len2; ++i)
                    if (elem(a, i) == elem(b, i)) r1 |= (1u << i);
            } else if (len2 == 0) {            // equal ordered, empty needle
                r1 = (len1 > 0) ? 0xFFFFu : 0u;
            } else {
                for (int i = 0; i + len2 <= len1; ++i) {
                    bool eq = true;
                    for (int j = 0; j < len2; ++j)
                        if (elem(a, i + j) != elem(b, j)) { eq = false; break; }
                    if (eq) r1 |= (1u << i);
                }
            }

            const uint32_t valid = (1u << lanes) - 1;
            r1 &= valid;

            // Mask of second-operand elements whose MSB is set.
            uint32_t bmask = 0;
            for (int j = 0; j < lanes; ++j) {
                const bool msb = word ? ((elem(b, j) & 0x8000u) != 0)
                                      : ((elem(b, j) & 0x80u) != 0);
                if (msb) bmask |= (1u << j);
            }

            uint32_t r2;
            switch ((imm >> 4) & 3) {
                case 0:  r2 = r1; break;
                case 1:  r2 = (~r1) & valid; break;
                case 2:  r2 = r1 & bmask; break;
                default: r2 = (~r1) & bmask; break;
            }

            int index = lanes;
            if ((imm & 0x0C) == 0x04) {        // most significant
                for (int i = lanes - 1; i >= 0; --i)
                    if (r2 & (1u << i)) { index = i; break; }
            } else {                            // least significant / masked
                for (int i = 0; i < lanes; ++i)
                    if (r2 & (1u << i)) { index = i; break; }
            }

            if (in.cc == 0 || in.cc == 2) {     // PCMP*STRI
                ctx.rcx() = static_cast<uint64_t>(index) & 0xFFFFFFFFu;
            } else {                            // PCMP*STRM -> XMM0
                uint8_t out[16] = {};
                if ((imm & 0x0C) == 0x08 || (imm & 0x0C) == 0x0C) {
                    std::memcpy(out, &r2, 4);   // masked forms: raw bit mask
                } else {
                    for (int i = 0; i < lanes; ++i)
                        if (r2 & (1u << i)) std::memset(out + i * esz, 0xFF, esz);
                }
                writeXmm(ctx, 16, out);         // XMM0
            }

            uint64_t set = 0;
            if (r2) set |= 1ULL;                        // CF: any match
            if (len2 < lanes) set |= (1ULL << 6);       // ZF: second operand short
            if (len1 < lanes) set |= (1ULL << 7);       // SF: first operand short
            if (r2 & 1u) set |= (1ULL << 11);           // OF: bit 0 of the result
            setFlagsMasked(ctx, 0x8D5, set);
            ctx.rip = r.next_pc;
            return r;
        }

        // =====================================================================
        // §2.18 — GPR / system group
        // =====================================================================

        case X86Op::POPCNT: {
            const int bits = in.dst.size ? in.dst.size : 32;
            const uint64_t v = maskSize(readOperand(ctx, in.src, bits), bits);
            uint64_t n = 0;
            for (uint64_t x = v; x; x &= x - 1) ++n;
            writeOperand(ctx, in.dst, n, bits);
            const uint64_t clear = (1ULL << 0) | (1ULL << 2) | (1ULL << 4) |
                                   (1ULL << 7) | (1ULL << 11);
            setFlagsMasked(ctx, clear, n == 0 ? (1ULL << 6) : 0ULL);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- RCL/RCR: rotate through CF over a (bits+1)-wide value --------
        case X86Op::RCL: case X86Op::RCR: {
            const int bits = in.dst.size ? in.dst.size : 32;
            const uint64_t mask = (bits >= 64) ? ~0ULL : ((1ULL << bits) - 1);
            uint64_t a = readOperand(ctx, in.dst, bits) & mask;
            uint64_t c = readOperand(ctx, in.src, 8) & static_cast<uint64_t>(bits - 1);
            if (c) {
                uint64_t cf = flags_.get(FlagId::CF) ? 1 : 0;
                const uint64_t msb = (bits >= 64) ? (1ULL << 63) : (1ULL << (bits - 1));
                uint64_t last = 0;
                for (uint64_t k = 0; k < c; ++k) {
                    if (in.op == X86Op::RCL) {
                        last = (a & msb) ? 1 : 0;
                        a = ((a << 1) | cf) & mask;
                    } else {
                        last = a & 1;
                        a = (a >> 1) | (cf ? msb : 0);
                    }
                    cf = last;
                }
                writeOperand(ctx, in.dst, a, bits);
                uint64_t of = 0;
                if (c == 1) {
                    const bool top = (a & msb) != 0;
                    of = (top != (cf != 0)) ? (1ULL << 11) : 0ULL;
                }
                // A count other than 1 leaves OF undefined; NINE preserves it.
                setFlagsMasked(ctx, 1ULL | (1ULL << 11), (cf ? 1ULL : 0ULL) | of);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PUSHF/POPF ---------------------------------------------------
        case X86Op::PUSHF: {
            uint64_t v = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            v |= 0x2;   // bit 1 reads as 1
            ctx.rsp() -= 8;
            if (!storeMem(ctx.rsp(), &v, 8)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "pushf: stack fault";
                return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::POPF: {
            uint64_t v = 0;
            if (!loadMem(ctx.rsp(), &v, 8)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "popf: stack fault";
                return r;
            }
            ctx.rsp() += 8;
            flags_.setRaw(v | 0x2);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PUSHA/POPA are not encodable in 64-bit mode -------------------
        case X86Op::PUSHA: case X86Op::POPA: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D;
            r.exception_msg = std::string(in.mnemonic) + ": invalid in 64-bit mode";
            return r;
        }

        // ---- RDFSBASE/RDGSBASE --------------------------------------------
        case X86Op::RDFSBASE: case X86Op::RDGSBASE: {
            const int bits = in.dst.size ? in.dst.size : 32;
            const uint64_t base = in.op == X86Op::RDFSBASE ? ctx.fs_base : ctx.gs_base;
            writeOperand(ctx, in.dst, maskSize(base, bits), bits);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- privileged system reads: #GP(0) at CPL 3 ---------------------
        case X86Op::RDMSR: case X86Op::RDPMC: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC0000005;
            r.exception_msg = std::string(in.mnemonic) + ": #GP(0) at CPL 3";
            return r;
        }

        // ---- RDPID: TSC_AUX is 0 in NINE's virtual CPU ---------------------
        case X86Op::RDPID: {
            const int bits = in.dst.size ? in.dst.size : 32;
            writeOperand(ctx, in.dst, 0, bits);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- RDPKRU: #UD while CR4.PKE is clear ---------------------------
        case X86Op::RDPKRU: case X86Op::PTWRITE: case X86Op::PCONFIG: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D;
            r.exception_msg = std::string(in.mnemonic) + ": #UD (feature not enabled)";
            return r;
        }

        // ---- RDRAND: deterministic xorshift, CF reports success -------------
        case X86Op::RDRAND: {
            const int bits = in.dst.size ? in.dst.size : 32;
            static uint64_t s = 0x9E3779B97F4A7C15ULL;
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            writeOperand(ctx, in.dst, maskSize(s, bits), bits);
            setFlagsMasked(ctx, 1ULL, 1ULL);   // CF = 1 (random value valid)
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- PREFETCH*: architectural no-op -------------------------------
        case X86Op::PREFETCH:
            ctx.rip = r.next_pc;
            return r;

        // ---- PDEP / PEXT (BMI2): deposit / extract bits by mask -----------
        case X86Op::PDEP: case X86Op::PEXT: {
            const int bits = in.dst.size ? in.dst.size : 32;
            // VEX.vvvv (in.src) carries the bits; the r/m operand is the mask.
            const uint64_t data = maskSize(readOperand(ctx, in.src, bits), bits);
            const uint64_t mask = maskSize(readOperand(ctx, in.src2, bits), bits);
            uint64_t out = 0;
            int k = 0;
            for (int i = 0; i < bits; ++i) {
                if (!((mask >> i) & 1)) continue;
                if (in.op == X86Op::PDEP) {
                    if ((data >> k) & 1) out |= (1ULL << i);
                } else {
                    if ((data >> i) & 1) out |= (1ULL << k);
                }
                ++k;
            }
            writeOperand(ctx, in.dst, out, bits);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- POR -----------------------------------------------------------
        case X86Op::POR: {
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("por");
            for (int i = 0; i < 16; ++i) a[i] = static_cast<uint8_t>(a[i] | b[i]);
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // =====================================================================
        // §2.20 — completion of the scalar / system instruction set
        // =====================================================================

        // SAHF: AH -> EFLAGS[SF:ZF:AF:PF:CF]. OF and the reserved bit are
        // unaffected; bit 1 reads as 1.
        case X86Op::SAHF: {
            const uint32_t ah = static_cast<uint32_t>((ctx.rax() >> 8) & 0xFF);
            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            const uint64_t mask = (1ULL << 7) | (1ULL << 6) | (1ULL << 4) |
                                  (1ULL << 2) | 1ULL;
            rf &= ~mask;
            if (ah & 0x80) rf |= 1ULL << 7;
            if (ah & 0x40) rf |= 1ULL << 6;
            if (ah & 0x10) rf |= 1ULL << 4;
            if (ah & 0x04) rf |= 1ULL << 2;
            if (ah & 0x01) rf |= 1ULL << 0;
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        // RDTSC / RDTSCP: EDX:EAX = TSC, and RDTSCP also zeroes ECX (TSC_AUX).
        case X86Op::RDTSC:
        case X86Op::RDTSCP: {
            const uint64_t tsc = readTsc();
            ctx.rax() = tsc & 0xFFFFFFFFULL;
            ctx.rdx() = (tsc >> 32) & 0xFFFFFFFFULL;
            if (in.op == X86Op::RDTSCP) ctx.rcx() = 0;
            ctx.rip = r.next_pc;
            return r;
        }

        // RDSEED: hardware entropy. NINE has no entropy starvation, so the
        // read always succeeds and CF reports it.
        case X86Op::RDSEED: {
            const int bits = in.dst.size ? in.dst.size : 32;
            static uint64_t s = 0xD1B54A32D192ED03ULL;
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            writeOperand(ctx, in.dst, maskSize(s, bits), bits);
            setFlagsMasked(ctx, 1ULL, 1ULL);   // CF = 1 (seed valid)
            ctx.rip = r.next_pc;
            return r;
        }

        // SQRTPS / SQRTPD / SQRTSS / SQRTSD. Scalar forms leave the upper
        // lanes of the destination untouched, like every legacy SSE op.
        case X86Op::SQRTPS: case X86Op::SQRTPD:
        case X86Op::SQRTSS: case X86Op::SQRTSD: {
            const bool scalar = (in.op == X86Op::SQRTSS || in.op == X86Op::SQRTSD);
            const bool dbl = (in.op == X86Op::SQRTPD || in.op == X86Op::SQRTSD);
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, scalar ? (dbl ? 8 : 4) : 16))
                return sseFault(in.mnemonic.c_str());
            if (dbl) {
                const int lanes = scalar ? 1 : 2;
                for (int k = 0; k < lanes; ++k) {
                    double x;
                    std::memcpy(&x, b + 8 * k, 8);
                    const double s = std::sqrt(x);
                    std::memcpy(a + 8 * k, &s, 8);
                }
            } else {
                const int lanes = scalar ? 1 : 4;
                for (int k = 0; k < lanes; ++k) {
                    float x;
                    std::memcpy(&x, b + 4 * k, 4);
                    const float s = std::sqrt(x);
                    std::memcpy(a + 4 * k, &s, 4);
                }
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // SUBPS / SUBPD / SUBSS / SUBSD.
        case X86Op::SUBPS: case X86Op::SUBPD:
        case X86Op::SUBSS: case X86Op::SUBSD: {
            const bool scalar = (in.op == X86Op::SUBSS || in.op == X86Op::SUBSD);
            const bool dbl = (in.op == X86Op::SUBPD || in.op == X86Op::SUBSD);
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, scalar ? (dbl ? 8 : 4) : 16))
                return sseFault(in.mnemonic.c_str());
            if (dbl) {
                const int lanes = scalar ? 1 : 2;
                for (int k = 0; k < lanes; ++k) {
                    double x, y;
                    std::memcpy(&x, a + 8 * k, 8);
                    std::memcpy(&y, b + 8 * k, 8);
                    const double s = x - y;
                    std::memcpy(a + 8 * k, &s, 8);
                }
            } else {
                const int lanes = scalar ? 1 : 4;
                for (int k = 0; k < lanes; ++k) {
                    float x, y;
                    std::memcpy(&x, a + 4 * k, 4);
                    std::memcpy(&y, b + 4 * k, 4);
                    const float s = x - y;
                    std::memcpy(a + 4 * k, &s, 4);
                }
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // UNPCKLPS/PD, UNPCKHPS/PD. Element width in dst.size selects PS/PD.
        case X86Op::UNPCKF: {
            const bool dbl = (in.dst.size == 64);
            uint8_t a[16], b[16], out[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault("unpck");
            if (dbl) {
                const int o = in.cc ? 8 : 0;
                std::memcpy(out, a + o, 8);
                std::memcpy(out + 8, b + o, 8);
            } else {
                const int o = in.cc ? 8 : 0;
                for (int k = 0; k < 2; ++k) {
                    std::memcpy(out + 8 * k, a + o + 4 * k, 4);
                    std::memcpy(out + 8 * k + 4, b + o + 4 * k, 4);
                }
            }
            writeXmm(ctx, in.dst.reg, out);
            ctx.rip = r.next_pc;
            return r;
        }

        // STMXCSR m32.
        case X86Op::STMXCSR: {
            const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
            if (!storeMem(ea, &ctx.mxcsr, 4)) return sseFault("stmxcsr");
            ctx.rip = r.next_pc;
            return r;
        }

        // XGETBV: only XCR0 exists in this model and it advertises x87|SSE.
        case X86Op::XGETBV: {
            if ((ctx.rcx() & 0xFFFFFFFFULL) != 0) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "xgetbv: #GP(0) — undefined XCR index";
                return r;
            }
            ctx.rax() = 3;   // XCR0: x87 (bit 0) | SSE (bit 1)
            ctx.rdx() = 0;
            ctx.rip = r.next_pc;
            return r;
        }

        // XSETBV, WRMSR, WBINVD, SWAPGS, SYSENTER/SYSEXIT/SYSRET and the
        // virtualization entry points are all ring-0 operations.
        case X86Op::XSETBV: case X86Op::WRMSR: case X86Op::WBINVD:
        case X86Op::WBNOINVD: case X86Op::SWAPGS: case X86Op::SYSENTER:
        case X86Op::SYSEXIT: case X86Op::SYSRET: case X86Op::STGI:
        case X86Op::CLGI: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC0000096;   // STATUS_PRIVILEGED_INSTRUCTION
            r.exception_msg = std::string(in.mnemonic) + ": #GP(0) — CPL 0 operation at CPL 3";
            return r;
        }

        // RSM (outside SMM) and the TDX SEAM transitions (outside the SEAM
        // root module) are #UD, not #GP.
        case X86Op::RSM: case X86Op::SEAMCALL:
        case X86Op::SEAMOPS: case X86Op::SEAMRET: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D;
            r.exception_msg = std::string(in.mnemonic) + ": #UD — not valid outside its root mode";
            return r;
        }

        // SERIALIZE / SFENCE-class ordering: the guest is single-threaded and
        // every store is already visible to the runtime, so it retires as a
        // fence with no architectural effect.
        case X86Op::SERIALIZE: {
            ctx.rip = r.next_pc;
            return r;
        }

        // XTEST: ZF=1 (not inside a transaction), CF=OF=0.
        case X86Op::XTEST: {
            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            rf &= ~((1ULL << 0) | (1ULL << 11));
            rf |= 1ULL << 6;
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        // XBEGIN: NINE has no transactional memory, so every transaction
        // aborts immediately. Architectural abort path: ZF=1, EAX=0 (status),
        // control to the fallback target.
        case X86Op::XBEGIN: {
            ctx.rax() = 0;
            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            rf |= 1ULL << 6;
            flags_.setRaw(rf);
            syncFlags(ctx);
            const uint64_t target = static_cast<uint64_t>(in.dst.imm);
            ctx.rip = target;
            r.next_pc = target;
            r.exit = InterpExit::BLOCK_END;
            return r;
        }

        // XEND / XABORT outside a live transaction are #UD. Since XBEGIN
        // always aborts in this model, that is every occurrence.
        case X86Op::XEND:
        case X86Op::XABORT: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D;
            r.exception_msg = std::string(in.mnemonic) + ": #UD — no transaction active";
            return r;
        }

        // ---- XSAVE / XRSTOR family -------------------------------------
        // Only the legacy x87|SSE region is modelled, so the image is the
        // 512-byte FXSAVE layout followed by a 64-byte header whose
        // XSTATE_BV advertises exactly those two components.
        case X86Op::XSAVE: case X86Op::XSAVEOPT: case X86Op::XSAVEC: {
            const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
            uint8_t img[576];
            std::memset(img, 0, sizeof(img));
            std::memcpy(img + 0, &ctx.fpu.cw, 2);
            std::memcpy(img + 2, &ctx.fpu.sw, 2);
            uint8_t abridged = 0;
            for (int i = 0; i < 8; ++i)
                if (ctx.fpu.tagOfSt(i) != x87::TAG_EMPTY) abridged |= static_cast<uint8_t>(1u << i);
            img[4] = abridged;
            const uint32_t mxmask = 0xFFFF;
            std::memcpy(img + 24, &ctx.mxcsr, 4);
            std::memcpy(img + 28, &mxmask, 4);
            for (int i = 0; i < 8; ++i) {
                const x87::Val& v = ctx.fpu.sti(i);
                std::memcpy(img + 32 + 16 * i, &v.sig, 8);
                std::memcpy(img + 32 + 16 * i + 8, &v.se, 2);
            }
            for (int i = 0; i < 16; ++i) std::memcpy(img + 160 + 16 * i, ctx.ymm[i], 16);
            const uint64_t xstate_bv = 3;   // x87 | SSE
            std::memcpy(img + 512, &xstate_bv, 8);
            if (!storeMem(ea, img, sizeof(img))) return sseFault(in.mnemonic.c_str());
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::XRSTOR: {
            const uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, in.length);
            uint8_t img[576];
            if (!loadMem(ea, img, sizeof(img))) return sseFault("xrstor");
            std::memcpy(&ctx.fpu.cw, img + 0, 2);
            std::memcpy(&ctx.fpu.sw, img + 2, 2);
            const uint8_t abridged = img[4];
            for (int i = 0; i < 8; ++i) {
                std::memcpy(&ctx.fpu.sti(i).sig, img + 32 + 16 * i, 8);
                std::memcpy(&ctx.fpu.sti(i).se, img + 32 + 16 * i + 8, 2);
                ctx.fpu.setTagSt(i, ((abridged >> i) & 1) ? x87::TAG_VALID : x87::TAG_EMPTY);
                if ((abridged >> i) & 1) ctx.fpu.refreshTag((ctx.fpu.top() + i) & 7);
            }
            std::memcpy(&ctx.mxcsr, img + 24, 4);
            for (int i = 0; i < 16; ++i) std::memcpy(ctx.ymm[i], img + 160 + 16 * i, 16);
            ctx.rip = r.next_pc;
            return r;
        }

        // XSAVES/XRSTORS are supervisor forms.
        case X86Op::XSAVES: case X86Op::XRSTORS: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC0000096;
            r.exception_msg = std::string(in.mnemonic) + ": #GP(0) — CPL 0 form";
            return r;
        }

        // ---- descriptor-table / selector reads --------------------------
        case X86Op::SGDT:
        case X86Op::SIDT: {
            const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
            uint8_t d[10];
            std::memset(d, 0, sizeof(d));   // limit 0, base 0: no table modelled
            if (!storeMem(ea, d, sizeof(d))) return sseFault(in.mnemonic.c_str());
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SLDT:
        case X86Op::STR: {
            // No LDT is loaded and the task register is the flat kernel one.
            const int w = in.dst.size ? in.dst.size : 32;
            writeOperand(ctx, in.dst, 0, w);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SMSW: {
            const int w = in.dst.size ? in.dst.size : 32;
            writeOperand(ctx, in.dst, ctx.cr0 & 0xFFFFULL, w);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::VERR:
        case X86Op::VERW: {
            const uint16_t sel = static_cast<uint16_t>(readOperand(ctx, in.src, 16));
            bool ok = false;
            switch (sel & 0xFFF8u) {
                case 0x0008: case 0x0010: case 0x0028: case 0x0030: ok = true; break;
                default: break;
            }
            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            rf &= ~(1ULL << 6);
            if (ok) rf |= 1ULL << 6;
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- CET shadow-stack probes ------------------------------------
        // With CR4.CET clear both instructions are architectural no-ops that
        // leave every register (and RSTORSSP's memory operand) untouched.
        case X86Op::RDSSP:
        case X86Op::RSTORSSP: {
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- BMI2 flag-free shifts and RORX ------------------------------
        case X86Op::RORX: {
            const int bits = in.dst.size ? in.dst.size : 32;
            const uint64_t v = maskSize(readOperand(ctx, in.src, bits), bits);
            const int n = static_cast<int>(in.src2.imm) & (bits - 1);
            const uint64_t out = bits == 64 ? ((v >> n) | (v << (64 - n))) : [&] {
                const uint32_t w = static_cast<uint32_t>(v);
                return static_cast<uint64_t>(n ? ((w >> n) | (w << (32 - n))) : w);
            }();
            writeOperand(ctx, in.dst, maskSize(out, bits), bits);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SHLX: case X86Op::SHRX: case X86Op::SARX: {
            const int bits = in.dst.size ? in.dst.size : 32;
            const uint64_t v = maskSize(readOperand(ctx, in.src, bits), bits);
            const int n = static_cast<int>(readOperand(ctx, in.src2, bits)) & (bits - 1);
            uint64_t out = v;
            if (bits == 64) {
                if (in.op == X86Op::SHLX) out = v << n;
                else if (in.op == X86Op::SHRX) out = v >> n;
                else out = static_cast<uint64_t>(static_cast<int64_t>(v) >> n);
            } else {
                const uint32_t w = static_cast<uint32_t>(v);
                if (in.op == X86Op::SHLX) out = w << n;
                else if (in.op == X86Op::SHRX) out = w >> n;
                else out = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(w)) >> n);
            }
            writeOperand(ctx, in.dst, maskSize(out, bits), bits);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- AMD TBM (XOP map 9) ----------------------------------------
        // TZMSK sets every bit at or above the lowest set bit of the source;
        // T1MSKC is the dual, using the lowest *clear* bit.
        case X86Op::TBM: {
            const int bits = in.dst.size ? in.dst.size : 32;
            const uint64_t v = maskSize(readOperand(ctx, in.src, bits), bits);
            uint64_t out = 0;
            if (in.cc == 1) {                       // TZMSK
                const uint64_t lsb = v & (~v + 1ULL);
                out = lsb ? (0ULL - lsb) : 0ULL;
            } else {                                // T1MSKC
                const uint64_t inv = maskSize(~v, bits);
                const uint64_t lsb0 = inv & (~inv + 1ULL);
                out = lsb0 ? (0ULL - lsb0) : 0ULL;
            }
            writeOperand(ctx, in.dst, maskSize(out, bits), bits);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- AVX upper-state control ------------------------------------
        // No YMM/ZMM state is modelled, so VZEROUPPER/VZEROALL retire as the
        // architectural no-op they are on a machine whose upper halves are
        // already zero.
        case X86Op::VZERO: {
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- CET committed cipher stores --------------------------------
        case X86Op::WRSS: case X86Op::WRUSS: {
            const int bits = in.src.size ? in.src.size : 32;
            const uint64_t v = readOperand(ctx, in.src, bits);
            const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
            if (!storeMem(ea, &v, static_cast<size_t>(bits / 8)))
                return sseFault(in.mnemonic.c_str());
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- wait hints --------------------------------------------------
        case X86Op::TPAUSE: case X86Op::UMONITOR: {
            ctx.rip = r.next_pc;
            return r;
        }
        case X86Op::UMWAIT: {
            // No other thread can wake this guest, so the deadline always
            // expires: ZF=1 selects the timeout path.
            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            rf |= 1ULL << 6;
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- SHA-1 / SHA-256 extensions ---------------------------------
        case X86Op::SHA: {
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, 16)) return sseFault(in.mnemonic.c_str());
            uint32_t s1[4], s2[4], out[4];
            std::memcpy(s1, a, 16);
            std::memcpy(s2, b, 16);
            std::memcpy(out, a, 16);

            if (in.cc == 0) {                     // SHA1MSG1
                // W0..W3 live in s1[3..0]; W4/W5 are s2[3]/s2[2].
                out[3] = s1[1] ^ s1[3];
                out[2] = s1[0] ^ s1[2];
                out[1] = s2[3] ^ s1[1];
                out[0] = s2[2] ^ s1[0];
            } else if (in.cc == 1) {              // SHA1MSG2
                const uint32_t w13 = s2[2];
                const uint32_t w14 = s2[1];
                const uint32_t w15 = s2[0];
                const uint32_t w16 = rotl32(s1[3] ^ w13, 1);
                const uint32_t w17 = rotl32(s1[2] ^ w14, 1);
                const uint32_t w18 = rotl32(s1[1] ^ w15, 1);
                const uint32_t w19 = rotl32(s1[0] ^ w16, 1);
                out[3] = w16; out[2] = w17; out[1] = w18; out[0] = w19;
            } else if (in.cc == 2) {              // SHA1NEXTE
                const uint32_t tmp = rotl32(s1[3], 30);
                out[3] = s2[3] + tmp;
                out[2] = s2[2];
                out[1] = s2[1];
                out[0] = s2[0];
            } else if (in.cc == 3) {              // SHA1RNDS4
                const int sel = static_cast<int>(in.src2.imm) & 3;
                static const uint32_t K[4] = { 0x5A827999u, 0x6ED9EBA1u,
                                               0x8F1BBCDCu, 0xCA62C1D6u };
                const uint32_t k = K[sel];
                uint32_t A = s1[3], B = s1[2], C = s1[1], D = s1[0];
                const uint32_t w[4] = { s2[3], s2[2], s2[1], s2[0] };
                auto f = [&](uint32_t x, uint32_t y, uint32_t z) -> uint32_t {
                    switch (sel) {
                        case 0: return (x & y) | (~x & z);
                        case 1: return x ^ y ^ z;
                        case 2: return (x & y) | (x & z) | (y & z);
                        default: return x ^ y ^ z;
                    }
                };
                uint32_t E = D;   // only used from round 1 onward
                for (int i = 0; i < 4; ++i) {
                    const uint32_t t = f(B, C, D) + rotl32(A, 5) + w[i] + k +
                                       (i == 0 ? 0u : E);
                    E = D;
                    D = C;
                    C = rotl32(B, 30);
                    B = A;
                    A = t;
                }
                out[3] = A; out[2] = B; out[1] = C; out[0] = D;
            } else if (in.cc == 4) {              // SHA256MSG1
                const uint32_t W0 = s1[0], W1 = s1[1], W2 = s1[2], W3 = s1[3];
                const uint32_t W4 = s2[0];
                out[3] = W3 + sha256Sig0(W4);
                out[2] = W2 + sha256Sig0(W3);
                out[1] = W1 + sha256Sig0(W2);
                out[0] = W0 + sha256Sig0(W1);
            } else if (in.cc == 5) {              // SHA256MSG2
                const uint32_t w14 = s2[2];
                const uint32_t w15 = s2[3];
                const uint32_t w16 = s1[0] + sha256Sig1(w14);
                const uint32_t w17 = s1[1] + sha256Sig1(w15);
                const uint32_t w18 = s1[2] + sha256Sig1(w16);
                const uint32_t w19 = s1[3] + sha256Sig1(w17);
                out[3] = w19; out[2] = w18; out[1] = w17; out[0] = w16;
            } else {                              // SHA256RNDS2 (cc == 6)
                uint8_t x0[16];
                readXmm(ctx, 16, x0);   // XMM0 is register index 16
                uint32_t wk[2];
                std::memcpy(wk, x0, 8);
                uint32_t A = s2[3], B = s2[2], C = s1[3], D = s1[2];
                uint32_t E = s2[1], F = s2[0], G = s1[1], H = s1[0];
                for (int i = 0; i < 2; ++i) {
                    const uint32_t ch = (E & F) ^ (~E & G);
                    const uint32_t maj = (A & B) ^ (A & C) ^ (B & C);
                    const uint32_t t1 = H + sha256Sum1(E) + ch + wk[i];
                    const uint32_t t2 = sha256Sum0(A) + maj;
                    H = G; G = F; F = E;
                    E = D + t1;
                    D = C; C = B; B = A;
                    A = t1 + t2;
                }
                out[3] = A; out[2] = B; out[1] = E; out[0] = F;
            }
            std::memcpy(a, out, 16);
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- SHLD / SHRD ------------------------------------------------
        // A shift of the destination whose vacated bits are filled from the
        // second register. A zero count leaves the destination and flags
        // untouched; otherwise CF is the last bit shifted out and OF is only
        // defined for a count of one.
        case X86Op::SHXD: {
            const int bits = in.dst.size ? in.dst.size : 32;
            const int count = static_cast<int>(readOperand(ctx, in.src2, 8)) &
                              (bits == 64 ? 63 : 31);
            uint64_t dstv = maskSize(readOperand(ctx, in.dst, bits), bits);
            if (count == 0) {
                writeOperand(ctx, in.dst, dstv, bits);
                ctx.rip = r.next_pc;
                return r;
            }
            const uint64_t srcv = maskSize(readOperand(ctx, in.src, bits), bits);
            uint64_t out;
            bool cf;
            if (in.cc == 0) {                     // SHLD
                out = maskSize((dstv << count) | (srcv >> (bits - count)), bits);
                cf = ((dstv >> (bits - count)) & 1) != 0;
            } else {                              // SHRD
                out = maskSize((dstv >> count) | (srcv << (bits - count)), bits);
                cf = ((dstv >> (count - 1)) & 1) != 0;
            }
            writeOperand(ctx, in.dst, out, bits);
            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            rf &= ~((1ULL << 0) | (1ULL << 6) | (1ULL << 7) | (1ULL << 2));
            if (cf) rf |= 1ULL << 0;
            if ((out >> (bits - 1)) & 1) rf |= 1ULL << 7;
            if (out == 0) rf |= 1ULL << 6;
            if (__builtin_parityll(out & 0xFF) == 0) rf |= 1ULL << 2;
            if (count == 1) {
                rf &= ~(1ULL << 11);
                if ((((out >> (bits - 1)) & 1) != 0) != cf) rf |= 1ULL << 11;
            }
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- ROUNDPS / ROUNDPD / ROUNDSS / ROUNDSD ----------------------
        case X86Op::ROUNDPS: case X86Op::ROUNDPD:
        case X86Op::ROUNDSS: case X86Op::ROUNDSD: {
            const bool scalar = (in.op == X86Op::ROUNDSS || in.op == X86Op::ROUNDSD);
            const bool dbl = (in.op == X86Op::ROUNDPD || in.op == X86Op::ROUNDSD);
            const int mode = static_cast<int>(in.src2.imm) & 3;
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, scalar ? (dbl ? 8 : 4) : 16))
                return sseFault(in.mnemonic.c_str());
            if (dbl) {
                const int lanes = scalar ? 1 : 2;
                for (int k = 0; k < lanes; ++k) {
                    double x;
                    std::memcpy(&x, b + 8 * k, 8);
                    const double v = roundByMode(x, mode);
                    std::memcpy(a + 8 * k, &v, 8);
                }
            } else {
                const int lanes = scalar ? 1 : 4;
                for (int k = 0; k < lanes; ++k) {
                    float x;
                    std::memcpy(&x, b + 4 * k, 4);
                    const float v = static_cast<float>(roundByMode(x, mode));
                    std::memcpy(a + 4 * k, &v, 4);
                }
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- RSQRTPS / RSQRTSS ------------------------------------------
        case X86Op::RSQRTPS: case X86Op::RSQRTSS: {
            const bool scalar = (in.op == X86Op::RSQRTSS);
            uint8_t a[16], b[16];
            readXmm(ctx, in.dst.reg, a);
            if (!loadSseSource(ctx, in.src, b, scalar ? 4 : 16))
                return sseFault(in.mnemonic.c_str());
            const int lanes = scalar ? 1 : 4;
            for (int k = 0; k < lanes; ++k) {
                float x;
                std::memcpy(&x, b + 4 * k, 4);
                const float v = 1.0f / std::sqrt(x);
                std::memcpy(a + 4 * k, &v, 4);
            }
            writeXmm(ctx, in.dst.reg, a);
            ctx.rip = r.next_pc;
            return r;
        }

        // UD0/UD1: deliberately undefined encodings.
        case X86Op::UD: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D;
            r.exception_msg = std::string(in.mnemonic) + ": #UD";
            return r;
        }

        case X86Op::INVALID:
        default: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D;
            r.exception_msg = std::string("unimplemented: ") + in.mnemonic;
            return r;
        }
    }
}

InterpResult InsnInterpreter::executeBlock(GuestContext& ctx, const uint8_t* code, size_t len,
                                           uint64_t max_insns) {
    InterpResult last;
    for (uint64_t i = 0; i < max_insns; ++i) {
        if (!code || len == 0) {
            last.exit = InterpExit::EXCEPTION;
            last.exception_code = 0xC0000005;
            last.exception_msg = "no code bytes";
            last.next_pc = ctx.rip;
            return last;
        }
        auto in = X86Decoder::decode(code, len, ctx.rip);
        if (!in || in->length == 0) {
            last.exit = InterpExit::EXCEPTION;
            last.exception_code = 0xC000001D;
            last.exception_msg = "decode failed";
            last.next_pc = ctx.rip;
            return last;
        }
        last = execute(ctx, *in);
        if (mem_fault_) {
            // A load/store inside a handler failed — surface it (prevents
            // silent corruption racing through linear interpretation).
            last = InterpResult{};
            last.exit = InterpExit::EXCEPTION;
            last.exception_code = 0xC0000005;
            std::string msg = std::string("memory fault (") + mem_fault_what_ +
                              ") ea=0x" +
                              [&]{std::ostringstream o;o<<std::hex<<mem_fault_addr_;return o.str();}() +
                              " rax=0x" + [&]{std::ostringstream o;o<<std::hex<<ctx.rax();return o.str();}() +
                              " rbp=0x" + [&]{std::ostringstream o;o<<std::hex<<ctx.rbp();return o.str();}() +
                              " rsp=0x" + [&]{std::ostringstream o;o<<std::hex<<ctx.rsp();return o.str();}() +
                              " trace:";
            for (auto& t : trace_) {
                std::ostringstream o;
                o << " " << std::hex << t.first << ":" << t.second;
                msg += o.str();
            }
            last.exception_msg = msg;
            last.next_pc = ctx.rip;
            mem_fault_ = false;
            return last;
        }
        if (last.exit != InterpExit::CONTINUE) return last;
        size_t consumed = in->length;
        if (consumed >= len) break;
        code += consumed;
        len -= consumed;
    }
    last.exit = InterpExit::BLOCK_END;
    last.next_pc = ctx.rip;
    return last;
}

} // namespace nexus
