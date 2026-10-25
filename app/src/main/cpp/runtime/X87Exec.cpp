// x87 execution: the D8-DF escape group.
//
// Values live in nexus::x87::State (see X87.h) as exact 80-bit pairs. Every
// arithmetic result is rounded back to x87's 64-bit significand with the control
// word's RC field, so the register file behaves like the real thing even though
// the intermediate is a host long double.
//
// Deliberate deviations, all documented in ARCHITECTURE.md:
//   * the FPU instruction/data pointers are not tracked; FSTENV/FNSAVE store
//     zeros in those fields and FLDENV/FRSTOR ignore them;
//   * precision control (CW.PC) is not honoured — everything is computed and
//     stored at extended precision, which is the default and the only setting
//     any 64-bit code uses;
//   * transcendental results come from the host libm rather than x87's own
//     lookup tables, so the last bits can differ from real silicon.

#include "InsnInterpreter.h"
#include "X87.h"

#include <cmath>
#include <cstring>

namespace nexus {

using x87::State;
using x87::Val;

namespace {

// Round to an integral value using the x87 rounding control.
long double roundPerCw(long double v, uint16_t cw) {
    if (!std::isfinite(v)) return v;
    switch ((cw >> 10) & 3) {
        case 1: return std::floorl(v);   // toward -inf
        case 2: return std::ceill(v);    // toward +inf
        case 3: return std::truncl(v);   // toward zero
        default: break;                  // nearest, ties to even (host default)
    }
    const long double lo = std::floorl(v);
    const long double frac = v - lo;
    if (frac < 0.5L) return lo;
    if (frac > 0.5L) return lo + 1.0L;
    return (std::fmodl(lo, 2.0L) == 0.0L) ? lo : lo + 1.0L;
}

Val constValue(int idx, uint16_t& sw) {
    switch (idx) {
        case 0: return x87::fromLd(1.0L, sw);
        case 1: return x87::fromLd(3.32192809488736234787031942949L, sw);  // log2(10)
        case 2: return x87::fromLd(1.44269504088896340735992468100L, sw);  // log2(e)
        case 3: return x87::fromLd(3.14159265358979323846264338328L, sw);  // pi
        case 4: return x87::fromLd(0.30102999566398119521373889472L, sw);  // log10(2)
        case 5: return x87::fromLd(0.69314718055994530941723212146L, sw);  // ln(2)
        default: return x87::makeZero(false);
    }
}

} // namespace

InterpResult InsnInterpreter::executeX87(GuestContext& ctx, const Insn& in) {
    InterpResult r;
    r.next_pc = ctx.rip + in.length;
    State& f = ctx.fpu;
    const uint8_t fl = in.x87_flags;
    const bool wantPop = (fl & X87F_POP) != 0;
    const bool wantInt = (fl & X87F_INT) != 0;

    auto fault = [&]() {
        InterpResult e;
        e.exit = InterpExit::EXCEPTION;
        e.exception_code = 0xC0000005;
        e.exception_msg = "x87 " + in.mnemonic + ": memory fault";
        e.next_pc = r.next_pc;
        return e;
    };
    auto memAddrOf = [&](const Operand& o) {
        return effectiveAddress(ctx, o.mem, ctx.rip, in.length);
    };
    // Tag bookkeeping for an architectural register index.
    auto retag = [&](int stIndex) { f.refreshTag((f.top() + stIndex) & 7); };

    // ---- read one operand (ST(i) or memory) ------------------------------
    auto readVal = [&](const Operand& o, int bits, bool isInt, Val& out) -> bool {
        if (o.kind == OperandKind::ST) { out = f.sti(o.reg); return true; }
        if (o.kind != OperandKind::MEM) { out = Val{}; return true; }
        const size_t n = static_cast<size_t>(bits / 8);
        uint8_t buf[16] = {};
        if (n > sizeof(buf)) return false;
        if (!loadMem(memAddrOf(o), buf, n)) return false;
        if (isInt) {
            long double v = 0.0L;
            if (bits == 16) { int16_t x; std::memcpy(&x, buf, 2); v = x; }
            else if (bits == 32) { int32_t x; std::memcpy(&x, buf, 4); v = x; }
            else { int64_t x; std::memcpy(&x, buf, 8); v = static_cast<long double>(x); }
            out = x87::fromLd(v, f.sw);
        } else if (bits == 32) {
            uint32_t b; std::memcpy(&b, buf, 4);
            out = x87::fromF32(b);
        } else if (bits == 64) {
            uint64_t b; std::memcpy(&b, buf, 8);
            out = x87::fromF64(b);
        } else {
            std::memcpy(&out.sig, buf, 8);
            uint16_t se; std::memcpy(&se, buf + 8, 2);
            out.se = se;
        }
        return true;
    };

    // ---- write one operand (ST(i) or memory) -----------------------------
    auto writeVal = [&](const Operand& o, int bits, bool isInt, const Val& v,
                        bool trunc) -> bool {
        if (o.kind == OperandKind::ST) {
            f.sti(o.reg) = v;
            retag(o.reg);
            return true;
        }
        if (o.kind != OperandKind::MEM) return true;
        uint8_t buf[16] = {};
        if (isInt) {
            const long double x = x87::toLd(v);
            const long double q = trunc ? std::truncl(x) : roundPerCw(x, f.cw);
            const long double hi = std::ldexp(1.0L, bits - 1);           // 2^(n-1)
            const long double lo = -hi;
            bool fits = std::isfinite(q) && q >= lo && q < hi;
            int64_t iv;
            if (!fits) {
                f.sw |= x87::SW_IE;
                iv = static_cast<int64_t>(std::ldexp(1.0L, bits - 1));  // "integer indefinite"
            } else {
                iv = static_cast<int64_t>(q);
                if (static_cast<long double>(iv) != q) f.sw |= x87::SW_PE;
            }
            if (bits == 16) { int16_t s = static_cast<int16_t>(iv); std::memcpy(buf, &s, 2); }
            else if (bits == 32) { int32_t s = static_cast<int32_t>(iv); std::memcpy(buf, &s, 4); }
            else std::memcpy(buf, &iv, 8);
            return storeMem(memAddrOf(o), buf, static_cast<size_t>(bits / 8));
        }
        if (bits == 32) {
            const uint32_t b = x87::toF32(v, f.sw);
            std::memcpy(buf, &b, 4);
        } else if (bits == 64) {
            const uint64_t b = x87::toF64(v, f.sw);
            std::memcpy(buf, &b, 8);
        } else {
            std::memcpy(buf, &v.sig, 8);
            std::memcpy(buf + 8, &v.se, 2);
        }
        return storeMem(memAddrOf(o), buf, static_cast<size_t>(bits / 8));
    };

    // ---- the 28-byte environment image ----------------------------------
    // 0 FCW, 2 FSW, 4 FTW, 6 FIP(8), 14 FDP(8), 22 FOP(2), 24..27 reserved.
    // NINE tracks no x87 instruction pointer, so FIP/FDP/FOP are stored as
    // zero; everything the guest can observe and restore round-trips exactly.
    auto saveEnv = [&](uint8_t* p) {
        std::memset(p, 0, 28);
        std::memcpy(p + 0, &f.cw, 2);
        std::memcpy(p + 2, &f.sw, 2);
        std::memcpy(p + 4, &f.tw, 2);
    };
    auto loadEnv = [&](const uint8_t* p) {
        std::memcpy(&f.cw, p + 0, 2);
        std::memcpy(&f.sw, p + 2, 2);
        std::memcpy(&f.tw, p + 4, 2);
    };

    switch (in.x87op) {
        // ---- arithmetic -------------------------------------------------
        case X87Op::ADD:
        case X87Op::MUL:
        case X87Op::SUB:
        case X87Op::SUBR:
        case X87Op::DIV:
        case X87Op::DIVR: {
            const int dstIdx = (in.dst.kind == OperandKind::ST) ? in.dst.reg : 0;
            Val b;
            if (!readVal(in.src, in.src.size ? in.src.size : 80, wantInt, b)) return fault();
            const long double left = x87::toLd(f.sti(dstIdx));
            const long double right = x87::toLd(b);
            const bool rev = (fl & X87F_REV) != 0 || in.x87op == X87Op::SUBR ||
                             in.x87op == X87Op::DIVR;
            const long double a = rev ? right : left;
            const long double c = rev ? left : right;
            const bool isDiv = in.x87op == X87Op::DIV || in.x87op == X87Op::DIVR;
            long double z = 0.0L;
            switch (in.x87op) {
                case X87Op::ADD: z = a + c; break;
                case X87Op::MUL: z = a * c; break;
                case X87Op::SUB:
                case X87Op::SUBR: z = a - c; break;
                default:
                    if (c == 0.0L && !std::isnan(a)) f.sw |= x87::SW_ZE;
                    z = a / c;
                    break;
            }
            f.sti(dstIdx) = x87::fromLd(z, f.sw, f.rc());
            retag(dstIdx);
            if (wantPop) f.pop();
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- compares into the status word -------------------------------
        case X87Op::COM:
        case X87Op::UCOM: {
            Val b;
            if (!readVal(in.src, in.src.size ? in.src.size : 80, wantInt, b)) return fault();
            const int c = x87::cmp(f.sti(0), b);
            f.sw &= static_cast<uint16_t>(~(x87::SW_C0 | x87::SW_C2 | x87::SW_C3));
            if (c == 2) {
                f.sw |= x87::SW_C0 | x87::SW_C2 | x87::SW_C3;
                // FCOM signals invalid on a QNaN; FUCOM is the quiet variant.
                if (in.x87op == X87Op::COM) f.sw |= x87::SW_IE;
            } else if (c < 0) {
                f.sw |= x87::SW_C0;
            } else if (c == 0) {
                f.sw |= x87::SW_C3;
            }
            if (wantPop) f.pop();
            if (fl & X87F_POP2) f.pop();
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- compares into EFLAGS ---------------------------------------
        case X87Op::COMI:
        case X87Op::UCOMI: {
            Val b;
            if (!readVal(in.src, in.src.size ? in.src.size : 80, wantInt, b)) return fault();
            const int c = x87::cmp(f.sti(0), b);
            uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            rf &= ~((1ULL << 0) | (1ULL << 2) | (1ULL << 4) | (1ULL << 6) |
                    (1ULL << 7) | (1ULL << 11));
            if (c == 2) {
                rf |= (1ULL << 0) | (1ULL << 2) | (1ULL << 6);
                // FCOMI signals on a QNaN, FUCOMI does not.
                if (in.x87op == X87Op::COMI) f.sw |= x87::SW_IE;
            } else if (c < 0) {
                rf |= 1ULL << 0;
            } else if (c == 0) {
                rf |= 1ULL << 6;
            }
            flags_.setRaw(rf);
            syncFlags(ctx);
            if (wantPop) f.pop();
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::TEST: {
            const int c = x87::cmp(f.sti(0), x87::makeZero(false));
            f.sw &= static_cast<uint16_t>(~(x87::SW_C0 | x87::SW_C2 | x87::SW_C3));
            if (c == 2) f.sw |= x87::SW_C0 | x87::SW_C2 | x87::SW_C3;
            else if (c < 0) f.sw |= x87::SW_C0;
            else if (c == 0) f.sw |= x87::SW_C3;
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- loads / stores ---------------------------------------------
        case X87Op::LOAD: {
            Val v;
            if (!readVal(in.src, in.src.size ? in.src.size : 80, wantInt, v)) return fault();
            f.push(v);
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::STORE: {
            const Val v = f.sti(0);
            if (!writeVal(in.dst, in.dst.size ? in.dst.size : 80, wantInt, v,
                          (fl & X87F_TRUNC) != 0))
                return fault();
            if (wantPop) f.pop();
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::XCH: {
            const int i = in.src.reg;
            const int pt = f.top();
            Val t = f.phys(pt);
            f.phys(pt) = f.sti(i);
            f.phys((pt + i) & 7) = t;
            f.refreshTag(pt);
            f.refreshTag((pt + i) & 7);
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::FREE:
            f.setTagSt(in.src.reg, x87::TAG_EMPTY);
            if (wantPop) f.pop();
            ctx.rip = r.next_pc;
            return r;

        case X87Op::STSW: {
            if (fl & X87F_AX) {
                ctx.rax() = (ctx.rax() & ~0xFFFFULL) | f.sw;
            } else {
                uint8_t buf[2];
                std::memcpy(buf, &f.sw, 2);
                if (!storeMem(memAddrOf(in.dst), buf, 2)) return fault();
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::STCW: {
            uint8_t buf[2];
            std::memcpy(buf, &f.cw, 2);
            if (!storeMem(memAddrOf(in.dst), buf, 2)) return fault();
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::FLDCW: {
            uint8_t buf[2];
            if (!loadMem(memAddrOf(in.src), buf, 2)) return fault();
            std::memcpy(&f.cw, buf, 2);
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::STENV: {
            uint8_t buf[28];
            saveEnv(buf);
            if (!storeMem(memAddrOf(in.dst), buf, sizeof(buf))) return fault();
            f.sw &= static_cast<uint16_t>(~0x7Fu);   // mask all exceptions
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::LDENV: {
            uint8_t buf[28];
            if (!loadMem(memAddrOf(in.src), buf, sizeof(buf))) return fault();
            loadEnv(buf);
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::SAVE: {
            // 108 bytes: 28-byte environment followed by ST(0..7), 10 bytes each.
            uint8_t buf[108];
            saveEnv(buf);
            for (int i = 0; i < 8; ++i) {
                std::memcpy(buf + 28 + 10 * i, &f.phys(i).sig, 8);
                std::memcpy(buf + 28 + 10 * i + 8, &f.phys(i).se, 2);
            }
            if (!storeMem(memAddrOf(in.dst), buf, sizeof(buf))) return fault();
            f.reset();   // FNSAVE leaves the FPU initialised
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::RESTORE: {
            uint8_t buf[108];
            if (!loadMem(memAddrOf(in.src), buf, sizeof(buf))) return fault();
            loadEnv(buf);
            for (int i = 0; i < 8; ++i) {
                std::memcpy(&f.phys(i).sig, buf + 28 + 10 * i, 8);
                std::memcpy(&f.phys(i).se, buf + 28 + 10 * i + 8, 2);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::CLR_EXCEPTIONS:
            f.sw &= static_cast<uint16_t>(~(x87::SW_IE | x87::SW_DE | x87::SW_ZE |
                                            x87::SW_OE | x87::SW_UE | x87::SW_PE |
                                            x87::SW_SF | x87::SW_ES));
            ctx.rip = r.next_pc;
            return r;

        case X87Op::INIT:
            f.reset();
            ctx.rip = r.next_pc;
            return r;

        case X87Op::NOP:
            ctx.rip = r.next_pc;
            return r;

        // ---- sign / magnitude / rounding --------------------------------
        case X87Op::CHS: {
            Val& v = f.sti(0);
            v.se = static_cast<uint16_t>(v.se ^ 0x8000);
            retag(0);
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::ABS: {
            Val& v = f.sti(0);
            v.se = static_cast<uint16_t>(v.se & 0x7FFF);
            retag(0);
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::SQRT: {
            const Val v = f.sti(0);
            if (x87::isNaN(v) || x87::signOf(v) && !x87::isZero(v)) {
                f.sw |= x87::SW_IE;
                f.sti(0) = x87::makeIndefinite();
            } else {
                f.sti(0) = x87::fromLd(std::sqrtl(x87::toLd(v)), f.sw, f.rc());
            }
            retag(0);
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::RNDINT: {
            const long double v = x87::toLd(f.sti(0));
            const long double q = roundPerCw(v, f.cw);
            f.sw &= static_cast<uint16_t>(~x87::SW_C1);
            if (q != v) f.sw |= x87::SW_C1;
            f.sti(0) = x87::fromLd(q, f.sw, f.rc());
            retag(0);
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::SCALE: {
            // ST(0) *= 2^trunc(ST(1))
            const long double e = std::truncl(x87::toLd(f.sti(1)));
            const long double base = x87::toLd(f.sti(0));
            long double z;
            if (e > 32767.0L) z = std::ldexp(base, 32767) * 2.0L;
            else if (e < -32767.0L) z = std::ldexp(base, -32767) / 2.0L;
            else z = std::ldexp(base, static_cast<int>(e));
            f.sw &= static_cast<uint16_t>(~x87::SW_C1);
            if (x87::toLd(f.sti(1)) != e) f.sw |= x87::SW_C1;
            f.sti(0) = x87::fromLd(z, f.sw, f.rc());
            retag(0);
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- partial remainder ------------------------------------------
        case X87Op::PREM:
        case X87Op::PREM1: {
            const long double a = x87::toLd(f.sti(0));
            const long double b = x87::toLd(f.sti(1));
            f.sw &= static_cast<uint16_t>(~(x87::SW_C0 | x87::SW_C1 | x87::SW_C2 | x87::SW_C3));
            if (std::isnan(a) || std::isnan(b) || std::isinf(a) || b == 0.0L) {
                if (!std::isnan(a) && !std::isnan(b)) f.sw |= x87::SW_IE;
                f.sti(0) = x87::makeIndefinite();
                f.sw |= x87::SW_C2;
                retag(0);
                ctx.rip = r.next_pc;
                return r;
            }
            if (std::isinf(b)) {          // |a| < inf: remainder is the dividend
                f.sti(0) = x87::fromLd(a, f.sw, f.rc());
                retag(0);
                ctx.rip = r.next_pc;
                return r;
            }
            const long double q = a / b;
            const bool complete = std::fabs(q) < 9223372036854775808.0L;  // 2^63
            const long double rem = (in.x87op == X87Op::PREM) ? std::fmodl(a, b)
                                                              : std::remainderl(a, b);
            const long double qi = (in.x87op == X87Op::PREM) ? std::truncl(q)
                                                             : std::nearbyintl(q);
            const long double q3 = std::fmodl(qi, 8.0L);
            const int bits = static_cast<int>(q3);
            if (bits & 1) f.sw |= x87::SW_C0;
            if (bits & 2) f.sw |= x87::SW_C3;
            if (bits & 4) f.sw |= x87::SW_C1;
            if (!complete) f.sw |= x87::SW_C2;   // reduction needs another pass
            f.sti(0) = x87::fromLd(rem, f.sw, f.rc());
            retag(0);
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::XTRACT: {
            // Intel's sequence: ST(0) := exponent, TOP--, ST(0) := significand
            // — so the result is ST(0) = significand (in [1,2), original sign)
            // and ST(1) = the unbiased exponent as a floating-point value.
            const Val v = f.sti(0);
            f.sw &= static_cast<uint16_t>(~x87::SW_C1);
            Val significand;
            Val exponent;
            if (x87::isZero(v)) {
                f.sw |= x87::SW_ZE;
                significand = v;                  // ±0 keeps its sign
                exponent = x87::makeInf(true);    // -inf
            } else if (x87::isNaN(v) || x87::isInf(v)) {
                if (x87::isInf(v)) f.sw |= x87::SW_IE;
                significand = x87::makeIndefinite();
                exponent = x87::makeIndefinite();
            } else {
                int e2 = 0;
                const long double m = std::frexpl(std::fabs(x87::toLd(v)), &e2);
                long double sig = m * 2.0L;       // [1, 2)
                if (x87::signOf(v)) sig = -sig;
                significand = x87::fromLd(sig, f.sw);
                exponent = x87::fromLd(static_cast<long double>(e2 - 1), f.sw);
            }
            f.sti(0) = exponent;
            f.push(significand);
            retag(0);
            retag(1);
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::EXAM: {
            const Val& v = f.sti(0);
            const bool empty = f.tagOfSt(0) == x87::TAG_EMPTY;
            f.sw &= static_cast<uint16_t>(~(x87::SW_C0 | x87::SW_C1 | x87::SW_C2 | x87::SW_C3));
            if (empty) {
                f.sw |= x87::SW_C3 | x87::SW_C2;
            } else if (x87::isNaN(v)) {
                // C3=C2=C1=C0=0
            } else if (x87::isInf(v)) {
                f.sw |= x87::SW_C2 | x87::SW_C0;
                if (x87::signOf(v)) f.sw |= x87::SW_C1;
            } else if (x87::isZero(v)) {
                f.sw |= x87::SW_C3;
                if (x87::signOf(v)) f.sw |= x87::SW_C1;
            } else if (x87::isDenormal(v)) {
                f.sw |= x87::SW_C3 | x87::SW_C0;
                if (x87::signOf(v)) f.sw |= x87::SW_C1;
            } else {
                f.sw |= x87::SW_C2;   // normal finite
                if (x87::signOf(v)) f.sw |= x87::SW_C1;
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::CONST: {
            f.push(constValue(static_cast<int>(in.src.imm), f.sw));
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- transcendentals --------------------------------------------
        case X87Op::F2XM1: {
            const long double x = x87::toLd(f.sti(0));
            if (!(x >= -1.0L && x <= 1.0L)) {
                f.sw |= x87::SW_IE;
                f.sti(0) = x87::makeIndefinite();
            } else {
                f.sti(0) = x87::fromLd(std::exp2l(x) - 1.0L, f.sw, f.rc());
            }
            retag(0);
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::FYL2X:
        case X87Op::FYL2XP1: {
            const long double y = x87::toLd(f.sti(1));
            long double x = x87::toLd(f.sti(0));
            if (in.x87op == X87Op::FYL2XP1) x += 1.0L;
            long double z;
            if (std::isnan(x) || std::isnan(y)) z = std::nanl("");
            else if (x < 0.0L) { f.sw |= x87::SW_IE; z = std::nanl(""); }
            else if (x == 0.0L) { f.sw |= x87::SW_ZE; z = -HUGE_VALL; }
            else z = y * std::log2l(x);
            f.sti(1) = x87::fromLd(z, f.sw, f.rc());
            retag(1);
            f.pop();
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::FPTAN: {
            const long double x = x87::toLd(f.sti(0));
            if (std::fabs(x) >= 9223372036854775808.0L) {
                f.sw |= x87::SW_C2;      // argument reduction incomplete
                ctx.rip = r.next_pc;
                return r;
            }
            f.sw &= static_cast<uint16_t>(~x87::SW_C2);
            const long double t = std::tanl(x);
            f.sti(0) = x87::fromLd(t, f.sw, f.rc());
            f.push(x87::fromLd(1.0L, f.sw));   // FPTAN always pushes 1.0
            retag(0);
            retag(1);
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::FPATAN: {
            const long double y = x87::toLd(f.sti(1));
            const long double x = x87::toLd(f.sti(0));
            f.sti(1) = x87::fromLd(std::atan2l(y, x), f.sw, f.rc());
            retag(1);
            f.pop();
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::SIN:
        case X87Op::COS: {
            const long double x = x87::toLd(f.sti(0));
            if (std::fabs(x) >= 9223372036854775808.0L) {
                f.sw |= x87::SW_C2;
                ctx.rip = r.next_pc;
                return r;
            }
            f.sw &= static_cast<uint16_t>(~x87::SW_C2);
            const long double z = (in.x87op == X87Op::SIN) ? std::sinl(x) : std::cosl(x);
            f.sti(0) = x87::fromLd(z, f.sw, f.rc());
            retag(0);
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::SINCOS: {
            const long double x = x87::toLd(f.sti(0));
            if (std::fabs(x) >= 9223372036854775808.0L) {
                f.sw |= x87::SW_C2;
                ctx.rip = r.next_pc;
                return r;
            }
            f.sw &= static_cast<uint16_t>(~x87::SW_C2);
            const long double s = std::sinl(x);
            const long double c = std::cosl(x);
            f.sti(0) = x87::fromLd(s, f.sw, f.rc());
            f.push(x87::fromLd(c, f.sw, f.rc()));   // cosine is pushed on top
            retag(0);
            retag(1);
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::DECSTP:
            f.setTop((f.top() - 1) & 7);
            f.sw &= static_cast<uint16_t>(~x87::SW_C1);
            ctx.rip = r.next_pc;
            return r;

        case X87Op::INCSTP:
            f.setTop((f.top() + 1) & 7);
            f.sw &= static_cast<uint16_t>(~x87::SW_C1);
            ctx.rip = r.next_pc;
            return r;

        case X87Op::CMOV: {
            const uint8_t cc = in.cc & 7;
            const uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
            const bool cf = (rf >> 0) & 1;
            const bool zf = (rf >> 6) & 1;
            const bool pf = (rf >> 2) & 1;
            bool take = false;
            switch (cc & 3) {
                case 0: take = cf; break;          // B
                case 1: take = zf; break;          // E
                case 2: take = cf || zf; break;    // BE
                default: take = pf; break;         // U
            }
            if (cc & 4) take = !take;              // Ncc
            if (take) {
                f.sti(0) = f.sti(in.src.reg);
                retag(0);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        // ---- packed BCD --------------------------------------------------
        case X87Op::BCD_LOAD: {
            uint8_t buf[10];
            if (!loadMem(memAddrOf(in.src), buf, sizeof(buf))) return fault();
            const bool neg = (buf[9] & 0x80) != 0;
            long double v = 0.0L;
            for (int i = 8; i >= 0; --i) {
                v = v * 100.0L + (buf[i] >> 4) * 10.0L + (buf[i] & 0x0F);
            }
            if (neg) v = -v;
            f.push(x87::fromLd(v, f.sw));
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::BCD_STORE: {
            const long double x = roundPerCw(x87::toLd(f.sti(0)), f.cw);
            const bool neg = std::signbit(x);
            long double a = std::fabs(x);
            uint8_t buf[10] = {};
            if (!std::isfinite(a) || a >= 1e18L) {
                f.sw |= x87::SW_IE;
                std::memset(buf, 0, 9);
                buf[9] = 0x80;   // integer indefinite form
            } else {
                for (int i = 0; i < 9; ++i) {
                    const int two = static_cast<int>(std::fmodl(a, 100.0L));
                    a = std::floorl(a / 100.0L);
                    buf[i] = static_cast<uint8_t>(((two / 10) << 4) | (two % 10));
                }
                buf[9] = static_cast<uint8_t>(neg ? 0x80 : 0x00);
            }
            if (!storeMem(memAddrOf(in.dst), buf, sizeof(buf))) return fault();
            if (wantPop) f.pop();
            ctx.rip = r.next_pc;
            return r;
        }

        case X87Op::INVALID:
        default: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D;
            r.exception_msg = std::string("unimplemented: ") + in.mnemonic;
            return r;
        }
    }
}

} // namespace nexus
