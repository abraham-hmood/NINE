#pragma once

// x87 floating-point register file and 80-bit value arithmetic.
//
// NINE keeps every ST(i) in the real 80-bit "double extended" format instead of
// a host long double: the register file has to round-trip through guest memory
// (FLD m80fp / FSTP m80fp, FNSAVE, FXSAVE) byte-exactly, and the host's long
// double is not the same type on every target (binary128 on aarch64, 80-bit on
// x86-64, plain double with MSVC). Two 16/64-bit halves make the representation
// exact everywhere.
//
// Arithmetic itself is performed in the host long double and rounded back to
// x87's 64-bit significand by fromLd(). On aarch64 long double carries 113
// significand bits, so the intermediate is wide enough that a single rounding
// to 64 bits gives the correctly rounded x87 result for + - * / and sqrt.

#include <cmath>
#include <cstdint>
#include <cstring>

namespace nexus {
namespace x87 {

struct Val {
    uint64_t sig = 0;  // 64-bit significand, explicit integer bit
    uint16_t se = 0;   // bit 15 = sign, bits 14..0 = biased exponent
};

// Status word bits (the architectural layout; TOP lives in bits 13..11).
enum : uint16_t {
    SW_IE = 1u << 0,   // invalid operation
    SW_DE = 1u << 1,   // denormal operand
    SW_ZE = 1u << 2,   // divide-by-zero
    SW_OE = 1u << 3,   // overflow
    SW_UE = 1u << 4,   // underflow
    SW_PE = 1u << 5,   // precision
    SW_SF = 1u << 6,   // stack fault
    SW_ES = 1u << 7,   // exception summary
    SW_C0 = 1u << 8,
    SW_C1 = 1u << 9,
    SW_C2 = 1u << 10,
    SW_C3 = 1u << 14,
    SW_B  = 1u << 15,
};

// Tag word values, two bits per physical register.
enum : uint16_t { TAG_VALID = 0, TAG_ZERO = 1, TAG_SPECIAL = 2, TAG_EMPTY = 3 };

inline uint16_t expOf(const Val& v) { return static_cast<uint16_t>(v.se & 0x7FFF); }
inline bool signOf(const Val& v) { return (v.se & 0x8000) != 0; }
inline bool isZero(const Val& v) { return expOf(v) == 0 && v.sig == 0; }
inline bool isDenormal(const Val& v) { return expOf(v) == 0 && v.sig != 0; }
inline bool isInf(const Val& v) { return expOf(v) == 0x7FFF && v.sig == 0x8000000000000000ULL; }
inline bool isNaN(const Val& v) { return expOf(v) == 0x7FFF && v.sig != 0x8000000000000000ULL; }
inline bool isFinite(const Val& v) { return expOf(v) != 0x7FFF; }

inline Val makeInf(bool neg) {
    Val v;
    v.sig = 0x8000000000000000ULL;
    v.se = static_cast<uint16_t>(0x7FFF | (neg ? 0x8000 : 0));
    return v;
}

// x87's "real indefinite" QNaN, produced by every invalid operation.
inline Val makeIndefinite() {
    Val v;
    v.sig = 0xC000000000000000ULL;
    v.se = 0x7FFF;
    return v;
}

inline Val makeZero(bool neg) {
    Val v;
    v.se = static_cast<uint16_t>(neg ? 0x8000 : 0);
    return v;
}

// ---------------------------------------------------------------------------
// 80-bit <-> host conversions
// ---------------------------------------------------------------------------

inline long double toLd(const Val& v) {
    const uint16_t e = expOf(v);
    if (e == 0x7FFF) {
        long double r = (v.sig == 0x8000000000000000ULL) ? HUGE_VALL : NAN;
        return signOf(v) ? -r : r;
    }
    if (e == 0 && v.sig == 0) return signOf(v) ? -0.0L : 0.0L;
    // Normals: sig * 2^(e - 16383 - 63). Denormals use the same expression with
    // an effective exponent of 1 (i.e. sig * 2^-16445).
    const int ex = static_cast<int>(e == 0 ? 1 : e) - 16383 - 63;
    long double r = std::ldexp(static_cast<long double>(v.sig), ex);
    return signOf(v) ? -r : r;
}

// Round `scaled` (a positive magnitude already on the 64-bit grid) to an
// integer using the x87 rounding control. `inexact` reports lost bits and
// `carried` reports a round-up that wrapped past 2^64 into the next binade
// (which the caller must absorb by incrementing the exponent).
inline uint64_t roundScaled(long double scaled, unsigned rc, bool& inexact,
                            bool& carried) {
    const long double fl = std::floorl(scaled);
    const long double frac = scaled - fl;
    inexact = frac != 0.0L;
    carried = false;
    if (fl >= 18446744073709551616.0L) {  // 2^64: already out of range
        carried = true;
        return 0;
    }
    uint64_t ip = static_cast<uint64_t>(fl);
    bool up = false;
    switch (rc & 3) {
        case 0:  // round to nearest, ties to even
            up = frac > 0.5L || (frac == 0.5L && (ip & 1));
            break;
        case 1:  // round down (toward -inf); the caller flips rc for negatives
            break;
        case 2:  // round up (toward +inf)
            up = frac > 0.0L;
            break;
        default: // truncate
            break;
    }
    if (up) {
        ++ip;
        if (ip == 0) carried = true;   // wrapped to 2^64
    }
    return ip;
}

// Convert a host long double to an 80-bit value, rounding the significand to
// x87's 64 bits with the requested rounding control (0=nearest, 1=down,
// 2=up, 3=truncate) and raising the matching status-word bits.
inline Val fromLd(long double x, uint16_t& sw, unsigned rc = 0) {
    Val v;
    const bool neg = std::signbit(x);
    const uint16_t sbit = static_cast<uint16_t>(neg ? 0x8000 : 0);

    if (std::isnan(x)) {
        sw |= SW_IE;
        return makeIndefinite();
    }
    if (std::isinf(x)) {
        sw |= SW_OE;
        return makeInf(neg);
    }
    if (x == 0.0L) return makeZero(neg);

    const long double a = neg ? -x : x;
    int e2 = 0;
    const long double m = std::frexpl(a, &e2);  // a = m * 2^e2, m in [0.5, 1)
    int ex = e2 - 1;                            // a = (2m) * 2^ex, 2m in [1, 2)
    int biased = ex + 16383;

    long double scaled;
    if (biased >= 1) {
        scaled = std::ldexpl(a, 63 - ex);       // in [2^63, 2^64)
    } else {
        scaled = std::ldexpl(a, 16445);         // denormal grid, < 2^63
        biased = 0;
    }

    // Rounding toward -inf/0 flips for negatives because we round |x|.
    unsigned eff = rc & 3;
    if (neg) {
        if (eff == 1) eff = 2;
        else if (eff == 2) eff = 1;
    }

    bool inexact = false;
    bool carried = false;
    uint64_t ip = roundScaled(scaled, eff, inexact, carried);
    if (carried) {                     // rounded up into the next binade
        ip = 0x8000000000000000ULL;
        ++biased;
    }

    if (biased >= 0x7FFF) {
        sw |= SW_OE;
        if (inexact) sw |= SW_PE;
        return makeInf(neg);
    }
    if (ip == 0) {                    // underflowed to zero
        sw |= SW_UE;
        if (inexact) sw |= SW_PE;
        return makeZero(neg);
    }
    if (biased == 0) sw |= SW_UE;     // subnormal result
    if (inexact) sw |= SW_PE;

    v.sig = ip;
    v.se = static_cast<uint16_t>(sbit | static_cast<uint16_t>(biased));
    return v;
}

// 32/64-bit binary interchange conversions (exact, no status word).
inline Val fromF32(uint32_t bits) {
    Val v;
    const uint16_t s = static_cast<uint16_t>((bits >> 31) ? 0x8000 : 0);
    const uint32_t e = (bits >> 23) & 0xFF;
    uint32_t m = bits & 0x7FFFFF;
    if (e == 0xFF) {
        v.sig = m ? (0x8000000000000000ULL | (static_cast<uint64_t>(m) << 40))
                  : 0x8000000000000000ULL;
        v.se = static_cast<uint16_t>(s | 0x7FFF);
        return v;
    }
    if (e == 0 && m == 0) { v.se = s; return v; }
    if (e == 0) {                      // 32-bit denormal -> 80-bit normal
        int shift = 0;
        while (!(m & 0x800000)) { m <<= 1; ++shift; }
        m &= 0x7FFFFF;
        v.sig = 0x8000000000000000ULL | (static_cast<uint64_t>(m) << 40);
        v.se = static_cast<uint16_t>(s | static_cast<uint16_t>(1 - 127 + 16383 - shift));
        return v;
    }
    v.sig = 0x8000000000000000ULL | (static_cast<uint64_t>(m) << 40);
    v.se = static_cast<uint16_t>(s | static_cast<uint16_t>(e - 127 + 16383));
    return v;
}

inline Val fromF64(uint64_t bits) {
    Val v;
    const uint16_t s = static_cast<uint16_t>((bits >> 63) ? 0x8000 : 0);
    const uint32_t e = static_cast<uint32_t>((bits >> 52) & 0x7FF);
    uint64_t m = bits & 0xFFFFFFFFFFFFFULL;
    if (e == 0x7FF) {
        v.sig = m ? (0x8000000000000000ULL | (m << 11)) : 0x8000000000000000ULL;
        v.se = static_cast<uint16_t>(s | 0x7FFF);
        return v;
    }
    if (e == 0 && m == 0) { v.se = s; return v; }
    if (e == 0) {
        int shift = 0;
        while (!(m & 0x10000000000000ULL)) { m <<= 1; ++shift; }
        m &= 0xFFFFFFFFFFFFFULL;
        v.sig = 0x8000000000000000ULL | (m << 11);
        v.se = static_cast<uint16_t>(s | static_cast<uint16_t>(1 - 1023 + 16383 - shift));
        return v;
    }
    v.sig = 0x8000000000000000ULL | (m << 11);
    v.se = static_cast<uint16_t>(s | static_cast<uint16_t>(e - 1023 + 16383));
    return v;
}

// 80-bit -> binary32/binary64 with rounding to nearest-even.
inline uint32_t toF32(const Val& in, uint16_t& sw) {
    const uint32_t s = signOf(in) ? 0x80000000u : 0;
    const uint16_t e = expOf(in);
    if (e == 0x7FFF) {
        if (in.sig == 0x8000000000000000ULL) return s | 0x7F800000u;
        uint32_t m = static_cast<uint32_t>((in.sig >> 40) & 0x7FFFFF);
        if (!m) m = 0x400000;
        return s | 0x7F800000u | m;
    }
    if (in.sig == 0 && e == 0) return s;
    const long double x = toLd(in);
    if (std::fabs(x) > 3.4028235677973366e38L) {
        sw |= SW_OE;
        return s | 0x7F800000u;
    }
    float f = static_cast<float>(x);   // values are exactly representable here
    uint32_t bits = 0;
    std::memcpy(&bits, &f, 4);
    if (std::fabs(x) < 1.1754943508222875e-38L) sw |= SW_UE;
    return bits;
}

inline uint64_t toF64(const Val& in, uint16_t& sw) {
    const uint64_t s = signOf(in) ? 0x8000000000000000ULL : 0;
    const uint16_t e = expOf(in);
    if (e == 0x7FFF) {
        if (in.sig == 0x8000000000000000ULL) return s | 0x7FF0000000000000ULL;
        uint64_t m = (in.sig >> 11) & 0xFFFFFFFFFFFFFULL;
        if (!m) m = 0x8000000000000ULL;
        return s | 0x7FF0000000000000ULL | m;
    }
    if (in.sig == 0 && e == 0) return s;
    const long double x = toLd(in);
    if (std::fabs(x) > 1.7976931348623157e308L) {
        sw |= SW_OE;
        return s | 0x7FF0000000000000ULL;
    }
    double d = static_cast<double>(x);
    uint64_t bits = 0;
    std::memcpy(&bits, &d, 8);
    if (std::fabs(x) < 2.2250738585072014e-308L) sw |= SW_UE;
    return bits;
}

inline int cmp(const Val& a, const Val& b) {
    if (isNaN(a) || isNaN(b)) return 2;  // unordered
    const long double x = toLd(a), y = toLd(b);
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}

// ---------------------------------------------------------------------------
// Register stack
// ---------------------------------------------------------------------------
struct State {
    Val st[8];
    uint16_t cw = 0x037F;  // RC=nearest, PC=extended precision, all masked
    uint16_t sw = 0;       // TOP lives in bits 13..11
    uint16_t tw = 0xFFFF;  // 2 bits per physical register, 11 = empty

    int top() const { return (sw >> 11) & 7; }
    void setTop(int t) {
        sw = static_cast<uint16_t>((sw & ~0x3800u) | ((t & 7) << 11));
    }
    unsigned rc() const { return (cw >> 10) & 3; }

    Val& phys(int p) { return st[p & 7]; }
    const Val& phys(int p) const { return st[p & 7]; }
    Val& sti(int i) { return st[(top() + i) & 7]; }
    const Val& sti(int i) const { return st[(top() + i) & 7]; }

    int tagOf(int p) const { return (tw >> (2 * (p & 7))) & 3; }
    void setTag(int p, int v) {
        const int sh = 2 * (p & 7);
        tw = static_cast<uint16_t>((tw & ~(3u << sh)) | ((v & 3) << sh));
    }
    int tagOfSt(int i) const { return tagOf((top() + i) & 7); }
    void setTagSt(int i, int v) { setTag((top() + i) & 7, v); }

    // Recompute the tag for one physical register from its value.
    void refreshTag(int p) {
        const Val& v = phys(p);
        int t;
        if (expOf(v) == 0x7FFF) t = TAG_SPECIAL;       // NaN / infinity
        else if (isZero(v)) t = TAG_ZERO;
        else if (isDenormal(v)) t = TAG_SPECIAL;       // unnormal / denormal
        else t = TAG_VALID;
        setTag(p, t);
    }

    void setC(int bit, bool on) {
        if (on) sw = static_cast<uint16_t>(sw | bit);
        else sw = static_cast<uint16_t>(sw & ~bit);
    }

    // Push a value; returns false (and flags a stack overflow) when the slot
    // about to be overwritten was still occupied.
    bool push(const Val& v) {
        const int t = (top() - 1) & 7;
        const bool overflow = tagOf(t) != TAG_EMPTY;
        setTop(t);
        phys(t) = v;
        refreshTag(t);
        if (overflow) {
            sw |= SW_C1 | SW_SF | SW_IE;
            return false;
        }
        return true;
    }

    // Pop one register; returns false (stack underflow) if it was empty.
    bool pop() {
        const int t = top();
        const bool underflow = tagOf(t) == TAG_EMPTY;
        setTag(t, TAG_EMPTY);
        setTop((t + 1) & 7);
        if (underflow) {
            sw |= SW_C1 | SW_SF | SW_IE;
            return false;
        }
        return true;
    }

    void reset() {  // FINIT / FNINIT
        cw = 0x037F;
        sw = 0;
        tw = 0xFFFF;
        for (auto& v : st) v = Val{};
    }
};

} // namespace x87
} // namespace nexus
