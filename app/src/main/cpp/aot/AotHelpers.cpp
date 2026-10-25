#include "AotImage.h"
#include "../runtime/GuestContext.h"

// Runtime support called from AOT-compiled code.
//
// The generated code keeps guest state in GuestContext memory; flag updates go
// through this helper so the arithmetic-flag rules exist in exactly one place
// (they mirror translator/FlagState.cpp). Everything else — register moves,
// address computation, branches, calls — is emitted natively by AotCompiler.

namespace nexus {
namespace aot {

namespace {

inline uint64_t maskFor(int bits) {
    if (bits >= 64) return ~0ull;
    return (1ull << bits) - 1ull;
}

inline bool parityEven(uint8_t v) {
    v ^= static_cast<uint8_t>(v >> 4);
    v ^= static_cast<uint8_t>(v >> 2);
    v ^= static_cast<uint8_t>(v >> 1);
    return (v & 1) == 0;
}

} // namespace

} // namespace aot
} // namespace nexus

extern "C" {

// kind: 0 = add, 1 = sub, 2 = logic, 3 = inc/dec (CF preserved)
// bits: 8 / 16 / 32 / 64
// keep: non-zero preserves CF from the incoming RFLAGS (INC/DEC)
//
// Returns the masked result so emitted code can store it after the call: every
// register the generated block would otherwise keep the value in is
// caller-saved, so the value has to come back in x0.
uint64_t nine_aot_flags(nexus::GuestContext* ctx, int kind, uint64_t res,
                        uint64_t a, uint64_t b, int bits, int keep) {
    using namespace nexus::aot;
    if (!ctx) return res;
    if (bits <= 0) bits = 32;
    const uint64_t mask = maskFor(bits);
    const uint64_t r = res & mask;
    const uint64_t x = a & mask;
    const uint64_t y = b & mask;
    const uint64_t sign = 1ull << (bits - 1);
    const uint64_t old = ctx->rflags;

    bool cf = false, of = false, af = false;
    switch (kind) {
        case 1: // sub
            cf = x < y;
            of = (((x ^ y) & (x ^ r)) & sign) != 0;
            af = (((x ^ y ^ r) & 0x10) != 0);
            break;
        case 2: // logic
            break;
        case 3: // inc/dec keeps CF
            cf = (old & 1ull) != 0;
            of = (((~(x ^ y)) & (x ^ r)) & sign) != 0;
            af = (((x ^ y ^ r) & 0x10) != 0);
            break;
        default: // add
            cf = r < x;
            of = (((~(x ^ y)) & (x ^ r)) & sign) != 0;
            af = (((x ^ y ^ r) & 0x10) != 0);
            break;
    }
    if (keep) cf = (old & 1ull) != 0;

    uint64_t nf = old & ~0x8D5ull;             // keep IF/DF/AC/IOPL...
    nf |= 0x2;                                 // reserved bit 1
    if (cf) nf |= 1ull << 0;
    if (parityEven(static_cast<uint8_t>(r))) nf |= 1ull << 2;
    if (af) nf |= 1ull << 4;
    if (r == 0) nf |= 1ull << 6;
    if (r & sign) nf |= 1ull << 7;
    if (of) nf |= 1ull << 11;
    ctx->rflags = nf;
    return r;
}

// kind: 0 = shl, 1 = shr, 2 = sar, 3 = rol, 4 = ror
// A zero count leaves every flag untouched, matching x86.
uint64_t nine_aot_shift_flags(nexus::GuestContext* ctx, uint64_t res, uint64_t src,
                              uint64_t count, int bits, int kind) {
    using namespace nexus::aot;
    if (!ctx) return res;
    if (bits <= 0) bits = 32;
    const uint64_t mask = maskFor(bits);
    const unsigned c = static_cast<unsigned>(count) & (bits == 64 ? 63u : 31u);
    if (c == 0) return res & mask;
    const uint64_t r = res & mask;
    const uint64_t s = src & mask;
    const uint64_t sign = 1ull << (bits - 1);
    uint64_t nf = ctx->rflags;

    bool cf = false, of = false;
    switch (kind) {
        case 0: // shl
            cf = ((s >> (bits - c)) & 1ull) != 0;
            of = (((r & sign) != 0) != cf);
            break;
        case 1: // shr
            cf = ((s >> (c - 1)) & 1ull) != 0;
            of = ((s & sign) != 0);
            break;
        case 2: // sar
            cf = ((s >> (c - 1)) & 1ull) != 0;
            of = false;
            break;
        case 3: // rol
            cf = (r & 1ull) != 0;
            of = (((r & sign) != 0) != cf);
            break;
        default: // ror
            cf = (r & sign) != 0;
            of = (((r & sign) != 0) != (((r >> (bits - 2)) & 1ull) != 0));
            break;
    }

    nf &= (kind <= 2) ? ~((1ull << 0) | (1ull << 2) | (1ull << 6) | (1ull << 7) | (1ull << 11))
                      : ~((1ull << 0) | (1ull << 11));
    if (cf) nf |= 1ull << 0;
    if (of) nf |= 1ull << 11;
    if (kind <= 2) {   // shifts set SZP from the result; rotates leave them alone
        if (parityEven(static_cast<uint8_t>(r))) nf |= 1ull << 2;
        if (r == 0) nf |= 1ull << 6;
        if (r & sign) nf |= 1ull << 7;
    }
    ctx->rflags = nf;
    return r;
}

} // extern "C"
