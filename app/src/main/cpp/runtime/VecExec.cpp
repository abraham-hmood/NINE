// ---------------------------------------------------------------------------
// AVX / AVX2 / AVX-512 execution.
//
// One entry point drives every VEX and EVEX data instruction. The decoder has
// already resolved the encoding to a VecOp, a lane width, a numeric domain and
// a vector length; this file supplies the element-wise kernels and the shared
// writemask / merge / broadcast semantics.
//
// Vector registers live in GuestContext::ymm[32][64]. XMM is the low 16 bytes,
// YMM the low 32, ZMM all 64, which is exactly the architectural aliasing.
// ---------------------------------------------------------------------------

#include "InsnInterpreter.h"
#include "AesPrimitives.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <string>

namespace nexus {

namespace {

inline uint64_t ldv(const uint8_t* p, int n) {
    uint64_t v = 0;
    for (int k = 0; k < n; ++k) v |= static_cast<uint64_t>(p[k]) << (8 * k);
    return v;
}
inline void stv(uint8_t* p, uint64_t v, int n) {
    for (int k = 0; k < n; ++k) p[k] = static_cast<uint8_t>(v >> (8 * k));
}
inline int64_t sx(uint64_t v, int bits) {
    if (bits >= 64) return static_cast<int64_t>(v);
    const uint64_t m = 1ULL << (bits - 1);
    const uint64_t u = v & ((1ULL << bits) - 1);
    return static_cast<int64_t>((u ^ m) - m);
}
inline uint64_t satS(int64_t v, int bits) {
    const int64_t lo = -(1LL << (bits - 1));
    const int64_t hi = (1LL << (bits - 1)) - 1;
    return static_cast<uint64_t>(v < lo ? lo : (v > hi ? hi : v));
}
inline uint64_t satU(int64_t v, int bits) {
    const uint64_t hi = bits >= 64 ? ~0ULL : ((1ULL << bits) - 1);
    return v < 0 ? 0 : static_cast<uint64_t>(v) > hi ? hi : static_cast<uint64_t>(v);
}
inline uint32_t rotl32(uint32_t v, int n) { n &= 31; return n ? (v << n) | (v >> (32 - n)) : v; }

// GF(2^8) inverse for VGF2P8AFFINEINVQB: a^254 in the AES field.
inline uint8_t gfInv(uint8_t a) {
    if (!a) return 0;
    uint8_t r = 1;
    for (int i = 0; i < 254; ++i) r = aes::gmul(r, a);
    return r;
}

// Rounding used by the AVX-512 conversions and VRNDSCALE. MXCSR is assumed at
// its reset value (round-to-nearest-even) unless the instruction carries an
// explicit mode, which is what these helpers implement.
inline double roundMode(double x, int mode) {
    if (!std::isfinite(x)) return x;
    switch (mode & 7) {
        case 0: return std::nearbyint(x);
        case 1: return std::floor(x);
        case 2: return std::ceil(x);
        case 3: return std::trunc(x);
        default: return std::nearbyint(x);
    }
}

// avx512 min/max: the second source wins on NaN and on equal zeros.
inline float fminx(float a, float b) { return (std::isnan(a) || std::isnan(b)) ? b : (a < b ? a : b); }
inline float fmaxx(float a, float b) { return (std::isnan(a) || std::isnan(b)) ? b : (a > b ? a : b); }
inline double fminx(double a, double b) { return (std::isnan(a) || std::isnan(b)) ? b : (a < b ? a : b); }
inline double fmaxx(double a, double b) { return (std::isnan(a) || std::isnan(b)) ? b : (a > b ? a : b); }

inline bool cmpFloat(double a, double b, int p) {
    switch (p & 15) {
        case 0: return a == b;
        case 1: return a < b;
        case 2: return a <= b;
        case 3: return std::isnan(a) || std::isnan(b);
        case 4: return !(a == b);
        case 5: return !(a < b);
        case 6: return !(a <= b);
        case 7: return !std::isnan(a) && !std::isnan(b);
        case 8: return a == b;
        case 9: return !(a >= b);
        case 10: return !(a > b);
        case 11: return false;
        case 12: return a != b;
        case 13: return a >= b;
        case 14: return a > b;
        default: return true;
    }
}

} // namespace

InterpResult InsnInterpreter::executeVec(GuestContext& ctx, const Insn& in) {
    InterpResult r;
    r.next_pc = ctx.rip + in.length;

    const int width = static_cast<int>(in.vec_bits / 8);
    const int elemB = in.elem_bits ? static_cast<int>(in.elem_bits / 8) : width;
    const bool isF32 = in.vec_class == VC_F32;
    const bool isF64 = in.vec_class == VC_F64;
    const bool isFloat = isF32 || isF64;
    const bool isU = in.vec_class == VC_UINT;
    const std::string nm = in.mnemonic;
    const char* ns = nm.c_str();
    auto has = [&](const char* s) { return nm.find(s) != std::string::npos; };
    auto starts = [&](const char* s) { return nm.rfind(s, 0) == 0; };
    // Scalar forms (…ss / …sd) operate on lane 0 only and merge the rest of
    // the register from VEX.vvvv.
    const bool scalarForm = elemB <= 8 && nm.size() >= 2 &&
                            (nm.compare(nm.size() - 2, 2, "ss") == 0 ||
                             nm.compare(nm.size() - 2, 2, "sd") == 0) &&
                            !has("dpwssd");
    const int fullLanes = elemB ? width / elemB : 1;
    const int lanes = scalarForm ? 1 : fullLanes;

    // ---- operand loads -------------------------------------------------
    uint8_t a[64] = {};   // VEX.vvvv (first source)
    uint8_t b[64] = {};   // ModRM.r/m (second source)
    uint8_t d[64] = {};   // current destination
    auto regPtr = [&](int reg) -> uint8_t* {
        return ctx.ymm[(reg - 16) & 31];
    };
    auto loadOp = [&](const Operand& op, uint8_t* out, int bytes) -> bool {
        std::memset(out, 0, 64);
        if (op.kind == OperandKind::REG && op.reg >= 16) {
            std::memcpy(out, regPtr(op.reg), static_cast<size_t>(std::min(bytes, 64)));
            return true;
        }
        if (op.kind == OperandKind::MEM) {
            const uint64_t ea = effectiveAddress(ctx, op.mem, ctx.rip, in.length);
            return loadMem(ea, out, static_cast<size_t>(bytes));
        }
        if (op.kind == OperandKind::REG) {
            std::memcpy(out, &ctx.gpr[op.reg & 15], static_cast<size_t>(std::min(bytes, 8)));
            return true;
        }
        if (op.kind == OperandKind::K) {
            const uint64_t v = op.reg >= 0 && op.reg < 8 ? ctx.kmask[op.reg] : 0;
            std::memcpy(out, &v, 8);
            return true;
        }
        if (op.kind == OperandKind::IMM) {
            const uint64_t v = static_cast<uint64_t>(op.imm);
            std::memcpy(out, &v, 8);
            return true;
        }
        return true;
    };

    const bool storeForm = in.dst.kind == OperandKind::MEM;
    const int srcBytes = std::max(0, std::min(width, in.src.size ? in.src.size / 8 : width));
    const int dstBytes = in.dst.size ? in.dst.size / 8 : width;

    // vvvv is the merge/source-1 operand for three-operand shapes.
    if (in.src.kind != OperandKind::NONE) loadOp(in.src, a, 64);
    if (in.src2.kind != OperandKind::NONE) loadOp(in.src2, b, 64);
    if (in.dst.kind == OperandKind::REG && in.dst.reg >= 16) {
        std::memcpy(d, regPtr(in.dst.reg), 64);
    } else if (in.dst.kind == OperandKind::REG && in.dst.reg >= 0) {
        loadOp(in.dst, d, 8);
    }

    // Result starts as the merge value: src1 for 3-operand forms, the old
    // destination for two-operand forms.
    uint8_t res[64];
    if (in.src.kind != OperandKind::NONE && !storeForm)
        std::memcpy(res, a, 64);
    else
        std::memcpy(res, d, 64);

    uint64_t kres = 0;         // mask-register result
    bool maskResult = false;   // dst is a k register
    bool writesDst = true;
    bool skipMask = false;     // gather/scatter already applied the mask
    int64_t flagZ = -1, flagC = -1, flagP = -1;

    const uint32_t imm = in.src3.kind == OperandKind::IMM
                             ? static_cast<uint32_t>(in.src3.imm) : 0;

    // ---- element accessors ---------------------------------------------
    auto ai = [&](int i) { return ldv(a + i * elemB, elemB); };
    auto bi = [&](int i) { return ldv(b + i * elemB, elemB); };
    auto di = [&](int i) { return ldv(d + i * elemB, elemB); };
    auto wi = [&](int i, uint64_t v) { stv(res + i * elemB, v, elemB); };

    switch (static_cast<VecOp>(in.vec_op)) {
        // ================================================================
        // Moves
        // ================================================================
        case VecOp::MOV: {
            if (storeForm) {
                const int n = std::min<int>(in.dst.size ? in.dst.size / 8 : width, 64);
                writesDst = false;
                const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
                if (!storeMem(ea, a, static_cast<size_t>(n))) return sseFault(ns);
            } else if (in.elem_bits == 0) {
                int n = width;
                if (in.src2.kind != OperandKind::NONE) n = srcBytes ? srcBytes : width;
                std::memcpy(res, b, static_cast<size_t>(std::min(n, 64)));
            } else if (in.src2.kind == OperandKind::REG && in.src2.reg < 16) {
                // vmovd/vmovq from a GPR.
                std::memcpy(res, b, static_cast<size_t>(std::min(elemB, 8)));
            } else {
                std::memcpy(res, b, static_cast<size_t>(std::min(srcBytes, 64)));
            }
            break;
        }
        case VecOp::MOV_SCALAR: {
            const int n = elemB;
            if (storeForm) {
                writesDst = false;
                const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
                if (!storeMem(ea, a, static_cast<size_t>(n))) return sseFault(ns);
                break;
            }
            // vmovss/vmovsd merge the low element into src1; vmovlps/movhps
            // merge a 64-bit half.
            if (has("movhlps")) {
                std::memcpy(res + 0, b + 8, 8);
                break;
            }
            if (has("movlhps")) {
                std::memcpy(res + 8, b + 0, 8);
                break;
            }
            if (has("movlps")) {
                std::memcpy(res + 0, b, 8);
                break;
            }
            if (has("movhps")) {
                std::memcpy(res + 8, b, 8);
                break;
            }
            std::memcpy(res, b, static_cast<size_t>(n));
            break;
        }
        case VecOp::MOV_DUP: {
            if (has("ddup")) {
                for (int i = 0; i < width / 8; ++i) std::memcpy(res + i * 8, b, 8);
            } else {
                const bool odd = has("shdup");
                const int el = elemB ? elemB : 4;
                for (int i = 0; i < width / el; ++i)
                    std::memcpy(res + i * el, b + ((i & 1) || !odd ? (i & ~1) : (i | 1)) * el, el);
            }
            break;
        }
        case VecOp::MOVNT: {
            if (storeForm) {
                writesDst = false;
                const int n = std::min(width, 64);
                const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
                if (!storeMem(ea, a, static_cast<size_t>(n))) return sseFault(ns);
            } else {
                std::memcpy(res, b, static_cast<size_t>(std::min(width, 64)));
            }
            break;
        }
        case VecOp::MOVMSK: {
            uint64_t m = 0;
            if (in.elem_bits == 8) {
                for (int i = 0; i < width; ++i) m |= static_cast<uint64_t>((b[i] >> 7) & 1) << i;
            } else {
                const int el = elemB ? elemB : 4;
                for (int i = 0; i < width / el; ++i)
                    m |= static_cast<uint64_t>((b[i * el + el - 1] >> 7) & 1) << i;
            }
            writesDst = false;
            maskResult = false;
            if (in.dst.kind == OperandKind::REG) ctx.gpr[in.dst.reg & 15] = m;
            ctx.rip = r.next_pc;
            return r;
        }
        case VecOp::ZERO: {
            const int n = has("all") ? 32 : 16;
            for (int i = 0; i < n; ++i) std::memset(ctx.ymm[i] + 16, 0, 48);
            ctx.rip = r.next_pc;
            return r;
        }

        // ================================================================
        // Arithmetic
        // ================================================================
        case VecOp::ADD: case VecOp::SUB: case VecOp::MUL: case VecOp::DIV:
        case VecOp::MIN: case VecOp::MAX: case VecOp::SQRT: case VecOp::RCP:
        case VecOp::RSQRT: case VecOp::ABS: case VecOp::NEG: {
            const bool unary = in.op == X86Op::VEC && in.src2.kind == OperandKind::NONE;
            const int n = (in.src.kind != OperandKind::NONE && !storeForm) ? lanes : lanes;
            for (int i = 0; i < n; ++i) {
                uint64_t rv = 0;
                if (isF32) {
                    float x, y;
                    std::memcpy(&x, a + i * 4, 4);
                    std::memcpy(&y, b + i * 4, 4);
                    float o = 0;
                    switch (static_cast<VecOp>(in.vec_op)) {
                        case VecOp::ADD: o = x + y; break;
                        case VecOp::SUB: o = x - y; break;
                        case VecOp::MUL: o = x * y; break;
                        case VecOp::DIV: o = x / y; break;
                        case VecOp::MIN: o = fminx(x, y); break;
                        case VecOp::MAX: o = fmaxx(x, y); break;
                        case VecOp::SQRT: o = std::sqrt(x); break;
                        case VecOp::RCP: o = 1.0f / x; break;
                        case VecOp::RSQRT: o = 1.0f / std::sqrt(x); break;
                        case VecOp::ABS: o = std::fabs(x); break;
                        case VecOp::NEG: o = -x; break;
                        default: break;
                    }
                    std::memcpy(&rv, &o, 4);
                } else if (isF64) {
                    double x, y;
                    std::memcpy(&x, a + i * 8, 8);
                    std::memcpy(&y, b + i * 8, 8);
                    double o = 0;
                    switch (static_cast<VecOp>(in.vec_op)) {
                        case VecOp::ADD: o = x + y; break;
                        case VecOp::SUB: o = x - y; break;
                        case VecOp::MUL: o = x * y; break;
                        case VecOp::DIV: o = x / y; break;
                        case VecOp::MIN: o = fminx(x, y); break;
                        case VecOp::MAX: o = fmaxx(x, y); break;
                        case VecOp::SQRT: o = std::sqrt(x); break;
                        case VecOp::RCP: o = 1.0 / x; break;
                        case VecOp::RSQRT: o = 1.0 / std::sqrt(x); break;
                        case VecOp::ABS: o = std::fabs(x); break;
                        case VecOp::NEG: o = -x; break;
                        default: break;
                    }
                    std::memcpy(&rv, &o, 8);
                } else {
                    const uint64_t x = ai(i), y = bi(i);
                    const int bits = elemB * 8;
                    switch (static_cast<VecOp>(in.vec_op)) {
                        case VecOp::ADD: rv = x + y; break;
                        case VecOp::SUB: rv = x - y; break;
                        case VecOp::MUL: rv = x * y; break;
                        case VecOp::MIN:
                            rv = isU ? std::min(x, y) : static_cast<uint64_t>(std::min(sx(x, bits), sx(y, bits)));
                            break;
                        case VecOp::MAX:
                            rv = isU ? std::max(x, y) : static_cast<uint64_t>(std::max(sx(x, bits), sx(y, bits)));
                            break;
                        case VecOp::ABS:
                            rv = static_cast<uint64_t>(sx(x, bits) < 0 ? -sx(x, bits) : sx(x, bits));
                            break;
                        case VecOp::NEG: rv = static_cast<uint64_t>(0) - x; break;
                        case VecOp::SQRT: rv = static_cast<uint64_t>(std::sqrt(static_cast<double>(x))); break;
                        case VecOp::RCP: rv = x ? ~0ULL / x : ~0ULL; break;
                        default: rv = x; break;
                    }
                }
                wi(i, rv);
            }
            (void)unary;
            break;
        }
        case VecOp::SATADD: case VecOp::SATSUB: {
            const int bits = elemB * 8;
            for (int i = 0; i < lanes; ++i) {
                const int64_t x = sx(ai(i), bits), y = sx(bi(i), bits);
                uint64_t v;
                if (isU) {
                    const int64_t ux = static_cast<int64_t>(ai(i)), uy = static_cast<int64_t>(bi(i));
                    v = in.vec_op == static_cast<uint16_t>(VecOp::SATADD) ? satU(ux + uy, bits)
                                                                          : satU(ux - uy, bits);
                } else {
                    v = in.vec_op == static_cast<uint16_t>(VecOp::SATADD) ? satS(x + y, bits)
                                                                          : satS(x - y, bits);
                }
                wi(i, v);
            }
            break;
        }
        case VecOp::AVG: {
            for (int i = 0; i < lanes; ++i) wi(i, (ai(i) + bi(i) + 1) >> 1);
            break;
        }
        case VecOp::MULH: {
            const int bits = elemB * 8;
            const bool rounding = has("hrs");
            for (int i = 0; i < lanes; ++i) {
                uint64_t v;
                if (rounding) {
                    const int32_t p = static_cast<int32_t>(sx(ai(i), 16)) *
                                      static_cast<int32_t>(sx(bi(i), 16));
                    v = static_cast<uint16_t>((p + (1 << 13)) >> 14);
                } else if (isU) {
                    v = (ai(i) * bi(i)) >> bits;
                } else {
                    v = static_cast<uint64_t>((static_cast<__int128>(sx(ai(i), bits)) *
                                               sx(bi(i), bits)) >> bits);
                }
                wi(i, v);
            }
            break;
        }
        case VecOp::MULLO: case VecOp::MUL_Q: {
            const bool evenPairs = has("pmuludq") || has("pmuldq");
            if (evenPairs) {
                if (has("pmuludq")) {
                    for (int i = 0; i < width / 8; ++i) {
                        const int src = i * 8;  // even dword of each qword
                        wi(i, static_cast<uint64_t>(ldv(a + src, 4)) * ldv(b + src, 4));
                    }
                } else {
                    for (int i = 0; i < width / 8; ++i) {
                        const int src = i * 8;
                        wi(i, static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(ldv(a + src, 4))) *
                                                    static_cast<int64_t>(static_cast<int32_t>(ldv(b + src, 4)))));
                    }
                }
                break;
            }
            const int bits = elemB * 8;
            for (int i = 0; i < lanes; ++i) {
                if (bits == 64) wi(i, ai(i) * bi(i));
                else wi(i, (ai(i) * bi(i)) & ((1ULL << bits) - 1));
            }
            break;
        }
        case VecOp::MADDWD: {
            for (int i = 0; i < width / 4; ++i) {
                const int s = i * 4;
                const int64_t p0 = static_cast<int64_t>(sx(ldv(a + s, 2), 16)) * sx(ldv(b + s, 2), 16);
                const int64_t p1 = static_cast<int64_t>(sx(ldv(a + s + 2, 2), 16)) * sx(ldv(b + s + 2, 2), 16);
                wi(i, static_cast<uint32_t>(p0 + p1));
            }
            break;
        }
        case VecOp::MADDUBSW: {
            for (int i = 0; i < width / 2; ++i) {
                const int s = i * 2;
                const int64_t p0 = static_cast<int64_t>(a[s]) * sx(b[s], 8);
                const int64_t p1 = static_cast<int64_t>(a[s + 1]) * sx(b[s + 1], 8);
                wi(i, satS(p0 + p1, 16));
            }
            break;
        }
        case VecOp::MADD52: {
            const bool high = has("huq");
            for (int i = 0; i < width / 8; ++i) {
                const uint64_t x = ai(i) & 0xFFFFFFFFFFFFFULL;
                const uint64_t y = bi(i) & 0xFFFFFFFFFFFFFULL;
                const unsigned __int128 p = static_cast<unsigned __int128>(x) * y;
                const uint64_t add = high ? static_cast<uint64_t>(p >> 52)
                                          : static_cast<uint64_t>(p & 0xFFFFFFFFFFFFFULL);
                wi(i, di(i) + add);
            }
            break;
        }

        // ================================================================
        // Logic
        // ================================================================
        case VecOp::AND: case VecOp::ANDN: case VecOp::OR: case VecOp::XOR:
        case VecOp::NOT: {
            for (int i = 0; i < width; ++i) {
                uint8_t v;
                switch (static_cast<VecOp>(in.vec_op)) {
                    case VecOp::AND: v = a[i] & b[i]; break;
                    case VecOp::ANDN: v = static_cast<uint8_t>(~a[i]) & b[i]; break;
                    case VecOp::OR: v = a[i] | b[i]; break;
                    case VecOp::XOR: v = a[i] ^ b[i]; break;
                    default: v = static_cast<uint8_t>(~b[i]); break;
                }
                res[i] = v;
            }
            break;
        }
        case VecOp::TERNLOG: {
            const uint8_t tbl = static_cast<uint8_t>(imm);
            for (int i = 0; i < width; ++i) {
                uint8_t out = 0;
                for (int bit = 0; bit < 8; ++bit) {
                    const int idx = (((d[i] >> bit) & 1) << 2) |
                                    (((a[i] >> bit) & 1) << 1) |
                                    ((b[i] >> bit) & 1);
                    out |= static_cast<uint8_t>(((tbl >> idx) & 1) << bit);
                }
                res[i] = out;
            }
            break;
        }

        // ================================================================
        // Compares and tests
        // ================================================================
        case VecOp::CMP: {
            const bool toMask = in.dst.kind == OperandKind::K;
            if (starts("vucom") || starts("vcom")) {
                double x = 0, y = 0;
                if (isF32) { float fx, fy; std::memcpy(&fx, a, 4); std::memcpy(&fy, b, 4); x = fx; y = fy; }
                else { std::memcpy(&x, a, 8); std::memcpy(&y, b, 8); }
                uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
                rf &= ~0x45ULL;  // CF PF ZF
                if (std::isnan(x) || std::isnan(y)) rf |= 0x45;
                else if (x < y) rf |= 0x01;
                else if (x == y) rf |= 0x40;
                flags_.setRaw(rf);
                syncFlags(ctx);
                ctx.rip = r.next_pc;
                return r;
            }
            const int bits = elemB * 8;
            for (int i = 0; i < lanes; ++i) {
                bool ok = false;
                if (isFloat) {
                    double x, y;
                    if (isF32) { float fx, fy; std::memcpy(&fx, a + i * 4, 4); std::memcpy(&fy, b + i * 4, 4); x = fx; y = fy; }
                    else { std::memcpy(&x, a + i * 8, 8); std::memcpy(&y, b + i * 8, 8); }
                    ok = cmpFloat(x, y, static_cast<int>(imm));
                } else if (in.src3.kind == OperandKind::IMM) {
                    const uint64_t x = ai(i), y = bi(i);
                    const bool lt = isU ? x < y : sx(x, bits) < sx(y, bits);
                    const bool eq = x == y;
                    switch (imm & 7) {
                        case 0: ok = eq; break;
                        case 1: ok = lt; break;
                        case 2: ok = lt || eq; break;
                        case 4: ok = !eq; break;
                        case 5: ok = !lt; break;
                        case 6: ok = !(lt || eq); break;
                        default: ok = false; break;
                    }
                } else if (has("eq")) {
                    ok = ai(i) == bi(i);
                } else if (has("gt")) {
                    ok = isU ? ai(i) > bi(i) : sx(ai(i), bits) > sx(bi(i), bits);
                } else {
                    ok = ai(i) == bi(i);
                }
                if (toMask) {
                    if (ok) kres |= 1ULL << i;
                } else {
                    wi(i, ok ? (bits == 64 ? ~0ULL : ((1ULL << bits) - 1)) : 0);
                }
            }
            if (toMask) { maskResult = true; writesDst = false; }
            break;
        }
        case VecOp::TEST: {
            uint64_t z = 0, c = 0;
            for (int i = 0; i < width; ++i) {
                z |= static_cast<uint64_t>(d[i] & b[i]);
                c |= static_cast<uint64_t>(static_cast<uint8_t>(~d[i]) & b[i]);
            }
            flagZ = z == 0;
            flagC = c == 0;
            writesDst = false;
            break;
        }
        case VecOp::FPCLASS: {
            // imm8 bit order: QNaN, +0, -0, +inf, -inf, denormal, negative
            // finite, SNaN.
            for (int i = 0; i < lanes; ++i) {
                double x;
                if (isF32) { float f; std::memcpy(&f, b + i * 4, 4); x = f; }
                else std::memcpy(&x, b + i * 8, 8);
                const bool sign = std::signbit(x);
                int bitIndex = -1;
                if (std::isnan(x)) {
                    const bool quiet = std::fpclassify(x) == FP_NAN;  // NaN payload quiet bit
                    bitIndex = quiet ? 0 : 7;
                } else if (x == 0.0) {
                    bitIndex = sign ? 2 : 1;
                } else if (std::isinf(x)) {
                    bitIndex = sign ? 4 : 3;
                } else if (std::fpclassify(x) == FP_SUBNORMAL) {
                    bitIndex = 5;
                } else if (sign) {
                    bitIndex = 6;
                }
                if (bitIndex >= 0 && (imm & (1u << bitIndex))) kres |= 1ULL << i;
            }
            maskResult = true;
            writesDst = false;
            break;
        }

        // ================================================================
        // Shifts
        // ================================================================
        case VecOp::SHIFT: {
            const int bits = elemB * 8;
            int64_t count = 0;
            if (in.src3.kind == OperandKind::IMM) count = in.src3.imm;
            else count = static_cast<int64_t>(ldv(b, std::min(8, elemB)));
            if (count < 0) count = 0;
            // vpsllw/vpslld/vpsllq vs vpsrl/vpsra, selected by the mnemonic.
            const bool left = has("sll");
            const bool arith = has("sra");
            for (int i = 0; i < lanes; ++i) {
                const uint64_t x = ai(i);
                uint64_t v;
                if (count >= bits) v = (arith && sx(x, bits) < 0) ? ~0ULL : 0;
                else if (left) v = x << count;
                else if (arith) v = static_cast<uint64_t>(sx(x, bits) >> count);
                else v = x >> count;
                wi(i, v);
            }
            break;
        }
        case VecOp::SHIFTV: {
            const int bits = elemB * 8;
            const bool left = has("sll");
            const bool arith = has("sra");
            for (int i = 0; i < lanes; ++i) {
                const int64_t count = static_cast<int64_t>(bi(i));
                const uint64_t x = ai(i);
                uint64_t v;
                if (count < 0 || count >= bits) v = (arith && sx(x, bits) < 0) ? ~0ULL : 0;
                else if (left) v = x << count;
                else if (arith) v = static_cast<uint64_t>(sx(x, bits) >> count);
                else v = x >> count;
                wi(i, v);
            }
            break;
        }
        case VecOp::SHIFTDQ: {
            const int count = static_cast<int>(imm) & (width - 1);
            const bool left = has("sll");
            if (left) {
                for (int i = width - 1; i >= 0; --i)
                    res[i] = (i - count >= 0) ? a[i - count] : 0;
            } else {
                for (int i = 0; i < width; ++i)
                    res[i] = (i + count < width) ? a[i + count] : 0;
            }
            break;
        }
        // ================================================================
        // Shuffles, permutes, blends
        // ================================================================
        case VecOp::SHUFFLE: {
            if (has("phminpos")) {
                uint16_t best = 0xFFFF;
                int idx = 0;
                for (int i = 0; i < 8; ++i) {
                    const uint16_t v = static_cast<uint16_t>(ldv(b + i * 2, 2));
                    if (v < best) { best = v; idx = i; }
                }
                std::memset(res, 0, 64);
                stv(res, best, 2);
                stv(res + 2, static_cast<uint64_t>(idx), 2);
                break;
            }
            if (has("shufps")) {
                for (int l = 0; l < width / 16; ++l) {
                    const int o = l * 16;
                    for (int k = 0; k < 2; ++k)
                        std::memcpy(res + o + k * 4, a + o + ((imm >> (2 * k)) & 3) * 4, 4);
                    for (int k = 0; k < 2; ++k)
                        std::memcpy(res + o + 8 + k * 4, b + o + ((imm >> (4 + 2 * k)) & 3) * 4, 4);
                }
            } else if (has("shufpd")) {
                for (int l = 0; l < width / 16; ++l) {
                    const int o = l * 16;
                    std::memcpy(res + o, a + o + ((imm >> 0) & 1) * 8, 8);
                    std::memcpy(res + o + 8, b + o + ((imm >> 1) & 1) * 8, 8);
                }
            } else if (has("pshufhw") || has("pshuflw")) {
                const bool high = has("pshufhw");
                for (int l = 0; l < width / 16; ++l) {
                    const int o = l * 16;
                    std::memcpy(res + o, b + o, 16);
                    const int base = high ? 8 : 0;
                    for (int k = 0; k < 4; ++k)
                        std::memcpy(res + o + base + k * 2,
                                    b + o + base + ((imm >> (2 * k)) & 3) * 2, 2);
                }
            } else if (has("permilpd")) {
                for (int l = 0; l < width / 16; ++l) {
                    const int o = l * 16;
                    std::memcpy(res + o, b + o + ((imm >> 0) & 1) * 8, 8);
                    std::memcpy(res + o + 8, b + o + ((imm >> 1) & 1) * 8, 8);
                }
            } else {  // vpshufd / vpermilps imm
                for (int l = 0; l < width / 16; ++l) {
                    const int o = l * 16;
                    for (int k = 0; k < 4; ++k)
                        std::memcpy(res + o + k * 4, b + o + ((imm >> (2 * k)) & 3) * 4, 4);
                }
            }
            break;
        }
        case VecOp::SHUFFLEB: {
            for (int l = 0; l < width / 16; ++l) {
                const int o = l * 16;
                for (int j = 0; j < 16; ++j) {
                    const uint8_t ctl = b[o + j];
                    res[o + j] = (ctl & 0x80) ? 0 : b[o + (ctl & 0x0F)];
                }
                // The table is src1 (vvvv), not the destination.
                for (int j = 0; j < 16; ++j) {
                    const uint8_t ctl = b[o + j];
                    res[o + j] = (ctl & 0x80) ? 0 : a[o + (ctl & 0x0F)];
                }
            }
            break;
        }
        case VecOp::PERMUTE: {
            const int bits = elemB * 8;
            const int perLane = has("permil") ? 16 / elemB : 0;
            const uint64_t imask = (uint64_t)(lanes - 1);
            for (int i = 0; i < lanes; ++i) {
                uint64_t idx = bi(i) & (bits == 64 ? 63 : 31);
                if (perLane) {
                    const int lane = i / perLane;
                    idx = (idx & (perLane - 1)) + lane * perLane;
                } else {
                    idx &= imask;
                }
                wi(i, ai(static_cast<int>(idx)));
            }
            break;
        }
        case VecOp::PERMUTEI: {
            const int el = elemB ? elemB : 8;
            if (has("perm2f128") || has("perm2i128")) {
                const int lo = (imm & 1) * 16;
                const int hi = ((imm >> 4) & 1) * 16;
                std::memcpy(res, (imm & 8) ? std::memset(res, 0, 16) : a + lo, 16);
                if (!(imm & 8)) std::memcpy(res, a + lo, 16);
                if (!(imm & 0x80)) std::memcpy(res + 16, b + hi, 16);
                break;
            }
            if (has("shuff32x4") || has("shufi32x4") || has("shuff64x2") || has("shufi64x2")) {
                const int blocks = width / 16;
                for (int i = 0; i < blocks; ++i) {
                    const int field = (imm >> (2 * (i & 3))) & 3;
                    const uint8_t* src = (field & 2) ? b : a;
                    std::memcpy(res + i * 16, src + (field & 1) * 16, 16);
                }
                break;
            }
            if (has("vpermq") || has("vpermpd")) {
                const int per = 4;   // 2-bit fields cover four qwords
                for (int i = 0; i < width / el; ++i) {
                    const int field = (imm >> (2 * (i % per))) & 3;
                    const int base = (i / per) * per;
                    wi(i, ai(base + field));
                }
                break;
            }
            break;
        }
        case VecOp::PERMUTE2: {
            const bool tableForm = has("permt2");
            const uint64_t imask = (uint64_t)(lanes - 1);
            for (int i = 0; i < lanes; ++i) {
                const uint64_t idx = bi(i) & imask;
                if (tableForm) {
                    // dst is table 1, src2 table 2, vvvv is the index.
                    const uint64_t table = idx < (uint64_t)lanes ? di(i) : 0;
                    const uint64_t v = idx < (uint64_t)lanes ? di(static_cast<int>(idx))
                                                             : b[idx - lanes];
                    (void)table;
                    wi(i, v);
                } else {
                    // vvvv is table 1, src2 table 2, dst holds the index.
                    wi(i, idx < (uint64_t)lanes ? ai(static_cast<int>(idx))
                                                : bi(static_cast<int>(idx - lanes)));
                }
            }
            break;
        }
        case VecOp::BLEND: {
            for (int i = 0; i < lanes; ++i)
                wi(i, ((imm >> (i & 31)) & 1) ? bi(i) : ai(i));
            break;
        }
        case VecOp::BLENDV: {
            if (in.evex || in.mask) {
                std::memcpy(res, b, static_cast<size_t>(std::min(width, 64)));
                break;
            }
            const int mreg = 16 + ((imm >> 4) & 0xF);
            const uint8_t* m = regPtr(mreg);
            for (int i = 0; i < lanes; ++i) {
                const bool take = (m[i * elemB + elemB - 1] & 0x80) != 0;
                wi(i, take ? bi(i) : ai(i));
            }
            break;
        }
        case VecOp::UNPCK: {
            const bool high = has("unpckh") || has("unpckh");
            const int n = 16 / elemB;
            for (int l = 0; l < width / 16; ++l) {
                const int o = l * 16;
                for (int k = 0; k < n / 2; ++k) {
                    const int src = (high ? n / 2 : 0) + k;
                    std::memcpy(res + o + (2 * k) * elemB, a + o + src * elemB, elemB);
                    std::memcpy(res + o + (2 * k + 1) * elemB, b + o + src * elemB, elemB);
                }
            }
            break;
        }
        case VecOp::PACK: {
            const int srcEl = elemB;
            const int dstEl = elemB / 2;
            const int n = 16 / srcEl;
            const bool uns = isU;
            for (int l = 0; l < width / 16; ++l) {
                const int o = l * 16;
                for (int k = 0; k < n; ++k) {
                    const int64_t va = sx(ldv(a + o + k * srcEl, srcEl), srcEl * 8);
                    const int64_t vb = sx(ldv(b + o + k * srcEl, srcEl), srcEl * 8);
                    const uint64_t pa = uns ? satU(va, dstEl * 8) : satS(va, dstEl * 8);
                    const uint64_t pb = uns ? satU(vb, dstEl * 8) : satS(vb, dstEl * 8);
                    stv(res + o + k * dstEl, pa, dstEl);
                    stv(res + o + 8 + k * dstEl, pb, dstEl);
                }
            }
            break;
        }
        case VecOp::ALIGN: {
            if (has("palignr")) {
                const int sh = static_cast<int>(imm) & 31;
                for (int l = 0; l < width / 16; ++l) {
                    uint8_t concat[32];
                    std::memcpy(concat, b + l * 16, 16);
                    std::memcpy(concat + 16, a + l * 16, 16);
                    const int off = sh > 16 ? 16 : sh;
                    for (int j = 0; j < 16; ++j)
                        res[l * 16 + j] = (off + j < 32) ? concat[off + j] : 0;
                }
            } else {
                uint8_t concat[128];
                std::memcpy(concat, b, static_cast<size_t>(width));
                std::memcpy(concat + width, a, static_cast<size_t>(width));
                const int sh = static_cast<int>(imm) * elemB;
                for (int j = 0; j < width; ++j)
                    res[j] = (sh + j < width * 2) ? concat[sh + j] : 0;
            }
            break;
        }
        case VecOp::BROADCAST: {
            if (in.elem_bits == 0 || in.elem_bits == 128) {
                for (int l = 0; l < width / 16; ++l) std::memcpy(res + l * 16, b, 16);
            } else {
                for (int i = 0; i < lanes; ++i)
                    std::memcpy(res + i * elemB, b, static_cast<size_t>(elemB));
            }
            break;
        }
        case VecOp::INSERT: {
            if (has("insertps")) {
                std::memcpy(res, a, 64);
                const int selSrc = (imm >> 6) & 3;
                const int selDst = (imm >> 4) & 3;
                std::memcpy(res + selDst * 4, b + selSrc * 4, 4);
                for (int k = 0; k < 4; ++k)
                    if (imm & (1u << k)) std::memset(res + k * 4, 0, 4);
                break;
            }
            if (in.elem_bits == 0 || in.elem_bits == 128) {
                std::memcpy(res, a, 64);
                const int lane = static_cast<int>(imm) & 1;
                std::memcpy(res + lane * 16, b, 16);
                break;
            }
            std::memcpy(res, a, 64);
            const int idx = static_cast<int>(imm) & (lanes - 1);
            std::memcpy(res + idx * elemB, b, static_cast<size_t>(elemB));
            break;
        }
        case VecOp::EXTRACT: {
            if (in.elem_bits == 0) {  // vextractf128 / vextracti128
                const int lane = static_cast<int>(imm) & 1;
                writesDst = false;
                if (in.dst.kind == OperandKind::MEM) {
                    const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
                    if (!storeMem(ea, a + lane * 16, 16)) return sseFault(ns);
                } else {
                    std::memcpy(res, a + lane * 16, 16);
                    writesDst = true;
                }
                break;
            }
            const int idx = static_cast<int>(imm) & (lanes - 1);
            writesDst = false;
            if (in.dst.kind == OperandKind::MEM) {
                const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
                if (!storeMem(ea, a + idx * elemB, static_cast<size_t>(elemB))) return sseFault(ns);
            } else if (in.dst.kind == OperandKind::REG) {
                uint64_t v = ldv(a + idx * elemB, elemB);
                const int bits = in.dst.size ? in.dst.size : elemB * 8;
                ctx.gpr[in.dst.reg & 15] = v & ((bits >= 64) ? ~0ULL : ((1ULL << bits) - 1));
            }
            break;
        }
        case VecOp::EXPAND: {
            const uint64_t k = in.mask ? ctx.kmask[in.mask & 7] : ~0ULL;
            int j = 0;
            const int srcLanes = (in.src2.size ? in.src2.size / 8 : width) / elemB;
            for (int i = 0; i < lanes; ++i) {
                if ((k >> i) & 1) {
                    const int si = j < srcLanes ? j : srcLanes - 1;
                    wi(i, ldv(b + si * elemB, elemB));
                    ++j;
                } else {
                    std::memset(res + i * elemB, 0, static_cast<size_t>(elemB));
                }
            }
            break;
        }
        case VecOp::COMPRESS: {
            const uint64_t k = in.mask ? ctx.kmask[in.mask & 7] : ~0ULL;
            int j = 0;
            for (int i = 0; i < lanes; ++i)
                if ((k >> i) & 1) stv(res + (j++) * elemB, ai(i), elemB);
            if (storeForm) {
                writesDst = false;
                const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
                if (!storeMem(ea, res, static_cast<size_t>(j * elemB))) return sseFault(ns);
            }
            break;
        }
        case VecOp::CONFLICT: {
            for (int i = 0; i < lanes; ++i) {
                uint64_t bits = 0;
                for (int j = 0; j < i; ++j)
                    if (ai(j) == ai(i)) bits |= 1ULL << j;
                wi(i, bits);
            }
            break;
        }
        case VecOp::MULTISHIFT: {
            for (int q = 0; q < width / 8; ++q) {
                const uint64_t src = bi(q);
                for (int j = 0; j < 8; ++j) {
                    const int ctl = a[q * 8 + j] & 63;
                    res[q * 8 + j] = static_cast<uint8_t>(src >> ctl);
                }
            }
            break;
        }
        // ================================================================
        // Conversions
        // ================================================================
        case VecOp::CVT: {
            const int outLanes = dstBytes / elemB;
            const int bits = elemB * 8;
            if (has("si2ss") || has("si2sd")) {
                const int64_t v = sx(ldv(b, std::min(8, in.elem_bits / 8)), in.elem_bits);
                std::memcpy(res, a, 64);
                if (has("si2ss")) { float f = static_cast<float>(v); std::memcpy(res, &f, 4); }
                else { double f = static_cast<double>(v); std::memcpy(res, &f, 8); }
                break;
            }
            if (has("tss2si") || has("tsd2si") || has("ss2si") || has("sd2si")) {
                const bool dbl = has("sd2si");
                const bool trunc = has("tss2si") || has("tsd2si");
                double x;
                if (dbl) std::memcpy(&x, b, 8);
                else { float f; std::memcpy(&f, b, 4); x = f; }
                if (!trunc) x = roundMode(x, 0);
                writesDst = false;
                const int64_t v = static_cast<int64_t>(x);
                ctx.gpr[in.dst.reg & 15] = in.dst.size == 64
                    ? static_cast<uint64_t>(v) : static_cast<uint64_t>(static_cast<int32_t>(v));
                break;
            }
            if (has("ss2sd")) {
                std::memcpy(res, a, 64);
                float f; std::memcpy(&f, b, 4);
                double o = f; std::memcpy(res, &o, 8);
                break;
            }
            if (has("sd2ss")) {
                std::memcpy(res, a, 64);
                double o; std::memcpy(&o, b, 8);
                float f = static_cast<float>(o); std::memcpy(res, &f, 4);
                break;
            }
            if (has("ps2pd")) {
                for (int i = 0; i < outLanes; ++i) {
                    float f; std::memcpy(&f, b + i * 4, 4);
                    double o = f; std::memcpy(res + i * 8, &o, 8);
                }
                break;
            }
            if (has("pd2ps")) {
                for (int i = 0; i < outLanes; ++i) {
                    double o; std::memcpy(&o, b + i * 8, 8);
                    float f = static_cast<float>(o); std::memcpy(res + i * 4, &f, 4);
                }
                break;
            }
            if (has("dq2ps")) {
                for (int i = 0; i < outLanes; ++i) {
                    const int32_t v = static_cast<int32_t>(ldv(b + i * 4, 4));
                    float f = static_cast<float>(v); std::memcpy(res + i * 4, &f, 4);
                }
                break;
            }
            if (has("dq2pd")) {
                for (int i = 0; i < outLanes; ++i) {
                    const int32_t v = static_cast<int32_t>(ldv(b + i * 4, 4));
                    double o = static_cast<double>(v); std::memcpy(res + i * 8, &o, 8);
                }
                break;
            }
            if (has("tps2dq") || has("ps2dq")) {
                const bool trunc = has("tt");
                for (int i = 0; i < outLanes; ++i) {
                    float f; std::memcpy(&f, b + i * 4, 4);
                    double x = f;
                    if (!trunc) x = roundMode(x, 0);
                    const int32_t v = (x >= 2147483648.0 || x < -2147483648.0 || std::isnan(x))
                                          ? INT32_MIN : static_cast<int32_t>(x);
                    stv(res + i * 4, static_cast<uint32_t>(v), 4);
                }
                break;
            }
            if (has("pd2dq")) {
                // dst is half the width: one dword per double.
                const bool trunc = has("ttpd");
                for (int i = 0; i < outLanes; ++i) {
                    double x; std::memcpy(&x, b + i * 8, 8);
                    if (!trunc) x = roundMode(x, 0);
                    const int32_t v = (x >= 2147483648.0 || x < -2147483648.0 || std::isnan(x))
                                          ? INT32_MIN : static_cast<int32_t>(x);
                    stv(res + i * 4, static_cast<uint32_t>(v), 4);
                }
                break;
            }
            if (has("pmovsx") || has("pmovzx")) {
                const bool sign = has("pmovsx");
                int db = 16;
                if (has("bw")) db = 16;
                else if (has("bd")) db = 32;
                else if (has("bq")) db = 64;
                else if (has("wd")) db = 32;
                else if (has("wq")) db = 64;
                else if (has("dq")) db = 64;
                const int dl = dstBytes / (db / 8);
                for (int i = 0; i < dl; ++i) {
                    uint64_t v = ldv(b + i * (bits / 8), bits / 8);
                    if (sign) v = static_cast<uint64_t>(sx(v, bits));
                    stv(res + i * (db / 8), v, db / 8);
                }
                break;
            }
            break;
        }
        case VecOp::CVT_HALF: {
            auto toHalf = [](float f) -> uint16_t {
                uint32_t x;
                std::memcpy(&x, &f, 4);
                const uint32_t sign = (x >> 16) & 0x8000;
                int32_t exp = static_cast<int32_t>((x >> 23) & 0xFF) - 127 + 15;
                uint32_t mant = x & 0x7FFFFF;
                if (((x >> 23) & 0xFF) == 0xFF) return static_cast<uint16_t>(sign | 0x7C00 | (mant ? 0x200 : 0));
                if (exp >= 31) return static_cast<uint16_t>(sign | 0x7C00);
                if (exp <= 0) {
                    if (exp < -10) return static_cast<uint16_t>(sign);
                    mant |= 0x800000;
                    const int shift = 14 - exp;
                    return static_cast<uint16_t>(sign | (mant >> shift));
                }
                return static_cast<uint16_t>(sign | (static_cast<uint32_t>(exp) << 10) | (mant >> 13));
            };
            auto fromHalf = [](uint16_t h) -> float {
                const uint32_t sign = static_cast<uint32_t>(h & 0x8000) << 16;
                const uint32_t exp = (h >> 10) & 0x1F;
                const uint32_t mant = h & 0x3FF;
                uint32_t x;
                if (exp == 0) {
                    if (mant == 0) x = sign;
                    else {
                        uint32_t e = 127 - 15 + 1;
                        uint32_t m = mant;
                        while (!(m & 0x400)) { m <<= 1; --e; }
                        x = sign | (e << 23) | ((m & 0x3FF) << 13);
                    }
                } else if (exp == 31) {
                    x = sign | 0x7F800000 | (mant << 13);
                } else {
                    x = sign | ((exp - 15 + 127) << 23) | (mant << 13);
                }
                float f; std::memcpy(&f, &x, 4); return f;
            };
            const int mode = static_cast<int>(imm) & 3;
            if (has("ph2ps")) {
                for (int i = 0; i < dstBytes / 4; ++i) {
                    const float f = fromHalf(static_cast<uint16_t>(ldv(b + i * 2, 2)));
                    std::memcpy(res + i * 4, &f, 4);
                }
            } else {
                writesDst = false;
                const int n = dstBytes / 2;
                uint8_t out[64] = {};
                for (int i = 0; i < n; ++i) {
                    float f; std::memcpy(&f, a + i * 4, 4);
                    f = static_cast<float>(roundMode(f, mode));
                    stv(out + i * 2, toHalf(f), 2);
                }
                if (in.dst.kind == OperandKind::MEM) {
                    const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
                    if (!storeMem(ea, out, static_cast<size_t>(n * 2))) return sseFault(ns);
                } else {
                    std::memcpy(res, out, 64);
                    writesDst = true;
                }
            }
            break;
        }

        // ================================================================
        // Packed helpers
        // ================================================================
        case VecOp::PLZCNT: {
            const int bits = elemB * 8;
            for (int i = 0; i < lanes; ++i) {
                uint64_t x = bi(i);
                int n = 0;
                for (int b = bits - 1; b >= 0 && !((x >> b) & 1); --b) ++n;
                wi(i, static_cast<uint64_t>(n));
            }
            break;
        }
        case VecOp::POPCNT: {
            for (int i = 0; i < lanes; ++i) wi(i, static_cast<uint64_t>(__builtin_popcountll(bi(i))));
            break;
        }
        case VecOp::SAD: {
            for (int g = 0; g < width / 8; ++g) {
                uint64_t sum = 0;
                for (int k = 0; k < 8; ++k) {
                    const int d0 = static_cast<int>(a[g * 8 + k]) - static_cast<int>(b[g * 8 + k]);
                    sum += static_cast<uint64_t>(d0 < 0 ? -d0 : d0);
                }
                stv(res + g * 8, sum, 2);  // low word of each qword
            }
            break;
        }
        case VecOp::SIGN: {
            const int bits = elemB * 8;
            for (int i = 0; i < lanes; ++i) {
                const int64_t s = sx(bi(i), bits);
                const uint64_t x = ai(i);
                wi(i, s < 0 ? static_cast<uint64_t>(0) - x : (s == 0 ? 0 : x));
            }
            break;
        }
        case VecOp::MPSADBW: {
            const int aOff = static_cast<int>(imm & 3) * 4;
            const int bOff = static_cast<int>((imm >> 2) & 1) * 4;
            for (int l = 0; l < width / 16; ++l) {
                for (int i = 0; i < 8; ++i) {
                    uint64_t sum = 0;
                    for (int k = 0; k < 4; ++k) {
                        const int d0 = static_cast<int>(a[l * 16 + aOff + k]) -
                                       static_cast<int>(b[l * 16 + bOff + i * 2 + k]);
                        sum += static_cast<uint64_t>(d0 < 0 ? -d0 : d0);
                    }
                    stv(res + l * 16 + i * 2, sum, 2);
                }
            }
            break;
        }
        case VecOp::DP: {
            const int n = 16 / elemB;
            const uint32_t maskBits = elemB == 4 ? ((imm >> 4) & 0xF) : ((imm >> 4) & 0x3);
            const uint32_t storeBits = elemB == 4 ? (imm & 0xF) : (imm & 0x3);
            for (int l = 0; l < width / 16; ++l) {
                double sum = 0;
                for (int k = 0; k < n; ++k) {
                    if (!(maskBits & (1u << k))) continue;
                    if (elemB == 4) {
                        float x, y;
                        std::memcpy(&x, a + l * 16 + k * 4, 4);
                        std::memcpy(&y, b + l * 16 + k * 4, 4);
                        sum += static_cast<double>(x) * y;
                    } else {
                        double x, y;
                        std::memcpy(&x, a + l * 16 + k * 8, 8);
                        std::memcpy(&y, b + l * 16 + k * 8, 8);
                        sum += x * y;
                    }
                }
                for (int k = 0; k < n; ++k) {
                    stv(res + l * 16 + k * elemB, 0, elemB);
                    if (!(storeBits & (1u << k))) continue;
                    if (elemB == 4) {
                        const float f = static_cast<float>(sum);
                        std::memcpy(res + l * 16 + k * 4, &f, 4);
                    } else {
                        std::memcpy(res + l * 16 + k * 8, &sum, 8);
                    }
                }
            }
            break;
        }
        case VecOp::HADD: case VecOp::HSUB: {
            const bool add = in.vec_op == static_cast<uint16_t>(VecOp::HADD);
            const int n = 16 / elemB;
            const int bits = elemB * 8;
            for (int l = 0; l < width / 16; ++l) {
                // Result lane l comes from src1 for even l and src2 for odd l.
                const uint8_t* s1 = (l & 1) ? b : a;
                const int off = (l / 2) * 16;
                for (int i = 0; i < n / 2; ++i) {
                    uint64_t o = 0;
                    if (isFloat && elemB == 4) {
                        float x, y;
                        std::memcpy(&x, s1 + off + i * 8, 4);
                        std::memcpy(&y, s1 + off + i * 8 + 4, 4);
                        const float f = add ? x + y : x - y;
                        std::memcpy(res + l * 16 + i * 4, &f, 4);
                        continue;
                    }
                    if (isFloat) {
                        double x, y;
                        std::memcpy(&x, s1 + off + i * 16, 8);
                        std::memcpy(&y, s1 + off + i * 16 + 8, 8);
                        const double f = add ? x + y : x - y;
                        std::memcpy(res + l * 16 + i * 8, &f, 8);
                        continue;
                    }
                    const int64_t x = sx(ldv(s1 + off + i * 2 * elemB, elemB), bits);
                    const int64_t y = sx(ldv(s1 + off + (i * 2 + 1) * elemB, elemB), bits);
                    o = add ? static_cast<uint64_t>(x + y) : static_cast<uint64_t>(x - y);
                    if (has("haddsw") || has("hsubsw")) o = satS(static_cast<int64_t>(o), bits);
                    stv(res + l * 16 + i * elemB, o, elemB);
                }
            }
            break;
        }
        case VecOp::ADDSUB: {
            if (isF32) {
                for (int i = 0; i < lanes; ++i) {
                    float x, y;
                    std::memcpy(&x, a + i * 4, 4); std::memcpy(&y, b + i * 4, 4);
                    const float o = (i & 1) ? x - y : x + y;
                    std::memcpy(res + i * 4, &o, 4);
                }
            } else {
                for (int i = 0; i < lanes; ++i) {
                    double x, y;
                    std::memcpy(&x, a + i * 8, 8); std::memcpy(&y, b + i * 8, 8);
                    const double o = (i & 1) ? x - y : x + y;
                    std::memcpy(res + i * 8, &o, 8);
                }
            }
            break;
        }
        // ================================================================
        // Fused multiply-add
        // ================================================================
        case VecOp::FMA: case VecOp::FMADDSUB: case VecOp::FMSUBADD: {
            const bool neg = has("vfnm");
            const bool sub = has("vfmsub") && !has("addsub");
            const bool addsub = has("fmaddsub");
            const bool subadd = has("fmsubadd");
            int mode = 0;
            if (has("213")) mode = 1;
            else if (has("231")) mode = 2;
            for (int i = 0; i < lanes; ++i) {
                double x, y, z;
                if (elemB == 4) {
                    float fx, fy, fz;
                    std::memcpy(&fx, a + i * 4, 4);
                    std::memcpy(&fy, b + i * 4, 4);
                    std::memcpy(&fz, d + i * 4, 4);
                    x = fx; y = fy; z = fz;
                } else {
                    std::memcpy(&x, a + i * 8, 8);
                    std::memcpy(&y, b + i * 8, 8);
                    std::memcpy(&z, d + i * 8, 8);
                }
                double prod = (mode == 0) ? z * y : (mode == 1 ? x * z : x * y);
                if (neg) prod = -prod;
                double o;
                if (addsub) o = (i & 1) ? prod - x : prod + x;
                else if (subadd) o = (i & 1) ? prod + x : prod - x;
                else {
                    const double addend = (mode == 0) ? x : (mode == 1 ? y : z);
                    o = sub ? prod - addend : prod + addend;
                }
                if (elemB == 4) { const float f = static_cast<float>(o); std::memcpy(res + i * 4, &f, 4); }
                else std::memcpy(res + i * 8, &o, 8);
            }
            break;
        }

        // ================================================================
        // Crypto
        // ================================================================
        case VecOp::AES: {
            for (int blk = 0; blk < width / 16; ++blk) {
                uint8_t s[16];
                if (has("aesimc")) {
                    std::memcpy(s, b + blk * 16, 16);
                    aes::invMixColumns(s);
                } else {
                    std::memcpy(s, a + blk * 16, 16);
                    if (has("enclast")) aes::roundEncLast(s, b + blk * 16);
                    else if (has("aesenc")) aes::roundEnc(s, b + blk * 16);
                    else if (has("declast")) aes::roundDecLast(s, b + blk * 16);
                    else if (has("aesdec")) aes::roundDec(s, b + blk * 16);
                }
                std::memcpy(res + blk * 16, s, 16);
            }
            break;
        }
        case VecOp::CLMUL: {
            auto clmul = [](uint64_t x, uint64_t y) {
                unsigned __int128 p = 0;
                for (int i = 0; i < 64; ++i)
                    if ((y >> i) & 1) p ^= static_cast<unsigned __int128>(x) << i;
                return p;
            };
            const int s1 = (imm & 1) ? 1 : 0;
            const int s2 = ((imm >> 4) & 1) ? 1 : 0;
            for (int blk = 0; blk < width / 16; ++blk) {
                const uint64_t x0 = ldv(a + blk * 16 + s1 * 8, 8);
                const uint64_t y0 = ldv(b + blk * 16 + s1 * 8, 8);
                const uint64_t x1 = ldv(a + blk * 16 + s2 * 8, 8);
                const uint64_t y1 = ldv(b + blk * 16 + s2 * 8, 8);
                const unsigned __int128 p0 = clmul(x0, y0);
                const unsigned __int128 p1 = clmul(x1, y1);
                stv(res + blk * 16, static_cast<uint64_t>(p0), 8);
                stv(res + blk * 16 + 8, static_cast<uint64_t>(p1), 8);
            }
            break;
        }
        case VecOp::GF2P8: {
            if (has("affine")) {
                for (int q = 0; q < width / 8; ++q) {
                    const uint64_t matrix = ldv(a + q * 8, 8);
                    uint64_t out = 0;
                    for (int j = 0; j < 8; ++j) {
                        uint8_t x = b[q * 8 + j];
                        if (has("inv")) x = gfInv(x);
                        uint8_t r = 0;
                        for (int bit = 0; bit < 8; ++bit) {
                            const uint8_t row = static_cast<uint8_t>(matrix >> (bit * 8));
                            r |= static_cast<uint8_t>(__builtin_parity(static_cast<unsigned>(row & x)) << bit);
                        }
                        r ^= static_cast<uint8_t>(imm);
                        out |= static_cast<uint64_t>(r) << (j * 8);
                    }
                    stv(res + q * 8, out, 8);
                }
            } else {
                for (int i = 0; i < width; ++i) res[i] = aes::gmul(a[i], b[i]);
            }
            break;
        }
        case VecOp::VNNI: {
            for (int i = 0; i < width / 4; ++i) {
                const uint8_t* ap = a + i * 4;
                const uint8_t* bp = b + i * 4;
                int64_t sum;
                if (elemB == 1) {
                    sum = static_cast<int64_t>(ap[0]) * static_cast<int8_t>(bp[0]) +
                          static_cast<int64_t>(ap[1]) * static_cast<int8_t>(bp[1]) +
                          static_cast<int64_t>(ap[2]) * static_cast<int8_t>(bp[2]) +
                          static_cast<int64_t>(ap[3]) * static_cast<int8_t>(bp[3]);
                } else {
                    sum = static_cast<int64_t>(static_cast<int16_t>(ldv(ap, 2))) * static_cast<int16_t>(ldv(bp, 2)) +
                          static_cast<int64_t>(static_cast<int16_t>(ldv(ap + 2, 2))) * static_cast<int16_t>(ldv(bp + 2, 2));
                }
                int64_t acc = static_cast<int32_t>(ldv(d + i * 4, 4)) + sum;
                if (has("dps") || has("dpbusds")) acc = static_cast<int32_t>(satS(acc, 32));
                stv(res + i * 4, static_cast<uint32_t>(static_cast<int32_t>(acc)), 4);
            }
            break;
        }

        // ================================================================
        // AVX-512 special forms
        // ================================================================
        case VecOp::RANGE: {
            for (int i = 0; i < lanes; ++i) {
                double x, y;
                if (elemB == 4) {
                    float fx, fy;
                    std::memcpy(&fx, b + i * 4, 4); std::memcpy(&fy, a + i * 4, 4);
                    x = fx; y = fy;
                } else {
                    std::memcpy(&x, b + i * 8, 8); std::memcpy(&y, a + i * 8, 8);
                }
                bool sel = false;
                switch (imm & 7) {
                    case 0: sel = x < y; break;
                    case 1: sel = x <= y; break;
                    case 2: sel = x == y; break;
                    case 3: sel = x != y; break;
                    case 4: sel = !(x < y); break;
                    case 5: sel = !(x <= y); break;
                    case 6: sel = !(x == y); break;
                    default: sel = !std::isnan(x) && !std::isnan(y); break;
                }
                const double o = (imm & 0x10) ? (sel ? std::min(x, y) : std::max(x, y))
                                              : (sel ? std::max(x, y) : std::min(x, y));
                if (elemB == 4) { float f = static_cast<float>(o); std::memcpy(res + i * 4, &f, 4); }
                else std::memcpy(res + i * 8, &o, 8);
            }
            break;
        }
        case VecOp::REDUCE: case VecOp::RNDSCALE: case VecOp::ROUND: {
            const int m = in.vec_op == static_cast<uint16_t>(VecOp::ROUND)
                              ? 0 : static_cast<int>((imm >> 4) & 0xF);
            const int mode = static_cast<int>(imm & 3);
            const double scale = std::pow(2.0, m);
            for (int i = 0; i < lanes; ++i) {
                double x;
                if (elemB == 4) { float f; std::memcpy(&f, b + i * 4, 4); x = f; }
                else std::memcpy(&x, b + i * 8, 8);
                const double o = roundMode(x * scale, mode) / scale;
                if (elemB == 4) { float f = static_cast<float>(o); std::memcpy(res + i * 4, &f, 4); }
                else std::memcpy(res + i * 8, &o, 8);
            }
            break;
        }
        case VecOp::GETEXP: {
            for (int i = 0; i < lanes; ++i) {
                double x;
                if (elemB == 4) { float f; std::memcpy(&f, b + i * 4, 4); x = f; }
                else std::memcpy(&x, b + i * 8, 8);
                double o = 0;
                if (std::isnan(x)) o = x;
                else if (std::isinf(x)) o = std::signbit(x) ? -0.0 : 0.0;
                else if (x == 0) o = -std::numeric_limits<double>::infinity();
                else o = std::floor(std::log2(std::fabs(x)));
                if (elemB == 4) { float f = static_cast<float>(o); std::memcpy(res + i * 4, &f, 4); }
                else std::memcpy(res + i * 8, &o, 8);
            }
            break;
        }
        case VecOp::GETMANT: {
            const int interval = static_cast<int>(imm & 3);
            const int signCtl = static_cast<int>((imm >> 2) & 3);
            for (int i = 0; i < lanes; ++i) {
                double x;
                if (elemB == 4) { float f; std::memcpy(&f, b + i * 4, 4); x = f; }
                else std::memcpy(&x, b + i * 8, 8);
                double o;
                int e = 0;
                if (x == 0 || std::isnan(x) || std::isinf(x)) o = x;
                else {
                    o = std::frexp(std::fabs(x), &e);
                    if (interval == 0 || interval == 2) o *= 2.0;
                }
                if (signCtl == 2) o = std::fabs(o);
                else if (signCtl == 3) o = -std::fabs(o);
                if (elemB == 4) { float f = static_cast<float>(o); std::memcpy(res + i * 4, &f, 4); }
                else std::memcpy(res + i * 8, &o, 8);
            }
            break;
        }
        case VecOp::FIXUPIMM: {
            // The destination is both source and result. imm8 bit 0 enables
            // the zero fix-up, bit 1 the NaN fix-up; the replacement value is
            // the corresponding lane of the third source.
            std::memcpy(res, d, 64);
            for (int i = 0; i < lanes; ++i) {
                const int o = i * elemB;
                double x, y;
                if (elemB == 4) { float f1, f2; std::memcpy(&f1, d + o, 4); std::memcpy(&f2, b + o, 4); x = f1; y = f2; }
                else { std::memcpy(&x, d + o, 8); std::memcpy(&y, b + o, 8); }
                if ((x == 0 && (imm & 0x01)) || (std::isnan(x) && (imm & 0x02))) {
                    if (elemB == 4) { float f = static_cast<float>(y); std::memcpy(res + o, &f, 4); }
                    else std::memcpy(res + o, &y, 8);
                }
            }
            break;
        }

        // ================================================================
        // Gather / scatter
        // ================================================================
        case VecOp::GATHER: {
            const int64_t base = static_cast<int64_t>(
                effectiveAddress(ctx, in.src2.mem, ctx.rip, in.length));
            const uint8_t* idx = in.vsib_reg ? regPtr(in.vsib_reg) : b;
            uint8_t* vmask = in.src.kind == OperandKind::REG ? regPtr(in.src.reg) : nullptr;
            uint64_t k = in.mask ? ctx.kmask[in.mask & 7]
                                 : (in.src.kind == OperandKind::K ? ctx.kmask[in.src.reg & 7] : 0);
            for (int i = 0; i < lanes; ++i) {
                const bool sel = vmask ? (vmask[i * elemB + elemB - 1] & 0x80) != 0
                                       : ((k >> i) & 1) != 0;
                if (!sel) {
                    std::memcpy(res + i * elemB, d + i * elemB, static_cast<size_t>(elemB));
                    continue;
                }
                const int64_t off = sx(ldv(idx + i * elemB, elemB), elemB * 8);
                const uint64_t ea = static_cast<uint64_t>(base + off * in.vsib_scale);
                uint8_t tmp[8] = {};
                if (!loadMem(ea, tmp, static_cast<size_t>(elemB))) return sseFault(ns);
                std::memcpy(res + i * elemB, tmp, static_cast<size_t>(elemB));
                if (vmask) vmask[i * elemB + elemB - 1] = 0;
                else k &= ~(1ULL << i);
            }
            if (!vmask) {
                if (in.mask) ctx.kmask[in.mask & 7] = k;
                else if (in.src.kind == OperandKind::K) ctx.kmask[in.src.reg & 7] = k;
            }
            skipMask = true;
            break;
        }
        case VecOp::SCATTER: {
            const int64_t base = static_cast<int64_t>(
                effectiveAddress(ctx, in.src2.mem, ctx.rip, in.length));
            const uint8_t* idx = in.vsib_reg ? regPtr(in.vsib_reg) : b;
            const uint64_t k = in.mask ? ctx.kmask[in.mask & 7] : ~0ULL;
            writesDst = false;
            skipMask = true;
            for (int i = 0; i < lanes; ++i) {
                if (!((k >> i) & 1)) continue;
                const int64_t off = sx(ldv(idx + i * elemB, elemB), elemB * 8);
                const uint64_t ea = static_cast<uint64_t>(base + off * in.vsib_scale);
                if (!storeMem(ea, a + i * elemB, static_cast<size_t>(elemB))) return sseFault(ns);
            }
            break;
        }
        case VecOp::MOVMASK: {
            const uint64_t k = in.mask ? ctx.kmask[in.mask & 7] : 0;
            const uint8_t* m = in.src.kind == OperandKind::REG ? regPtr(in.src.reg) : b;
            if (storeForm) {
                writesDst = false;
                const uint64_t base = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
                for (int i = 0; i < lanes; ++i) {
                    const bool sel = in.mask ? ((k >> i) & 1) : (m[i * elemB + elemB - 1] & 0x80);
                    if (sel && !storeMem(base + i * elemB, b + i * elemB, static_cast<size_t>(elemB)))
                        return sseFault(ns);
                }
            } else {
                const uint64_t base = effectiveAddress(ctx, in.src2.mem, ctx.rip, in.length);
                for (int i = 0; i < lanes; ++i) {
                    const bool sel = in.mask ? ((k >> i) & 1) : (m[i * elemB + elemB - 1] & 0x80);
                    if (sel) {
                        if (!loadMem(base + i * elemB, res + i * elemB, static_cast<size_t>(elemB)))
                            return sseFault(ns);
                    } else {
                        std::memcpy(res + i * elemB, d + i * elemB, static_cast<size_t>(elemB));
                    }
                }
            }
            break;
        }
        case VecOp::PHMINPOS: {
            uint16_t best = 0xFFFF;
            int idx = 0;
            for (int i = 0; i < 8; ++i) {
                const uint16_t v = static_cast<uint16_t>(ldv(b + i * 2, 2));
                if (v < best) { best = v; idx = i; }
            }
            std::memset(res, 0, 64);
            stv(res, best, 2);
            stv(res + 2, static_cast<uint64_t>(idx), 2);
            break;
        }
        // @@PART5@@


        default: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D;
            r.exception_msg = "unimplemented vector op: " + nm;
            return r;
        }
    }

    // ---- writemask / zeroing -------------------------------------------
    if (maskResult) {
        if (in.mask) ctx.kmask[in.mask & 7] = kres;
        else ctx.kmask[in.dst.reg & 7] = kres;
        ctx.rip = r.next_pc;
        return r;
    }
    if (in.mask && in.elem_bits && !skipMask) {
        const uint64_t k = ctx.kmask[in.mask & 7];
        for (int i = 0; i < lanes; ++i) {
            if (!((k >> i) & 1)) {
                if (in.zeroing) std::memset(res + i * elemB, 0, static_cast<size_t>(elemB));
                else std::memcpy(res + i * elemB, d + i * elemB, static_cast<size_t>(elemB));
            }
        }
        if (scalarForm && in.zeroing)
            std::memset(res + elemB, 0, static_cast<size_t>(std::max(0, width - elemB)));
    }

    if (writesDst) {
        if (in.dst.kind == OperandKind::REG && in.dst.reg >= 16) {
            uint8_t* p = regPtr(in.dst.reg);
            std::memcpy(p, res, static_cast<size_t>(std::min(dstBytes, 64)));
            // VEX/EVEX forms zero the bits above the operating width.
            if (width < 64) std::memset(p + width, 0, static_cast<size_t>(64 - width));
        } else if (in.dst.kind == OperandKind::REG && in.dst.reg >= 0) {
            uint64_t v = 0;
            std::memcpy(&v, res, 8);
            const int bits = in.dst.size ? in.dst.size : 32;
            if (bits == 64) ctx.gpr[in.dst.reg & 15] = v;
            else ctx.gpr[in.dst.reg & 15] = v & ((1ULL << bits) - 1);
        } else if (in.dst.kind == OperandKind::MEM) {
            const int n = std::min(dstBytes, 64);
            const uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
            if (!storeMem(ea, res, static_cast<size_t>(n))) return sseFault(ns);
        }
    }

    if (flagZ >= 0 || flagC >= 0) {
        uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
        rf &= ~0x41ULL;
        if (flagZ == 1) rf |= 0x40;
        if (flagC == 1) rf |= 0x01;
        flags_.setRaw(rf);
        syncFlags(ctx);
    }
    (void)flagP;
    ctx.rip = r.next_pc;
    return r;
}

} // namespace nexus
