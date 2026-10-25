#pragma once

#include <cstdint>

namespace nexus {

// ---------------------------------------------------------------------------
// Vector IR for VEX/EVEX instructions (AVX, AVX2, AVX-512).
//
// A VEX or EVEX instruction decodes to X86Op::VEC plus one VecOp. The op names
// the semantic family, and three more fields finish the description:
//
//   elem_bits  lane width (8/16/32/64) or 0 for whole-register ops
//   vec_class  INT / UINT / F32 / F64 (signedness and arithmetic domain)
//   vec_bits   128 / 256 / 512 — the operating width (VEX.L or EVEX.L'L)
//
// Operand roles are fixed across the whole family:
//   dst   ModRM.reg   (vector register, mask register, or GPR for extracts)
//   src   VEX/EVEX.vvvv (the non-destructive first source)
//   src2  ModRM.r/m   (register or memory)
//   src3  imm8, when the encoding has one
//
// Masking lives in Insn::mask / Insn::zeroing / Insn::evex_b. The interpreter
// applies it uniformly at lane granularity for every element-wise operation,
// which is what all EVEX data instructions promise (k0 means "no mask").
// ---------------------------------------------------------------------------

enum class VecOp : uint16_t {
    INVALID = 0,

    // ---- moves ---------------------------------------------------------
    MOV,          // vmovaps/ups/dqa/dqu32/64, full width or masked
    MOV_SCALAR,   // vmovss/vmovsd register and load forms
    MOV_DUP,      // vmovddup (cc 0), vmovsldup (1), vmovshdup (2)
    MOVNT,        // non-temporal store (architecturally a plain store)
    MOVMSK,       // vmovmskps/pd, vpmovmskb
    MOVMASK,      // vmaskmovps/pd, vpmaskmovd/q (masked gather/store)
    ZERO,         // vzeroupper / vzeroall

    // ---- arithmetic ----------------------------------------------------
    ADD, SUB, MUL, DIV, MIN, MAX, SQRT, RCP, RSQRT, ABS, NEG,
    SATADD, SATSUB,   // saturating adds/subtracts (signed via class)
    AVG,              // (a + b + 1) >> 1
    MULH,             // high half of a widening multiply (cc: 0 plain,
                      // 1 unsigned, 2 rounding)
    MULLO,            // low half multiply, including the even-lane
                      // pmuludq/pmuldq forms
    MADDWD,           // vpmaddwd
    MADDUBSW,         // vpmaddubsw
    MADD52,           // vpmadd52luq (cc 0) / vpmadd52huq (cc 1)
    MUL_Q,            // vpmullq (64-bit lane multiply, low half)

    // ---- logic ---------------------------------------------------------
    AND, ANDN, OR, XOR, NOT,
    TERNLOG,          // vpternlogd/q, truth table in imm8

    // ---- compares and tests --------------------------------------------
    CMP,              // compare to all-ones lanes (or a k mask)
    TEST,             // vptest / vtestps / vtestpd — writes ZF/CF
    FPCLASS,          // vfpclass* -> k mask

    // ---- shifts --------------------------------------------------------
    SHIFT,            // count from imm8 or from the low qword of src2
    SHIFTV,           // per-lane variable count (vpsllvd family)
    SHIFTDQ,          // whole-register byte shift (vpslldq/vpsrldq)

    // ---- shuffles and permutes -----------------------------------------
    SHUFFLE,          // in-lane shuffle selected by imm8 (cc picks form)
    SHUFFLEB,         // byte shuffle driven by src2 bytes (vpshufb)
    PERMUTE,          // lane permute driven by a vector index
    PERMUTEI,         // lane permute driven by imm8 (vpermq/vpermpd/…)
    PERMUTE2,         // vpermt2*/vpermi2* (cc 0 = table, 1 = index)
    BLEND,            // imm8 blend, granularity in cc
    BLENDV,           // variable blend (mask in src2)
    UNPCK, PACK, ALIGN,

    // ---- lane traffic ---------------------------------------------------
    BROADCAST, INSERT, EXTRACT, EXPAND, COMPRESS,
    CONFLICT, MULTISHIFT,

    // ---- conversions ----------------------------------------------------
    CVT, CVT_HALF, CVT_BF16,

    // ---- packed helpers -------------------------------------------------
    PLZCNT, POPCNT, MPSADBW, DP, HADD, HSUB, ADDSUB, SAD, SIGN,
    PHMINPOS,     // vphminposuw

    // ---- memory ---------------------------------------------------------
    GATHER, SCATTER,

    // ---- fused multiply-add ---------------------------------------------
    FMA,              // imm8[1:0] selects 132 / 213 / 231
    FMADDSUB, FMSUBADD,

    // ---- crypto ---------------------------------------------------------
    AES, CLMUL, GF2P8, SHA, SM3, SM4,

    // ---- AVX-512 special forms ------------------------------------------
    RANGE, REDUCE, GETEXP, GETMANT, RNDSCALE, SCALE, FIXUPIMM,
    ROUND,            // VEX VROUNDPS/PD/SS/SD (imm8[2:0] only)
    VNNI,
};

enum VecClass : uint8_t {
    VC_INT = 0,
    VC_UINT = 1,
    VC_F32 = 2,
    VC_F64 = 3,
};

// Decoded operand shapes. The decoder and the interpreter agree on these.
enum VecShape : uint8_t {
    VS_NONE = 0,
    VS_3R,      // dst = reg, src = vvvv, src2 = r/m
    VS_3RI,     // + imm8 in src3
    VS_2R,      // dst = reg, src2 = r/m
    VS_2RI,     // + imm8
    VS_ST,      // dst = r/m, src = reg (store form)
    VS_STI,     // store + imm8
    VS_EX,      // dst = r/m (may be GPR), src = reg, src3 = imm8
    VS_INS,     // dst = reg, src = vvvv, src2 = r/m, src3 = imm8
    VS_CMPK,    // dst = k, src = vvvv, src2 = r/m, src3 = imm8
    VS_KF,      // dst = k, src2 = r/m, src3 = imm8 (vfpclass*)
    VS_GATHER,  // dst = reg, src = vvvv (mask), src2 = VSIB memory
    VS_SCATTER, // dst = VSIB memory, src = reg
    VS_MOV,     // dst/src2 direction depends on ModRM.mod
    VS_1R,      // dst = reg only (vzero*, vmovmsk handled separately)
    VS_3RG,     // dst = reg, src = vvvv, src2 = GPR/memory (vcvtsi2ss)
    VS_G2V,     // dst = reg, src2 = GPR/memory (vmovd/vmovq load)
    VS_V2G,     // dst = GPR/memory, src = reg (vmovd store, vcvtss2si)
};

// EVEX disp8 compression tuple. Every entry names a group whose N the decoder
// computes from the vector length and element width.
enum VecTuple : uint8_t {
    VT_NONE = 0,
    VT_FV,      // full vector
    VT_HV,      // half vector
    VT_QV,      // quarter vector
    VT_EV,      // eighth vector
    VT_T1S,     // one scalar element
    VT_T1F,     // 16 bytes
    VT_T2,      // 32 bytes
    VT_T4,      // 64 bytes
    VT_T8,      // 128 bytes
    VT_M128,    // 16 bytes (memory-only forms)
    VT_FVM,     // full vector, memory only
    VT_HVM,     // half vector, memory only
    VT_T2S,     // two elements
    VT_T4S,     // four elements
    VT_T8S,     // eight elements
};

constexpr bool vecClassIsFloat(uint8_t c) { return c == VC_F32 || c == VC_F64; }

} // namespace nexus
