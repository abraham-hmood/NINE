#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <optional>

#include "VecOp.h"

namespace nexus {

enum class X86Op : uint16_t {
    INVALID = 0,
    NOP, MOV, MOVZX, MOVSX, LEA, PUSH, POP, LEAVE,
    ADD, SUB, ADC, SBB, AND, OR, XOR, CMP, TEST, INC, DEC, NEG, NOT,
    IMUL, MUL, IDIV, DIV, XCHG, CMPXCHG, XADD, CDQ,
    SHL, SHR, SAR, ROL, ROR,
    JMP, JE, JNE, JL, JLE, JG, JGE, JB, JBE, JA, JAE, JS, JNS, JO, JNO,
    CALL, RET,
    SYSCALL, INT3, UD2,
    CMOV, SETCC,
    MOVD, SSE_MOV, PXOR, PUNPCKLDQ, PUNPCKLQDQ, PUNPCKHQDQ,
    MOVLPS_LOAD, MOVLPS_STORE, MOVHPS_LOAD, MOVHPS_STORE,  // SSE scalar/128-bit moves + zeroing
    MOVAPS, ADDPS, MULPS,  // SSE samples; full SSE/AVX via VEX path
    // SSE/SSE2/SSE3 floating-point adds (0F 58 / 0F D0 by prefix)
    ADDPD, ADDSD, ADDSS, ADDSUBPD, ADDSUBPS,
    // ADX carry-chain additions (0F 38 F6 by prefix)
    ADCX, ADOX,
    // Legacy ASCII/BCD adjust (one-byte 27/2F/37/3F, D4/D5 ib)
    AAA, AAS, AAD, AAM, DAA, DAS,
    // AES-NI round primitives (66 0F 38 DB-DF, 66 0F 3A DF ib)
    AESENC, AESENCLAST, AESDEC, AESDECLAST, AESIMC, AESKEYGENASSIST,
    // Key Locker bulk AES (F3 0F 38 D8-DF; key handle in memory)
    AESENC128KL, AESDEC128KL, AESENC256KL, AESDEC256KL,
    AESENCWIDE128KL, AESDECWIDE128KL, AESENCWIDE256KL, AESDECWIDE256KL,
    // Bitwise SIMD logical ops (0F 54 / 0F 55 by prefix)
    ANDPS, ANDPD, ANDNPS, ANDNPD,
    // SSE4.1 blends (66 0F 38 15/16 implicit XMM0 mask, 66 0F 3A 0C/0D imm8 mask)
    BLENDVPS, BLENDVPD, BLENDPS, BLENDPD,
    // BMI1 (VEX.LZ.0F38 F2/F3/F5/F7)
    ANDN, BLSI, BLSMSK, BLSR, BEXTR, BZHI,
    // Bit scans / byte swap
    BSF, BSR, TZCNT, LZCNT, BSWAP,
    // Bit test family (0F A3/AB/B3/BB and 0F BA /4-/7)
    BT, BTS, BTR, BTC,
    // Legacy/compat-only: ARPL (63) and BOUND (62)
    ARPL, BOUND,
    // Halt (F4): stops the guest cleanly (a CPL-3 HLT would #GP on hardware).
    HLT,
    // Stack frame setup (C8 iw ib).
    ENTER,

    // x87 escape group (D8-DF). One opcode carries the whole family: the
    // semantic operation lives in `x87op`, operand shapes in dst/src and the
    // pop/reverse/integer modifiers in `x87_flags`.
    X87,
    // MMX tag reset (0F 77).
    EMMS,
    // CET indirect-branch landing pads — architectural no-ops at CPL 3
    // (F3 0F 1E FA/FB).
    ENDBR,

    // MPX bound register ops
    BNDCL, BNDCU, BNDCN, BNDMK,
    BNDMOV_LOAD, BNDMOV_STORE, BNDLDX, BNDSTX,
    // Flag control (F8-FD, 0F 01 CA/CB) and cache/prefetch hints
    CLC, STC, CLI, STI, CLD, STD, CLAC, STAC,
    CLDEMOTE, CLFLUSH, CLFLUSHOPT, CLWB,
    // Sign-extension idioms with implicit accumulator
    CBW, CWDE, CDQE,
    // Privileged / OS-only instructions. Decoded exactly, then refused with the
    // fault real hardware raises for a CPL-3 guest (see InsnInterpreter).
    CLTS, CLUI, CLRSSBSY,
    CMC,
    // SSE/SSE2 compare-with-predicate (0F C2 /r ib); imm8[2:0] picks the
    // predicate. CMPSD_SSE is the scalar-double form — the mnemonic collides
    // with the string CMPSD above, hence the suffix.
    CMPPS, CMPPD, CMPSS, CMPSD_SSE,
    // String compare (A6/A7); dst.size carries the element width.
    CMPS,
    // Interlocked compare-and-exchange of a 8/16-byte block (0F C7 /1).
    CMPXCHG8B, CMPXCHG16B,
    // Ordered scalar compares (0F 2F) — only ZF/PF/CF are written.
    COMISS, COMISD,
    CPUID,
    // CRC-32C accumulator (F2 0F 38 F0/F1).
    CRC32,
    // SSE/SSE2 conversions.
    CVTDQ2PD, CVTDQ2PS, CVTPS2DQ, CVTPS2PD, CVTTPD2DQ,
    CVTSD2SS, CVTSS2SD, CVTSD2SI, CVTSS2SI, CVTSI2SD, CVTSI2SS,
    CVTTSD2SI, CVTTSS2SI,
    // SSE/SSE2 divides (0F 5E by mandatory prefix)
    DIVPS, DIVPD, DIVSS, DIVSD,
    // Horizontal add/sub (0F 7C/7D: 66 = PD, F2 = PS)
    HADDPS, HADDPD, HSUBPS, HSUBPD,
    // SSE4.1 dot products (66 0F 3A 40/41 ib) and EXTRACTPS (66 0F 3A 17 ib)
    DPPS, DPPD, EXTRACTPS,
    // GFNI byte-field ops (66 0F 38 CF, 66 0F 3A CE/CF ib)
    GF2P8MULB, GF2P8AFFINEQB, GF2P8AFFINEINVQB,
    // Enqueue-command and Key Locker encode (privileged/hardware-managed)
    ENQCMD, ENQCMDS, ENCODEKEY128, ENCODEKEY256,
    // History reset — #GP at CPL 3
    HRESET,
    // x87/SSE state images (0F AE /0 and /1)
    FXSAVE, FXRSTOR,
    // MMX-state conversions (CVTPI2PD/CVTPI2PS/CVTPS2PI): decoded so the
    // stream stays aligned, refused at execute time because NINE models no
    // MMX/x87 register file.
    MMX_OP,
    VEX_OP, EVEX_OP,
    STOS, LODS, MOVS, SCAS,  // string ops (AA-AF); REP/REPNE via prefix flags

    // --- I/O port space, privileged system instructions, control transfer ---
    IN, INS, INVD, INVLPG, INVPCID, IRET, INCSSP,
    INTN, INT1, INTO,
    // CET shadow-stack bookkeeping (F3 0F AE /5)
    // AMX tile configuration (VEX.128.NP.0F38 49 /0) — decoded, then #UD
    LDTILECFG,
    // Segment access rights, LAHF, and the leftover load/store forms
    LAHF, LAR, LDS, LDDQU, LDMXCSR, INSERTPS,
    // AVX-512 mask-register instructions (k0-k7). dst.size carries the
    // element width: 8/16/32/64.
    KAND, KANDN, KOR, KXOR, KXNOR, KNOT, KADD, KUNPCK,
    KTEST, KORTEST, KSHIFTL, KSHIFTR, KMOV,

    // ---- §2.17: GPR / system / packed-SIMD additions ----
    // Loop family (E0-E3). `cc` picks LOOP / LOOPE / LOOPNE / JRCXZ.
    LOOP,
    // Port output (E6/E7/EE/EF, 6E/6F) — #GP(0) at CPL 3, like IN.
    OUT, OUTS,
    // Far-pointer loads. LES is compat-mode only (C4 is VEX in long mode).
    LES, LFS, LGS, LSS,
    // Descriptor-table / task-register loads — privileged (#GP(0)).
    LGDT, LIDT, LLDT, LTR, LMSW,
    // Segment limit read (0F 03).
    LSL,
    // Monitor/mwait (0F 01 C8/C9) — CPL 0 only, so #GP(0).
    MONITOR, MWAIT,
    // Key Locker wrapping-key load (F3 0F 38 DC) — #UD without CR4.KL.
    LOADIWKEY,
    // MOV to/from CR/DR (0F 20-23) — #GP(0) at CPL 3.
    MOVCR,
    // BMI2 multiply without flags (VEX.F2.0F38 F6).
    MULX,
    // Direct / byte-swapping stores.
    MOVBE, MOVDIRI, MOVDIR64B,
    // SSE/SSE2 floating-point min/max/mul and bitwise OR.
    MAXPS, MAXPD, MAXSS, MAXSD, MINPS, MINPD, MINSS, MINSD,
    MULPD, MULSS, MULSD, ORPS, ORPD,
    // Scalar and lane moves.
    MOVSS, MOVSD_SSE, MOVHLPS, MOVLHPS, MOVDDUP, MOVSHDUP, MOVSLDUP,
    MOVMSKPS, MOVMSKPD,
    // Non-temporal stores / loads (cache hints collapse to plain moves).
    MOVNTPS, MOVNTPD, MOVNTDQ, MOVNTDQA, MOVNTI, MOVNTQ,
    // Masked byte store (66 0F F7).
    MASKMOVDQU,
    // Packed-integer group. dst.size carries the element width.
    PABS, PACKSS, PACKUS, PADD, PADDS, PADDUS, PALIGNR,
    PAND, PANDN, PAVG, PBLENDVB, PBLENDW, PCLMULQDQ, PCMPEQ, MPSADBW,

    // ---- §2.18: packed integer, SSE4.2 string compare, system group ----
    // Signed packed compare (66 0F 64/65/66, 66 0F 38 37). Element width in
    // dst.size, 64 for the qword form.
    PCMPGT,
    // Packed subtract families (0F D8/D9/E8/E9/F8-FB).
    PSUB, PSUBS, PSUBUS,
    // Packed interleave (0F 60-6D). cc: 0 = low half, 1 = high half.
    PUNPCK,
    // Packed shuffle (0F 70 + imm8). cc: 0 = D, 1 = HW, 2 = LW, 3 = W.
    PSHUF,
    // Byte shuffle by per-lane mask (66 0F 38 00).
    PSHUFB,
    // Packed shifts. cc: 0 = left, 1 = logical right, 2 = arithmetic right.
    // The count comes from an imm8 or from the low qword of the source.
    PSHIFT,
    // Whole-register byte shift (66 0F 73 /3 /7). cc: 0 = left, 1 = right.
    PSHIFTDQ,
    // Packed multiply. cc picks the variant:
    //   0 PMULLW 1 PMULHW 2 PMULHUW 3 PMULLD 4 PMULLQ
    //   5 PMULUDQ 6 PMULDQ 7 PMULHRSW 8 PMADDWD 9 PMADDUBSW
    PMUL,
    // Packed min/max. cc bit0 = max, bit1 = unsigned compare.
    PMINMAX,
    // Mask of the MSBs of each byte (66 0F D7) into a GPR.
    PMOVMSKB,
    // Sign/zero extend narrowing lanes (66 0F 38 20-25 / 30-35).
    // cc: 0 = sign extend, 1 = zero extend. dst.size = source element width.
    PMOVX,
    // Packed sign (66 0F 38 08-0A).
    PSIGN,
    // Sum of absolute byte differences (66 0F F6).
    PSADBW,
    // Horizontal add/sub (66 0F 38 01-03 / 05-07):
    //   0 HADDW 1 HADDD 2 HADDSW 3 HSUBW 4 HSUBD 5 HSUBSW
    PHADDSUB,
    // Minimum unsigned word and its index (66 0F 38 41).
    PHMINPOSUW,
    // Packed bit test (66 0F 38 17): writes only ZF/CF.
    PTEST,
    // Extract/insert an element (66 0F 3A 14-16 / 20 / 22). dst.size = width.
    PEXTR, PINS,
    // SSE4.2 string compare. cc: 0 = PCMPISTRI, 1 = PCMPISTRM,
    // 2 = PCMPESTRI, 3 = PCMPESTRM.
    PCMPSTR,

    // ---- §2.18: GPR / system ----
    POPCNT, RCL, RCR, PUSHF, POPF, PUSHA, POPA,
    RDFSBASE, RDGSBASE, WRFSBASE, WRGSBASE, RDMSR, RDPMC, RDPID, RDPKRU, RDRAND,
    PREFETCH, PCONFIG, PTWRITE, PDEP, PEXT, POR,

    // ---- §2.20: the last of the scalar / system core ----
    // Time stamp counter. RDTSCP also returns the TSC_AUX value in ECX.
    RDTSC, RDTSCP,
    // Hardware entropy. RDSEED sets CF=1 on success, CF=0 when the entropy
    // pool is exhausted (modelled as always-successful).
    RDSEED,
    // Store AH into the low byte of EFLAGS (SF/ZF/AF/PF/CF).
    SAHF,
    // Scalar float compare, unordered-quiet: like COMISS/COMISD but only
    // ZF/PF/CF are written (both forms take #UD on a QNaN in older ISAs; the
    // interpreter reports the unordered result instead of faulting).
    UCOMISS, UCOMISD,
    // SSE/SSE2 square root (0F 51 by mandatory prefix).
    SQRTPS, SQRTPD, SQRTSS, SQRTSD,
    // SSE/SSE2 subtract (0F 5C by mandatory prefix).
    SUBPS, SUBPD, SUBSS, SUBSD,
    // Float interleave (0F 14/15): cc 0 = UNPCKL, 1 = UNPCKH; 66 = PD.
    UNPCKF,
    // SMM / VMX / SVM / TDX entry points and the descriptor-table reads.
    // Everything in this list is decoded exactly and then refused with the
    // fault real hardware raises for a CPL-3 guest.
    RSM, SYSENTER, SYSEXIT, SYSRET, SWAPGS, WRMSR, WBINVD, WBNOINVD,
    SERIALIZE, XSETBV, SEAMCALL, SEAMOPS, SEAMRET, STGI, CLGI,
    // Descriptor-table and task-register reads. SGDT/SIDT are unprivileged
    // (subject to UMIP); SLDT/STR/SMSW read selectors/machine status.
    SGDT, SIDT, SLDT, STR, SMSW, VERR, VERW,
    // Extended-state save/restore (0F AE /4,/5,/6 and 0F C7 /3,/4,/5).
    // Only the legacy x87/SSE region is modelled, so each image is the
    // 512-byte FXSAVE layout with XSTATE_BV = 3 (x87 | SSE).
    XSAVE, XSAVEOPT, XSAVEC, XSAVES, XRSTOR, XRSTORS,
    // Read XCR0 (D0) / transactional-memory control (E8 SERIALIZE, D5 XEND,
    // D6 XTEST, C7 F8 XBEGIN, C6 F8 XABORT).
    XGETBV, XEND, XTEST, XBEGIN, XABORT,
    // SSE control/status store (0F AE /3).
    STMXCSR,
    // SHA-1 / SHA-256 message schedule and round instructions. `cc` selects
    // the exact one: 0 MSG1, 1 MSG2, 2 NEXTE, 3 RNDS4, 4 SHA256MSG1,
    // 5 SHA256MSG2, 6 SHA256RNDS2.
    SHA,
    // CET shadow-stack probes. With CET disabled architecturally a no-op that
    // still consumes its operand.
    RDSSP, RSTORSSP,
    // BMI2 flag-free shifts and the rotate that does not touch flags.
    RORX, SARX, SHLX, SHRX,
    // AMD TBM (XOP map 9): cc 0 = T1MSKC, 1 = TZMSK.
    TBM,
    // AVX upper-state control: cc 0 = VZEROUPPER, 1 = VZEROALL.  YMM/ZMM are
    // not modelled, so both retire as architectural no-ops that end any
    // pending AVX transaction.
    VZERO,
    // Committed cipher-store forms (CET): WRSSD/WRSSQ and the user-supervisor
    // pair WRUSSD/WRUSSQ.  No shadow stack is modelled, so they store normally.
    WRSS, WRUSS,
    // Test-and-set / clock / wait hints that retire without visible state.
    TPAUSE, UMONITOR, UMWAIT,
    // Double-precision shifts. cc: 0 = SHLD, 1 = SHRD. The count comes from
    // an imm8 or CL (src2); the second source is the register operand.
    SHXD,
    // SSE4.1 rounding with the mode in imm8[1:0].
    ROUNDPS, ROUNDPD, ROUNDSS, ROUNDSD,
    // Reciprocal square root (0F 52 by mandatory prefix). The result is the
    // exact 1/sqrt(x); x86 only promises an approximation.
    RSQRTPS, RSQRTSS,
    // UD0 (0F FF) and UD1 (0F B9) — deliberately undefined encodings.
    UD,

    // ---- §2.21: AVX/AVX2/AVX-512 ------------------------------------
    // One opcode carries the whole vector ISA; the semantic operation lives in
    // `vec_op`, with the lane width, numeric domain, operating width and mask
    // in their own fields. This keeps the IR uniform across ~450 mnemonics
    // without 450 enum values that the translator would never distinguish.
    VEC,

    // ---- §2.22: Intel SGX -------------------------------------------------
    // ENCLS (0F 01 CF), ENCLU (0F 01 D7) and ENCLV (0F 01 C0) dispatch on the
    // leaf number in EAX; `sgx_leaf` carries the decoded leaf and `mnemonic`
    // the exact leaf name.
    ENCLS, ENCLU, ENCLV
};

// K is the AVX-512 opmask file (k0-k7); only the mask instructions use it.
enum class OperandKind : uint8_t { NONE, REG, MEM, IMM, REL, ST, K };

// Semantic operation of an X86Op::X87 instruction. Operand shapes:
//   arithmetic   dst = destination ST, src = the other ST or the memory operand
//   LOAD/STORE   src/dst respectively (ST(i) or MEM, width in .size)
//   compare      src is compared against ST(0)
enum class X87Op : uint8_t {
    INVALID = 0,
    ADD, MUL, SUB, SUBR, DIV, DIVR,
    COM, UCOM,        // C0/C2/C3 in the status word
    COMI, UCOMI,      // ZF/PF/CF in EFLAGS
    TEST,             // FTST
    LOAD, STORE, XCH, FREE,
    STSW, STCW, FLDCW, STENV, LDENV, SAVE, RESTORE,
    CLR_EXCEPTIONS, INIT, NOP,
    CHS, ABS, SQRT, RNDINT, SCALE, PREM, PREM1, XTRACT, EXAM, CONST,
    F2XM1, FYL2X, FPTAN, FPATAN, FYL2XP1, SINCOS, SIN, COS,
    DECSTP, INCSTP, CMOV,
    BCD_LOAD, BCD_STORE,
};

// x87 modifier bits carried in Insn::x87_flags.
enum : uint8_t {
    X87F_POP    = 1,   // pop the stack after the operation
    X87F_REV    = 2,   // ST(0) is the second source (FSUBR/FDIVR, STi,ST0 forms)
    X87F_INT    = 4,   // memory operand is an integer (FILD/FIST/FIxxx)
    X87F_TRUNC  = 8,   // FISTTP: truncate instead of honouring the RC field
    X87F_AX     = 16,  // FNSTSW writes AX instead of memory
    X87F_POP2   = 32,  // FCOMPP/FUCOMPP: pop both operands
};

struct MemOp {
    int base = -1;       // register index, -1 = none
    int index = -1;
    int scale = 1;
    int64_t disp = 0;
    bool rip_relative = false;
    uint8_t seg = 0;     // 0=none, 1=FS, 2=GS — base added at emit time
};

struct Operand {
    OperandKind kind = OperandKind::NONE;
    int reg = -1;            // 0-15 GPR, 16+ XMM
    int size = 0;            // bits
    int64_t imm = 0;
    MemOp mem;
    // 8-bit legacy high-byte register (AH/CH/DH/BH). With no REX prefix,
    // encoding numbers 4-7 name the second byte of RAX/RCX/RDX/RBX instead of
    // SPL/BPL/SIL/DIL. `reg` then names the containing 64-bit register.
    bool high8 = false;
};

struct Insn {
    X86Op op = X86Op::INVALID;
    uint8_t length = 0;
    uint64_t address = 0;
    Operand dst;
    Operand src;
    Operand src2;
    Operand src3;        // imm8 for the vector shapes that carry one
    bool rex_w = false;
    bool lock = false;
    bool rep = false;    // F3 prefix (REP/REPE)
    bool repne = false;  // F2 prefix (REPNE)
    bool o16 = false;    // 0x66 operand-size prefix
    uint8_t cc = 0;      // condition index (0-15) for CMOV/SETCC
    uint8_t seg = 0;     // segment override: 0=none, 1=FS, 2=GS
    uint8_t vex_l = 0;
    // VEX operand fields (BMI1/BMI2 etc.). vex_v is the decoded 4-bit
    // vvvv field, already inverted back to the register number.
    bool vex = false;
    bool vex_w = false;
    uint8_t vex_map = 0;  // 1 = 0F, 2 = 0F38, 3 = 0F3A
    uint8_t vex_v = 0;
    bool vex_pp = false;  // pp != 0 (mandatory prefix present)
    uint8_t vex_pp_bits = 0;  // raw pp: 0=none, 1=66, 2=F3, 3=F2
    // x87 escape decoding (op == X86Op::X87).
    X87Op x87op = X87Op::INVALID;
    uint8_t x87_flags = 0;

    // ---- VEX/EVEX vector state (op == X86Op::VEC) ---------------------
    uint16_t vec_op = 0;        // VecOp
    uint8_t elem_bits = 0;      // lane width, 0 for whole-register forms
    uint8_t vec_class = 0;      // VecClass
    uint16_t vec_bits = 128;    // 128 / 256 / 512
    bool evex = false;
    uint8_t evex_ll = 0;        // raw L'L: 0=128 1=256 2=512
    uint8_t mask = 0;           // EVEX.aaa (0 = k0 = unmasked)
    bool zeroing = false;       // EVEX.z
    bool evex_b = false;        // EVEX.b (broadcast or rounding control)
    uint8_t vsib_reg = 0;       // gather/scatter index register + 16
    uint8_t vsib_scale = 1;
    uint8_t vsib_index_bits = 32;

    // SGX leaf number (op == ENCLS/ENCLU/ENCLV).
    uint16_t sgx_leaf = 0;

    std::string mnemonic;
};

class X86Decoder {
public:
    // Decode one instruction at `data` (guest address `addr`). Returns nullopt on failure.
    static std::optional<Insn> decode(const uint8_t* data, size_t len, uint64_t addr);

    // Compatibility/legacy-mode decoding for the handful of opcodes that
    // 64-bit mode re-purposes (ARPL at 63, BOUND at 62 — EVEX in long mode).
    // Off by default: NINE's normal pipeline is 64-bit only, so those bytes
    // must keep decoding as MOVSXD and EVEX. Thread-local so a relinker pass
    // can enable it for a 32-bit guest image without disturbing other work.
    static void setCompat32(bool on);
    static bool compat32();

    // Decode a linear range into IR.
    static std::vector<Insn> decodeRange(const uint8_t* data, size_t len, uint64_t addr);
};

} // namespace nexus
