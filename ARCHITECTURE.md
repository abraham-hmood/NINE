# ARCHITECTURE.md — NINE Runtime Architecture & x86-64 Instruction Ledger

**Legend (all grids in this doc):** 🟩 = implemented (decode + execute) · 🟨 = partial / sample / stubbed semantics · ⬛ = not implemented (decode refuses → "unimplemented: *mnemonic*" SEH log; JIT path treats as NOP)

---

## 1. Runtime architecture (what NINE is)

```
ELF/PE file ──► Loader (ElfMapper / PeMapper)
                 │  PT_LOAD map, relocations, TLS template, auxv/envp stack
                 ▼
        GuestContext (Intel-style register file on ARM64 host)
                 │  rax..r15, rip, rflags, xmm/ymm byte arrays, fs_base/gs_base,
                 │  stack pointer, TEB, guest_tid, cur_insn block state
                 ▼
        X86Decoder  ──►  Insn IR (op, dst/src/src2, cc, lock/rep/o16, seg)
                 │
                 ├─►  InsnInterpreter   (semantic reference path — runs binaries today)
                 │        executes blocks linearly, resumable via InterpExit
                 │        (CONTINUE / BLOCK_END / SYSCALL / IMPORT / EXCEPTION)
                 │        faults surfaced as 0xC0000005 SEH with 48-deep trace ring
                 ▼
        Translator ──► CodeCache (AArch64 blocks, W^X, persistent "NINE" v2 format,
                 │            SMC-coherent via exec-page store tracking)
                 ▼
        ABI boundary
          ├─ SyscallTranslator  (Linux x86-64 syscall numbers → host Linux/Android)
          ├─ Kernel32/Ntdll/…   (PE guest Win32 DLL contract)
          └─ Threading          (1:1 clone / CreateThread, shared CodeCache)
```

Cross-cutting subsystems:

| Subsystem | File(s) |
|---|---|
| Memory: guest VA ↔ host, regions, W^X, guard pages, perms query | `cpp/memory/MemoryManager.*` |
| Lazy flags machine (`FlagState`: CF/PF/AF/ZF/SF/OF + raw mode) | `cpp/translator/FlagState.*` |
| Persistent translation cache keyed by image hash + translator version | `CodeCache` |
| Diagnostics ring logger → logcat tag `NINE` (8 categories incl. `LogCategory::ABI`) | `diagnostics/Logger.*` |
| Host-side debug on-device hook: `am broadcast -n com.nine.dbt/.DevRunReceiver` | `java/com/nine/dbt/DevRunReceiver.kt` |

### 1.1 GuestContext layout (`runtime/GuestContext.h`)

| Field | Purpose |
|---|---|
| `ctx.rax…r15`, `ctx.rip`, `ctx.rflags` | integer architect state |
| `ctx.ymm[16][32]` | XMM/YMM as byte arrays (XMM n = `ymm[n]`, indexed ≥16 for XMM regs after GPRs) |
| `ctx.fs_base`, `ctx.gs_base` | TLS bases; added in `effectiveAddress` when `seg==1/2` |
| `ctx.rdx` carries pd value; helper `GuestContext::rax()/rdx()` etc. | accessors for syscall shims |
| thread-local per thread; `GuestContext::cur_block` tracks the executing block | |

### 1.2 Packaging / relinking future-architecture (library `.so` split)

Current NFC: all guest ABI surfaces live in `libnexus_core.so`. Roadmap so per-program "relinking" does not drag the whole runtime with it, and so translated binaries can eventually run **standalone on ARM64 without any NINE runtime**:

1. Split the runtime into component `.so`s:
   - `libnexus_core.so` — loader + memory + diagnostics (always needed)
   - `libnexus_jit.so` — decoder/translator/codecache (versioned independently of the interpreter; cache format carries the JIT version, cold interpreter becomes the fallback ABI anchor)
   - `libabi_windows.so` / `libabi_linux.so` — syscall + DLL exports
   - `libai.so` (llama.cpp) — only paged in inside the AI tabs
2. The **Relink** step already packages `libnexus_core.so` + guest libraries + executable into a zip; next step is emitting **APK-sized bundles** where executables get relinked against whichever surface they truly import (REVERSE_TECHNIQUE.md's demand-driven inventory).
3. **Native-ARM relinker**: eventual mode where relocations are resolved at *translation* time against AArch64 stubs, producing ARM64 binaries that do not depend on the interpreter at all (full-flag-refined codegen + real `svc` mapping). Interpreted execution today is the semantic specification for that emitter.

---

## 2. x86-64 instruction universe — implementation ledger

Rows are grouped like Intel SDM ordering. The **current live contract**:
unsupported mnemonic → `X86Op::INVALID` → interpreter SEH `0xc000001d … unimplemented: <mnemonic>` at the exact guest RIP; run-loop stops with `stop reason=EXCEPTION @<rip>`; the trace ring (48 entries, `ea=… trace: …` line) shows how control flow reached it — this is the demand-driven expansion loop from `REVERSE_TECHNIQUE.md`.

### 2.1 Decoder infrastructure

| Mechanism | Status |
|---|---|
| Legacy prefixes: LOCK(F0), REP/REPE(F3), REPNE(F2), o16(66), CS/DS/ES/SS overrides, Segment FS(64)/GS(65) recorded (`in.seg`), opsize branches | 🟩 |
| ModRM/SIB with index=4-no-XMM trap, `[rbp+disp]`, absolute disps, RIP-relative (+ instruction-length fix — `cur_insn_len_`) | 🟩 |
| REX (W/R/X/B), VEX.128/.256 structurally detected (→ per-op AVX table below), EVEX structurally detected | 🟨 |
| Operand-size handling for ALU 16-bit imm, C7, B8–BF, string ops | 🟩 |
| FS/GS segment bases honored in memory ops | 🟩 |
| LOCK prefix accepted on RMW ALU/CMPXCHG/XADD (unlocked single-thread semantics) | 🟨 |
| REPE/REPNE loop execution for string ops | 🟨 |

### 2.2 Data / inter-register movs

| Instruction | Family | Status |
|---|---|---|
| `MOV r/m8, r8` (88), `MOV r/m16/64, r` (89), `MOV r8 ← r/m8` (8A), `MOV r ← r/m` (8B) | int | 🟩 |
| `MOV r/m64, imm64` (B8+r imm64), reg-immediate for 16/32 | int | 🟩 |
| MOV moffs (A0–A3 absolute) | int | 🟩 |
| `MOV r/m, imm` (C6 = 8-bit, C7 = 16/32/64-sign-extended) | int | 🟩 |
| MOV reg store via ModRM+disp32 → mem indexing shift | int | 🟩 |
| LEA (8D) — incl. SIB index / base-most / bmp / RIP-relative | int | 🟩 |
| MOVZX (0F B6/B7), MOVSX (0F BE/BF), MOVSXD (63, 32→sign ext 64) | int | 🟩 |
| MOVSXD with reg from shift w / 63 decoded | int | 🟩 |
| CDQE (48 98) | int | 🟩 (as MOVSX) |
| CDQ (99) — EAX→EDX sign, D | int | 🟩 |
| XCHG — 87/86 mem/reg and 90+r accumulator shortform (incl. 91–97 reg swap) | int | 🟩 |
| BSWAP (0F C8+r) | int | ⬛ |
| MOVBE (F2 0F 38 F0/F1) | int | ⬛ |
| PUSH r/r-r/push imm (50+r/68/6A) / PUSH FS,GS | int | 🟩 (r + imm) |
| POP r / 8F /0 + POP FS/GS | int | 🟩 |
| ENTER (C8) | int | ⬛ |
| LEAVE (C9) | int | 🟩 |
| MOV emits into stack prolog/epilog patterns (61-byte stubs?) | — | n/a |

### 2.3 Flag-shaped integer ALU

| Instruction | Status | Notes |
|---|---|---|
| ADD (00–03, 04/05) | 🟩 | |
| OR (08-0B), AND (20-23), XOR (30-33), SUB (28-2B), CMP (38-3B) | 🟩 | |
| ADC (10-13, 14/15) + SBB (18-1B, 1C/1D) with true carry handling, rflags-smart | 🟩 | SBB r,r (−CF) verified |
| grp1 imm8/imm16/imm32 (80/81/83) — all 8 extensions | 🟩 | |
| ALU-eAX,imm — imm32 AND imm8 forms for all 8 extensions | 🟩 | need `opc&7` ∈ {4,5} both |
| TEST (88/89, A8/A9) | 🟩 | |
| INC/DEC (FF/F, FE/F + 40–4F shortform via 0100 WXXX? — decoder maps 40–4F as real ops) | 🟩 | |
| NEG (F6 /3, F7 /3) | 🟩 | |
| NOT (F6 /2, F7 /2) | 🟩 | |
| CMPS (A6/A7) | ⬛ | |
| full PF flag from `materialize()`; AF/CF/OF/SF/ZF live | 🟩 | lazy evaluations in `FlagState` |

### 2.4 Shifts / rotates

| Instruction | Status |
|---|---|
| SHL/SAL (C0/C1/D0-D3 /4), SHR (/5), SRL/SAL/SHR by reg (D2/D3) | 🟩 |
| SAR (F8 /7 group) | 🟩 |
| ROL (/0), ROR (/1) with CF/OF end corrections, count masking | 🟩 |
| RCL, RCR (through-CF rotates) | ⬛ |
| SHLD/SHRD (0F A4/A5/AC/AD) | ⬛ |
| RORX (VEX F2), SHLX/SHRX/SARX (BMI2) | ⬛ |

### 2.5 Multiplication / division

| Instruction | Status |
|---|---|
| IMUL 2-op (0F AF), 3-op 69/IBM… | 🟩 (incl. src2_IMM) |
| grp3 F6/F7 (MUL/IMUL/DIV/IDIV /4-/7) | 🟩 |
| MUL (F6 /4) | 🟩 |
| DIV/IDIV (F6/F7 /6,/7) | 🟩 |

### 2.6 Control flow

| Instruction | Status |
|---|---|
| JMP short/near (EB/E9) | 🟩 |
| JMP reg/mem 16 FF /4 /5 | 🟩 |
| Jcc (one-byte 70-7F + 0F 80-8F near), all 16 conditions via `evalCc` cn field | 🟩 |
| CMOVcc (0F 40-4F) real operands | 🟩 |
| SETcc (0F 90-9F) | 🟩 |
| CALL near (E8), CALL r/m FF /2 | 🟩 |
| RET (C3), RET imm16 (C2), RET far | 🟩 |
| LOOP/LOOPE/LOOPNE (E0–E2), JECXZ (E3) | ⬛ |
| ENTER/LEAVE | LEAVE 🟩 / ENTER ⬛ |
| HLT, INT n, IRET/IRETQ, INTO, RSM | ⬛ (privileged/system path) |

### 2.7 String operations (AA–AF + F2/F3 loops)

| Instruction | Status |
|---|---|
| MOVS (A4/A5) | 🟩 |
| STOS (AA/AB) | 🟩 |
| LODS (AC/AD) | 🟩 |
| SCAS (AE/AF) | 🟩 |
| CMPS (A6/A7) | ⬛ |
| INS/OUTS | ⬛ (privileged-ish I/O) |
| REP/REPE/REPNE prefix loop shapes | 🟨 |

### 2.8 Atomic / sighandling RMW

| Instruction | Status |
|---|---|
| CMPXCHG (0F B0/B1) | 🟩 |
| XADD (0F C0/C1) | 🟩 |
| CMPXCHG8B/16B (0F C7) | ⬛ |
| LOCK prefix semantics’ real memory precedence (single-threaded ok; multi-thread atomics → LSE) | 🟨 |
| MOVDIRI/MOVDIR64B, ENQCMD | ⬛ |

### 2.9 x87 FPU (all ⬛ today)

FLD/FST/FSTP/FSTCW/FNSTCW/FLDCW/FLDENV/FSTENV · FADD/FADDP/FSUB/FMUL/FDIV/FDIVR/FMULP · FUCOM/FUCOMI/FUCOMIP/FCOMI/FCOMIP/FTST/FXAM · FCHS/FABS/FSQRT/FSCALE/FPREM/FPTAN/F2XM1 · FLDZ/FLD1/FLDL2E/FLDLG2/FLDLN2 · FSTSW/FNSTSW/FSAHF/FNSAHF · FINIT/FNINIT/FSAVE/FNSAVE/FRSTOR · FXCH/FNSTENV

### 2.10 SSE / SIMD — integer + FP on XMM/YMM

Foundation ops we can decode+execute today are those demanded by glibc's internal startup paths (`__tunable_get_val`/`init_cpu_features` use MOVD/MOVQ/MOVHPS/PUNPCK/PXOR/TESTS etc.):

| Instruction | Status |
|---|---|
| MOVD (66 0F 6E/7E) GPR↔XMM | 🟩 |
| MOVQ (66 0F D6 store; 66 0F 6E/7E with 64 bits) XMM↔r/m64 | 🟩 |
| MOVAPS/MOVUPS/MOVAPD/MOVUPD/0F 10/11 | 🟩 |
| MOVAPS 0F 28/29 + MOVDQA/MOVDQU 66 0F 6F/7F (16-byte moves) | 🟩 |
| MOVLPS/MOVLPD load (0F 12 both without / with 66), MOVLPS reg-reg flavor | 🟨 (mem-only) |
| MOVLPS store (0F 13) | 🟩 |
| MOVHPS/MOVHPD load (0F 16) | 🟩 |
| MOVHPS/MOVHPD store (0F 17) | 🟩 |
| MOVHLPS/MOVLHPS (0F 12/16 with reg,reg) | ⬛ |
| PXOR (0F EF) zeroing 128 | 🟩 |
| PUNPCKLDQ (66 0F 62), PUNPCKLQDQ (66 0F 6C), PUNPCKHQDQ (66 0F 6D) | 🟩 |
| ADDPS (0F 58), MULPS singles (sample verified correctness on SSE decode vertical) | 🟨 |

Everything else still ⬛ per family:

| Family | Representative mnemonics | Status |
|---|---|---|
| SSE1 FP | ADDSS/ADDPS, SUBSS/SUBPS, MULSS/MULS, DIVSS/DIVPS, SQRTSS/SQRTPS, RCPSS/RCPPS, RSSPSS/RSQRTPS, MINSS/MINPS, MAXSS/MAXPS, CMPSS/CMPPS, COMISS/UCOMISS, CVTSI2SS, CVTSS2SI, CVTTSS2SI, LDMXCSR/STMXCSR, MASKMOVQ, PSHUFW, SYNCH | ⬛ (singles ADDPS/MULPS partially via 🟨 sample) |
| SSE2 int128 | PAND/PANDN/POR/PXOR*, PADDB/PADDW/PADDD/PADDQ, PSUB*, PSLLQ/PSRLQ/PSLLD/PSRLD, PMULUDQ/PADDQ, MOVQ2DQ, MOVDQ2Q, PAUSE-along top CMPPD, UNPCK* | ⬛ except `PXOR/PUNPCK*` 🟩 and `PADDD`-level simple arithmetic stub testcases |
| SSE2 FP | MOVSD/MOVSS, CVT*D/DQ, ADDSD/SUBSD/MULSD/DIVSD, MAXSD/MINSD, UCOMISD, SQRTSD | ⬛ |
| SSE3/SSSE3 | MOVSHDUP/MOVSLDUP/MOVDDUP (F2 0F 16/12 etc), HADDPS, PHADD*, PSHUFB, PALIGNR, PSHUFLW | ⬛ |
| SSE4.1/4.2 | PMULLD, PBLEND*, PMULUDQ*, PEXTRD/PINSRD, PTEST, CRC32, PCMPEQQ, PHMINPOSUW, ROUNDSS/ROUNDSD/ROUNDPS | ⬛ |
| AVX (VEX) | VEX.128/256 — everything: VADDPS, VPXOR, VMAC, VMOVAPS, VBROADCAST, VGATHER… | ⬛ (VEX_OP placeholder — structurally detected only) |
| AVX2 | VPBROADCAST*, VPGATHERDD, VPMASKMOV, VPBLENDD integer 128 AVX2 ops | ⬛ |
| AVX-512 (EVEX) | EVEX_OP placeholder; zmm, masking (k), SAE/ER | ⬛ |
| Prefetch | PREFETCHT0/T1/T2/NTA, CLWDEM, MOVDIR64B | ⬛ |
| PAUSE (F3 90) | treated as NOP (96-byte spin path) | 🟨 |

### 2.11 Segment / system / privileged

| Instruction | Status |
|---|---|
| Architecture-aware prefixes for endbr64 (F3 0F 1E FA) | 🟩 |
| CPUID (0F A2) — synthesized leaf set (brand, TSC freq, HWCAP-zero) | 🟩 |
| RDTSC (0F 31), RDTSCP (0F 01 F9) | ⬛ |
| RDMSR/WRMSR, SYSENTER/SYSEXIT, RDPID/RDPMC | ⬛ |
| SYSCALL (0F 05) | 🟩 (routes into SyscallTranslator) |
| SYSRET | ⬛ (kernel-only) |
| SGDT/SIDT/LSL/LAR/VERR/VERW/LLDT/LGDT/UD2 variants | ⬛ |
| INT3 (CC) | 🟩 (breakpoint trap → SEH INT3 path) |
| MONITOR/MWAIT, CLFLUSH/CLFLUSHOPT, SFENCE/MFENCE/LFENCE (serializing fences execute as nops?) | ⬛ (they matter once multi-thread SMT becomes critical) |
| XSAVE/XRSTOR/XSETBV/XGETBV | ⬛ |
| STC/CLC/CMC/STD/CLD, SAHF/LAHF, PUSHF/POPF | ⬛ (flags materialize path mostly covers, but decoders refuse) |
| IN/OUT, INS/OUTS, CLI/STI | ⬛ |

### 2.12 Known decode quality fixes discovered through the loop

| Fix | Why |
|---|---|
| ALU-eAX区块 needed `opc&7 ∈ {4,5}` | first patch only matched imm32 form; imm8 (04/etc) got swallowed |
| SIB index=4 without REX.X | Nones (`lea rcx,[rax*8]` etc) |
| Real 0x19 ED SBB r13d,r13d carry in | `-CF` idiom everywhere in glibc |
| 0x66 prefix 全 o16 record + disp32 abs32 fix (SIB base=5) | disp was skipped → instruction length wrong |
| String ops honoring o16 (66 A4 = MOVSW) | glibc init uses 16-bit string ops |
| %gs:/%fs: basis bases into TS mem ops | PIC glibc uses %fs:0x28 / %gs:memory+off heavily |

---

## 3. Alignment to the coverage docs

- README carries the *visual* coverage grids (Windows ABI / Linux API / ISA), now including the **complete Windows system-DLL inventory** (≈80 app-linkable DLLs incl. kernelbase/win32u/api-ms-win-* API-sets) and the **complete Linux system-library inventory** (glibc family + GCC runtime + ecosystems listed per family).
- `LIBRARIES.md` carries the *named* per-API and per-syscall checklists.
- This file carries the *instruction* inventory + the runtime architecture rationale.
- `app/src/main/cpp/SUPPORTED.md` remains the original hardcoded technical table (syscalls, relocations, PE directories).

**Maintenance rule:** any patch that adds/removes a guest-visible capability must update cells in AUTHOR-enclosing docs in the same commit. If the ISA cell you are flipping touches one row's mnemonic too — add a row to §2 here and flip the equivalent cell in README’s ISA grid in the same commit (details in REVERSE_TECHNIQUE.md "Coverage ledger maintenance").
