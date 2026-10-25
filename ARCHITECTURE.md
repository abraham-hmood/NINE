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
| `ctx.gpr[16]`, `ctx.rip`, `ctx.rflags` | integer architect state; accessors `ctx.rax()` … `ctx.rdi()` |
| `ctx.ymm[32][64]` | the whole vector file: 32 registers × 64 bytes. XMMn is bytes 0-15, YMMn 0-31, ZMMn 0-63 of the same slot, so an SSE write leaves the upper bytes alone and VEX/EVEX zero-extends them where the ISA says |
| `ctx.kmask[8]` | AVX-512 opmask k0-k7 (k0 = implicit unmasked) |
| `ctx.fpu` (`x87::State`) | x87 stack (8 × 80-bit), control/status/tag words; travels with the context |
| `ctx.bnd[4][2]` | MPX bounds BND0-BND3 as (LB, UB) in architecturally visible 1's-complement form |
| `ctx.fs_base`, `ctx.gs_base` | TLS bases; added in `effectiveAddress` when `seg==1/2` |
| `ctx.mxcsr` | SSE control/status, round-tripped by LDMXCSR/STMXCSR/FXSAVE; routing bits not applied to SSE math yet |
| `ctx.exit_reason`, `exit_code`, `exit_arg0..2` | the J1.2/J6 exit channel written by translated and AOT blocks before `RET` |
| thread-local per thread; `ContextSwitch::current()` reaches it; `kRedZone` = 128 bytes | |

### 1.1 Host feature modules (`app/src/main/cpp/upscale/`)

| Module | Behavior |
|---|---|
| `Upscaler` (singleton) | DLSS-style frame upscaler: bilinear base pass then edge-adaptive 9-tap refinement (edge magnitude gates kernel strength). Models: `.n9up` (first-party format: magic "N9UP", version 1, scale 2..8, ≤64 float32 tap weights) or `.tflite`/`.onnx` registered as opaque payloads (default kernel runs until the TFLite delegate lands). JNI: `nativeUpscalerSetModel/Status/SetEnabled`. The per-frame hook (`upscaleFrame`) activates with the G1 guest framebuffer pipeline. |
| `GameDetector` | Scored byte-scan of the first 2 MiB: engine/d3d/GL/Vulkan/SDL/GLFW/XInput tokens (strong weights) plus saturated weak signals ("fullscreen", "fps", …); `score ≥ 35 → isGame`. Called at every `loadAndRun` for logging + JNI-exposed as `nativeDetectGame`. |

| Light shell host surface | Behavior |
|---|---|
| `LightShellPackager` | Runtime APK surgery: template `:shell` APK from assets, `AxmlPatcher` string-pool rewrite (package → `com.nine.shell.<program>` incl. derived component names, label → program name), icon PNG replacement, payload `assets/program/**` + `lib/arm64-v8a/libnexus_core.so` (read from NINE's own `sourceDir` APK — NINE ships `extractNativeLibs=false`, so `nativeLibraryDir` is empty) + `assets/vhd_path.txt`, v1-signed by `ApkV1Signer` (fresh RSA-2048, hand-built X.509/PKCS#7 DER; every non-`META-INF` entry signed), saved to `/sdcard/NINE/shells` (`MANAGE_EXTERNAL_STORAGE`, requested at tutorial end + one-off prompt; app-scoped fallback). One APK is built per selected program; `ShellInstallQueue` commits the sessions sequentially (Android shows one installer prompt at a time), and `InstallResultReceiver` → `grantVhdFor` hands each installed package `com.nine.dbt.vhdshare` access to the VHD recorded for it. A batch of exactly one publishes `ShellEvents.pendingRun`, which the UI turns into a `Run <program>?` dialog that launches the shell. |
| Shell payload mirror | Guest executables/libraries are duplicated as `lib/arm64-v8a/libnine_<n>.so` with `assets/program/payload.json` mapping slot → real relative path. The installer extracts those into `nativeLibraryDir` (the only payload surface Android keeps consistently), and `ShellPayload` copies from there, falling back to `assets/program/**`. Files are named `.so` precisely because arbitrary binary names are dropped/refused. |
| `AxmlPatcher` | Binary Android XML (AXML) string-pool rewriter; rebuilds the pool in UTF-8 keeping entry count (index-stable), so no resource editor ships with the app. Validated with `aapt2 dump xmltree`. |

### 1.2 Packaging / relinking future-architecture (library `.so` split)

Current NFC: all guest ABI surfaces live in `libnexus_core.so`. Roadmap so per-program "relinking" does not drag the whole runtime with it, and so translated binaries can eventually run **standalone on ARM64 without any NINE runtime**:

1. Split the runtime into component `.so`s:
   - `libnexus_core.so` — loader + memory + diagnostics (always needed)
   - `libnexus_jit.so` — decoder/translator/codecache (versioned independently of the interpreter; cache format carries the JIT version, cold interpreter becomes the fallback ABI anchor)
   - `libabi_windows.so` / `libabi_linux.so` — syscall + DLL exports
   - `libai.so` (llama.cpp) — only paged in inside the AI tabs
2. The **Relink** step already packages `libnexus_core.so` + guest libraries + executable into a zip; next step is emitting **APK-sized bundles** where executables get relinked against whichever surface they truly import (REVERSE_TECHNIQUE.md's demand-driven inventory).
3. **Native-ARM relinker**: eventual mode where relocations are resolved at *translation* time against AArch64 stubs, producing ARM64 binaries that do not depend on the interpreter at all (full-flag-refined codegen + real `svc` mapping). Interpreted execution today is the semantic specification for that emitter — §1.3 is that step, implemented.

### 1.3 Relinker-side AOT translation (`app/src/main/cpp/aot/`)

The relinker compiles the program while the image is mapped and relocated and
writes native images beside it, so the result no longer *needs* a translator to be
interpretable. `AotEngine`/`AotModule` load and dispatch those images. **Status:** the
compiler, runtime and relink step are done and exercised on device; wiring the run
path (`ExecutionLoop` / light shell) to *prefer* a `.nine.aot` image over the
translator is not done yet — today the relink report is the only consumer, so a
program still executes through the interpreter/JIT.

| Piece | Role |
|---|---|
| `AotCompiler` | `compile(code, len, base, entry)`. Linear decode with `X86Decoder`, block split at the range start, after every terminator (`JMP`/`Jcc`/`CALL`/`RET`/`SYSCALL`/`INT3`/`UD2`) and at every direct branch target; one AArch64 function per block. Guest state stays in `GuestContext` memory (x23 = ctx, x9–x16 scratch, guest GPRs loaded/stored per instruction), so blocks are position independent and callable from any dispatcher. Because a memory operand goes through a C helper, which clobbers every scratch register, the two halves an instruction has already computed are parked on the stack around that call (16 bytes, keeping SP aligned). |
| Exit protocol | Each block stores guest RIP and `exit_reason` into the context and returns — the same J1.2 channel the JIT uses (`CONTINUE`, `SYSCALL`, `EXCEPTION`, `INDIRECT`). `AotRuntime` is the trampoline. |
| Runtime helpers (`AotHelpers.cpp`) | `nine_aot_flags(ctx, kind, res, a, b, bits, keep)` and `nine_aot_shift_flags(ctx, res, src, count, bits, kind)` — the single home of x86 flag arithmetic for AOT (mirrors `translator/FlagState.cpp`), including shift/rotate CF/OF rules. Both *return* the masked result because every scratch register is caller-saved. Memory goes through the existing `nine_load*`/`nine_store*` helpers, so guest page permissions and faults behave exactly as in the interpreter. |
| `AotImage` | `Header | Block[] | Reloc[] | code[]`, FNV-1a over the code words. `Reloc` entries point at a 4-word `MOVZ/MOVK` sequence that carries a helper address; the loader patches the 16-bit immediates. |
| `AotRuntime` | `AotModule` maps an image RW, patches helper relocations, `__clear_cache`, `mprotect` RX, and indexes blocks by guest pc. `AotEngine` holds the images of a program (one per executable segment) and runs blocks until an exit reason other than `CONTINUE`. No decoder, no code cache, no SMC handling. |
| `AotRelink` | `translate()` walks the executable ranges of a mapped/relocated module (ELF `PT_LOAD` with `PF_X`, PE executable sections), splits ranges at memory-region boundaries, compiles each, and writes `<stem>.<n>.nine.aot` beside the program. Runs from `RuntimeBridge::relinkElf`/`relinkPe`. |

Acceptance is all-or-nothing per module: an unsupported instruction yields no image,
the relink result carries `aot.unsupported` (deduplicated mnemonics) and
`aot.error`, and the summary line says `AOT: not translated`. Nothing is
silently miscompiled. `aot.ok` in the relink JSON is the contract a run path will
use to decide whether a program can run without a translator; today the relink
report is the only consumer of it.

Emitted-code coverage today: `NOP`, `MOV`, `MOVZX`, `MOVSX`, `LEA`, `PUSH`,
`POP`, `LEAVE`, `ADD/SUB/AND/OR/XOR/CMP/TEST`, `INC/DEC/NEG/NOT`,
`SHL/SHR/SAR/ROL/ROR`, `SETcc`, `CMOV`, `XCHG`, `Jcc`, `JMP`, `CALL`, `RET`,
`SYSCALL`, `INT3`, `UD2`, `BSWAP`, `CBW/CWDE/CDQE/CDQ`, `CLC/STC/CLI/STI/CLD/STD/CLAC/STAC`.
8-bit operands follow the legacy register rule end to end: encoding numbers 4-7 on
`ah/bh/ch/dh` are read from and written to bits 15:8 of the containing GPR (matches
`InsnInterpreter::readOperand`/`writeOperand`), so `mov ah,1` cannot alias the low
byte. Anything else (SSE/AVX, `IMUL`, `DIV`, string ops, x87, MPX, BCD adjusts) is
refused by name until it gets an emitter.

Verified on a real arm64 device (NDK-built harness linking the shipped sources):
arith+flags/SETcc, loop+branch, guest-memory load/store (including a memory
source with a live destination, e.g. `add rax, [rbx]`), `xchg` in both the
r/m↔reg and reg↔reg forms, `CALL`/`PUSH`/`POP`/`RET` with a balanced stack, and
shift/rotate/`BSWAP` all execute correctly; high-byte access
(`mov al/ah`, `add ah`, `mov bl,ah`, `mov bh,ah`) lands in the right bits while the
rest of the GPR is preserved; an SSE blob is refused with its mnemonic listed. Each
case was also run against a build with the fix removed to prove the check fails
without it (`add rax,[rbx]` returned helper garbage; high-byte ops aliased the low
byte, `rax=0x1279` instead of `0x5778`). The same cases live in
`tests/NativeTests.cpp` behind test id `j5`/`9.5`/`aot`.

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
| Operand-size handling for ALU 16-bit imm, C7, B0–BF, string ops | 🟩 |
| Legacy 8-bit register rule: without REX, encoding 4-7 is AH/CH/DH/BH (`Operand::high8`, set by `applyByteReg`) | 🟩 |
| FS/GS segment bases honored in memory ops | 🟩 |
| LOCK prefix accepted on RMW ALU/CMPXCHG/XADD (unlocked single-thread semantics) | 🟨 |
| REPE/REPNE loop execution for string ops | 🟨 |

### 2.2 Data / inter-register movs

| Instruction | Family | Status |
|---|---|---|
| `MOV r/m8, r8` (88), `MOV r/m16/64, r` (89), `MOV r8 ← r/m8` (8A), `MOV r ← r/m` (8B) | int | 🟩 |
| `MOV r8, imm8` (B0+r) — incl. AH/CH/DH/BH destinations | int | 🟩 |
| `MOV r/m64, imm64` (B8+r imm64), reg-immediate for 16/32 | int | 🟩 |
| MOV moffs (A0–A3 absolute) | int | 🟩 |
| `MOV r/m, imm` (C6 = 8-bit, C7 = 16/32/64-sign-extended) | int | 🟩 |
| MOV reg store via ModRM+disp32 → mem indexing shift | int | 🟩 |
| LEA (8D) — incl. SIB index / base-most / bmp / RIP-relative | int | 🟩 |
| MOVZX (0F B6/B7), MOVSX (0F BE/BF), MOVSXD (63, 32→sign ext 64) | int | 🟩 |
| MOVSXD with reg from shift w / 63 decoded | int | 🟩 |
| CDQE (48 98) | int | 🟩 (as MOVSX) |
| CDQ (99) — RDX = sign of RAX (CWD/CDQ/CQO by operand size) | int | 🟩 |
| XCHG — 87/86 mem/reg and 90+r accumulator shortform (incl. 91–97 reg swap) | int | 🟩 |
| BSWAP (0F C8+r) | int | 🟩 |
| MOVBE (F2 0F 38 F0/F1, load and store) | int | 🟩 |
| 8-bit ALU/MOV/CMP source or destination naming AH/CH/DH/BH | int | 🟩 (interpreter + AOT honour bits 15:8) |
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
| ADCX (66 0F 38 F6) / ADOX (F3 0F 38 F6) — r32/64 += r/m + CF (ADCX) or + OF (ADOX) | 🟩 | only CF (ADCX) / OF (ADOX) written; SF/ZF/AF/PF preserved (ADX) |
| AAA (37), AAS (3F), AAM (D4 ib), AAD (D5 ib) — ASCII/BCD adjust | 🟩 | compat/legacy semantics executed in 64-bit mode (no #UD); AAM base 0 → `0xC0000094` #DE; SF/ZF/PF only for AAD/AAM |
| full PF flag from `materialize()`; AF/CF/OF/SF/ZF live | 🟩 | lazy evaluations in `FlagState` |
| Bit test/scan: BT/BTS/BTR/BTC (0F A3/AB/B3/BB + 0F BA /4-/7), BSF/BSR (0F BC/BD), TZCNT/LZCNT (F3 0F BC/BD), BSWAP (0F C8+r) | 🟩 | memory bit-string addressing (`ea + idx/bits * bytes`); TZCNT/LZCNT set CF when the source is zero |
| BMI1: ANDN (VEX.0F38 F2), BLSI/BLSMSK/BLSR (F3 /3 /2 /1), BEXTR (F7), BZHI (F5) | 🟩 | real VEX C4/C5 prefix decode; CF/OF/ZF per the SDM pseudo-code |
| Flag control CLC/STC/CLI/STI/CLD/STD (F8–FD), CLAC/STAC (0F 01 CA/CB) | 🟩 | IF/DF/AC live in the RFLAGS shadow; CLI/STI never fault (no interrupt delivery) |
| Cache hints CLDEMOTE (0F 1C /0), CLFLUSH/CLFLUSHOPT (0F AE /7), CLWB (66 0F AE /6) | 🟩 | architectural no-ops |
| Legacy/compat-only ARPL (63), BOUND (62) | 🟨 | semantics implemented; decode only under `X86Decoder::setCompat32(true)` (MOVSXD/EVEX in long mode) |
| MPX BNDMK/BNDMOV/BNDCL/BNDCU/BNDCN, BNDLDX/BNDSTX (F3/F2/66/None 0F 1A/1B) | 🟩 BNDMK/BNDMOV/checks; 🟨 LDX/STX | four bound registers in `GuestContext`; violations raise `#BR` (`0xC0000085`); bound tables not modelled (see §2.15) |
| CBW (66 98), CWDE (98), CDQE (48 98), CDQ (99), CQO (48 99) | 🟩 | widths follow the destination, as the SDM defines them |

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
| CMPXCHG8B/16B (0F C7 /1) | 🟩 (§2.10.1; 16-byte form compares/updates EDX:EAX / RDX:RAX as one guest-atomic block) |
| LOCK prefix semantics’ real memory precedence (single-threaded ok; multi-thread atomics → LSE) | 🟨 |
| MOVDIRI/MOVDIR64B, ENQCMD | 🟩 MOVDIRI/MOVDIR64B store as documented; ENQCMD/ENQCMDS decode then #UD (CR4.ENQCMD = 0) |

### 2.9 x87 FPU (D8–DF) — implemented

The register file lives in `GuestContext::fpu` (`runtime/X87.h`): eight 80-bit
values kept as an explicit 64-bit significand plus a sign/exponent word, the
control word, the status word (TOP in bits 13..11) and the 2-bit-per-register
tag word. Holding values in real 80-bit form is what makes FLD m80fp / FSTP m80fp,
FNSAVE/FRSTOR and FXSAVE/FXRSTOR round-trip byte-exactly — a host `long double`
cannot promise that (binary128 on aarch64, 80-bit on x86-64, plain double on MSVC).
Execution lives in `runtime/X87Exec.cpp`, decoding in `X86Decoder.cpp`
(`decodeX87`), which maps each encoding onto `X86Op::X87` + a semantic `X87Op`
plus pop/reverse/integer/truncate modifiers.

| Group | Mnemonics | Status |
|---|---|---|
| Load / store | FLD (m32/m64/m80, ST(i)), FST, FSTP (m32/m64/m80, ST(i)), FXCH, FFREE/FFREEP, FILD (m16/32/64), FIST/FISTP/FISTTP (m16/32/64), FBLD/FBSTP | 🟩 |
| Arithmetic | FADD/FADDP/FIADD, FSUB/FSUBP/FISUB, FSUBR/FSUBRP/FISUBR, FMUL/FMULP/FIMUL, FDIV/FDIVP/FIDIV, FDIVR/FDIVRP/FIDIVR — m32/m64/m16-int, ST(0),ST(i) and ST(i),ST(0) forms | 🟩 |
| Compare | FCOM/FCOMP/FCOMPP, FUCOM/FUCOMP/FUCOMPP (C0/C2/C3), FCOMI/FCOMIP/FUCOMI/FUCOMIP (ZF/PF/CF), FICOM/FICOMP, FTST, FXAM | 🟩 |
| Unary | FCHS, FABS, FSQRT, FRNDINT, FSCALE, FXTRACT, FPREM, FPREM1, FDECSTP, FINCSTP, FNOP | 🟩 |
| Transcendental | F2XM1, FYL2X, FYL2XP1, FPTAN, FPATAN, FSIN, FCOS, FSINCOS | 🟩 (host libm; last bits can differ from x87 tables) |
| Constants | FLD1, FLDL2T, FLDL2E, FLDPI, FLDLG2, FLDLN2, FLDZ | 🟩 |
| Control | FLDCW, FNSTCW, FLDENV, FNSTENV, FNSAVE, FRSTOR, FNCLEX, FNINIT, FWAIT (9B) | 🟩 (FWAIT is a no-op: no pending x87 exception is ever reported) |
| Conditional move | FCMOVB/E/BE/U and FCMOVNB/NE/NBE/NU | 🟩 |
| State images | FXSAVE (0F AE /0), FXRSTOR (0F AE /1), EMMS | 🟩 |

Decisions worth knowing:

* **Rounding** of every result to the 64-bit significand honours the control
  word's RC field (nearest-even / down / up / truncate). PC is not honoured:
  everything is computed and stored at extended precision, which is what the
  default CW 0x037F selects and what all 64-bit code uses.
* **Arithmetic** runs in the host `long double` and is rounded back to 64 bits,
  so a single + − × ÷ or √ is correctly rounded — binary128 carries 113
  significand bits, far more than the 64 needed to absorb the second rounding.
  Only pathological cases could differ in the last bit from real silicon.
* **Pointers are not tracked**: FNSTENV/FNSAVE store zeros for FIP/FDP/FOP and
  FLDENV/FRSTOR ignore those fields.
* **Stack faults** set SF|IE|C1 in the status word, but FP exception *delivery*
  (#MF/#XM) is not modelled — NINE never reports a pending x87 exception.
* **Environment image** is NINE's own layout: FCW@0, FSW@2, FTW@4, FIP@6,
  FDP@14, FOP@22 (28 bytes), followed by 8×10 bytes of register data for the
  108-byte FNSAVE image. FXSAVE/FXRSTOR use the architectural 512-byte layout
  (FCW/FSW/abridged FTW, MXCSR@24, ST0–ST7@32, XMM0–XMM15@160); MXCSR itself is
  not modelled, so FXSAVE writes the default 0x1F80 and FXRSTOR ignores it.

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
| ADDPS (NP 0F 58), ADDPD (66 0F 58), ADDSS (F3 0F 58), ADDSD (F2 0F 58) | 🟩 | packed 4×f32 / 2×f64 lanes; scalar forms preserve the upper lanes (legacy SSE) |
| ADDSUBPS (F2 0F D0), ADDSUBPD (66 0F D0) | 🟩 | even lanes dst−src, odd lanes dst+src (SSE3) |
| DIVPS (NP 0F 5E), DIVPD (66 0F 5E), DIVSS (F3 0F 5E), DIVSD (F2 0F 5E) | 🟩 | packed 4×f32 / 2×f64, or the scalar low lane with the upper lane preserved |
| HADDPS (F2 0F 7C), HADDPD (66 0F 7C), HSUBPS (F2 0F 7D), HSUBPD (66 0F 7D) | 🟩 | adjacent-lane horizontal add/sub, source lanes then destination lanes (SSE3) |
| DPPS (66 0F 3A 40 ib), DPPD (66 0F 3A 41 ib) | 🟩 | imm8[3:0] selects the source lanes, imm8[7:4] the result lanes (SSE4.1) |
| EXTRACTPS (66 0F 3A 17 ib) | 🟩 | dword imm8[1:0] of the XMM source → r/m32 (SSE4.1) |
| GF2P8MULB (66 0F 38 CF), GF2P8AFFINEQB (66 0F 3A CE ib), GF2P8AFFINEINVQB (66 0F 3A CF ib) | 🟩 | GF(2^8) byte multiply / affine transform over the AES polynomial 0x11B |
| AESENC (66 0F 38 DC), AESENCLAST (DD), AESDEC (DE), AESDECLAST (DF) | 🟩 | ShiftRows/SubBytes/MixColumns/XOR and inverse equivalents, per FIPS-197 |
| AESIMC (66 0F 38 DB), AESKEYGENASSIST (66 0F 3A DF /r ib) | 🟩 | InvMixColumns; SubWord/RotWord/Rcon key-schedule assist |
| ANDPS (NP 0F 54), ANDPD (66 0F 54), ANDNPS (0F 55), ANDNPD (66 0F 55) | 🟩 | bitwise AND / AND-NOT, 128-bit, legacy two-operand form |
| BLENDPS (66 0F 3A 0C ib), BLENDPD (0D ib) | 🟩 | per-lane imm8 mask selects the source lane |
| BLENDVPS (66 0F 38 16), BLENDVPD (15) | 🟩 | mask from implicit XMM0, per-lane MSB |
| AESENC128KL (F3 0F 38 DC), AESDEC128KL (DD), AESENC256KL (DE), AESDEC256KL (DF) | 🟩 | full 10/14-round AES on one block; memory key handle, ZF=handle violation |
| AESENCWIDE128KL (F3 0F 38 D8), AESDECWIDE128KL (D9), AESENCWIDE256KL (DA), AESDECWIDE256KL (DB) | 🟩 | same handles, XMM0–XMM7 implicit, ModRM.reg must be 000 |
| MULPS (0F 59) and the rest of SSE1–4.2 | ⬛ | |

Everything else still ⬛ per family:

| Family | Representative mnemonics | Status |
|---|---|---|
| SSE1 FP | SUBSS/SUBPS, MULSS/MULPS, SQRTSS/SQRTPS, RCPSS/RCPPS, RSSPSS/RSQRTPS, MINSS/MINPS, MAXSS/MAXPS, UCOMISS, LDMXCSR/STMXCSR, MASKMOVQ, PSHUFW, SYNC | ⬛ (ADDPS/ADDSS 🟩, SUBPS/SUBSS 🟩, DIVPS/DIVSS 🟩, ADDSUBPS 🟩, CMPSS/CMPPS 🟩, COMISS 🟩, CVTSI2SS/CVTSS2SI/CVTTSS2SI/CVTPS2DQ/CVTDQ2PS/CVTPS2PD 🟩, HADDPS/HSUBPS 🟩) |
| SSE2 int128 | PAND/PANDN/POR/PXOR*, PADDB/PADDW/PADDD/PADDQ, PSUB*, PSLLQ/PSRLQ/PSLLD/PSRLD, PMULUDQ/PADDQ, MOVQ2DQ, MOVDQ2Q, PAUSE-along top CMPPD, UNPCK* | ⬛ except `PXOR/PUNPCK*` 🟩 and `PADDD`-level simple arithmetic stub testcases |
| SSE2 FP | MOVSD/MOVSS, MAXSD/MINSD, UCOMISD, SQRTSD, CVTPD2PS/CVTPD2DQ | ⬛ (ADDPD/ADDSD 🟩, SUBPD/SUBSD 🟩, DIVPD/DIVSD 🟩, ADDSUBPD 🟩, CMPPD/COMISD 🟩, CVTSD2SI/CVTTSD2SI/CVTSD2SS/CVTPS2DQ/CVTTPD2DQ/CVTDQ2PD 🟩, HADDPD/HSUBPD 🟩) |
| AES-NI / Key Locker | AESENC, AESENCLAST, AESDEC, AESDECLAST, AESIMC, AESKEYGENASSIST, AES{ENC,DEC}{128,256}KL, AES{ENC,DEC}WIDE{128,256}KL | 🟩 (NINE software key handle — see §2.14) |
| SSE3/SSSE3 | MOVSHDUP/MOVSLDUP/MOVDDUP (F2 0F 16/12 etc), PHADD*, PSHUFB, PALIGNR, PSHUFLW | ⬛ (HADDPS/HADDPD/HSUBPS/HSUBPD 🟩, FISTTP 🟩) |
| SSE4.1/4.2 | PMULLD, PBLEND*, PMULUDQ*, PEXTRD/PINSRD, PTEST, PCMPEQQ, PHMINPOSUW, ROUNDSS/ROUNDSD/ROUNDPS | ⬛ except CRC32, DPPS/DPPD, EXTRACTPS 🟩 |
| AVX (VEX) | VEX.128/256 — VADDPS, VPXOR, VMOVAPS, VBROADCAST, VPERM*, VFMADD*, VGATHER… | 🟩 §2.21 |
| AVX2 | VPBROADCAST*, VPGATHERDD, VPMASKMOV, VPBLENDD, VPINSR/VPEXTR, 256-bit integer | 🟩 §2.21 |
| AVX-512 (EVEX) | zmm/k registers, writemasks, zeroing, broadcast, disp8×N, 453-row table | 🟩 §2.21 (no SAE/ER exceptions) |
| SGX | ENCLS/ENCLU/ENCLV leaves with a software EPCM and SECS model | 🟩 §2.22 (privileged leaves gated) |
| Prefetch | PREFETCHT0/T1/T2/NTA, CLWDEM, MOVDIR64B | ⬛ |
| PAUSE (F3 90) | treated as NOP (96-byte spin path) | 🟨 |

### 2.10.1 FP compare / convert / CRC batch (CMC … CVTTPD2DQ)

| Instruction | Encoding | Status |
|---|---|---|
| CMPPS / CMPPD | NP 0F C2 /r ib, 66 0F C2 /r ib | 🟩 4×f32 / 2×f64 lanes, imm8[2:0] predicate |
| CMPSS / CMPSD (scalar) | F3 0F C2 /r ib, F2 0F C2 /r ib | 🟩 low lane only, upper lanes untouched |
| COMISS / COMISD | NP / 66 0F 2F /r | 🟩 ZF/PF/CF, unordered = all three |
| CVTDQ2PD / CVTDQ2PS | F3 0F E6 /r, NP 0F 5B /r | 🟩 |
| CVTPS2DQ / CVTTPD2DQ | 66 0F 5B /r, 66 0F E6 /r | 🟩 rounded / truncated, CF on integer-indefinite |
| CVTPS2PD / CVTSD2SS / CVTSS2SD | 0F 5A by prefix | 🟩 upper lanes preserved (legacy SSE) |
| CVTSD2SI / CVTSS2SI | F2 / F3 0F 2D /r | 🟩 32- or 64-bit destination by REX.W |
| CVTSI2SD / CVTSI2SS | F2 / F3 0F 2A /r | 🟩 r/m32 or r/m64 source |
| CMPXCHG8B / CMPXCHG16B | NP / REX.W 0F C7 /1 | 🟩 EDX:EAX / RDX:RAX block compare-exchange |
| CRC32 | F2 0F 38 F0 / F1 /r | 🟩 CRC-32C (reflected 0x82F63B78), seeded from the destination |
| CMPS / CMPSB / CMPSW / CMPSD / CMPSQ | A6 / A7 | 🟩 [RSI]−[RDI], REPE/REPNE, DF respected |
| CPUID | 0F A2 | 🟩 leaves 0, 1, 7, 80000000H, 80000001H |

Decisions worth knowing:

* **CPUID is synthesized, never forwarded from the host.** Leaf 1 advertises the
  integer/SSE2 baseline only (FPU, CMOV, CX8, FXSR, SSE, SSE2, CLFSH…); ECX is 0
  and leaf 7 is all-zeroes, so a guest never picks SSE3/SSSE3/SSE4/AVX paths
  NINE cannot execute. `80000001H` reports SYSCALL/NX/LM. The values are
  constants, so a guest sees the same CPU on every device.
* **Rounding** is round-to-nearest-even, x86's MXCSR default. MXCSR is not
  modelled (LDMXCSR/STMXCSR are still ⬛), so a guest that changes RC is not
  honoured yet. Out-of-range/NaN conversions return the integer-indefinite
  pattern (0x8000…) and set CF, as hardware does.
* **CMP predicates** implement imm8[2:0] — EQ/LT/LE/UNORD/NEQ/NLT/NLE/ORD.
  Signalling vs quiet (#IA) is not differentiated because NINE models no FP
  exception delivery; the lane mask (all ones or all zeroes) is exact.
* **CMPXCHG8B/16B** treat the update as atomic for the guest; the 16-byte form
  raises #GP on a non-16-byte-aligned address and a `mod=3` encoding is #UD.
* **CMPS** compares the DS:RSI element with the ES:RDI element, honours DF, and
  ends a REPE run on the first mismatch / a REPNE run on the first match.
* **Privileged forms** do not pretend to change kernel state: CLTS raises #GP(0),
  CLUI and CLRSSBSY raise #UD because CR4.UINTR and CR4.CET are clear in the
  CPU model the guest runs on (CPL 3).
* **MMX conversions** (CVTPI2PD/CVTPI2PS/CVTPS2PI) decode to `MMX_OP` so the
  instruction stream stays aligned, then refuse at execute time with a message
  naming the instruction: NINE models no MMX/x87 register file.
* **Emitter interaction:** `Translator` now sets `TranslationUnit::unsupported`
  when any instruction of a block falls through to the nop placeholder, and
  `ExecutionLoop::ensureTranslated` refuses to install such a block (and stops
  re-translating its PC). Blocks with new instructions therefore run in the
  interpreter instead of executing as silent nops.

### 2.10.2 x87 + integer/SSE batch (CVTTPS2PI … HSUBPS)

| Instruction | Encoding | Status |
|---|---|---|
| CVTTSS2SI / CVTTSD2SI | F3 / F2 0F 2C /r | 🟩 truncating; r32 or r64 by REX.W, integer-indefinite + CF out of range |
| CVTTPS2PI / CVTTPD2PI | NP / 66 0F 2C /r | 🟨 decode only — MMX destination (`MMX_OP` refusal) |
| CWD / CWDE | 66 99 / 98 | 🟩 16/32-bit halves of the CDQ/CQO family |
| DAA / DAS | 27 / 2F | 🟩 legacy BCD adjust (invalid in 64-bit mode, executed anyway — see AAA/AAS) |
| DEC / DIV | FE/FF /1, F6/F7 /6 | 🟩 (pre-existing; audited alongside the div batch) |
| DIVPS / DIVPD / DIVSS / DIVSD | NP / 66 / F3 / F2 0F 5E /r | 🟩 |
| DPPS / DPPD | 66 0F 3A 40 / 41 /r ib | 🟩 |
| EMMS | 0F 77 | 🟩 empties the whole tag word |
| ENCODEKEY128 / ENCODEKEY256 | F3 0F 38 FA / FB /r | 🟩 #UD — CR4.KL is clear in the CPU model |
| ENDBR32 / ENDBR64 | F3 0F 1E FB / FA | 🟩 architectural no-op at CPL 3 |
| ENQCMD / ENQCMDS | F2 / F3 0F 38 F8 /r | 🟩 #UD — CR4.ENQCMD is clear |
| ENTER | C8 iw ib | 🟩 full nesting-level frame chain (level & 31) |
| EXTRACTPS | 66 0F 3A 17 /r ib | 🟩 |
| GF2P8MULB / GF2P8AFFINEQB / GF2P8AFFINEINVQB | 66 0F 38 CF, 66 0F 3A CE/CF ib | 🟩 |
| HADDPD / HADDPS / HSUBPD / HSUBPS | 66 / F2 0F 7C and 7D /r | 🟩 |
| HLT | F4 | 🟩 stops the guest with `InterpExit::HALT` (a CPL-3 #GP would just kill the run) |
| HRESET | F3 0F 3A F0 C0 ib | 🟩 #GP(0) — needs CR4.HRESET at CPL 0 |
| *x87 family* | D8–DF | 🟩 see §2.9 |

Not implementable as requested:

* `CVTDQ2PI` and `CVTDQ2DQ` do not exist — felixcloutier.com/x86 has no such
  entries and there is no packed integer→integer convert in the ISA.
* `CVTPI2PD`, `CVTPI2PS`, `CVTPS2PI` and `CVTTPS2PI` read/write **MMX**
  registers; NINE models no MMX register file, so they decode to `MMX_OP` and
  refuse at execute time with the instruction name in the message.
* `FXSTOR` is not an x86 mnemonic; FXSAVE's counterpart **FXRSTOR** (0F AE /1)
  is implemented here.
* `FSAVE`/`FSTCW`/`FSTENV`/`FSTSW`/`FCLEX`/`FINIT` are assembler spellings that
  emit `9B` + the `FNxxx` form; 9B decodes as `fwait` (a no-op) and the FN form
  does the work.

### 2.11 Segment / system / privileged

| Instruction | Status |
|---|---|
| Architecture-aware prefixes for endbr64 (F3 0F 1E FA) | 🟩 |
| CPUID (0F A2) — deterministic synthesized leaf set, see §2.10.1 | 🟩 |
| CLTS (0F 06) | 🟩 — privileged: #GP(0) at the guest's CPL 3, never a silent CR0 write |
| CLUI (F3 0F 01 EE), CLRSSBSY (F3 0F AE /6) | 🟩 — #UD because CR4.UINTR / CR4.CET are clear in the CPU model |
| CMC (F5) | 🟩 |
| RDTSC (0F 31), RDTSCP (0F 01 F9) | ⬛ |
| RDMSR/WRMSR, SYSENTER/SYSEXIT, RDPID/RDPMC | ⬛ |
| SYSCALL (0F 05) | 🟩 (routes into SyscallTranslator) |
| SYSRET | ⬛ (kernel-only) |
| SGDT/SIDT/VERR/VERW | ⬛ |
| LSL (0F 03), LGDT/LIDT (0F 01 /2,/3), LLDT/LTR (0F 00 /2,/3), LMSW (0F 01 /6) | 🟩 — LSL synthesises the flat-mode limit; the descriptor/status loads raise #GP(0) at CPL 3 (§2.17) |
| LAR (0F 02) | 🟩 — rights of the canonical long-mode selectors; ZF=0 otherwise (§2.16) |
| INT3 (CC) | 🟩 (breakpoint trap → SEH INT3 path) |
| INT n (CD ib), INT1 (F1), INTO (CE, compat) | 🟩 — #GP(0): NINE models no IDT, so no gate is reachable at CPL 3 |
| IRET / IRETD / IRETQ (CF) | 🟩 — #GP(0): there is never an interrupt frame to pop |
| INVD (0F 08), INVLPG (0F 01 /7), INVPCID (66 0F 38 82) | 🟩 — #GP(0) at CPL 3 |
| INCSSPD / INCSSPQ (F3 0F AE /5) | 🟩 — #UD: CR4.CET is clear in the CPU model |
| LDTILECFG (VEX.128.NP.0F38 49 /0) | 🟩 — #UD: AMX is not part of the CPU model |
| MONITOR/MWAIT | 🟩 — #GP(0) at CPL 3 (§2.17) |
| CLFLUSH/CLFLUSHOPT/CLWB | 🟩 — ordering hints, retired as no-ops |
| SFENCE/MFENCE/LFENCE | 🟩 — ordered no-ops: one guest CPU, every store already visible (§2.17) |
| XSAVE/XRSTOR/XSETBV/XGETBV | ⬛ |
| STC/CLC/CMC/STD/CLD, LAHF, SAHF/PUSHF/POPF | 🟨 (STC/CLC/CMC/STD/CLD and LAHF 🟩; SAHF/PUSHF/POPF still refuse) |
| IN (E4/E5/EC/ED), INS (6C/6D) | 🟩 — #GP(0): IOPL is 0 at CPL 3 |
| OUT/OUTS (E6/E7/EE/EF, 6E/6F) | 🟩 — #GP(0), same IOPL gate as IN (§2.17) |
| CLI/STI | 🟨 (toggle IF only; NINE delivers no interrupts) |

### 2.12 Known decode quality fixes discovered through the loop

| Fix | Why |
|---|---|
| ALU-eAX区块 needed `opc&7 ∈ {4,5}` | first patch only matched imm32 form; imm8 (04/etc) got swallowed |
| SIB index=4 without REX.X | Nones (`lea rcx,[rax*8]` etc) |
| Real 0x19 ED SBB r13d,r13d carry in | `-CF` idiom everywhere in glibc |
| 0x66 prefix 全 o16 record + disp32 abs32 fix (SIB base=5) | disp was skipped → instruction length wrong |
| String ops honoring o16 (66 A4 = MOVSW) | glibc init uses 16-bit string ops |
| %gs:/%fs: basis bases into TS mem ops | PIC glibc uses %fs:0x28 / %gs:memory+off heavily |
| `B0-B7` (MOV r8, imm8) was missing entirely | the chain only handled `B8-BF`; `mov al,imm` / `mov ah,imm` decoded as one-byte `invalid` and desynchronised the stream (`0xB4 0x56` then read `0x56` as `push rsi`) |
| AH/CH/DH/BH (`high8`) dropped by the AOT emitter | `mov ah,1` wrote the low byte, silently corrupting the GPR; interpreter already honoured it, AOT now loads bits 15:8 and writes them back with the low byte and upper 48 bits preserved |

---

### 2.13 Complete x86-64 instruction inventory (felixcloutier.com/x86)

Every instruction in the December 2023 Intel SDM index as published at
[felixcloutier.com/x86](https://www.felixcloutier.com/x86/) — 1208 entries, including the
ones NINE implements and the ones it does not. Rows are in site (alphabetical) order.
The per-family tables above (§2.2–§2.11) explain *how* the green rows are implemented;
this table is the exhaustive ledger the demand-driven loop draws from.

Status: 🟩 implemented (decode + execute) · 🟨 partial/sample/decoded-as-NOP · ⬛ not implemented (decode refuses or never dispatched).

| Mnemonic | Summary | NINE |
|---|---|---|
| `AAA` | ASCII Adjust After Addition | 🟩 |
| `AAD` | ASCII Adjust AX Before Division | 🟩 |
| `AAM` | ASCII Adjust AX After Multiply | 🟩 |
| `AAS` | ASCII Adjust AL After Subtraction | 🟩 |
| `ADC` | Add With Carry | 🟩 |
| `ADCX` | Unsigned Integer Addition of Two Operands With Carry Flag | 🟩 |
| `ADD` | Add | 🟩 |
| `ADDPD` | Add Packed Double Precision Floating-Point Values | 🟩 |
| `ADDPS` | Add Packed Single Precision Floating-Point Values | 🟩 |
| `ADDSD` | Add Scalar Double Precision Floating-Point Values | 🟩 |
| `ADDSS` | Add Scalar Single Precision Floating-Point Values | 🟩 |
| `ADDSUBPD` | Packed Double Precision Floating-Point Add/Subtract | 🟩 |
| `ADDSUBPS` | Packed Single Precision Floating-Point Add/Subtract | 🟩 |
| `ADOX` | Unsigned Integer Addition of Two Operands With Overflow Flag | 🟩 |
| `AESDEC` | Perform One Round of an AES Decryption Flow | 🟩 |
| `AESDEC128KL` | Perform Ten Rounds of AES Decryption Flow With Key Locker Using 128-BitKey | 🟩 |
| `AESDEC256KL` | Perform 14 Rounds of AES Decryption Flow With Key Locker Using 256-Bit Key | 🟩 |
| `AESDECLAST` | Perform Last Round of an AES Decryption Flow | 🟩 |
| `AESDECWIDE128KL` | Perform Ten Rounds of AES Decryption Flow With Key Locker on 8 BlocksUsing 128-Bit Key | 🟩 |
| `AESDECWIDE256KL` | Perform 14 Rounds of AES Decryption Flow With Key Locker on 8 BlocksUsing 256-Bit Key | 🟩 |
| `AESENC` | Perform One Round of an AES Encryption Flow | 🟩 |
| `AESENC128KL` | Perform Ten Rounds of AES Encryption Flow With Key Locker Using 128-Bit Key | 🟩 |
| `AESENC256KL` | Perform 14 Rounds of AES Encryption Flow With Key Locker Using 256-Bit Key | 🟩 |
| `AESENCLAST` | Perform Last Round of an AES Encryption Flow | 🟩 |
| `AESENCWIDE128KL` | Perform Ten Rounds of AES Encryption Flow With Key Locker on 8 BlocksUsing 128-Bit Key | 🟩 |
| `AESENCWIDE256KL` | Perform 14 Rounds of AES Encryption Flow With Key Locker on 8 BlocksUsing 256-Bit Key | 🟩 |
| `AESIMC` | Perform the AES InvMixColumn Transformation | 🟩 |
| `AESKEYGENASSIST` | AES Round Key Generation Assist | 🟩 |
| `AND` | Logical AND | 🟩 |
| `ANDN` | Logical AND NOT | 🟩 |
| `ANDNPD` | Bitwise Logical AND NOT of Packed Double Precision Floating-Point Values | 🟩 |
| `ANDNPS` | Bitwise Logical AND NOT of Packed Single Precision Floating-Point Values | 🟩 |
| `ANDPD` | Bitwise Logical AND of Packed Double Precision Floating-Point Values | 🟩 |
| `ANDPS` | Bitwise Logical AND of Packed Single Precision Floating-Point Values | 🟩 |
| `ARPL` | Adjust RPL Field of Segment Selector | 🟨 |
| `BEXTR` | Bit Field Extract | 🟩 |
| `BLENDPD` | Blend Packed Double Precision Floating-Point Values | 🟩 |
| `BLENDPS` | Blend Packed Single Precision Floating-Point Values | 🟩 |
| `BLENDVPD` | Variable Blend Packed Double Precision Floating-Point Values | 🟩 |
| `BLENDVPS` | Variable Blend Packed Single Precision Floating-Point Values | 🟩 |
| `BLSI` | Extract Lowest Set Isolated Bit | 🟩 |
| `BLSMSK` | Get Mask Up to Lowest Set Bit | 🟩 |
| `BLSR` | Reset Lowest Set Bit | 🟩 |
| `BNDCL` | Check Lower Bound | 🟩 |
| `BNDCN` | Check Upper Bound | 🟩 |
| `BNDCU` | Check Upper Bound | 🟩 |
| `BNDLDX` | Load Extended Bounds Using Address Translation | 🟨 |
| `BNDMK` | Make Bounds | 🟩 |
| `BNDMOV` | Move Bounds | 🟩 |
| `BNDSTX` | Store Extended Bounds Using Address Translation | 🟨 |
| `BOUND` | Check Array Index Against Bounds | 🟨 |
| `BSF` | Bit Scan Forward | 🟩 |
| `BSR` | Bit Scan Reverse | 🟩 |
| `BSWAP` | Byte Swap | 🟩 |
| `BT` | Bit Test | 🟩 |
| `BTC` | Bit Test and Complement | 🟩 |
| `BTR` | Bit Test and Reset | 🟩 |
| `BTS` | Bit Test and Set | 🟩 |
| `BZHI` | Zero High Bits Starting with Specified Bit Position | 🟩 |
| `CALL` | Call Procedure | 🟩 |
| `CBW` | Convert Byte to Word/Convert Word to Doubleword/Convert Doubleword toQuadword | 🟩 |
| `CDQ` | Convert Word to Doubleword/Convert Doubleword to Quadword | 🟩 |
| `CDQE` | Convert Byte to Word/Convert Word to Doubleword/Convert Doubleword toQuadword | 🟩 |
| `CLAC` | Clear AC Flag in EFLAGS Register | 🟩 |
| `CLC` | Clear Carry Flag | 🟩 |
| `CLD` | Clear Direction Flag | 🟩 |
| `CLDEMOTE` | Cache Line Demote | 🟩 |
| `CLFLUSH` | Flush Cache Line | 🟩 |
| `CLFLUSHOPT` | Flush Cache Line Optimized | 🟩 |
| `CLI` | Clear Interrupt Flag | 🟩 |
| `CLRSSBSY` | Clear Busy Flag in a Supervisor Shadow Stack Token | 🟩 |
| `CLTS` | Clear Task-Switched Flag in CR0 | 🟩 |
| `CLUI` | Clear User Interrupt Flag | 🟩 |
| `CLWB` | Cache Line Write Back | 🟩 |
| `CMC` | Complement Carry Flag | 🟩 |
| `CMOVcc` | Conditional Move | 🟩 |
| `CMP` | Compare Two Operands | 🟩 |
| `CMPPD` | Compare Packed Double Precision Floating-Point Values | 🟩 |
| `CMPPS` | Compare Packed Single Precision Floating-Point Values | 🟩 |
| `CMPS` | Compare String Operands | 🟩 |
| `CMPSB` | Compare String Operands | 🟩 |
| `CMPSD` | Compare String Operands | 🟩 |
| `CMPSQ` | Compare String Operands | 🟩 |
| `CMPSS` | Compare Scalar Single Precision Floating-Point Value | 🟩 |
| `CMPSW` | Compare String Operands | 🟩 |
| `CMPXCHG` | Compare and Exchange | 🟩 |
| `CMPXCHG16B` | Compare and Exchange Bytes | 🟩 |
| `CMPXCHG8B` | Compare and Exchange Bytes | 🟩 |
| `COMISD` | Compare Scalar Ordered Double Precision Floating-Point Values and Set EFLAGS | 🟩 |
| `COMISS` | Compare Scalar Ordered Single Precision Floating-Point Values and Set EFLAGS | 🟩 |
| `CPUID` | CPU Identification | 🟩 |
| `CQO` | Convert Word to Doubleword/Convert Doubleword to Quadword | 🟩 |
| `CRC32` | Accumulate CRC32 Value | 🟩 |
| `CVTDQ2PD` | Convert Packed Doubleword Integers to Packed Double Precision Floating-PointValues | 🟩 |
| `CVTDQ2PS` | Convert Packed Doubleword Integers to Packed Single Precision Floating-PointValues | 🟩 |
| `CVTPD2DQ` | Convert Packed Double Precision Floating-Point Values to Packed DoublewordIntegers | ⬛ |
| `CVTPD2PI` | Convert Packed Double Precision Floating-Point Values to Packed Dword Integers | ⬛ |
| `CVTPD2PS` | Convert Packed Double Precision Floating-Point Values to Packed Single PrecisionFloating-Point Values | ⬛ |
| `CVTPI2PD` | Convert Packed Dword Integers to Packed Double Precision Floating-Point Values | 🟨 (no MMX state) |
| `CVTPI2PS` | Convert Packed Dword Integers to Packed Single Precision Floating-Point Values | 🟨 (no MMX state) |
| `CVTPS2DQ` | Convert Packed Single Precision Floating-Point Values to Packed SignedDoubleword Integer Values | 🟩 |
| `CVTPS2PD` | Convert Packed Single Precision Floating-Point Values to Packed Double PrecisionFloating-Point Values | 🟩 |
| `CVTPS2PI` | Convert Packed Single Precision Floating-Point Values to Packed Dword Integers | 🟨 (no MMX state) |
| `CVTSD2SI` | Convert Scalar Double Precision Floating-Point Value to Doubleword Integer | 🟩 |
| `CVTSD2SS` | Convert Scalar Double Precision Floating-Point Value to Scalar Single PrecisionFloating-Point Value | 🟩 |
| `CVTSI2SD` | Convert Doubleword Integer to Scalar Double Precision Floating-Point Value | 🟩 |
| `CVTSI2SS` | Convert Doubleword Integer to Scalar Single Precision Floating-Point Value | 🟩 |
| `CVTSS2SD` | Convert Scalar Single Precision Floating-Point Value to Scalar Double PrecisionFloating-Point Value | 🟩 |
| `CVTSS2SI` | Convert Scalar Single Precision Floating-Point Value to Doubleword Integer | 🟩 |
| `CVTTPD2DQ` | Convert with Truncation Packed Double Precision Floating-Point Values toPacked Doubleword Integers | 🟩 |
| `CVTTPD2PI` | Convert With Truncation Packed Double Precision Floating-Point Values to PackedDword Integers | ⬛ |
| `CVTTPS2DQ` | Convert With Truncation Packed Single Precision Floating-Point Values to PackedSigned Doubleword Integer Values | ⬛ |
| `CVTTPS2PI` | Convert With Truncation Packed Single Precision Floating-Point Values to PackedDword Integers | 🟨 |
| `CVTTSD2SI` | Convert With Truncation Scalar Double Precision Floating-Point Value to SignedInteger | 🟩 |
| `CVTTSS2SI` | Convert With Truncation Scalar Single Precision Floating-Point Value to Integer | 🟩 |
| `CWD` | Convert Word to Doubleword/Convert Doubleword to Quadword | 🟩 |
| `CWDE` | Convert Byte to Word/Convert Word to Doubleword/Convert Doubleword toQuadword | 🟩 |
| `DAA` | Decimal Adjust AL After Addition | 🟩 |
| `DAS` | Decimal Adjust AL After Subtraction | 🟩 |
| `DEC` | Decrement by 1 | 🟩 |
| `DIV` | Unsigned Divide | 🟩 |
| `DIVPD` | Divide Packed Double Precision Floating-Point Values | 🟩 |
| `DIVPS` | Divide Packed Single Precision Floating-Point Values | 🟩 |
| `DIVSD` | Divide Scalar Double Precision Floating-Point Value | 🟩 |
| `DIVSS` | Divide Scalar Single Precision Floating-Point Values | 🟩 |
| `DPPD` | Dot Product of Packed Double Precision Floating-Point Values | 🟩 |
| `DPPS` | Dot Product of Packed Single Precision Floating-Point Values | 🟩 |
| `EMMS` | Empty MMX Technology State | 🟩 |
| `ENCODEKEY128` | Encode 128-Bit Key With Key Locker | 🟩 |
| `ENCODEKEY256` | Encode 256-Bit Key With Key Locker | 🟩 |
| `ENDBR32` | Terminate an Indirect Branch in 32-bit and Compatibility Mode | 🟩 |
| `ENDBR64` | Terminate an Indirect Branch in 64-bit Mode | 🟩 |
| `ENQCMD` | Enqueue Command | 🟩 |
| `ENQCMDS` | Enqueue Command Supervisor | 🟩 |
| `ENTER` | Make Stack Frame for Procedure Parameters | 🟩 |
| `EXTRACTPS` | Extract Packed Floating-Point Values | 🟩 |
| `F2XM1` | Compute 2x–1 | 🟩 |
| `FABS` | Absolute Value | 🟩 |
| `FADD` | Add | 🟩 |
| `FADDP` | Add | 🟩 |
| `FBLD` | Load Binary Coded Decimal | 🟩 |
| `FBSTP` | Store BCD Integer and Pop | 🟩 |
| `FCHS` | Change Sign | 🟩 |
| `FCLEX` | Clear Exceptions | 🟨 |
| `FCMOVcc` | Floating-Point Conditional Move | 🟩 |
| `FCOM` | Compare Floating-Point Values | 🟩 |
| `FCOMI` | Compare Floating-Point Values and Set EFLAGS | 🟩 |
| `FCOMIP` | Compare Floating-Point Values and Set EFLAGS | 🟩 |
| `FCOMP` | Compare Floating-Point Values | 🟩 |
| `FCOMPP` | Compare Floating-Point Values | 🟩 |
| `FCOS` | Cosine | 🟩 |
| `FDECSTP` | Decrement Stack-Top Pointer | 🟩 |
| `FDIV` | Divide | 🟩 |
| `FDIVP` | Divide | 🟩 |
| `FDIVR` | Reverse Divide | 🟩 |
| `FDIVRP` | Reverse Divide | 🟩 |
| `FFREE` | Free Floating-Point Register | 🟩 |
| `FIADD` | Add | 🟩 |
| `FICOM` | Compare Integer | 🟩 |
| `FICOMP` | Compare Integer | 🟩 |
| `FIDIV` | Divide | 🟩 |
| `FIDIVR` | Reverse Divide | 🟩 |
| `FILD` | Load Integer | 🟩 |
| `FIMUL` | Multiply | 🟩 |
| `FINCSTP` | Increment Stack-Top Pointer | 🟩 |
| `FINIT` | Initialize Floating-Point Unit | 🟨 |
| `FIST` | Store Integer | 🟩 |
| `FISTP` | Store Integer | 🟩 |
| `FISTTP` | Store Integer With Truncation | 🟩 |
| `FISUB` | Subtract | 🟩 |
| `FISUBR` | Reverse Subtract | 🟩 |
| `FLD` | Load Floating-Point Value | 🟩 |
| `FLD1` | Load Constant | 🟩 |
| `FLDCW` | Load x87 FPU Control Word | 🟩 |
| `FLDENV` | Load x87 FPU Environment | 🟩 |
| `FLDL2E` | Load Constant | 🟩 |
| `FLDL2T` | Load Constant | 🟩 |
| `FLDLG2` | Load Constant | 🟩 |
| `FLDLN2` | Load Constant | 🟩 |
| `FLDPI` | Load Constant | 🟩 |
| `FLDZ` | Load Constant | 🟩 |
| `FMUL` | Multiply | 🟩 |
| `FMULP` | Multiply | 🟩 |
| `FNCLEX` | Clear Exceptions | 🟩 |
| `FNINIT` | Initialize Floating-Point Unit | 🟩 |
| `FNOP` | No Operation | 🟩 |
| `FNSAVE` | Store x87 FPU State | 🟩 |
| `FNSTCW` | Store x87 FPU Control Word | 🟩 |
| `FNSTENV` | Store x87 FPU Environment | 🟩 |
| `FNSTSW` | Store x87 FPU Status Word | 🟩 |
| `FPATAN` | Partial Arctangent | 🟩 |
| `FPREM` | Partial Remainder | 🟩 |
| `FPREM1` | Partial Remainder | 🟩 |
| `FPTAN` | Partial Tangent | 🟩 |
| `FRNDINT` | Round to Integer | 🟩 |
| `FRSTOR` | Restore x87 FPU State | 🟩 |
| `FSAVE` | Store x87 FPU State | 🟨 |
| `FSCALE` | Scale | 🟩 |
| `FSIN` | Sine | 🟩 |
| `FSINCOS` | Sine and Cosine | 🟩 |
| `FSQRT` | Square Root | 🟩 |
| `FST` | Store Floating-Point Value | 🟩 |
| `FSTCW` | Store x87 FPU Control Word | 🟨 |
| `FSTENV` | Store x87 FPU Environment | 🟨 |
| `FSTP` | Store Floating-Point Value | 🟩 |
| `FSTSW` | Store x87 FPU Status Word | 🟨 |
| `FSUB` | Subtract | 🟩 |
| `FSUBP` | Subtract | 🟩 |
| `FSUBR` | Reverse Subtract | 🟩 |
| `FSUBRP` | Reverse Subtract | 🟩 |
| `FTST` | TEST | 🟩 |
| `FUCOM` | Unordered Compare Floating-Point Values | 🟩 |
| `FUCOMI` | Compare Floating-Point Values and Set EFLAGS | 🟩 |
| `FUCOMIP` | Compare Floating-Point Values and Set EFLAGS | 🟩 |
| `FUCOMP` | Unordered Compare Floating-Point Values | 🟩 |
| `FUCOMPP` | Unordered Compare Floating-Point Values | 🟩 |
| `FWAIT` | Wait | 🟩 |
| `FXAM` | Examine Floating-Point | 🟩 |
| `FXCH` | Exchange Register Contents | 🟩 |
| `FXRSTOR` | Restore x87 FPU, MMX, XMM, and MXCSR State | 🟩 |
| `FXSAVE` | Save x87 FPU, MMX Technology, and SSE State | 🟩 |
| `FXTRACT` | Extract Exponent and Significand | 🟩 |
| `FYL2X` | Compute y ∗ log2x | 🟩 |
| `FYL2XP1` | Compute y ∗ log2(x +1) | 🟩 |
| `GF2P8AFFINEINVQB` | Galois Field Affine Transformation Inverse | 🟩 |
| `GF2P8AFFINEQB` | Galois Field Affine Transformation | 🟩 |
| `GF2P8MULB` | Galois Field Multiply Bytes | 🟩 |
| `HADDPD` | Packed Double Precision Floating-Point Horizontal Add | 🟩 |
| `HADDPS` | Packed Single Precision Floating-Point Horizontal Add | 🟩 |
| `HLT` | Halt | 🟩 |
| `HRESET` | History Reset | 🟩 |
| `HSUBPD` | Packed Double Precision Floating-Point Horizontal Subtract | 🟩 |
| `HSUBPS` | Packed Single Precision Floating-Point Horizontal Subtract | 🟩 |
| `IDIV` | Signed Divide | 🟩 |
| `IMUL` | Signed Multiply | 🟩 |
| `IN` | Input From Port | 🟩 |
| `INC` | Increment by 1 | 🟩 |
| `INCSSPD` | Increment Shadow Stack Pointer | 🟩 |
| `INCSSPQ` | Increment Shadow Stack Pointer | 🟩 |
| `INS` | Input from Port to String | 🟩 |
| `INSB` | Input from Port to String | 🟩 |
| `INSD` | Input from Port to String | 🟩 |
| `INSERTPS` | Insert Scalar Single Precision Floating-Point Value | 🟩 |
| `INSW` | Input from Port to String | 🟩 |
| `INT n` | Call to Interrupt Procedure | 🟩 |
| `INT1` | Call to Interrupt Procedure | 🟩 |
| `INT3` | Call to Interrupt Procedure | 🟩 |
| `INTO` | Call to Interrupt Procedure | 🟩 |
| `INVD` | Invalidate Internal Caches | 🟩 |
| `INVLPG` | Invalidate TLB Entries | 🟩 |
| `INVPCID` | Invalidate Process-Context Identifier | 🟩 |
| `IRET` | Interrupt Return | 🟩 |
| `IRETD` | Interrupt Return | 🟩 |
| `IRETQ` | Interrupt Return | 🟩 |
| `JMP` | Jump | 🟩 |
| `Jcc` | Jump if Condition Is Met | 🟩 |
| `KADDB` | ADD Two Masks | 🟩 |
| `KADDD` | ADD Two Masks | 🟩 |
| `KADDQ` | ADD Two Masks | 🟩 |
| `KADDW` | ADD Two Masks | 🟩 |
| `KANDB` | Bitwise Logical AND Masks | 🟩 |
| `KANDD` | Bitwise Logical AND Masks | 🟩 |
| `KANDNB` | Bitwise Logical AND NOT Masks | 🟩 |
| `KANDND` | Bitwise Logical AND NOT Masks | 🟩 |
| `KANDNQ` | Bitwise Logical AND NOT Masks | 🟩 |
| `KANDNW` | Bitwise Logical AND NOT Masks | 🟩 |
| `KANDQ` | Bitwise Logical AND Masks | 🟩 |
| `KANDW` | Bitwise Logical AND Masks | 🟩 |
| `KMOVB` | Move From and to Mask Registers | 🟩 |
| `KMOVD` | Move From and to Mask Registers | 🟩 |
| `KMOVQ` | Move From and to Mask Registers | 🟩 |
| `KMOVW` | Move From and to Mask Registers | 🟩 |
| `KNOTB` | NOT Mask Register | 🟩 |
| `KNOTD` | NOT Mask Register | 🟩 |
| `KNOTQ` | NOT Mask Register | 🟩 |
| `KNOTW` | NOT Mask Register | 🟩 |
| `KORB` | Bitwise Logical OR Masks | 🟩 |
| `KORD` | Bitwise Logical OR Masks | 🟩 |
| `KORQ` | Bitwise Logical OR Masks | 🟩 |
| `KORTESTB` | OR Masks and Set Flags | 🟩 |
| `KORTESTD` | OR Masks and Set Flags | 🟩 |
| `KORTESTQ` | OR Masks and Set Flags | 🟩 |
| `KORTESTW` | OR Masks and Set Flags | 🟩 |
| `KORW` | Bitwise Logical OR Masks | 🟩 |
| `KSHIFTLB` | Shift Left Mask Registers | 🟩 |
| `KSHIFTLD` | Shift Left Mask Registers | 🟩 |
| `KSHIFTLQ` | Shift Left Mask Registers | 🟩 |
| `KSHIFTLW` | Shift Left Mask Registers | 🟩 |
| `KSHIFTRB` | Shift Right Mask Registers | 🟩 |
| `KSHIFTRD` | Shift Right Mask Registers | 🟩 |
| `KSHIFTRQ` | Shift Right Mask Registers | 🟩 |
| `KSHIFTRW` | Shift Right Mask Registers | 🟩 |
| `KTESTB` | Packed Bit Test Masks and Set Flags | 🟩 |
| `KTESTD` | Packed Bit Test Masks and Set Flags | 🟩 |
| `KTESTQ` | Packed Bit Test Masks and Set Flags | 🟩 |
| `KTESTW` | Packed Bit Test Masks and Set Flags | 🟩 |
| `KUNPCKBW` | Unpack for Mask Registers | 🟩 |
| `KUNPCKDQ` | Unpack for Mask Registers | 🟩 |
| `KUNPCKWD` | Unpack for Mask Registers | 🟩 |
| `KXNORB` | Bitwise Logical XNOR Masks | 🟩 |
| `KXNORD` | Bitwise Logical XNOR Masks | 🟩 |
| `KXNORQ` | Bitwise Logical XNOR Masks | 🟩 |
| `KXNORW` | Bitwise Logical XNOR Masks | 🟩 |
| `KXORB` | Bitwise Logical XOR Masks | 🟩 |
| `KXORD` | Bitwise Logical XOR Masks | 🟩 |
| `KXORQ` | Bitwise Logical XOR Masks | 🟩 |
| `KXORW` | Bitwise Logical XOR Masks | 🟩 |
| `LAHF` | Load Status Flags Into AH Register | 🟩 |
| `LAR` | Load Access Rights Byte | 🟩 |
| `LDDQU` | Load Unaligned Integer 128 Bits | 🟩 |
| `LDMXCSR` | Load MXCSR Register | 🟩 |
| `LDS` | Load Far Pointer | 🟨 |
| `LDTILECFG` | Load Tile Configuration | 🟩 |
| `LEA` | Load Effective Address | 🟩 |
| `LEAVE` | High Level Procedure Exit | 🟩 |
| `LES` | Load Far Pointer | 🟨 |
| `LFENCE` | Load Fence | 🟩 |
| `LFS` | Load Far Pointer | 🟩 |
| `LGDT` | Load Global/Interrupt Descriptor Table Register | 🟩 |
| `LGS` | Load Far Pointer | 🟩 |
| `LIDT` | Load Global/Interrupt Descriptor Table Register | 🟩 |
| `LLDT` | Load Local Descriptor Table Register | 🟩 |
| `LMSW` | Load Machine Status Word | 🟩 |
| `LOADIWKEY` | Load Internal Wrapping Key With Key Locker | 🟩 (#GP at CPL 3) |
| `LOCK` | Assert LOCK# Signal Prefix | 🟨 |
| `LODS` | Load String | 🟩 |
| `LODSB` | Load String | 🟩 |
| `LODSD` | Load String | 🟩 |
| `LODSQ` | Load String | 🟩 |
| `LODSW` | Load String | 🟩 |
| `LOOP` | Loop According to ECX Counter | 🟩 |
| `LOOPcc` | Loop According to ECX Counter | ⬛ |
| `LSL` | Load Segment Limit | 🟩 |
| `LSS` | Load Far Pointer | 🟩 |
| `LTR` | Load Task Register | 🟩 |
| `LZCNT` | Count the Number of Leading Zero Bits | 🟩 |
| `MASKMOVDQU` | Store Selected Bytes of Double Quadword | 🟩 |
| `MASKMOVQ` | Store Selected Bytes of Quadword | ⬛ |
| `MAXPD` | Maximum of Packed Double Precision Floating-Point Values | 🟩 |
| `MAXPS` | Maximum of Packed Single Precision Floating-Point Values | 🟩 |
| `MAXSD` | Return Maximum Scalar Double Precision Floating-Point Value | 🟩 |
| `MAXSS` | Return Maximum Scalar Single Precision Floating-Point Value | 🟩 |
| `MFENCE` | Memory Fence | 🟩 |
| `MINPD` | Minimum of Packed Double Precision Floating-Point Values | 🟩 |
| `MINPS` | Minimum of Packed Single Precision Floating-Point Values | 🟩 |
| `MINSD` | Return Minimum Scalar Double Precision Floating-Point Value | 🟩 |
| `MINSS` | Return Minimum Scalar Single Precision Floating-Point Value | 🟩 |
| `MONITOR` | Set Up Monitor Address | 🟩 |
| `MOV` | Move | 🟩 |
| `MOVAPD` | Move Aligned Packed Double Precision Floating-Point Values | 🟩 |
| `MOVAPS` | Move Aligned Packed Single Precision Floating-Point Values | 🟩 |
| `MOVBE` | Move Data After Swapping Bytes | 🟩 |
| `MOVD` | Move Doubleword/Move Quadword | 🟩 |
| `MOVDDUP` | Replicate Double Precision Floating-Point Values | 🟩 |
| `MOVDIR64B` | Move 64 Bytes as Direct Store | 🟩 |
| `MOVDIRI` | Move Doubleword as Direct Store | 🟩 |
| `MOVDQ2Q` | Move Quadword from XMM to MMX Technology Register | 🟨 |
| `MOVDQA` | Move Aligned Packed Integer Values | 🟩 |
| `MOVDQU` | Move Unaligned Packed Integer Values | 🟩 |
| `MOVHLPS` | Move Packed Single Precision Floating-Point Values High to Low | 🟩 |
| `MOVHPD` | Move High Packed Double Precision Floating-Point Value | 🟩 |
| `MOVHPS` | Move High Packed Single Precision Floating-Point Values | 🟩 |
| `MOVLHPS` | Move Packed Single Precision Floating-Point Values Low to High | 🟩 |
| `MOVLPD` | Move Low Packed Double Precision Floating-Point Value | 🟩 |
| `MOVLPS` | Move Low Packed Single Precision Floating-Point Values | 🟩 |
| `MOVMSKPD` | Extract Packed Double Precision Floating-Point Sign Mask | 🟩 |
| `MOVMSKPS` | Extract Packed Single Precision Floating-Point Sign Mask | 🟩 |
| `MOVNTDQ` | Store Packed Integers Using Non-Temporal Hint | 🟩 |
| `MOVNTDQA` | Load Double Quadword Non-Temporal Aligned Hint | 🟩 |
| `MOVNTI` | Store Doubleword Using Non-Temporal Hint | 🟩 |
| `MOVNTPD` | Store Packed Double Precision Floating-Point Values Using Non-Temporal Hint | 🟩 |
| `MOVNTPS` | Store Packed Single Precision Floating-Point Values Using Non-Temporal Hint | 🟩 |
| `MOVNTQ` | Store of Quadword Using Non-Temporal Hint | 🟩 |
| `MOVQ` | Move Doubleword/Move Quadword | 🟩 |
| `MOVQ2DQ` | Move Quadword from MMX Technology to XMM Register | 🟨 |
| `MOVS` | Move Data From String to String | 🟩 |
| `MOVSB` | Move Data From String to String | 🟩 |
| `MOVSD` | Move Data From String to String | 🟩 |
| `MOVSHDUP` | Replicate Single Precision Floating-Point Values | 🟩 |
| `MOVSLDUP` | Replicate Single Precision Floating-Point Values | 🟩 |
| `MOVSQ` | Move Data From String to String | 🟩 |
| `MOVSS` | Move or Merge Scalar Single Precision Floating-Point Value | 🟩 |
| `MOVSW` | Move Data From String to String | 🟩 |
| `MOVSX` | Move With Sign-Extension | 🟩 |
| `MOVSXD` | Move With Sign-Extension | 🟩 |
| `MOVUPD` | Move Unaligned Packed Double Precision Floating-Point Values | 🟩 |
| `MOVUPS` | Move Unaligned Packed Single Precision Floating-Point Values | 🟩 |
| `MOVZX` | Move With Zero-Extend | 🟩 |
| `MPSADBW` | Compute Multiple Packed Sums of Absolute Difference | 🟩 |
| `MUL` | Unsigned Multiply | 🟩 |
| `MULPD` | Multiply Packed Double Precision Floating-Point Values | 🟩 |
| `MULPS` | Multiply Packed Single Precision Floating-Point Values | 🟩 |
| `MULSD` | Multiply Scalar Double Precision Floating-Point Value | 🟩 |
| `MULSS` | Multiply Scalar Single Precision Floating-Point Values | 🟩 |
| `MULX` | Unsigned Multiply Without Affecting Flags | 🟩 |
| `MWAIT` | Monitor Wait | 🟩 |
| `NEG` | Two's Complement Negation | 🟩 |
| `NOP` | No Operation | 🟩 |
| `NOT` | One's Complement Negation | 🟩 |
| `OR` | Logical Inclusive OR | 🟩 |
| `ORPD` | Bitwise Logical OR of Packed Double Precision Floating-Point Values | 🟩 |
| `ORPS` | Bitwise Logical OR of Packed Single Precision Floating-Point Values | 🟩 |
| `OUT` | Output to Port | 🟩 |
| `OUTS` | Output String to Port | 🟩 |
| `OUTSB` | Output String to Port | 🟩 |
| `OUTSD` | Output String to Port | 🟩 |
| `OUTSW` | Output String to Port | 🟩 |
| `PABSB` | Packed Absolute Value | 🟩 |
| `PABSD` | Packed Absolute Value | 🟩 |
| `PABSQ` | Packed Absolute Value | 🟩 |
| `PABSW` | Packed Absolute Value | 🟩 |
| `PACKSSDW` | Pack With Signed Saturation | 🟩 |
| `PACKSSWB` | Pack With Signed Saturation | 🟩 |
| `PACKUSDW` | Pack With Unsigned Saturation | 🟩 |
| `PACKUSWB` | Pack With Unsigned Saturation | 🟩 |
| `PADDB` | Add Packed Integers | 🟩 |
| `PADDD` | Add Packed Integers | 🟩 |
| `PADDQ` | Add Packed Integers | 🟩 |
| `PADDSB` | Add Packed Signed Integers with Signed Saturation | 🟩 |
| `PADDSW` | Add Packed Signed Integers with Signed Saturation | 🟩 |
| `PADDUSB` | Add Packed Unsigned Integers With Unsigned Saturation | 🟩 |
| `PADDUSW` | Add Packed Unsigned Integers With Unsigned Saturation | 🟩 |
| `PADDW` | Add Packed Integers | 🟩 |
| `PALIGNR` | Packed Align Right | 🟩 |
| `PAND` | Logical AND | 🟩 |
| `PANDN` | Logical AND NOT | 🟩 |
| `PAUSE` | Spin Loop Hint | 🟩 |
| `PAVGB` | Average Packed Integers | 🟩 |
| `PAVGW` | Average Packed Integers | 🟩 |
| `PBLENDVB` | Variable Blend Packed Bytes | 🟩 |
| `PBLENDW` | Blend Packed Words | 🟩 |
| `PCLMULQDQ` | Carry-Less Multiplication Quadword | 🟩 |
| `PCMPEQB` | Compare Packed Data for Equal | 🟩 |
| `PCMPEQD` | Compare Packed Data for Equal | 🟩 |
| `PCMPEQQ` | Compare Packed Qword Data for Equal | ⬛ |
| `PCMPEQW` | Compare Packed Data for Equal | 🟩 |
| `PCMPESTRI` | Packed Compare Explicit Length Strings, Return Index | ⬛ |
| `PCMPESTRM` | Packed Compare Explicit Length Strings, Return Mask | ⬛ |
| `PCMPGTB` | Compare Packed Signed Integers for Greater Than | ⬛ |
| `PCMPGTD` | Compare Packed Signed Integers for Greater Than | ⬛ |
| `PCMPGTQ` | Compare Packed Data for Greater Than | ⬛ |
| `PCMPGTW` | Compare Packed Signed Integers for Greater Than | ⬛ |
| `PCMPISTRI` | Packed Compare Implicit Length Strings, Return Index | ⬛ |
| `PCMPISTRM` | Packed Compare Implicit Length Strings, Return Mask | ⬛ |
| `PCONFIG` | Platform Configuration | ⬛ |
| `PDEP` | Parallel Bits Deposit | ⬛ |
| `PEXT` | Parallel Bits Extract | ⬛ |
| `PEXTRB` | Extract Byte/Dword/Qword | ⬛ |
| `PEXTRD` | Extract Byte/Dword/Qword | ⬛ |
| `PEXTRQ` | Extract Byte/Dword/Qword | ⬛ |
| `PEXTRW` | Extract Word | ⬛ |
| `PHADDD` | Packed Horizontal Add | ⬛ |
| `PHADDSW` | Packed Horizontal Add and Saturate | ⬛ |
| `PHADDW` | Packed Horizontal Add | ⬛ |
| `PHMINPOSUW` | Packed Horizontal Word Minimum | ⬛ |
| `PHSUBD` | Packed Horizontal Subtract | ⬛ |
| `PHSUBSW` | Packed Horizontal Subtract and Saturate | ⬛ |
| `PHSUBW` | Packed Horizontal Subtract | ⬛ |
| `PINSRB` | Insert Byte/Dword/Qword | ⬛ |
| `PINSRD` | Insert Byte/Dword/Qword | ⬛ |
| `PINSRQ` | Insert Byte/Dword/Qword | ⬛ |
| `PINSRW` | Insert Word | ⬛ |
| `PMADDUBSW` | Multiply and Add Packed Signed and Unsigned Bytes | ⬛ |
| `PMADDWD` | Multiply and Add Packed Integers | ⬛ |
| `PMAXSB` | Maximum of Packed Signed Integers | ⬛ |
| `PMAXSD` | Maximum of Packed Signed Integers | ⬛ |
| `PMAXSQ` | Maximum of Packed Signed Integers | ⬛ |
| `PMAXSW` | Maximum of Packed Signed Integers | ⬛ |
| `PMAXUB` | Maximum of Packed Unsigned Integers | ⬛ |
| `PMAXUD` | Maximum of Packed Unsigned Integers | ⬛ |
| `PMAXUQ` | Maximum of Packed Unsigned Integers | ⬛ |
| `PMAXUW` | Maximum of Packed Unsigned Integers | ⬛ |
| `PMINSB` | Minimum of Packed Signed Integers | ⬛ |
| `PMINSD` | Minimum of Packed Signed Integers | ⬛ |
| `PMINSQ` | Minimum of Packed Signed Integers | ⬛ |
| `PMINSW` | Minimum of Packed Signed Integers | ⬛ |
| `PMINUB` | Minimum of Packed Unsigned Integers | ⬛ |
| `PMINUD` | Minimum of Packed Unsigned Integers | ⬛ |
| `PMINUQ` | Minimum of Packed Unsigned Integers | ⬛ |
| `PMINUW` | Minimum of Packed Unsigned Integers | ⬛ |
| `PMOVMSKB` | Move Byte Mask | ⬛ |
| `PMOVSX` | Packed Move With Sign Extend | ⬛ |
| `PMOVZX` | Packed Move With Zero Extend | ⬛ |
| `PMULDQ` | Multiply Packed Doubleword Integers | ⬛ |
| `PMULHRSW` | Packed Multiply High With Round and Scale | ⬛ |
| `PMULHUW` | Multiply Packed Unsigned Integers and Store High Result | ⬛ |
| `PMULHW` | Multiply Packed Signed Integers and Store High Result | ⬛ |
| `PMULLD` | Multiply Packed Integers and Store Low Result | ⬛ |
| `PMULLQ` | Multiply Packed Integers and Store Low Result | ⬛ |
| `PMULLW` | Multiply Packed Signed Integers and Store Low Result | ⬛ |
| `PMULUDQ` | Multiply Packed Unsigned Doubleword Integers | ⬛ |
| `POP` | Pop a Value From the Stack | 🟩 |
| `POPA` | Pop All General-Purpose Registers | ⬛ |
| `POPAD` | Pop All General-Purpose Registers | ⬛ |
| `POPCNT` | Return the Count of Number of Bits Set to 1 | ⬛ |
| `POPF` | Pop Stack Into EFLAGS Register | ⬛ |
| `POPFD` | Pop Stack Into EFLAGS Register | ⬛ |
| `POPFQ` | Pop Stack Into EFLAGS Register | ⬛ |
| `POR` | Bitwise Logical OR | ⬛ |
| `PREFETCHW` | Prefetch Data Into Caches in Anticipation of a Write | ⬛ |
| `PREFETCHh` | Prefetch Data Into Caches | ⬛ |
| `PSADBW` | Compute Sum of Absolute Differences | ⬛ |
| `PSHUFB` | Packed Shuffle Bytes | ⬛ |
| `PSHUFD` | Shuffle Packed Doublewords | ⬛ |
| `PSHUFHW` | Shuffle Packed High Words | ⬛ |
| `PSHUFLW` | Shuffle Packed Low Words | ⬛ |
| `PSHUFW` | Shuffle Packed Words | ⬛ |
| `PSIGNB` | Packed SIGN | ⬛ |
| `PSIGND` | Packed SIGN | ⬛ |
| `PSIGNW` | Packed SIGN | ⬛ |
| `PSLLD` | Shift Packed Data Left Logical | ⬛ |
| `PSLLDQ` | Shift Double Quadword Left Logical | ⬛ |
| `PSLLQ` | Shift Packed Data Left Logical | ⬛ |
| `PSLLW` | Shift Packed Data Left Logical | ⬛ |
| `PSRAD` | Shift Packed Data Right Arithmetic | ⬛ |
| `PSRAQ` | Shift Packed Data Right Arithmetic | ⬛ |
| `PSRAW` | Shift Packed Data Right Arithmetic | ⬛ |
| `PSRLD` | Shift Packed Data Right Logical | ⬛ |
| `PSRLDQ` | Shift Double Quadword Right Logical | ⬛ |
| `PSRLQ` | Shift Packed Data Right Logical | ⬛ |
| `PSRLW` | Shift Packed Data Right Logical | ⬛ |
| `PSUBB` | Subtract Packed Integers | ⬛ |
| `PSUBD` | Subtract Packed Integers | ⬛ |
| `PSUBQ` | Subtract Packed Quadword Integers | ⬛ |
| `PSUBSB` | Subtract Packed Signed Integers With Signed Saturation | ⬛ |
| `PSUBSW` | Subtract Packed Signed Integers With Signed Saturation | ⬛ |
| `PSUBUSB` | Subtract Packed Unsigned Integers With Unsigned Saturation | ⬛ |
| `PSUBUSW` | Subtract Packed Unsigned Integers With Unsigned Saturation | ⬛ |
| `PSUBW` | Subtract Packed Integers | ⬛ |
| `PTEST` | Logical Compare | ⬛ |
| `PTWRITE` | Write Data to a Processor Trace Packet | ⬛ |
| `PUNPCKHBW` | Unpack High Data | ⬛ |
| `PUNPCKHDQ` | Unpack High Data | ⬛ |
| `PUNPCKHQDQ` | Unpack High Data | 🟩 |
| `PUNPCKHWD` | Unpack High Data | ⬛ |
| `PUNPCKLBW` | Unpack Low Data | ⬛ |
| `PUNPCKLDQ` | Unpack Low Data | 🟩 |
| `PUNPCKLQDQ` | Unpack Low Data | 🟩 |
| `PUNPCKLWD` | Unpack Low Data | ⬛ |
| `PUSH` | Push Word, Doubleword, or Quadword Onto the Stack | 🟩 |
| `PUSHA` | Push All General-Purpose Registers | ⬛ |
| `PUSHAD` | Push All General-Purpose Registers | ⬛ |
| `PUSHF` | Push EFLAGS Register Onto the Stack | ⬛ |
| `PUSHFD` | Push EFLAGS Register Onto the Stack | ⬛ |
| `PUSHFQ` | Push EFLAGS Register Onto the Stack | ⬛ |
| `PXOR` | Logical Exclusive OR | 🟩 |
| `RCL` | Rotate | ⬛ |
| `RCPPS` | Compute Reciprocals of Packed Single Precision Floating-Point Values | ⬛ |
| `RCPSS` | Compute Reciprocal of Scalar Single Precision Floating-Point Values | ⬛ |
| `RCR` | Rotate | ⬛ |
| `RDFSBASE` | Read FS/GS Segment Base | ⬛ |
| `RDGSBASE` | Read FS/GS Segment Base | ⬛ |
| `RDMSR` | Read From Model Specific Register | ⬛ |
| `RDPID` | Read Processor ID | ⬛ |
| `RDPKRU` | Read Protection Key Rights for User Pages | ⬛ |
| `RDPMC` | Read Performance-Monitoring Counters | ⬛ |
| `RDRAND` | Read Random Number | ⬛ |
| `RDSEED` | Read Random SEED | ⬛ |
| `RDSSPD` | Read Shadow Stack Pointer | ⬛ |
| `RDSSPQ` | Read Shadow Stack Pointer | ⬛ |
| `RDTSC` | Read Time-Stamp Counter | ⬛ |
| `RDTSCP` | Read Time-Stamp Counter and Processor ID | ⬛ |
| `REP` | Repeat String Operation Prefix | 🟨 |
| `REPE` | Repeat String Operation Prefix | 🟨 |
| `REPNE` | Repeat String Operation Prefix | 🟨 |
| `REPNZ` | Repeat String Operation Prefix | 🟨 |
| `REPZ` | Repeat String Operation Prefix | 🟨 |
| `RET` | Return From Procedure | 🟩 |
| `ROL` | Rotate | 🟩 |
| `ROR` | Rotate | 🟩 |
| `RORX` | Rotate Right Logical Without Affecting Flags | ⬛ |
| `ROUNDPD` | Round Packed Double Precision Floating-Point Values | ⬛ |
| `ROUNDPS` | Round Packed Single Precision Floating-Point Values | ⬛ |
| `ROUNDSD` | Round Scalar Double Precision Floating-Point Values | ⬛ |
| `ROUNDSS` | Round Scalar Single Precision Floating-Point Values | ⬛ |
| `RSM` | Resume From System Management Mode | ⬛ |
| `RSQRTPS` | Compute Reciprocals of Square Roots of Packed Single Precision Floating-PointValues | ⬛ |
| `RSQRTSS` | Compute Reciprocal of Square Root of Scalar Single Precision Floating-Point Value | ⬛ |
| `RSTORSSP` | Restore Saved Shadow Stack Pointer | ⬛ |
| `SAHF` | Store AH Into Flags | ⬛ |
| `SAL` | Shift | 🟩 |
| `SAR` | Shift | 🟩 |
| `SARX` | Shift Without Affecting Flags | ⬛ |
| `SAVEPREVSSP` | Save Previous Shadow Stack Pointer | ⬛ |
| `SBB` | Integer Subtraction With Borrow | 🟩 |
| `SCAS` | Scan String | 🟩 |
| `SCASB` | Scan String | 🟩 |
| `SCASD` | Scan String | 🟩 |
| `SCASW` | Scan String | 🟩 |
| `SENDUIPI` | Send User Interprocessor Interrupt | ⬛ |
| `SERIALIZE` | Serialize Instruction Execution | ⬛ |
| `SETSSBSY` | Mark Shadow Stack Busy | ⬛ |
| `SETcc` | Set Byte on Condition | 🟩 |
| `SFENCE` | Store Fence | ⬛ |
| `SGDT` | Store Global Descriptor Table Register | ⬛ |
| `SHA1MSG1` | Perform an Intermediate Calculation for the Next Four SHA1 Message Dwords | ⬛ |
| `SHA1MSG2` | Perform a Final Calculation for the Next Four SHA1 Message Dwords | ⬛ |
| `SHA1NEXTE` | Calculate SHA1 State Variable E After Four Rounds | ⬛ |
| `SHA1RNDS4` | Perform Four Rounds of SHA1 Operation | ⬛ |
| `SHA256MSG1` | Perform an Intermediate Calculation for the Next Four SHA256 MessageDwords | ⬛ |
| `SHA256MSG2` | Perform a Final Calculation for the Next Four SHA256 Message Dwords | ⬛ |
| `SHA256RNDS2` | Perform Two Rounds of SHA256 Operation | ⬛ |
| `SHL` | Shift | 🟩 |
| `SHLD` | Double Precision Shift Left | ⬛ |
| `SHLX` | Shift Without Affecting Flags | ⬛ |
| `SHR` | Shift | 🟩 |
| `SHRD` | Double Precision Shift Right | ⬛ |
| `SHRX` | Shift Without Affecting Flags | ⬛ |
| `SHUFPD` | Packed Interleave Shuffle of Pairs of Double Precision Floating-Point Values | ⬛ |
| `SHUFPS` | Packed Interleave Shuffle of Quadruplets of Single Precision Floating-Point Values | ⬛ |
| `SIDT` | Store Interrupt Descriptor Table Register | ⬛ |
| `SLDT` | Store Local Descriptor Table Register | ⬛ |
| `SMSW` | Store Machine Status Word | ⬛ |
| `SQRTPD` | Square Root of Double Precision Floating-Point Values | ⬛ |
| `SQRTPS` | Square Root of Single Precision Floating-Point Values | ⬛ |
| `SQRTSD` | Compute Square Root of Scalar Double Precision Floating-Point Value | ⬛ |
| `SQRTSS` | Compute Square Root of Scalar Single Precision Value | ⬛ |
| `STAC` | Set AC Flag in EFLAGS Register | 🟩 |
| `STC` | Set Carry Flag | 🟩 |
| `STD` | Set Direction Flag | 🟩 |
| `STI` | Set Interrupt Flag | 🟩 |
| `STMXCSR` | Store MXCSR Register State | ⬛ |
| `STOS` | Store String | 🟩 |
| `STOSB` | Store String | 🟩 |
| `STOSD` | Store String | 🟩 |
| `STOSQ` | Store String | 🟩 |
| `STOSW` | Store String | 🟩 |
| `STR` | Store Task Register | ⬛ |
| `STTILECFG` | Store Tile Configuration | ⬛ |
| `STUI` | Set User Interrupt Flag | ⬛ |
| `SUB` | Subtract | 🟩 |
| `SUBPD` | Subtract Packed Double Precision Floating-Point Values | ⬛ |
| `SUBPS` | Subtract Packed Single Precision Floating-Point Values | ⬛ |
| `SUBSD` | Subtract Scalar Double Precision Floating-Point Value | ⬛ |
| `SUBSS` | Subtract Scalar Single Precision Floating-Point Value | ⬛ |
| `SWAPGS` | Swap GS Base Register | ⬛ |
| `SYSCALL` | Fast System Call | 🟩 |
| `SYSENTER` | Fast System Call | ⬛ |
| `SYSEXIT` | Fast Return from Fast System Call | ⬛ |
| `SYSRET` | Return From Fast System Call | ⬛ |
| `TDPBF16PS` | Dot Product of BF16 Tiles Accumulated into Packed Single Precision Tile | ⬛ |
| `TDPBSSD` | Dot Product of Signed/Unsigned Bytes with DwordAccumulation | ⬛ |
| `TDPBSUD` | Dot Product of Signed/Unsigned Bytes with DwordAccumulation | ⬛ |
| `TDPBUSD` | Dot Product of Signed/Unsigned Bytes with DwordAccumulation | ⬛ |
| `TDPBUUD` | Dot Product of Signed/Unsigned Bytes with DwordAccumulation | ⬛ |
| `TEST` | Logical Compare | 🟩 |
| `TESTUI` | Determine User Interrupt Flag | ⬛ |
| `TILELOADD` | Load Tile | ⬛ |
| `TILELOADDT1` | Load Tile | ⬛ |
| `TILERELEASE` | Release Tile | ⬛ |
| `TILESTORED` | Store Tile | ⬛ |
| `TILEZERO` | Zero Tile | ⬛ |
| `TPAUSE` | Timed PAUSE | ⬛ |
| `TZCNT` | Count the Number of Trailing Zero Bits | ⬛ |
| `UCOMISD` | Unordered Compare Scalar Double Precision Floating-Point Values and Set EFLAGS | ⬛ |
| `UCOMISS` | Unordered Compare Scalar Single Precision Floating-Point Values and Set EFLAGS | ⬛ |
| `UD` | Undefined Instruction | 🟩 |
| `UIRET` | User-Interrupt Return | ⬛ |
| `UMONITOR` | User Level Set Up Monitor Address | ⬛ |
| `UMWAIT` | User Level Monitor Wait | ⬛ |
| `UNPCKHPD` | Unpack and Interleave High Packed Double Precision Floating-Point Values | ⬛ |
| `UNPCKHPS` | Unpack and Interleave High Packed Single Precision Floating-Point Values | ⬛ |
| `UNPCKLPD` | Unpack and Interleave Low Packed Double Precision Floating-Point Values | ⬛ |
| `UNPCKLPS` | Unpack and Interleave Low Packed Single Precision Floating-Point Values | ⬛ |
| `VADDPH` | Add Packed FP16 Values | ⬛ |
| `VADDSH` | Add Scalar FP16 Values | ⬛ |
| `VALIGND` | Align Doubleword/Quadword Vectors | ⬛ |
| `VALIGNQ` | Align Doubleword/Quadword Vectors | ⬛ |
| `VBLENDMPD` | Blend Float64/Float32 Vectors Using an OpMask Control | ⬛ |
| `VBLENDMPS` | Blend Float64/Float32 Vectors Using an OpMask Control | ⬛ |
| `VBROADCAST` | Load with Broadcast Floating-Point Data | ⬛ |
| `VCMPPH` | Compare Packed FP16 Values | ⬛ |
| `VCMPSH` | Compare Scalar FP16 Values | ⬛ |
| `VCOMISH` | Compare Scalar Ordered FP16 Values and Set EFLAGS | ⬛ |
| `VCOMPRESSPD` | Store Sparse Packed Double Precision Floating-Point Values Into DenseMemory | ⬛ |
| `VCOMPRESSPS` | Store Sparse Packed Single Precision Floating-Point Values Into Dense Memory | ⬛ |
| `VCOMPRESSW` | Store Sparse Packed Byte/Word Integer Values Into DenseMemory/Register | ⬛ |
| `VCVTDQ2PH` | Convert Packed Signed Doubleword Integers to Packed FP16 Values | ⬛ |
| `VCVTNE2PS2BF16` | Convert Two Packed Single Data to One Packed BF16 Data | ⬛ |
| `VCVTNEPS2BF16` | Convert Packed Single Data to Packed BF16 Data | ⬛ |
| `VCVTPD2PH` | Convert Packed Double Precision FP Values to Packed FP16 Values | ⬛ |
| `VCVTPD2QQ` | Convert Packed Double Precision Floating-Point Values to Packed QuadwordIntegers | ⬛ |
| `VCVTPD2UDQ` | Convert Packed Double Precision Floating-Point Values to Packed UnsignedDoubleword Integers | ⬛ |
| `VCVTPD2UQQ` | Convert Packed Double Precision Floating-Point Values to Packed UnsignedQuadword Integers | ⬛ |
| `VCVTPH2DQ` | Convert Packed FP16 Values to Signed Doubleword Integers | ⬛ |
| `VCVTPH2PD` | Convert Packed FP16 Values to FP64 Values | ⬛ |
| `VCVTPH2PS` | Convert Packed FP16 Values to Single Precision Floating-PointValues | ⬛ |
| `VCVTPH2PSX` | Convert Packed FP16 Values to Single Precision Floating-PointValues | ⬛ |
| `VCVTPH2QQ` | Convert Packed FP16 Values to Signed Quadword Integer Values | ⬛ |
| `VCVTPH2UDQ` | Convert Packed FP16 Values to Unsigned Doubleword Integers | ⬛ |
| `VCVTPH2UQQ` | Convert Packed FP16 Values to Unsigned Quadword Integers | ⬛ |
| `VCVTPH2UW` | Convert Packed FP16 Values to Unsigned Word Integers | ⬛ |
| `VCVTPH2W` | Convert Packed FP16 Values to Signed Word Integers | ⬛ |
| `VCVTPS2PH` | Convert Single-Precision FP Value to 16-bit FP Value | ⬛ |
| `VCVTPS2PHX` | Convert Packed Single Precision Floating-Point Values to Packed FP16 Values | ⬛ |
| `VCVTPS2QQ` | Convert Packed Single Precision Floating-Point Values to Packed SignedQuadword Integer Values | ⬛ |
| `VCVTPS2UDQ` | Convert Packed Single Precision Floating-Point Values to Packed UnsignedDoubleword Integer Values | ⬛ |
| `VCVTPS2UQQ` | Convert Packed Single Precision Floating-Point Values to Packed UnsignedQuadword Integer Values | ⬛ |
| `VCVTQQ2PD` | Convert Packed Quadword Integers to Packed Double Precision Floating-PointValues | ⬛ |
| `VCVTQQ2PH` | Convert Packed Signed Quadword Integers to Packed FP16 Values | ⬛ |
| `VCVTQQ2PS` | Convert Packed Quadword Integers to Packed Single Precision Floating-PointValues | ⬛ |
| `VCVTSD2SH` | Convert Low FP64 Value to an FP16 Value | ⬛ |
| `VCVTSD2USI` | Convert Scalar Double Precision Floating-Point Value to Unsigned DoublewordInteger | ⬛ |
| `VCVTSH2SD` | Convert Low FP16 Value to an FP64 Value | ⬛ |
| `VCVTSH2SI` | Convert Low FP16 Value to Signed Integer | ⬛ |
| `VCVTSH2SS` | Convert Low FP16 Value to FP32 Value | ⬛ |
| `VCVTSH2USI` | Convert Low FP16 Value to Unsigned Integer | ⬛ |
| `VCVTSI2SH` | Convert a Signed Doubleword/Quadword Integer to an FP16 Value | ⬛ |
| `VCVTSS2SH` | Convert Low FP32 Value to an FP16 Value | ⬛ |
| `VCVTSS2USI` | Convert Scalar Single Precision Floating-Point Value to Unsigned DoublewordInteger | ⬛ |
| `VCVTTPD2QQ` | Convert With Truncation Packed Double Precision Floating-Point Values toPacked Quadword Integers | ⬛ |
| `VCVTTPD2UDQ` | Convert With Truncation Packed Double Precision Floating-Point Values toPacked Unsigned Doubleword Integers | ⬛ |
| `VCVTTPD2UQQ` | Convert With Truncation Packed Double Precision Floating-Point Values toPacked Unsigned Quadword Integers | ⬛ |
| `VCVTTPH2DQ` | Convert with Truncation Packed FP16 Values to Signed Doubleword Integers | ⬛ |
| `VCVTTPH2QQ` | Convert with Truncation Packed FP16 Values to Signed Quadword Integers | ⬛ |
| `VCVTTPH2UDQ` | Convert with Truncation Packed FP16 Values to Unsigned DoublewordIntegers | ⬛ |
| `VCVTTPH2UQQ` | Convert with Truncation Packed FP16 Values to Unsigned Quadword Integers | ⬛ |
| `VCVTTPH2UW` | Convert Packed FP16 Values to Unsigned Word Integers | ⬛ |
| `VCVTTPH2W` | Convert Packed FP16 Values to Signed Word Integers | ⬛ |
| `VCVTTPS2QQ` | Convert With Truncation Packed Single Precision Floating-Point Values toPacked Signed Quadword Integer Values | ⬛ |
| `VCVTTPS2UDQ` | Convert With Truncation Packed Single Precision Floating-Point Values toPacked Unsigned Doubleword Integer Values | ⬛ |
| `VCVTTPS2UQQ` | Convert With Truncation Packed Single Precision Floating-Point Values toPacked Unsigned Quadword Integer Values | ⬛ |
| `VCVTTSD2USI` | Convert With Truncation Scalar Double Precision Floating-Point Value toUnsigned Integer | ⬛ |
| `VCVTTSH2SI` | Convert with Truncation Low FP16 Value to a Signed Integer | ⬛ |
| `VCVTTSH2USI` | Convert with Truncation Low FP16 Value to an Unsigned Integer | ⬛ |
| `VCVTTSS2USI` | Convert With Truncation Scalar Single Precision Floating-Point Value toUnsigned Integer | ⬛ |
| `VCVTUDQ2PD` | Convert Packed Unsigned Doubleword Integers to Packed Double PrecisionFloating-Point Values | ⬛ |
| `VCVTUDQ2PH` | Convert Packed Unsigned Doubleword Integers to Packed FP16 Values | ⬛ |
| `VCVTUDQ2PS` | Convert Packed Unsigned Doubleword Integers to Packed Single PrecisionFloating-Point Values | ⬛ |
| `VCVTUQQ2PD` | Convert Packed Unsigned Quadword Integers to Packed Double PrecisionFloating-Point Values | ⬛ |
| `VCVTUQQ2PH` | Convert Packed Unsigned Quadword Integers to Packed FP16 Values | ⬛ |
| `VCVTUQQ2PS` | Convert Packed Unsigned Quadword Integers to Packed Single PrecisionFloating-Point Values | ⬛ |
| `VCVTUSI2SD` | Convert Unsigned Integer to Scalar Double Precision Floating-Point Value | ⬛ |
| `VCVTUSI2SH` | Convert Unsigned Doubleword Integer to an FP16 Value | ⬛ |
| `VCVTUSI2SS` | Convert Unsigned Integer to Scalar Single Precision Floating-Point Value | ⬛ |
| `VCVTUW2PH` | Convert Packed Unsigned Word Integers to FP16 Values | ⬛ |
| `VCVTW2PH` | Convert Packed Signed Word Integers to FP16 Values | ⬛ |
| `VDBPSADBW` | Double Block Packed Sum-Absolute-Differences (SAD) on Unsigned Bytes | ⬛ |
| `VDIVPH` | Divide Packed FP16 Values | ⬛ |
| `VDIVSH` | Divide Scalar FP16 Values | ⬛ |
| `VDPBF16PS` | Dot Product of BF16 Pairs Accumulated Into Packed Single Precision | ⬛ |
| `VERR` | Verify a Segment for Reading or Writing | ⬛ |
| `VERW` | Verify a Segment for Reading or Writing | ⬛ |
| `VEXPANDPD` | Load Sparse Packed Double Precision Floating-Point Values From Dense Memory | ⬛ |
| `VEXPANDPS` | Load Sparse Packed Single Precision Floating-Point Values From Dense Memory | ⬛ |
| `VEXTRACTF128` | Extract Packed Floating-Point Values | ⬛ |
| `VEXTRACTF32x4` | Extract Packed Floating-Point Values | ⬛ |
| `VEXTRACTF32x8` | Extract Packed Floating-Point Values | ⬛ |
| `VEXTRACTF64x2` | Extract Packed Floating-Point Values | ⬛ |
| `VEXTRACTF64x4` | Extract Packed Floating-Point Values | ⬛ |
| `VEXTRACTI128` | ExtractPacked Integer Values | ⬛ |
| `VEXTRACTI32x4` | ExtractPacked Integer Values | ⬛ |
| `VEXTRACTI32x8` | ExtractPacked Integer Values | ⬛ |
| `VEXTRACTI64x2` | ExtractPacked Integer Values | ⬛ |
| `VEXTRACTI64x4` | ExtractPacked Integer Values | ⬛ |
| `VFCMADDCPH` | Complex Multiply and Accumulate FP16 Values | ⬛ |
| `VFCMADDCSH` | Complex Multiply and Accumulate Scalar FP16 Values | ⬛ |
| `VFCMULCPH` | Complex Multiply FP16 Values | ⬛ |
| `VFCMULCSH` | Complex Multiply Scalar FP16 Values | ⬛ |
| `VFIXUPIMMPD` | Fix Up Special Packed Float64 Values | ⬛ |
| `VFIXUPIMMPS` | Fix Up Special Packed Float32 Values | ⬛ |
| `VFIXUPIMMSD` | Fix Up Special Scalar Float64 Value | ⬛ |
| `VFIXUPIMMSS` | Fix Up Special Scalar Float32 Value | ⬛ |
| `VFMADD132PD` | Fused Multiply-Add of Packed DoublePrecision Floating-Point Values | ⬛ |
| `VFMADD132PH` | Fused Multiply-Add of Packed FP16 Values | ⬛ |
| `VFMADD132PS` | Fused Multiply-Add of Packed SinglePrecision Floating-Point Values | ⬛ |
| `VFMADD132SD` | Fused Multiply-Add of Scalar DoublePrecision Floating-Point Values | ⬛ |
| `VFMADD132SH` | Fused Multiply-Add of Scalar FP16 Values | ⬛ |
| `VFMADD132SS` | Fused Multiply-Add of Scalar Single PrecisionFloating-Point Values | ⬛ |
| `VFMADD213PD` | Fused Multiply-Add of Packed DoublePrecision Floating-Point Values | ⬛ |
| `VFMADD213PH` | Fused Multiply-Add of Packed FP16 Values | ⬛ |
| `VFMADD213PS` | Fused Multiply-Add of Packed SinglePrecision Floating-Point Values | ⬛ |
| `VFMADD213SD` | Fused Multiply-Add of Scalar DoublePrecision Floating-Point Values | ⬛ |
| `VFMADD213SH` | Fused Multiply-Add of Scalar FP16 Values | ⬛ |
| `VFMADD213SS` | Fused Multiply-Add of Scalar Single PrecisionFloating-Point Values | ⬛ |
| `VFMADD231PD` | Fused Multiply-Add of Packed DoublePrecision Floating-Point Values | ⬛ |
| `VFMADD231PH` | Fused Multiply-Add of Packed FP16 Values | ⬛ |
| `VFMADD231PS` | Fused Multiply-Add of Packed SinglePrecision Floating-Point Values | ⬛ |
| `VFMADD231SD` | Fused Multiply-Add of Scalar DoublePrecision Floating-Point Values | ⬛ |
| `VFMADD231SH` | Fused Multiply-Add of Scalar FP16 Values | ⬛ |
| `VFMADD231SS` | Fused Multiply-Add of Scalar Single PrecisionFloating-Point Values | ⬛ |
| `VFMADDCPH` | Complex Multiply and Accumulate FP16 Values | ⬛ |
| `VFMADDCSH` | Complex Multiply and Accumulate Scalar FP16 Values | ⬛ |
| `VFMADDRND231PD` | Fused Multiply-Add of Packed Double-Precision Floating-Point Valueswith rounding control | ⬛ |
| `VFMADDSUB132PD` | Fused Multiply-AlternatingAdd/Subtract of Packed Double Precision Floating-Point Values | ⬛ |
| `VFMADDSUB132PH` | Fused Multiply-AlternatingAdd/Subtract of Packed FP16 Values | ⬛ |
| `VFMADDSUB132PS` | Fused Multiply-AlternatingAdd/Subtract of Packed Single Precision Floating-Point Values | ⬛ |
| `VFMADDSUB213PD` | Fused Multiply-AlternatingAdd/Subtract of Packed Double Precision Floating-Point Values | ⬛ |
| `VFMADDSUB213PH` | Fused Multiply-AlternatingAdd/Subtract of Packed FP16 Values | ⬛ |
| `VFMADDSUB213PS` | Fused Multiply-AlternatingAdd/Subtract of Packed Single Precision Floating-Point Values | ⬛ |
| `VFMADDSUB231PD` | Fused Multiply-AlternatingAdd/Subtract of Packed Double Precision Floating-Point Values | ⬛ |
| `VFMADDSUB231PH` | Fused Multiply-AlternatingAdd/Subtract of Packed FP16 Values | ⬛ |
| `VFMADDSUB231PS` | Fused Multiply-AlternatingAdd/Subtract of Packed Single Precision Floating-Point Values | ⬛ |
| `VFMSUB132PD` | Fused Multiply-Subtract of Packed DoublePrecision Floating-Point Values | ⬛ |
| `VFMSUB132PH` | Fused Multiply-Subtract of Packed FP16 Values | ⬛ |
| `VFMSUB132PS` | Fused Multiply-Subtract of Packed SinglePrecision Floating-Point Values | ⬛ |
| `VFMSUB132SD` | Fused Multiply-Subtract of Scalar DoublePrecision Floating-Point Values | ⬛ |
| `VFMSUB132SH` | Fused Multiply-Subtract of Scalar FP16 Values | ⬛ |
| `VFMSUB132SS` | Fused Multiply-Subtract of Scalar SinglePrecision Floating-Point Values | ⬛ |
| `VFMSUB213PD` | Fused Multiply-Subtract of Packed DoublePrecision Floating-Point Values | ⬛ |
| `VFMSUB213PH` | Fused Multiply-Subtract of Packed FP16 Values | ⬛ |
| `VFMSUB213PS` | Fused Multiply-Subtract of Packed SinglePrecision Floating-Point Values | ⬛ |
| `VFMSUB213SD` | Fused Multiply-Subtract of Scalar DoublePrecision Floating-Point Values | ⬛ |
| `VFMSUB213SH` | Fused Multiply-Subtract of Scalar FP16 Values | ⬛ |
| `VFMSUB213SS` | Fused Multiply-Subtract of Scalar SinglePrecision Floating-Point Values | ⬛ |
| `VFMSUB231PD` | Fused Multiply-Subtract of Packed DoublePrecision Floating-Point Values | ⬛ |
| `VFMSUB231PH` | Fused Multiply-Subtract of Packed FP16 Values | ⬛ |
| `VFMSUB231PS` | Fused Multiply-Subtract of Packed SinglePrecision Floating-Point Values | ⬛ |
| `VFMSUB231SD` | Fused Multiply-Subtract of Scalar DoublePrecision Floating-Point Values | ⬛ |
| `VFMSUB231SH` | Fused Multiply-Subtract of Scalar FP16 Values | ⬛ |
| `VFMSUB231SS` | Fused Multiply-Subtract of Scalar SinglePrecision Floating-Point Values | ⬛ |
| `VFMSUBADD132PD` | Fused Multiply-AlternatingSubtract/Add of Packed Double Precision Floating-Point Values | ⬛ |
| `VFMSUBADD132PH` | Fused Multiply-AlternatingSubtract/Add of Packed FP16 Values | ⬛ |
| `VFMSUBADD132PS` | Fused Multiply-AlternatingSubtract/Add of Packed Single Precision Floating-Point Values | ⬛ |
| `VFMSUBADD213PD` | Fused Multiply-AlternatingSubtract/Add of Packed Double Precision Floating-Point Values | ⬛ |
| `VFMSUBADD213PH` | Fused Multiply-AlternatingSubtract/Add of Packed FP16 Values | ⬛ |
| `VFMSUBADD213PS` | Fused Multiply-AlternatingSubtract/Add of Packed Single Precision Floating-Point Values | ⬛ |
| `VFMSUBADD231PD` | Fused Multiply-AlternatingSubtract/Add of Packed Double Precision Floating-Point Values | ⬛ |
| `VFMSUBADD231PH` | Fused Multiply-AlternatingSubtract/Add of Packed FP16 Values | ⬛ |
| `VFMSUBADD231PS` | Fused Multiply-AlternatingSubtract/Add of Packed Single Precision Floating-Point Values | ⬛ |
| `VFMULCPH` | Complex Multiply FP16 Values | ⬛ |
| `VFMULCSH` | Complex Multiply Scalar FP16 Values | ⬛ |
| `VFNMADD132PD` | Fused Negative Multiply-Add of PackedDouble Precision Floating-Point Values | ⬛ |
| `VFNMADD132PH` | Fused Multiply-Add of Packed FP16 Values | ⬛ |
| `VFNMADD132PS` | Fused Negative Multiply-Add of PackedSingle Precision Floating-Point Values | ⬛ |
| `VFNMADD132SD` | Fused Negative Multiply-Add of ScalarDouble Precision Floating-Point Values | ⬛ |
| `VFNMADD132SH` | Fused Multiply-Add of Scalar FP16 Values | ⬛ |
| `VFNMADD132SS` | Fused Negative Multiply-Add of ScalarSingle Precision Floating-Point Values | ⬛ |
| `VFNMADD213PD` | Fused Negative Multiply-Add of PackedDouble Precision Floating-Point Values | ⬛ |
| `VFNMADD213PH` | Fused Multiply-Add of Packed FP16 Values | ⬛ |
| `VFNMADD213PS` | Fused Negative Multiply-Add of PackedSingle Precision Floating-Point Values | ⬛ |
| `VFNMADD213SD` | Fused Negative Multiply-Add of ScalarDouble Precision Floating-Point Values | ⬛ |
| `VFNMADD213SH` | Fused Multiply-Add of Scalar FP16 Values | ⬛ |
| `VFNMADD213SS` | Fused Negative Multiply-Add of ScalarSingle Precision Floating-Point Values | ⬛ |
| `VFNMADD231PD` | Fused Negative Multiply-Add of PackedDouble Precision Floating-Point Values | ⬛ |
| `VFNMADD231PH` | Fused Multiply-Add of Packed FP16 Values | ⬛ |
| `VFNMADD231PS` | Fused Negative Multiply-Add of PackedSingle Precision Floating-Point Values | ⬛ |
| `VFNMADD231SD` | Fused Negative Multiply-Add of ScalarDouble Precision Floating-Point Values | ⬛ |
| `VFNMADD231SH` | Fused Multiply-Add of Scalar FP16 Values | ⬛ |
| `VFNMADD231SS` | Fused Negative Multiply-Add of ScalarSingle Precision Floating-Point Values | ⬛ |
| `VFNMSUB132PD` | Fused Negative Multiply-Subtract ofPacked Double Precision Floating-Point Values | ⬛ |
| `VFNMSUB132PH` | Fused Multiply-Subtract of Packed FP16 Values | ⬛ |
| `VFNMSUB132PS` | Fused Negative Multiply-Subtract ofPacked Single Precision Floating-Point Values | ⬛ |
| `VFNMSUB132SD` | Fused Negative Multiply-Subtract ofScalar Double Precision Floating-Point Values | ⬛ |
| `VFNMSUB132SH` | Fused Multiply-Subtract of Scalar FP16 Values | ⬛ |
| `VFNMSUB132SS` | Fused Negative Multiply-Subtract ofScalar Single Precision Floating-Point Values | ⬛ |
| `VFNMSUB213PD` | Fused Negative Multiply-Subtract ofPacked Double Precision Floating-Point Values | ⬛ |
| `VFNMSUB213PH` | Fused Multiply-Subtract of Packed FP16 Values | ⬛ |
| `VFNMSUB213PS` | Fused Negative Multiply-Subtract ofPacked Single Precision Floating-Point Values | ⬛ |
| `VFNMSUB213SD` | Fused Negative Multiply-Subtract ofScalar Double Precision Floating-Point Values | ⬛ |
| `VFNMSUB213SH` | Fused Multiply-Subtract of Scalar FP16 Values | ⬛ |
| `VFNMSUB213SS` | Fused Negative Multiply-Subtract ofScalar Single Precision Floating-Point Values | ⬛ |
| `VFNMSUB231PD` | Fused Negative Multiply-Subtract ofPacked Double Precision Floating-Point Values | ⬛ |
| `VFNMSUB231PH` | Fused Multiply-Subtract of Packed FP16 Values | ⬛ |
| `VFNMSUB231PS` | Fused Negative Multiply-Subtract ofPacked Single Precision Floating-Point Values | ⬛ |
| `VFNMSUB231SD` | Fused Negative Multiply-Subtract ofScalar Double Precision Floating-Point Values | ⬛ |
| `VFNMSUB231SH` | Fused Multiply-Subtract of Scalar FP16 Values | ⬛ |
| `VFNMSUB231SS` | Fused Negative Multiply-Subtract ofScalar Single Precision Floating-Point Values | ⬛ |
| `VFPCLASSPD` | Tests Types of Packed Float64 Values | ⬛ |
| `VFPCLASSPH` | Test Types of Packed FP16 Values | ⬛ |
| `VFPCLASSPS` | Tests Types of Packed Float32 Values | ⬛ |
| `VFPCLASSSD` | Tests Type of a Scalar Float64 Value | ⬛ |
| `VFPCLASSSH` | Test Types of Scalar FP16 Values | ⬛ |
| `VFPCLASSSS` | Tests Type of a Scalar Float32 Value | ⬛ |
| `VGATHERDPD` | Gather Packed Double Precision Floating-Point Values UsingSigned Dword/Qword Indices | ⬛ |
| `VGATHERDPS` | Gather Packed Single Precision Floating-Point Values UsingSigned Dword/Qword Indices | ⬛ |
| `VGATHERQPD` | Gather Packed Double Precision Floating-Point Values UsingSigned Dword/Qword Indices | ⬛ |
| `VGATHERQPS` | Gather Packed Single Precision Floating-Point Values UsingSigned Dword/Qword Indices | ⬛ |
| `VGETEXPPD` | Convert Exponents of Packed Double Precision Floating-Point Values to DoublePrecision Floating-Point Values | ⬛ |
| `VGETEXPPH` | Convert Exponents of Packed FP16 Values to FP16 Values | ⬛ |
| `VGETEXPPS` | Convert Exponents of Packed Single Precision Floating-Point Values to SinglePrecision Floating-Point Values | ⬛ |
| `VGETEXPSD` | Convert Exponents of Scalar Double Precision Floating-Point Value to DoublePrecision Floating-Point Value | ⬛ |
| `VGETEXPSH` | Convert Exponents of Scalar FP16 Values to FP16 Values | ⬛ |
| `VGETEXPSS` | Convert Exponents of Scalar Single Precision Floating-Point Value to SinglePrecision Floating-Point Value | ⬛ |
| `VGETMANTPD` | Extract Float64 Vector of Normalized Mantissas From Float64 Vector | ⬛ |
| `VGETMANTPH` | Extract FP16 Vector of Normalized Mantissas from FP16 Vector | ⬛ |
| `VGETMANTPS` | Extract Float32 Vector of Normalized Mantissas From Float32 Vector | ⬛ |
| `VGETMANTSD` | Extract Float64 of Normalized Mantissa From Float64 Scalar | ⬛ |
| `VGETMANTSH` | Extract FP16 of Normalized Mantissa from FP16 Scalar | ⬛ |
| `VGETMANTSS` | Extract Float32 Vector of Normalized Mantissa From Float32 Scalar | ⬛ |
| `VINSERTF128` | Insert PackedFloating-Point Values | ⬛ |
| `VINSERTF32x4` | Insert PackedFloating-Point Values | ⬛ |
| `VINSERTF32x8` | Insert PackedFloating-Point Values | ⬛ |
| `VINSERTF64x2` | Insert PackedFloating-Point Values | ⬛ |
| `VINSERTF64x4` | Insert PackedFloating-Point Values | ⬛ |
| `VINSERTI128` | Insert PackedInteger Values | ⬛ |
| `VINSERTI32x4` | Insert PackedInteger Values | ⬛ |
| `VINSERTI32x8` | Insert PackedInteger Values | ⬛ |
| `VINSERTI64x2` | Insert PackedInteger Values | ⬛ |
| `VINSERTI64x4` | Insert PackedInteger Values | ⬛ |
| `VMASKMOV` | Conditional SIMD Packed Loads and Stores | ⬛ |
| `VMAXPH` | Return Maximum of Packed FP16 Values | ⬛ |
| `VMAXSH` | Return Maximum of Scalar FP16 Values | ⬛ |
| `VMINPH` | Return Minimum of Packed FP16 Values | ⬛ |
| `VMINSH` | Return Minimum Scalar FP16 Value | ⬛ |
| `VMOVDQA32` | Move Aligned Packed Integer Values | ⬛ |
| `VMOVDQA64` | Move Aligned Packed Integer Values | ⬛ |
| `VMOVDQU16` | Move Unaligned Packed Integer Values | ⬛ |
| `VMOVDQU32` | Move Unaligned Packed Integer Values | ⬛ |
| `VMOVDQU64` | Move Unaligned Packed Integer Values | ⬛ |
| `VMOVDQU8` | Move Unaligned Packed Integer Values | ⬛ |
| `VMOVSH` | Move Scalar FP16 Value | ⬛ |
| `VMOVW` | Move Word | ⬛ |
| `VMULPH` | Multiply Packed FP16 Values | ⬛ |
| `VMULSH` | Multiply Scalar FP16 Values | ⬛ |
| `VP2INTERSECTD` | Compute Intersection Between DWORDS/QUADWORDS to aPair of Mask Registers | ⬛ |
| `VP2INTERSECTQ` | Compute Intersection Between DWORDS/QUADWORDS to aPair of Mask Registers | ⬛ |
| `VPBLENDD` | Blend Packed Dwords | ⬛ |
| `VPBLENDMB` | Blend Byte/Word Vectors Using an Opmask Control | ⬛ |
| `VPBLENDMD` | Blend Int32/Int64 Vectors Using an OpMask Control | ⬛ |
| `VPBLENDMQ` | Blend Int32/Int64 Vectors Using an OpMask Control | ⬛ |
| `VPBLENDMW` | Blend Byte/Word Vectors Using an Opmask Control | ⬛ |
| `VPBROADCAST` | Load Integer and Broadcast | ⬛ |
| `VPBROADCASTB` | Load With Broadcast Integer Data From General Purpose Register | ⬛ |
| `VPBROADCASTD` | Load With Broadcast Integer Data From General Purpose Register | ⬛ |
| `VPBROADCASTM` | Broadcast Mask to Vector Register | ⬛ |
| `VPBROADCASTQ` | Load With Broadcast Integer Data From General Purpose Register | ⬛ |
| `VPBROADCASTW` | Load With Broadcast Integer Data From General Purpose Register | ⬛ |
| `VPCMPB` | Compare Packed Byte Values Into Mask | ⬛ |
| `VPCMPD` | Compare Packed Integer Values Into Mask | ⬛ |
| `VPCMPQ` | Compare Packed Integer Values Into Mask | ⬛ |
| `VPCMPUB` | Compare Packed Byte Values Into Mask | ⬛ |
| `VPCMPUD` | Compare Packed Integer Values Into Mask | ⬛ |
| `VPCMPUQ` | Compare Packed Integer Values Into Mask | ⬛ |
| `VPCMPUW` | Compare Packed Word Values Into Mask | ⬛ |
| `VPCMPW` | Compare Packed Word Values Into Mask | ⬛ |
| `VPCOMPRESSB` | Store Sparse Packed Byte/Word Integer Values Into DenseMemory/Register | ⬛ |
| `VPCOMPRESSD` | Store Sparse Packed Doubleword Integer Values Into Dense Memory/Register | ⬛ |
| `VPCOMPRESSQ` | Store Sparse Packed Quadword Integer Values Into Dense Memory/Register | ⬛ |
| `VPCONFLICTD` | Detect Conflicts Within a Vector of Packed Dword/Qword Values Into DenseMemory/ Register | ⬛ |
| `VPCONFLICTQ` | Detect Conflicts Within a Vector of Packed Dword/Qword Values Into DenseMemory/ Register | ⬛ |
| `VPDPBUSD` | Multiply and Add Unsigned and Signed Bytes | ⬛ |
| `VPDPBUSDS` | Multiply and Add Unsigned and Signed Bytes With Saturation | ⬛ |
| `VPDPWSSD` | Multiply and Add Signed Word Integers | ⬛ |
| `VPDPWSSDS` | Multiply and Add Signed Word Integers With Saturation | ⬛ |
| `VPERM2F128` | Permute Floating-Point Values | ⬛ |
| `VPERM2I128` | Permute Integer Values | ⬛ |
| `VPERMB` | Permute Packed Bytes Elements | ⬛ |
| `VPERMD` | Permute Packed Doubleword/Word Elements | ⬛ |
| `VPERMI2B` | Full Permute of Bytes From Two Tables Overwriting the Index | ⬛ |
| `VPERMI2D` | Full Permute From Two Tables Overwriting the Index | ⬛ |
| `VPERMI2PD` | Full Permute From Two Tables Overwriting the Index | ⬛ |
| `VPERMI2PS` | Full Permute From Two Tables Overwriting the Index | ⬛ |
| `VPERMI2Q` | Full Permute From Two Tables Overwriting the Index | ⬛ |
| `VPERMI2W` | Full Permute From Two Tables Overwriting the Index | ⬛ |
| `VPERMILPD` | Permute In-Lane of Pairs of Double Precision Floating-Point Values | ⬛ |
| `VPERMILPS` | Permute In-Lane of Quadruples of Single Precision Floating-Point Values | ⬛ |
| `VPERMPD` | Permute Double Precision Floating-Point Elements | ⬛ |
| `VPERMPS` | Permute Single Precision Floating-Point Elements | ⬛ |
| `VPERMQ` | Qwords Element Permutation | ⬛ |
| `VPERMT2B` | Full Permute of Bytes From Two Tables Overwriting a Table | ⬛ |
| `VPERMT2D` | Full Permute From Two Tables Overwriting One Table | ⬛ |
| `VPERMT2PD` | Full Permute From Two Tables Overwriting One Table | ⬛ |
| `VPERMT2PS` | Full Permute From Two Tables Overwriting One Table | ⬛ |
| `VPERMT2Q` | Full Permute From Two Tables Overwriting One Table | ⬛ |
| `VPERMT2W` | Full Permute From Two Tables Overwriting One Table | ⬛ |
| `VPERMW` | Permute Packed Doubleword/Word Elements | ⬛ |
| `VPEXPANDB` | Expand Byte/Word Values | ⬛ |
| `VPEXPANDD` | Load Sparse Packed Doubleword Integer Values From Dense Memory/Register | ⬛ |
| `VPEXPANDQ` | Load Sparse Packed Quadword Integer Values From Dense Memory/Register | ⬛ |
| `VPEXPANDW` | Expand Byte/Word Values | ⬛ |
| `VPGATHERDD` | Gather Packed Dword Values Using Signed Dword/Qword Indices | ⬛ |
| `VPGATHERDQ` | Gather Packed Dword, Packed Qword With Signed Dword Indices | ⬛ |
| `VPGATHERQD` | Gather Packed Dword Values Using Signed Dword/Qword Indices | ⬛ |
| `VPGATHERQQ` | Gather Packed Qword Values Using Signed Dword/Qword Indices | ⬛ |
| `VPLZCNTD` | Count the Number of Leading Zero Bits for Packed Dword, Packed Qword Values | ⬛ |
| `VPLZCNTQ` | Count the Number of Leading Zero Bits for Packed Dword, Packed Qword Values | ⬛ |
| `VPMADD52HUQ` | Packed Multiply of Unsigned 52-Bit Unsigned Integers and Add High 52-BitProducts to 64-Bit Accumulators | ⬛ |
| `VPMADD52LUQ` | Packed Multiply of Unsigned 52-Bit Integers and Add the Low 52-Bit Productsto Qword Accumulators | ⬛ |
| `VPMASKMOV` | Conditional SIMD Integer Packed Loads and Stores | ⬛ |
| `VPMOVB2M` | Convert a Vector Register to a Mask | ⬛ |
| `VPMOVD2M` | Convert a Vector Register to a Mask | ⬛ |
| `VPMOVDB` | Down Convert DWord to Byte | ⬛ |
| `VPMOVDW` | Down Convert DWord to Word | ⬛ |
| `VPMOVM2B` | Convert a Mask Register to a VectorRegister | ⬛ |
| `VPMOVM2D` | Convert a Mask Register to a VectorRegister | ⬛ |
| `VPMOVM2Q` | Convert a Mask Register to a VectorRegister | ⬛ |
| `VPMOVM2W` | Convert a Mask Register to a VectorRegister | ⬛ |
| `VPMOVQ2M` | Convert a Vector Register to a Mask | ⬛ |
| `VPMOVQB` | Down Convert QWord to Byte | ⬛ |
| `VPMOVQD` | Down Convert QWord to DWord | ⬛ |
| `VPMOVQW` | Down Convert QWord to Word | ⬛ |
| `VPMOVSDB` | Down Convert DWord to Byte | ⬛ |
| `VPMOVSDW` | Down Convert DWord to Word | ⬛ |
| `VPMOVSQB` | Down Convert QWord to Byte | ⬛ |
| `VPMOVSQD` | Down Convert QWord to DWord | ⬛ |
| `VPMOVSQW` | Down Convert QWord to Word | ⬛ |
| `VPMOVSWB` | Down Convert Word to Byte | ⬛ |
| `VPMOVUSDB` | Down Convert DWord to Byte | ⬛ |
| `VPMOVUSDW` | Down Convert DWord to Word | ⬛ |
| `VPMOVUSQB` | Down Convert QWord to Byte | ⬛ |
| `VPMOVUSQD` | Down Convert QWord to DWord | ⬛ |
| `VPMOVUSQW` | Down Convert QWord to Word | ⬛ |
| `VPMOVUSWB` | Down Convert Word to Byte | ⬛ |
| `VPMOVW2M` | Convert a Vector Register to a Mask | ⬛ |
| `VPMOVWB` | Down Convert Word to Byte | ⬛ |
| `VPMULTISHIFTQB` | Select Packed Unaligned Bytes From Quadword Sources | ⬛ |
| `VPOPCNT` | Return the Count of Number of Bits Set to 1 in BYTE/WORD/DWORD/QWORD | ⬛ |
| `VPROLD` | Bit Rotate Left | ⬛ |
| `VPROLQ` | Bit Rotate Left | ⬛ |
| `VPROLVD` | Bit Rotate Left | ⬛ |
| `VPROLVQ` | Bit Rotate Left | ⬛ |
| `VPRORD` | Bit Rotate Right | ⬛ |
| `VPRORQ` | Bit Rotate Right | ⬛ |
| `VPRORVD` | Bit Rotate Right | ⬛ |
| `VPRORVQ` | Bit Rotate Right | ⬛ |
| `VPSCATTERDD` | Scatter Packed Dword, PackedQword with Signed Dword, Signed Qword Indices | ⬛ |
| `VPSCATTERDQ` | Scatter Packed Dword, PackedQword with Signed Dword, Signed Qword Indices | ⬛ |
| `VPSCATTERQD` | Scatter Packed Dword, PackedQword with Signed Dword, Signed Qword Indices | ⬛ |
| `VPSCATTERQQ` | Scatter Packed Dword, PackedQword with Signed Dword, Signed Qword Indices | ⬛ |
| `VPSHLD` | Concatenate and Shift Packed Data Left Logical | ⬛ |
| `VPSHLDV` | Concatenate and Variable Shift Packed Data Left Logical | ⬛ |
| `VPSHRD` | Concatenate and Shift Packed Data Right Logical | ⬛ |
| `VPSHRDV` | Concatenate and Variable Shift Packed Data Right Logical | ⬛ |
| `VPSHUFBITQMB` | Shuffle Bits From Quadword Elements Using Byte Indexes Into Mask | ⬛ |
| `VPSLLVD` | Variable Bit Shift Left Logical | ⬛ |
| `VPSLLVQ` | Variable Bit Shift Left Logical | ⬛ |
| `VPSLLVW` | Variable Bit Shift Left Logical | ⬛ |
| `VPSRAVD` | Variable Bit Shift Right Arithmetic | ⬛ |
| `VPSRAVQ` | Variable Bit Shift Right Arithmetic | ⬛ |
| `VPSRAVW` | Variable Bit Shift Right Arithmetic | ⬛ |
| `VPSRLVD` | Variable Bit Shift Right Logical | ⬛ |
| `VPSRLVQ` | Variable Bit Shift Right Logical | ⬛ |
| `VPSRLVW` | Variable Bit Shift Right Logical | ⬛ |
| `VPTERNLOGD` | Bitwise Ternary Logic | ⬛ |
| `VPTERNLOGQ` | Bitwise Ternary Logic | ⬛ |
| `VPTESTMB` | Logical AND and Set Mask | ⬛ |
| `VPTESTMD` | Logical AND and Set Mask | ⬛ |
| `VPTESTMQ` | Logical AND and Set Mask | ⬛ |
| `VPTESTMW` | Logical AND and Set Mask | ⬛ |
| `VPTESTNMB` | Logical NAND and Set | ⬛ |
| `VPTESTNMD` | Logical NAND and Set | ⬛ |
| `VPTESTNMQ` | Logical NAND and Set | ⬛ |
| `VPTESTNMW` | Logical NAND and Set | ⬛ |
| `VRANGEPD` | Range Restriction Calculation for Packed Pairs of Float64 Values | ⬛ |
| `VRANGEPS` | Range Restriction Calculation for Packed Pairs of Float32 Values | ⬛ |
| `VRANGESD` | Range Restriction Calculation From a Pair of Scalar Float64 Values | ⬛ |
| `VRANGESS` | Range Restriction Calculation From a Pair of Scalar Float32 Values | ⬛ |
| `VRCP14PD` | Compute Approximate Reciprocals of Packed Float64 Values | ⬛ |
| `VRCP14PS` | Compute Approximate Reciprocals of Packed Float32 Values | ⬛ |
| `VRCP14SD` | Compute Approximate Reciprocal of Scalar Float64 Value | ⬛ |
| `VRCP14SS` | Compute Approximate Reciprocal of Scalar Float32 Value | ⬛ |
| `VRCPPH` | Compute Reciprocals of Packed FP16 Values | ⬛ |
| `VRCPSH` | Compute Reciprocal of Scalar FP16 Value | ⬛ |
| `VREDUCEPD` | Perform Reduction Transformation on Packed Float64 Values | ⬛ |
| `VREDUCEPH` | Perform Reduction Transformation on Packed FP16 Values | ⬛ |
| `VREDUCEPS` | Perform Reduction Transformation on Packed Float32 Values | ⬛ |
| `VREDUCESD` | Perform a Reduction Transformation on a Scalar Float64 Value | ⬛ |
| `VREDUCESH` | Perform Reduction Transformation on Scalar FP16 Value | ⬛ |
| `VREDUCESS` | Perform a Reduction Transformation on a Scalar Float32 Value | ⬛ |
| `VRNDSCALEPD` | Round Packed Float64 Values to Include a Given Number of Fraction Bits | ⬛ |
| `VRNDSCALEPH` | Round Packed FP16 Values to Include a Given Number of Fraction Bits | ⬛ |
| `VRNDSCALEPS` | Round Packed Float32 Values to Include a Given Number of Fraction Bits | ⬛ |
| `VRNDSCALESD` | Round Scalar Float64 Value to Include a Given Number of Fraction Bits | ⬛ |
| `VRNDSCALESH` | Round Scalar FP16 Value to Include a Given Number of Fraction Bits | ⬛ |
| `VRNDSCALESS` | Round Scalar Float32 Value to Include a Given Number of Fraction Bits | ⬛ |
| `VRSQRT14PD` | Compute Approximate Reciprocals of Square Roots of Packed Float64 Values | ⬛ |
| `VRSQRT14PS` | Compute Approximate Reciprocals of Square Roots of Packed Float32 Values | ⬛ |
| `VRSQRT14SD` | Compute Approximate Reciprocal of Square Root of Scalar Float64 Value | ⬛ |
| `VRSQRT14SS` | Compute Approximate Reciprocal of Square Root of Scalar Float32 Value | ⬛ |
| `VRSQRTPH` | Compute Reciprocals of Square Roots of Packed FP16 Values | ⬛ |
| `VRSQRTSH` | Compute Approximate Reciprocal of Square Root of Scalar FP16 Value | ⬛ |
| `VSCALEFPD` | Scale Packed Float64 Values With Float64 Values | ⬛ |
| `VSCALEFPH` | Scale Packed FP16 Values with FP16 Values | ⬛ |
| `VSCALEFPS` | Scale Packed Float32 Values With Float32 Values | ⬛ |
| `VSCALEFSD` | Scale Scalar Float64 Values With Float64 Values | ⬛ |
| `VSCALEFSH` | Scale Scalar FP16 Values with FP16 Values | ⬛ |
| `VSCALEFSS` | Scale Scalar Float32 Value With Float32 Value | ⬛ |
| `VSCATTERDPD` | Scatter Packed Single, PackedDouble with Signed Dword and Qword Indices | ⬛ |
| `VSCATTERDPS` | Scatter Packed Single, PackedDouble with Signed Dword and Qword Indices | ⬛ |
| `VSCATTERQPD` | Scatter Packed Single, PackedDouble with Signed Dword and Qword Indices | ⬛ |
| `VSCATTERQPS` | Scatter Packed Single, PackedDouble with Signed Dword and Qword Indices | ⬛ |
| `VSHUFF32x4` | Shuffle Packed Values at 128-BitGranularity | ⬛ |
| `VSHUFF64x2` | Shuffle Packed Values at 128-BitGranularity | ⬛ |
| `VSHUFI32x4` | Shuffle Packed Values at 128-BitGranularity | ⬛ |
| `VSHUFI64x2` | Shuffle Packed Values at 128-BitGranularity | ⬛ |
| `VSQRTPH` | Compute Square Root of Packed FP16 Values | ⬛ |
| `VSQRTSH` | Compute Square Root of Scalar FP16 Value | ⬛ |
| `VSUBPH` | Subtract Packed FP16 Values | ⬛ |
| `VSUBSH` | Subtract Scalar FP16 Value | ⬛ |
| `VTESTPD` | Packed Bit Test | ⬛ |
| `VTESTPS` | Packed Bit Test | ⬛ |
| `VUCOMISH` | Unordered Compare Scalar FP16 Values and Set EFLAGS | ⬛ |
| `VZEROALL` | Zero XMM, YMM, and ZMM Registers | ⬛ |
| `VZEROUPPER` | Zero Upper Bits of YMM and ZMM Registers | ⬛ |
| `WAIT` | Wait | ⬛ |
| `WBINVD` | Write Back and Invalidate Cache | ⬛ |
| `WBNOINVD` | Write Back and Do Not Invalidate Cache | ⬛ |
| `WRFSBASE` | Write FS/GS Segment Base | ⬛ |
| `WRGSBASE` | Write FS/GS Segment Base | ⬛ |
| `WRMSR` | Write to Model Specific Register | ⬛ |
| `WRPKRU` | Write Data to User Page Key Register | ⬛ |
| `WRSSD` | Write to Shadow Stack | ⬛ |
| `WRSSQ` | Write to Shadow Stack | ⬛ |
| `WRUSSD` | Write to User Shadow Stack | ⬛ |
| `WRUSSQ` | Write to User Shadow Stack | ⬛ |
| `XABORT` | Transactional Abort | ⬛ |
| `XACQUIRE` | Hardware Lock Elision Prefix Hints | ⬛ |
| `XADD` | Exchange and Add | 🟩 |
| `XBEGIN` | Transactional Begin | ⬛ |
| `XCHG` | Exchange Register/Memory With Register | 🟩 |
| `XEND` | Transactional End | ⬛ |
| `XGETBV` | Get Value of Extended Control Register | ⬛ |
| `XLAT` | Table Look-up Translation | ⬛ |
| `XLATB` | Table Look-up Translation | ⬛ |
| `XOR` | Logical Exclusive OR | 🟩 |
| `XORPD` | Bitwise Logical XOR of Packed Double Precision Floating-Point Values | ⬛ |
| `XORPS` | Bitwise Logical XOR of Packed Single Precision Floating-Point Values | ⬛ |
| `XRELEASE` | Hardware Lock Elision Prefix Hints | ⬛ |
| `XRESLDTRK` | Resume Tracking Load Addresses | ⬛ |
| `XRSTOR` | Restore Processor Extended States | ⬛ |
| `XRSTORS` | Restore Processor Extended States Supervisor | ⬛ |
| `XSAVE` | Save Processor Extended States | ⬛ |
| `XSAVEC` | Save Processor Extended States With Compaction | ⬛ |
| `XSAVEOPT` | Save Processor Extended States Optimized | ⬛ |
| `XSAVES` | Save Processor Extended States Supervisor | ⬛ |
| `XSETBV` | Set Extended Control Register | ⬛ |
| `XSUSLDTRK` | Suspend Tracking Load Addresses | ⬛ |
| `XTEST` | Test if in Transactional Execution | ⬛ |
| `ENCLS` | Execute an Enclave System Function of Specified Leaf Number | ⬛ |
| `ENCLS[EADD]` | Add a Page to an Uninitialized Enclave | ⬛ |
| `ENCLS[EAUG]` | Add a Page to an Initialized Enclave | ⬛ |
| `ENCLS[EBLOCK]` | Mark a page in EPC as Blocked | ⬛ |
| `ENCLS[ECREATE]` | Create an SECS page in the Enclave Page Cache | ⬛ |
| `ENCLS[EDBGRD]` | Read From a Debug Enclave | ⬛ |
| `ENCLS[EDBGWR]` | Write to a Debug Enclave | ⬛ |
| `ENCLS[EEXTEND]` | Extend Uninitialized Enclave Measurement by 256 Bytes | ⬛ |
| `ENCLS[EINIT]` | Initialize an Enclave for Execution | ⬛ |
| `ENCLS[ELDBC]` | Load an EPC Page and Mark its State | ⬛ |
| `ENCLS[ELDB]` | Load an EPC Page and Mark its State | ⬛ |
| `ENCLS[ELDUC]` | Load an EPC Page and Mark its State | ⬛ |
| `ENCLS[ELDU]` | Load an EPC Page and Mark its State | ⬛ |
| `ENCLS[EMODPR]` | Restrict the Permissions of an EPC Page | ⬛ |
| `ENCLS[EMODT]` | Change the Type of an EPC Page | ⬛ |
| `ENCLS[EPA]` | Add Version Array | ⬛ |
| `ENCLS[ERDINFO]` | Read Type and Status Information About an EPC Page | ⬛ |
| `ENCLS[EREMOVE]` | Remove a page from the EPC | ⬛ |
| `ENCLS[ETRACKC]` | Activates EBLOCK Checks | ⬛ |
| `ENCLS[ETRACK]` | Activates EBLOCK Checks | ⬛ |
| `ENCLS[EWB]` | Invalidate an EPC Page and Write out to Main Memory | ⬛ |
| `ENCLU` | Execute an Enclave User Function of Specified Leaf Number | ⬛ |
| `ENCLU[EACCEPTCOPY]` | Initialize a Pending Page | ⬛ |
| `ENCLU[EACCEPT]` | Accept Changes to an EPC Page | ⬛ |
| `ENCLU[EDECCSSA]` | Decrements TCS.CSSA | ⬛ |
| `ENCLU[EENTER]` | Enters an Enclave | ⬛ |
| `ENCLU[EEXIT]` | Exits an Enclave | ⬛ |
| `ENCLU[EGETKEY]` | Retrieves a Cryptographic Key | ⬛ |
| `ENCLU[EMODPE]` | Extend an EPC Page Permissions | ⬛ |
| `ENCLU[EREPORT]` | Create a Cryptographic Report of the Enclave | ⬛ |
| `ENCLU[ERESUME]` | Re-Enters an Enclave | ⬛ |
| `ENCLV` | Execute an Enclave VMM Function of Specified Leaf Number | ⬛ |
| `ENCLV[EDECVIRTCHILD]` | Decrement VIRTCHILDCNT in SECS | ⬛ |
| `ENCLV[EINCVIRTCHILD]` | Increment VIRTCHILDCNT in SECS | ⬛ |
| `ENCLV[ESETCONTEXT]` | Set the ENCLAVECONTEXT Field in SECS | ⬛ |
| `GETSEC[CAPABILITIES]` | Report the SMX Capabilities | ⬛ |
| `GETSEC[ENTERACCS]` | Execute Authenticated Chipset Code | ⬛ |
| `GETSEC[EXITAC]` | Exit Authenticated Code Execution Mode | ⬛ |
| `GETSEC[PARAMETERS]` | Report the SMX Parameters | ⬛ |
| `GETSEC[SENTER]` | Enter a Measured Environment | ⬛ |
| `GETSEC[SEXIT]` | Exit Measured Environment | ⬛ |
| `GETSEC[SMCTRL]` | SMX Mode Control | ⬛ |
| `GETSEC[WAKEUP]` | Wake Up Sleeping Processors in Measured Environment | ⬛ |
| `INVEPT` | Invalidate Translations Derived from EPT | ⬛ |
| `INVVPID` | Invalidate Translations Based on VPID | ⬛ |
| `VMCALL` | Call to VM Monitor | ⬛ |
| `VMCLEAR` | Clear Virtual-Machine Control Structure | ⬛ |
| `VMFUNC` | Invoke VM function | ⬛ |
| `VMLAUNCH` | Launch/Resume Virtual Machine | ⬛ |
| `VMPTRLD` | Load Pointer to Virtual-Machine Control Structure | ⬛ |
| `VMPTRST` | Store Pointer to Virtual-Machine Control Structure | ⬛ |
| `VMREAD` | Read Field from Virtual-Machine Control Structure | ⬛ |
| `VMRESUME` | Launch/Resume Virtual Machine | ⬛ |
| `VMWRITE` | Write Field to Virtual-Machine Control Structure | ⬛ |
| `VMXOFF` | Leave VMX Operation | ⬛ |
| `VMXON` | Enter VMX Operation | ⬛ |
| `PREFETCHWT1` | Prefetch Vector Data Into Caches With Intent to Write and T1 Hint | ⬛ |
| `V4FMADDPS` | Packed Single Precision Floating-Point Fused Multiply-Add(4-Iterations) | ⬛ |
| `V4FMADDSS` | Scalar Single Precision Floating-Point Fused Multiply-Add(4-Iterations) | ⬛ |
| `V4FNMADDPS` | Packed Single Precision Floating-Point Fused Multiply-Add(4-Iterations) | ⬛ |
| `V4FNMADDSS` | Scalar Single Precision Floating-Point Fused Multiply-Add(4-Iterations) | ⬛ |
| `VEXP2PD` | Approximation to the Exponential 2^x of Packed Double Precision Floating-PointValues With Less Than 2^-23 Relative Error | ⬛ |
| `VEXP2PS` | Approximation to the Exponential 2^x of Packed Single Precision Floating-PointValues With Less Than 2^-23 Relative Error | ⬛ |
| `VGATHERPF0DPD` | Sparse PrefetchPacked SP/DP Data Values With Signed Dword, Signed Qword Indices Using T0 Hint | ⬛ |
| `VGATHERPF0DPS` | Sparse PrefetchPacked SP/DP Data Values With Signed Dword, Signed Qword Indices Using T0 Hint | ⬛ |
| `VGATHERPF0QPD` | Sparse PrefetchPacked SP/DP Data Values With Signed Dword, Signed Qword Indices Using T0 Hint | ⬛ |
| `VGATHERPF0QPS` | Sparse PrefetchPacked SP/DP Data Values With Signed Dword, Signed Qword Indices Using T0 Hint | ⬛ |
| `VGATHERPF1DPD` | Sparse PrefetchPacked SP/DP Data Values With Signed Dword, Signed Qword Indices Using T1 Hint | ⬛ |
| `VGATHERPF1DPS` | Sparse PrefetchPacked SP/DP Data Values With Signed Dword, Signed Qword Indices Using T1 Hint | ⬛ |
| `VGATHERPF1QPD` | Sparse PrefetchPacked SP/DP Data Values With Signed Dword, Signed Qword Indices Using T1 Hint | ⬛ |
| `VGATHERPF1QPS` | Sparse PrefetchPacked SP/DP Data Values With Signed Dword, Signed Qword Indices Using T1 Hint | ⬛ |
| `VP4DPWSSD` | Dot Product of Signed Words With Dword Accumulation (4-Iterations) | ⬛ |
| `VP4DPWSSDS` | Dot Product of Signed Words With Dword Accumulation and Saturation(4-Iterations) | ⬛ |
| `VRCP28PD` | Approximation to the Reciprocal of Packed Double Precision Floating-Point ValuesWith Less Than 2^-28 Relative Error | ⬛ |
| `VRCP28PS` | Approximation to the Reciprocal of Packed Single Precision Floating-Point ValuesWith Less Than 2^-28 Relative Error | ⬛ |
| `VRCP28SD` | Approximation to the Reciprocal of Scalar Double Precision Floating-Point ValueWith Less Than 2^-28 Relative Error | ⬛ |
| `VRCP28SS` | Approximation to the Reciprocal of Scalar Single Precision Floating-Point ValueWith Less Than 2^-28 Relative Error | ⬛ |
| `VRSQRT28PD` | Approximation to the Reciprocal Square Root of Packed Double PrecisionFloating-Point Values With Less Than 2^-28 Relative Error | ⬛ |
| `VRSQRT28PS` | Approximation to the Reciprocal Square Root of Packed Single PrecisionFloating-Point Values With Less Than 2^-28 Relative Error | ⬛ |
| `VRSQRT28SD` | Approximation to the Reciprocal Square Root of Scalar Double PrecisionFloating-Point Value With Less Than 2^-28 Relative Error | ⬛ |
| `VRSQRT28SS` | Approximation to the Reciprocal Square Root of Scalar Single Precision Floating-Point Value With Less Than 2^-28 Relative Error | ⬛ |
| `VSCATTERPF0DPD` | Sparse PrefetchPacked SP/DP Data Values with Signed Dword, Signed Qword Indices Using T0 Hint With Intentto Write | ⬛ |
| `VSCATTERPF0DPS` | Sparse PrefetchPacked SP/DP Data Values with Signed Dword, Signed Qword Indices Using T0 Hint With Intentto Write | ⬛ |
| `VSCATTERPF0QPD` | Sparse PrefetchPacked SP/DP Data Values with Signed Dword, Signed Qword Indices Using T0 Hint With Intentto Write | ⬛ |
| `VSCATTERPF0QPS` | Sparse PrefetchPacked SP/DP Data Values with Signed Dword, Signed Qword Indices Using T0 Hint With Intentto Write | ⬛ |
| `VSCATTERPF1DPD` | Sparse PrefetchPacked SP/DP Data Values With Signed Dword, Signed Qword Indices Using T1 Hint With Intentto Write | ⬛ |
| `VSCATTERPF1DPS` | Sparse PrefetchPacked SP/DP Data Values With Signed Dword, Signed Qword Indices Using T1 Hint With Intentto Write | ⬛ |
| `VSCATTERPF1QPD` | Sparse PrefetchPacked SP/DP Data Values With Signed Dword, Signed Qword Indices Using T1 Hint With Intentto Write | ⬛ |
| `VSCATTERPF1QPS` | Sparse PrefetchPacked SP/DP Data Values With Signed Dword, Signed Qword Indices Using T1 Hint With Intentto Write | ⬛ |

### 2.14 AES / Key Locker implementation notes

**AES-NI.** `runtime/AesPrimitives.h` implements the byte-level transforms the SDM
uses to define the instructions (`SubBytes`, `ShiftRows`, `MixColumns` and the
inverse forms, plus `SubWord`/`RotWord`/`Rcon` for `AESKEYGENASSIST`). The S-box is
derived at first use from the GF(2⁸) multiplicative inverse and the affine
transform, so it cannot drift from the arithmetic `MixColumns` uses.
Verification: the interpreter's `AESENC` × 9 + `AESENCLAST` reproduces the
FIPS-197 Appendix B ciphertext `69c4e0d8…` from `00112233…` with key `000102…0f`,
and the `AESIMC`-transformed-key `AESDEC` chain reproduces the plaintext.

**Key Locker.** `LOADIWKEY` is ring-0 and the real 384/512-bit handles are wrapped
with the internal wrapping key, so no user-mode runtime can synthesise an Intel
handle. NINE therefore defines its own plaintext handle (the CPU *is* the
implementation) and fails closed on anything else:

| Offset (48-byte handle) | Content |
|---|---|
| 0..6 | ASCII `NINEKL` + `0x01` |
| 7 | `0x00` |
| 8 | key length in bytes — 16 (`*128KL`) or 32 (`*256KL`) |
| 9..15 | zero |
| 16..47 | key bytes (AES-128; for a 64-byte handle bytes 16..47 hold the AES-256 key) |
| 48..63 | zero (512-bit handle only) |

Behaviour: the handle is loaded unaligned from memory (ModRM must be `!(11)`, so
only the memory form decodes); a handle that does not match the layout, or whose
recorded key length disagrees with the instruction, sets `ZF=1` and leaves the
destination untouched; `OF/SF/AF/PF/CF` are cleared either way. Valid handles run
the full 10 (AES-128) or 14 (AES-256) rounds on one block, or on XMM0–XMM7 for the
`WIDE` forms.

### 2.15 Bit-manipulation / legacy / MPX notes

- **VEX decoding** is now structural: `C5` (2-byte) and `C4` (3-byte) prefixes are
  parsed into map/vvvv/L/pp/W plus the inverted RXB extension bits, so the BMI1
  group (`ANDN`, `BLSI`, `BLSMSK`, `BLSR`, `BEXTR`, `BZHI`) is decoded and executed,
  as is the AVX-512 opmask group (`K*`, §2.16). Every other VEX form still
  surfaces as `VEX_OP` — but with its full instruction length (ModRM + SIB/disp +
  imm8), which keeps the decode stream aligned.
- **Bit-test addressing.** `BT/BTS/BTR/BTC` on a memory operand implement the
  bit-string rule: the bit index selects a word within the operand
  (`ea + (index / operand_bits) * operand_bytes`) and is then taken modulo the
  operand size. Register destinations mask the index directly.
- **Flag-control instructions** write the shadow RFLAGS. `CLI`/`STI` do not raise
  `#GP` — the sandbox never delivers interrupts, so they only toggle IF.
- **ARPL / BOUND.** Both are invalid in 64-bit mode (63 = MOVSXD, 62 = EVEX).
  Their semantics are implemented and reachable through
  `X86Decoder::setCompat32(true)` (thread-local), used by the relinker only when
  it is deliberately decoding a 32-bit compatibility image.
- **MPX.** Four bound registers live in `GuestContext` (`bnd[4][2]`, upper bound
  kept in its 1's-complement form). `BNDMK` builds bounds from a memory base,
  `BNDMOV` moves the 128-bit pair, and `BNDCL`/`BNDCU`/`BNDCN` raise `#BR`
  (`0xC0000085`) on violation. Bound tables (BNDCFG/BNDSTATUS, the MPX address
  translation tables used by `BNDLDX`/`BNDSTX`) are not modelled: `BNDLDX`
  produces the architectural INIT bounds `{LB=0, UB=0}` and `BNDSTX` is a no-op.

**Execution path.** All of the instructions in §2.13 marked 🟩 are implemented in
`X86Decoder` + `InsnInterpreter` (the semantic reference and the path the app
enables via `ExecutionLoop::setTranslate(false)`). The x87 family lives in
`runtime/X87Exec.cpp` on top of the same interpreter. `Translator` (the AArch64
emitter) still handles only the integer subset it did before; these opcodes are
recorded as emitter fallbacks in `OpcodeCoverage`, and any block containing one
is marked `TranslationUnit::unsupported` so `ExecutionLoop` leaves that PC to the
interpreter instead of installing a nop-patched block. `AotCompiler` refuses such
a block outright. JIT-only mode (`setJitOnly(true)`) must therefore not be enabled
for guests that execute them.

**Regression test.** `tests/NativeTests.cpp::testNewIsa()` decodes every new
opcode, then executes the BCD-adjust / ADX / SSE-add / AES-NI / Key Locker paths
(FIPS-197 Appendix B ciphertext for `AESENC`×9+`AESENCLAST`, `AESIMC` undoing
`MixColumns`, `AESKEYGENASSIST` for `si128=0, rcon=1`, and a NINE handle through
`AESENC128KL`, including the fail-closed `ZF=1` case), followed by the x87 basic
arithmetic/compare/constant paths, FISTP/FISTTP rounding, FNSAVE/FRSTOR and
FXSAVE/FXRSTOR round-trips, plus DAA/DAS, DIVSS, HADDPS, DPPS, EXTRACTPS, GFNI,
CVTTSD2SI and the restricted-by-CR4 faults. Run it on-device from Debugger → `5.8`
(`NativeTests.run("5.8")`).

### 2.16 Mask-register / I/O / system batch (IN … LEAVE)

| Instruction | Encoding | Status |
|---|---|---|
| IN AL/eAX, imm8 | E4 / E5 ib | 🟩 #GP(0) — port I/O needs IOPL 3 |
| IN AL/eAX, DX | EC / ED | 🟩 #GP(0) |
| INS / INSB / INSW / INSD | 6C / 6D, 66 and REX.W pick 8/16/32 | 🟩 #GP(0) (element width in `dst.size`) |
| INVD | 0F 08 | 🟩 #GP(0) — privileged |
| INVLPG m8 | 0F 01 /7 | 🟩 #GP(0) — privileged |
| INVPCID r64, m128 | 66 0F 38 82 /r | 🟩 #GP(0) — privileged |
| INCSSPD / INCSSPQ | F3 0F AE /5 (register form, REX.W for Q) | 🟩 #UD — CR4.CET clear |
| INT n | CD ib | 🟩 #GP(0), message names the vector |
| INT1 | F1 | 🟩 #GP(0) |
| INTO | CE (compat mode only; invalid in long mode) | 🟩 #GP(0) |
| IRET / IRETD / IRETQ | CF, o16 / default / REX.W | 🟩 #GP(0) — no IDT, so never a frame |
| LAHF | 9F | 🟩 AH ← SF:ZF:0:AF:0:PF:1:CF |
| LAR r16/32/64, r/m16 | 0F 02 /r | 🟩 rights for 0x08/0x10/0x28/0x30, ZF=0 otherwise |
| LDS r16/32, m16:16 | C5 /r (**compat mode only**) | 🟨 offset half loaded; flat segment model |
| LDDQU xmm, m128 | F2 0F F0 /r | 🟩 |
| LDMXCSR m32 | 0F AE /2 | 🟩 fills `GuestContext::mxcsr` |
| INSERTPS xmm, xmm/m32, imm8 | 66 0F 3A 21 /r ib | 🟩 source/dest lane + zero mask |
| LDTILECFG m512 | VEX.128.NP.0F38 49 /0 | 🟩 #UD — AMX absent |
| KADDB/W/D/Q | VEX.NDS.0F 4A /r | 🟩 add without carry out |
| KANDB/W/D/Q, KANDNB/W/D/Q, KORB/W/D/Q, KXORB/W/D/Q, KXNORB/W/D/Q | VEX.NDS.0F 41/42/45/46/47 /r | 🟩 bitwise, element width from pp/W |
| KNOTB/W/D/Q | VEX.0F 44 /r | 🟩 |
| KUNPCKBW / WD / DQ | VEX.0F 4B /r (pp/W pick the source width) | 🟩 dest = SRC2:SRC1 |
| KTESTB/W/D/Q | VEX.NDS.0F **99** /r | 🟩 ZF = (a&b)==0, CF = (a&~b)==0 |
| KORTESTB/W/D/Q | VEX.NDS.0F **98** /r | 🟩 ZF = (a\|b)==0, CF = all ones |
| KSHIFTLB/W/D/Q, KSHIFTRB/W/D/Q | VEX.66.0F3A 32/33, 30/31 /r ib | 🟩 counts ≥ width produce 0 |
| KMOVB/W/D/Q k↔k/m | VEX.0F 90/91 /r | 🟩 m8/m16/m32/m64 forms |
| KMOVD/Q k↔r32/r64 | VEX.F2.0F 92/93 /r | 🟩 |
| IDIV, IMUL, INC, JMP, Jcc, LEA, LEAVE | — | 🟩 already implemented; audited, unchanged |

Design notes:

* **k-register file.** `GuestContext::kmask[8]` holds the eight 64-bit opmask
  registers. Only the VEX-encoded mask instructions touch it — zmm0–zmm31 and
  EVEX decoding remain unimplemented, so `K*` is the one AVX-512 corner NINE can
  run, and every destination width is masked to 8/16/32/64 bits on write.
  `k0` is never a legal destination (opmask as a write mask is implicit in
  EVEX), so those encodings raise `#UD`, matching silicon.
* **Element width.** For the arithmetic/bitwise group the width comes from
  `pp` and `VEX.W`: (pp=0,W=0)=16, (pp=1,W=0)=8, (pp=0,W=1)=64, (pp=1,W=1)=32.
  `KSHIFTL/KSHIFTR` use only pp=1 and take W as B/W (opcodes 32/30) or D/Q
  (33/31); `KMOV` uses pp=3 (F2) for the GPR forms, where the k side is always
  the full 32/64 bits of the GPR.
* **MXCSR exists now.** `GuestContext::mxcsr` (default `0x1F80`) is stored by
  `FXSAVE`, restored by `FXRSTOR`, and written by `LDMXCSR`. No SSE arithmetic
  consults it yet (rounding control, FTZ/DAZ and the exception masks are still
  ignored); conversions keep using round-half-even.
* **Faults, not silent no-ops.** Everything in this batch that a CPL-3 guest may
  not execute decodes to its exact length and then raises the architectural
  fault — `#GP(0)` for IOPL/privilege/IDT (`0xC0000005` in NINE's exception
  plane), `#UD` (`0xC000001D`) for feature-gated encodings. That keeps the decode
  stream aligned and makes an unexpected hit diagnosable from the message.
* **LDS is compat-only.** `C5` is VEX in long mode, so the far-pointer load is
  reachable only through `X86Decoder::setCompat32(true)` (the same gate as
  ARPL/BOUND); `C4` (LES) is still refused.

Not implementable as written in this batch: nothing — every requested mnemonic
is either implemented above or was already present. Two readings needed
interpreting: `IVD` is not an x86 mnemonic (INVD is), and `Jcc` is sixteen
opcodes (JO…JG, short 7x and near 0F 8x), all of which already existed.

Limits specific to this batch (beyond the global ones in §2.9 and §2.14):

* Opmask state is **not** included in `FXSAVE`/`FXRSTOR`; architecturally it
  belongs to XSAVE state component 5, and NINE models no XSAVE.
* `LAR` synthesises descriptor bits for the canonical selectors only; there is
  no GDT/LDT, so `SGDT`/`LLDT`/`VERR`/`VERW` remain unimplemented and a guest
  that installs its own descriptor table cannot query it.
* `IN`/`INS` never touch real ports — they always fault, so emulated hardware
  that needs port I/O cannot work yet.
* There is no interrupt machinery end to end: no IDT, no gate delivery, no
  interrupt frame, so `INT n`, `INT1`, `INTO` and `IRET` are decode-and-fault
  only, and guest SEH/`int 0x2e`-style transitions do not exist.

### 2.17 Packed-SIMD / GPR batch (LES … PCMPEQD)

| Instruction | Encoding | Status |
|---|---|---|
| LES r16/32, m16:16 | C4 /r (**compat mode only**) | 🟨 offset half loaded; `C4` is VEX in long mode |
| LFS / LGS / LSS | 0F B4 / B5 / B2 /r | 🟩 offset half (m16:16/32/64 by operand size), selector dropped |
| LGDT / LIDT m | 0F 01 /2, /3 | 🟩 #GP(0) — descriptor tables are kernel state |
| LLDT / LTR r/m16 | 0F 00 /2, /3 | 🟩 #GP(0) |
| LMSW r/m16 | 0F 01 /6 | 🟩 #GP(0) |
| LSL r32/64, r/m16 | 0F 03 /r | 🟩 limit 0xFFFFF for GDT selectors, ZF=1 on success like LAR |
| LOADIWKEY xmm, xmm, EAX, XMM0 | F3 0F 38 DC (mod = 11) | 🟩 #GP(0) — the SDM's operation starts with the CPL > 0 check |
| LOOP / LOOPE / LOOPNE | E2 / E1 / E0 cb | 🟩 RCX decremented, then the ZF test |
| JRCXZ | E3 cb | 🟩 no decrement |
| LOCK (F0) | prefix | 🟨 recorded in `Insn::lock`; a single guest CPU makes the RMW it prefixes already atomic |
| LODS / LODSB / LODSW / LODSD / LODSQ | AC / AD | 🟩 pre-existing, audited unchanged |
| LZCNT r32/64, r/m | F3 0F BD /r | 🟩 pre-existing, audited unchanged |
| MASKMOVDQU xmm, xmm | 66 0F F7 /r | 🟩 byte store to [RDI], only where mask MSB is set |
| MAXPS / MAXPD / MAXSS / MAXSD | 0F 5F / 66 0F 5F / F3 / F2 | 🟩 NaN or equal zeros return the second source |
| MINPS / MINPD / MINSS / MINSD | 0F 5D / 66 0F 5D / F3 / F2 | 🟩 same rule as MAX |
| MULPS / MULPD / MULSS / MULSD | 0F 59 / 66 0F 59 / F3 / F2 | 🟩 |
| ORPS / ORPD | 0F 56 / 66 0F 56 | 🟩 128-bit bitwise |
| LFENCE / MFENCE / SFENCE | 0F AE E8 / F0 / F8 | 🟩 ordered no-ops (single guest CPU, stores already visible) |
| MONITOR / MWAIT | 0F 01 C8 / C9 | 🟩 #GP(0) — CPL 0 only |
| MOV to/from CR, DR | 0F 20-23 /r | 🟩 decoded exactly, then #GP(0) |
| MOVBE r, m / m, r | 0F 38 F0 / F1 | 🟩 byte-swapping 16/32/64-bit load and store |
| MOVDIRI m32/64, r | 0F 38 F9 /r | 🟩 direct store (#GP on a register destination) |
| MOVDIR64B r64, m512 | 66 0F 38 F8 /r | 🟩 64-byte copy |
| MOVSS / MOVSD xmm, xmm/m | F3 / F2 0F 10 / 11 | 🟩 reg form merges, memory form zeroes the upper lanes |
| MOVHLPS / MOVLHPS | 0F 12 / 16 (mod = 11) | 🟩 half-register shuffle |
| MOVLPD / MOVHPD | 66 0F 12 / 13 / 16 / 17 | 🟩 64-bit half load/store |
| MOVDDUP / MOVSLDUP / MOVSHDUP | F2 0F 12, F3 0F 12, F3 0F 16 | 🟩 lane replication |
| MOVMSKPS / MOVMSKPD | 0F 50 / 66 0F 50 | 🟩 sign-bit mask into r32/r64 |
| MOVNTPS / MOVNTPD / MOVNTDQ / MOVNTQ / MOVNTI | 0F 2B, 66 0F 2B, 66 0F E7, 0F E7, 0F C3 | 🟩 hint collapses to a plain store |
| MOVNTDQA xmm, m128 | 66 0F 38 2A /r | 🟩 plain 128-bit load |
| MOVQ xmm, xmm/m64 | F3 0F 7E /r | 🟩 low 64 bits |
| MOVQ2DQ / MOVDQ2Q | F3 / F2 0F D6 /r | 🟨 `MMX_OP` — no MMX register file |
| MPSADBW xmm, xmm/m128, imm8 | 66 0F 3A 42 /r ib | 🟩 eight sliding 4-byte SADs, imm8 selects both block offsets |
| MULX r32a, r32b, r/m32 | VEX.F2.0F38 F6 /r | 🟩 RDX × r/m, low in ModRM.reg, high in VEX.vvvv, flags untouched |
| OUT imm8/DX, AL/eAX | E6 / E7 / EE / EF | 🟩 #GP(0) — IOPL is 0 at CPL 3 |
| OUTS / OUTSB / OUTSW / OUTSD | 6E / 6F | 🟩 #GP(0) |
| PABSB / PABSW / PABSD / PABSQ | 66 0F 38 1C-1F /r | 🟩 element width in `dst.size` |
| PACKSSWB / PACKSSDW / PACKUSWB / PACKUSDW | 66 0F 63 / 6B / 67, 66 0F 38 2B | 🟩 signed source, saturating pack |
| PADDB / PADDW / PADDD / PADDQ | 66 0F FC / FD / FE / D4 | 🟩 wraparound |
| PADDSB / PADDSW / PADDUSB / PADDUSW | 66 0F EC / ED / DC / DD | 🟩 saturating |
| PALIGNR xmm, xmm/m128, imm8 | 66 0F 3A 0F /r ib | 🟩 `(dst:src) >> imm8` bytes |
| PAND / PANDN | 66 0F DB / DF | 🟩 |
| PAUSE | F3 90 | 🟩 retires as NOP (pre-existing) |
| PAVGB / PAVGW | 66 0F E0 / E3 | 🟩 `(a + b + 1) >> 1` |
| PBLENDVB / PBLENDW | 66 0F 38 10, 66 0F 3A 0E ib | 🟩 implicit XMM0 mask / imm8 word mask |
| PCLMULQDQ xmm, xmm/m128, imm8 | 66 0F 3A 44 /r ib | 🟩 64×64 carry-less multiply |
| PCMPEQB / PCMPEQW / PCMPEQD | 66 0F 74 / 75 / 76 | 🟩 all-ones or all-zeros per element |
| MOV (moffs forms) | A0-A3 | 🟩 pre-existing, audited unchanged |
| MOV (CR/DR forms) | 0F 20-23 | 🟩 see above |
| MUL / NEG / NOP / NOT / OR / PAUSE | — | 🟩 pre-existing, audited unchanged |

Design notes:

* **One op per semantic, width in `dst.size`.** The packed-integer group
  compresses four 16-bit mnemonics into one `X86Op` (`PADD`, `PADDS`, `PADDUS`,
  `PABS`, `PACKSS`, `PACKUS`, `PAVG`, `PCMPEQ`) with the element width carried in
  `dst.size`, exactly like `KAND`/`KMOV` carry theirs. The interpreter masks
  every lane write to that width.
* **Non-temporal and direct stores are plain stores.** NINE models no cache
  hierarchy, so `MOVNT*` write through the normal path and `MOVDIRI`/
  `MOVDIR64B` do the same; the ordering guarantees a WC buffer would need are
  trivially satisfied because there is one guest CPU.
* **Fences.** `LFENCE`/`MFENCE`/`SFENCE` decode to `NOP` with their own mnemonic
  so traces stay honest. Every guest store is already visible to the runtime and
  the interpreter is single-threaded in guest terms, so the architectural effect
  is empty.
* **Far pointers.** `LFS/LGS/LSS/LES` load only the offset half. NINE has no
  GDT/LDT and a flat address space, so the selector has no effect on the next
  access; the read still covers the full m16:16/32/64 operand so a bad pointer
  faults at the right place.
* **`MOVSS`/`MOVSD` merge semantics.** The decoder routes the F3/F2 forms of
  0F 10/11 to `MOVSS`/`MOVSD_SSE` instead of the generic `SSE_MOV`, because the
  generic path copies 16 bytes and would clobber lanes the scalar form must
  leave alone.

Not implementable as written in this batch:

* `LMSQ` is not an x86 mnemonic — the instruction between LGDT/LIDT and LLDT is
  **LMSW** (0F 01 /6), which is what §2.17 implements.
* `MASKMOVDQ` is a typo for **MASKMOVDQU** (66 0F F7); the MMX form
  (`MASKMOVQ`, 0F F7) needs the MMX register file NINE does not model.
* `MOV (1)` and `MOV (2)` are the two extra MOV encodings on the same SDM page —
  the moffs forms (A0-A3) and the control/debug-register forms (0F 20-23).
  Both are covered here.
* `MOVQ (1)` is the load half `F3 0F 7E`; the store half `66 0F D6` existed and
  the MMX conversions (`MOVQ2DQ`, `MOVDQ2Q`) decode to `MMX_OP` by design.
* `MOVSD (1)` is the string form (A5), already present; the scalar SSE form is
  `MOVSD_SSE` in the enum to avoid the collision.
* `LOCK` is a prefix, not an instruction: F0 is already parsed into
  `Insn::lock`. With one guest CPU the RMW encodings it may prefix are already
  atomic with respect to the runtime, so there is nothing further to implement.

Limits specific to this batch (beyond the global ones in §2.9 and §2.14):

* `MOVNT*` and `MOVDIR*` do not enforce alignment: real hardware raises #GP for
  a misaligned `MOVDIR64B` destination and #GP for unaligned `MOVNTDQ`/`MOVAPS`.
  NINE accepts any address, matching its existing `MOVAPS`/`MOVDQA` behaviour.
* SSE arithmetic still ignores MXCSR: rounding control, FTZ/DAZ, and the
  exception masks/flags are not applied, so `MAXPS`/`MULPS` never set the
  precision/overflow sticky bits. `MAX*`/`MIN*` do implement the NaN and
  signed-zero rules, which are part of the result, not of MXCSR.
* `PBLENDVB` reads the mask from XMM0 as the legacy encoding requires; the VEX
  four-operand form is not decoded.
* All of this batch is legacy (non-VEX) except `MULX`: the AVX versions of these
  moves and blends need the VEX path plus 256-bit YMM state that NINE does not
  model.
* `MPSADBW` implements the 128-bit legacy form only (eight SADs) and ignores
  imm8 bits 7:3, as the SDM specifies.
* `MASKMOVDQU` writes through the normal store path byte-by-byte; there is no
  write-combining buffer to bypass, and no #UD check for CR0.EM/CR4.OSFXSR.
* `MONITOR`/`MWAIT` always fault at CPL 3, so the MWAIT state machine (and the
  address-range monitoring it depends on) does not exist.

### 2.18 Packed-integer / SSE4.2 / system batch (PCMPEQQ … RDPMC)

All of the packed forms below are legacy (non-VEX) encodings with the 66
mandatory prefix unless noted. `dst.size` carries the element width (8/16/32/64)
or 128 for whole-register operations; `cc` selects a sub-operation where one
X86Op covers a family.

| Instruction | Encoding | Status |
|---|---|---|
| PCMPGTB / PCMPGTW / PCMPGTD | 66 0F 64 / 65 / 66 | 🟩 signed packed compare |
| PCMPGTQ | 66 0F 38 37 | 🟩 64-bit signed compare |
| PCMPEQQ | 66 0F 38 29 | 🟩 reuses `PCMPEQ` with an 8-byte element |
| PSUBB / PSUBW / PSUBD / PSUBQ | 66 0F F8 / F9 / FA / FB | 🟩 wrapping |
| PSUBSB / PSUBSW | 66 0F E8 / E9 | 🟩 signed saturation |
| PSUBUSB / PSUBUSW | 66 0F D8 / D9 | 🟩 unsigned saturation |
| PUNPCKLBW / LWD / LDQ / LQDQ | 66 0F 60 / 61 / 62 / 6C | 🟩 interleave low half |
| PUNPCKHBW / HWD / HDQ / HQDQ | 66 0F 68 / 69 / 6A / 6D | 🟩 interleave high half |
| PSHUFD / PSHUFHW / PSHUFLW / PSHUFW | 66 / F3 / F2 / NP 0F 70 ib | 🟩 imm8 lane select |
| PSHUFB | 66 0F 38 00 | 🟩 per-byte lookup, MSB zeroes the lane |
| PSLLW / PSLLD / PSLLQ | 66 0F F1 / F2 / F3 | 🟩 count from the low qword of src |
| PSRLW / PSRLD / PSRLQ | 66 0F D1 / D2 / D3 | 🟩 |
| PSRAW / PSRAD | 66 0F E1 / E2 | 🟩 sign fill |
| PSLLW/D/Q, PSRLW/D/Q, PSRAW/D imm8 | 66 0F 71 / 72 / 73 ib | 🟩 group 13 |
| PSLLDQ / PSRLDQ | 66 0F 73 /7, /3 ib | 🟩 whole-register byte shift |
| PMULLW | 66 0F D5 | 🟩 |
| PMULHW / PMULHUW | 66 0F E5 / E4 | 🟩 high half, signed/unsigned |
| PMULLD / PMULLQ | 66 0F 38 40 (W0/W1) | 🟩 |
| PMULUDQ / PMULDQ | 66 0F F4 / 66 0F 38 28 | 🟩 even dwords → qwords |
| PMADDWD | 66 0F F5 | 🟩 |
| PMADDUBSW | 66 0F 38 04 | 🟩 unsigned × signed bytes, saturated |
| PMULHRSW | 66 0F 38 0B | 🟩 round-and-scale |
| PMINSB/D, PMINUW/D, PMINSQ/UQ | 66 0F 38 38-3B (+REX.W) | 🟩 |
| PMAXSB/D, PMAXUW/D, PMAXSQ/UQ | 66 0F 38 3C-3F (+REX.W) | 🟩 |
| PMINSW / PMAXSW / PMINUB / PMAXUB | 66 0F EA / EE / DA / DE | 🟩 |
| PMOVMSKB | 66 0F D7 | 🟩 GPR in ModRM.reg, XMM source in r/m |
| PMOVSXBW/BD/BQ/WD/WQ/DQ | 66 0F 38 20-25 | 🟩 sign-extending narrow load |
| PMOVZXBW/BD/BQ/WD/WQ/DQ | 66 0F 38 30-35 | 🟩 zero-extending narrow load |
| PEXTRB / PEXTRW / PEXTRD / PEXTRQ | 66 0F 3A 14 / 15 / 16 (W0/W1) | 🟩 to GPR or memory |
| PEXTRW (legacy) | 66 0F C5 ib | 🟩 |
| PINSRB / PINSRW / PINSRD / PINSRQ | 66 0F 3A 20 / 66 0F C4 / 66 0F 3A 22 | 🟩 from GPR or memory |
| PSIGNB / PSIGNW / PSIGND | 66 0F 38 08 / 09 / 0A | 🟩 |
| PSADBW | 66 0F F6 | 🟩 per-qword SAD |
| PHADDW / PHADDD / PHADDSW | 66 0F 38 01 / 02 / 03 | 🟩 all of src1, then src2 |
| PHSUBW / PHSUBD / PHSUBSW | 66 0F 38 05 / 06 / 07 | 🟩 |
| PHMINPOSUW | 66 0F 38 41 | 🟩 value + index in the low dword |
| PTEST | 66 0F 38 17 | 🟩 writes only ZF and CF |
| PCMPESTRI / PCMPESTRM | 66 0F 3A 61 / 60 ib | 🟩 explicit EAX/EDX lengths |
| PCMPISTRI / PCMPISTRM | 66 0F 3A 63 / 62 ib | 🟩 implicit NUL lengths |
| POR | 66 0F EB | 🟩 128-bit OR |
| POPCNT | F3 0F B8 /r | 🟩 |
| RCL / RCR | C0/C1 ib, D0/D1, D2/D3 | 🟩 rotate through CF over bits+1 |
| PUSHFQ / POPFQ | 9C / 9D | 🟩 64-bit RFLAGS image (66 → 16-bit) |
| PUSH imm32 / imm8 | 68 id / 6A ib | 🟩 sign-extended to the operand size |
| PUSHA / POPA | 60 / 61 | 🟩 decoded, then #UD in 64-bit mode |
| RDFSBASE / RDGSBASE | F3 0F AE /0, /1 | 🟩 reads `ctx.fs_base` / `gs_base` |
| RDMSR / RDPMC | 0F 32 / 33 | 🟩 #GP(0) at CPL 3 |
| RDPID | F3 0F C7 /7 | 🟩 TSC_AUX is always 0 |
| RDPKRU | 0F 01 EE | 🟩 #UD — CR4.PKE is clear, so the register does not exist |
| RDRAND | 0F C7 /6 | 🟩 xorshift generator, CF=1 |
| PDEP / PEXT | VEX.F2/F3.0F38.F5 | 🟩 bits come from VEX.vvvv, mask from r/m |
| PREFETCHNTA/T0/T1/T2 | 0F 18 /0-/3 | 🟩 no-op; prefetches never fault |
| PREFETCHW / PREFETCH | 0F 0D /1, /0 | 🟩 no-op |
| PCONFIG | 0F 01 C5 | 🟩 #UD — CPUID does not advertise the leaf |
| PTWRITE | F3 0F AE /4 | 🟩 #UD — CR4.PTW is clear |

**Notes and limits.**

* The SSE4.2 string instructions implement all four aggregations (equal any,
  ranges, equal each, equal ordered), both length modes, the positive/negative
  and masked polarities, and the least/most-significant index selection. The
  flags are the SDM's: CF = any match, ZF = second operand shorter than 16,
  SF = first operand shorter than 16, OF = result bit 0. Masked modes write the
  raw 16-bit result to XMM0; unmasked modes expand it per element.
* `PMULLQ`, `PMINSQ`/`PMINUQ`, `PMAXSQ`/`PMAXUQ` are the REX.W/VEX.W1 forms;
  legacy encodings cannot express them.
* `PCMPEQ*`/`PCMPGT*` return all-ones per *element*, and the qword forms only
  exist with the 66 0F 38 map.
* `PUSHA`/`POPA` are decoded so a stray byte sequence stays aligned, then raise
  #UD exactly as long mode requires. The 16/32-bit push-all forms are not
  modelled because NINE has no compat-mode stack frame to apply them to.
* `RCL`/`RCR` with a count other than 1 leave OF undefined (as the SDM allows);
  a zero count changes neither the destination nor the flags.
* `PSADBW`, the horizontal families and `PHMINPOSUW` read the full 128-bit
  source; the narrowing `PMOVSX`/`PMOVZX` forms load only the bytes their lane
  count needs, so a load at a page boundary does not over-read.

### 2.19 Windows ABI boundary — callable shims

Before this change `Kernel32::resolve()` returned a *fake address* in the
`0x7ff0_xxxx` range. Nothing mapped that range, so a guest that actually
imported and called `CreateFileA` jumped into unmapped memory: imports were
"resolved" only for reporting.

`abi/WinAbi.{h,cpp}` replaces that with real guest code. Every export owns a
16-byte stub in an executable page:

```
49 89 CA        mov  r10, rcx        ; park arg0 (syscall clobbers RCX)
B8 <imm32>      mov  eax, 0x40000000 | id
0F 05           syscall
C3              ret
CC …            padding
```

* The stub performs **no stack adjustment**, so at dispatch time RSP still
  points at the caller's return address. The 5th+ arguments are exactly at
  `[rsp+0x28]`, `[rsp+0x30]`, … per the Microsoft x64 convention.
* The trap number lives in a reserved range (`WinAbi::kCallBase = 0x4000_0000`),
  far above every Linux syscall number. `ExecutionLoop::handleSyscall` offers
  the number to the ABI dispatcher first and falls through to the Linux
  translator otherwise.
* `WinCall` exposes the marshalled arguments (`iarg[4]`, `sarg[4]`, `farg[4]`),
  bounds-checked guest memory, ANSI/UTF-16 string readers and writers, and a
  floating return path (XMM0) alongside the integer one (RAX).
* `WinAbi::callGuest` is the inverse direction: it pushes a sentinel return
  address, fills the Win64 argument registers and stack, and interprets guest
  code until RET reaches the sentinel. That is the window-procedure / thread-
  entry / comparator path. It is bounded (depth 8, 4M steps) and does not yet
  unwind a guest exception across the native frame.
* Exports are registered with real handlers in `abi/Win32Exports.cpp`
  (kernel32 + kernelbase + ntdll) and `abi/OtherDlls.cpp` (user32/gdi32/
  advapi32). Unknown exports of a module NINE owns are bound to a logging stub,
  so the call is a safe no-op instead of a wild jump, and the log is the
  backlog. Unknown *modules* still resolve to 0.
* `PeImports::resolveAndPatch` and `RuntimeBridge::runPe` now patch the IAT with
  these thunks and install the dispatcher on the execution loop. `relink[PE]`
  distinguishes "stubbed" (callable, unimplemented) from "unresolved".

**Known gaps.** Varargs (`printf`-style) have no marshaller yet; by-value
structs larger than 8 bytes and `__m128` arguments are not decomposed; returns
in `ST(0)` (x87) are not modelled; `ExitProcess` is logged but does not tear
down the execution loop; and mixed-mode unwinding (guest throw through a native
shim frame) is still the exception-path work listed in §2.2 of LIBRARIES.md.

### 2.20 Scalar / system completion batch (RDTSC … XTEST)

The last of the non-vector x86-64 core. Everything below is a legacy encoding
unless the encoding column says VEX or XOP; `cc` selects a sub-operation where
one `X86Op` covers a family.

| Instruction | Encoding | Status |
|---|---|---|
| SAHF | 9E | 🟩 AH → SF/ZF/AF/PF/CF, OF untouched |
| RDTSC / RDTSCP | 0F 31 / 0F 01 F9 | 🟩 monotonic 2.5 GHz-equivalent counter; RDTSCP also clears ECX (TSC_AUX = 0) |
| RDSEED | 0F C7 /7 | 🟩 xorshift entropy, CF=1 |
| SQRTPS / SQRTPD / SQRTSS / SQRTSD | 0F 51, 66, F3, F2 | 🟩 scalar forms leave the upper lanes alone |
| SUBPS / SUBPD / SUBSS / SUBSD | 0F 5C by mandatory prefix | 🟩 |
| UNPCKLPS / UNPCKLPD / UNPCKHPS / UNPCKHPD | 0F 14 / 15, 66 0F 14 / 15 | 🟩 `UNPCKF`, cc 0 = low, 1 = high |
| ROUNDPS / ROUNDPD / ROUNDSS / ROUNDSD | 66 0F 3A 08 / 09 / 0A / 0B ib | 🟩 imm8[1:0] = nearest-even / floor / ceil / truncate |
| RSQRTPS / RSQRTSS | 0F 52 / F3 0F 52 | 🟩 exact 1/√x (hardware only promises an approximation) |
| SHLD / SHRD | 0F A4 / A5 / AC / AD (imm8 or CL) | 🟩 CF from the last bit out, OF only for a count of one, count 0 changes nothing |
| RORX | VEX.F2.0F3A.F0 ib | 🟩 rotate without flags |
| SHLX / SARX / SHRX | VEX.66/F3/F2.0F38.F7 | 🟩 count from VEX.vvvv, no flags |
| UCOMISS / UCOMISD | 0F 2E / 66 0F 2E | 🟩 ZF/PF/CF only, unordered reads as ZF=PF=CF=1 |
| SHA1MSG1 / SHA1MSG2 / SHA1NEXTE | 0F 38 C9 / CA / C8 | 🟩 SDM schedule arithmetic |
| SHA1RNDS4 | 0F 3A CC ib | 🟩 four rounds, imm8[1:0] picks f() and K |
| SHA256MSG1 / SHA256MSG2 | 0F 38 CC / CD | 🟩 σ0/σ1 schedule arithmetic |
| SHA256RNDS2 | 0F 38 CB, implicit XMM0 | 🟩 two rounds, round constants from XMM0[63:0] |
| STMXCSR / LDMXCSR | 0F AE /3, /2 | 🟩 MXCSR is live; VEX forms decode too |
| XSAVE / XSAVEOPT / XSAVEC | 0F AE /4, 0F AE /6, 0F C7 /4 | 🟩 512-byte FXSAVE image + 64-byte header, XSTATE_BV = 3 (x87\|SSE) |
| XRSTOR | 0F AE /5 | 🟩 restores the legacy region |
| XSAVES / XRSTORS | 0F C7 /5, 0F C7 /3 | 🟩 #GP(0) — supervisor forms |
| XGETBV | 0F 01 D0 | 🟩 XCR0 = 3 |
| XSETBV | 0F 01 D1 | 🟩 #GP(0) at CPL 3 |
| XTEST | 0F 01 D6 | 🟩 ZF=1 (never in a transaction), CF=OF=0 |
| XBEGIN / XEND / XABORT | C7 F8 cd / 0F 01 D5 / C6 F8 ib | 🟩 every transaction aborts immediately to the fallback (ZF=1, EAX=0); XEND/XABORT are #UD outside one |
| SERIALIZE | 0F 01 E8 | 🟩 ordering no-op (single-threaded guest) |
| SGDT / SIDT | 0F 01 /0, /1 | 🟩 writes limit 0 / base 0 — no GDT or IDT is modelled |
| SLDT / STR | 0F 00 /0, /1 | 🟩 null selector |
| SMSW | 0F 01 /4 (reg or m16) | 🟩 CR0[15:0], zero-extended |
| VERR / VERW | 0F 00 /4, /5 | 🟩 ZF reflects the flat-model selectors |
| RDSSPD / RDSSPQ | F3 0F 1E /1 | 🟩 no-op with CET off (destination untouched) |
| RSTORSSP | F3 0F 01 /5 | 🟩 no-op with CET off |
| WRSSD / WRSSQ / WRUSSD / WRUSSQ | 0F 38 F6, 66 0F 38 F5 | 🟩 ordinary stores (no shadow stack to commit to) |
| TZMSK / T1MSKC | XOP.09.01 /4, /7 | 🟩 AMD TBM mask builders; the whole XOP prefix is decoded exactly |
| VZEROUPPER / VZEROALL | VEX.NP.0F 77 | 🟩 no-op — no upper YMM/ZMM state exists to clear |
| TPAUSE / UMONITOR / UMWAIT | 66/F3/F2 0F AE /6 | 🟩 hints; UMWAIT reports the timeout path in ZF |
| WRFSBASE / WRGSBASE | F3 0F AE /2, /3 | 🟩 writes `ctx.fs_base` / `gs_base` |
| RSM / SEAMCALL / SEAMOPS / SEAMRET | 0F AA / 66 0F 01 CF, CC, CD | 🟩 #UD outside SMM or the SEAM root module |
| SYSRET / SYSENTER / SYSEXIT / SWAPGS / WRMSR / WBINVD / WBNOINVD / STGI / CLGI | 0F 07, 34, 35, 01 F8, 30, 09, F3 09, 01 DC, 01 DD | 🟩 #GP(0) — ring-0 operations at CPL 3 |
| UD0 / UD1 | 0F FF / 0F B9 | 🟩 #UD |
| REP / REPE / REPZ / REPNE / REPNZ | F3 / F2 on A4-AF | 🟩 prefixes drive the repeat; the disassembly reads `rep stosb`, `repe cmpsb`, `repne scasb` |
| SETcc (all 16 + aliases) | 0F 90-9F | 🟩 primary mnemonics; SETC/SETZ/SETNZ/SETPE/SETPO decode to the same conditions |

**Notes and limits.**

* The string primitives were also fixed in this batch: the byte/word/dword
  forms were masking the accumulator to `size` *bits* rather than bytes, so a
  `STOSB` of `0xAA` stored 0 and `LODSW` loaded one bit. SCAS now honours
  REPE/REPNE (stop on the matching ZF sense) instead of breaking on ZF
  unconditionally.
* `RDTSC` is not a cycle counter. It returns a monotonic 2.5 GHz-scaled
  nanosecond value from the first read, which is enough for the pacing loops
  (`QueryPerformanceCounter`, `clock_gettime` fallbacks) real binaries use.
* The XSAVE image only covers x87 and SSE. `XSTATE_BV = 3` says exactly that,
  so a guest that asks for AVX state sees it unsupported rather than garbage;
  `XSAVES`/`XRSTORS` stay ring-0 and fault.
* SHA-1/SHA-256 are implemented from the SDM operation blocks and cross-checked
  against scalar FIPS 180-4 round functions in the host harness.
* `XBEGIN` models a machine whose transactions always abort. That is
  architecturally legal (the fallback path must work), it keeps RTM code
  correct, and it never silently loses a store. There is no retry loop.
* `SEAMCALL`/`SEAMOPS`/`SEAMRET` and `RSM` are #UD, not #GP, because they are
  only defined inside a different root mode.
* The V-prefixed AVX/AVX-512 forms are a separate batch — §2.21 below, which
  adds the 256/512-bit data path, the EVEX prefix and writemasks.

---

### 2.21 AVX / AVX2 / AVX-512

The vector ISA is one decoder table and one interpreter entry point, not a
mnemonic-per-enum explosion. `X86Op::VEC` carries a `VecOp` family, the lane
width, the numeric domain, the operating width and the writemask:

| Piece | Where | What it does |
|---|---|---|
| Register file | `GuestContext::ymm[32][64]` | 32 × 64 bytes; XMM = bytes 0-15, YMM = 0-31, ZMM = 0-63 of the same slot, so the architectural aliasing is free |
| Opcode table | `translator/VecTable.h` | 453 encoding rows keyed by map (0F/0F38/0F3A), opcode, mandatory prefix and W; plus the 0F 71-73 ModRM.reg group table |
| VEX decode | `translator/X86Decoder.cpp` | C4/C5 (2- and 3-byte), 128/256-bit, vvvv operand, map/pp/W |
| EVEX decode | same | 62 P0 P1 P2: R/X/B/R', W, vvvv[4:0], L'L, broadcast/rounding, z, aaa; `disp8×N` compression per tuple type (FV/HV/QV/EV/T1S/T1F/T2/T4/M128/…) |
| Semantics | `runtime/VecExec.cpp` | element-wise kernels over 8/16/32/64-bit lanes and f32/f64, shared writemask/zeroing/merge logic |
| Mask file | `GuestContext::kmask[8]` | k0-k7; k0 is never named by aaa and means "unmasked" |

The covered families (all VEX and EVEX widths where the ISA defines them):

* **Moves**: VMOV{UPS,UPD,APS,APD,DQA32/64,DQU8/16/32/64,SS,SD,D,DUP,SLDUP,SHDUP,HLPS,LHPS,LPS,HPS,NTPS,NTPD,NTDQ,NTDQA,MSKPS,MSKPD,MSKB}, VPBROADCAST{B,W,D,Q}, VBROADCAST{SS,SD,F128,I128}, VLDDQU.
* **FP arithmetic**: VADD/VMUL/VSUB/VDIV/VMIN/VMAX/VSQRT/VRCP/VRSQRT/VAND/VANDN/VOR/VXOR/VUNPCK/VSHUF/VCMP/VCOM/VUCOM/VHADD/VHSUB/VADDSUB/VROUND/VRNDSCALE/VRANGE/VREDUCE/VGETEXP/VGETMANT/VFIXUPIMM/VFPCLASS.
* **Integer**: VPADD/VPADD{S,US}/VPSUB/VPSUB{S,US}/VPAVG/VPMUL{LW,HW,HUW,LD,LQ,UDQ,DQ,HRSW}/VPMADDWD/VPMADDUBSW/VPMADD52/VPMIN/VMAX/VPABS/VPSIGN/VPACK/VPCMPEQ/VPCMPGT/VPCMP{B,W,D,Q,UB,UW,UD,UQ}/VPTEST/VPAND/VPANDN/VPOR/VPXOR/VPTERNLOG/VPSLL/VPSRL/VPSRA (+V forms, +DQ byte shifts)/VPSHUF{B,D,HW,LW}/VPERM{D,Q,PS,PD,B,W,I2,T2}/VPERM2{F,I}128/VPERMIL{PS,PD}/VPBLEND{D,W,VB}/VPALIGNR/VALIGN{D,Q}/VPINSR/VPEXTR/VINSERT/VEXTRACT{F,I}128/VPMOVSX*/VPMOVZX*/VPMOVMSKB/VPSADBW/VPHADD/VPHSUB/VPHMINPOSUW/VPUNPCK/VPEXPAND*/VPCOMPRESS*/VPCONFLICT/VPLZCNT/VPOPCNT/VPMULTISHIFTQB/VPMPSADBW/VPDPBUSD/VPDPBUSDS/VPDPWSSD/VPDPWSSDS.
* **Conversions**: VCVT{PS2PD,PD2PS,SS2SD,SD2SS,DQ2PS,PS2DQ,TPS2DQ,PD2DQ,TPD2DQ,DQ2PD,SI2SS,SI2SD,SS2SI,SD2SI,TSS2SI,TSD2SI,PH2PS,PS2PH} and the narrowing/widening VPMOV* family.
* **FMA**: VFMADD132/213/231, VFMSUB, VFNMADD, VFNMSUB, VFMADDSUB, VFMSUBADD — PS/PD/SS/SD.
* **Crypto**: VAESENC/VAESENCLAST/VAESDEC/VAESDECLAST/VAESIMC, VPCLMULQDQ, VGF2P8MULB, VGF2P8AFFINE{QB,INVQB}.
* **Memory**: VMASKMOVPS/PD, VPGATHER{DD,DQ,QD,QQ}, VGATHER{DPS,DPD,QPS,QPD}, VPSCATTER*/VSCATTER* with VSIB addressing (SIB.index names the vector index register).

**Notes and limits.**

* EVEX writemasks are applied uniformly: element-selected lanes from the
  result, the rest merged from the destination or zeroed with `{z}`. For
  gather/scatter the mask is also the completion mask and is cleared per
  successful element, as the SDM specifies.
* `VL` and the vector length are enforced by the table: scalar rows force 128
  bits, 512-bit-only rows reject shorter encodings, VEX-only and EVEX-only
  rows are separated so an EVEX-only opcode cannot be decoded from a VEX
  prefix (and vice versa).
* Rounding control (`{rn-sae}` etc.) is not modelled: MXCSR sits at its reset
  value, so conversions and VRNDSCALE use round-to-nearest-even unless the
  instruction carries an explicit imm8 mode. No exceptions are raised.
* The generic AVX-512 specials that are table-driven approximations are marked
  in the notes of their kernels: VFIXUPIMM implements the zero/NaN fix-up
  subset, VRANGE the imm[2:0] compare plus imm[4] min/max select, and the
  math-extension forms (VEXP2, VRCP28, VRSQRT28) use the exact IEEE result
  rather than the 2^-28 approximation silicon promises.
* DBT: `X86Op::VEC` is not translated to AArch64 yet, so blocks containing
  vector instructions take the existing interpreter fallback (the translator
  already marked unknown ops unsupported and let the runtime interpret them).

---

### 2.22 SGX: ENCLS / ENCLU / ENCLV

`0F 01 CF` (ENCLS), `0F 01 D7` (ENCLU) and `0F 01 C0` (ENCLV) decode to their
own opcodes; the leaf number is in EAX at run time and selects the operation.
The model lives in `runtime/Sgx.{h,cpp}`: a software EPCM (`SgxPage` per 4 KiB
page), an `SgxEnclave` record per SECS, and the architected RAX return codes
(0 = SGX_SUCCESS, otherwise the SGX_INVALID_* / SGX_PAGE_* codes).

| Leaf | Behaviour |
|---|---|
| ENCLS[ECREATE] | validates alignment, zeroes the SECS, seeds MRENCLAVE from base+size, inserts a blocked SECS page |
| ENCLS[EADD] / [EAUG] | adds TCS/REG pages (EAUG only to an initialized enclave, pending acceptance) |
| ENCLS[EEXTEND] | hashes a 256-byte chunk (offset in RCX) into MRENCLAVE |
| ENCLS[EINIT] | marks the enclave initialized, unblocks the SECS, writes MRENCLAVE to the SECS image |
| ENCLS[EREMOVE] | removes a page; removing the SECS destroys the enclave |
| ENCLS[EDBGRD] / [EDBGWR] | 8-byte debug read/write at page+offset (RAX = value on read) |
| ENCLS[EBLOCK] / [ETRACK] / [ETRACKC] / [EWB] | block, track and evict page state |
| ENCLS[ELDB] / [ELDU] / [ELDBC] / [ELDUC] | reload an evicted page |
| ENCLS[EPA] / [EMODPR] / [EMODT] / [ERDINFO] | version-array pages, permission/type changes, 64-byte page info |
| ENCLU[EENTER] / [ERESUME] | jumps to TCS.OENTRY (offset 0x18) after checking the enclave is initialized |
| ENCLU[EEXIT] | returns to the address in RBX |
| ENCLU[EGETKEY] | derives a deterministic 32-byte key from the KEYREQUEST at RCX |
| ENCLU[EREPORT] | fills the 432-byte report from the target info and MRENCLAVE |
| ENCLU[EACCEPT] / [EMODPE] / [EACCEPTCOPY] / [EDECCSSA] | accept pending pages, extend permissions, copy acceptance, decrement TCS.CSSA |
| ENCLV[EINCVIRTCHILD] / [EDECVIRTCHILD] / [ESETCONTEXT] | virtual-child counter and context word on the SECS |

**Privilege.** ENCLS and ENCLV are ring-0 instructions: at CPL > 0 they raise
#UD, which is what the SDM specifies and what a CPL-3 NINE guest sees. The
interpreter exposes `setSgxEnabled()` (model present at all) and
`setSgxRing0()` (allow the privileged leaves); the host harness and a future
ring-0 bring-up use the second. With the model off, all three instructions are
#UD, matching CPUID.SGX = 0.

---

## 3. Alignment to the coverage docs

- README carries the *visual* coverage grids (Windows ABI / Linux API / ISA), now including the **complete Windows system-DLL inventory** (≈80 app-linkable DLLs incl. kernelbase/win32u/api-ms-win-* API-sets) and the **complete Linux system-library inventory** (glibc family + GCC runtime + ecosystems listed per family).
- `LIBRARIES.md` carries the *named* per-API and per-syscall checklists.
- This file carries the *instruction* inventory + the runtime architecture rationale.
- `app/src/main/cpp/SUPPORTED.md` is the hard, enumerable contract (62 syscall arms with per-number behaviour, 14 ELF relocation types, PE directory consumers, and the AOT emitter opcode surface) — refreshed against the tree on 2026-10-25.
- `DevelopmentPlan.md` / `JITImplementationPlan.md` carry the phase status, including **J6** (relinker-side AOT translation: compiler/runtime/relink done, run-path wiring open).

**Maintenance rule:** any patch that adds/removes a guest-visible capability must update cells in AUTHOR-enclosing docs in the same commit. If the ISA cell you are flipping touches one row's mnemonic too — add a row to §2 here and flip the equivalent cell in README’s ISA grid in the same commit (details in REVERSE_TECHNIQUE.md "Coverage ledger maintenance").
