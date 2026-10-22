# NINE Phase 2 Implementation Plan
## Production JIT, Host Trampoline, and Extended Compatibility Surface

**Goal**: Replace the software interpreter as the primary execution engine with a production-quality dynamic binary translator that emits callable AArch64 machine code, wires a real host trampoline, and expands coverage toward Windows GUI / graphics and related surfaces — **entirely in-tree**, with **zero** dependence on Wine, Box64, QEMU, FEX, libHoudini, or any other external compatibility layer.

**Invariant**: Every line of guest-facing compatibility code lives under `app/src/main/cpp/`. Third-party libraries are limited to host infrastructure already used (Android NDK, llama.cpp for the AI UI path). No PE/ELF compatibility is outsourced.

**Prerequisite**: Phase 0–8 of `DevelopmentPlan.md` (loaders, linker, interpreter-backed execution loop, multi-threading, hardening) are the foundation this plan builds on.


---

## Status Legend (audited against current tree)

| Mark | Meaning |
|------|---------|
| 🟢 | **Fully implemented** — meets the phase exit criteria as written |
| 🟡 | **Partially implemented** — real code exists; exit criteria not fully met |
| ⬜ | **Not started** |

Last audit: 2026-10-16.

### Phase rollup (JIT plan)

| Phase | Title | Status |
|-------|-------|--------|
| J1 | Host trampoline & callable blocks | 🟢 (1.4 exit criteria 🟡 pending device proof) |
| J2 | Full AArch64 emitter & coverage | 🟢 (2.3 🟡 until on-device hello %) |
| J3 | Traces & optimizations | 🟢 (3.4 🟡 until measured) |
| J4 | Persistent cache & MT JIT safety | 🟢 (4.3 🟡 until device stress) |
| J5 | App integration | 🟢 (5.4 🟡 until hello on device) |
| G1 | Windows GUI | ⬜ |
| G2 | D3D/Vulkan translation | ⬜ |
| K1 | Kernel research | ⬜ |
| A1 | 32-bit guests | ⬜ |
| C1 | Compatibility depth | 🟡 |
| K2 | User-mode drivers (no root) | ⬜ |

---

## 0. Architecture Target

```
┌──────────────────────────────────────────────────────────────────┐
│  Guest x86-64 code (ELF / PE)                                    │
│       │ decode                                                   │
│       ▼                                                          │
│  X86Decoder → IR (Insn)                                          │
│       │                                                          │
│       ├─► InsnInterpreter (fallback / cold path / debug)         │
│       │                                                          │
│       └─► Translator → AArch64 machine code                      │
│               │                                                  │
│               ▼                                                  │
│         CodeCache (W^X, persistent)                              │
│               │                                                  │
│               ▼                                                  │
│    HostTrampoline: load GuestContext → call host_code → store   │
│               │                                                  │
│               ▼                                                  │
│    Exit reasons: SYSCALL / IMPORT / EXCEPTION / HALT             │
│               │                                                  │
│               ▼                                                  │
│    ABI layer (Linux syscalls / ntdll / kernel32 / …)             │
└──────────────────────────────────────────────────────────────────┘
```

**Non-negotiable**: when a translated block is present and not stale, the execution loop **jumps to it**. The interpreter remains only for:
- un-translated opcodes (progressive coverage),
- single-step / debugger mode,
- validation (differential testing against JIT).

---

## 1. Phase J1 — Host Trampoline & Callable Blocks  🟢

**Objective**: Make every `CodeCache` entry invocable as a real function that reads/writes `GuestContext`.

### 1.1 Calling convention  🟢
- Host entry: `void (*)(GuestContext* ctx)` (or equivalent with a fixed register: e.g. `X0 = ctx`).
- Prologue (emitted by translator or a fixed stub):
  - Spill callee-saved host regs as required by AAPCS64.
  - Load guest GPRs from `ctx->gpr[]` into the pinned host mapping (X21–X28 hot set, X9–X15 scratch).
  - Load `ctx->rip` / flags into X19 / X20 (existing `RegisterAllocator` pins).
- Epilogue:
  - Store host regs back into `ctx->gpr[]`, flags, RIP.
  - Return to the C++ execution loop.

### 1.2 Block exit protocol  🟢
Translated blocks must not fall off the end. Every block ends with one of:
- **Direct branch** → patchable branch/veneer to another cached block (or exit to loop on miss).
- **Indirect branch / RET** → lookup helper (inline cache + slow path into `ControlFlow::lookupIndirect`).
- **Syscall / import** → store exit reason + args into a side channel or fixed ctx fields, then `RET` to trampoline.
- **Exception** → same, with exception code.

### 1.3 ExecutionLoop change  🟢
```
lookup(pc) → if host_code:
    trampoline(ctx, host_code)
    switch (ctx.exit_reason) { SYSCALL / IMPORT / EXCEPTION / CONTINUE }
else:
    translate OR interpret one block
```

### 1.4 Exit criteria  🟡
- A pure-register x86 block (ADD/SUB/MOV/JMP) runs **only** via JIT (interpreter disabled) and leaves correct `GuestContext`.
- Syscall exit from a translated block reaches `SyscallTranslator` and resumes into JIT.

---

## 2. Phase J2 — Full AArch64 Emitter & Instruction Coverage  🟢

**Objective**: Grow the translator from “sample encodings” to coverage sufficient for real user-mode binaries.

### 2.1 Emitter completeness  🟢
- Integer ALU (all sizes 8/16/32/64), shifts, rotates, LEA, PUSH/POP, CALL/RET.
- Conditional moves and setcc.
- Memory operands (SIB, RIP-relative, scaled index) with correct effective-address sequences.
- SSE/AVX subset used by glibc / msvcrt (MOVAPS/D, basic arith, XORPS zeroing). Extend via VEX path already stubbed in the decoder.
- Atomic ops (LOCK prefix) using AArch64 `LDAXR`/`STLXR` or `LDADD` where available.
- Flags: either materialize into `RFLAGS` at block end, or keep lazy producers and only spill when a consumer is emitted (match `FlagState`).

### 2.2 Coverage process  🟢
1. Inventory opcodes from real targets (static `hello`, dynamic with libc, simple PE console).
2. For each missing opcode: decoder case → IR → emitter → unit test (host-side if possible, else on-device native test).
3. Differential test: same block through interpreter vs JIT; assert identical `GuestContext`.

### 2.3 Exit criteria  🟡  
*(Infrastructure: OpcodeCoverage + differential native test `j2`, JIT hit counters. On-device glibc/PE hello >95% cache-hit not yet proven in CI — mark green when measured.)*
- glibc-linked “hello world” ELF reaches `write` via JIT-dominated execution (>95% of blocks from cache hits).
- PE console “hello” reaches `WriteFile` similarly.

---

## 3. Phase J3 — Trace Compilation & Optimizations  🟢

**Objective**: Move beyond single basic blocks.

### 3.1 Traces  🟢
- Record hot paths of chained blocks (edge counters in `ControlFlow`).
- Linearize a hot trace into one translation unit with fall-through, reducing trampoline exits.
- Guard exits on side exits (bail to interpreter or re-translate).

### 3.2 Register caching across blocks  🟢
- Keep hot GPRs in host registers across direct-linked blocks when the mapping is stable.
- Spill only at trace exits / syscall boundaries.

### 3.3 IC / PLT / IAT  🟢
- Fast path for repeated indirect calls (import stubs, vtables).
- Patch PLT/IAT trampolines to direct host helpers where the ABI layer owns the function.

### 3.4 Exit criteria  🟡  
*(Counters: trampolineCrossings, traceHits, icHits — measure on device.)*
- Measurable reduction in trampoline crossings on a CPU-bound guest workload (document numbers in counters).

---

## 4. Phase J4 — Persistent Cache & Multi-thread JIT Safety  🟢

### 4.1 Persistent cache (extend Phase 8)  🟢
- Key entries by `(guest image identity, content hash, translator version)`.
- Load on process start; validate hashes before use.
- Store under app-private storage only.

### 4.2 Concurrent translation  🟢
- Per-thread translation buffers; publish into shared `CodeCache` under lock.
- No thread executes a block until `install` has completed and I-cache is cleaned (`__builtin___clear_cache` / `__clear_cache`).
- SMC: existing page invalidation must also drop persistent entries for that range.

### 4.3 Exit criteria  🟡  
*(Native test `j4` covers concurrent install + warm load; stress on device for full green.)*
- Two guest threads translating disjoint code regions without races (stress test).
- Cold start with warm persistent cache skips re-translation of known blocks.

---

## 5. Phase J5 — App Integration (UI → Runtime)  🟢

**Objective**: The Compose UI is not a mock; it drives the real runtime.

### 5.1 Load path  🟢
- “Load New Program” → detect ELF vs PE → `ElfLoader` / `PeMapper` → map into `MemoryManager` → set up stack/auxv or PEB/TEB → `ExecutionLoop::run`.
- Status card shows live counters (blocks, hits, syscalls, SMC invalidations).

### 5.2 Logs & debugger  🟢
- Stream `Logger` categories into the Logs tab.
- DebuggerActivity: pause, single-step (force interpreter), inspect `GuestContext`, breakpoints (INT3 or PC match).

### 5.3 Background execution  🟢
- Guest process runs on a dedicated host thread pool owned by `Threading`.
- UI never blocks on the interpreter/JIT; use coroutines + shared state.

### 5.4 Exit criteria  🟡  
*(UI load path + GuestLog stdout capture present; full static hello on device still the proof.)*
- User can load a static Linux hello ELF from storage and see stdout in Logs without any external translator.

---

## 6. Phase G1 — Windows GUI Subsystem (beyond minimal stubs)  ⬜

*Former non-goal; now a planned expansion. Still **no Wine**.*

### 6.1 Scope (user-mode only)  ⬜
- `user32` / `gdi32` / `gdiplus` surface sufficient for:
  - Message loop (`GetMessage` / `PeekMessage` / `DispatchMessage`)
  - Window creation (`CreateWindowEx`) mapped to an Android `SurfaceView` or Compose-hosted surface
  - Basic GDI (`BitBlt`, `TextOut`, simple brushes) rendered into a software framebuffer, then uploaded to the surface
- Coordinate system, DPI, and input (touch → mouse messages) translation owned by NINE.

### 6.2 Explicitly out of scope for G1  ⬜
- Full visual parity with every Windows theme.
- Accessibility APIs, IME completeness (can be G2).

### 6.3 Exit criteria  ⬜
- A simple Win32 “Hello GUI” (RegisterClass + CreateWindow + message loop + TextOut) displays text on-device.

---

## 7. Phase G2 — Graphics: Direct3D / Vulkan Translation  ⬜

*Former non-goal; planned as a long-horizon phase. Still **no external translator**.*

### 7.1 Strategy  ⬜
- Intercept D3D9/11/12 and Vulkan entry points at the PE import / `GetProcAddress` boundary.
- Map to **host Vulkan** (Android) or GLES where Vulkan is unavailable.
- Resource lifetime, shaders (DXBC/DXIL → SPIR-V **in-tree** or documented subset), and presentation (`IDXGISwapChain` → ANativeWindow) are NINE code.

### 7.2 Phased sub-milestones  ⬜
1. Device/adapter enumeration + empty present (black frame).
2. Fixed-function / simple triangle path.
3. Shader pipeline for a constrained HLSL/DXBC subset.
4. Widen API coverage by demand from target titles.

### 7.3 Exit criteria  ⬜
- A minimal D3D11 sample (clear + present, then a triangle) runs through NINE’s own mapping layer.

---

## 8. Phase K1 — Kernel-Mode Research Track (Optional / Separate)  ⬜

*Former non-goal. Not required for user-mode goals.*

- User-mode NINE will **not** load kernel drivers in-process.
- If ever pursued: a separate design for a host kernel module or hypervisor is required; it is **not** part of the app’s user-mode DBT mandate.
- This phase exists only so the roadmap acknowledges the boundary; default is **do not implement**.

---

## 9. Phase A1 — 32-bit Guests  ⬜

*Former non-goal; now scheduled after 64-bit JIT is solid.*

### 9.1 Work items  ⬜
- x86 (IA-32) decoder path alongside x86-64.
- 32-bit ELF (EM_386) and PE32 loaders (existing PE parser extended).
- Compatibility: `int 0x80` syscalls, WoW64-like thunking **only if** running 32-bit Windows guests on the 64-bit Windows ABI layer — prefer native 32-bit Linux ABI first.
- Register file: 32-bit views of GPRs; no REX.

### 9.2 Exit criteria  ⬜
- 32-bit static Linux hello works through the same trampoline/JIT design.

---

## 10. Phase C1 — Compatibility Depth (Not Bug-for-Bug)  🟡

*Former non-goal of “perfect bug-for-bug with every Windows version” remains rejected. This phase defines a practical alternative.*

### 10.1 Principles  🟡
- Document supported Windows API sets and Linux syscall numbers (`SUPPORTED.md`).
- Version-gate PEB/TEB fields and `Rtl*` behaviours to a chosen baseline (e.g. Win10 user-mode).
- Where apps rely on undefined behaviour, prefer **documented NINE behaviour** over chasing every quirk.
- Maintain a corpus of target apps and CI-like on-device smoke tests.

### 10.2 Exit criteria  ⬜
- Compatibility matrix published; regressions tracked against the corpus, not against “every Windows binary ever.”

---

## 11. Testing Strategy (JIT-era)

| Layer | Method |
|-------|--------|
| Emitter unit | Encode known sequences; disassemble with LLVM/objdump offline |
| Differential | Interpreter vs JIT on random and corpus blocks |
| Integration | Static/dynamic ELF, PE console, multi-thread futex |
| UI | Load program → observe Logs + counters |
| Stress | SMC under concurrent threads; cache grow/seal; persistent reload |
| Graphics (G2) | Golden-frame compares for clear/triangle |

Fuzz decoder and loader continuously; never require an external emulator to validate NINE.

---

## 12. Milestones

| ID | Deliverable | Depends on |
|----|-------------|------------|
| J1 🟢 | Callable trampoline; JIT executes ALU/branch blocks | Current runtime |
| J2 🟢 | Coverage for hello ELF + PE console via JIT | J1 |
| J3 🟢 | Traces + cross-block reg caching | J2 |
| J4 🟢 | Concurrent JIT + persistent cache keyed by image | J2 |
| J5 🟢 | UI drives real load/execute/debug | J2 |
| G1 ⬜ | Minimal Win32 GUI on Android surface | J5 + Windows ABI |
| G2 ⬜ | D3D/Vulkan subset → host Vulkan | G1 |
| A1 ⬜ | 32-bit Linux guests | J2 |
| C1 🟡 | Compatibility matrix + corpus | J5 |
| K1 ⬜ | Explicitly deferred (host ring-0) | — |
| K2 ⬜ | User-mode driver framework (+ optional AVF) | J5 |

---

## 13. Explicit Constraints (Carried Forward)

- **No Wine, Box64, QEMU, FEX, libhoudini, or similar.**
- **No kernel drivers** in the default product (see K1).
- **User-mode only** for all shipping phases except a possible future K1 research track.
- All PE/ELF/ABI/JIT code is first-party under this repository.

---

## 14. Immediate Next Step

1. Land the `CLONE_*` → `NINE_CLONE_*` build fix (this change set).
2. Implement **Phase J1**: fixed trampoline + translator prolog/epilog that load/store `GuestContext`, and switch `ExecutionLoop` to call `host_code` when present.
3. Add a differential test (interpreter vs JIT) for a hand-crafted ADD/JMP block.

---

*This plan extends NINE from an interpreter-backed user-mode runtime into a self-contained production DBT capable of Linux and Windows user-mode programs, with optional later tracks for GUI, graphics, and 32-bit guests — without ever outsourcing translation to an external compatibility stack.*

---

## 15. Phase K2 — Optional: Driver Compatibility Without Root (User-Mode + Platform-Allowed Paths)  ⬜

**Status**: Optional, long-horizon. Does **not** require root, custom ROMs, or modifying the Android kernel.

### 15.1 Hard platform facts (why true ring-0 is impossible here)

An unprivileged Android app **cannot**:
- insert a `.ko` / `.sys` into the Android kernel,
- execute privileged (ring-0) instructions,
- map arbitrary physical MMIO,
- or “natively” become a kernel driver of any ring.

Those actions require capabilities the Play-compatible sandbox does not grant. Any design that claims otherwise without OEM privileges is incorrect.

What **is** possible without root:

| Mechanism | What it gives you | What it does not |
|-----------|-------------------|------------------|
| **User-mode driver framework (UMDF-style shims)** | Apps that `CreateFile(\\.\X)`, `DeviceIoControl`, or load a companion “driver” for API access can run if NINE implements the device interface in process | Real interrupt handlers, DMA, privileged ops |
| **Android USB Host / HID / USB accessories** | Talk to physical USB devices the user authorizes | Windows kernel USB stack parity |
| **Standard NDK + system services** | Camera, sensors, GPU via Vulkan/GLES, audio | Arbitrary kernel modules |
| **Android Virtualization Framework (AVF / pKVM)** on supported devices | Isolated guest VM with its own kernel **inside the VM** (still not the host Android kernel) | Universal availability; loading Windows `.sys` into *Android’s* kernel |

### 15.2 Design: NINE User-Mode Driver Framework (UMDF)

Goal: when a guest Windows program “loads a kernel driver” or opens a device object, NINE satisfies it **in user mode** so the **application** keeps working.

```
Guest PE
  │ LoadLibrary("foo.sys") / NtLoadDriver / CreateService
  ▼
NINE Driver Manager (user-mode)
  │  does NOT map code as ring-0
  │  registers a virtual DEVICE_OBJECT / symbolic link
  ▼
Guest opens \\.\Foo
  ▼
DeviceIoControl / ReadFile / WriteFile
  ▼
NINE dispatch table → first-party C++ handlers
  │  (USB via Android USB Host API, files, sockets, GPU, …)
  ▼
Result codes / buffers back to guest
```

**Components (all in-tree under `abi/drivers/` or similar)**:
1. **Driver catalog** — map known driver names / hardware IDs to shim modules.
2. **Service control manager stub** — `CreateService` / `StartService` record state only; no kernel load.
3. **Object manager** — symbolic links (`\Device\`, `\DosDevices\`) → handle table entries.
4. **IRP/IOCTL dispatcher** — implement the IOCTL codes required by target apps.
5. **USB/HID bridge** — optional shim that uses Android USB Host (user grants permission).
6. **Fail closed** — unknown drivers: log, return `STATUS_NO_SUCH_DEVICE` / equivalent, never pretend ring-0 succeeded.

### 15.3 Linux “kernel module” analogue

For Linux guests that `insmod` or open `/dev/*`:
- **Do not** call host `init_module`.
- Map common `/dev` nodes to Android-accessible resources (null, zero, urandom, ashmem-like regions, USB).
- `mmap` of device memory only where the host exposes an allowed fd.

### 15.4 Optional AVF path (device-dependent, still no host-kernel module load)

On devices with AVF:
- Spin a minimal VM for workloads that truly need a guest kernel.
- That kernel is **inside the VM**, isolated from Android’s kernel.
- Windows/Linux drivers load **in the VM’s kernel**, not in Android’s — still first-party orchestration from the app, still no root on the host.
- Treat as a separate backend behind the same “load program” UI; not required for the default path.

### 15.5 What “any ring variety” means under this phase

| Guest expectation | NINE behavior |
|-------------------|---------------|
| Ring 3 app calling Win32/Linux APIs | Existing user-mode ABI (default product) |
| App + companion `.sys` talking via IOCTL | UMDF shims (this phase) |
| True ring-0 in **Android** kernel | **Not possible** without OEM/root — out of scope |
| True ring-0 in **AVF guest** kernel | Optional AVF backend only where hardware supports it |

### 15.6 Implementation steps (when scheduled)

1. Handle table + `\Device\` / `\DosDevices\` object namespace.
2. `NtCreateFile` / `CreateFileW` path for device opens.
3. `DeviceIoControl` dispatch with a plugin interface for shims.
4. First shims: null device, serial-over-USB (Android USB), shared-memory buffer device for testing.
5. Catalog + logging UI so users see “driver X emulated / unsupported”.
6. (Optional) AVF detection and backend switch.

### 15.7 Exit criteria

- A sample Win32 program that opens `\\.\NineNull` and issues an IOCTL succeeds entirely in user mode.
- A program that requires an unknown `.sys` fails cleanly with a logged reason (no crash, no fake success).
- No path in the default build requests root, loads a host kernel module, or depends on a custom ROM.

### 15.8 Explicit non-claim

This phase **does not** make Android run arbitrary Windows/Linux kernel drivers at true ring-0 on the host. It makes **applications that expect drivers** runnable by **emulating the driver interface in user mode** (and, optionally, inside an AVF VM on capable devices). That is the maximum compatible with unrooted Android and NINE’s “no external compatibility stack” rule.

---

*End of Phase K2.*
