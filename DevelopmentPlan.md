# NINE Development Plan
## Comprehensive ELF Loader, PE Loader, Dynamic Binary Translator, ISA Translator, and Linker

**Goal**: A near fully-fledged system capable of loading and executing x86-64 Linux ELF binaries and Windows PE binaries on an ARM64 Android host via dynamic binary translation, with custom loaders and a custom dynamic linker. No reliance on Wine, Box64, QEMU, or other external compatibility layers.

**Target host**: Android (ARM64 / AArch64), API 26+.
**Guest architectures**: x86-64 (primary). Future extension points for others.
**Scope**: User-mode only. No kernel drivers.

This plan is intentionally detailed. Each phase builds production-quality components rather than throwaway prototypes.


---

## Status Legend (audited against current tree)

| Mark | Meaning |
|------|---------|
| 🟢 | **Fully implemented** — production-usable for the scoped exit criteria |
| 🟡 | **Partially implemented** — real code exists; coverage or edge cases incomplete |
| ⬜ | **Not started** |

Last audit: 2026-10-25.

### Phase rollup (DevelopmentPlan)

| Phase | Title | Status |
|-------|-------|--------|
| 0 | Foundations | 🟢 |
| 1 | ELF Loader | 🟡 |
| 2 | Dynamic Linker | 🟡 |
| 3 | DBT (decoder/cache/interp + partial JIT + AOT emitter) | 🟡 |
| 4 | PE Loader | 🟡 |
| 5 | Linux ABI | 🟡 |
| 6 | Windows ABI | 🟡 |
| 7 | Integration & Runtime | 🟡 (9.1–9.3 🟢; 9.4 🟡) |
| 8 | Hardening & Completeness | 🟡 |

---

## 1. Overall Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Android Host Process                     │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │   UI / App  │  │  DBT Engine  │  │  ABI Compatibility  │ │
│  │  (Compose)  │  │ (x86-64→ARM) │  │  Layer (Linux/Win)  │ │
│  └──────┬──────┘  └──────┬───────┘  └──────────┬──────────┘ │
│         │                │                     │            │
│  ┌──────▼────────────────▼─────────────────────▼──────────┐ │
│  │              Memory Manager & Code Cache                │ │
│  └──────────────────────────┬─────────────────────────────┘ │
│                             │                               │
│  ┌──────────────────────────▼─────────────────────────────┐ │
│  │         Loaders (ELF + PE) + Dynamic Linker             │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**Core modules** (to be implemented as separate compilation units / packages):

- `dbt/` — Decoder, translator, encoder, code cache, register allocator
- `loader/elf/` — ELF64 parser, mapper, relocator
- `loader/pe/` — PE/COFF parser, mapper, import resolver
- `linker/` — Symbol resolution, dependency loading, GOT/PLT/IAT management
- `abi/linux/` — Linux x86-64 syscall translation to host
- `abi/windows/` — Minimal-to-comprehensive ntdll/kernel32 surface
- `memory/` — Guest address space, host mappings, executable pages
- `runtime/` — Threading, TLS, exception handling glue

---

## 2. Phase 0 — Foundations (Week 1)  🟢

### 2.1 Project Structure  🟢
### 2.2 Memory Manager  🟢
### 2.3 Logging & Diagnostics  🟢

**Exit criteria**: Can allocate guest VA ranges and map them executable on device.  🟢

---

## 3. Phase 1 — ELF Loader (Comprehensive)  🟡

### 3.1 ELF64 Parsing  🟢
- Full header validation (EI_MAG, class, data, version, machine = EM_X86_64).
- Program header table walk (PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_TLS, PT_GNU_STACK, PT_GNU_RELRO).
- Section header table (for symbols, strings, relocations when not fully dynamic).
- Support both ET_EXEC and ET_DYN (PIE).

### 3.2 Loading & Mapping  🟡
- Map PT_LOAD segments at correct guest VAs with correct permissions.
- Handle p_align, zero-fill BSS.
- Apply GNU_RELRO (make specified ranges read-only after relocation).
- TLS template extraction (PT_TLS) and per-thread allocation later.

### 3.3 Dynamic Section  🟢
- Parse DT_NEEDED, DT_SONAME, DT_RPATH/DT_RUNPATH, DT_SYMTAB, DT_STRTAB, DT_RELA, DT_RELASZ, DT_JMPREL, DT_PLTRELSZ, DT_INIT/DT_FINI, DT_INIT_ARRAY, etc.
- Build dependency list.

### 3.4 Relocation Processing  🟡
- Support all common x86-64 relocations:
  - `R_X86_64_64`, `R_X86_64_PC32`, `R_X86_64_GOTPCREL`, `R_X86_64_PLT32`
  - `R_X86_64_GLOB_DAT`, `R_X86_64_JUMP_SLOT`
  - `R_X86_64_RELATIVE`, `R_X86_64_IRELATIVE`
  - `R_X86_64_DTPMOD64`, `R_X86_64_DTPOFF64`, `R_X86_64_TPOFF64` (TLS)
- Apply relocations after symbol resolution.
- Lazy binding support via PLT (initially eager; lazy optional later).

### 3.5 Symbol Tables  🟡
- Parse `.dynsym` / `.symtab` + string tables.
- Handle symbol visibility (STV_DEFAULT, STV_HIDDEN, etc.), binding (STB_GLOBAL, STB_WEAK, STB_LOCAL).
- Versioned symbols (VERSYM, VERNEED, VERDEF) — required for real glibc binaries.

**Exit criteria**: Load a static or simple dynamic x86-64 ELF, map it, apply relocations, and transfer control to its entry point (even if it immediately faults on syscalls).

---

## 4. Phase 2 — Dynamic Linker  🟡

### 4.1 Module Graph  🟢
- Represent each loaded ELF/PE as a Module with its own symbol table, base address, and dependency list.
- Topological load order (dependencies before dependents).

### 4.2 Symbol Resolution  🟡
- Breadth-first or dependency-order search.
- Support weak symbols, versioned symbols, and interposition.
- Cache resolved symbols.

### 4.3 GOT / PLT / IAT Management  🟡
- For ELF: Populate GOT, rewrite PLT entries or use lazy resolver stub.
- For PE: Build and patch the Import Address Table.
- Provide a resolver callback that the DBT can invoke on first call.

### 4.4 Search Paths  🟢
- Guest `LD_LIBRARY_PATH` equivalent + embedded RPATH/RUNPATH.
- Host-provided system library directory for reimplemented libs.

**Exit criteria**: Load a binary that depends on `libc.so.6` and `libm.so.6` (using our stubs) and resolve all symbols.

---

## 5. Phase 3 — ISA Translator & DBT Engine (Core)

### 5.1 x86-64 Decoder  🟢
- Full decoder for user-mode x86-64 (including VEX/EVEX for AVX/AVX2; AVX-512 optional later).  *(Delivered: VEX AVX/AVX2 and EVEX AVX-512 — zmm16-31, k-masks, broadcast, disp8×N — decode into the same `X86Op::VEC` IR, 453 encoding rows. `ARCHITECTURE.md` §2.21 lists what remains: SAE/ER.)*
- Handle prefixes, ModR/M, SIB, RIP-relative, immediates.
- Produce a clean IR or directly drive the encoder.
- Recommended: structured IR (opcodes + operands) for easier analysis.

### 5.2 Register Allocation & Mapping  🟡
- Map x86-64 GPRs (RAX–R15, RIP, RFLAGS) onto ARM64 registers with spilling.
- Dedicated host registers for guest RIP, flags, and a scratch pool.
- Handle x86-64’s fewer registers vs ARM64’s larger set (advantage) while managing flag dependencies.

### 5.3 Flag Handling  🟡
- Lazy flag computation (do not materialize RFLAGS unless a later instruction reads them).
- Correct CF, ZF, SF, OF, PF, AF for arithmetic/logic ops.

### 5.4 Translation Units  🟡
- Translate at basic-block granularity (end at branch, call, return, or system call).
- Support trace formation later for better optimization.
- Emit ARM64 code with proper literal pools and veneers for long branches.

### 5.5 Control Flow  🟡
- Direct branches: patch or use relative offsets.
- Indirect branches / returns: inline cache or hash table lookup into code cache.
- Calls: maintain guest stack discipline; optional shadow stack for diagnostics.
- Syscalls / interrupts: exit to ABI layer.

### 5.6 Code Cache  🟢
- Growable executable region.
- Lookup by guest PC.
- Invalidation support (for self-modifying code — rare but must be detectable).
- Persistent cache optional later.

### 5.7 SIMD & Atomics  🟡
- Map SSE/AVX registers to NEON/SVE where possible; fallback to scalar or software for missing ops.
  *(Delivered for the interpreter: `runtime/VecExec.cpp` executes the full XMM/YMM/ZMM surface, x87 lives in `X87Exec.cpp`, AES/SHA/GFNI in `AesPrimitives.h`. The **JIT emitter** does not emit SIMD yet, so a block containing vector work falls back to the interpreter.)*
- Correct memory ordering for `lock` prefixes and atomic instructions (`mfence`, `lock cmpxchg`, etc.).  *(Fences retire as ordered no-ops for the single guest CPU model; true multi-core LOCK semantics are still 🟡 — `translator/SimdAtomics` is designed but not wired into the JIT.)*

### 5.8 Relinker-side AOT translation  🟢 *(new, added after this plan was written)*
- `aot/AotCompiler.cpp` compiles each executable range of a mapped, relocated ELF/PE ahead of time: one AArch64 function per basic block, guest state kept in `GuestContext` memory, all-or-nothing per module.
- `aot/AotImage.h` defines the on-disk image (header | blocks | helper relocations | code, FNV-1a over the code words); `aot/AotRuntime.cpp` maps it RW, patches helper addresses, `__clear_cache`, `mprotect` RX, and dispatches by guest PC with no decoder, code cache or SMC tracking.
- `aot/AotRelink.cpp` is driven from `RuntimeBridge::relinkElf`/`relinkPe` and writes `<stem>.<n>.nine.aot` next to the program; the relink JSON reports `aot.ok`, module/block/byte counts, and the blocking mnemonics.
- Coverage is the integer/flag/branch/memory subset (§4 of `SUPPORTED.md`); SSE/AVX, `IMUL`/`DIV`, string ops and x87 are refused by name.
- **Not done:** the run path (`ExecutionLoop`, light shell) does not yet prefer a `.nine.aot` image over the translator, and the emitter only produces self-contained images — it does not yet link guest relocations into native calls.

**Exit criteria**: Translate and execute simple arithmetic, branches, memory ops, and function calls in a test binary. Measure overhead.

---

## 6. Phase 4 — PE Loader (Comprehensive)  🟡

### 6.1 Parsing  🟢
- DOS header + e_lfanew.
- NT headers (FileHeader, OptionalHeader — PE32+).
- Section table with characteristics (executable, writable, discardable, etc.).
- Data directories: Import, Export, Relocation, TLS, Exception, Resource, Delay-Import, Bound Import.

### 6.2 Mapping  🟡
- Map sections at preferred ImageBase or relocated base.
- Apply section permissions.
- Handle section alignment vs file alignment.

### 6.3 Relocations  🟡
- Process base relocations (HIGHLOW, DIR64, etc.).
- Support ASLR-style rebasing.

### 6.4 Imports  🟡
- Walk Import Directory.
- Load dependent DLLs (recursively).
- Resolve and patch IAT (Import Address Table).
- Support delay-load imports.
- Bound imports (optional optimization).

### 6.5 Exports  🟢
- Parse Export Directory for when this module is itself a dependency.
- Forwarded exports.

### 6.6 TLS & Exceptions  🟡
- TLS directory: template, callbacks, index.
- Exception directory (pdata/xdata) — required for C++ EH and SEH. At minimum, parse and store; full unwinding later.
- SafeSEH / CFG awareness (can be stubbed initially but structure must exist).

**Exit criteria**: Load a simple PE that imports from `kernel32.dll`, resolve the imports against our stubs, and reach the entry point.

---

## 7. Phase 5 — Linux ABI Layer  🟡

### 7.1 Syscall Translation  🟡
- Map common x86-64 Linux syscalls to host equivalents or Android Bionic:
  - `read`, `write`, `openat`, `close`, `mmap`, `munmap`, `mprotect`, `brk`
  - `exit`, `exit_group`, `getpid`, `gettimeofday`, `clock_gettime`
  - `futex`, `clone` (threads — complex)
  - File descriptor table virtualization
- Unimplemented syscalls return `-ENOSYS` with logging.

### 7.2 vDSO & Auxiliary Vector  🟡
- Provide a minimal guest vDSO or handle `AT_*` entries in the auxiliary vector.
- Stack setup per System V ABI (argc, argv, envp, auxv).

### 7.3 Threading  🟡
- `clone` / `set_tid_address` / robust futexes.
- Guest TLS (FS segment on x86-64) mapped to host TLS or emulated.

**Exit criteria**: Run a statically-linked or lightly dynamic “Hello World” and a simple file I/O program.

---

## 8. Phase 6 — Windows ABI Layer (Foundational but Extensible)  🟡

### 8.1 ntdll Surface  🟡
- Process/thread environment block (PEB/TEB) structures.
- Basic heap (`RtlAllocateHeap`, etc.).
- Loader data table.
- Critical sections, SRW locks (initially simple).

### 8.2 kernel32 Surface  🟡
- `GetModuleHandle`, `GetProcAddress`, `LoadLibrary`
- `CreateFile` / `ReadFile` / `WriteFile` / `CloseHandle` (mapped to host file descriptors)
- `VirtualAlloc` / `VirtualFree` / `VirtualProtect`
- `GetLastError` / `SetLastError`
- `ExitProcess`
- Thread creation (`CreateThread`) — map to host threads with guest TEB

### 8.3 Other DLLs  🟡
- `kernelbase.dll` forwarding.
- Stubs for `user32`, `gdi32`, `advapi32` that log and return failure or minimal success so programs do not immediately crash.
- Expand only when a target binary requires a specific function.

### 8.4 Exception Handling  🟡
- Minimal SEH dispatcher that can unwind using the exception directory.
- C++ EH support is a later major milestone.

**Exit criteria**: A PE console program that calls `GetStdHandle` + `WriteFile` + `ExitProcess` runs to completion.

---

## 9. Phase 7 — Integration & Runtime  🟡

### 9.1 Execution Loop  🟢
- DBT lookup → translate on miss → execute translated block.
- Syscall / import call exits to ABI layer and returns.
- Signal / exception delivery from host to guest context.

### 9.2 Guest Context Switching  🟢
- Save/restore full guest register state (including XMM/YMM).
- Correct stack and red-zone handling.

### 9.3 Self-Modifying Code & Cache Coherency  🟢
- Detect writes to executable pages.
- Invalidate affected translations.

### 9.4 Multi-threading  🟡
- Shared code cache with proper mutex synchronization (CodeCache).
- Guest thread ↔ host thread 1:1 mapping (Threading::clone / createThread).
- Per-host-thread GuestContext via thread_local (ContextSwitch).
- CLONE_VM / CLONE_THREAD / CLONE_SETTLS / CLEARTID / SETTLD supported.
- Worker threads run ExecutionLoop::resume until exit / halt / exception.

**Exit criteria**: Concurrent guest threads can run simple workloads.  🟡

---

## 10. Phase 8 — Hardening & Completeness  🟡

- Full x86-64 instruction coverage audit (use existing test suites or generate random blocks).  🟡 (decoder + interpreter + partial JIT emitter)
- Relocation and symbol version stress tests.  🟡 (SUPPORTED.md + common reloc set; not exhaustive stress)
- Large address space and many-module stress tests.  🟡 (guards + region tracking present; limited stress harness)
- Performance counters and basic optimizations (trace compilation, register caching across blocks).  🟡 (ExecCounters + cache counters; no trace compilation yet — see JIT plan J3)
- Persistent translation cache.  🟢 (CodeCache::saveToFile / loadFromFile)
- Security: W^X where possible, guard pages, pointer authentication awareness on ARM64.  🟡 (W^X + guards; PAC not implemented)
- Documentation of every supported syscall, relocation type, and PE data directory.  🟢 (SUPPORTED.md refreshed against the tree: 62 syscall arms, 14 relocation types, PE directory consumers, AOT opcode surface — keep it in sync as coverage grows)

---

## 11. Testing Strategy

- Unit tests for decoder, relocator, PE parser (host-side).
- Integration tests: known-good small binaries (static hello world, dynamic with one libc call, simple PE).
- Differential testing against native execution where possible.
- Fuzz the decoder and loaders.
- Android instrumentation tests for the full pipeline.

---

## 12. Milestones (Suggested)

| Milestone | Deliverable | Target |
|-----------|-------------|--------|
| M1 | Memory manager + ELF loader (no DBT) | End of Phase 1 |
| M2 | Dynamic linker resolves multi-module ELF | End of Phase 2 |
| M3 | DBT executes arithmetic + branches | End of Phase 3 |
| M4 | PE loader + IAT patching | End of Phase 4 |
| M5 | Linux “Hello World” via full stack | End of Phase 5 |
| M6 | Windows console “Hello World” via full stack | End of Phase 6 |
| M7 | Multi-threaded guest + self-mod code handling | End of Phase 7 |
| M8 | Near-complete instruction & relocation coverage | End of Phase 8 |

---

## 13. Explicit Non-Goals (for this plan)

- Full DirectX / Vulkan translation
- Windows GUI subsystem beyond minimal stubs
- Kernel-mode code
- 32-bit guests (can be added later)
- Perfect bug-for-bug compatibility with every Windows version

---

## 14. Immediate Next Step (as of the 2026-10-25 audit)

Phases 0–8 are all in place at the 🟢/🟡 level above; the open work is depth, not
new subsystems:

1. **Finish the AOT path** (§5.8): load `.nine.aot` images in `ExecutionLoop` and
the light shell so a relinked program runs pre-compiled blocks, then extend the
emitter past its integer subset.
2. **JIT depth (J2/J3)**: emit SIMD (currently interpreter-only via `VecExec`)
and real LOCK/atomics, and prove >95% cache-hit execution for glibc `hello` on
device — the last J-phase exit criterion still marked 🟡.
3. **ABI depth demanded by real binaries**: real futex semantics, signal
delivery, `CLONE_CHILD_CLEARTID` writeback, `fork`/`execve`, and the ELF
relocation gaps listed in `SUPPORTED.md` §2.

---

*This plan is designed so that at completion the system is a coherent, extensible, near fully-fledged user-mode binary translation and compatibility environment rather than a collection of minimal demos.*
