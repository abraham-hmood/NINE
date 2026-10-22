# NINE Reverse-Engineering Technique (AnyPS5-style)

Demand-driven binary surface discovery: inventory what a guest executable **actually** needs from the outside, implement that in NINE, then iterate on the next failure from logs. Prefer this over reimplementing entire OS/API sets up front.

## Core idea

| Guest has… | NINE provides… |
|------------|----------------|
| Code in the image (static libc, game logic) | DBT / interpreter — **run it** |
| Imports / `DT_NEEDED` (dynamic) | ABI shims or load+translate those modules |
| Syscalls / `Nt*` / IOCTLs | Thin host translations |
| GPU / window / audio APIs | Later host surfaces (only when imports demand them) |

**Do not** assume every binary needs a full private `printf`/`CreateFile` if that code is already inside the guest image. **Do** implement the **kernel/ABI boundary** and **process startup state**.

## Workflow

1. **Classify the binary**
   - ELF vs PE; 32 vs 64; static vs dynamic
   - ELF: `PT_INTERP`, `PT_DYNAMIC` / `DT_NEEDED`, `PT_TLS`, entry
   - PE: imports (IAT), subsystems, TLS directory

2. **Inventory external surface**
   - Dynamic: library list + imported symbols
   - Static: **no** shared libs — surface is **syscalls** (and Win32 if PE static with no imports is rare)
   - Scan for `syscall` / `int 0x80` / `svc` patterns; list likely numbers
   - Symbols/strings for hints (`main`, `puts`, `__libc_start_main`, `Hello, world!`)

3. **Map call chain to success**
   - e.g. `_start` → `__libc_start_main` → `main` → `puts` → `write` → `exit_group`
   - Identify what must exist **before** `main` (stack, auxv, TLS)

4. **Implement in priority order**
   - **P0**: process image (stack argc/argv/envp/auxv), TLS, syscalls that exit path needs (`write`, `exit_group`, `brk`, `mmap` family, `arch_prctl`, …)
   - **P1**: signals, futex, openat/close — as logs demand
   - **ISA gaps**: next `unimplemented: <mnemonic>` from the interpreter/JIT log

5. **Run → log → next gap**
   - Illegal opcode → extend decoder/interpreter/emitter
   - Missing syscall → extend `SyscallTranslator` / Windows ABI
   - Crash on null auxv/TLS → fix startup, not random libc functions

6. **Scale to large apps (Chrome, games)**
   - Same technique; import tables become large backlogs
   - Still **priority by first failure**, not “implement all of Win32”
   - GPU/GUI only when the binary’s imports/execution reach them

## Static ELF example (`hello` / glibc-static)

- **Libraries to reimplement as `.so`:** none (fully static)
- **In-image:** glibc (`puts`, `malloc`, stdio, …)
- **External contract:** Linux syscalls + startup:
  - Stack: `argc`, `argv`, `envp`, auxv (`AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_PAGESZ`, `AT_BASE`, `AT_ENTRY`, `AT_UID`, `AT_RANDOM`, `AT_NULL`, …)
  - `PT_TLS` template
  - Syscalls: `write`, `exit`/`exit_group`, `brk`, `mmap`/`mprotect`/`munmap`, `arch_prctl`, `set_tid_address`, then others as needed
- **Success metric:** log shows `stdout: Hello, world!` (or equivalent) then clean exit

## Dynamic ELF / PE

- List `DT_NEEDED` / import DLLs and symbols
- Either shim each symbol in NINE ABI, or load guest libraries into the same address space and translate them
- Kernel boundary still required underneath

## Anti-patterns

- Reimplementing all of glibc for a static binary
- Building a full kernel emulator when a thin syscall table suffices
- Ignoring auxv/TLS and only chasing opcodes
- Implementing GPU before `main` runs

## Log-driven loop

```
load → parse inventory → implement P0 env
  → run → capture GuestLog
  → if unimplemented opcode: decoder/interp
  → if bad syscall nr: syscall table
  → if SEGV in startup: stack/auxv/TLS/memory map
  → repeat until program goal (e.g. printed hello)
```

This is the **AnyPS5-style** approach: the binary teaches you the API surface; NINE grows only where execution proves it is required.

---

## Coverage ledger maintenance (AI contract)

Every color-coded coverage doc is part of the loop, not just documentation. When
you implement a new guest-visible surface � a Linux syscall, a Windows API, an
x86-64 instruction family, a PE component � you **must, in the same commit**:

1. Flip the affected cell(s) to ?? (implemented) / ?? (partial/stub) / ?
   (removed ? back to unimplemented) in:
   - **README.md � Coverage grids** (Windows ABI grid, Linux API grid, ISA grid)
   - **LIBRARIES.md** (per-API named checklists for Windows DLLs and Linux APIs)
   - **ARCHITECTURE.md** (per-instruction family ledger �2; add the new mnemonic
     rows properly marked, not as a footnote)
   - `app/src/main/cpp/SUPPORTED.md` where the item matches its original table
2. Update the "Count Snapshot" block at the bottom of LIBRARIES.md when the
   implemented-area *counts* change (e.g. kernel32 exports with real behavior,
   syscall numbers with full behavior).
3. Leave the cells that are still ? untouched � the grid is the backlog; the
   next model reading this file must be able to rediscover the not-yet-implemented
   surface directly from README's dark cells.

If a fix changed *decode behavior only* (e.g. a length fix, SIB fix, prefix
fix) with no new instruction, note it in ARCHITECTURE.md �2.12
("known decode quality fixes") instead of flipping cells.

Rule of thumb: **fix the binary first, then the ledgers**; never flip a cell
from spec reading alone � it is green only after the on-device run proves the
binary executes past that point (REVERSE_TECHNIQUE.md loop discipline).


