# NINE Supported Surface (Phase 8 Documentation)

This document enumerates every syscall, relocation type, and PE data directory
that the current runtime recognises. Items marked **stub** log and return a
safe failure / success so guest code does not crash immediately.

---

## 1. Linux x86-64 Syscalls (`SyscallTranslator`)

| Nr | Name            | Status   | Notes |
|----|-----------------|----------|-------|
| 0  | read            | full     | via FD table |
| 1  | write           | full     | via FD table |
| 2  | open            | full     | (legacy; openat preferred) |
| 3  | close           | full     | |
| 9  | mmap            | full     | anonymous / file |
| 10 | mprotect        | full     | |
| 11 | munmap          | full     | |
| 12 | brk             | full     | simple heap end |
| 13 | rt_sigaction    | stub     | returns 0 |
| 14 | rt_sigprocmask  | stub     | |
| 16 | ioctl           | stub     | |
| 24 | sched_yield     | full     | |
| 28 | madvise          | stub     | |
| 39 | getpid          | full     | host pid |
| 56 | clone           | full     | Threading::clone |
| 60 | exit            | full     | |
| 231| exit_group      | full     | |
| 202| futex           | partial  | WAIT/WAKE; robust via Threading |
| 228| clock_gettime   | full     | |
| 96 | gettimeofday    | full     | |
| 257| openat          | full     | |
| 218| set_tid_address | full     | Threading |

Unimplemented numbers return `-ENOSYS` and are logged under `LogCategory::ABI`.

---

## 2. ELF x86-64 Relocations

Handled by `ElfRelocator`:

| Type                    | Value | Status |
|-------------------------|-------|--------|
| R_X86_64_NONE           | 0     | full   |
| R_X86_64_64             | 1     | full   |
| R_X86_64_PC32           | 2     | full   |
| R_X86_64_GOT32          | 3     | full   |
| R_X86_64_PLT32          | 4     | full   |
| R_X86_64_COPY           | 5     | full   |
| R_X86_64_GLOB_DAT       | 6     | full   |
| R_X86_64_JUMP_SLOT      | 7     | full   |
| R_X86_64_RELATIVE       | 8     | full   |
| R_X86_64_GOTPCREL       | 9     | full   |
| R_X86_64_32             | 10    | full   |
| R_X86_64_32S            | 11    | full   |
| R_X86_64_16             | 12    | full   |
| R_X86_64_PC16           | 13    | full   |
| R_X86_64_8              | 14    | full   |
| R_X86_64_PC8            | 15    | full   |
| R_X86_64_DTPMOD64       | 16    | full   |
| R_X86_64_DTPOFF64       | 17    | full   |
| R_X86_64_TPOFF64        | 18    | full   |
| R_X86_64_TLSGD          | 19    | partial|
| R_X86_64_TLSLD          | 20    | partial|
| R_X86_64_DTPOFF32       | 21    | full   |
| R_X86_64_GOTTPOFF       | 22    | full   |
| R_X86_64_TPOFF32        | 23    | full   |
| R_X86_64_PC64           | 24    | full   |
| R_X86_64_GOTOFF64       | 25    | full   |
| R_X86_64_GOTPC32        | 26    | full   |
| R_X86_64_GOTPC64        | 27    | full   |
| R_X86_64_GOTPCRELX      | 41    | full   |
| R_X86_64_REX_GOTPCRELX  | 42    | full   |
| R_X86_64_IRELATIVE      | 37    | full   |

Versioned symbols (`VERSYM`, `VERNEED`, `VERDEF`) are parsed; resolution
prefers the default version when multiple exist.

---

## 3. PE Data Directories

Parsed / acted on by `PeParser` / `PeMapper` / `PeImports` / `PeExports` /
`PeRelocator` / `PeTlsExceptions`:

| Index | Directory              | Status |
|-------|------------------------|--------|
| 0     | Export Table           | full   |
| 1     | Import Table           | full   |
| 2     | Resource Table         | stub   |
| 3     | Exception (pdata)      | partial (SEH dispatcher) |
| 4     | Certificate            | ignored |
| 5     | Base Relocation        | full   |
| 6     | Debug                  | ignored |
| 7     | Architecture           | ignored |
| 8     | Global Ptr             | ignored |
| 9     | TLS Table              | full   |
| 10    | Load Config            | partial |
| 11    | Bound Import           | ignored |
| 12    | IAT                    | full   |
| 13    | Delay Import           | partial |
| 14    | CLR Runtime            | not supported |
| 15    | Reserved               | — |

---

## 4. Security / Hardening (Phase 8)

- **W^X code cache**: pages mapped RW, sealed to RX via `mprotect` after
  install; temporary unseal only for the duration of a write.
- **Guard pages**: `MemoryManager::allocateWithGuards` places inaccessible
  pages on both sides of usable regions.
- **SMC coherency**: stores into pages marked executable invalidate the
  corresponding translation-cache entries (hash + page tracking).
- **Pointer authentication**: ARM64 PAC is not yet instrumented; future
  work will strip/re-sign when the host requires it.
- **Persistent translation cache**: `CodeCache::saveToFile` /
  `loadFromFile` (binary format, magic `NINE`).

---

## 5. Multi-threading (9.4)

- 1:1 guest thread ↔ host `std::thread`.
- Shared `CodeCache` protected by mutex; each host thread has its own
  `GuestContext` via `thread_local` (`ContextSwitch::current()`).
- Linux `clone` honours `CLONE_VM`, `CLONE_THREAD`, `CLONE_SETTLS`,
  `CLONE_CHILD_CLEARTID`, `CLONE_CHILD_SETTID`.
- Windows `CreateThread` mapped onto the same machinery.
- TLS via emulated FS base (`GuestTls`).

---

*Generated as part of Phase 8 — Hardening & Completeness.*
