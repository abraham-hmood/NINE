# NINE Supported Surface

The hard, enumerable guest-visible contract: Linux syscall numbers, ELF
relocations, PE data directories, and the opcodes the relinker-side AOT
compiler can emit. Audited against the tree on 2026-10-25.

Anything not listed here is **not** silently accepted: syscalls return
`-ENOSYS` (logged under `LogCategory::ABI`), relocations are skipped with a
log line, and an un-emittable opcode refuses the whole module image by name.

Superseded numbers/inventories live in `ARCHITECTURE.md` (§2 per-family
ledger, §1.3 AOT) and `LIBRARIES.md` (named API checklists).

---

## 1. Linux x86-64 Syscalls (`abi/SyscallTranslator.cpp`)

62 numbers have a `case` arm. The table gives the current behaviour; `stub`
means the call succeeds (or returns a safe failure) without doing the real
work, and `refused` means `-ENOSYS` on purpose.

### File descriptors / files

| Nr | Name | Status | Notes |
|----|------------------|--------|-------|
| 0  | read             | full   | via `FdTable` |
| 1  | write            | full   | via `FdTable`; guest stdout/stderr surface in Logs as `stdout:` |
| 2  | open             | full   | legacy form |
| 3  | close            | full   | |
| 4  | stat             | full   | |
| 5  | fstat            | full   | |
| 6  | lstat            | full   | |
| 7  | poll             | full   | |
| 8  | lseek            | full   | |
| 16 | ioctl            | refused| `-ENOTTY` |
| 17 | pread64          | full   | |
| 18 | pwrite64         | refused| no case arm → `-ENOSYS` |
| 19 | readv            | full   | |
| 20 | writev           | full   | |
| 21 | access           | full   | |
| 32 | dup              | full   | |
| 33 | dup2             | full   | |
| 72 | fcntl            | full   | |
| 79 | getcwd           | full   | |
| 80 | chdir            | full   | |
| 217| getdents64       | full   | |
| 257| openat           | full   | |
| 262| newfstatat       | full   | |
| 267| readlinkat       | full   | |
| 269| faccessat        | full   | |
| 302| prlimit64        | full   | |

### Memory

| Nr | Name | Status | Notes |
|----|------------------|--------|-------|
| 9  | mmap             | full   | anonymous + file |
| 10 | mprotect         | full   | |
| 11 | munmap           | full   | |
| 12 | brk              | full   | heap end |
| 25 | mremap           | full   | emulated |
| 28 | madvise          | stub   | returns 0 |
| 26 | msync            | refused| no case arm → `-ENOSYS` |

### Process / threads / scheduling

| Nr | Name | Status | Notes |
|----|------------------|--------|-------|
| 24 | sched_yield      | full   | |
| 35 | nanosleep        | full   | |
| 39 | getpid           | full   | |
| 56 | clone            | full   | `Threading::clone` (VM/THREAD/SETTLS/CLEARTID/SETTID) |
| 57 | fork             | refused | `-ENOSYS` |
| 58 | vfork            | refused | `-ENOSYS` |
| 59 | execve           | refused | `-ENOSYS` |
| 60 | exit             | full   | |
| 99 | sysinfo          | full   | struct filled |
| 102| getuid           | full   | |
| 104| getgid           | full   | |
| 107| geteuid          | full   | |
| 108| getegid          | full   | |
| 110| getppid          | full   | |
| 143| sched_getparam   | full   | |
| 144| sched_setscheduler | full | |
| 145| sched_getscheduler | full | |
| 146| sched_get_priority_max | full | |
| 147| sched_get_priority_min | full | |
| 186| gettid           | full   | |
| 202| futex            | partial| WAIT / WAKE only |
| 204| sched_getaffinity| partial| single-CPU mask |
| 218| set_tid_address  | full   | `Threading` |
| 231| exit_group       | full   | |
| 234| tgkill           | full   | |

### Signals, time, misc

| Nr | Name | Status | Notes |
|----|------------------|--------|-------|
| 13 | rt_sigaction     | stub   | handler table kept guest-visible, no delivery |
| 14 | rt_sigprocmask   | stub   | mask bookkeeping |
| 63 | uname            | full   | spoofs x86_64 |
| 96 | gettimeofday     | full   | |
| 157| prctl            | partial| `PR_SET_NAME` class only |
| 158| arch_prctl       | full   | `ARCH_SET_FS/GS` into the guest context |
| 228| clock_gettime    | full   | |
| 318| getrandom        | full   | |
| 334| rseq             | refused| `-ENOSYS` + log (glibc tolerates absence) |

Everything else (sockets, pipes, `select`, `wait4`, `kill`, mount family,
`epoll`, `io_uring`, `ptrace`, `bpf`, …) falls through to `-ENOSYS` and is
logged. See `LIBRARIES.md` §1.2 for the grouped backlog.

---

## 2. ELF x86-64 Relocations (`loader/elf/ElfRelocator.cpp`)

14 types have a `case` arm. Everything else logs and is skipped, so a guest
that depends on it will fault at first use rather than run with a wrong value.

| Type | Value | Status | Notes |
|------|-------|--------|-------|
| R_X86_64_NONE | 0 | full | |
| R_X86_64_64 | 1 | full | |
| R_X86_64_PC32 | 2 | full | |
| R_X86_64_PLT32 | 4 | full | resolved through the linker |
| R_X86_64_GLOB_DAT | 6 | full | |
| R_X86_64_JUMP_SLOT | 7 | full | eager binding |
| R_X86_64_RELATIVE | 8 | full | |
| R_X86_64_IRELATIVE | 37 | full | ifunc resolver is called |
| R_X86_64_GOTPCREL | 9 | full | |
| R_X86_64_32 | 10 | full | |
| R_X86_64_32S | 11 | full | |
| R_X86_64_DTPMOD64 | 16 | full | TLS module id |
| R_X86_64_DTPOFF64 | 17 | full | TLS offset |
| R_X86_64_TPOFF64 | 18 | full | TLS offset |

Not handled (each one is a real gap for a dynamic guest that needs it):
`R_X86_64_GOT32`(3), `COPY`(5), `16`(12), `PC16`(13), `8`(14), `PC8`(15),
`TLSGD`(19), `TLSLD`(20), `DTPOFF32`(21), `GOTTPOFF`(22), `TPOFF32`(23),
`PC64`(24), `GOTOFF64`(25), `GOTPC32`(26), `GOTPC64`(27),
`GOTPCRELX`(41), `REX_GOTPCRELX`(42).

Versioned symbols (`VERSYM`, `VERNEED`, `VERDEF`) are parsed; resolution
prefers the default version when several exist.

---

## 3. PE Data Directories

The 16 directory entries are parsed (`PeParser`); consumers act on these:

| Index | Directory | Status |
|-------|-----------|--------|
| 0 | Export Table | full (`PeExports`, forwarders included) |
| 1 | Import Table | full (`PeImports`) |
| 2 | Resource Table | stub (addresses preserved, not interpreted) |
| 3 | Exception (pdata) | partial (parsed; generic fault dispatcher, no unwind) |
| 4 | Certificate | ignored |
| 5 | Base Relocation | full (`PeRelocator`, ASLR-style rebase) |
| 6 | Debug | ignored |
| 7 | Architecture | ignored |
| 8 | Global Ptr | ignored |
| 9 | TLS Table | full (`PeTlsExceptions`) |
| 10 | Load Config | partial |
| 11 | Bound Import | ignored |
| 12 | IAT | full |
| 13 | Delay Import | partial |
| 14 | CLR Runtime | not supported (no .NET) |
| 15 | Reserved | — |

---

## 4. AOT emitter surface (`aot/AotCompiler.cpp`)

The relinker compiles executable ranges ahead of time. Support is
all-or-nothing per module, so this list is the exact set a program may use and
still produce a `.nine.aot` image:

`NOP`, `ENDBR`, `MOV` (incl. `mov r8,imm8` and AH/CH/DH/BH operands),
`MOVZX`, `MOVSX`, `LEA`, `PUSH`, `POP`, `LEAVE`,
`ADD`/`SUB`/`AND`/`OR`/`XOR`/`CMP`/`TEST`, `INC`/`DEC`/`NEG`/`NOT`,
`SHL`/`SHR`/`SAR`/`ROL`/`ROR`, `SETcc`, `CMOV`, `XCHG`, `BSWAP`,
`CBW`/`CWDE`/`CDQE`/`CDQ`, `CLC`/`STC`/`CLI`/`STI`/`CLD`/`STD`/`CLAC`/`STAC`,
`Jcc`, `JMP`, `CALL`, `RET`, `SYSCALL`, `INT3`, `UD2`.

Refused by name today: `IMUL`/`MUL`/`DIV`/`IDIV` (2- and 3-operand forms
included), every SSE/AVX form, all string ops (`MOVS`/`STOS`/`LODS`/`SCAS`/
`CMPS`, with or without REP), x87, BCD adjusts, `CMPXCHG`/`XADD`/`LOCK` RMW,
`BT`/`BSF`/`BSR`/`POPCNT`/BMI, `PUSHF`/`POPF`/`SAHF`/`LAHF`.

Flags are produced by the AOT helpers (`nine_aot_flags`,
`nine_aot_shift_flags`) — the same arithmetic as the interpreter's
`FlagState`, including shift/rotate CF/OF rules — and memory accesses go
through `nine_load*`/`nine_store*`, so guest page permissions and faults
behave exactly as under the interpreter.

---

## 5. Security / Hardening

- **W^X code cache**: pages mapped RW, sealed to RX via `mprotect` after
  install; temporary unseal only for the duration of a write. AOT images use
  the same discipline (map RW → patch helper relocations → `__clear_cache` →
  `mprotect` RX).
- **Guard pages**: `MemoryManager::allocateWithGuards` places inaccessible
  pages on both sides of usable regions.
- **SMC coherency**: stores into pages marked executable invalidate the
  corresponding translation-cache entries (hash + page tracking). AOT images
  assume the code they were compiled from; they have no SMC handling, which is
  why they are produced at relink time rather than while running.
- **Pointer authentication**: ARM64 PAC is not instrumented yet.
- **Persistent translation cache**: `CodeCache::saveToFile` /
  `loadFromFile` (binary format, magic `NINE`, v2 keyed by image hash +
  translator version).

---

## 6. Multi-threading (9.4)

- 1:1 guest thread ↔ host `std::thread`.
- Shared `CodeCache` protected by mutex; each host thread has its own
  `GuestContext` via `thread_local` (`ContextSwitch::current()`).
- Linux `clone` honours `CLONE_VM`, `CLONE_THREAD`, `CLONE_SETTLS`,
  `CLONE_CHILD_CLEARTID`, `CLONE_CHILD_SETTID`.
- Windows `CreateThread` mapped onto the same machinery.
- TLS via emulated FS base (`GuestTls`).

---

*Originally generated for Phase 8; refreshed against the tree on 2026-10-25.*
