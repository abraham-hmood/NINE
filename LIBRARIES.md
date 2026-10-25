# LIBRARIES.md — Guest API Surface Inventory

**Legend:** 🟩 = implemented (real behavior behind the shim) · 🟨 = partial / stub (safe failure, logged, or simplified semantics) · ⬛ = not implemented (returns failure / ENOSYS / unresolved import)

Two guest ABIs sit under NINE:

1. **Linux x86-64** (primary target today): the **kernel syscall table** + **process bootstrap** (auxv/TLS/vDSO). Static binaries carry their own glibc; NINE only has to be the kernel boundary.
2. **Windows x86-64** (PE32+ guests): the **ntdll / kernel32 / user32 / ... DLL contract** + PE startup state (PEB/TEB/LDR/SEH).

Updates: when a new syscall/API/instruction is implemented, flip its cell in the grids here, in `README.md`, and in `ARCHITECTURE.md` (see the maintenance contract appended to `REVERSE_TECHNIQUE.md`).

---

## Part 1 — Linux API Surface

### 1.1 Process bootstrap / ELF runtime environment

| Facility | Status | Notes |
|---|---|---|
| ELF64 loader (PT_LOAD + BSS + RELRO) | 🟩 | `LinuxStartup` / `ElfMapper` |
| PIE base selection / ET_EXEC | 🟩 | fixed base search |
| `auxv` (AT_PHDR/AT_PHENT/AT_PHNUM/AT_PAGESZ/AT_BASE/AT_ENTRY/AT_UID/AT_EUID/AT_GID/AT_EGID/AT_SECURE/AT_RANDOM/AT_HWCAP/AT_HWCAP2/AT_PLATFORM/AT_EXECFN/AT_NULL) | 🟩 | full System V bootstrap |
| Stack layout argc/argv/envp | 🟩 | 2 MiB stack, configurable |
| TLS: PT_TLS template, `arch_prctl(ARCH_SET_FS)`, tcbhead at FS:0 | 🟩 | GuestTls, FS/GS bases honored in memory ops |
| vDSO | 🟨 | minimal surface (clock_gettime path) |
| Static glibc `_start` → `__libc_start_main` chain | 🟩 | runs end-to-end |
| Dynamic-ELF path: `ld-linux-x86-64.so.2` bootstrap of `ldso` | 🟨 | ldso loads via ELF loader; full audit untested |
| Signal delivery (SIGSEGV→guest handler, μstack frames) | 🟨 | bookkeeping stubs, no real delivery |
| `/proc/self/maps` emulation | ⬛ | read of mapped files falls back to real FD content |

### 1.2 Kernel syscalls (x86-64 numbers)

The authoritative per-number list lives behind `case SYS_*:` in `SyscallTranslator.cpp`; anything reaching `default:` logs and returns `-ENOSYS`.

**Implemented 🟩 (full behavior):**

```
read(0)            write(1)          open(2)           close(3)
stat(4)            fstat(5)          lstat(6)          poll(7)
lseek(8)           mmap(9)           mprotect(10)      munmap(11)
brk(12)            access(21)        readv(19)         writev(20)
dup(32)            dup2(33)          nanosleep(35)     getpid(39)
getppid(110)       gettid(186)       getuid(102)       geteuid(107)
getgid(104)        getegid(108)      uname(63)         fcntl(72)
getcwd(79)         chdir(80)         gettimeofday(96)  sysinfo(99)
mremap(25)         sched_yield(24)   exit(60)          exit_group(231)
clone(56)          set_tid_address(218)  futex(202, WAIT/WAKE)  tgkill(234)
sched_getparam(143)  sched_setscheduler(144)  sched_getscheduler(145)
sched_get_priority_max(146)  sched_get_priority_min(147)
clock_gettime(228) getrandom(318)    arch_prctl(158)
openat(257)        newfstatat(262)   unlinkat(263)     readlinkat(267)
faccessat(269)     prlimit64(302)
```

**Partial / stub 🟨:**

| Syscall | Nr | State |
|---|---|---|
| rt_sigaction | 13 | stub, returns 0 |
| rt_sigprocmask | 14 | stub |
| pread64 / pwrite64 | 17/18 | partial |
| ioctl | 16 | stub (termios-ish paths) |
| madvise | 28 | stub |
| msync | 26 | stub |
| prctl | 157 | partial (SET_NAME etc.) |
| sched_getaffinity | 204 | partial (single-cpu mask) |

**Not implemented ⬛ (log + `-ENOSYS`, defaults):**

| Group | Numbers | Notes |
|---|---|---|
| Process lifecycle | fork(57) vfork(58) execve(59) wait4(61) kill(62) | single-process guests only |
| Sockets | socket(41) connect(42) accept(43) bind(49) listen(50) sendto(44)/recvfrom(45) recvmsg(47) sendmsg(46) shutdown(48) socketpair(53) | enum entries exist; no host networking bridge |
| Pipes / IPC | pipe(22) pipe2(293) SysV shm(29–53 range) sem(64–75) | absent |
| select family | select(23) pselect6(270) | enum only |
| File tree ops | mkdir(83) rmdir(84) rename(82) unlink(87) chmod(90) chown(92) truncate(76) flock(73) fsync(74) | enum entries without full behavior unless listed above |
| Signals full semantics | rt_sigtimedwait(35) sigaltstack(132) | no guest signal stack yet |
| Overlay / mount | mount(165) statfs(137)/fstatfs(138) umount2(166) | consumed occasionally by loaders |
| rseq | 334 | `-ENOSYS` + logged (glibc handles absence gracefully) |
| epoll/io_uring/timers | epoll_* (232 etc) timer_create(226) itimer getitimer(36) | busy-wait apps would need |
| Misc kernel | perf_event_open(298) bpf(321) kexec(246) ptrace(101) | out of scope |
| i386 compat | int 0x80 ABI | A1 roadmap |

### 1.3 glibc services demanded by static guests

| Service | Status | Deliverer |
|---|---|---|
| malloc / glibc heap | 🟩 | in-guest (static binary ships it); NINE provides mmap/brk substrate |
| printf / puts stdout | 🟩 | via write(1) surfacing to Logs as `stdout:` lines |
| libdl-style dlopen within guest | 🟨 | only through the dynamic-loader chain; no dlopen of host libs |
| libstdc++ / libgcc_s | 🟨 | loaded via dynamic-linker path only |
| custom LD_PRELOAD-style interposition | ⬛ | relinker roadmap |

---

## Part 2 — Windows x64 API Surface (PE32+ guests)

### 2.1 PE loader & runtime state

| Piece | Status | Notes |
|---|---|---|
| PE32+ parse/map (headers, sections) | 🟩 | `PeMapper` |
| Base relocations (incl. DIR64, ASLR-style random base) | 🟩 | full reloc types |
| Import table + IAT patching, delay-load imports | 🟩 | `PeImports` |
| Export table → callable guest thunks | 🟩 | `WinAbi`: every export is a 16-byte `mov r10,rcx / mov eax,nr / syscall / ret` stub |
| Export table (forwarders, ordinals) | 🟩 | `PeExports` |
| PEB / TEB placement, TEB LastErrorValue, GS-based state | 🟩 | TEB block honored via FS/GS memory bases |
| PEB LDR table registration | 🟩 | `Ntdll::ldrAdd` |
| TLS directory callbacks + TlsAlloc/Get/SetValue/Free | 🟨 | `PeTlsExceptions`; index registry only |
| `.pdata`/`.xdata` unwind parse | 🟨 | loader-side only; no real unwinding |
| Hardware SEH / vectored exception dispatch | 🟨 | generic fault handler path only |
| Resource directory (icons/strings/dialogs) | 🟨 | stub |
| Load Config / CFG guarded calls | 🟨 | partial parse |
| Debug directory (PDB path) | ⬛ | ignored |

### 2.2 ntdll

| API | Status |
|---|---|
| RtlAllocateHeap / RtlFreeHeap | 🟩 (bump allocator) |
| LdrAdd / PEB-LDR bookkeeping | 🟩 |
| RtlInitialize/Enter/LeaveCriticalSection | 🟩 (host mutex) |
| RtlAcquireSRWLockExclusive / Release | 🟩 |
| NtCurrentTeb / TLS vector helpers | 🟨 |
| RtlRaiseException / RtlUnwindEx / RtlLookupFunctionEntry (true x64 SEH) | ⬛ |
| NtCreateFile / NtReadFile / NtWriteFile native layer | ⬛ |
| NtQueryInformationProcess / NtQueryVirtualMemory | ⬛ |
| NtWaitForSingleObject / NtWaitForMultipleObjects | ⬛ |

### 2.3 kernel32 — registered exports

Every export below is bound to a real callable thunk and a native handler
(`abi/Win32Exports.cpp`); the guest calls it with the Microsoft x64 convention
and gets the value back in RAX/XMM0. Unknown exports of a module NINE owns are
bound to a logging stub, so a call is a safe no-op instead of a wild jump.

| Group | Implemented 🟩 | Stub 🟨 |
|---|---|---|
| Modules | GetModuleHandleA/W, GetProcAddress, LoadLibraryA/W | |
| Files | CreateFileA/W (host fd), ReadFile, WriteFile, CloseHandle, GetStdHandle | |
| Memory | VirtualAlloc, VirtualFree, VirtualProtect | |
| Errors/Info | GetLastError, SetLastError, GetCurrentProcessId, GetCurrentThreadId, IsDebuggerPresent | ExitProcess (log only) |
| Time | QueryPerformanceCounter/Frequency, GetTickCount/64, GetSystemTimeAsFileTime | |
| Environment | GetCommandLineA/W, GetEnvironmentVariableA, SetEnvironmentVariableA | GetStartupInfoA/W (empty block) |
| Threads | CreateThread (1:1 host), Sleep, SwitchToThread | ExitThread (log only) |
| Sync objects | CreateEventA/W, SetEvent, ResetEvent, WaitForSingleObject | WaitForMultipleObjects |
| Files (extra) | GetFileType, GetFileSize(Ex), SetFilePointer(Ex), FlushFileBuffers, DeleteFileA/W | FindFirstFile* |
| Heap | GetProcessHeap, HeapCreate/Destroy, HeapAlloc/Free/ReAlloc/Size | |
| Critical sections | Initialize/Enter/Leave/DeleteCriticalSection, TryEnter, +SpinCount, SRW exclusive/shared | |
| TLS | | TlsAlloc/GetValue/SetValue/Free (index registry only) |
| Unicode | MultiByteToWideChar, WideCharToMultiByte | |

**Missing ⬛ among commonly imported kernel32 (backlog):** CreateProcessA/W, Thread32*, WaitForSingleObject, CreateEventA/W, SetEvent, CreateFileMappingA/W, MapViewOfFile, VirtualQuery{Ex}, FindFirstFile*, GetModuleFileName, FormatMessage*, HeapCreate/HeapDestroy (Rtl heap covers), LZW/compression, GetEnvironmentStringsW (walkable), SetConsoleCtrlHandler, console screen APIs, GetDiskFreeSpace, AddDllDirectory/SetDllDirectory, RaiseException forwarding, TLS callback helpers, IsProcessorFeaturePresent, RegisterClass*/CreateWindowEx* (to G1)…

### 2.4 Interactive / graphics / runtime DLLs

| DLL | Status | Notes |
|---|---|---|
| user32.dll | 🟨 all imports callable: MessageBoxA/W, window-class and window stubs, GetMessage returns 0 (clean WinMain exit), GetClientRect/GetSystemMetrics/HWND values | G1: message loop + SurfaceView HWND |
| gdi32.dll | 🟨 callable: GetStockObject, CreateSolidBrush/Pen, SelectObject, TextOutA/W, GetDeviceCaps | G1: software DC/framebuffer |
| advapi32.dll | 🟨 callable, honest failures: RegOpenKeyExA/W → ERROR_FILE_NOT_FOUND, RegSetValueEx → ACCESS_DENIED | registry emulation later |
| shell32.dll / comctl32.dll / comdlg32.dll | ⬛ | unresolved imports |
| ole32.dll / oleaut32.dll (COM) | ⬛ | vtable/AddRef/QueryInterface plumbing |
| ws2_32.dll | ⬛ | Winsock bridge |
| d3d9 / d3d11 / d3d12 / d2d1 / dwrite / dxgi | ⬛ | G2 interception → host Vulkan/GLES |
| winmm.dll / xinput* | ⬛ | audio & input |
| msvcrt.dll / ucrtbase.dll | ⬛ | PEs typically ship static CRT |
| netapi32 / shlwapi / version / setupapi | ⬛ | import-driven as demands |
| bcrypt / ncrypt | ⬛ | CNG crypto bridge |

---

## Part 3 — Count snapshot (keep refreshed when grids change)

- Linux syscalls with real behavior: **≈60** of ~450 documented numbers
- Windows: PE loader stack 🟩; **every export is a callable thunk** (`WinAbi`), with ~140 native handlers across kernel32/kernelbase/ntdll and callable stubs for user32/gdi32/advapi32; unknown names are logged no-ops. Still missing: wait-multiple, sections, APC/overlapped I/O, the registry, mixed-mode unwinding, varargs marshalling
- ISA: ≈760 of the 1208 felixcloutier.com-indexed instructions decoded + executed end-to-end (SSE4.2 string compare, ADX, BCD adjust, AES-NI, Key Locker, SHA-1/SHA-256, BMI1/BMI2, XSAVE family, RDTSC/RDTSCP/RDSEED, SHLD/SHRD, CET/TBM/RTM/Ring-0 refusals, bit-test/scan, MPX; plus the full AVX/AVX2/AVX-512 vector path — 426 distinct vector mnemonics, 453 encoding rows — and the SGX ENCLS/ENCLU/ENCLV leaves); see ARCHITECTURE.md §2.1–§2.22 for the ledger
- **System-library inventory** (README › Coverage grids): Windows ≈80 app-linkable DLLs catalogued; NINE-side behavioral shims exist only for ntdll/kernel32/user32/gdi32/advapi32 stubs — everything else ⬛. Linux ≈55 library families catalogued; the satisfiable set is the glibc core family (loader, libc, libm, merged pthread/dl/rt/util via static-in-image + loader merge-awareness) 🟩/🟨 and libresolv 🟨, liberally everything else ⬛ demand-driven backlog for dynamic guests
- ⬛-only rule: a DLL/library row stays ⬛ until a guest proves it needs it (REVERSE_TECHNIQUE.md); the inventories are the backlog, not a forced pre-implementation todo

Refresh cadence rule: any commit that adds/changes a guest-visible surface must flip the corresponding cells in README grids, LIBRARIES.md, and ARCHITECTURE.md (see REVERSE_TECHNIQUE.md "Coverage ledger maintenance").
