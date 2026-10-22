# NINE — Nine Is Not An Emulator

NINE is an Android app (ARM64, API 26+) that combines a **user-mode dynamic binary
translation (DBT) runtime** for x86-64 guests with an **AI agent platform** and a
**virtual disk / program store**, all first-party. No Wine, no Box64, no QEMU, no
FEX, no libHoudini — every guest-facing loader, linker, translator, and ABI shim
lives in this repository under `app/src/main/cpp/`.

```
┌──────────────────────────────────────────────────────────────────┐
│  Guest x86-64 code (ELF / PE)                                    │
│       │ decode                                                   │
│       ▼                                                          │
│  X86Decoder → IR (Insn)                                          │
│       ├─► InsnInterpreter (fallback / cold path / step debug)    │
│       └─► Translator → AArch64 machine code                      │
│               │                                                  │
│               ▼                                                  │
│         CodeCache (W^X, persistent, SMC-invalidated)              │
│               ▼                                                  │
│    HostTrampoline → ExecutionLoop → GuestContext                 │
│               ▼                                                  │
│    ABI layer (Linux syscalls / ntdll / kernel32 / vDSO)          │
│                                                                  │
│  ── In parallel, the Android app layer ──                        │
│  Compose UI (Home/Library/Logs/Extensions/Creator)               │
│  AI stack (llama.cpp + cloud endpoints + tool calling)           │
│  VHD manager (create/format/compress/export disk images)         │
└──────────────────────────────────────────────────────────────────┘
```

## What is already added

### Translation engine (`app/src/main/cpp/`, builds as `libnexus_core.so`)

| Component | Status | Notes |
|---|---|---|
| Memory manager | 🟢 | Guest VA ↔ host VA, region table, `protect`/split, guard pages (W^X hardening) |
| ELF loader | 🟢 | Full ELF64 x86-64 parse, PT_LOAD mapping, BSS, RELRO, TLS template, PIE base search |
| ELF relocations | 🟢 | Common `R_X86_64_*` set incl. RELATIVE, IRELATIVE, GLOB_DAT, JUMP_SLOT, TLS basics |
| Dynamic linker | 🟢 | Module graph, topological resolution, GOT/PLT/IAT, `$ORIGIN`, RUNPATH/RPATH, caching |
| PE loader (PE32+) | 🟢 | Parse, map, base relocations, imports (incl. delay-load), exports, TLS, `.pdata` |
| x86-64 decoder | 🟡 | ALU, shifts/rotates, MOV family, LEA, PUSH/POP, branches, CALL/RET, SETCC, CMOV*, string ops, SYSCALL; VEX/EVEX detected-but-not-decoded |
| AArch64 emitter / JIT | 🟡 | Working ARM64 codegen for the decoded integer subset; lazy flags; SSE only sampled; LOCK/atomics designed (`SimdAtomics`) but not wired into the JIT |
| Interpreter fallback | 🟡 | Broad, semantically careful integer/branch/string execution with real flag semantics — **this is what runs binaries today** |
| Execution loop | 🟢 | JIT-first with interpreter fallback, FNV hash staleness checks, syscall/import/exception exits, resumable |
| Host trampoline | 🟢 | Translated blocks invoke as `void(*)(GuestContext*)` with pinned X0/X19/X20 ABI (`CtxLayout.h`) |
| Code cache | 🟢 | W^X `seal`/`unseal`, concurrency-safe install + icache flush, **persistent save/load** ("NINE" v2 format keyed by image hash + translator version) |
| SMC coherency | 🟢 | Exec-page tracking; stores into executable pages invalidate overlapping translations |
| Self-mod code + counters | 🟢 | Invalidation, hit/trace/IC counters exposed to UI |
| Linux syscall ABI | 🟡 | ~50 numbers: read/write/open*/close/mmap/mprotect/munmap/brk, exit*, pid/uid family, fstat family, getrandom, stat/lstat/fstat/newfstatat, getdents64, poll, writev/readv, uname (spoofs x86_64), `arch_prctl` FS/GS into guest ctx; futex/signals bookkeeping stubs; fork/execve → `-ENOSYS` |
| Windows ABI | 🟡 | kernel32: 43 registered exports (~13 with real behavior — files, VirtualAlloc*, TEB last-error, CreateThread, PEB/LDR registration); ntdll: 8 Rtl primitives (heap, critical sections, SRW); user32/gdi32/advapi32 fake-address stubs |
| Threading | 🟡 | 1:1 guest↔host threads (`clone` CLONE_VM/FS/FILES/SIGHAND/THREAD, `CreateThread`), shared CodeCache, `thread_local` GuestContext, GuestTls FS base |
| Diagnostics | 🟢 | Ring-buffer logger (8 categories) → logcat → app log sink, guest register/memory dumps |
| llama.cpp runtime | 🟢 | Static llama.cpp v0.7.0 fetched at configure time; `.gguf` load → greedy generate → free, JNI-exposed |
| vDSO / auxv | 🟡 | Full System V bootstrap (stack 2 MiB, argv/envp, AT_* auxv incl. AT_RANDOM), minimal vDSO surface |

Statuses align with the audits in `DevelopmentPlan.md` and `JITImplementationPlan.md`.

### Android app (`app/src/main/java/com/nine/dbt`)

- **Dark cyberpunk Compose UI** (cyan/purple, 5 tabs: Home, Library, Logs, Extensions, Creator) with a 9-step first-launch tutorial and permission flow.
- **Home**: live RUNTIME card polling `GuestRuntime.status()` (Pause/Resume/Stop, counters), recent programs list.
- **Library**: permanent program store. Import ELF / PE / ZIP program bundles via SAF, magic sniffing (ELF class, PE DLL bit, `config.json` bundles), per-program normalized metadata, Relink → writes a package-export zip containing the app's own `libnexus_core.so` + programs + libraries laid out at guest install paths.
- **Logs**: streams native `Logger` output through the static JNI sink `GuestLog.onNativeLine`; captures guest `write(1/2, …)` as `stdout:` lines; save to txt via SAF.
- **Debugger**: pause / resume / single-step (forced-interpreter), PC breakpoints, guest status snapshot; plus a feature matrix screen listing ~45 roadmap features (Phase 0–8, J1–J5, GUI/D3D/32-bit) with a native test runner (`NativeTests.run(id)`).
- **AI stack**:
  - Cloud chat against any OpenAI-compatible endpoint (configurable URL/key/model list), with tool calling.
  - Local models: `.gguf` via llama.cpp in `libnexus_core` (greedy decode); `.tflite` path exists but with a byte-level test tokenizer.
  - Model search/download from Hugging Face with device-aware filtering (RAM, NPU, quant picker), background + notification progress.
- **Agent tool-calling**: a multi-dialect parser (fenced blocks, OpenAI `tool_calls`, Mistral `[TOOL_CALLS]`, Qwen/Llama-3.1 XML & `<|python_tag|>`, Hermes, key=value lines, Python-call syntax), 11 built-in executor tools (`search_web`, file CRUD in a sandbox workspace, `compile_extension`, `compile_patch`, `add_tool`).
- **Repositories / Extensions**: browse GitHub `nine-catalog.json` catalogs, download extensions → real `PackageInstaller` APK install session, patches downloaded.
- **VHD manager**: create fixed/sparse raw disk images (512–4096-byte sectors), real MBR partition table, and **genuine FAT12/16/32 formatting**, best-effort exFAT layout, stubbed NTFS/ext plus ~17 other filesystem magics; gzip compress-on-background / decompress-on-foreground lifecycle; delete and `.tar.gz` export with sidecars.

### JNI surfaces

- `com.nine.dbt.GuestRuntime` → loadAndRun, relink, stop/pause/resume/step, breakpoints, status (crash-guarded: guest SIGSEGV does not kill the app).
- `com.nine.dbt.LlamaRuntime` → available/load/generate/free.
- `com.nine.dbt.NativeTests` → per-feature native test dispatch used by the Debugger screen.

## Coverage grids

Full named inventories live in [LIBRARIES.md](LIBRARIES.md) (Windows DLLs / Linux APIs with per-API status) and [ARCHITECTURE.md](ARCHITECTURE.md) (every x86-64 instruction family + runtime architecture). Updates to any guest-visible surface require flipping cells in all three places (see `REVERSE_TECHNIQUE.md › Coverage ledger maintenance`).

**Legend:** 🟩 implemented (real behavior) · 🟨 partial / stub (safe failure, logged, simplified semantics) · ⬛ not implemented (ENOSYS / unresolved import / refuses to decode)

### Windows ABI (PE32+ guests)

| Layer | 🟩 areas | 🟨 areas | ⬛ areas |
|---|---|---|---|
| PE loader | 🟩 image map, relocs, imports incl. delay-load, exports, TLS dir, PEB/TEB/LDR, IAT | 🟨 `.pdata` parse, Load Config, resources | ⬛ debug directory, humanized SEH unwind, COM activation |
| ntdll | 🟩 RtlAllocate/FreeHeap, critical sections, SRW, Ldr bookkeeping | 🟨 TLS helpers, NtCurrentTeb | ⬛ NtCreateFile/NtQuery*, RtlRaiseException, RtlUnwindEx, true x64 SEH |
| kernel32 (45 registered exports) | 🟩 GetModuleHandle/ProcAddress/LoadLibrary, CreateFile/ReadFile/WriteFile/CloseHandle/GetStdHandle, VirtualAlloc/Free/Protect, GetLastError/SetLastError, GetCurrentPID/TID, QueryPerf*, GetTick*, GetSystemTimeAsFileTime, GetCommandLine, Get/SetEnvVar, MultiByte/WideChar, all four critical-section APIs, CreateThread, IsDebuggerPresent | 🟨 ExitProcess (log), Sleep (no-op), GetStartupInfo, TlsAlloc/Get/Set/Free (registry only) | ⬛ CreateProcess, file mapping/overlapped I/O, FindFirstFile*, Synchronization (WaitFor*), FormatMessage, VirtualQuery, console/full codepages |
| user32 | 🟨 MessageBoxA / GetDesktopWindow fake-address | ⬛ message pump, windows, input | G1: SurfaceView HWND + software GDI |
| gdi32 | ⬛ anything realizer-level | 🟨 fake addresses | G1 software DC/framebuffer |
| advapi32 | 🟨 RegOpenKeyExA failure-correct | ⬛ registry emulation, LSA | |
| shell32 / comctl32 / comdlg32 | ⬛ everything | | |
| ole32 / oleaut32 (COM) | ⬛ everything (vtable/AddRef/QueryInterface plumbing absent) | | |
| ws2_32 | ⬛ Winsock bridge | | |
| d3d9/d3d11/d3d12/d2d1/dwrite/dxgi/winmm/xinput | ⬛ G2 interception phase | | |
| msvcrt / ucrtbase | ⬛ CRT runtime shim | | |

### Linux API (ELF guests, primary today)

| Group | 🟩 | 🟨 | ⬛ |
|---|---|---|---|
| Bootstrap | 🟩 ELF64 map, auxv (AT_PHDR…AT_HWCAP2/AT_RANDOM/AT_EXECFN), stack/argv/envp, TLS + `arch_prctl`, static `_start→__libc_start_main`, vDSO start | 🟨 ldso dynamic path audit, vDSO depth | ⬛ `/proc/self/*` demux, full signal delivery |
| Mem syscalls | 🟩 mmap/mprotect/munmap/brk/mremap(25, emulated)/madvise-stub | 🟨 msync | ⬛ process VM overlays (mincore, remap within-same protocols) |
| File syscalls | 🟩 open/openat/read/write/readv/writev/lseek/close/dup/dup2/fcntl/access/faccessat/getcwd/chdir/stat/fstat/lstat/newfstatat/readlinkat/getdents64/prlimit64 | 🟨 pread64/pwrite64 partial, ioctl stub | ⬛ pipe/pipe2, mkdir/rmdir/rename/unlink legacy, truncate/flock, inotify, fanotify, mount family |
| Process | 🟩 exit/exit_group/getpid/getppid/gettid/getuid/geteuid/getgid/getegid/clone/set_tid_address/tgkill/sysinfo | 🟨 futex WAIT/WAKE only; fork/vfork/execve→ENOSYS | ⬛ wait4/kill, ptrace, namespaces, cgroups |
| Sched / time | 🟩 nanosleep, sched_yield, sched group (144-147), sched_getaffinity, clock_gettime, gettimeofday | | ⬛ timer_create, itimers, epoll_wait (busy apps) |
| Signals | 🟨 rt_sigaction/rt_sigprocmask bookkeeping stubs | | ⬛ real delivery, sigaltstack, rt_sigtimedwait |
| Sockets | enum'd only | 🟨 sendto/recvfrom paths routed through SocketABI | ⬛ socket/connect/bind/listen/accept, socketpair, recvmsg/sendmsg |
| Misc | 🟩 uname (x86_64 spoof), getrandom, prctl (partial), rseq→ENOSYS graceful | 🟨 sysinfo struct fill | ⬛ bpf, perf_event, io_uring |

### x86-64 instruction coverage (detail per family in ARCHITECTURE.md §2)

| Family | State |
|---|---|
| Decoding infrastructure (prefixes, ModRM/SIB incl. idx=4 trap + abs32 disp, REX, RIP-relative, FS/GS bases) | 🟩 (VEX/EVEX structurally detected → 🟨 placeholders) |
| MOV family (88–8B, A0–A3, B8–BF, C6/C7, 63 MOVSXD, 98 CWDE/CDQE, 99 CDQ, XCHG 86/87/90+r) | 🟩 (BSWAP / MOVBE ⬛) |
| ALU (00–3B all 8 groups + eAX-imm 04-3D forms + 80/81/83 imm) | 🟩 with true ADC/SBB carry |
| TEST/INC/DEC/NEG/NOT, grp3 F6/F7 MUL/IMUL/DIV/IDIV, IMUL 2/3-op + 0F AF | 🟩 |
| Shifts C0/C1/D0–D3 (SHL/SHR/SAR/ROL/ROR), FF/F-shifts, FE/FF inc/dec/jmp/call/push mem | 🟩 (RCL/RCR, SHLD/SHRD ⬛) |
| PUSH/POP (incl. 8F /0, moffs store), LEAVE | 🟩 (ENTER ⬛) |
| Jcc (all 16, near+short), CMOVcc, SETcc, JMP/CALL/RET (± imm16) | 🟩 (LOOP/JECXZ ⬛) |
| String ops MOVS/STOS/LODS/SCAS 8/16/32 with FS/GS segment override | 🟩 (CMPS ⬛; REP loops 🟨) |
| RMW atomics CMPXCHG 0F B0/B1, XADD 0F C0/C1 | 🟩 (CMPXCHG8B/16B ⬛; true LOCK-multicore atomics 🟨) |
| SSE dataplane for glibc startup: MOVD/MOVQ/MOVAPS-family 128-bit moves/MOVLPS/MOVHPS/PUNPCKLDQ/LQDQ/HQDQ/PXOR | 🟩 (MOVAPS/ADDPS/MULPS sampled 🟨) |
| x87 FPU (entire x87 family) | ⬛ |
| SSE1/2/3/SSSE3/4.1/4.2 beyond what glibc startup touches | ⬛ |
| AVX / VEX.128+256, AVX2, AVX-512 (VEX_OP/EVEX_OP placeholders) | ⬛ |
| System: endbr64, UD2, INT3, CPUID (synthetic), SYSCALL routing | 🟩 (RDTSC/RDMSR/fences/WAIT variants ⬛) |
| PAUSE | 🟨 treated as nop |

## What it can do today

- **Load a statically linked x86-64 Linux ELF from storage and run it end-to-end**, through the interpreter-backed execution loop, and see its `hello world` stdout in the Logs tab — fully offline, zero external compatibility layers.
- Relink an ELF against bundled guest libraries, get a JSON report of resolved/unresolved symbols, and package the result for distribution.
- Load PE32+ executables: mapped, rebased (ASLR-style), imports patched against the kernel32/ntdll stubs; simple console apps that use implemented APIs (`WriteFile`, `ExitProcess`, `VirtualAlloc`, …) work.
- Warm-start repeated runs from the **persistent translation cache**, with SMC-safety and two guest threads running concurrently.
- Chat with a cloud LLM of your choice (or a local GGUF if the llama build is linked), have it parse tool calls in essentially any model's format, execute file/search tools, and compile/apply patches for extensions.
- Create, format, compress, and export virtual disk images for future program installation.

## What will be added next

Near-term (highest impact, in rough order):

1. **JIT-default execution** — flip `ExecutionLoop` to run translated blocks by default (currently interpreter-first for safety); prove on-device: glibc "hello world" reaches `write` with >95% cache-hit JIT execution.
2. **Instruction coverage growth** — full SSE/AVX decode via the stubbed VEX/EVEX path, ADC/SBB with carry, correct SETCC/CMOV for all 16 conditions, LOCK-prefixed atomics using LSE/LDAXR+STLXR.
3. **ABI depth for real binaries** — real futex semantics, signal delivery, `clone` CHILD_CLEARTID writeback, `fork`/`execve`; full string-op lowering in the JIT.
4. **Windows GUI (G1)** — user32/gdi32 message loop, `CreateWindowEx` onto an Android `SurfaceView`, software-framebuffer GDI, touch→mouse.
5. **Graphics (G2)** — D3D9/11/12 + Vulkan entry-point interception mapped to host Vulkan/GLES, in-tree DXBC/DXIL → SPIR-V subset.
6. **32-bit guests (A1)** — IA-32 decoder path, PE32 / EM_386 loaders, `int 0x80` syscall ABI.

Mid-term:

7. **User-mode driver framework (K2)** — `\\.\Device` object namespace, IOCTL dispatch, Android USB Host shims; fail-closed for unknown `.sys` (no root, ever).
8. **Custom agent tools become executable** — a runtime interpreter for user-defined `fun name(params)` tools (persisted today, not yet executed).
9. **Extension build pipeline** — replace zip-and-install `compile_extension` with a real in-app build (kotlinc/d8), and apply catalog patches with hunk-offset-accurate diffing.
10. **VHD integration** — mount-in-place file access and program/library installation into images (the packaged-zip format already anticipates this).
11. **AI polish** — streaming responses, proper TFLite tokenization (or drop it for GGUF-only), On-device NPU delegate path.
12. **Coverage docs** — keep `app/src/main/cpp/SUPPORTED.md` (syscalls, relocations, PE data directories) in sync as coverage grows; on-device stress for J-phase 🟡 items.
13. **Runtime `.so` split + translated relinker** — split `libnexus_core` into component `.so`s (`core` / `jit` / `abi_windows` / `abi_linux` / `ai`) so per-program relinking stays light; emit self-contained light APKs that bundle a program + only the ABI surfaces it imports; long-term mode where the **relinker itself translates x86-64 → AArch64**, producing binaries that run natively on ARM64 without booting the NINE interpreter at all (see ARCHITECTURE.md §1.2).

Explicit non-goals: full DirectX/Vulkan *parity*, kernel-mode drivers, bug-for-bug Windows compatibility. See `JITImplementationPlan.md` §13.

## Build & run

Requirements: Android Studio Ladybug+, NDK 26.1, CMake 3.22.1, JDK 17. Building fetches llama.cpp v0.7.0 via CMake FetchContent (network required on first configure).

```powershell
.\gradlew.bat :app:assembleDebug
# Outputs land in %TEMP%\nine-build (build dirs are redirected away from OneDrive;
# override with the NINE_BUILD_DIR environment variable)
```

Install the APK on an **ARM64 device or emulator running API 26+**.

- Programs are loaded via **Library → Load New Program** (statically linked x86-64 ELF is the safest bet).
- The **Debugger** screen runs the native phase/J tests (memory, loaders, zones 5–10, j1–j4, exit-criteria `ec.*`).
- Model imports: import a `.gguf` (Settings → Import Local LLM) or search HF in Browse Models; cloud endpoints are managed in Cloud Models.

## Repository layout

```
app/src/main/cpp/           libnexus_core — memory/, loader/elf/, loader/pe/, linker/,
                            translator/, runtime/, abi/, diagnostics/, llama/, tests/
app/src/main/java/          com.nine.dbt — Compose UI + GuestRuntime/Llama/NativeTests bridges
devtools/toolcalling-tests/ Parser/E2E/stub tests for the tool-call parser
```

Surface-coverage docs (keep in sync — see REVERSE_TECHNIQUE.md "Coverage ledger maintenance"):

```
app/src/main/cpp/SUPPORTED.md   original technical surface table (syscalls, relocations, PE directories)
LIBRARIES.md                    per-API named checklist, Windows DLLs + Linux APIs with 🟩🟨⬛ status
ARCHITECTURE.md                 x86-64 instruction universe ledger + runtime architecture
DevelopmentPlan.md              Phases 0–8 with per-item audit
JITImplementationPlan.md        Phase J1–J5 + G1/G2/K1/K2/A1/C1 roadmap with audit
PATCHING.md                     Catalog patch format / application notes
REVERSE_TECHNIQUE.md            Techniques investigated (demand-driven loop) + ledger contract
nine_logs.md                    Run logs
```
