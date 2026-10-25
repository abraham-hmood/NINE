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
| x86-64 decoder | 🟡 | Integer ALU/shifts/rotates/MOV family/LEA/PUSH-POP/branches/CALL-RET/SETCC/CMOV/string/atomics, x87 (`D8–DF`), SSE/SSE2/SSE3/SSSE3/SSE4.1/SSE4.2, AES/Key Locker/GFNI/SHA, VEX AVX/AVX2 and EVEX AVX-512 (453 encoding rows), BMI1/BMI2/TBM, CET/MPX/SGX/RTM, plus exact decode-then-fault for privileged forms. Remaining gaps are named per row in `ARCHITECTURE.md` §2 |
| AArch64 emitter / JIT | 🟡 | Working ARM64 codegen for the decoded integer subset; lazy flags; SIMD surfaces executed by `VecExec` rather than emitted; LOCK/atomics designed (`SimdAtomics`) but not wired into the JIT |
| Interpreter fallback | 🟡 | Broad, semantically careful integer/branch/string execution with real flag semantics — **this is what runs binaries today** |
| Execution loop | 🟢 | JIT-first with interpreter fallback, FNV hash staleness checks, syscall/import/exception exits, resumable |
| Host trampoline | 🟢 | Translated blocks invoke as `void(*)(GuestContext*)` with pinned X0/X19/X20 ABI (`CtxLayout.h`) |
| Code cache | 🟢 | W^X `seal`/`unseal`, concurrency-safe install + icache flush, **persistent save/load** ("NINE" v2 format keyed by image hash + translator version) |
| AOT emitter (`aot/`) | 🟡 | Relinker-side ahead-of-time compiler: decodes each executable range of a mapped/relocated ELF or PE, emits one AArch64 function per basic block into a self-contained `.nine.aot` image (header + blocks + helper relocations + code, FNV-1a checked), and `AotEngine`/`AotModule` load, patch and dispatch it with no decoder, code cache or SMC tracking. All-or-nothing per module: an unsupported instruction means no image and the mnemonics are reported by name. Integer/flag/branch/memory subset only (list in ARCHITECTURE.md §1.3) — SSE/AVX, `IMUL`, `DIV`, string ops and x87 are still refused. Images are produced and load-tested today; the run path does not yet prefer them over the translator |
| SMC coherency | 🟢 | Exec-page tracking; stores into executable pages invalidate overlapping translations |
| Self-mod code + counters | 🟢 | Invalidation, hit/trace/IC counters exposed to UI |
| Linux syscall ABI | 🟡 | 62 numbers with a `case` arm (documented per number in `SUPPORTED.md` §1): read/write/open*/close/mmap/mprotect/munmap/brk, exit*, pid/uid family, fstat family, getrandom, stat/lstat/fstat/newfstatat, getdents64, poll, writev/readv, uname (spoofs x86_64), `arch_prctl` FS/GS into guest ctx; futex/signals bookkeeping stubs; fork/execve → `-ENOSYS` |
| Windows ABI | 🟡 | every export is a real callable thunk (`WinAbi`): 16-byte guest stub → reserved syscall → Microsoft x64 marshaller → native handler. 105 kernel32 export names (each also registered on kernelbase) plus ntdll and 55 user32/gdi32/advapi32 exports — files, memory, heap, threads, events/waits, TLS, critical sections/SRW, time, environment, ANSI/UTF-16, error codes; user32/gdi32/advapi32 callable; unknown names of a shim module become logged no-ops instead of jumping into unmapped memory |
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
- **Debugger**: pause / resume / single-step (forced-interpreter), PC breakpoints, guest status snapshot; plus a feature matrix screen listing 83 roadmap rows (Phase 0–8, J1–J5, GUI/D3D/32-bit, app/AI surfaces) with a native test runner (`NativeTests.run(id)`).
- **AI stack**:
  - Cloud chat against any OpenAI-compatible endpoint (configurable URL/key/model list), with tool calling.
  - Local models: `.gguf` via llama.cpp in `libnexus_core` (greedy decode); `.tflite` path exists but with a byte-level test tokenizer.
  - Model search/download from Hugging Face with device-aware filtering (RAM, NPU, quant picker), background + notification progress.
- **Agent tool-calling**: a multi-dialect parser (fenced blocks, OpenAI `tool_calls`, Mistral `[TOOL_CALLS]`, Qwen/Llama-3.1 XML & `<|python_tag|>`, Hermes, key=value lines, Python-call syntax), 11 built-in executor tools (`search_web`, file CRUD in a sandbox workspace, `compile_extension`, `compile_patch`, `add_tool`).
- **Repositories / Extensions**: browse GitHub `nine-catalog.json` catalogs, download extensions → real `PackageInstaller` APK install session, patches downloaded.
- **VHD manager**: create fixed/sparse raw disk images (512–4096-byte sectors), real MBR partition table, and **genuine FAT12/16/32 formatting**, best-effort exFAT layout, stubbed NTFS/ext plus ~17 other filesystem magics; gzip compress-on-background / decompress-on-foreground lifecycle; delete and `.tar.gz` export with sidecars; **active VHD** (explicit pick via tap in the manager, else newest) recorded for all programs and shared with light shells.
- **DLSS-style upscaling** (first-party, `app/src/main/cpp/upscale/`): bilinear base pass + edge-adaptive unsharp refinement; own `.n9up` model format (magic, version, scale, tap weights) with `.tflite`/`.onnx` accepted as opaque payloads until a real NN runtime lands. Settings → PERFORMANCE: DLSS switch + folder-picker import (copied into `files/upscaler/model`, greyed while the switch is off); the same pair exists inside light shells.
- **Game detection** (`GameDetector`): scored byte-scan of the first 2 MiB (D3D/GL/Vulkan/SDL/GLFW/XInput/engine tokens, weak signals saturated), threshold ≥ 35 pts; runs at every `loadAndRun` and is JNI-exposed (`detectGame`) for the Library UI.
- **Light shells** (`:shell` module + runtime APK surgery): Relink builds **one shell APK per selected program** — template `assets/shell-template.apk` is patched via binary-XML string-pool rewriting (`AxmlPatcher`: unique package `com.nine.shell.<program>`, program label, derived component names), icon replaced with a generated PNG, program payload + `libnexus_core.so` + `vhd_path.txt` embedded, **v1-signed** with a throwaway self-signed RSA key (`ApkV1Signer`, hand-built X.509/PKCS#7 DER — UTCTime YY, plain SHA-256 digest alg, PKCS#9 contentType attribute, `A0` directly wrapping attribute SEQUENCEs, per-entry `.SF` sections; offline-verified against `apksigner` via `devtools/signer_check.py`), saved to `/sdcard/NINE/shells` (needs All-files access, requested from the tutorial and a one-off launch prompt; app-scoped fallback). Every APK is built before any prompt appears, then `ShellInstallQueue` commits the `PackageInstaller` sessions **one at a time**, granting each package its VHD access (per-package `com.nine.dbt.vhdshare` grant) as its install lands. When the batch is exactly one shell, a `Run <program>?` dialog offers to launch it immediately. Every non-`META-INF` entry including the core `.so` is covered by the signature.
- **Shell payload persistence**: Android only keeps payload files that look like part of the native-library surface, so every guest binary is mirrored as `lib/arm64-v8a/libnine_<n>.so` and mapped back to its real program path by `assets/program/payload.json`; the package manager extracts those into `nativeLibraryDir`, and the shell reads them from there (falling back to the `assets/program/**` copy when a slot is missing). This keeps executables and guest libraries present across installs instead of being dropped as non-`.so`/`.o` files.
- **Shell UI**: plain-View activities styled like NINE (near-black `#0A0A12`, cyan `#00E5FF`/purple `#7C4DFF` accents, `9` header mark, letter-spaced mono labels, rounded stroked cards) — home shows program + live run status over the render SurfaceView, settings holds the DLSS pair / model import / VHD path / session-log entry, and the log viewer mirrors the Logs tab's monospace panel.

### JNI surfaces

- `com.nine.dbt.GuestRuntime` → loadAndRun, relink, stop/pause/resume/step, breakpoints, status, `detectGame`, upscaler model/status/enable (crash-guarded: guest SIGSEGV does not kill the app).
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
| kernel32 (callable thunks) | 🟩 GetModuleHandle/ProcAddress/LoadLibrary/FreeLibrary/GetModuleFileNameA/W, CreateFileA/W/ReadFile/WriteFile/CloseHandle/GetStdHandle/GetFileType/GetFileSize(Ex)/SetFilePointer(Ex)/FlushFileBuffers/DeleteFile, VirtualAlloc/Free/Protect/Query, GetLastError/SetLastError, GetCurrentProcess/Thread/PID/TID, IsDebuggerPresent, QueryPerf*/GetTick*, GetSystemTime(AsFileTime)/GetLocalTime, GetCommandLineA/W, Get/SetEnvVar + GetEnvironmentStringsW, MultiByte/WideChar, lstrlen/lstrcpy/lstrcmp, all critical-section + SRW APIs, CreateThread/Sleep/SwitchToThread, CreateEventA/W/SetEvent/ResetEvent/WaitForSingleObject, TLS, heap (GetProcessHeap/HeapAlloc/Free/ReAlloc/Size), Interlocked*, GetSystemInfo/GetVersion/IsProcessorFeaturePresent, EncodePointer/DecodePointer, OutputDebugString | 🟨 ExitProcess/ExitThread (logged, no teardown), x87 returns | ⬛ CreateProcess, file mapping/overlapped I/O, FindFirstFile*, WaitForMultipleObjects, FormatMessage, console/codepages, varargs marshalling |
| user32 | 🟨 MessageBoxA / GetDesktopWindow fake-address | ⬛ message pump, windows, input | G1: SurfaceView HWND + software GDI |
| gdi32 | ⬛ anything realizer-level | 🟨 fake addresses | G1 software DC/framebuffer |
| advapi32 | 🟨 RegOpenKeyExA failure-correct | ⬛ registry emulation, LSA | |
| shell32 / comctl32 / comdlg32 | ⬛ everything | | |
| ole32 / oleaut32 (COM) | ⬛ everything (vtable/AddRef/QueryInterface plumbing absent) | | |
| ws2_32 | ⬛ Winsock bridge | | |
| d3d9/d3d11/d3d12/d2d1/dwrite/dxgi/winmm/xinput | ⬛ G2 interception phase | | |
| msvcrt / ucrtbase | ⬛ CRT runtime shim | | |

#### Windows system DLL inventory (app-linkable libraries)

Every DLL a Windows app can link against, grouped by purpose. 🟩 = NINE implements real behavior · 🟨 = stub-recognized (fake IAT addresses / safe-fail dispatch) · ⬛ = not implemented (unresolved imports). Note: on Win10+ the syscall *bodies* behind kernel32/user32/gdi32 live in **kernelbase.dll** and **win32u.dll**, and `api-ms-win-*` **API-set** redirection is resolved at load time — the loader must treat API-set names as aliases.

| Library | Purpose | Status |
|---|---|---|
| ntdll.dll | Native API, RTL heap/critical-sections, LDR/PEB, SEH base | 🟨 (8 RTL primitives + Ldr real; most `Nt*` ⬛) |
| kernel32.dll | Base API: process/thread/memory/file/sync/console | 🟩 callable thunks, ~70 handlers (see the Windows grid above) |
| kernelbase.dll | Win10+ merged kernel32/advapi32 bodies | 🟩 forwards to the same handlers as kernel32 |
| win32u.dll | Win10+ syscall layer for user32/gdi32 | ⬛ |
| user32.dll | Windows, message loop, input, hotkeys, timers | 🟨 (2 fake-address stubs) |
| gdi32.dll | Device contexts BitBlt/GDI raster | 🟨 (fake addresses) |
| advapi32.dll | Registry, services, LSA, event log, crypto (legacy) | 🟨 (RegOpenKeyExA fail-correct) |
| shell32.dll | Shell namespace, icons, SHFileOperation, tray | ⬛ |
| shlwapi.dll | Path/URL/registry string helpers | ⬛ |
| shcore.dll | HiDPI scaling, display enumeration | ⬛ |
| comctl32.dll | Common controls (listview, toolbar, hotkey...) | ⬛ |
| comdlg32.dll | Common dialogs (open/save/print/color) | ⬛ |
| ole32.dll | COM activation, apartment management | ⬛ |
| oleaut32.dll | OLE Automation, typelib, SAFEARRAYs | ⬛ |
| combase.dll | Modern COM platform API | ⬛ |
| propsys.dll | Property system / metadata | ⬛ |
| ws2_32.dll | Winsock 2 networking | ⬛ |
| wsock32.dll | Winsock 1.x compat shim | ⬛ |
| mswsock.dll | Kernel-mode socket extensions (AIO, DNS queries) | ⬛ |
| wininet.dll | High-level HTTP/FTP (IE stack) | ⬛ |
| winhttp.dll | HTTP client services | ⬛ |
| urlmon.dll | URL Monikers / MIME handling | ⬛ |
| dnsapi.dll | DNS resolution | ⬛ |
| iphlpapi.dll | IP helper (adapters, ARP, routes) | ⬛ |
| netapi32.dll | Network management APIs | ⬛ |
| mpr.dll | Multi-provider network routing | ⬛ |
| wldap32.dll | LDAP client | ⬛ |
| secur32.dll / sspicli.dll | SSPI security channels (NTLM/Kerberos) | ⬛ |
| rpcrt4.dll | RPC runtime (COM channel too) | ⬛ |
| crypt32.dll | Certificates, PKI, CryptProtectData (DPAPI) | ⬛ |
| bcrypt.dll + bcryptprimitives.dll | CNG crypto primitives (AES/SHA/RNG) | ⬛ |
| ncrypt.dll | CNG key storage / certificates | ⬛ |
| cryptbase.dll / cryptnet.dll | Crypto base SPI + network CRL fetch | ⬛ |
| wintrust.dll | Authenticode signature verification | ⬛ |
| winmm.dll | Wave/midi, mciSendString, time functions | ⬛ |
| dsound.dll | DirectSound audio | ⬛ |
| dinput8.dll | DirectInput input devices | ⬛ |
| xinput1_4.dll / xinput9_1_0.dll | Gamepad API | ⬛ |
| xaudio2_*.dll / xapofx1_*.dll / x3daudio1_*.dll | XAudio2 DSP stack | ⬛ |
| ddraw.dll | DirectDraw legacy 2D/3D | ⬛ |
| d3d8.dll / d3d9.dll / d3d10.dll / d3d10_1.dll / d3d11.dll / d3d12.dll | DirectX 3D | ⬛ |
| d3dcompiler_47.dll | HLSL compiler | ⬛ |
| dxgi.dll | Swapchains, adapters, output resolution | ⬛ |
| dxcore.dll | Modern adapter enumeration | ⬛ |
| d2d1.dll | Direct2D vector raster | ⬛ |
| dwrite.dll | DirectWrite font shaping/rendering | ⬛ |
| dwmapi.dll | Desktop Window Manager composition | ⬛ |
| uxtheme.dll | Theme visual styles | ⬛ |
| imm32.dll | Input Method Editor bridge | ⬛ |
| opengl32.dll / glu32.dll | OpenGL + WGL | ⬛ |
| gdiplus.dll | GDI+ 2D vector/image/metafiles | ⬛ |
| windowscodecs.dll | WIC image codecs (PNG/JPEG/TIFF...) | ⬛ |
| mfplat.dll / mf.dll / mfreadwrite.dll / mfplay.dll | Media Foundation pipeline | ⬛ |
| wmva? evr.dll / wmvcore.dll | Enhanced video renderer, WM media | ⬛ |
| msvcrt.dll | Legacy msvcrt export set | ⬛ |
| ucrtbase.dll | Universal CRT (api-ms-win-crt-* forward to it) | ⬛ |
| msvcp140.dll / vcruntime140.dll / concrt140.dll | VC++ toolchain runtimes (redistributable) | ⬛ |
| dbghelp.dll | Symbol inspection, minidumps | ⬛ |
| imagehlp.dll | Image integrity/tooling | ⬛ |
| version.dll | File version metadata | ⬛ |
| psapi.dll | Process memory/module enumeration | ⬛ |
| powrprof.dll | Power schemes / battery state | ⬛ |
| userenv.dll | Profiles / environment expansion | ⬛ |
| wtsapi32.dll | Terminal-services (RDP) session APIs | ⬛ |
| wevtapi.dll | Event log publishing/consumer | ⬛ |
| setupapi.dll / cfgmgr32.dll / devobj.dll / newdev.dll | Device enumeration + INF install | ⬛ |
| winspool.drv | Printing spooler | ⬛ |
| winusb.dll / hid.dll / ksuser.dll | Raw USB/HID/kernel-streaming | ⬛ |
| virtdisk.dll | Virtual disk (VHD/VHDX) management API | ⬛ |
| winbio.dll | Biometric auth | ⬛ |
| sapi.dll / mmdevapi.dll / msacm32.dll | Speech, default audio endpoint, codecs | ⬛ |
| winscard.dll / tapi32.dll / winfax.dll | Smart card, TAPI, fax | ⬛ |
| msi.dll | Installer engine | ⬛ |
| odbc32.dll / odbccp32.dll | ODBC driver-manager | ⬛ |
| ntdsapi.dll / activeds.dll / adsldp*.dll | Active Directory clients | ⬛ |
| api-ms-win-* (≈400 libs) | API-set forwarders, alias table pending | ⬛ |
| api-ms-win-downlevel-* / unicows / msvcrt legacy set | Downlevel compat versions | ⬛ |

### Linux API (ELF guests, primary today)

| Group | 🟩 | 🟨 | ⬛ |
|---|---|---|---|
| Bootstrap | 🟩 ELF64 map, auxv (AT_PHDR…AT_HWCAP2/AT_RANDOM/AT_EXECFN), stack/argv/envp, TLS + `arch_prctl`, static `_start→__libc_start_main`, vDSO start | 🟨 ldso dynamic path audit, vDSO depth | ⬛ `/proc/self/*` demux, full signal delivery |
| Mem syscalls | 🟩 mmap/mprotect/munmap/brk/mremap(25, emulated)/madvise-stub | 🟨 msync | ⬛ process VM overlays (mincore, remap within-same protocols) |
| File syscalls | 🟩 open/openat/read/write/readv/writev/lseek/close/dup/dup2/fcntl/access/faccessat/getcwd/chdir/stat/fstat/lstat/newfstatat/readlinkat/getdents64/prlimit64 | 🟨 pread64/pwrite64 partial, ioctl stub | ⬛ pipe/pipe2, mkdir/rmdir/rename/unlink legacy, truncate/flock, inotify, fanotify, mount family |
| Process | 🟩 exit/exit_group/getpid/getppid/gettid/getuid/geteuid/getgid/getegid/clone/set_tid_address/tgkill/sysinfo | 🟨 futex WAIT/WAKE only; fork/vfork/execve→ENOSYS | ⬛ wait4/kill, ptrace, namespaces, cgroups |
| Sched / time | 🟩 nanosleep, sched_yield, sched group (144-147), sched_getaffinity, clock_gettime, gettimeofday | | ⬛ timer_create, itimers, epoll_wait (busy apps) |
| Signals | 🟨 rt_sigaction/rt_sigprocmask bookkeeping stubs | | ⬛ real delivery, sigaltstack, rt_sigtimedwait |
| Sockets | — | — | ⬛ socket/connect/bind/listen/accept, sendto/recvfrom, socketpair, recvmsg/sendmsg (numbers are enumerated, every one returns `-ENOSYS`) |
| Misc | 🟩 uname (x86_64 spoof), getrandom, prctl (partial), rseq→ENOSYS graceful | 🟨 sysinfo struct fill | ⬛ bpf, perf_event, io_uring |

#### Linux system library inventory (all programs link these)

What a dynamically linked ELF can `DT_NEEDED`. 🟩 = satisfiable today (in-image for static glibc guests, or resolvable/bundled through the Relinker's library table) · 🟨 = recognized by the loader abstraction but not bundled · ⬛ = not provided — a dynamic guest needing it fails at symbol resolution until the Relinker ships it. Static-binaries sidestep every row: glibc is baked in, and everything here is demand-driven backlog only when a *dynamic* guest needs it.

| Library family | Contents | Status |
|---|---|---|
| Dynamic loader | `ld-linux-x86-64.so.2` (ldso: PT_INTERP bootstrap, path search, versioned symbols, dlopen) | 🟩 (loader runs; audit untested) |
| glibc core | `libc.so.6` (ISO C + POSIX: stdio, malloc, string, env, locale, iconv, qsort, time, sockets wrappers...) | 🟩 (static guests bake it in; dynamic via ldso path 🟨) |
| glibc math | `libm.so.6` (sinf/cos/exp/log/pow...) | 🟩 (in-image for statics) |
| glibc POSIX split-outs (merged into libc.so.6 in glibc ≥2.34; callers still link the stub sonames) | `libpthread.so.0`, `libdl.so.2`, `librt.so.1`, `libutil.so.1` | 🟩 (merge-aware support in loader) |
| glibc crypt | `libcrypt.so.2` / libxcrypt | 🟨 |
| glibc resolver | `libresolv.so.2` (getaddrinfo plumbing, gai) | 🟨 (interface recognized) |
| glibc async name | `libanl.so.1` (getaddrinfo_a) | ⬛ |
| glibc NIS | `libnsl.so.3` (legacy ypbind/RPC glue) | ⬛ |
| broken locale | `libBrokenLocale.so.1` | ⬛ |
| NSS service modules | `libnss_files.so.2`, `libnss_dns.so.2`, `libnss_compat`, `libnss_nis`, `libnss_db`, `libnss_hesiod` (getent/passwd/hosts sources) | ⬛ |
| LD_PRELOAD/audit internals | `libc.so, libc_nonshared.a`, `libthread_db.so` (gdb glue) | ⬛ |
| GCC / clang runtime | `libgcc_s.so.1` (unwinder, split atomics), `libatomic.so.1`, `libstdc++.so.6` (C++ ABI + libsupc++), `libc++`(Clang alt), `libquadmath`, `libgfortran` (Fortran), `libgomp` (OpenMP), `libitanium`, `libsanitizer` | 🟨 handled for statics only; dynamic unresolved |
| Compression codecs | `libz.so.1`, `libbz2.so.1`, `liblzma.so.5`, `libzstd.so.1`, `liblz4.so.1` | ⬛ |
| SSL / TLS | `libssl.so.3`, `libcrypto.so.3`; also `libgnutls.so.30`, `libgcrypt.so.20`, `libgpg-error` | ⬛ |
| HTTP / URI | `libcurl.so.4`, `libnghttp2`, `libidn2`, `libpsl`, `libunistring`, `libssh` | ⬛ |
| Kerberos / auth / LDAP | `libgssapi_krb5.so.2`, `libkrb5.so.3`, `libk5crypto.so.3`, `libcom_err.so.2`, `libsasl2`, `libldap`, `libnss3.so`(Mozilla NSS), `libnspr4` | ⬛ |
| RPC | `libtirpc.so.3`, `librpcsvc`, `libgssrpc` | ⬛ |
| DBus / systemd | `libdbus-1.so.3`, `libsystemd.so.0`, `libudev.so.1`, `libsd-bus` | ⬛ |
| Kernel-adjacent helpers | `libseccomp.so.2`, `libcap.so.2`, `libacl.so.1`, `libattr.so.1`, `libselinux.so.1`, `libpam.so.0`, `libaudit.so.1`, `libcap-ng`, `libmount`/`libblkid`/`libuuid` (util-linux), `libnuma`, `libaio`, `liburing(aio 2)` | ⬛ |
| C_Helper (glib family) | `libglib-2.0.so`, `libgobject-2.0.so`, `libgio.so`, `libffi.so.8` | ⬛ |
| X11 / Wayland stack | `libX11.so.6`, `libxcb.so.1` (+`-util`, `-image`, `-shm`, `xfixes` etc), `libXext`, `libXrender`, `libXrandr`, `libXi`, `libXinerama`, `libXcursor`, `libXfixes`, `libXau`, `libXdmcp`, `libxkbcommon`(+`-x11`), `libwayland-client/server` | ⬛ |
| OpenGL / Vulkan | `libGL.so.1`, `libGLX.so.0`, `libOpenGL.so.0`, `libEGL.so.1`, `libGLESv2.so`, `libdrm.so.2`, `libgbm.so.1`, `libvulkan.so.1`, `libva`/`libvdpau` | ⬛ |
| Audio | `libasound.so.2` (ALSA), `libpulse.so.0` (PulseAudio), `libpulse-simple`, `libjack` | ⬛ |
| Text / regex / markup | `libpcre.so.1` / `libpcre2-8.so.0`, `libexpat.so.1`, `libxml2`, `libxslt`, `libfontconfig.so.1`, `libfreetype.so.6`, `libharfbuzz.so.0`, `libcairo.so.2`, `libpango` | ⬛ |
| Imaging | `libpng16.so.16`, `libjpeg.so.8/62/9`, `libtiff`, `libwebp`, `libgif` | ⬛ |
| Toolkits | `libgtk-3.so.0`, `libgdk`, `libatk`, `libQt5/6Core/Gui/Widgets...` | ⬛ |
| media codecs | `libavcodec` / `libavformat` / `libavutil` / `libswscale` (usually bundled), `libogg`, `libvorbis`, `libopus`, `libx264`, `libx265` | ⬛ |
| printing / CUPS | `libcups.so.2` | ⬛ |
| NIS/RPC legacy | `libnsl.so.1` legacy symlink | ⬛ |
| alternative libc | musl-exclusive imports (`musl libc`, rarely as app `DT_NEEDED`, static binaries etc) | ⬛ |
| debug/diag | `libSegFault.so` (glibc crash handler catchsegv) | ⬛ |

### x86-64 instruction coverage (detail per family in ARCHITECTURE.md §2)

| Family | State |
|---|---|
| Decoding infrastructure (prefixes, ModRM/SIB incl. idx=4 trap + abs32 disp, REX, RIP-relative, FS/GS bases) | 🟩 (VEX and EVEX fully decoded into the same IR — §2.21) |
| MOV family (88–8B, A0–A3, B0–B7 `mov r8,imm8`, B8–BF, C6/C7, 63 MOVSXD, 98 CWDE/CDQE, 99 CDQ, XCHG 86/87/90+r) | 🟩 (BSWAP, MOVBE, MOVDIRI/MOVDIR64B 🟩; AH/CH/DH/BH honoured as bits 15:8 in interpreter and AOT) |
| ALU (00–3B all 8 groups + eAX-imm 04-3D forms + 80/81/83 imm) | 🟩 with true ADC/SBB carry |
| ADX (ADCX/ADOX 0F 38 F6), ASCII/BCD adjust (AAA/AAS/AAM/AAD, DAA/DAS) | 🟩 |
| Bit test/scan: BT/BTS/BTR/BTC, BSF/BSR, TZCNT/LZCNT, BSWAP | 🟩 |
| BMI1: ANDN, BLSI, BLSMSK, BLSR, BEXTR, BZHI (real VEX C4/C5 decoding) | 🟩 |
| Flag control CLC/STC/CMC/CLI/STI/CLD/STD/CLAC/STAC, cache hints CLFLUSH/CLFLUSHOPT/CLWB/CLDEMOTE | 🟩 |
| MPX bound registers: BNDMK/BNDMOV/BNDCL/BNDCU/BNDCN | 🟩 (BNDLDX/BNDSTX 🟨, no bound tables) |
| Legacy/compat-only ARPL/BOUND (63/62) | 🟨 (`setCompat32(true)` decode path) |
| TEST/INC/DEC/NEG/NOT, grp3 F6/F7 MUL/IMUL/DIV/IDIV, IMUL 2/3-op + 0F AF | 🟩 |
| Shifts C0/C1/D0–D3 (SHL/SHR/SAR/ROL/ROR), FF/F-shifts, FE/FF inc/dec/jmp/call/push mem | 🟩 (RCL/RCR, SHLD/SHRD ⬛) |
| PUSH/POP (incl. 8F /0, moffs store), LEAVE, ENTER (frame chain, level & 31) | 🟩 |
| Jcc (all 16, near+short), CMOVcc, SETcc, JMP/CALL/RET (± imm16) | 🟩 |
| LOOP/LOOPE/LOOPNE/JRCXZ (E0–E3, RCX counter) | 🟩 |
| String ops MOVS/STOS/LODS/SCAS/CMPS 8/16/32/64 with FS/GS segment override, REPE/REPNE | 🟩 (REP loops 🟨) |
| RMW atomics CMPXCHG 0F B0/B1, CMPXCHG8B/16B 0F C7 /1, XADD 0F C0/C1 | 🟩 (true LOCK-multicore atomics 🟨) |
| SSE dataplane for glibc startup: MOVD/MOVQ/MOVAPS-family 128-bit moves/MOVLPS/MOVHPS/PUNPCKLDQ/LQDQ/HQDQ/PXOR | 🟩 |
| Scalar/lane moves: MOVSS/MOVSD (merge vs zero), MOVHLPS/MOVLHPS, MOVLPD/MOVHPD, MOVDDUP/MOVSLDUP/MOVSHDUP, MOVMSKPS/MOVMSKPD | 🟩 |
| SSE/SSE2/SSE3 FP add: ADDPS/ADDPD/ADDSS/ADDSD, ADDSUBPS/ADDSUBPD | 🟩 |
| SIMD logical/blends: ANDPS/ANDPD/ANDNPS/ANDNPD, ORPS/ORPD, BLENDPS/BLENDPD, BLENDVPS/BLENDVPD, PBLENDVB/PBLENDW | 🟩 |
| SIMD multiply/min/max: MULPS/MULPD/MULSS/MULSD, MINPS/MINPD/MINSS/MINSD, MAXPS/MAXPD/MAXSS/MAXSD (NaN → second source) | 🟩 |
| Packed integer: PABSB/W/D/Q, PACKSSWB/SSDW/USWB/USDW, PADDB/W/D/Q, PADDSB/W, PADDUSB/W, PAVGB/W, PAND/PANDN, PALIGNR, PCMPEQB/W/D, PCLMULQDQ, MPSADBW | 🟩 |
| Non-temporal / direct stores: MOVNTPS/MOVNTPD/MOVNTDQ/MOVNTQ/MOVNTI/MOVNTDQA, MOVDIRI/MOVDIR64B, MASKMOVDQU | 🟩 (hints collapse to plain stores) |
| SSE divides + horizontal: DIVPS/DIVPD/DIVSS/DIVSD, HADDPS/HADDPD, HSUBPS/HSUBPD | 🟩 |
| SSE4.1 dot product/extract: DPPS/DPPD (imm8 lane masks), EXTRACTPS | 🟩 |
| GFNI: GF2P8MULB, GF2P8AFFINEQB, GF2P8AFFINEINVQB (GF(2^8), AES polynomial) | 🟩 |
| AES-NI: AESENC/AESENCLAST/AESDEC/AESDECLAST/AESIMC/AESKEYGENASSIST | 🟩 |
| Key Locker: AES{ENC,DEC}{128,256}KL + AES{ENC,DEC}WIDE{128,256}KL | 🟩 (NINE software handle; ARCHITECTURE.md §2.14) |
| SSE/SSE2 compare + convert: CMPPS/CMPPD/CMPSS/CMPSD, COMISS/COMISD, CVT{DQ2PD,DQ2PS,PS2DQ,PS2PD,SD2SS,SS2SD,SD2SI,SS2SI,SI2SD,SI2SS,TTPD2DQ,TSD2SI,TTSS2SI}, CRC32 (CRC-32C) | 🟩 (MMX-destination CVT*2PI decoded, refused) |
| CPUID (0F A2) synthesized leaf set, CLTS/CLUI/CLRSSBSY privileged faults | 🟩 (deterministic model, ARCHITECTURE.md §2.10.1) |
| x87 FPU (D8–DF): FLD/FST/FSTP/FILD/FIST/FISTP/FISTTP/FBLD/FBSTP, FADD…FDIVR (m32/m64/m16-int + ST(i) forms), FCOM/FUCOM/FCOMI/FCOMIP, FTST/FXAM/FXTRACT/FSCALE/FPREM/FPREM1/FRNDINT/FSQRT/FCHS/FABS, FSIN/FCOS/FSINCOS/FPTAN/FPATAN/F2XM1/FYL2X/FYL2XP1, FLD1/FLDZ/FLDPI/FLDL2E/FLDL2T/FLDLG2/FLDLN2, FLDCW/FNSTCW/FLDENV/FNSTENV/FNSAVE/FRSTOR/FNCLEX/FNINIT/FNOP/FWAIT/FXCH/FFREE/FCMOVcc, FXSAVE/FXRSTOR, EMMS | 🟩 (80-bit register file + control/status/tag words, ARCHITECTURE.md §2.9) |
| AVX-512 opmask registers: KAND/KANDN/KOR/KXOR/KXNOR/KNOT/KADD/KUNPCK/KTEST/KORTEST/KSHIFTL/KSHIFTR/KMOV (k0–k7) | 🟩 (zmm/EVEX now covered by §2.21) |
| SSE4.1 insert: INSERTPS (lane select + zero mask) | 🟩 |
| SSE loads/stores: LDDQU, LDMXCSR (MXCSR is live; rounding control not applied yet) | 🟩 |
| I/O and privileged batch: IN/INS, INV D/INVLPG/INVPCID, INCSSPD/Q, INT n/INT1/INTO/IRET, LDTILECFG — decoded exactly, then the fault real hardware raises at CPL 3 | 🟩 |
| LAHF (AH ← SF:ZF:0:AF:0:PF:1:CF), LAR (canonical long-mode selectors), LDS (compat mode) | 🟩 (LDS 🟨) |
| Packed integer (§2.18): PCMPEQ/PCMPGT (B/W/D/Q), PSUB{S,US}, PUNPCK{L,H}, PSHUFD/HW/LW/W, PSHUFB, PSLL/PSRL/PSRA (W/D/Q, imm and register count), PSLLDQ/PSRLDQ, PMUL{LW,HW,HUW,LD,LQ,UDQ,DQ,HRSW}, PMADDWD/PMADDUBSW, PMIN/PMAX (B/W/D/Q signed and unsigned), PMOVMSKB, PMOVSX*/PMOVZX*, PEXTRB/W/D/Q, PINSRB/W/D/Q, PSIGN, PSADBW, PHADD/PHSUB(+SW), PHMINPOSUW, PTEST, POR | 🟩 |
| SSE4.2 string compare: PCMPESTRI/PCMPESTRM (EAX/EDX lengths), PCMPISTRI/PCMPISTRM (NUL lengths), all four aggregations and polarities | 🟩 |
| GPR/system: POPCNT, RCL/RCR, PUSHFQ/POPFQ, PUSH imm32/imm8, PUSHA/POPA (#UD), RDFSBASE/RDGSBASE, RDMSR/RDPMC (#GP), RDPID, RDPKRU/PCONFIG/PTWRITE (#UD), RDRAND, PDEP/PEXT, PREFETCH/PREFETCHW/PREFETCHh | 🟩 |
| SSE1/2/3/SSSE3/4.1/4.2 beyond adds/AES/compare/convert | 🟨 (packed integer, SSE4.2 string ops, sqrt/sub/unpack/round/rsqrt done — §2.18/§2.20) |
| AVX / VEX.128+256, AVX2: full VEX data path with 32 × 64-byte ymm/zmm registers — moves, packed integer, FP arithmetic, shifts, shuffles/permutes, blends, conversions, FMA, AES/CLMUL/GFNI, gather/scatter, crypto (ARCHITECTURE.md §2.21) | 🟩 |
| EVEX / AVX-512: zmm16-31, k0-k7 writemasks with merge/zeroing, broadcast, disp8×N, ternary logic, VPTERNLOG, VPCMP*, VFPCLASS, VCOMPRESS/VPEXPAND, VPMOV* narrowing (453 encoding rows) | 🟩 (no SAE/ER) |
| SGX: ENCLS (ECREATE/EADD/EAUG/EBLOCK/EDBGRD/EDBGWR/EEXTEND/EINIT/ELDB/ELDU/ELDBC/ELDUC/EMODPR/EMODT/EPA/ERDINFO/EREMOVE/ETRACK/ETRACKC/EWB), ENCLU (EACCEPT/EACCEPTCOPY/EDECCSSA/EENTER/EEXIT/EGETKEY/EMODPE/EREPORT/ERESUME), ENCLV (EDECVIRTCHILD/EINCVIRTCHILD/ESETCONTEXT) | 🟩 (§2.22; privileged leaves #UD at CPL 3) |
| System: ENDBR32/ENDBR64, UD2/UD0/UD1, INT3, CPUID (synthetic), SYSCALL routing, HLT, RDMSR/RDPMC (#GP at CPL 3), RDTSC/RDTSCP/RDSEED, XGETBV/XSETBV, XSAVE/XRSTOR/XSAVEC/XSAVEOPT (+ XSAVES/XRSTORS faults), XTEST/XBEGIN/XEND/XABORT, SERIALIZE | 🟩 (ARCHITECTURE.md §2.20) |
| Scalar/system §2.20: SAHF, SGDT/SIDT/SLDT/STR/SMSW/VERR/VERW, SHLD/SHRD, RORX, SHLX/SARX/SHRX, SQRT*, SUB*, UNPCK{PS,PD}, ROUND*, RSQRT*, STMXCSR, SHA1*/SHA256*, RDSSPD/Q, RSTORSSP, WRSS/WRUSS, TPAUSE/UMONITOR/UMWAIT, WRFSBASE/WRGSBASE, VZEROUPPER/VZEROALL, AMD TBM (TZMSK/T1MSKC), RSM/SEAM*/STGI/CLGI/SYSENTER/SYSEXIT/SYSRET/SWAPGS/WRMSR/WBINVD (#GP or #UD as hardware does) | 🟩 |
| Descriptor/status loads: LGDT/LIDT/LLDT/LTR/LMSW (#GP), LSL, LFS/LGS/LSS/LES (offset half), MOV to/from CR/DR (#GP), MONITOR/MWAIT (#GP) | 🟩 |
| Fences LFENCE/MFENCE/SFENCE, LOCK prefix | 🟩 (ordered no-ops for one guest CPU) |
| MULX (RDX × r/m → reg:vvvv, flags untouched) | 🟩 |
| Restricted-by-CR4 forms: ENQCMD/ENQCMDS, ENCODEKEY128/256 (#UD), HRESET (#GP) | 🟩 decoded exactly, then the fault real hardware raises |
| PAUSE | 🟩 retires as NOP |

## What it can do today

- **Load a statically linked x86-64 Linux ELF from storage and run it end-to-end**, through the interpreter-backed execution loop, and see its `hello world` stdout in the Logs tab — fully offline, zero external compatibility layers.
- Relink an ELF against bundled guest libraries, get a JSON report of resolved/unresolved symbols, and package the result for distribution.
- Load PE32+ executables: mapped, rebased (ASLR-style), and every imported function patched to a **real callable thunk** that marshals the Microsoft x64 convention into a native handler — simple console apps that use implemented APIs (`WriteFile`, `ExitProcess`, `VirtualAlloc`, …) work, and a call to an API NINE has not written yet is a logged no-op rather than a jump into unmapped memory.
- **Relink emits AOT images**: every Relink (ELF or PE) also compiles the executable ranges ahead of time and writes `<stem>.<n>.nine.aot` next to the program, with a JSON summary (`aot.ok`, module/block/byte counts) or the blocking mnemonics when a range cannot be compiled. The same generated AArch64 has been executed on device through `AotEngine`, including guest-memory operands, calls, and high-byte register forms.
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
13. **Runtime `.so` split + translated relinker** — split `libnexus_core` into component `.so`s (`core` / `jit` / `abi_windows` / `abi_linux` / `ai`) so per-program relinking stays light; emit self-contained light APKs that bundle a program + only the ABI surfaces it imports (see ARCHITECTURE.md §1.2).
14. **Finish the AOT path** — wire `.nine.aot` images into `ExecutionLoop` and the light shell so a relinked program runs the pre-compiled blocks instead of re-translating (the engine, image format and relinker step already exist), then grow the emitter past its integer subset: `IMUL`/`DIV`, string ops with REP, SSE moves/arithmetic, and x87 — each one moves a real binary from "refused by name" to "runs without a translator".

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
                            translator/, aot/, runtime/, abi/, diagnostics/, upscale/,
                            llama/, tests/
app/src/main/java/          com.nine.dbt — Compose UI, VHD manager, light-shell packager
                            (AxmlPatcher/ApkV1Signer/ShellInstallQueue) + GuestRuntime/
                            Llama/NativeTests bridges
shell/                      :shell — the light-shell host APK (program launcher, settings,
                            logs, render surface)
devtools/                   signer_check.py / cert_probe.py / pkcs7_diff.py (offline
                            APK-signature verification), test_light_shell.ps1,
                            toolcalling-tests/ (parser/E2E/stub tests)
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
