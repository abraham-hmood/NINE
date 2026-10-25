# Native core — `libnexus_core.so`

Everything guest-facing lives here: loaders, linker, x86-64 decoder, JIT, AOT
compiler, execution loop, ABI shims, diagnostics, upscaler and the JNI bridges.
There is no Window/Box64/QEMU/FEX dependency — the only third-party code linked
in is llama.cpp (fetched by CMake, `NINE_HAS_LLAMA=1`, used by the AI tabs).

## Module map

| Directory | Contents | State |
|---|---|---|
| `memory/` | `MemoryManager`: guest VA ↔ host VA, region table, perms, guard pages, W^X | 🟢 |
| `diagnostics/` | Ring-buffer `Logger` (8 categories) → logcat tag `NINE` → `GuestLog` sink; guest register/memory dumps | 🟢 |
| `loader/elf/` | `ElfParser`, `ElfLoader` (PT_LOAD/BSS/RELRO/TLS/PIE), `ElfRelocator` (14 relocation types) | 🟡 (see `SUPPORTED.md` §2) |
| `loader/pe/` | `PeParser`, `PeMapper`, `PeRelocator`, `PeImports` (incl. delay-load), `PeExports`, `PeTlsExceptions` | 🟡 |
| `linker/` | `ModuleGraph`, `SymbolResolver`, `GotPltManager`, `SearchPaths` ($ORIGIN, RPATH/RUNPATH) | 🟡 |
| `translator/` | `X86Decoder` (integer + x87 + SSE…SSE4.2 + AVX/AVX2/AVX-512/BMI/CET/SGX), `Arm64Emitter`, `Translator` (JIT blocks), `FlagState` (lazy flags), `CodeCache` (W^X, persistent `NINE` v2), `ControlFlow`, `SimdAtomics` | 🟡 JIT covers the integer subset; SIMD executes in the interpreter |
| `aot/` | `AotCompiler` (relinker-side AArch64 codegen), `AotImage` (header/blocks/relocs/code), `AotRuntime` (`AotModule`/`AotEngine`), `AotHelpers`, `AotRelink` | 🟡 compiler+runtime+relink done, run-path wiring pending; `SUPPORTED.md` §4 lists the opcodes |
| `runtime/` | `InsnInterpreter` (semantic reference — runs binaries today), `VecExec` (SSE/AVX dataplane), `X87Exec`, `Sgx`, `ExecutionLoop`, `HostTrampoline`, `SmcCoherency`, `LinuxStartup`, `MemHelpers`, `RuntimeBridge`(+JNI) | 🟢 |
| `abi/` | `SyscallTranslator` (62 numbers), `Vdso`, `Threading` (1:1 clone/CreateThread), `WinAbi` + `Win32Exports` (callable thunks for kernel32/kernelbase/ntdll, stubs for user32/gdi32/advapi32), `Kernel32`, `Ntdll`, `OtherDlls`, `Seh` | 🟡 |
| `upscale/` | `Upscaler` (`.n9up` bilinear + edge-adaptive refine), `GameDetector` | 🟢 (hook-up to a guest framebuffer awaits G1) |
| `llama/` | `nine_llama.cpp`: gguf load → greedy generate → free | 🟢 |
| `tests/` | `NativeTests.cpp` (feature/test-id dispatch for the Debugger screen), `Phase0Test.cpp` | 🟢 |

## JNI surfaces

`runtime/RuntimeBridgeJni.cpp` exposes `com.nine.dbt.GuestRuntime`
(`nativeLoadAndRun`, `nativeRelink*`, stop/pause/resume/step, breakpoints,
status, `detectGame`, upscaler model/status/enable), while
`llama/nine_llama.cpp` backs `com.nine.dbt.LlamaRuntime`.
`NativeTests.run(id)` dispatches the per-feature tests.

## Tests

- On-device suite: `NativeTests.run("<id>")` from the Debugger screen — phase
  tests, J-phase tests (`j1`…`j5`), `9.x` zones, and the AOT suite (`aot`, also
  reachable as `j5`/`9.5`).
- The AOT suite compiles x86 blobs, loads the image through `aot::AotModule` and
  runs the emitted AArch64 for real: integer/flags/SETcc, loops, memory-source
  ALU with a live destination, `xchg` both forms, balanced `CALL`/`RET`,
  shifts/rotates/`BSWAP`, AH/CH/DH/BH, plus a refusal check for SSE.

## Building

Built by Gradle/CMake (`:app:assembleDebug`) as `libnexus_core.so` for
`arm64-v8a`. Configure fetches llama.cpp v0.7.0, so the first build needs
network. Build directories are redirected to `%TEMP%\nine-build` (override with
`NINE_BUILD_DIR`).

## Where the ledgers live

`SUPPORTED.md` (syscalls / relocations / PE directories / AOT opcodes) ·
`../../../../ARCHITECTURE.md` (runtime + per-instruction inventory) ·
`../../../../LIBRARIES.md` (per-API checklists) ·
`../../../../REVERSE_TECHNIQUE.md` (the demand-driven loop + the rule that every
new guest-visible surface flips its cells in the same commit).
