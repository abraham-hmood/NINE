cmake_minimum_required(VERSION 3.22.1)
project(nexus_core)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Fetch llama.cpp (ggml + llama). This is the real runtime for .gguf.
# Force static so Android/Gradle only sees libnexus_core.so (no libggml-base.so
# symlinks, which Gradle 9 cannot snapshot — especially under OneDrive).
include(FetchContent)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_SERVER OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(GGML_STATIC ON CACHE BOOL "" FORCE)
set(GGML_NATIVE OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    llama
    GIT_REPOSITORY https://github.com/ggml-org/llama.cpp.git
    GIT_TAG        v0.7.0
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(llama)

add_library(nexus_core SHARED
    memory/MemoryManager.cpp
    diagnostics/Logger.cpp
    loader/elf/ElfParser.cpp
    loader/elf/ElfLoader.cpp
    loader/elf/ElfRelocator.cpp
    linker/ModuleGraph.cpp
    linker/SymbolResolver.cpp
    linker/GotPltManager.cpp
    linker/SearchPaths.cpp
    translator/X86Decoder.cpp
    translator/RegisterAllocator.cpp
    translator/FlagState.cpp
    translator/Translator.cpp
    translator/Arm64Emitter.cpp
    translator/ControlFlow.cpp
    translator/CodeCache.cpp
    translator/SimdAtomics.cpp
    loader/pe/PeParser.cpp
    loader/pe/PeMapper.cpp
    loader/pe/PeRelocator.cpp
    loader/pe/PeImports.cpp
    loader/pe/PeExports.cpp
    loader/pe/PeTlsExceptions.cpp
    abi/SyscallTranslator.cpp
    abi/Vdso.cpp
    abi/Threading.cpp
    abi/Ntdll.cpp
    abi/Kernel32.cpp
    abi/OtherDlls.cpp
    abi/Seh.cpp
    runtime/ExecutionLoop.cpp
    runtime/GuestContext.cpp
    runtime/SmcCoherency.cpp
    runtime/InsnInterpreter.cpp
    runtime/HostTrampoline.cpp
    runtime/MemHelpers.cpp
    runtime/RuntimeBridge.cpp
    runtime/RuntimeBridgeJni.cpp
    runtime/LinuxStartup.cpp
    tests/NativeTests.cpp
    llama/nine_llama.cpp
    tests/Phase0Test.cpp
)

target_include_directories(nexus_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${llama_SOURCE_DIR}/include
    ${llama_SOURCE_DIR}/ggml/include
)

target_compile_definitions(nexus_core PRIVATE NINE_HAS_LLAMA=1)

target_link_libraries(nexus_core
    android
    log
    llama
)
