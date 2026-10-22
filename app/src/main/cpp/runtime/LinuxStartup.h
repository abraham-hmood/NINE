#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "../loader/elf/ElfLoader.h"
#include "../loader/elf/ElfParser.h"
#include "../memory/MemoryManager.h"
#include "GuestContext.h"

namespace nexus {

// Build Linux x86-64 process startup state for a loaded static/dynamic ELF
// (argc/argv/envp/auxv, TLS, initial brk hint). See REVERSE_TECHNIQUE.md.
struct LinuxStartupResult {
    uint64_t rsp = 0;
    uint64_t tls_tp = 0;   // FS base (thread pointer)
    uint64_t brk_start = 0;
    bool ok = false;
    std::string error;
};

class LinuxStartup {
public:
    // Allocate stack, write argc/argv/envp/auxv, place TLS from PT_TLS if present.
    static LinuxStartupResult prepare(MemoryManager& mm, const LoadedElf& loaded,
                                      const std::string& argv0 = "./guest");
};

} // namespace nexus
