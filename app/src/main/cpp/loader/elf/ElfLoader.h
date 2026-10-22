#pragma once

#include "ElfParser.h"
#include "../../memory/MemoryManager.h"
#include <cstdint>
#include <vector>
#include <string>
#include <optional>

namespace nexus {

struct TlsInfo {
    uint64_t template_vaddr = 0;
    uint64_t template_filesz = 0;
    uint64_t template_memsz = 0;
    uint64_t align = 0;
    bool present = false;
};

struct LoadedElf {
    ParsedElf parsed;
    uint64_t load_bias = 0;          // difference between preferred and actual base (for PIE)
    uint64_t base = 0;               // actual guest base of the first PT_LOAD
    uint64_t entry = 0;              // relocated entry point
    std::vector<uint64_t> mapped_regions; // guest starts we allocated (for cleanup)
    TlsInfo tls;
    bool relro_applied = false;
};

class ElfLoader {
public:
    // Map all PT_LOAD segments of a parsed ELF into the MemoryManager.
    // For ET_DYN, a free base is chosen; for ET_EXEC the preferred VAs are used.
    // Returns nullopt on failure.
    static std::optional<LoadedElf> load(const ParsedElf& elf, MemoryManager& mm);

    // Apply GNU_RELRO (make the RELRO range read-only). Call after relocations.
    static bool applyRelro(LoadedElf& loaded, MemoryManager& mm);

    // Convenience: dependency list already extracted by the parser
    static const std::vector<std::string>& dependencies(const LoadedElf& loaded) {
        return loaded.parsed.needed;
    }

private:
    static PagePerm flagsToPerm(uint32_t p_flags);
    static uint64_t alignDown(uint64_t v, uint64_t align);
    static uint64_t alignUp(uint64_t v, uint64_t align);
};

} // namespace nexus
