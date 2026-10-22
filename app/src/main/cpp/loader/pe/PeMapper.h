#pragma once

#include "PeParser.h"
#include "../../memory/MemoryManager.h"
#include <cstdint>

namespace nexus {

struct MappedPe {
    uint64_t base = 0;
    uint64_t entry = 0;
    ParsedPe parsed;
    bool relocated = false;
};

class PeMapper {
public:
    explicit PeMapper(MemoryManager& mm) : mm_(mm) {}

    // Map at preferred ImageBase, or at `relocated_base` if preferred is taken.
    // Copies raw section data, zero-fills BSS, applies section permissions.
    // Honors section alignment vs file alignment.
    std::optional<MappedPe> map(const ParsedPe& pe, const uint8_t* file, size_t file_len,
                                uint64_t relocated_base = 0);

private:
    MemoryManager& mm_;
    static PagePerm perms(const SectionHeader& s);
};

} // namespace nexus
