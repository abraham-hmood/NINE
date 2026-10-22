#pragma once

#include "PeParser.h"
#include "PeMapper.h"
#include "../../memory/MemoryManager.h"
#include <cstdint>
#include <cstddef>

namespace nexus {

// PE base relocation types
enum class RelocType : uint16_t {
    ABSOLUTE = 0,
    HIGH = 1,
    LOW = 2,
    HIGHLOW = 3,
    HIGHADJ = 4,
    DIR64 = 10
};

class PeRelocator {
public:
    explicit PeRelocator(MemoryManager& mm) : mm_(mm) {}

    // Apply IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5).
    // delta = actual_base - preferred ImageBase. ASLR-style rebasing.
    // Returns number of relocations applied.
    size_t apply(const MappedPe& mapped, const uint8_t* file, size_t file_len);

private:
    MemoryManager& mm_;
    static uint32_t r32(const uint8_t* p);
    static uint64_t r64(const uint8_t* p);
};

} // namespace nexus
