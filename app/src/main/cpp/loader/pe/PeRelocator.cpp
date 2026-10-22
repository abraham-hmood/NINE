#include "PeRelocator.h"
#include "../../diagnostics/Logger.h"
#include <cstring>

namespace nexus {

uint32_t PeRelocator::r32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24); }
uint64_t PeRelocator::r64(const uint8_t* p) {
    return r32(p) | (static_cast<uint64_t>(r32(p + 4)) << 32);
}

size_t PeRelocator::apply(const MappedPe& mapped, const uint8_t* file, size_t file_len) {
    if (mapped.parsed.opt.directories.size() <= 5) return 0;
    const auto& dir = mapped.parsed.opt.directories[5]; // BASERELOC
    if (dir.rva == 0 || dir.size == 0) return 0;

    int64_t delta = static_cast<int64_t>(mapped.base) - static_cast<int64_t>(mapped.parsed.opt.image_base);
    if (delta == 0) return 0;

    // Find the file offset for the reloc directory via sections.
    uint32_t file_off = 0;
    bool found = false;
    for (const auto& s : mapped.parsed.sections) {
        if (dir.rva >= s.virtual_address && dir.rva < s.virtual_address + s.virtual_size) {
            file_off = s.pointer_to_raw_data + (dir.rva - s.virtual_address);
            found = true;
            break;
        }
    }
    if (!found || file_off + dir.size > file_len) return 0;

    size_t applied = 0;
    const uint8_t* p = file + file_off;
    const uint8_t* end = p + dir.size;
    while (p + 8 <= end) {
        uint32_t page_rva = r32(p);
        uint32_t block_size = r32(p + 4);
        if (block_size < 8) break;
        const uint8_t* entries = p + 8;
        size_t count = (block_size - 8) / 2;
        for (size_t i = 0; i < count && entries + i * 2 + 2 <= end; ++i) {
            uint16_t e = entries[i * 2] | (entries[i * 2 + 1] << 8);
            uint16_t type = e >> 12;
            uint16_t offset = e & 0xFFF;
            uint64_t addr = mapped.base + page_rva + offset;
            void* host = mm_.guestToHost(addr);
            if (!host) continue;
            if (type == static_cast<uint16_t>(RelocType::DIR64)) {
                uint64_t v = r64(static_cast<uint8_t*>(host));
                v = static_cast<uint64_t>(static_cast<int64_t>(v) + delta);
                std::memcpy(host, &v, 8);
                ++applied;
            } else if (type == static_cast<uint16_t>(RelocType::HIGHLOW)) {
                uint32_t v = r32(static_cast<uint8_t*>(host));
                v = static_cast<uint32_t>(static_cast<int64_t>(v) + delta);
                std::memcpy(host, &v, 4);
                ++applied;
            } else if (type == static_cast<uint16_t>(RelocType::ABSOLUTE)) {
                // padding
            }
        }
        p += block_size;
    }
    Logger::instance().infof(LogCategory::LOADER, "PE relocs applied: %zu (delta 0x%llx)",
                             applied, (unsigned long long)delta);
    return applied;
}

} // namespace nexus
