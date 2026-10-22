#include "PeMapper.h"
#include "../../diagnostics/Logger.h"
#include <cstring>
#include <algorithm>

namespace nexus {

PagePerm PeMapper::perms(const SectionHeader& s) {
    PagePerm p = PagePerm::READ;
    if (s.writable()) p = p | PagePerm::WRITE;
    if (s.executable()) p = p | PagePerm::EXEC;
    return p;
}

std::optional<MappedPe> PeMapper::map(const ParsedPe& pe, const uint8_t* file, size_t file_len,
                                      uint64_t relocated_base) {
    uint64_t base = relocated_base ? relocated_base : pe.opt.image_base;
    uint32_t align = pe.opt.section_alignment ? pe.opt.section_alignment : 0x1000;
    size_t image = (pe.opt.size_of_image + align - 1) & ~(align - 1);

    uint64_t mapped = mm_.allocate(base, image, PagePerm::READ_WRITE); // RW while loading
    if (!mapped) {
        base = relocated_base ? relocated_base : (pe.opt.image_base + 0x10000000);
        mapped = mm_.allocate(base, image, PagePerm::READ_WRITE);
        if (!mapped) {
            Logger::instance().error(LogCategory::LOADER, "PE map failed");
            return std::nullopt;
        }
    }

    // Headers
    size_t hdr = std::min(file_len, static_cast<size_t>(pe.opt.size_of_headers));
    void* host = mm_.guestToHost(mapped);
    if (host && hdr) std::memcpy(host, file, hdr);

    for (const auto& sec : pe.sections) {
        uint64_t va = mapped + sec.virtual_address;
        size_t vsize = sec.virtual_size ? sec.virtual_size : sec.size_of_raw_data;
        size_t raw = sec.size_of_raw_data;
        // File alignment: raw size is already file-aligned; copy only what exists.
        size_t copy = std::min(raw, vsize);
        if (sec.pointer_to_raw_data + copy > file_len) copy = 0;
        void* dest = mm_.guestToHost(va);
        if (!dest) continue;
        if (copy) std::memcpy(dest, file + sec.pointer_to_raw_data, copy);
        if (vsize > copy) std::memset(static_cast<uint8_t*>(dest) + copy, 0, vsize - copy);
        mm_.protectRange(va, vsize, perms(sec));
    }

    MappedPe out;
    out.base = mapped;
    out.entry = mapped + pe.opt.address_of_entry;
    out.parsed = pe;
    out.relocated = mapped != pe.opt.image_base;
    Logger::instance().infof(LogCategory::LOADER, "PE mapped at 0x%llx entry 0x%llx",
                             (unsigned long long)out.base, (unsigned long long)out.entry);
    return out;
}

} // namespace nexus
