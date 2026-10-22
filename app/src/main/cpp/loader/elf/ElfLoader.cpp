#include "ElfLoader.h"
#include "../../diagnostics/Logger.h"
#include <cstring>
#include <algorithm>

namespace nexus {

PagePerm ElfLoader::flagsToPerm(uint32_t p_flags) {
    PagePerm p = PagePerm::NONE;
    if (p_flags & PF_R) p = p | PagePerm::READ;
    if (p_flags & PF_W) p = p | PagePerm::WRITE;
    if (p_flags & PF_X) p = p | PagePerm::EXEC;
    return p;
}

uint64_t ElfLoader::alignDown(uint64_t v, uint64_t align) {
    if (align == 0) align = MemoryManager::kPageSize;
    return v & ~(align - 1);
}

uint64_t ElfLoader::alignUp(uint64_t v, uint64_t align) {
    if (align == 0) align = MemoryManager::kPageSize;
    return (v + align - 1) & ~(align - 1);
}

std::optional<LoadedElf> ElfLoader::load(const ParsedElf& elf, MemoryManager& mm) {
    auto& log = Logger::instance();
    LoadedElf loaded;
    loaded.parsed = elf;

    // Determine load bias
    uint64_t preferred_base = 0;
    bool found_load = false;
    for (const auto& ph : elf.phdrs) {
        if (ph.p_type == PT_LOAD) {
            if (!found_load || ph.p_vaddr < preferred_base) {
                preferred_base = ph.p_vaddr;
                found_load = true;
            }
        }
    }
    if (!found_load) {
        log.error(LogCategory::LOADER, "No PT_LOAD segments");
        return std::nullopt;
    }

    if (elf.is_pie) {
        // Choose a free base. We allocate a dummy range first to get a hint, then free it.
        // Simpler: ask MemoryManager for any address of sufficient span.
        uint64_t min_vaddr = UINT64_MAX, max_vaddr = 0;
        for (const auto& ph : elf.phdrs) {
            if (ph.p_type != PT_LOAD) continue;
            uint64_t start = alignDown(ph.p_vaddr, ph.p_align ? ph.p_align : MemoryManager::kPageSize);
            uint64_t end   = alignUp(ph.p_vaddr + ph.p_memsz, ph.p_align ? ph.p_align : MemoryManager::kPageSize);
            min_vaddr = std::min(min_vaddr, start);
            max_vaddr = std::max(max_vaddr, end);
        }
        size_t span = static_cast<size_t>(max_vaddr - min_vaddr);
        uint64_t hint = mm.allocate(0, span, PagePerm::NONE, "elf_pie_probe");
        if (hint == 0) {
            log.error(LogCategory::LOADER, "Failed to find VA space for PIE");
            return std::nullopt;
        }
        mm.free(hint);
        loaded.load_bias = hint - min_vaddr;
        loaded.base = hint;
    } else {
        loaded.load_bias = 0;
        loaded.base = preferred_base;
    }

    loaded.entry = elf.entry + loaded.load_bias;

    // Map each PT_LOAD
    for (const auto& ph : elf.phdrs) {
        if (ph.p_type != PT_LOAD) continue;

        uint64_t align = ph.p_align ? ph.p_align : MemoryManager::kPageSize;
        uint64_t seg_start = alignDown(ph.p_vaddr, align) + loaded.load_bias;
        uint64_t seg_end   = alignUp(ph.p_vaddr + ph.p_memsz, align) + loaded.load_bias;
        size_t   map_size  = static_cast<size_t>(seg_end - seg_start);

        PagePerm perms = flagsToPerm(ph.p_flags);
        // Temporarily map writable so we can copy file contents + zero BSS
        PagePerm map_perms = perms | PagePerm::WRITE;

        uint64_t guest = mm.allocate(seg_start, map_size, map_perms, "elf_load");
        if (guest == 0 || guest != seg_start) {
            log.errorf(LogCategory::LOADER, "Failed to map PT_LOAD at 0x%llx", (unsigned long long)seg_start);
            // Cleanup already mapped
            for (uint64_t r : loaded.mapped_regions) mm.free(r);
            return std::nullopt;
        }
        loaded.mapped_regions.push_back(guest);

        void* host = mm.guestToHost(guest);
        if (!host) {
            log.error(LogCategory::LOADER, "guestToHost failed after allocate");
            for (uint64_t r : loaded.mapped_regions) mm.free(r);
            return std::nullopt;
        }

        // Zero the whole mapping (covers BSS)
        std::memset(host, 0, map_size);

        // Copy file-backed portion
        if (ph.p_filesz > 0) {
            uint64_t file_off = ph.p_offset;
            uint64_t dest_off = (ph.p_vaddr + loaded.load_bias) - seg_start;
            if (file_off + ph.p_filesz <= elf.file_data.size()) {
                std::memcpy(static_cast<char*>(host) + dest_off,
                            elf.file_data.data() + file_off,
                            static_cast<size_t>(ph.p_filesz));
            } else {
                log.error(LogCategory::LOADER, "PT_LOAD file range out of bounds");
                for (uint64_t r : loaded.mapped_regions) mm.free(r);
                return std::nullopt;
            }
        }

        // Drop write permission if the segment is not supposed to be writable
        if (!hasPerm(perms, PagePerm::WRITE)) {
            mm.protect(guest, perms);
        }

        log.infof(LogCategory::LOADER,
                  "Mapped PT_LOAD guest=0x%llx-0x%llx perms=%d filesz=%llu memsz=%llu",
                  (unsigned long long)seg_start, (unsigned long long)seg_end,
                  static_cast<int>(perms),
                  (unsigned long long)ph.p_filesz, (unsigned long long)ph.p_memsz);
    }

    // TLS
    for (const auto& ph : elf.phdrs) {
        if (ph.p_type == PT_TLS) {
            loaded.tls.present = true;
            loaded.tls.template_vaddr = ph.p_vaddr + loaded.load_bias;
            loaded.tls.template_filesz = ph.p_filesz;
            loaded.tls.template_memsz = ph.p_memsz;
            loaded.tls.align = ph.p_align;
            log.infof(LogCategory::LOADER, "TLS template at 0x%llx memsz=%llu",
                      (unsigned long long)loaded.tls.template_vaddr,
                      (unsigned long long)loaded.tls.template_memsz);
            break;
        }
    }

    log.infof(LogCategory::LOADER,
              "ELF loaded: base=0x%llx bias=0x%llx entry=0x%llx deps=%zu",
              (unsigned long long)loaded.base, (unsigned long long)loaded.load_bias,
              (unsigned long long)loaded.entry, loaded.parsed.needed.size());

    return loaded;
}

bool ElfLoader::applyRelro(LoadedElf& loaded, MemoryManager& mm) {
    auto& log = Logger::instance();
    const Elf64_Phdr* relro = nullptr;
    for (const auto& ph : loaded.parsed.phdrs) {
        if (ph.p_type == PT_GNU_RELRO) {
            relro = &ph;
            break;
        }
    }
    if (!relro) {
        log.info(LogCategory::LOADER, "No GNU_RELRO segment");
        return true;
    }

    uint64_t start = alignDown(relro->p_vaddr + loaded.load_bias, MemoryManager::kPageSize);
    uint64_t end   = alignUp(relro->p_vaddr + loaded.load_bias + relro->p_memsz, MemoryManager::kPageSize);
    size_t   len   = static_cast<size_t>(end - start);

    // Make the RELRO range read-only (keep EXEC if it was executable, though RELRO is normally data)
    PagePerm np = PagePerm::READ;
    if (mm.protectRange(start, len, np)) {
        loaded.relro_applied = true;
        log.infof(LogCategory::LOADER, "GNU_RELRO applied at 0x%llx-0x%llx",
                  (unsigned long long)start, (unsigned long long)end);
        return true;
    }

    log.error(LogCategory::LOADER, "GNU_RELRO protectRange failed");
    return false;
}

} // namespace nexus
