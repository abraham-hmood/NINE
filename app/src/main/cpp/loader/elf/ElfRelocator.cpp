#include "ElfRelocator.h"
#include "../../diagnostics/Logger.h"
#include <cstring>

namespace nexus {

bool ElfRelocator::writeU64(MemoryManager& mm, uint64_t guest_addr, uint64_t value) {
    void* host = mm.guestToHost(guest_addr);
    if (!host) return false;
    std::memcpy(host, &value, sizeof(value));
    return true;
}

bool ElfRelocator::writeU32(MemoryManager& mm, uint64_t guest_addr, uint32_t value) {
    void* host = mm.guestToHost(guest_addr);
    if (!host) return false;
    std::memcpy(host, &value, sizeof(value));
    return true;
}

bool ElfRelocator::writeI32(MemoryManager& mm, uint64_t guest_addr, int32_t value) {
    void* host = mm.guestToHost(guest_addr);
    if (!host) return false;
    std::memcpy(host, &value, sizeof(value));
    return true;
}

bool ElfRelocator::applyOne(const Elf64_Rela& rela, LoadedElf& loaded, MemoryManager& mm,
                             const ElfSymbolResolverFn& resolver, bool is_plt) {
    auto& log = Logger::instance();
    uint32_t type = relaType(rela.r_info);
    uint32_t sym_idx = relaSym(rela.r_info);

    uint64_t where = rela.r_offset + loaded.load_bias;
    uint64_t S = 0; // symbol value
    bool is_weak = false;

    if (sym_idx != 0 && sym_idx < loaded.parsed.symbols.size()) {
        const auto& sym = loaded.parsed.symbols[sym_idx];
        const std::string& name = (sym_idx < loaded.parsed.symbol_names.size())
                                  ? loaded.parsed.symbol_names[sym_idx] : "";

        uint8_t bind = symBind(sym.st_info);
        uint8_t vis  = symVis(sym.st_other);

        // Prefer versioned lookup if the resolver supports it via the name.
        // We pass the plain name; version is available on the symbol for the linker.
        if (sym.st_shndx != 0 && bind != STB_WEAK) {
            S = sym.st_value + loaded.load_bias;
        } else if (resolver && !name.empty()) {
            S = resolver(name, &is_weak);
            // If weak and unresolved, S stays 0 (allowed)
            if (S == 0 && bind == STB_WEAK) {
                is_weak = true;
            }
        } else if (sym.st_shndx != 0) {
            S = sym.st_value + loaded.load_bias;
        }

        // Hidden/internal symbols should not be interposed; prefer local definition
        if ((vis == STV_HIDDEN || vis == STV_INTERNAL) && sym.st_shndx != 0) {
            S = sym.st_value + loaded.load_bias;
        }
    }

    uint64_t A = static_cast<uint64_t>(rela.r_addend);
    uint64_t P = where; // place
    uint64_t B = loaded.load_bias;

    switch (type) {
        case R_X86_64_NONE:
            return true;

        case R_X86_64_64:
            return writeU64(mm, where, S + A);

        case R_X86_64_PC32:
        case R_X86_64_PLT32: {
            int64_t val = static_cast<int64_t>(S + A - P);
            if (val > INT32_MAX || val < INT32_MIN) {
                log.errorf(LogCategory::LOADER, "PC32/PLT32 overflow at 0x%llx", (unsigned long long)where);
                return false;
            }
            return writeI32(mm, where, static_cast<int32_t>(val));
        }

        case R_X86_64_GOTPCREL: {
            // Without a dedicated GOT yet, emit a PC-relative reference to the symbol.
            // The dynamic linker (Phase 2) will replace this with a real GOT slot.
            int64_t val = static_cast<int64_t>(S + A - P);
            if (val > INT32_MAX || val < INT32_MIN) {
                log.errorf(LogCategory::LOADER, "GOTPCREL overflow at 0x%llx", (unsigned long long)where);
                return false;
            }
            return writeI32(mm, where, static_cast<int32_t>(val));
        }

        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
            return writeU64(mm, where, S);

        case R_X86_64_RELATIVE:
            return writeU64(mm, where, B + A);

        case R_X86_64_IRELATIVE: {
            // Indirect: the addend is a function that returns the real address.
            // Without a running guest we record it and skip execution for now.
            log.warn(LogCategory::LOADER, "R_X86_64_IRELATIVE encountered (deferred until runtime)");
            return writeU64(mm, where, B + A); // store the function address; caller can invoke later
        }

        case R_X86_64_32:
            return writeU32(mm, where, static_cast<uint32_t>(S + A));

        case R_X86_64_32S:
            return writeI32(mm, where, static_cast<int32_t>(S + A));

        // TLS relocations — record the values; full TLS is per-thread later
        case R_X86_64_DTPMOD64:
            return writeU64(mm, where, 1); // module id placeholder
        case R_X86_64_DTPOFF64:
            return writeU64(mm, where, S + A);
        case R_X86_64_TPOFF64:
            return writeU64(mm, where, S + A); // simplified

        default:
            log.errorf(LogCategory::LOADER, "Unsupported relocation type %u at 0x%llx",
                       type, (unsigned long long)where);
            return false;
    }
}

size_t ElfRelocator::apply(LoadedElf& loaded, MemoryManager& mm, const ElfSymbolResolverFn& resolver) {
    auto& log = Logger::instance();
    size_t applied = 0;
    size_t failed = 0;

    auto process = [&](const std::vector<Elf64_Rela>& relas, bool is_plt) {
        for (const auto& r : relas) {
            if (applyOne(r, loaded, mm, resolver, is_plt)) {
                ++applied;
            } else {
                ++failed;
            }
        }
    };

    process(loaded.parsed.rela, false);
    process(loaded.parsed.plt_rela, true);

    log.infof(LogCategory::LOADER, "Relocations: applied=%zu failed=%zu", applied, failed);
    return applied;
}

} // namespace nexus
