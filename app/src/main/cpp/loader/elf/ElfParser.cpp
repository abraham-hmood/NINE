#include "ElfParser.h"
#include "../../diagnostics/Logger.h"

#include <cstring>
#include <algorithm>

namespace nexus {

bool ElfParser::validateIdent(const uint8_t ident[16]) {
    if (ident[0] != ELFMAG0 || ident[1] != ELFMAG1 ||
        ident[2] != ELFMAG2 || ident[3] != ELFMAG3) {
        return false;
    }
    if (ident[4] != ELFCLASS64) return false;          // EI_CLASS
    if (ident[5] != ELFDATA2LSB) return false;         // EI_DATA
    if (ident[6] != 1) return false;                   // EI_VERSION
    return true;
}

std::string ElfParser::readCString(std::span<const uint8_t> data, uint64_t offset) {
    if (offset >= data.size()) return {};
    const char* start = reinterpret_cast<const char*>(data.data() + offset);
    size_t max_len = data.size() - offset;
    size_t len = strnlen(start, max_len);
    return std::string(start, len);
}

std::optional<ParsedElf> ElfParser::parse(std::span<const uint8_t> data) {
    auto& log = Logger::instance();

    if (data.size() < sizeof(Elf64_Ehdr)) {
        log.error(LogCategory::LOADER, "ELF too small for header");
        return std::nullopt;
    }

    ParsedElf elf;
    elf.file_data.assign(data.begin(), data.end());

    std::memcpy(&elf.ehdr, data.data(), sizeof(Elf64_Ehdr));

    if (!validateIdent(elf.ehdr.e_ident)) {
        log.error(LogCategory::LOADER, "Invalid ELF identification");
        return std::nullopt;
    }
    if (elf.ehdr.e_machine != EM_X86_64) {
        log.errorf(LogCategory::LOADER, "Unsupported machine: %u (expected EM_X86_64)", elf.ehdr.e_machine);
        return std::nullopt;
    }
    if (elf.ehdr.e_type != ET_EXEC && elf.ehdr.e_type != ET_DYN) {
        log.errorf(LogCategory::LOADER, "Unsupported type: %u", elf.ehdr.e_type);
        return std::nullopt;
    }
    elf.is_pie = (elf.ehdr.e_type == ET_DYN);
    elf.entry = elf.ehdr.e_entry;

    // Program headers
    if (elf.ehdr.e_phoff + elf.ehdr.e_phnum * sizeof(Elf64_Phdr) > data.size()) {
        log.error(LogCategory::LOADER, "Program headers out of bounds");
        return std::nullopt;
    }
    elf.phdrs.resize(elf.ehdr.e_phnum);
    std::memcpy(elf.phdrs.data(), data.data() + elf.ehdr.e_phoff,
                elf.ehdr.e_phnum * sizeof(Elf64_Phdr));

    // Section headers (optional but parsed)
    if (elf.ehdr.e_shoff != 0 && elf.ehdr.e_shnum > 0) {
        if (elf.ehdr.e_shoff + elf.ehdr.e_shnum * sizeof(Elf64_Shdr) <= data.size()) {
            elf.shdrs.resize(elf.ehdr.e_shnum);
            std::memcpy(elf.shdrs.data(), data.data() + elf.ehdr.e_shoff,
                        elf.ehdr.e_shnum * sizeof(Elf64_Shdr));
        }
    }

    // Walk program headers for key segments
    const Elf64_Phdr* dynamic_phdr = nullptr;
    for (const auto& ph : elf.phdrs) {
        if (ph.p_type == PT_INTERP && ph.p_filesz > 0 && ph.p_offset + ph.p_filesz <= data.size()) {
            elf.interpreter = readCString(data, ph.p_offset);
        }
        if (ph.p_type == PT_TLS) {
            elf.has_tls = true;
        }
        if (ph.p_type == PT_DYNAMIC) {
            dynamic_phdr = &ph;
        }
    }

    // Parse dynamic section
    if (dynamic_phdr && dynamic_phdr->p_offset + dynamic_phdr->p_filesz <= data.size()) {
        size_t count = dynamic_phdr->p_filesz / sizeof(Elf64_Dyn);
        const auto* dyn = reinterpret_cast<const Elf64_Dyn*>(data.data() + dynamic_phdr->p_offset);
        elf.dynamic.assign(dyn, dyn + count);

        // Collect key dynamic values
        for (const auto& d : elf.dynamic) {
            switch (d.d_tag) {
                case DT_STRTAB:     elf.dt_strtab = d.d_val; break;
                case DT_SYMTAB:     elf.dt_symtab = d.d_val; break;
                case DT_RELA:       elf.dt_rela = d.d_val; break;
                case DT_RELASZ:     elf.dt_relasz = d.d_val; break;
                case DT_JMPREL:     elf.dt_jmprel = d.d_val; break;
                case DT_PLTRELSZ:   elf.dt_pltrelsz = d.d_val; break;
                case DT_INIT:         elf.dt_init = d.d_val; break;
                case DT_FINI:         elf.dt_fini = d.d_val; break;
                case DT_INIT_ARRAY:   elf.dt_init_array = d.d_val; break;
                case DT_FINI_ARRAY:   elf.dt_fini_array = d.d_val; break;
                case DT_INIT_ARRAYSZ: elf.dt_init_arraysz = d.d_val; break;
                case DT_FINI_ARRAYSZ: elf.dt_fini_arraysz = d.d_val; break;
                case DT_BIND_NOW:   elf.bind_now = true; break;
                case DT_FLAGS:
                    if (d.d_val & 0x8) elf.bind_now = true; // DF_BIND_NOW
                    break;
                case DT_VERSYM:     elf.dt_versym = d.d_val; break;
                case DT_VERNEED:    elf.dt_verneed = d.d_val; break;
                case DT_VERNEEDNUM: elf.dt_verneednum = d.d_val; break;
                case DT_VERDEF:     elf.dt_verdef = d.d_val; break;
                case DT_VERDEFNUM:  elf.dt_verdefnum = d.d_val; break;
                default: break;
            }
        }

        auto vaddrToOffset = [&](uint64_t vaddr) -> std::optional<uint64_t> {
            for (const auto& ph : elf.phdrs) {
                if (ph.p_type == PT_LOAD &&
                    vaddr >= ph.p_vaddr && vaddr < ph.p_vaddr + ph.p_filesz) {
                    return ph.p_offset + (vaddr - ph.p_vaddr);
                }
            }
            return std::nullopt;
        };

        // DT_NEEDED / SONAME / RPATH / RUNPATH
        for (const auto& d : elf.dynamic) {
            if (d.d_tag == DT_NEEDED || d.d_tag == DT_SONAME ||
                d.d_tag == DT_RPATH || d.d_tag == DT_RUNPATH) {
                if (auto off = vaddrToOffset(elf.dt_strtab + d.d_val)) {
                    std::string s = readCString(data, *off);
                    if (d.d_tag == DT_NEEDED) elf.needed.push_back(std::move(s));
                    else if (d.d_tag == DT_SONAME) elf.soname = std::move(s);
                    else if (d.d_tag == DT_RPATH) elf.rpath = std::move(s);
                    else if (d.d_tag == DT_RUNPATH) elf.runpath = std::move(s);
                }
            }
        }

        // Symbols (.dynsym)
        if (elf.dt_symtab && elf.dt_strtab) {
            if (auto sym_off = vaddrToOffset(elf.dt_symtab)) {
                // Estimate count from section or from hash; for now read until we hit a reasonable limit
                // Better: use section headers if available
                size_t sym_count = 0;
                for (const auto& sh : elf.shdrs) {
                    if (sh.sh_addr == elf.dt_symtab && sh.sh_entsize == sizeof(Elf64_Sym)) {
                        sym_count = sh.sh_size / sizeof(Elf64_Sym);
                        break;
                    }
                }
                if (sym_count == 0) sym_count = 1024; // fallback cap
                if (*sym_off + sym_count * sizeof(Elf64_Sym) <= data.size()) {
                    const auto* syms = reinterpret_cast<const Elf64_Sym*>(data.data() + *sym_off);
                    elf.symbols.assign(syms, syms + sym_count);
                    elf.symbol_names.resize(sym_count);
                    for (size_t i = 0; i < sym_count; ++i) {
                        if (auto noff = vaddrToOffset(elf.dt_strtab + elf.symbols[i].st_name)) {
                            elf.symbol_names[i] = readCString(data, *noff);
                        }
                    }
                }
            }
        }

        // Symbol versions (VERSYM + VERNEED)
        if (elf.dt_versym && !elf.symbols.empty()) {
            if (auto off = vaddrToOffset(elf.dt_versym)) {
                size_t n = elf.symbols.size();
                if (*off + n * sizeof(uint16_t) <= data.size()) {
                    const auto* vs = reinterpret_cast<const uint16_t*>(data.data() + *off);
                    elf.symbol_versions.resize(n);
                    for (size_t i = 0; i < n; ++i) {
                        elf.symbol_versions[i].versym = vs[i];
                        // bit 15 = hidden
                        if (vs[i] & 0x8000) elf.symbol_versions[i].is_hidden = true;
                    }
                }
            }
        }

        // VERNEED: map version index -> (file, version name)
        if (elf.dt_verneed && elf.dt_verneednum && elf.dt_strtab) {
            if (auto base_off = vaddrToOffset(elf.dt_verneed)) {
                uint64_t cursor = *base_off;
                for (uint64_t i = 0; i < elf.dt_verneednum && cursor + sizeof(Elf64_Verneed) <= data.size(); ++i) {
                    Elf64_Verneed vn;
                    std::memcpy(&vn, data.data() + cursor, sizeof(vn));
                    std::string file;
                    if (auto foff = vaddrToOffset(elf.dt_strtab + vn.vn_file)) {
                        file = readCString(data, *foff);
                    }
                    uint64_t aux = cursor + vn.vn_aux;
                    for (uint16_t a = 0; a < vn.vn_cnt && aux + sizeof(Elf64_Vernaux) <= data.size(); ++a) {
                        Elf64_Vernaux vna;
                        std::memcpy(&vna, data.data() + aux, sizeof(vna));
                        std::string vname;
                        if (auto noff = vaddrToOffset(elf.dt_strtab + vna.vna_name)) {
                            vname = readCString(data, *noff);
                        }
                        // Attach to any symbol that has this versym index
                        uint16_t idx = vna.vna_other & 0x7fff;
                        for (size_t s = 0; s < elf.symbol_versions.size(); ++s) {
                            if ((elf.symbol_versions[s].versym & 0x7fff) == idx) {
                                elf.symbol_versions[s].version_name = vname;
                                elf.symbol_versions[s].file_name = file;
                            }
                        }
                        if (vna.vna_next == 0) break;
                        aux += vna.vna_next;
                    }
                    if (vn.vn_next == 0) break;
                    cursor += vn.vn_next;
                }
            }
        }

        // Static symbol table (.symtab) if section headers present
        for (const auto& sh : elf.shdrs) {
            if (sh.sh_type == 2 /* SHT_SYMTAB */ && sh.sh_entsize == sizeof(Elf64_Sym)) {
                if (sh.sh_offset + sh.sh_size <= data.size()) {
                    size_t n = sh.sh_size / sizeof(Elf64_Sym);
                    const auto* syms = reinterpret_cast<const Elf64_Sym*>(data.data() + sh.sh_offset);
                    elf.static_symbols.assign(syms, syms + n);
                    elf.static_symbol_names.resize(n);
                    // string table is sh_link
                    if (sh.sh_link < elf.shdrs.size()) {
                        const auto& strsh = elf.shdrs[sh.sh_link];
                        for (size_t i = 0; i < n; ++i) {
                            uint64_t off = strsh.sh_offset + elf.static_symbols[i].st_name;
                            if (off < data.size()) {
                                elf.static_symbol_names[i] = readCString(data, off);
                            }
                        }
                    }
                }
                break;
            }
        }

        // Relocations (DT_RELA)
        if (elf.dt_rela && elf.dt_relasz) {
            if (auto off = vaddrToOffset(elf.dt_rela)) {
                size_t count = elf.dt_relasz / sizeof(Elf64_Rela);
                if (*off + count * sizeof(Elf64_Rela) <= data.size()) {
                    const auto* rela = reinterpret_cast<const Elf64_Rela*>(data.data() + *off);
                    elf.rela.assign(rela, rela + count);
                }
            }
        }

        // PLT relocations
        if (elf.dt_jmprel && elf.dt_pltrelsz) {
            if (auto off = vaddrToOffset(elf.dt_jmprel)) {
                size_t count = elf.dt_pltrelsz / sizeof(Elf64_Rela);
                if (*off + count * sizeof(Elf64_Rela) <= data.size()) {
                    const auto* rela = reinterpret_cast<const Elf64_Rela*>(data.data() + *off);
                    elf.plt_rela.assign(rela, rela + count);
                }
            }
        }
    }

    log.infof(LogCategory::LOADER,
              "Parsed ELF64: entry=0x%llx pie=%d phdrs=%zu needed=%zu symbols=%zu static_syms=%zu versions=%zu rela=%zu plt_rela=%zu",
              (unsigned long long)elf.entry, elf.is_pie,
              elf.phdrs.size(), elf.needed.size(),
              elf.symbols.size(), elf.static_symbols.size(), elf.symbol_versions.size(),
              elf.rela.size(), elf.plt_rela.size());

    return elf;
}

} // namespace nexus
