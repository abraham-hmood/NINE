#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <optional>
#include <span>

namespace nexus {

// ELF64 constants (subset of <elf.h>)
constexpr uint8_t  ELFMAG0 = 0x7f;
constexpr uint8_t  ELFMAG1 = 'E';
constexpr uint8_t  ELFMAG2 = 'L';
constexpr uint8_t  ELFMAG3 = 'F';
constexpr uint8_t  ELFCLASS64 = 2;
constexpr uint8_t  ELFDATA2LSB = 1;
constexpr uint16_t EM_X86_64 = 62;
constexpr uint16_t ET_EXEC = 2;
constexpr uint16_t ET_DYN  = 3;

constexpr uint32_t PT_LOAD    = 1;
constexpr uint32_t PT_DYNAMIC = 2;
constexpr uint32_t PT_INTERP  = 3;
constexpr uint32_t PT_TLS     = 7;
constexpr uint32_t PT_GNU_STACK = 0x6474e551;
constexpr uint32_t PT_GNU_RELRO = 0x6474e552;

constexpr uint32_t PF_X = 1;
constexpr uint32_t PF_W = 2;
constexpr uint32_t PF_R = 4;

constexpr uint64_t DT_NULL     = 0;
constexpr uint64_t DT_NEEDED   = 1;
constexpr uint64_t DT_PLTRELSZ = 2;
constexpr uint64_t DT_PLTGOT   = 3;
constexpr uint64_t DT_HASH     = 4;
constexpr uint64_t DT_STRTAB   = 5;
constexpr uint64_t DT_SYMTAB   = 6;
constexpr uint64_t DT_RELA     = 7;
constexpr uint64_t DT_RELASZ   = 8;
constexpr uint64_t DT_RELAENT  = 9;
constexpr uint64_t DT_STRSZ    = 10;
constexpr uint64_t DT_SYMENT   = 11;
constexpr uint64_t DT_INIT     = 12;
constexpr uint64_t DT_FINI     = 13;
constexpr uint64_t DT_SONAME   = 14;
constexpr uint64_t DT_RPATH    = 15;
constexpr uint64_t DT_SYMBOLIC = 16;
constexpr uint64_t DT_REL      = 17;
constexpr uint64_t DT_RELSZ    = 18;
constexpr uint64_t DT_RELENT   = 19;
constexpr uint64_t DT_PLTREL   = 20;
constexpr uint64_t DT_DEBUG    = 21;
constexpr uint64_t DT_TEXTREL  = 22;
constexpr uint64_t DT_JMPREL   = 23;
constexpr uint64_t DT_BIND_NOW = 24;
constexpr uint64_t DT_INIT_ARRAY   = 25;
constexpr uint64_t DT_FINI_ARRAY   = 26;
constexpr uint64_t DT_INIT_ARRAYSZ = 27;
constexpr uint64_t DT_FINI_ARRAYSZ = 28;
constexpr uint64_t DT_RUNPATH  = 29;
constexpr uint64_t DT_FLAGS    = 30;
constexpr uint64_t DT_VERSYM   = 0x6ffffff0;
constexpr uint64_t DT_VERDEF   = 0x6ffffffc;
constexpr uint64_t DT_VERDEFNUM= 0x6ffffffd;
constexpr uint64_t DT_VERNEED  = 0x6ffffffe;
constexpr uint64_t DT_VERNEEDNUM=0x6fffffff;

struct Elf64_Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct Elf64_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct Elf64_Dyn {
    int64_t  d_tag;
    uint64_t d_val;
};

struct Elf64_Sym {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct Elf64_Rela {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
};

struct Elf64_Verneed {
    uint16_t vn_version;
    uint16_t vn_cnt;
    uint32_t vn_file;
    uint32_t vn_aux;
    uint32_t vn_next;
};

struct Elf64_Vernaux {
    uint32_t vna_hash;
    uint16_t vna_flags;
    uint16_t vna_other;
    uint32_t vna_name;
    uint32_t vna_next;
};

struct SymbolVersionInfo {
    uint16_t versym = 0;          // from VERSYM
    std::string version_name;     // resolved name if available
    std::string file_name;        // needed file for this version
    bool is_hidden = false;
};

struct ParsedElf {
    Elf64_Ehdr ehdr;
    std::vector<Elf64_Phdr> phdrs;
    std::vector<Elf64_Shdr> shdrs;
    std::vector<Elf64_Dyn>  dynamic;

    // Dynamic strings / dependencies
    std::vector<std::string> needed;
    std::optional<std::string> soname;
    std::optional<std::string> rpath;
    std::optional<std::string> runpath;
    std::optional<std::string> interpreter;

    // Symbols (from .dynsym; .symtab also parsed into static_symbols if present)
    std::vector<Elf64_Sym> symbols;
    std::vector<std::string> symbol_names;   // parallel to symbols
    std::vector<SymbolVersionInfo> symbol_versions; // parallel, from VERSYM/VERNEED

    std::vector<Elf64_Sym> static_symbols;
    std::vector<std::string> static_symbol_names;

    // Relocations
    std::vector<Elf64_Rela> rela;
    std::vector<Elf64_Rela> plt_rela;

    // Useful dynamic addresses (guest VAs)
    uint64_t dt_strtab = 0;
    uint64_t dt_symtab = 0;
    uint64_t dt_rela = 0;
    uint64_t dt_relasz = 0;
    uint64_t dt_jmprel = 0;
    uint64_t dt_pltrelsz = 0;
    uint64_t dt_init = 0;
    uint64_t dt_fini = 0;
    uint64_t dt_init_array = 0;
    uint64_t dt_init_arraysz = 0;
    uint64_t dt_fini_array = 0;
    uint64_t dt_fini_arraysz = 0;
    uint64_t dt_versym = 0;
    uint64_t dt_verneed = 0;
    uint64_t dt_verneednum = 0;
    uint64_t dt_verdef = 0;
    uint64_t dt_verdefnum = 0;

    uint64_t entry = 0;
    bool is_pie = false;
    bool has_tls = false;
    bool bind_now = false;

    std::vector<uint8_t> file_data;
};

class ElfParser {
public:
    // Parse a complete ELF64 x86-64 image from memory.
    // Returns nullopt on any validation failure.
    static std::optional<ParsedElf> parse(std::span<const uint8_t> data);

private:
    static bool validateIdent(const uint8_t ident[16]);
    static std::string readCString(std::span<const uint8_t> data, uint64_t offset);
};

} // namespace nexus
