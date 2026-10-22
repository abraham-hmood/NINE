#pragma once

#include "ElfLoader.h"
#include "../../memory/MemoryManager.h"
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <string>

namespace nexus {

// x86-64 relocation types
constexpr uint32_t R_X86_64_NONE     = 0;
constexpr uint32_t R_X86_64_64       = 1;
constexpr uint32_t R_X86_64_PC32     = 2;
constexpr uint32_t R_X86_64_GOT32    = 3;
constexpr uint32_t R_X86_64_PLT32    = 4;
constexpr uint32_t R_X86_64_COPY     = 5;
constexpr uint32_t R_X86_64_GLOB_DAT = 6;
constexpr uint32_t R_X86_64_JUMP_SLOT= 7;
constexpr uint32_t R_X86_64_RELATIVE = 8;
constexpr uint32_t R_X86_64_GOTPCREL = 9;
constexpr uint32_t R_X86_64_32       = 10;
constexpr uint32_t R_X86_64_32S      = 11;
constexpr uint32_t R_X86_64_16       = 12;
constexpr uint32_t R_X86_64_PC16     = 13;
constexpr uint32_t R_X86_64_8        = 14;
constexpr uint32_t R_X86_64_PC8      = 15;
constexpr uint32_t R_X86_64_DTPMOD64 = 16;
constexpr uint32_t R_X86_64_DTPOFF64 = 17;
constexpr uint32_t R_X86_64_TPOFF64  = 18;
constexpr uint32_t R_X86_64_TLSGD    = 19;
constexpr uint32_t R_X86_64_TLSLD    = 20;
constexpr uint32_t R_X86_64_DTPOFF32 = 21;
constexpr uint32_t R_X86_64_GOTTPOFF = 22;
constexpr uint32_t R_X86_64_TPOFF32  = 23;
constexpr uint32_t R_X86_64_IRELATIVE= 37;

inline uint32_t relaType(uint64_t r_info)  { return static_cast<uint32_t>(r_info & 0xffffffff); }
inline uint32_t relaSym(uint64_t r_info)   { return static_cast<uint32_t>(r_info >> 32); }

// Symbol binding / visibility helpers
inline uint8_t symBind(uint8_t st_info) { return st_info >> 4; }
inline uint8_t symType(uint8_t st_info) { return st_info & 0xf; }
inline uint8_t symVis(uint8_t st_other) { return st_other & 0x3; }

constexpr uint8_t STB_LOCAL  = 0;
constexpr uint8_t STB_GLOBAL = 1;
constexpr uint8_t STB_WEAK   = 2;

constexpr uint8_t STV_DEFAULT   = 0;
constexpr uint8_t STV_INTERNAL  = 1;
constexpr uint8_t STV_HIDDEN    = 2;
constexpr uint8_t STV_PROTECTED = 3;

// Resolver: given a symbol name, return its guest address (0 if unresolved).
// Named distinctly from linker/SymbolResolver.h (the module-graph resolver
// class) so both headers can be included in one translation unit.
using ElfSymbolResolverFn = std::function<uint64_t(const std::string& name, bool* is_weak)>;

class ElfRelocator {
public:
    // Apply all relocations in the loaded ELF.
    // resolver is used for symbol-based relocs (GLOB_DAT, JUMP_SLOT, etc.).
    // For RELATIVE, only the load bias is needed.
    // Returns number of successfully applied relocations; logs failures.
    static size_t apply(LoadedElf& loaded, MemoryManager& mm, const ElfSymbolResolverFn& resolver);

private:
    static bool applyOne(const Elf64_Rela& rela, LoadedElf& loaded, MemoryManager& mm,
                         const ElfSymbolResolverFn& resolver, bool is_plt);
    static bool writeU64(MemoryManager& mm, uint64_t guest_addr, uint64_t value);
    static bool writeU32(MemoryManager& mm, uint64_t guest_addr, uint32_t value);
    static bool writeI32(MemoryManager& mm, uint64_t guest_addr, int32_t value);
};

} // namespace nexus
