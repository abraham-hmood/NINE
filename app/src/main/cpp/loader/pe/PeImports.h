#pragma once

#include "PeParser.h"
#include "PeMapper.h"
#include "../../memory/MemoryManager.h"
#include "../../linker/GotPltManager.h"
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>

namespace nexus {

struct ImportEntry {
    std::string dll;
    std::string name;
    uint16_t ordinal = 0;
    bool by_ordinal = false;
    uint64_t iat_slot = 0;   // guest address of the IAT entry
};

using DllLoader = std::function<uint64_t(const std::string& dll)>;
using ProcResolver = std::function<uint64_t(const std::string& dll, const std::string& name)>;

class PeImports {
public:
    explicit PeImports(MemoryManager& mm) : mm_(mm) {}

    // Walk the Import Directory (index 1). Returns every import.
    std::vector<ImportEntry> walk(const MappedPe& mapped, const uint8_t* file, size_t file_len);

    // Walk delay-load imports (index 13).
    std::vector<ImportEntry> walkDelay(const MappedPe& mapped, const uint8_t* file, size_t file_len);

    // Load dependent DLLs (recursively via the provided loader) and patch the IAT.
    // Bound imports are honored when present (directory 11) as an optional fast path.
    size_t resolveAndPatch(const MappedPe& mapped, const std::vector<ImportEntry>& imports,
                           DllLoader load_dll, ProcResolver resolve);

private:
    MemoryManager& mm_;
    static uint32_t r32(const uint8_t* p);
    uint32_t rvaToFile(const ParsedPe& pe, uint32_t rva) const;
};

} // namespace nexus
