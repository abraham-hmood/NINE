#pragma once

#include "PeParser.h"
#include "PeMapper.h"
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace nexus {

struct ExportEntry {
    std::string name;
    uint16_t ordinal = 0;
    uint32_t rva = 0;
    uint64_t address = 0;          // base + rva
    bool forwarded = false;
    std::string forwarder;         // "DLL.Func" when forwarded
};

class PeExports {
public:
    // Parse the Export Directory (index 0). Resolves names, ordinals, and forwarded exports.
    static std::vector<ExportEntry> parse(const MappedPe& mapped, const uint8_t* file, size_t file_len);

    // Look up by name or by ordinal. Returns nullopt if missing.
    static std::optional<ExportEntry> find(const std::vector<ExportEntry>& exports, const std::string& name);
    static std::optional<ExportEntry> findOrdinal(const std::vector<ExportEntry>& exports, uint16_t ordinal);
};

} // namespace nexus
