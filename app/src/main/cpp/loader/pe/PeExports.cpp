#include "PeExports.h"
#include "../../diagnostics/Logger.h"

namespace nexus {

static uint32_t r32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24); }
static uint16_t r16(const uint8_t* p) { return p[0] | (p[1] << 8); }

static uint32_t rvaToFile(const ParsedPe& pe, uint32_t rva) {
    for (const auto& s : pe.sections) {
        if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size)
            return s.pointer_to_raw_data + (rva - s.virtual_address);
    }
    return 0;
}

std::vector<ExportEntry> PeExports::parse(const MappedPe& mapped, const uint8_t* file, size_t file_len) {
    std::vector<ExportEntry> out;
    if (mapped.parsed.opt.directories.empty()) return out;
    const auto& dir = mapped.parsed.opt.directories[0];
    if (dir.rva == 0 || dir.size == 0) return out;
    uint32_t off = rvaToFile(mapped.parsed, dir.rva);
    if (!off || off + 40 > file_len) return out;

    const uint8_t* ed = file + off;
    uint32_t ordinal_base = r32(ed + 16);
    uint32_t n_funcs = r32(ed + 20);
    uint32_t n_names = r32(ed + 24);
    uint32_t funcs_rva = r32(ed + 28);
    uint32_t names_rva = r32(ed + 32);
    uint32_t ords_rva = r32(ed + 36);

    uint32_t funcs_off = rvaToFile(mapped.parsed, funcs_rva);
    uint32_t names_off = rvaToFile(mapped.parsed, names_rva);
    uint32_t ords_off = rvaToFile(mapped.parsed, ords_rva);
    if (!funcs_off) return out;

    for (uint32_t i = 0; i < n_funcs; ++i) {
        if (funcs_off + (i + 1) * 4 > file_len) break;
        uint32_t rva = r32(file + funcs_off + i * 4);
        if (rva == 0) continue;
        ExportEntry e;
        e.ordinal = static_cast<uint16_t>(ordinal_base + i);
        e.rva = rva;
        e.address = mapped.base + rva;
        // Forwarded if RVA falls inside the export directory.
        if (rva >= dir.rva && rva < dir.rva + dir.size) {
            e.forwarded = true;
            uint32_t foff = rvaToFile(mapped.parsed, rva);
            if (foff && foff < file_len) e.forwarder = reinterpret_cast<const char*>(file + foff);
        }
        out.push_back(e);
    }
    // Attach names
    for (uint32_t i = 0; i < n_names && names_off && ords_off; ++i) {
        if (names_off + (i + 1) * 4 > file_len || ords_off + (i + 1) * 2 > file_len) break;
        uint32_t name_rva = r32(file + names_off + i * 4);
        uint16_t ord_index = r16(file + ords_off + i * 2);
        uint32_t name_off = rvaToFile(mapped.parsed, name_rva);
        if (!name_off || ord_index >= out.size()) continue;
        out[ord_index].name = reinterpret_cast<const char*>(file + name_off);
    }
    Logger::instance().infof(LogCategory::LOADER, "PE exports: %zu", out.size());
    return out;
}

std::optional<ExportEntry> PeExports::find(const std::vector<ExportEntry>& exports, const std::string& name) {
    for (const auto& e : exports) if (e.name == name) return e;
    return std::nullopt;
}

std::optional<ExportEntry> PeExports::findOrdinal(const std::vector<ExportEntry>& exports, uint16_t ordinal) {
    for (const auto& e : exports) if (e.ordinal == ordinal) return e;
    return std::nullopt;
}

} // namespace nexus
