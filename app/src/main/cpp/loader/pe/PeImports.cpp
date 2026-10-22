#include "PeImports.h"
#include "../../diagnostics/Logger.h"
#include <cstring>

namespace nexus {

uint32_t PeImports::r32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24); }

uint32_t PeImports::rvaToFile(const ParsedPe& pe, uint32_t rva) const {
    for (const auto& s : pe.sections) {
        if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size)
            return s.pointer_to_raw_data + (rva - s.virtual_address);
    }
    return 0;
}

std::vector<ImportEntry> PeImports::walk(const MappedPe& mapped, const uint8_t* file, size_t file_len) {
    std::vector<ImportEntry> out;
    if (mapped.parsed.opt.directories.size() <= 1) return out;
    const auto& dir = mapped.parsed.opt.directories[1];
    if (dir.rva == 0) return out;
    uint32_t off = rvaToFile(mapped.parsed, dir.rva);
    if (!off || off + 20 > file_len) return out;

    const uint8_t* p = file + off;
    while (p + 20 <= file + file_len) {
        uint32_t ilt_rva = r32(p);
        uint32_t name_rva = r32(p + 12);
        uint32_t iat_rva = r32(p + 16);
        if (ilt_rva == 0 && name_rva == 0) break;
        uint32_t name_off = rvaToFile(mapped.parsed, name_rva);
        std::string dll = (name_off && name_off < file_len) ? reinterpret_cast<const char*>(file + name_off) : "";
        uint32_t ilt_off = rvaToFile(mapped.parsed, ilt_rva);
        if (ilt_off) {
            const uint8_t* e = file + ilt_off;
            for (int i = 0; e + 8 <= file + file_len; ++i, e += 8) {
                uint64_t thunk = 0;
                std::memcpy(&thunk, e, 8);
                if (thunk == 0) break;
                ImportEntry ie;
                ie.dll = dll;
                ie.iat_slot = mapped.base + iat_rva + i * 8;
                if (thunk & (1ULL << 63)) {
                    ie.by_ordinal = true;
                    ie.ordinal = static_cast<uint16_t>(thunk & 0xFFFF);
                    ie.name = "#" + std::to_string(ie.ordinal);
                } else {
                    uint32_t hint_off = rvaToFile(mapped.parsed, static_cast<uint32_t>(thunk));
                    if (hint_off + 2 < file_len)
                        ie.name = reinterpret_cast<const char*>(file + hint_off + 2);
                }
                out.push_back(ie);
            }
        }
        p += 20;
    }
    Logger::instance().infof(LogCategory::LOADER, "PE imports: %zu", out.size());
    return out;
}

std::vector<ImportEntry> PeImports::walkDelay(const MappedPe& mapped, const uint8_t* file, size_t file_len) {
    // Delay-load directory (index 13) has the same thunk shape; reuse walk logic on that dir.
    if (mapped.parsed.opt.directories.size() <= 13) return {};
    auto saved = mapped;
    // Temporarily point directory 1 at the delay dir so walk() can parse it.
    // We instead parse directly.
    std::vector<ImportEntry> out;
    const auto& dir = mapped.parsed.opt.directories[13];
    if (dir.rva == 0) return out;
    // Delay descriptors are 32 bytes; name at +4, IAT at +12, INT at +16 (PE32+).
    uint32_t off = rvaToFile(mapped.parsed, dir.rva);
    if (!off) return out;
    const uint8_t* p = file + off;
    while (p + 32 <= file + file_len) {
        uint32_t name_rva = r32(p + 4);
        uint32_t iat_rva = r32(p + 12);
        uint32_t int_rva = r32(p + 16);
        if (name_rva == 0) break;
        uint32_t name_off = rvaToFile(mapped.parsed, name_rva);
        std::string dll = (name_off && name_off < file_len) ? reinterpret_cast<const char*>(file + name_off) : "";
        uint32_t int_off = rvaToFile(mapped.parsed, int_rva);
        if (int_off) {
            const uint8_t* e = file + int_off;
            for (int i = 0; e + 8 <= file + file_len; ++i, e += 8) {
                uint64_t thunk = 0;
                std::memcpy(&thunk, e, 8);
                if (thunk == 0) break;
                ImportEntry ie;
                ie.dll = dll;
                ie.iat_slot = mapped.base + iat_rva + i * 8;
                if (thunk & (1ULL << 63)) {
                    ie.by_ordinal = true;
                    ie.ordinal = static_cast<uint16_t>(thunk & 0xFFFF);
                    ie.name = "#" + std::to_string(ie.ordinal);
                } else {
                    uint32_t hint_off = rvaToFile(mapped.parsed, static_cast<uint32_t>(thunk));
                    if (hint_off + 2 < file_len)
                        ie.name = reinterpret_cast<const char*>(file + hint_off + 2);
                }
                out.push_back(ie);
            }
        }
        p += 32;
    }
    return out;
}

size_t PeImports::resolveAndPatch(const MappedPe& mapped, const std::vector<ImportEntry>& imports,
                                  DllLoader load_dll, ProcResolver resolve) {
    std::unordered_map<std::string, uint64_t> loaded;
    size_t patched = 0;
    for (const auto& ie : imports) {
        if (!loaded.count(ie.dll)) {
            uint64_t base = load_dll ? load_dll(ie.dll) : 0;
            loaded[ie.dll] = base;
        }
        uint64_t addr = resolve ? resolve(ie.dll, ie.name) : 0;
        void* slot = mm_.guestToHost(ie.iat_slot);
        if (slot) {
            std::memcpy(slot, &addr, 8);
            ++patched;
        }
    }
    Logger::instance().infof(LogCategory::LOADER, "IAT patched: %zu/%zu", patched, imports.size());
    return patched;
}

} // namespace nexus
