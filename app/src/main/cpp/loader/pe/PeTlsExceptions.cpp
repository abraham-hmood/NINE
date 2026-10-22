#include "PeTlsExceptions.h"
#include "../../diagnostics/Logger.h"

namespace nexus {

static uint32_t r32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24); }
static uint64_t r64(const uint8_t* p) { return r32(p) | (static_cast<uint64_t>(r32(p + 4)) << 32); }

static uint32_t rvaToFile(const ParsedPe& pe, uint32_t rva) {
    for (const auto& s : pe.sections) {
        if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size)
            return s.pointer_to_raw_data + (rva - s.virtual_address);
    }
    return 0;
}

PeTlsInfo PeTlsExceptions::parseTls(const MappedPe& mapped, const uint8_t* file, size_t file_len) {
    PeTlsInfo tls;
    if (mapped.parsed.opt.directories.size() <= 9) return tls;
    const auto& dir = mapped.parsed.opt.directories[9];
    if (dir.rva == 0) return tls;
    uint32_t off = rvaToFile(mapped.parsed, dir.rva);
    if (!off || off + 40 > file_len) return tls;
    const uint8_t* p = file + off;
    tls.raw_data_start = r64(p);
    tls.raw_data_end = r64(p + 8);
    tls.address_of_index = r64(p + 16);
    tls.callbacks = r64(p + 24);
    tls.zero_fill = r32(p + 32);
    tls.characteristics = r32(p + 36);
    // Callbacks are a null-terminated VA array.
    if (tls.callbacks) {
        uint64_t rva = tls.callbacks - mapped.parsed.opt.image_base;
        uint32_t coff = rvaToFile(mapped.parsed, static_cast<uint32_t>(rva));
        if (coff) {
            for (int i = 0; coff + (i + 1) * 8 <= file_len; ++i) {
                uint64_t cb = r64(file + coff + i * 8);
                if (cb == 0) break;
                tls.callback_vas.push_back(cb);
            }
        }
    }
    Logger::instance().infof(LogCategory::LOADER, "TLS: %zu callbacks", tls.callback_vas.size());
    return tls;
}

ExceptionInfo PeTlsExceptions::parseExceptions(const MappedPe& mapped, const uint8_t* file, size_t file_len) {
    ExceptionInfo info;
    if (mapped.parsed.opt.directories.size() > 3) {
        const auto& dir = mapped.parsed.opt.directories[3];
        if (dir.rva && dir.size) {
            uint32_t off = rvaToFile(mapped.parsed, dir.rva);
            if (off) {
                size_t n = dir.size / 12;
                for (size_t i = 0; i < n && off + (i + 1) * 12 <= file_len; ++i) {
                    const uint8_t* e = file + off + i * 12;
                    info.functions.push_back({ r32(e), r32(e + 4), r32(e + 8) });
                }
            }
        }
    }
    // Load config (index 10): CFG / SafeSEH flags.
    if (mapped.parsed.opt.directories.size() > 10) {
        const auto& lc = mapped.parsed.opt.directories[10];
        if (lc.rva) {
            uint32_t off = rvaToFile(mapped.parsed, lc.rva);
            if (off && off + 96 <= file_len) {
                // GuardFlags at offset 88 in PE32+ load config.
                info.cfg_guard_flags = r32(file + off + 88);
                info.has_cfg = (info.cfg_guard_flags & 0x100) != 0;
                info.has_safeseh = true; // structure present; full table is optional
            }
        }
    }
    Logger::instance().infof(LogCategory::LOADER, "pdata: %zu entries cfg=%d",
                             info.functions.size(), info.has_cfg ? 1 : 0);
    return info;
}

} // namespace nexus
