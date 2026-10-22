#include "PeParser.h"
#include "../../diagnostics/Logger.h"
#include <cstring>

namespace nexus {

static uint16_t r16(const uint8_t* p) { return p[0] | (p[1] << 8); }
static uint32_t r32(const uint8_t* p) { return r16(p) | (r16(p + 2) << 16); }
static uint64_t r64(const uint8_t* p) { return r32(p) | (static_cast<uint64_t>(r32(p + 4)) << 32); }

std::optional<ParsedPe> PeParser::parse(const uint8_t* data, size_t len) {
    if (!data || len < 64) return std::nullopt;
    ParsedPe pe;
    pe.dos.e_magic = r16(data);
    if (pe.dos.e_magic != 0x5A4D) {
        Logger::instance().error(LogCategory::LOADER, "PE: bad MZ");
        return std::nullopt;
    }
    pe.dos.e_lfanew = r32(data + 0x3C);
    if (pe.dos.e_lfanew + 24 > len) return std::nullopt;

    const uint8_t* nt = data + pe.dos.e_lfanew;
    pe.nt_signature = r32(nt);
    if (pe.nt_signature != 0x00004550) {
        Logger::instance().error(LogCategory::LOADER, "PE: bad PE signature");
        return std::nullopt;
    }
    const uint8_t* fh = nt + 4;
    pe.file.machine = r16(fh);
    pe.file.number_of_sections = r16(fh + 2);
    pe.file.time_date_stamp = r32(fh + 4);
    pe.file.size_of_optional_header = r16(fh + 16);
    pe.file.characteristics = r16(fh + 18);

    const uint8_t* oh = fh + 20;
    pe.opt.magic = r16(oh);
    pe.is_pe32_plus = pe.opt.magic == 0x20B;
    if (!pe.is_pe32_plus) {
        Logger::instance().error(LogCategory::LOADER, "PE: only PE32+ supported");
        return std::nullopt;
    }
    pe.opt.image_base = r64(oh + 24);
    pe.opt.section_alignment = r32(oh + 32);
    pe.opt.file_alignment = r32(oh + 36);
    pe.opt.size_of_image = r32(oh + 56);
    pe.opt.size_of_headers = r32(oh + 60);
    pe.opt.address_of_entry = r32(oh + 16);
    pe.opt.subsystem = r16(oh + 68);
    pe.opt.size_of_stack_reserve = r64(oh + 72);
    pe.opt.size_of_heap_reserve = r64(oh + 88);

    const uint8_t* dd = oh + 112;
    for (int i = 0; i < 16 && (dd + i * 8 + 8) <= data + len; ++i) {
        pe.opt.directories.push_back({ r32(dd + i * 8), r32(dd + i * 8 + 4) });
    }

    const uint8_t* sh = oh + pe.file.size_of_optional_header;
    for (int i = 0; i < pe.file.number_of_sections; ++i) {
        const uint8_t* s = sh + i * 40;
        if (s + 40 > data + len) break;
        SectionHeader sec;
        std::memcpy(sec.name, s, 8);
        sec.name[8] = 0;
        sec.virtual_size = r32(s + 8);
        sec.virtual_address = r32(s + 12);
        sec.size_of_raw_data = r32(s + 16);
        sec.pointer_to_raw_data = r32(s + 20);
        sec.characteristics = r32(s + 36);
        pe.sections.push_back(sec);
    }
    Logger::instance().infof(LogCategory::LOADER, "PE parsed: %u sections, image %u",
                             pe.file.number_of_sections, pe.opt.size_of_image);
    return pe;
}

} // namespace nexus
