#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace nexus {

struct DosHeader {
    uint16_t e_magic = 0;      // MZ
    uint32_t e_lfanew = 0;
};

struct FileHeader {
    uint16_t machine = 0;
    uint16_t number_of_sections = 0;
    uint32_t time_date_stamp = 0;
    uint16_t size_of_optional_header = 0;
    uint16_t characteristics = 0;
};

struct DataDirectory { uint32_t rva = 0; uint32_t size = 0; };

struct OptionalHeader {
    uint16_t magic = 0;            // 0x20b = PE32+
    uint64_t image_base = 0;
    uint32_t section_alignment = 0;
    uint32_t file_alignment = 0;
    uint32_t size_of_image = 0;
    uint32_t size_of_headers = 0;
    uint32_t address_of_entry = 0;
    uint16_t subsystem = 0;
    uint64_t size_of_stack_reserve = 0;
    uint64_t size_of_heap_reserve = 0;
    std::vector<DataDirectory> directories; // 16 entries
};

struct SectionHeader {
    char name[9] = {};
    uint32_t virtual_size = 0;
    uint32_t virtual_address = 0;
    uint32_t size_of_raw_data = 0;
    uint32_t pointer_to_raw_data = 0;
    uint32_t characteristics = 0;
    bool executable() const { return characteristics & 0x20000000; }
    bool writable() const { return characteristics & 0x80000000; }
    bool readable() const { return characteristics & 0x40000000; }
    bool discardable() const { return characteristics & 0x02000000; }
};

struct ParsedPe {
    DosHeader dos;
    uint32_t nt_signature = 0;
    FileHeader file;
    OptionalHeader opt;
    std::vector<SectionHeader> sections;
    bool is_pe32_plus = false;
};

class PeParser {
public:
    static std::optional<ParsedPe> parse(const uint8_t* data, size_t len);
};

} // namespace nexus
