#pragma once

#include "PeParser.h"
#include "PeMapper.h"
#include <cstdint>
#include <vector>

namespace nexus {

struct PeTlsInfo {
    uint64_t raw_data_start = 0;
    uint64_t raw_data_end = 0;
    uint64_t address_of_index = 0;
    uint64_t callbacks = 0;
    uint32_t zero_fill = 0;
    uint32_t characteristics = 0;
    std::vector<uint64_t> callback_vas;
};

struct RuntimeFunction {
    uint32_t begin = 0;
    uint32_t end = 0;
    uint32_t unwind = 0;
};

struct ExceptionInfo {
    std::vector<RuntimeFunction> functions; // pdata
    bool has_safeseh = false;
    bool has_cfg = false;
    uint32_t cfg_guard_flags = 0;
};

class PeTlsExceptions {
public:
    // TLS directory (index 9): template, index, callbacks.
    static PeTlsInfo parseTls(const MappedPe& mapped, const uint8_t* file, size_t file_len);

    // Exception directory (index 3): pdata entries. xdata stored as RVAs for later unwind.
    // SafeSEH / CFG flags recorded from the load-config directory (index 10) when present.
    static ExceptionInfo parseExceptions(const MappedPe& mapped, const uint8_t* file, size_t file_len);
};

} // namespace nexus
