#pragma once
// Relinker-side translation: take a mapped guest module and emit AOT images.
//
// This is the step that lets a light shell run a program with no dynamic
// binary translator: the relinker already has the program mapped and
// relocated in host memory, so it can hand every executable range to
// `aot::compile()` and write the results next to the program.
//
// Nothing here executes guest code. A rejected module (any unsupported
// instruction) simply produces no image, and the report says why.

#include "AotCompiler.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace nexus {
class MemoryManager;
struct LoadedElf;
struct ParsedPe;

namespace aot {

struct ExecRange {
    uint64_t base = 0;
    uint64_t end = 0;      // exclusive
};

struct SegmentTranslation {
    uint64_t base = 0;
    uint64_t end = 0;
    bool ok = false;
    uint32_t blocks = 0;
    uint32_t code_bytes = 0;
    size_t image_bytes = 0;
    std::string path;      // sidecar written, empty when compile was refused
};

struct ModuleTranslation {
    std::string name;
    bool ok = false;
    std::string error;
    uint32_t blocks = 0;
    size_t image_bytes = 0;
    std::vector<SegmentTranslation> segments;
    std::vector<std::string> unsupported;   // deduplicated blocking mnemonics

    // One line for the relink log.
    std::string summary() const;
};

// Compiles each range and writes `<out_dir>/<name>.<n>.nine.aot` beside the
// program. `entry` may be 0 (libraries); it is only recorded in the header.
ModuleTranslation translate(MemoryManager& mm,
                            const std::vector<ExecRange>& ranges,
                            uint64_t entry,
                            const std::string& name,
                            const std::string& out_dir);

// Executable ranges of a mapped ELF module.
std::vector<ExecRange> execRanges(const LoadedElf& loaded);

// Executable ranges of a mapped PE image (section virtual addresses).
std::vector<ExecRange> execRanges(const ParsedPe& pe);

// Reads a range out of the guest mapping, splitting at region boundaries.
// Returns false if any page of it is unmapped.
bool readGuestRange(MemoryManager& mm, uint64_t base, uint64_t end,
                    std::vector<uint8_t>* out);

} // namespace aot
} // namespace nexus
