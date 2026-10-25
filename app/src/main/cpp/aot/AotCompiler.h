#pragma once
// Ahead-of-time x86-64 → AArch64 compiler used by the relinker.
//
// The relinker hands `compile()` a contiguous executable range of the guest
// image. The compiler linearly decodes it, splits it into basic blocks (block
// starts are the range start, every instruction after a terminator, and every
// direct branch/call target), emits one AArch64 function per block, and
// serialises everything into an AotImage blob.
//
// Acceptance is all-or-nothing: if any reached instruction is not in the
// emitter's supported set the result is `ok == false` and `unsupported` lists
// the blocking mnemonics. The relinker then leaves the program without an AOT
// image, which is exactly what the "no interpreter in the shell" contract
// needs — better a clear refusal than silently wrong native code.

#include <cstdint>
#include <string>
#include <vector>

namespace nexus {
namespace aot {

struct AotResult {
    bool ok = false;
    std::string error;
    std::vector<std::string> unsupported;   // mnemonic or reason, deduplicated
    std::vector<uint8_t> image;
    uint32_t block_count = 0;
    uint32_t code_bytes = 0;
    uint32_t reloc_count = 0;
};

// `code`/`len` is one executable range, `base` its guest address.
AotResult compile(const uint8_t* code, size_t len, uint64_t base, uint64_t entry);

// Supported-opcode report, used by docs/tests: "op=…" names.
const std::vector<std::string>& supportedOpcodes();

} // namespace aot
} // namespace nexus
