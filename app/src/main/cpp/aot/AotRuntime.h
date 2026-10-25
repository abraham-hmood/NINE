#pragma once
// Loader + dispatcher for NINE AOT images.
//
// A light shell carries nothing but this file's runtime: the guest program was
// already translated to AArch64 by the relinker, so execution is a plain
// block lookup and call — no decoder, no JIT, no instruction cache.
//
// The image is mapped into its own executable region (RW at load, RX after the
// helper relocations are patched) and every block is entered with
// `GuestContext*` in X0, matching translator/HostTrampoline.h.

#include "AotImage.h"
#include "../runtime/GuestContext.h"
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace nexus {
namespace aot {

class AotModule {
public:
    AotModule() = default;
    ~AotModule();
    AotModule(const AotModule&) = delete;
    AotModule& operator=(const AotModule&) = delete;

    // Takes ownership of the blob bytes. Returns false (and sets `error`) on a
    // corrupt image, an unknown relocation kind, or an unmappable code region.
    bool load(std::vector<uint8_t> blob, std::string* error = nullptr);

    // Load straight from disk.
    bool loadFile(const std::string& path, std::string* error = nullptr);

    void unload();

    bool loaded() const { return parsed_.code != nullptr; }
    uint64_t entry() const { return parsed_.header.entry; }
    uint32_t blockCount() const { return parsed_.header.block_count; }
    size_t codeBytes() const { return parsed_.header.code_size; }

    // True if a block starts exactly at `pc`.
    bool contains(uint64_t pc) const { return index_.count(pc) != 0; }

    // Boundaries of the block starting at `pc` (0/0 when absent).
    uint64_t blockEnd(uint64_t pc) const;

    // Runs blocks from ctx.rip until the context requests a different exit
    // reason (syscall/exception/import) or `max_blocks` runs out. Returns the
    // reason; HALT means the block budget was exhausted with CONTINUE.
    BlockExitReason run(GuestContext& ctx, uint64_t max_blocks = (1ull << 40)) const;

    // Number of AOT images that failed validation (diagnostics only).
    static uint32_t loadFailures();

private:
    std::vector<uint8_t> blob_;
    Parsed parsed_{};
    void* code_map_ = nullptr;
    size_t code_map_size_ = 0;
    std::unordered_map<uint64_t, uint32_t> index_;
};

// Resolves a Sym id to the host address the generated code calls.
void* resolveSymbol(Sym sym);

// A program is usually translated as several images (one per executable
// segment), so execution needs to find the owning image for a guest pc.
class AotEngine {
public:
    // Adds an image. On failure the module is discarding and `error` is set.
    bool add(std::vector<uint8_t> blob, std::string* error = nullptr);
    bool addFile(const std::string& path, std::string* error = nullptr);
    void clear();

    size_t moduleCount() const { return modules_.size(); }
    uint32_t blockCount() const;
    bool contains(uint64_t pc) const;

    // The module that owns `pc`, or nullptr.
    const AotModule* find(uint64_t pc) const;

    // Dispatch loop across every loaded image until the guest asks for a
    // different exit reason. Returns that reason (HALT = block budget hit).
    BlockExitReason run(GuestContext& ctx, uint64_t max_blocks = (1ull << 40)) const;

private:
    std::vector<std::unique_ptr<AotModule>> modules_;
};

} // namespace aot
} // namespace nexus
