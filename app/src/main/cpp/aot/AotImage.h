#pragma once
// On-disk format for a NINE AOT image.
//
// The relinker decodes a guest program's executable ranges and emits one
// AArch64 function per basic block. The blob written next to the program is:
//
//   Header | Block[block_count] | Reloc[reloc_count] | code[code_size]
//
// All fields are little-endian, the code is word-aligned, and every absolute
// host address the generated code needs (memory helpers, the flag helper) is
// a relocation the loader patches after mapping. Guest addresses never appear
// in the code except as immediates written by the compiler, so an image is
// position independent with respect to the host.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace nexus {
namespace aot {

constexpr uint32_t kVersion = 1;
inline constexpr char kMagic[8] = { 'N', 'I', 'N', 'E', 'A', 'O', 'T', '\0' };

// Runtime entry points the generated code may reference. The loader resolves
// each id to the host function pointer of the same index.
enum class Sym : uint32_t {
    Load8 = 0,
    Load16,
    Load32,
    Load64,
    Store8,
    Store16,
    Store32,
    Store64,
    Flags,
    ShiftFlags,
    Count
};

enum class RelocKind : uint32_t { Helper = 1 };

#pragma pack(push, 1)
struct Header {
    char magic[8];
    uint32_t version;
    uint32_t block_count;
    uint32_t reloc_count;
    uint32_t code_size;
    uint64_t entry;
    uint64_t code_hash;   // FNV-1a over the code words
    uint64_t reserved;
};

struct Block {
    uint64_t guest_pc;
    uint64_t guest_end;
    uint32_t code_off;    // byte offset into code[]
    uint32_t code_len;    // bytes
    uint32_t exit_kind;   // BlockExitReason the block's fallthrough produces
    uint32_t reserved;
};

struct Reloc {
    uint32_t code_off;    // byte offset of the movz/movk sequence
    uint32_t kind;        // RelocKind
    uint64_t target;      // Sym id for Helper
};
#pragma pack(pop)

inline uint64_t fnv1a(const void* data, size_t n) {
    const auto* p = static_cast<const uint8_t*>(data);
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

// Serialises a complete image. `code` is the concatenated block code.
inline std::vector<uint8_t> serialize(const std::vector<Block>& blocks,
                                      const std::vector<uint32_t>& code,
                                      const std::vector<Reloc>& relocs,
                                      uint64_t entry) {
    Header h{};
    std::memcpy(h.magic, kMagic, sizeof(kMagic));
    h.version = kVersion;
    h.block_count = static_cast<uint32_t>(blocks.size());
    h.reloc_count = static_cast<uint32_t>(relocs.size());
    h.code_size = static_cast<uint32_t>(code.size() * sizeof(uint32_t));
    h.entry = entry;
    h.code_hash = fnv1a(code.data(), code.size() * sizeof(uint32_t));

    std::vector<uint8_t> out;
    out.resize(sizeof(Header) + blocks.size() * sizeof(Block) +
               relocs.size() * sizeof(Reloc) + code.size() * sizeof(uint32_t));
    size_t off = 0;
    std::memcpy(out.data() + off, &h, sizeof(h)); off += sizeof(h);
    if (!blocks.empty()) {
        std::memcpy(out.data() + off, blocks.data(), blocks.size() * sizeof(Block));
        off += blocks.size() * sizeof(Block);
    }
    if (!relocs.empty()) {
        std::memcpy(out.data() + off, relocs.data(), relocs.size() * sizeof(Reloc));
        off += relocs.size() * sizeof(Reloc);
    }
    if (!code.empty()) {
        std::memcpy(out.data() + off, code.data(), code.size() * sizeof(uint32_t));
    }
    return out;
}

struct Parsed {
    Header header{};
    const Block* blocks = nullptr;
    const Reloc* relocs = nullptr;
    const uint32_t* code = nullptr;
};

// Validates a blob and points at its sections. Returns false on any mismatch.
inline bool parse(const uint8_t* data, size_t len, Parsed& out) {
    if (!data || len < sizeof(Header)) return false;
    Header h{};
    std::memcpy(&h, data, sizeof(h));
    if (std::memcmp(h.magic, kMagic, sizeof(kMagic)) != 0) return false;
    if (h.version != kVersion) return false;
    const size_t need = sizeof(Header) +
                        static_cast<size_t>(h.block_count) * sizeof(Block) +
                        static_cast<size_t>(h.reloc_count) * sizeof(Reloc) +
                        static_cast<size_t>(h.code_size);
    if (need > len) return false;
    if (h.code_size % 4 != 0) return false;
    size_t off = sizeof(Header);
    out.header = h;
    out.blocks = reinterpret_cast<const Block*>(data + off);
    off += static_cast<size_t>(h.block_count) * sizeof(Block);
    out.relocs = reinterpret_cast<const Reloc*>(data + off);
    off += static_cast<size_t>(h.reloc_count) * sizeof(Reloc);
    out.code = reinterpret_cast<const uint32_t*>(data + off);
    if (fnv1a(out.code, h.code_size) != h.code_hash) return false;
    return true;
}

} // namespace aot
} // namespace nexus
