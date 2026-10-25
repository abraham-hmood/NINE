#include "AotRuntime.h"

#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

namespace nexus {
namespace aot {

// Implemented in AotHelpers.cpp.
extern "C" {
uint64_t nine_aot_flags(GuestContext*, int, uint64_t, uint64_t, uint64_t, int, int);
uint64_t nine_aot_shift_flags(GuestContext*, uint64_t, uint64_t, uint64_t, int, int);
}

namespace {

std::atomic<uint32_t> g_load_failures{0};

// The load/store helpers live in runtime/MemHelpers.cpp; declare them here so
// this file stays independent of the JIT headers.
extern "C" {
uint64_t nine_load8(GuestContext*, uint64_t);
uint64_t nine_load16(GuestContext*, uint64_t);
uint64_t nine_load32(GuestContext*, uint64_t);
uint64_t nine_load64(GuestContext*, uint64_t);
void nine_store8(GuestContext*, uint64_t, uint64_t);
void nine_store16(GuestContext*, uint64_t, uint64_t);
void nine_store32(GuestContext*, uint64_t, uint64_t);
void nine_store64(GuestContext*, uint64_t, uint64_t);
}

inline size_t alignUpPage(size_t n) {
    const size_t p = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    return (n + p - 1) & ~(p - 1);
}

} // namespace

void* resolveSymbol(Sym sym) {
    switch (sym) {
        case Sym::Load8:   return reinterpret_cast<void*>(&nine_load8);
        case Sym::Load16:  return reinterpret_cast<void*>(&nine_load16);
        case Sym::Load32:  return reinterpret_cast<void*>(&nine_load32);
        case Sym::Load64:  return reinterpret_cast<void*>(&nine_load64);
        case Sym::Store8:  return reinterpret_cast<void*>(&nine_store8);
        case Sym::Store16: return reinterpret_cast<void*>(&nine_store16);
        case Sym::Store32: return reinterpret_cast<void*>(&nine_store32);
        case Sym::Store64: return reinterpret_cast<void*>(&nine_store64);
        case Sym::Flags:   return reinterpret_cast<void*>(&nine_aot_flags);
        case Sym::ShiftFlags: return reinterpret_cast<void*>(&nine_aot_shift_flags);
        default: return nullptr;
    }
}

uint32_t AotModule::loadFailures() { return g_load_failures.load(); }

AotModule::~AotModule() { unload(); }

void AotModule::unload() {
    if (code_map_) {
        munmap(code_map_, code_map_size_);
        code_map_ = nullptr;
        code_map_size_ = 0;
    }
    index_.clear();
    blob_.clear();
    parsed_ = Parsed{};
}

bool AotModule::loadFile(const std::string& path, std::string* error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        if (error) *error = "cannot open " + path;
        ++g_load_failures;
        return false;
    }
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
    return load(std::move(bytes), error);
}

bool AotModule::load(std::vector<uint8_t> blob, std::string* error) {
    unload();
    auto fail = [&](const char* why) {
        if (error) *error = why;
        ++g_load_failures;
        unload();
        return false;
    };
    if (blob.size() < sizeof(Header)) return fail("image too small");
    blob_ = std::move(blob);

    Parsed parsed{};
    if (!parse(blob_.data(), blob_.size(), parsed))
        return fail("bad magic/version/hash");
    if (parsed.header.block_count == 0) return fail("no blocks");

    // Map a private RW region, copy the code, patch helper addresses, then seal
    // it read+execute. The image bytes stay untouched so `parse` remains valid.
    code_map_size_ = alignUpPage(parsed.header.code_size ? parsed.header.code_size : 4);
    void* mem = mmap(nullptr, code_map_size_, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return fail("mmap failed");
    code_map_ = mem;
    std::memcpy(code_map_, parsed.code, parsed.header.code_size);

    uint32_t* code = static_cast<uint32_t*>(code_map_);
    for (uint32_t i = 0; i < parsed.header.reloc_count; ++i) {
        const Reloc& r = parsed.relocs[i];
        if (r.kind != static_cast<uint32_t>(RelocKind::Helper))
            return fail("unknown relocation kind");
        void* target = resolveSymbol(static_cast<Sym>(r.target));
        if (!target) return fail("unresolved helper symbol");
        // The compiler emits MOVZ Rd,#0 ; MOVK Rd,#0,hw=1..3 — four words whose
        // 16-bit immediates are the four quarters of the helper address.
        if (static_cast<size_t>(r.code_off) + 16 > parsed.header.code_size)
            return fail("relocation out of range");
        const uint64_t addr = reinterpret_cast<uint64_t>(target);
        uint32_t* seq = reinterpret_cast<uint32_t*>(
            reinterpret_cast<uint8_t*>(code_map_) + r.code_off);
        for (int hw = 0; hw < 4; ++hw) {
            const uint16_t part = static_cast<uint16_t>((addr >> (16 * hw)) & 0xFFFF);
            seq[hw] = (seq[hw] & ~(0xFFFFu << 5)) | (static_cast<uint32_t>(part) << 5);
        }
    }

    __builtin___clear_cache(static_cast<char*>(code_map_),
                            static_cast<char*>(code_map_) + parsed.header.code_size);
    if (mprotect(code_map_, code_map_size_, PROT_READ | PROT_EXEC) != 0)
        return fail("mprotect RX failed");

    parsed_ = parsed;
    index_.reserve(parsed.header.block_count);
    for (uint32_t i = 0; i < parsed.header.block_count; ++i)
        index_[parsed.blocks[i].guest_pc] = i;
    return true;
}

uint64_t AotModule::blockEnd(uint64_t pc) const {
    auto it = index_.find(pc);
    if (it == index_.end()) return 0;
    return parsed_.blocks[it->second].guest_end;
}

BlockExitReason AotModule::run(GuestContext& ctx, uint64_t max_blocks) const {
    if (!loaded()) return BlockExitReason::EXCEPTION;
    const auto fn_base = reinterpret_cast<const uint8_t*>(code_map_);
    for (uint64_t n = 0; n < max_blocks; ++n) {
        auto it = index_.find(ctx.rip);
        if (it == index_.end()) {
            ctx.exit_reason = BlockExitReason::EXCEPTION;
            ctx.exit_code = 1;             // unknown guest pc
            ctx.exit_arg0 = ctx.rip;
            return BlockExitReason::EXCEPTION;
        }
        const Block& b = parsed_.blocks[it->second];
        auto fn = reinterpret_cast<void (*)(GuestContext*)>(
            const_cast<uint8_t*>(fn_base) + b.code_off);
        ctx.exit_reason = BlockExitReason::CONTINUE;
        fn(&ctx);
        if (ctx.exit_reason != BlockExitReason::CONTINUE) return ctx.exit_reason;
    }
    return BlockExitReason::HALT;
}

// ---------------------------------------------------------------------------
// AotEngine
// ---------------------------------------------------------------------------

bool AotEngine::add(std::vector<uint8_t> blob, std::string* error) {
    auto m = std::make_unique<AotModule>();
    if (!m->load(std::move(blob), error)) return false;
    modules_.push_back(std::move(m));
    return true;
}

bool AotEngine::addFile(const std::string& path, std::string* error) {
    auto m = std::make_unique<AotModule>();
    if (!m->loadFile(path, error)) return false;
    modules_.push_back(std::move(m));
    return true;
}

void AotEngine::clear() { modules_.clear(); }

uint32_t AotEngine::blockCount() const {
    uint32_t n = 0;
    for (const auto& m : modules_) n += m->blockCount();
    return n;
}

const AotModule* AotEngine::find(uint64_t pc) const {
    for (const auto& m : modules_)
        if (m->contains(pc)) return m.get();
    return nullptr;
}

bool AotEngine::contains(uint64_t pc) const { return find(pc) != nullptr; }

BlockExitReason AotEngine::run(GuestContext& ctx, uint64_t max_blocks) const {
    for (uint64_t n = 0; n < max_blocks; ++n) {
        const AotModule* m = find(ctx.rip);
        if (!m) {
            ctx.exit_reason = BlockExitReason::EXCEPTION;
            ctx.exit_code = 1;
            ctx.exit_arg0 = ctx.rip;
            return BlockExitReason::EXCEPTION;
        }
        const BlockExitReason r = m->run(ctx, 1);
        if (r != BlockExitReason::CONTINUE) return r;
    }
    return BlockExitReason::HALT;
}

} // namespace aot
} // namespace nexus
