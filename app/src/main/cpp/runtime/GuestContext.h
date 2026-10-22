#pragma once

#include <cstdint>
#include <cstring>

namespace nexus {

enum class BlockExitReason : uint32_t {
    CONTINUE  = 0,
    SYSCALL   = 1,
    IMPORT    = 2,
    EXCEPTION = 3,
    HALT      = 4,
    INDIRECT  = 5,
};

// Full guest x86-64 register file. Layout is ABI-stable for JIT (X0 = ctx*).
struct GuestContext {
    uint64_t gpr[16] = {};
    uint64_t rip = 0;
    uint64_t rflags = 0x202;
    uint64_t fs_base = 0;
    uint64_t gs_base = 0;
    uint64_t cr0 = 0x80050033;
    uint64_t cr2 = 0;
    uint64_t cr3 = 0;
    uint64_t cr4 = 0x00000668;
    alignas(32) uint8_t ymm[16][32] = {};

    // J1.2 exit channel — written by translated blocks before RET
    BlockExitReason exit_reason = BlockExitReason::CONTINUE;
    uint32_t exit_code = 0;
    uint64_t exit_arg0 = 0;
    uint64_t exit_arg1 = 0;
    uint64_t exit_arg2 = 0;

    uint64_t& rax() { return gpr[0]; }
    uint64_t& rcx() { return gpr[1]; }
    uint64_t& rdx() { return gpr[2]; }
    uint64_t& rbx() { return gpr[3]; }
    uint64_t& rsp() { return gpr[4]; }
    uint64_t& rbp() { return gpr[5]; }
    uint64_t& rsi() { return gpr[6]; }
    uint64_t& rdi() { return gpr[7]; }
    const uint64_t& rax() const { return gpr[0]; }
    const uint64_t& rcx() const { return gpr[1]; }
    const uint64_t& rdx() const { return gpr[2]; }
    const uint64_t& rbx() const { return gpr[3]; }
    const uint64_t& rsp() const { return gpr[4]; }
    const uint64_t& rbp() const { return gpr[5]; }
    const uint64_t& rsi() const { return gpr[6]; }
    const uint64_t& rdi() const { return gpr[7]; }

    static constexpr size_t kRedZone = 128;

    void clear() {
        std::memset(this, 0, sizeof(*this));
        rflags = 0x202;
        cr0 = 0x80050033;
        cr4 = 0x00000668;
        exit_reason = BlockExitReason::CONTINUE;
    }

    void clearExit() {
        exit_reason = BlockExitReason::CONTINUE;
        exit_code = 0;
        exit_arg0 = exit_arg1 = exit_arg2 = 0;
    }
};

class ContextSwitch {
public:
    static GuestContext& current();
    void save(GuestContext& ctx);
    void restore(const GuestContext& ctx);
    static bool hitsRedZone(const GuestContext& ctx, uint64_t addr, size_t size);
    void pushExceptionFrame(GuestContext& out);
    void popExceptionFrame(const GuestContext& in);
};

} // namespace nexus
