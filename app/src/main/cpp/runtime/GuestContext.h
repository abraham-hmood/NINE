#pragma once

#include <cstdint>
#include <cstring>

#include "X87.h"

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
    // SSE control/status. LDMXCSR/STMXCSR and FXSAVE/FXRSTOR round-trip it;
    // its rounding-control and FTZ bits are not yet applied to SSE math.
    uint32_t mxcsr = 0x1F80;
    // Full AVX-512 vector file: 32 registers, 64 bytes each. XMMn is bytes
    // 0-15, YMMn bytes 0-31, ZMMn bytes 0-63 of the same slot, so a legacy
    // SSE write leaves the upper bytes untouched and VEX/EVEX zero-extends
    // them exactly where the ISA says it should.
    alignas(64) uint8_t ymm[32][64] = {};

    // x87 register stack + control/status/tag words (see X87.h). Lives here so
    // it travels with the guest context through thread switches and saves.
    x87::State fpu;

    // AVX-512 opmask file k0-k7 (64 bits each; k0 is the implicit "no mask"
    // register for every EVEX data instruction and is never named by aaa=0).
    uint64_t kmask[8] = {};

    // MPX bound registers BND0-BND3. [i][0] = LB, [i][1] = UB stored in the
    // architecturally visible 1's-complement form (BNDMK writes ~EA, and
    // BNDCU compares against ~UB). Bound tables are not modelled — see
    // BNDLDX/BNDSTX in InsnInterpreter.cpp.
    uint64_t bnd[4][2] = {};

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
        mxcsr = 0x1F80;
        fpu = x87::State{};
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
