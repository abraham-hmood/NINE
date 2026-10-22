#pragma once
// Single source of truth for GuestContext field offsets used by the JIT emitter.
// Keep in sync with GuestContext.h member order.
#include "GuestContext.h"
#include <cstddef>
#include <cstdint>

namespace nexus {
namespace ctx_off {

constexpr std::size_t gpr(int i) { return static_cast<std::size_t>(i) * 8u; }

inline std::size_t rip()       { return offsetof(GuestContext, rip); }
inline std::size_t rflags()    { return offsetof(GuestContext, rflags); }
inline std::size_t fs_base()   { return offsetof(GuestContext, fs_base); }
inline std::size_t gs_base()   { return offsetof(GuestContext, gs_base); }
inline std::size_t exit_reason(){ return offsetof(GuestContext, exit_reason); }
inline std::size_t exit_code() { return offsetof(GuestContext, exit_code); }
inline std::size_t exit_arg0() { return offsetof(GuestContext, exit_arg0); }
inline std::size_t exit_arg1() { return offsetof(GuestContext, exit_arg1); }
inline std::size_t exit_arg2() { return offsetof(GuestContext, exit_arg2); }

// Host register pins (AAPCS64 + NINE convention)
constexpr int X_CTX = 0;   // X0  = GuestContext*
constexpr int X_RIP = 19;  // X19 = guest RIP
constexpr int X_FLG = 20;  // X20 = guest RFLAGS
// X21+i = guest GPR i for i in 0..7 (RAX..RDI)
inline int x_gpr(int guest_i) {
    if (guest_i >= 0 && guest_i <= 7) return 21 + guest_i;
    // R8..R15 → X9..X16
    return 9 + (guest_i - 8);
}

} // namespace ctx_off
} // namespace nexus
