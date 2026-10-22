#pragma once

#include <cstdint>
#include <array>
#include <vector>
#include <optional>

namespace nexus {

// ARM64 host registers we reserve.
// X0-X7 caller-saved scratch, X8 indirect result, X9-X15 caller-saved,
// X19-X28 callee-saved. We pin:
//   X19 = guest RIP
//   X20 = guest RFLAGS
//   X21-X28 = mapped guest GPRs (hot set)
//   X9-X15 = scratch pool
enum class HostReg : int {
    X0 = 0, X1, X2, X3, X4, X5, X6, X7,
    X8, X9, X10, X11, X12, X13, X14, X15,
    X19 = 19, X20, X21, X22, X23, X24, X25, X26, X27, X28,
    SP = 31, NONE = -1
};

enum class GuestReg : int {
    RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    RIP = 16, RFLAGS = 17, NONE = -1
};

struct RegAlloc {
    HostReg host = HostReg::NONE;
    bool spilled = false;
    int spill_slot = -1;
};

class RegisterAllocator {
public:
    RegisterAllocator();

    // Map a guest GPR to a host register. Spills if the hot set is full.
    RegAlloc allocate(GuestReg g);

    // Dedicated mappings (never spilled).
    HostReg guestRip() const { return HostReg::X19; }
    HostReg guestFlags() const { return HostReg::X20; }
    HostReg scratch(int i) const; // 0..6 -> X9..X15

    // Spill/reload helpers for the encoder.
    int spillSlot(GuestReg g) const;
    bool isHot(GuestReg g) const;

    void reset();

private:
    std::array<RegAlloc, 18> map_{};
    std::array<bool, 8> hot_used_{}; // X21-X28
    int next_spill_ = 0;

    static int guestIndex(GuestReg g) { return static_cast<int>(g); }
};

} // namespace nexus
