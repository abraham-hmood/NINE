#include "RegisterAllocator.h"

namespace nexus {

RegisterAllocator::RegisterAllocator() { reset(); }

void RegisterAllocator::reset() {
    for (auto& m : map_) m = {};
    hot_used_.fill(false);
    next_spill_ = 0;
    // Pin RIP and RFLAGS
    map_[static_cast<int>(GuestReg::RIP)] = { HostReg::X19, false, -1 };
    map_[static_cast<int>(GuestReg::RFLAGS)] = { HostReg::X20, false, -1 };
}

HostReg RegisterAllocator::scratch(int i) const {
    if (i < 0 || i > 6) return HostReg::NONE;
    return static_cast<HostReg>(static_cast<int>(HostReg::X9) + i);
}

int RegisterAllocator::spillSlot(GuestReg g) const {
    return map_[guestIndex(g)].spill_slot;
}

bool RegisterAllocator::isHot(GuestReg g) const {
    auto h = map_[guestIndex(g)].host;
    int idx = static_cast<int>(h);
    return idx >= 21 && idx <= 28;
}

RegAlloc RegisterAllocator::allocate(GuestReg g) {
    int gi = guestIndex(g);
    if (g == GuestReg::RIP || g == GuestReg::RFLAGS) return map_[gi];
    if (map_[gi].host != HostReg::NONE) return map_[gi];

    // Prefer a free hot register (X21-X28)
    for (int i = 0; i < 8; ++i) {
        if (!hot_used_[i]) {
            hot_used_[i] = true;
            map_[gi] = { static_cast<HostReg>(21 + i), false, -1 };
            return map_[gi];
        }
    }
    // Spill
    map_[gi] = { HostReg::NONE, true, next_spill_++ };
    return map_[gi];
}

} // namespace nexus
