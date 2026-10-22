#include "GotPltManager.h"
#include "../diagnostics/Logger.h"
#include <cstring>

namespace nexus {

static bool writeGuestU64(MemoryManager& mm, uint64_t addr, uint64_t value) {
    void* host = mm.guestToHost(addr);
    if (!host) return false;
    std::memcpy(host, &value, sizeof(value));
    return true;
}

size_t GotPltManager::populateGot(Module& mod,
                                  const std::vector<std::pair<uint64_t, std::string>>& got_entries) {
    size_t n = 0;
    for (const auto& [addr, name] : got_entries) {
        auto rs = resolver_.resolve(name, "", &mod);
        uint64_t value = rs ? rs->address : 0;
        if (writeGuestU64(mm_, addr, value)) ++n;
        else Logger::instance().errorf(LogCategory::LINKER, "GOT write failed at 0x%llx", (unsigned long long)addr);
    }
    Logger::instance().infof(LogCategory::LINKER, "GOT populated: %zu/%zu", n, got_entries.size());
    return n;
}

size_t GotPltManager::installLazyPlt(const std::vector<std::pair<uint64_t, std::string>>& plt_slots,
                                     uint64_t resolver_stub) {
    size_t n = 0;
    for (const auto& [addr, name] : plt_slots) {
        pending_[addr] = name;
        if (writeGuestU64(mm_, addr, resolver_stub)) ++n;
    }
    Logger::instance().infof(LogCategory::LINKER, "Lazy PLT slots: %zu", n);
    return n;
}

bool GotPltManager::patchSlot(uint64_t guest_got_addr, uint64_t resolved) {
    pending_.erase(guest_got_addr);
    return writeGuestU64(mm_, guest_got_addr, resolved);
}

size_t GotPltManager::patchIat(const std::vector<std::pair<uint64_t, std::string>>& iat_entries) {
    size_t n = 0;
    for (const auto& [addr, name] : iat_entries) {
        auto rs = resolver_.resolve(name);
        uint64_t value = rs ? rs->address : 0;
        if (writeGuestU64(mm_, addr, value)) ++n;
    }
    Logger::instance().infof(LogCategory::LINKER, "IAT patched: %zu/%zu", n, iat_entries.size());
    return n;
}

uint64_t GotPltManager::onLazyResolve(uint64_t guest_got_addr) {
    auto it = pending_.find(guest_got_addr);
    if (it == pending_.end()) return 0;
    const std::string name = it->second;
    uint64_t addr = 0;
    if (lazy_) addr = lazy_(name);
    if (addr == 0) {
        auto rs = resolver_.resolve(name);
        if (rs) addr = rs->address;
    }
    if (addr) patchSlot(guest_got_addr, addr);
    return addr;
}

} // namespace nexus
