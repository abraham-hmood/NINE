#pragma once

#include "SymbolResolver.h"
#include "../memory/MemoryManager.h"
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <string>

namespace nexus {

// DBT-facing callback: invoked on first call through an unresolved PLT/IAT slot.
using LazyResolveFn = std::function<uint64_t(const std::string& symbol)>;

class GotPltManager {
public:
    explicit GotPltManager(MemoryManager& mm, SymbolResolver& resolver)
        : mm_(mm), resolver_(resolver) {}

    // Populate ELF GOT entries (R_X86_64_GLOB_DAT) with resolved addresses.
    // plt_slots maps guest GOT address -> symbol name for lazy PLT.
    size_t populateGot(Module& mod, const std::vector<std::pair<uint64_t, std::string>>& got_entries);

    // Install a lazy resolver stub address into each PLT GOT slot.
    // On first call the DBT invokes onLazyResolve and we patch the slot.
    size_t installLazyPlt(const std::vector<std::pair<uint64_t, std::string>>& plt_slots,
                          uint64_t resolver_stub);

    // Patch a single slot after lazy resolution.
    bool patchSlot(uint64_t guest_got_addr, uint64_t resolved);

    // PE IAT: patch Import Address Table entries.
    size_t patchIat(const std::vector<std::pair<uint64_t, std::string>>& iat_entries);

    // Called by the DBT on first indirect call through a lazy slot.
    uint64_t onLazyResolve(uint64_t guest_got_addr);

    void setLazyCallback(LazyResolveFn fn) { lazy_ = std::move(fn); }

private:
    MemoryManager& mm_;
    SymbolResolver& resolver_;
    LazyResolveFn lazy_;
    std::unordered_map<uint64_t, std::string> pending_; // got addr -> symbol
};

} // namespace nexus
