#include "ControlFlow.h"

namespace nexus {

void ControlFlow::addDirect(uint64_t guest_from, uint64_t guest_to, size_t) {
    recordEdge(guest_from, guest_to);
    install(guest_to, 0);
}

void ControlFlow::recordEdge(uint64_t from_pc, uint64_t to_pc) {
    std::lock_guard<std::mutex> lock(mu_);
    edge_counts_[edgeKey(from_pc, to_pc)]++;
    adj_[from_pc].push_back(to_pc);
}

uint64_t ControlFlow::edgeCount(uint64_t from_pc, uint64_t to_pc) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = edge_counts_.find(edgeKey(from_pc, to_pc));
    return it == edge_counts_.end() ? 0 : it->second;
}

std::vector<uint64_t> ControlFlow::buildTrace(uint64_t seed_pc, size_t max_blocks,
                                              uint64_t min_edge_count) const {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<uint64_t> trace;
    std::unordered_map<uint64_t, bool> seen;
    uint64_t cur = seed_pc;
    for (size_t n = 0; n < max_blocks; ++n) {
        if (seen[cur]) break;
        seen[cur] = true;
        trace.push_back(cur);
        auto it = adj_.find(cur);
        if (it == adj_.end() || it->second.empty()) break;
        uint64_t best_to = 0;
        uint64_t best_c = 0;
        for (uint64_t to : it->second) {
            auto eit = edge_counts_.find(edgeKey(cur, to));
            uint64_t c = eit == edge_counts_.end() ? 0 : eit->second;
            if (c > best_c) { best_c = c; best_to = to; }
        }
        if (best_c < min_edge_count || best_to == 0) break;
        cur = best_to;
    }
    return trace;
}

std::optional<uint64_t> ControlFlow::lookupIndirect(uint64_t guest_target) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = inline_cache_.find(guest_target);
    if (it != inline_cache_.end() && it->second != 0) {
        ic_hits_.fetch_add(1, std::memory_order_relaxed);
        return it->second;
    }
    auto c = cache_.find(guest_target);
    if (c != cache_.end() && c->second != 0) {
        inline_cache_[guest_target] = c->second;
        return c->second;
    }
    return std::nullopt;
}

void ControlFlow::install(uint64_t guest_pc, uint64_t host_addr) {
    std::lock_guard<std::mutex> lock(mu_);
    cache_[guest_pc] = host_addr;
}

void ControlFlow::icUpdate(uint64_t call_site, uint64_t target_guest, uint64_t host_addr) {
    std::lock_guard<std::mutex> lock(mu_);
    ic_[edgeKey(call_site, target_guest)] = host_addr;
    inline_cache_[call_site] = host_addr;
}

std::optional<uint64_t> ControlFlow::icLookup(uint64_t call_site, uint64_t target_guest) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = ic_.find(edgeKey(call_site, target_guest));
    if (it != ic_.end() && it->second != 0) {
        ic_hits_.fetch_add(1, std::memory_order_relaxed);
        return it->second;
    }
    return std::nullopt;
}

void ControlFlow::pltBind(uint64_t plt_entry, uint64_t host_helper) {
    std::lock_guard<std::mutex> lock(mu_);
    plt_[plt_entry] = host_helper;
}
std::optional<uint64_t> ControlFlow::pltLookup(uint64_t plt_entry) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = plt_.find(plt_entry);
    if (it == plt_.end()) return std::nullopt;
    return it->second;
}
void ControlFlow::iatBind(uint64_t iat_slot, uint64_t host_helper) {
    std::lock_guard<std::mutex> lock(mu_);
    iat_[iat_slot] = host_helper;
}
std::optional<uint64_t> ControlFlow::iatLookup(uint64_t iat_slot) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = iat_.find(iat_slot);
    if (it == iat_.end()) return std::nullopt;
    return it->second;
}

void ControlFlow::pushCall(uint64_t return_guest) {
    std::lock_guard<std::mutex> lock(mu_);
    shadow_stack_.push_back(return_guest);
}
std::optional<uint64_t> ControlFlow::popCall() {
    std::lock_guard<std::mutex> lock(mu_);
    if (shadow_stack_.empty()) return std::nullopt;
    uint64_t v = shadow_stack_.back();
    shadow_stack_.pop_back();
    return v;
}

void ControlFlow::requestSyscallExit(uint64_t, uint64_t syscall_nr) {
    syscall_pending_ = true;
    pending_nr_ = syscall_nr;
}
void ControlFlow::requestImportExit(uint64_t addr) {
    import_pending_ = true;
    pending_import_ = addr;
}

} // namespace nexus
