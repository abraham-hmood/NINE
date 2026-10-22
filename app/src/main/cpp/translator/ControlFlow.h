#pragma once

#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <atomic>

namespace nexus {

// J3: edge-profiled control flow, traces, and inline cache for indirects.
class ControlFlow {
public:
    // ---- Direct / indirect linking ----
    void addDirect(uint64_t guest_from, uint64_t guest_to, size_t host_offset = 0);
    std::optional<uint64_t> lookupIndirect(uint64_t site_or_target);
    void install(uint64_t guest_pc, uint64_t host_addr);

    // ---- J3.1 Edge counters & traces ----
    void recordEdge(uint64_t from_pc, uint64_t to_pc);
    uint64_t edgeCount(uint64_t from_pc, uint64_t to_pc) const;
    // Build a hot linear path starting at seed (greedy highest-edge successors).
    std::vector<uint64_t> buildTrace(uint64_t seed_pc, size_t max_blocks = 16,
                                     uint64_t min_edge_count = 2) const;

    // ---- J3.2 Register caching across blocks ----
    // When true, ExecutionLoop may skip full GuestContext spill between
    // direct-linked blocks that share the same host GPR mapping.
    void setRegCacheActive(bool v) { reg_cache_active_.store(v, std::memory_order_release); }
    bool regCacheActive() const { return reg_cache_active_.load(std::memory_order_acquire); }

    // ---- J3.3 Inline cache (IC) for indirect call sites ----
    void icUpdate(uint64_t call_site, uint64_t target_guest, uint64_t host_addr);
    std::optional<uint64_t> icLookup(uint64_t call_site, uint64_t target_guest);
    void pltBind(uint64_t plt_entry, uint64_t host_helper);
    std::optional<uint64_t> pltLookup(uint64_t plt_entry) const;
    void iatBind(uint64_t iat_slot, uint64_t host_helper);
    std::optional<uint64_t> iatLookup(uint64_t iat_slot) const;

    // ---- Shadow stack ----
    void pushCall(uint64_t return_guest);
    std::optional<uint64_t> popCall();

    // ---- Syscall / import exits ----
    void requestSyscallExit(uint64_t guest_pc, uint64_t syscall_nr);
    void setSyscallPending(bool v) { syscall_pending_ = v; }
    void clearSyscall() { syscall_pending_ = false; pending_nr_ = 0; }
    bool syscallPending() const { return syscall_pending_; }
    uint64_t pendingSyscall() const { return pending_nr_; }
    void requestImportExit(uint64_t addr);
    void clearImport() { import_pending_ = false; pending_import_ = 0; }
    bool importPending() const { return import_pending_; }
    uint64_t pendingImport() const { return pending_import_; }

    // Counters for J3.4 exit criteria
    uint64_t trampolineCrossings() const { return trampoline_crossings_.load(); }
    uint64_t traceHits() const { return trace_hits_.load(); }
    uint64_t icHits() const { return ic_hits_.load(); }
    void noteTrampoline() { trampoline_crossings_.fetch_add(1, std::memory_order_relaxed); }
    void noteTraceHit() { trace_hits_.fetch_add(1, std::memory_order_relaxed); }
    void noteIcHit() { ic_hits_.fetch_add(1, std::memory_order_relaxed); }
    void resetCounters() {
        trampoline_crossings_ = 0;
        trace_hits_ = 0;
        ic_hits_ = 0;
    }

private:
    static uint64_t edgeKey(uint64_t from, uint64_t to) {
        return (from * 1315423911ull) ^ (to + 0x9e3779b97f4a7c15ull);
    }

    mutable std::mutex mu_;
    std::unordered_map<uint64_t, uint64_t> cache_;
    std::unordered_map<uint64_t, uint64_t> inline_cache_; // site -> last host
    std::unordered_map<uint64_t, uint64_t> edge_counts_;  // edgeKey -> count
    std::unordered_map<uint64_t, std::vector<uint64_t>> adj_;
    std::unordered_map<uint64_t, uint64_t> plt_;          // plt entry -> helper
    std::unordered_map<uint64_t, uint64_t> iat_;          // iat slot -> helper
    // IC: pack site+target -> host
    std::unordered_map<uint64_t, uint64_t> ic_;
    std::vector<uint64_t> shadow_stack_;
    bool syscall_pending_ = false;
    uint64_t pending_nr_ = 0;
    bool import_pending_ = false;
    uint64_t pending_import_ = 0;
    std::atomic<bool> reg_cache_active_{true};
    std::atomic<uint64_t> trampoline_crossings_{0};
    std::atomic<uint64_t> trace_hits_{0};
    std::atomic<uint64_t> ic_hits_{0};
};

} // namespace nexus
