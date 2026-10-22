#pragma once

#include "../translator/CodeCache.h"
#include "../memory/MemoryManager.h"
#include <cstdint>
#include <unordered_set>
#include <mutex>
#include <atomic>

namespace nexus {

// 9.3 Detect writes to executable pages and invalidate affected translations.
// Thread-safe; safe to call from any guest-thread store path.
class SmcCoherency {
public:
    explicit SmcCoherency(CodeCache& cache, MemoryManager& mm)
        : cache_(cache), mm_(mm) {}

    // Call on every guest store. If the target page is executable, invalidate.
    void onStore(uint64_t addr, size_t size);

    // Mark a guest range as executable (after mapping a code section).
    void markExecutable(uint64_t start, uint64_t end);

    // Unmark (e.g. after mprotect to non-exec).
    void unmarkExecutable(uint64_t start, uint64_t end);

    // Force invalidate everything (e.g. after large remap).
    void invalidateAll();

    size_t invalidations() const {
        return invalidations_.load(std::memory_order_relaxed);
    }

    size_t executablePages() const {
        std::lock_guard<std::mutex> lock(mu_);
        return exec_pages_.size();
    }

private:
    CodeCache& cache_;
    MemoryManager& mm_;
    mutable std::mutex mu_;
    std::unordered_set<uint64_t> exec_pages_;
    std::atomic<size_t> invalidations_{0};
};

} // namespace nexus
