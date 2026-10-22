#include "SmcCoherency.h"
#include "../diagnostics/Logger.h"

namespace nexus {

void SmcCoherency::markExecutable(uint64_t start, uint64_t end) {
    std::lock_guard<std::mutex> lock(mu_);
    for (uint64_t p = start & ~0xFFFULL; p < end; p += 0x1000) {
        exec_pages_.insert(p);
    }
}

void SmcCoherency::unmarkExecutable(uint64_t start, uint64_t end) {
    std::lock_guard<std::mutex> lock(mu_);
    for (uint64_t p = start & ~0xFFFULL; p < end; p += 0x1000) {
        exec_pages_.erase(p);
    }
}

void SmcCoherency::onStore(uint64_t addr, size_t size) {
    if (size == 0) return;
    uint64_t page = addr & ~0xFFFULL;
    uint64_t last = (addr + size - 1) & ~0xFFFULL;
    bool hit = false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (uint64_t p = page; p <= last; p += 0x1000) {
            if (exec_pages_.count(p)) {
                hit = true;
                break;
            }
        }
    }
    if (!hit) return;

    for (uint64_t p = page; p <= last; p += 0x1000) {
        std::lock_guard<std::mutex> lock(mu_);
        if (exec_pages_.count(p)) {
            cache_.invalidateRange(p, p + 0x1000);
            invalidations_.fetch_add(1, std::memory_order_relaxed);
            Logger::instance().infof(LogCategory::TRANSLATOR,
                                     "SMC invalidate page 0x%llx",
                                     (unsigned long long)p);
        }
    }
}

void SmcCoherency::invalidateAll() {
    std::lock_guard<std::mutex> lock(mu_);
    for (uint64_t p : exec_pages_) {
        cache_.invalidateRange(p, p + 0x1000);
        invalidations_.fetch_add(1, std::memory_order_relaxed);
    }
}

} // namespace nexus
