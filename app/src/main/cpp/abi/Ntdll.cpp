#include "Ntdll.h"
#include "../diagnostics/Logger.h"
#include <cstring>

namespace nexus {

uint64_t Ntdll::rtlAllocateHeap(uint64_t, uint32_t flags, size_t size) {
    (void)flags;
    std::lock_guard<std::mutex> lock(heap_mu_);
    if (size == 0) size = 1;
    size_t aligned = (size + 15) & ~static_cast<size_t>(15);
    uint64_t p = heap_next_;
    heap_next_ += aligned;
    heap_[p] = aligned;
    if (!peb_.process_heap) peb_.process_heap = 0x20000000;
    if (!peb_.image_base) peb_.image_base = 0x140000000ULL;
    return p;
}

bool Ntdll::rtlFreeHeap(uint64_t, uint32_t, uint64_t ptr) {
    std::lock_guard<std::mutex> lock(heap_mu_);
    return heap_.erase(ptr) > 0;
}

void Ntdll::ldrAdd(const std::string& name, uint64_t base, uint32_t size) {
    for (auto& e : ldr_) {
        if (e.name == name) { e.base = base; e.size = size; return; }
    }
    ldr_.push_back({ name, base, size });
    Logger::instance().infof(LogCategory::ABI, "LDR + %s @ 0x%llx size=0x%x",
                             name.c_str(), (unsigned long long)base, size);
}

void Ntdll::rtlInitializeCriticalSection(uint64_t cs) {
    std::lock_guard<std::mutex> lock(heap_mu_);
    if (locks_.count(cs)) return;
    locks_[cs] = new std::mutex();
}
void Ntdll::rtlEnterCriticalSection(uint64_t cs) {
    auto it = locks_.find(cs);
    if (it == locks_.end()) {
        rtlInitializeCriticalSection(cs);
        it = locks_.find(cs);
    }
    if (it != locks_.end()) it->second->lock();
}
void Ntdll::rtlLeaveCriticalSection(uint64_t cs) {
    auto it = locks_.find(cs);
    if (it != locks_.end()) it->second->unlock();
}
void Ntdll::rtlAcquireSRWLockExclusive(uint64_t lock) { rtlEnterCriticalSection(lock); }
void Ntdll::rtlReleaseSRWLockExclusive(uint64_t lock) { rtlLeaveCriticalSection(lock); }

} // namespace nexus
