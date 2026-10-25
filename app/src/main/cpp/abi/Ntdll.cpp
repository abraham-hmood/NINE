#include "Ntdll.h"
#include "../diagnostics/Logger.h"
#include "../memory/MemoryManager.h"
#include <cstring>

namespace nexus {

uint64_t Ntdll::rtlAllocateHeap(uint64_t, uint32_t flags, size_t size) {
    (void)flags;
    std::lock_guard<std::mutex> lock(heap_mu_);
    if (size == 0) size = 1;
    if (!peb_.process_heap) peb_.process_heap = 0x20000000;
    if (!peb_.image_base) peb_.image_base = 0x140000000ULL;

    if (mm_) {
        // Heap blocks come from the same guest address space as everything
        // else, so a guest pointer and a host pointer stay distinct.
        const size_t aligned = (size + 15) & ~static_cast<size_t>(15);
        uint64_t p = mm_->allocate(0, aligned, PagePerm::READ_WRITE, "RtlAllocateHeap");
        if (!p) return 0;
        heap_[p] = aligned;
        return p;
    }
    const size_t aligned = (size + 15) & ~static_cast<size_t>(15);
    uint64_t p = heap_next_;
    heap_next_ += aligned;
    heap_[p] = aligned;
    return p;
}

bool Ntdll::rtlFreeHeap(uint64_t, uint32_t, uint64_t ptr) {
    std::lock_guard<std::mutex> lock(heap_mu_);
    auto it = heap_.find(ptr);
    if (it == heap_.end()) return false;
    heap_.erase(it);
    if (mm_) return mm_->free(ptr);
    return true;
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
    std::mutex* m = nullptr;
    {
        std::lock_guard<std::mutex> lock(heap_mu_);
        auto it = locks_.find(cs);
        if (it == locks_.end()) {
            m = new std::mutex();
            locks_[cs] = m;
        } else {
            m = it->second;
        }
    }
    m->lock();
}

void Ntdll::rtlLeaveCriticalSection(uint64_t cs) {
    std::mutex* m = nullptr;
    {
        std::lock_guard<std::mutex> lock(heap_mu_);
        auto it = locks_.find(cs);
        if (it != locks_.end()) m = it->second;
    }
    if (m) m->unlock();
}

void Ntdll::rtlAcquireSRWLockExclusive(uint64_t lock) { rtlEnterCriticalSection(lock); }
void Ntdll::rtlReleaseSRWLockExclusive(uint64_t lock) { rtlLeaveCriticalSection(lock); }

void Ntdll::publishTeb(uint64_t fs_base) {
    if (!mm_ || !fs_base) return;
    teb_.self = fs_base;
    if (!peb_.process_heap) peb_.process_heap = 0x20000000;
    void* host = mm_->guestToHost(fs_base);
    if (!host) return;
    auto* p = static_cast<uint8_t*>(host);
    // The offsets a Windows x64 TEB is actually read at.
    auto wr64 = [&](size_t off, uint64_t v) {
        if (off + 8 <= 0x1000) std::memcpy(p + off, &v, 8);
    };
    auto wr32 = [&](size_t off, uint32_t v) {
        if (off + 4 <= 0x1000) std::memcpy(p + off, &v, 4);
    };
    wr64(0x00, fs_base);            // NT_TIB.Self
    wr64(0x08, teb_.stack_base);    // NT_TIB.StackBase
    wr64(0x10, teb_.stack_limit);   // NT_TIB.StackLimit
    wr64(0x30, fs_base);            // TEB.Self
    wr32(0x40, teb_.pid);           // ClientId.UniqueProcess
    wr32(0x48, teb_.tid);           // ClientId.UniqueThread
    wr64(0x58, 0);                  // ThreadLocalStoragePointer
    wr64(0x60, teb_.peb);           // ProcessEnvironmentBlock
    wr32(0x68, teb_.last_error);    // LastErrorValue
}

} // namespace nexus
