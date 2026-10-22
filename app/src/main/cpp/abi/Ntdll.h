#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>

namespace nexus {

// Minimal PEB / TEB for a user-mode Windows guest.
struct UnicodeString { uint16_t length; uint16_t max; uint64_t buffer; };
struct ListEntry { uint64_t flink; uint64_t blink; };

struct Peb {
    uint8_t inherited = 0;
    uint8_t being_debugged = 0;
    uint64_t image_base = 0;
    uint64_t ldr = 0;          // PEB_LDR_DATA
    uint64_t process_heap = 0;
    uint32_t os_major = 10;
    uint32_t os_minor = 0;
};

struct Teb {
    uint64_t self = 0;
    uint64_t peb = 0;
    uint32_t tid = 0;
    uint32_t pid = 0;
    uint64_t stack_base = 0;
    uint64_t stack_limit = 0;
    uint32_t last_error = 0;
};

struct LdrEntry {
    std::string name;
    uint64_t base = 0;
    uint32_t size = 0;
};

class Ntdll {
public:
    Peb& peb() { return peb_; }
    Teb& teb() { return teb_; }

    // Heap
    uint64_t rtlAllocateHeap(uint64_t heap, uint32_t flags, size_t size);
    bool rtlFreeHeap(uint64_t heap, uint32_t flags, uint64_t ptr);

    // Loader data table
    void ldrAdd(const std::string& name, uint64_t base, uint32_t size);
    const std::vector<LdrEntry>& ldr() const { return ldr_; }

    // Critical section / SRW (simple)
    void rtlInitializeCriticalSection(uint64_t cs);
    void rtlEnterCriticalSection(uint64_t cs);
    void rtlLeaveCriticalSection(uint64_t cs);
    void rtlAcquireSRWLockExclusive(uint64_t lock);
    void rtlReleaseSRWLockExclusive(uint64_t lock);

private:
    Peb peb_;
    Teb teb_;
    std::vector<LdrEntry> ldr_;
    std::mutex heap_mu_;
    uint64_t heap_next_ = 0x20000000;
    std::unordered_map<uint64_t, size_t> heap_;
    std::unordered_map<uint64_t, std::mutex*> locks_;
};

} // namespace nexus
