#pragma once

#include <cstdint>
#include <cstddef>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <optional>
#include <algorithm>

namespace nexus {

enum class PagePerm : uint8_t {
    NONE  = 0,
    READ  = 1 << 0,
    WRITE = 1 << 1,
    EXEC  = 1 << 2,
    READ_WRITE      = READ | WRITE,
    READ_EXEC       = READ | EXEC,
    READ_WRITE_EXEC = READ | WRITE | EXEC
};

inline PagePerm operator|(PagePerm a, PagePerm b) {
    return static_cast<PagePerm>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
}
inline PagePerm operator&(PagePerm a, PagePerm b) {
    return static_cast<PagePerm>(static_cast<uint8_t>(a) & static_cast<uint8_t>(b));
}
inline bool hasPerm(PagePerm p, PagePerm flag) {
    return (static_cast<uint8_t>(p) & static_cast<uint8_t>(flag)) != 0;
}

struct MemoryRegion {
    uint64_t guest_start = 0;
    uint64_t guest_end   = 0;   // exclusive
    void*    host_ptr    = nullptr;
    size_t   host_size   = 0;
    PagePerm perms       = PagePerm::NONE;
    bool     is_guard    = false;
    std::string tag;
};

class MemoryManager {
public:
    static constexpr size_t kPageSize = 4096;

    MemoryManager();
    ~MemoryManager();

    // Allocate. guest_addr == 0 → any-fit. Returns guest base or 0 on failure.
    // size is rounded up to page size.
    uint64_t allocate(uint64_t guest_addr, size_t size, PagePerm perms, const std::string& tag = "");

    // Change permissions of an exact existing region.
    bool protect(uint64_t guest_addr, PagePerm new_perms);

    // Change permissions of a sub-range inside an existing region.
    // Splits the region if necessary so only [guest_addr, guest_addr+size) is affected.
    bool protectRange(uint64_t guest_addr, size_t size, PagePerm new_perms);

    // Free an exact existing region (by its start address).
    bool free(uint64_t guest_addr);

    // Translate guest address → host pointer. Returns nullptr if unmapped or no access.
    void* guestToHost(uint64_t guest_addr) const;

    // True if the range [guest_addr, guest_addr+size) is fully mapped with at least the given perms.
    bool isRangeAccessible(uint64_t guest_addr, size_t size, PagePerm required) const;

    std::optional<MemoryRegion> query(uint64_t guest_addr) const;

    // Allocate usable region with inaccessible guard pages on both sides.
    // Returns the usable (middle) guest address.
    uint64_t allocateWithGuards(size_t usable_size, PagePerm perms, const std::string& tag = "");

    size_t regionCount() const;
    size_t totalMappedBytes() const;
    std::vector<MemoryRegion> listRegions() const;

private:
    mutable std::mutex mutex_;
    std::map<uint64_t, MemoryRegion> regions_;   // keyed by guest_start
    uint64_t next_hint_ = 0x10000000ULL;

    void* mapHost(size_t size, PagePerm perms);
    bool  unmapHost(void* ptr, size_t size);
    int   permsToProt(PagePerm p) const;

    static uint64_t alignUp(uint64_t n);
    static size_t   alignUpSize(size_t n);

    bool rangesOverlap(uint64_t a1, uint64_t a2, uint64_t b1, uint64_t b2) const;
    uint64_t findFreeRange(size_t size) const;
    bool hasOverlap(uint64_t start, uint64_t end) const;
};

} // namespace nexus
