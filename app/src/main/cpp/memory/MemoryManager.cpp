#include "MemoryManager.h"
#include "../diagnostics/Logger.h"

#include <android/log.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

#define LOGI(...) ::nexus::Logger::instance().infof(::nexus::LogCategory::MEMORY, __VA_ARGS__)
#define LOGE(...) ::nexus::Logger::instance().errorf(::nexus::LogCategory::MEMORY, __VA_ARGS__)

namespace nexus {

uint64_t MemoryManager::alignUp(uint64_t n) {
    return (n + kPageSize - 1) & ~(static_cast<uint64_t>(kPageSize) - 1);
}
size_t MemoryManager::alignUpSize(size_t n) {
    return (n + kPageSize - 1) & ~(kPageSize - 1);
}

MemoryManager::MemoryManager() = default;

MemoryManager::~MemoryManager() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [_, region] : regions_) {
        if (region.host_ptr) {
            munmap(region.host_ptr, region.host_size);
        }
    }
    regions_.clear();
}

int MemoryManager::permsToProt(PagePerm p) const {
    int prot = PROT_NONE;
    if (hasPerm(p, PagePerm::READ))  prot |= PROT_READ;
    if (hasPerm(p, PagePerm::WRITE)) prot |= PROT_WRITE;
    if (hasPerm(p, PagePerm::EXEC))  prot |= PROT_EXEC;
    return prot;
}

void* MemoryManager::mapHost(size_t size, PagePerm perms) {
    size = alignUpSize(size);
    int prot = permsToProt(perms);

    // On Android, anonymous executable mappings are allowed for JIT
    // (subject to the usual SELinux / seccomp constraints of the app process).
    void* ptr = mmap(nullptr, size, prot,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        LOGE("mmap failed: %s (size=%zu prot=0x%x)", strerror(errno), size, prot);
        return nullptr;
    }
    return ptr;
}

bool MemoryManager::unmapHost(void* ptr, size_t size) {
    if (!ptr) return false;
    if (munmap(ptr, alignUpSize(size)) != 0) {
        LOGE("munmap failed: %s", strerror(errno));
        return false;
    }
    return true;
}

bool MemoryManager::rangesOverlap(uint64_t a1, uint64_t a2, uint64_t b1, uint64_t b2) const {
    return a1 < b2 && b1 < a2;
}

bool MemoryManager::hasOverlap(uint64_t start, uint64_t end) const {
    for (const auto& [_, r] : regions_) {
        if (rangesOverlap(start, end, r.guest_start, r.guest_end)) return true;
    }
    return false;
}

uint64_t MemoryManager::findFreeRange(size_t size) const {
    uint64_t candidate = alignUp(next_hint_);
    const uint64_t kUserLimit = 0x00007FFFFFFFFFFFULL;

    // Simple linear scan; adequate for the number of regions we expect.
    for (int i = 0; i < 4096; ++i) {
        if (candidate + size >= kUserLimit) return 0;
        if (!hasOverlap(candidate, candidate + size)) {
            return candidate;
        }
        // Jump past the conflicting region
        auto it = regions_.lower_bound(candidate);
        if (it != regions_.end() && rangesOverlap(candidate, candidate + size,
                                                  it->second.guest_start, it->second.guest_end)) {
            candidate = alignUp(it->second.guest_end);
        } else {
            candidate += kPageSize;
        }
    }
    return 0;
}

uint64_t MemoryManager::allocate(uint64_t guest_addr, size_t size, PagePerm perms, const std::string& tag) {
    if (size == 0) return 0;
    size = alignUpSize(size);

    std::lock_guard<std::mutex> lock(mutex_);

    if (guest_addr == 0) {
        guest_addr = findFreeRange(size);
        if (guest_addr == 0) {
            LOGE("allocate: no free guest VA for %zu bytes", size);
            return 0;
        }
    } else {
        guest_addr = alignUp(guest_addr);
        if (hasOverlap(guest_addr, guest_addr + size)) {
            LOGE("allocate: guest range 0x%llx-0x%llx overlaps",
                 (unsigned long long)guest_addr,
                 (unsigned long long)(guest_addr + size));
            return 0;
        }
    }

    void* host = mapHost(size, perms);
    if (!host) return 0;

    MemoryRegion region;
    region.guest_start = guest_addr;
    region.guest_end   = guest_addr + size;
    region.host_ptr    = host;
    region.host_size   = size;
    region.perms       = perms;
    region.is_guard    = (perms == PagePerm::NONE);
    region.tag         = tag;

    regions_.emplace(guest_addr, std::move(region));
    next_hint_ = guest_addr + size;

    LOGI("allocate guest=0x%llx-0x%llx host=%p perms=%d tag=%s",
         (unsigned long long)guest_addr,
         (unsigned long long)(guest_addr + size),
         host, static_cast<int>(perms), tag.c_str());

    return guest_addr;
}

bool MemoryManager::protectRange(uint64_t guest_addr, size_t size, PagePerm new_perms) {
    if (size == 0) return true;
    size = alignUpSize(size);
    guest_addr = alignUp(guest_addr); // callers should already be page-aligned; we enforce it

    std::lock_guard<std::mutex> lock(mutex_);

    // Find containing region
    auto it = regions_.upper_bound(guest_addr);
    if (it == regions_.begin()) return false;
    --it;

    auto& region = it->second;
    if (guest_addr < region.guest_start || guest_addr + size > region.guest_end) {
        LOGE("protectRange: range not fully inside a region");
        return false;
    }

    // If the range is the whole region, just protect it
    if (guest_addr == region.guest_start && size == region.host_size) {
        int prot = permsToProt(new_perms);
        if (mprotect(region.host_ptr, region.host_size, prot) != 0) {
            LOGE("mprotect failed: %s", strerror(errno));
            return false;
        }
        region.perms = new_perms;
        region.is_guard = (new_perms == PagePerm::NONE);
        return true;
    }

    // Split: we need to mprotect the sub-range and track it as its own region.
    // For simplicity and correctness we mprotect the host sub-range and insert a new region entry,
    // adjusting the original. This is sufficient for RELRO.
    size_t offset = static_cast<size_t>(guest_addr - region.guest_start);
    void* sub_host = static_cast<char*>(region.host_ptr) + offset;

    int prot = permsToProt(new_perms);
    if (mprotect(sub_host, size, prot) != 0) {
        LOGE("mprotect (sub-range) failed: %s", strerror(errno));
        return false;
    }

    // Shrink original region to the part before the sub-range (if any)
    // and create a new region for the protected range. Trailing part becomes another region.
    MemoryRegion before = region;
    MemoryRegion mid = region;
    MemoryRegion after = region;

    bool has_before = (guest_addr > region.guest_start);
    bool has_after  = (guest_addr + size < region.guest_end);

    regions_.erase(it);

    if (has_before) {
        before.guest_end = guest_addr;
        before.host_size = static_cast<size_t>(before.guest_end - before.guest_start);
        regions_.emplace(before.guest_start, before);
    }
    mid.guest_start = guest_addr;
    mid.guest_end   = guest_addr + size;
    mid.host_ptr    = sub_host;
    mid.host_size   = size;
    mid.perms       = new_perms;
    mid.is_guard    = (new_perms == PagePerm::NONE);
    mid.tag        += ".relro";
    regions_.emplace(mid.guest_start, mid);

    if (has_after) {
        after.guest_start = guest_addr + size;
        after.host_ptr    = static_cast<char*>(sub_host) + size;
        after.host_size   = static_cast<size_t>(after.guest_end - after.guest_start);
        regions_.emplace(after.guest_start, after);
    }

    LOGI("protectRange guest=0x%llx size=%zu perms=%d", (unsigned long long)guest_addr, size, static_cast<int>(new_perms));
    return true;
}

bool MemoryManager::protect(uint64_t guest_addr, PagePerm new_perms) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = regions_.find(guest_addr);
    if (it == regions_.end()) {
        LOGE("protect: no region at 0x%llx", (unsigned long long)guest_addr);
        return false;
    }

    auto& region = it->second;
    int prot = permsToProt(new_perms);
    if (mprotect(region.host_ptr, region.host_size, prot) != 0) {
        LOGE("mprotect failed: %s", strerror(errno));
        return false;
    }

    region.perms    = new_perms;
    region.is_guard = (new_perms == PagePerm::NONE);
    LOGI("protect guest=0x%llx perms=%d", (unsigned long long)guest_addr, static_cast<int>(new_perms));
    return true;
}

bool MemoryManager::free(uint64_t guest_addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = regions_.find(guest_addr);
    if (it == regions_.end()) return false;

    unmapHost(it->second.host_ptr, it->second.host_size);
    regions_.erase(it);
    LOGI("free guest=0x%llx", (unsigned long long)guest_addr);
    return true;
}

void* MemoryManager::guestToHost(uint64_t guest_addr) const {
    std::lock_guard<std::mutex> lock(mutex_);
    // Find the region that contains guest_addr
    auto it = regions_.upper_bound(guest_addr);
    if (it == regions_.begin()) return nullptr;
    --it;

    const auto& region = it->second;
    if (guest_addr < region.guest_start || guest_addr >= region.guest_end) return nullptr;
    if (region.is_guard || region.perms == PagePerm::NONE) return nullptr;

    size_t offset = static_cast<size_t>(guest_addr - region.guest_start);
    return static_cast<char*>(region.host_ptr) + offset;
}

bool MemoryManager::isRangeAccessible(uint64_t guest_addr, size_t size, PagePerm required) const {
    if (size == 0) return true;
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t end = guest_addr + size;
    uint64_t cursor = guest_addr;

    while (cursor < end) {
        auto it = regions_.upper_bound(cursor);
        if (it == regions_.begin()) return false;
        --it;

        const auto& region = it->second;
        if (cursor < region.guest_start || cursor >= region.guest_end) return false;
        if ((region.perms & required) != required) return false;

        cursor = region.guest_end;
    }
    return true;
}

std::optional<MemoryRegion> MemoryManager::query(uint64_t guest_addr) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = regions_.upper_bound(guest_addr);
    if (it == regions_.begin()) return std::nullopt;
    --it;
    if (guest_addr >= it->second.guest_start && guest_addr < it->second.guest_end) {
        return it->second;
    }
    return std::nullopt;
}

uint64_t MemoryManager::allocateWithGuards(size_t usable_size, PagePerm perms, const std::string& tag) {
    usable_size = alignUpSize(usable_size);
    if (usable_size == 0) return 0;

    // Three distinct regions: guard | usable | guard
    uint64_t guard1 = allocate(0, kPageSize, PagePerm::NONE, tag + ".guard_lo");
    if (guard1 == 0) return 0;

    uint64_t usable = allocate(0, usable_size, perms, tag);
    if (usable == 0) {
        free(guard1);
        return 0;
    }

    uint64_t guard2 = allocate(0, kPageSize, PagePerm::NONE, tag + ".guard_hi");
    if (guard2 == 0) {
        free(usable);
        free(guard1);
        return 0;
    }

    LOGI("allocateWithGuards usable=0x%llx size=%zu", (unsigned long long)usable, usable_size);
    return usable;
}

size_t MemoryManager::regionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return regions_.size();
}

size_t MemoryManager::totalMappedBytes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t total = 0;
    for (const auto& [_, r] : regions_) total += r.host_size;
    return total;
}

std::vector<MemoryRegion> MemoryManager::listRegions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<MemoryRegion> out;
    out.reserve(regions_.size());
    for (const auto& [_, r] : regions_) out.push_back(r);
    return out;
}

} // namespace nexus
