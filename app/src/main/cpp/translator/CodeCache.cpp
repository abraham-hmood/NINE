#include "CodeCache.h"
#include <sys/mman.h>
#include <cstring>
#include <cstdio>
#include <sstream>

namespace nexus {

CodeCache::CodeCache(size_t initial_bytes) {
    mapRegion(initial_bytes ? initial_bytes : (1 << 20));
}

CodeCache::~CodeCache() {
    if (region_) munmap(region_, capacity_);
}

bool CodeCache::mapRegion(size_t bytes) {
    uint8_t* p = static_cast<uint8_t*>(
        mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (p == MAP_FAILED) return false;
    region_ = p;
    capacity_ = bytes;
    used_ = 0;
    sealed_ = false;
    return true;
}

bool CodeCache::setProt(int prot) {
    if (!region_) return false;
    return mprotect(region_, capacity_, prot) == 0;
}

bool CodeCache::growLocked(size_t min_additional) {
    size_t need = used_ + min_additional;
    size_t next = capacity_ ? capacity_ * 2 : (1 << 20);
    while (next < need) next *= 2;
    uint8_t* fresh = static_cast<uint8_t*>(
        mmap(nullptr, next, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (fresh == MAP_FAILED) return false;
    if (region_ && used_) std::memcpy(fresh, region_, used_);
    // Relocate host_code pointers
    ptrdiff_t delta = fresh - region_;
    for (auto& [pc, e] : by_pc_) {
        if (e.host_code)
            e.host_code = static_cast<uint8_t*>(e.host_code) + delta;
    }
    if (region_) munmap(region_, capacity_);
    region_ = fresh;
    capacity_ = next;
    sealed_ = false;
    return true;
}

bool CodeCache::grow(size_t min_additional) {
    std::lock_guard<std::mutex> lock(mu_);
    return growLocked(min_additional);
}

std::optional<CacheEntry> CodeCache::lookup(uint64_t guest_pc) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = by_pc_.find(guest_pc);
    if (it == by_pc_.end()) return std::nullopt;
    return it->second;
}

bool CodeCache::install(uint64_t guest_pc, uint64_t guest_end,
                        const uint32_t* code, size_t n_insns, uint64_t guest_hash) {
    size_t bytes = n_insns * 4;
    std::lock_guard<std::mutex> lock(mu_);
    concurrent_installs_.fetch_add(1, std::memory_order_relaxed);

    // Another thread may have installed the same PC already
    auto existing = by_pc_.find(guest_pc);
    if (existing != by_pc_.end() && existing->second.guest_hash == guest_hash)
        return true;

    if (used_ + bytes > capacity_) {
        if (!growLocked(bytes)) return false;
    }

    bool was_sealed = sealed_;
    if (was_sealed) {
        if (!setProt(PROT_READ | PROT_WRITE)) return false;
        sealed_ = false;
    }

    void* dest = region_ + used_;
    std::memcpy(dest, code, bytes);
#if defined(__GNUC__) || defined(__clang__)
    __builtin___clear_cache(static_cast<char*>(dest),
                            static_cast<char*>(dest) + bytes);
#endif

    CacheEntry e{ guest_pc, guest_end, dest, bytes, guest_hash };
    by_pc_[guest_pc] = e;
    used_ += (bytes + 15) & ~size_t(15);
    installs_.fetch_add(1, std::memory_order_relaxed);

    if (was_sealed) {
        setProt(PROT_READ | PROT_EXEC);
        sealed_ = true;
    }
    return true;
}

void CodeCache::invalidate(uint64_t guest_pc) {
    std::lock_guard<std::mutex> lock(mu_);
    by_pc_.erase(guest_pc);
    invalidates_.fetch_add(1, std::memory_order_relaxed);
}

void CodeCache::invalidateRange(uint64_t start, uint64_t end) {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto it = by_pc_.begin(); it != by_pc_.end(); ) {
        if (it->second.guest_pc < end && start < it->second.guest_end) {
            it = by_pc_.erase(it);
            invalidates_.fetch_add(1, std::memory_order_relaxed);
        } else {
            ++it;
        }
    }
}

bool CodeCache::isStale(uint64_t guest_pc, uint64_t current_hash) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = by_pc_.find(guest_pc);
    if (it == by_pc_.end()) return false;
    return it->second.guest_hash != current_hash;
}

size_t CodeCache::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return by_pc_.size();
}

size_t CodeCache::usedBytes() const {
    std::lock_guard<std::mutex> lock(mu_);
    return used_;
}

void CodeCache::setImageKey(uint64_t image_id, uint64_t image_content_hash) {
    std::lock_guard<std::mutex> lock(mu_);
    image_id_ = image_id;
    image_content_hash_ = image_content_hash;
}

std::string CodeCache::defaultCachePath(const std::string& dir, uint64_t image_id,
                                        uint64_t content_hash) {
    std::ostringstream oss;
    oss << dir << "/nine_tc_" << std::hex << image_id << "_" << content_hash
        << "_v" << std::dec << kTranslatorVersion << ".bin";
    return oss.str();
}

void CodeCache::seal() {
    std::lock_guard<std::mutex> lock(mu_);
    if (region_ && !sealed_) {
        setProt(PROT_READ | PROT_EXEC);
        sealed_ = true;
    }
}

void CodeCache::unseal() {
    std::lock_guard<std::mutex> lock(mu_);
    if (region_ && sealed_) {
        setProt(PROT_READ | PROT_WRITE);
        sealed_ = false;
    }
}

// Format v2: magic, version(=2), translator_version, image_id, content_hash, count, entries...
bool CodeCache::saveToFile(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mu_);
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    const uint32_t magic = 0x4E494E45;
    const uint32_t version = 2;
    const uint32_t tv = kTranslatorVersion;
    uint32_t count = static_cast<uint32_t>(by_pc_.size());
    std::fwrite(&magic, 4, 1, f);
    std::fwrite(&version, 4, 1, f);
    std::fwrite(&tv, 4, 1, f);
    std::fwrite(&image_id_, 8, 1, f);
    std::fwrite(&image_content_hash_, 8, 1, f);
    std::fwrite(&count, 4, 1, f);
    for (auto& [pc, e] : by_pc_) {
        std::fwrite(&e.guest_pc, 8, 1, f);
        std::fwrite(&e.guest_end, 8, 1, f);
        std::fwrite(&e.guest_hash, 8, 1, f);
        uint32_t sz = static_cast<uint32_t>(e.host_size);
        std::fwrite(&sz, 4, 1, f);
        if (e.host_code && e.host_size)
            std::fwrite(e.host_code, 1, e.host_size, f);
    }
    std::fclose(f);
    return true;
}

bool CodeCache::loadFromFile(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    uint32_t magic = 0, version = 0, tv = 0, count = 0;
    if (std::fread(&magic, 4, 1, f) != 1 || magic != 0x4E494E45) {
        std::fclose(f); return false;
    }
    std::fread(&version, 4, 1, f);
    if (version == 2) {
        std::fread(&tv, 4, 1, f);
        if (tv != kTranslatorVersion) { std::fclose(f); return false; }
        std::fread(&image_id_, 8, 1, f);
        std::fread(&image_content_hash_, 8, 1, f);
    } else if (version != 1) {
        std::fclose(f); return false;
    }
    std::fread(&count, 4, 1, f);

    std::lock_guard<std::mutex> lock(mu_);
    by_pc_.clear();
    used_ = 0;
    for (uint32_t i = 0; i < count; ++i) {
        CacheEntry e;
        uint32_t sz = 0;
        std::fread(&e.guest_pc, 8, 1, f);
        std::fread(&e.guest_end, 8, 1, f);
        std::fread(&e.guest_hash, 8, 1, f);
        std::fread(&sz, 4, 1, f);
        if (used_ + sz > capacity_) {
            if (!growLocked(sz)) { std::fclose(f); return false; }
        }
        void* dest = region_ + used_;
        if (sz) std::fread(dest, 1, sz, f);
#if defined(__GNUC__) || defined(__clang__)
        __builtin___clear_cache(static_cast<char*>(dest),
                                static_cast<char*>(dest) + sz);
#endif
        e.host_code = dest;
        e.host_size = sz;
        by_pc_[e.guest_pc] = e;
        used_ += (sz + 15) & ~size_t(15);
    }
    std::fclose(f);
    setProt(PROT_READ | PROT_EXEC);
    sealed_ = true;
    return true;
}

} // namespace nexus
