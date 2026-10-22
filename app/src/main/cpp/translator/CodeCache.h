#pragma once

#include <cstdint>
#include <cstddef>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <optional>
#include <string>
#include <atomic>

namespace nexus {

struct CacheEntry {
    uint64_t guest_pc = 0;
    uint64_t guest_end = 0;
    void* host_code = nullptr;
    size_t host_size = 0;
    uint64_t guest_hash = 0;
};

// J4: shared thread-safe code cache with W^X, concurrent install, and
// image-keyed persistent storage.
class CodeCache {
public:
    static constexpr uint32_t kTranslatorVersion = 4; // bump when emitter ABI changes

    explicit CodeCache(size_t initial_bytes = 1 << 20);
    ~CodeCache();

    bool grow(size_t min_additional);
    std::optional<CacheEntry> lookup(uint64_t guest_pc) const;

    // Thread-safe install: holds lock through copy + clear_cache + map insert.
    bool install(uint64_t guest_pc, uint64_t guest_end, const uint32_t* code,
                 size_t n_insns, uint64_t guest_hash);

    void invalidate(uint64_t guest_pc);
    void invalidateRange(uint64_t start, uint64_t end);
    bool isStale(uint64_t guest_pc, uint64_t current_hash) const;

    size_t size() const;
    size_t capacity() const { return capacity_; }
    size_t usedBytes() const;

    uint64_t installCount() const { return installs_.load(std::memory_order_relaxed); }
    uint64_t invalidateCount() const { return invalidates_.load(std::memory_order_relaxed); }
    uint64_t concurrentInstalls() const { return concurrent_installs_.load(std::memory_order_relaxed); }

    // J4.1: persistent cache keyed by image identity + content + translator version
    void setImageKey(uint64_t image_id, uint64_t image_content_hash);
    uint64_t imageId() const { return image_id_; }
    uint64_t imageContentHash() const { return image_content_hash_; }

    bool saveToFile(const std::string& path) const;
    bool loadFromFile(const std::string& path);
    // Preferred: derive path from image key under app-private dir
    static std::string defaultCachePath(const std::string& dir, uint64_t image_id, uint64_t content_hash);

    void seal();
    void unseal();

private:
    uint8_t* region_ = nullptr;
    size_t capacity_ = 0;
    size_t used_ = 0;
    mutable std::mutex mu_;
    std::unordered_map<uint64_t, CacheEntry> by_pc_;
    std::atomic<uint64_t> installs_{0};
    std::atomic<uint64_t> invalidates_{0};
    std::atomic<uint64_t> concurrent_installs_{0};
    bool sealed_ = false;
    uint64_t image_id_ = 0;
    uint64_t image_content_hash_ = 0;

    bool mapRegion(size_t bytes);
    bool setProt(int prot);
    bool growLocked(size_t min_additional); // caller holds mu_
};

} // namespace nexus
