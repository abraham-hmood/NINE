#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <mutex>
#include <vector>
#include <sstream>
#include <atomic>
#include <functional>

namespace nexus {

enum class LogLevel : uint8_t {
    TRACE = 0,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    FATAL
};

enum class LogCategory : uint8_t {
    GENERAL = 0,
    MEMORY,
    LOADER,
    LINKER,
    TRANSLATOR,
    ABI,
    FAULT,
    CACHE
};

struct GuestRegisterState {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rip;
    uint64_t rflags;
    // XMM/YMM can be added later
};

struct TranslationCacheStats {
    std::atomic<uint64_t> translations{0};
    std::atomic<uint64_t> cache_hits{0};
    std::atomic<uint64_t> cache_misses{0};
    std::atomic<uint64_t> invalidations{0};
    std::atomic<uint64_t> code_bytes{0};
};

class Logger {
public:
    static Logger& instance();

    void setMinLevel(LogLevel level);
    LogLevel minLevel() const;

    void log(LogLevel level, LogCategory cat, std::string_view msg);

    // Convenience
    void trace(LogCategory cat, std::string_view msg) { log(LogLevel::TRACE, cat, msg); }
    void debug(LogCategory cat, std::string_view msg) { log(LogLevel::DEBUG, cat, msg); }
    void info (LogCategory cat, std::string_view msg) { log(LogLevel::INFO,  cat, msg); }
    void warn (LogCategory cat, std::string_view msg) { log(LogLevel::WARN,  cat, msg); }
    void error(LogCategory cat, std::string_view msg) { log(LogLevel::ERROR, cat, msg); }
    void fatal(LogCategory cat, std::string_view msg) { log(LogLevel::FATAL, cat, msg); }

    // Formatted helpers
    void infof(LogCategory cat, const char* fmt, ...);
    void errorf(LogCategory cat, const char* fmt, ...);

    // Diagnostics
    void dumpGuestRegisters(const GuestRegisterState& regs, std::string_view reason = "");

    // Full hex dump of guest memory. Requires a valid host pointer (from MemoryManager::guestToHost).
    // If host_ptr is nullptr the call is a no-op with an error log.
    void dumpGuestMemory(const void* host_ptr, uint64_t guest_addr, size_t length, std::string_view reason = "");

    void dumpTranslationStats();

    TranslationCacheStats& cacheStats() { return cache_stats_; }
    const TranslationCacheStats& cacheStats() const { return cache_stats_; }

    // Optional: keep a ring buffer of recent messages for UI later
    std::vector<std::string> recentMessages(size_t max = 100) const;

    // Push every log line to UI / GuestLog (optional).
    using Sink = std::function<void(LogLevel, LogCategory, const std::string&)>;
    void setSink(Sink s);
    void clearSink();
    bool hasSink() const;

private:
    Logger();
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    mutable std::mutex mutex_;
    LogLevel min_level_ = LogLevel::INFO;
    std::vector<std::string> ring_;
    static constexpr size_t kRingCapacity = 512;
    TranslationCacheStats cache_stats_;
    Sink sink_;

    static const char* levelStr(LogLevel l);
    static const char* categoryStr(LogCategory c);
};

// Global convenience macros
#define NEXUS_LOG(level, cat, msg) \
    ::nexus::Logger::instance().log(::nexus::LogLevel::level, ::nexus::LogCategory::cat, msg)

#define NEXUS_INFO(cat, msg)  NEXUS_LOG(INFO,  cat, msg)
#define NEXUS_WARN(cat, msg)  NEXUS_LOG(WARN,  cat, msg)
#define NEXUS_ERROR(cat, msg) NEXUS_LOG(ERROR, cat, msg)

} // namespace nexus
