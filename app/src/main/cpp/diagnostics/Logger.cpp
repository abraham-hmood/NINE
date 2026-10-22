#include "Logger.h"

#include <android/log.h>
#include <cstdarg>
#include <cstdio>
#include <chrono>
#include <iomanip>
#include <algorithm>

#define LOG_TAG "NINE"

namespace nexus {

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

Logger::Logger() {
    ring_.reserve(kRingCapacity);
}

void Logger::setMinLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    min_level_ = level;
}

LogLevel Logger::minLevel() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return min_level_;
}

const char* Logger::levelStr(LogLevel l) {
    switch (l) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
    }
    return "?";
}

const char* Logger::categoryStr(LogCategory c) {
    switch (c) {
        case LogCategory::GENERAL:    return "GEN";
        case LogCategory::MEMORY:     return "MEM";
        case LogCategory::LOADER:     return "LDR";
        case LogCategory::LINKER:     return "LNK";
        case LogCategory::TRANSLATOR: return "DBT";
        case LogCategory::ABI:        return "ABI";
        case LogCategory::FAULT:      return "FLT";
        case LogCategory::CACHE:      return "CCH";
    }
    return "?";
}

void Logger::log(LogLevel level, LogCategory cat, std::string_view msg) {
    if (level < min_level_) return;

    // Timestamp (simple)
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) % 1000;

    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << ms.count()
        << " [" << levelStr(level) << "/" << categoryStr(cat) << "] "
        << msg;

    std::string line = oss.str();

    // Android log
    int prio = ANDROID_LOG_INFO;
    switch (level) {
        case LogLevel::TRACE:
        case LogLevel::DEBUG: prio = ANDROID_LOG_DEBUG; break;
        case LogLevel::INFO:  prio = ANDROID_LOG_INFO;  break;
        case LogLevel::WARN:  prio = ANDROID_LOG_WARN;  break;
        case LogLevel::ERROR: prio = ANDROID_LOG_ERROR; break;
        case LogLevel::FATAL: prio = ANDROID_LOG_FATAL; break;
    }
    __android_log_print(prio, LOG_TAG, "%s", line.c_str());

    // Ring buffer + optional UI sink
    Sink sink_copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (ring_.size() >= kRingCapacity) {
            ring_.erase(ring_.begin());
        }
        ring_.push_back(line);
        sink_copy = sink_;
    }
    if (sink_copy) {
        try { sink_copy(level, cat, line); } catch (...) {}
    }
}

void Logger::setSink(Sink s) {
    std::lock_guard<std::mutex> lock(mutex_);
    sink_ = std::move(s);
}
void Logger::clearSink() {
    std::lock_guard<std::mutex> lock(mutex_);
    sink_ = nullptr;
}
bool Logger::hasSink() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<bool>(sink_);
}

void Logger::infof(LogCategory cat, const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log(LogLevel::INFO, cat, buf);
}

void Logger::errorf(LogCategory cat, const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log(LogLevel::ERROR, cat, buf);
}

void Logger::dumpGuestRegisters(const GuestRegisterState& r, std::string_view reason) {
    std::ostringstream oss;
    oss << "Guest register dump";
    if (!reason.empty()) oss << " (" << reason << ")";
    oss << "\n"
        << "  RAX=" << std::hex << r.rax << " RBX=" << r.rbx
        << " RCX=" << r.rcx << " RDX=" << r.rdx << "\n"
        << "  RSI=" << r.rsi << " RDI=" << r.rdi
        << " RBP=" << r.rbp << " RSP=" << r.rsp << "\n"
        << "  R8 =" << r.r8  << " R9 =" << r.r9
        << " R10=" << r.r10 << " R11=" << r.r11 << "\n"
        << "  R12=" << r.r12 << " R13=" << r.r13
        << " R14=" << r.r14 << " R15=" << r.r15 << "\n"
        << "  RIP=" << r.rip << " RFLAGS=" << r.rflags;

    error(LogCategory::FAULT, oss.str());
}

void Logger::dumpGuestMemory(const void* host_ptr, uint64_t guest_addr, size_t length, std::string_view reason) {
    if (!host_ptr || length == 0) {
        error(LogCategory::FAULT, "dumpGuestMemory: null host pointer or zero length");
        return;
    }

    // Cap dump size to avoid log spam
    constexpr size_t kMaxDump = 256;
    size_t to_dump = std::min(length, kMaxDump);

    std::ostringstream oss;
    oss << "Guest memory dump @ 0x" << std::hex << guest_addr
        << " (" << std::dec << to_dump << " bytes)";
    if (!reason.empty()) oss << " (" << reason << ")";
    oss << "\n";

    const auto* bytes = static_cast<const uint8_t*>(host_ptr);
    for (size_t i = 0; i < to_dump; i += 16) {
        oss << "  " << std::hex << std::setw(8) << std::setfill('0') << (guest_addr + i) << ": ";
        for (size_t j = 0; j < 16 && (i + j) < to_dump; ++j) {
            oss << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i + j]) << " ";
        }
        oss << "\n";
    }
    if (length > kMaxDump) {
        oss << "  ... (" << (length - kMaxDump) << " more bytes truncated)";
    }

    error(LogCategory::FAULT, oss.str());
}

void Logger::dumpTranslationStats() {
    auto& s = cache_stats_;
    std::ostringstream oss;
    oss << "Translation cache stats: "
        << "translations=" << s.translations.load()
        << " hits=" << s.cache_hits.load()
        << " misses=" << s.cache_misses.load()
        << " invalidations=" << s.invalidations.load()
        << " code_bytes=" << s.code_bytes.load();
    info(LogCategory::CACHE, oss.str());
}

std::vector<std::string> Logger::recentMessages(size_t max) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (ring_.size() <= max) return ring_;
    return std::vector<std::string>(ring_.end() - static_cast<std::ptrdiff_t>(max), ring_.end());
}

} // namespace nexus
