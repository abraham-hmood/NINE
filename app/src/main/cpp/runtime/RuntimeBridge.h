#pragma once

#include <cstdint>
#include <string>
#include <atomic>
#include <mutex>
#include <vector>
#include <functional>

namespace nexus {

struct RuntimeStatus {
    std::atomic<bool> running{false};
    std::atomic<bool> pause_requested{false};
    std::atomic<bool> step_one{false};
    std::atomic<uint64_t> blocks{0};
    std::atomic<uint64_t> hits{0};
    std::atomic<uint64_t> misses{0};
    std::atomic<uint64_t> translations{0};
    std::atomic<uint64_t> syscalls{0};
    std::atomic<uint64_t> smc{0};
    std::atomic<uint64_t> guest_rip{0};
    std::string last_message;
    std::mutex msg_mu;
};

// J5: UI-driven load + background execution of ELF/PE.
class RuntimeBridge {
public:
    static RuntimeBridge& instance();

    // Detect ELF/PE, map, prepare context, start on background thread.
    // path is a host filesystem path readable by the process.
    std::string loadAndRun(const std::string& path, const std::string& cache_dir);

    // Pre-link a library program against NINE's ABI without executing it.
    // ELF: DT_NEEDED resolved via SearchPaths (lib_dirs: origin: system) into
    // bundled modules; anything absent is reported as served by NINE's Linux
    // syscall ABI. PE: IAT resolved against NINE's ntdll/kernel32/… shims.
    // Returns a one-line summary (also pushed to the log sink).
    std::string relink(const std::string& path, const std::string& lib_dirs);

    void requestStop();
    void requestPause();
    void requestResume();
    void requestStep(); // single-step via interpreter after pause
    void setBreakpoint(uint64_t guest_pc);
    void clearBreakpoints();

    RuntimeStatus& status() { return status_; }
    std::string statusSnapshot();

    // Called from Logger to push lines to Java GuestLog
    using LogSink = std::function<void(const std::string&)>;
    void setLogSink(LogSink s);

private:
    RuntimeBridge() = default;
    RuntimeStatus status_;
    std::mutex run_mu_;
    std::atomic<bool> stop_{false};
    std::vector<uint64_t> breakpoints_;
    std::mutex bp_mu_;
    LogSink log_sink_;
    std::mutex sink_mu_;

    void emitLog(const std::string& s);
    std::string runElf(const std::vector<uint8_t>& bytes, const std::string& cache_dir);
    std::string runPe(const std::vector<uint8_t>& bytes, const std::string& cache_dir);
    std::string runRawCode(const uint8_t* code, size_t len, uint64_t entry,
                           const std::string& cache_dir);
    std::string relinkElf(const std::string& path, const std::vector<uint8_t>& bytes,
                          const std::string& lib_dirs);
    std::string relinkPe(const std::string& path, const std::vector<uint8_t>& bytes);
};

} // namespace nexus
