#pragma once

#include "../translator/CodeCache.h"
#include "../translator/Translator.h"
#include "../translator/ControlFlow.h"
#include "../abi/SyscallTranslator.h"
#include "../abi/Seh.h"
#include "../memory/MemoryManager.h"
#include "GuestContext.h"
#include "SmcCoherency.h"
#include "InsnInterpreter.h"
#include <cstdint>
#include <functional>
#include <atomic>

namespace nexus {

enum class ExitReason {
    NONE,
    SYSCALL,
    IMPORT,
    EXCEPTION,
    HALT,
    YIELD,
    THREAD_EXIT
};

struct ExecResult {
    ExitReason reason = ExitReason::NONE;
    uint64_t guest_pc = 0;
    int64_t syscall_nr = -1;
    int64_t syscall_ret = 0;
    uint64_t import_addr = 0;
};

struct ExecCounters {
    std::atomic<uint64_t> blocks_executed{0};
    std::atomic<uint64_t> insns_executed{0};
    std::atomic<uint64_t> cache_hits{0};
    std::atomic<uint64_t> cache_misses{0};
    std::atomic<uint64_t> translations{0};
    std::atomic<uint64_t> smc_invalidations{0};
    std::atomic<uint64_t> syscalls{0};
    std::atomic<uint64_t> exceptions{0};
    std::atomic<uint64_t> jit_invokes{0};
    std::atomic<uint64_t> interp_fallbacks{0};
};

// J1.3 Execution loop:
//   lookup(pc) → if host_code: trampoline → handle exit_reason
//              → else: translate, then trampoline or interpret
class ExecutionLoop {
public:
    ExecutionLoop(CodeCache& cache, Translator& tr, SyscallTranslator& sys,
                  SehDispatcher& seh, MemoryManager* mm = nullptr,
                  SmcCoherency* smc = nullptr)
        : cache_(cache), tr_(tr), sys_(sys), seh_(seh), mm_(mm), smc_(smc),
          interp_(mm, smc) {}

    ExecResult run(uint64_t entry, const uint8_t* guest_code, size_t len,
                   uint64_t max_steps = 1000000);

    ExecResult resume(GuestContext& ctx, const uint8_t* guest_code, size_t len,
                      uint64_t max_steps = 1000000);

    void setImportHandler(std::function<uint64_t(uint64_t)> h) { import_ = std::move(h); }
    void setOnSyscall(std::function<int64_t(int64_t, GuestContext&)> h) {
        on_syscall_ = std::move(h);
    }

    // When true, fill CodeCache on miss.
    void setTranslate(bool v) { do_translate_ = v; }
    // When true, never use interpreter (J1.4 pure-JIT test path).
    void setJitOnly(bool v) { jit_only_ = v; }
    // When true, handle SYSCALL inside the loop and continue (resume into JIT).
    // When false, return ExitReason::SYSCALL to the caller.
    void setInlineSyscalls(bool v) { inline_syscalls_ = v; }

    ExecCounters& counters() { return counters_; }
    const ExecCounters& counters() const { return counters_; }

    void requestStop() { stop_.store(true, std::memory_order_release); }
    bool stopRequested() const { return stop_.load(std::memory_order_acquire); }

    InsnInterpreter& interpreter() { return interp_; }
    ControlFlow& controlFlow() { return cf_; }
    const ControlFlow& controlFlow() const { return cf_; }

private:
    CodeCache& cache_;
    Translator& tr_;
    SyscallTranslator& sys_;
    SehDispatcher& seh_;
    MemoryManager* mm_ = nullptr;
    SmcCoherency* smc_ = nullptr;
    InsnInterpreter interp_;
    ControlFlow cf_;
    std::function<uint64_t(uint64_t)> import_;
    std::function<int64_t(int64_t, GuestContext&)> on_syscall_;
    ExecCounters counters_;
    std::atomic<bool> stop_{false};
    bool do_translate_ = true;
    bool jit_only_ = false;
    bool inline_syscalls_ = true;

    uint64_t hashRange(const uint8_t* p, size_t n) const;
    const uint8_t* resolveGuestBytes(uint64_t pc, size_t& out_len,
                                     const uint8_t* fallback, size_t fallback_len,
                                     uint64_t fallback_base) const;
    void ensureTranslated(uint64_t pc, const uint8_t* bytes, size_t avail);
    int64_t handleSyscall(GuestContext& ctx, int64_t nr);
};

} // namespace nexus
