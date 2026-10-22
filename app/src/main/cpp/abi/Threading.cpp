#include "Threading.h"
#include "../diagnostics/Logger.h"
#include <cerrno>
#include <chrono>

namespace nexus {

thread_local uint64_t GuestTls::fs_base_ = 0;
thread_local uint64_t GuestTls::tls_block_ = 0;

void GuestTls::setFsBase(uint64_t base) { fs_base_ = base; }
uint64_t GuestTls::fsBase() const { return fs_base_; }
uint64_t GuestTls::allocate(size_t size) {
    // Simple sequential guest TLS arena. Real system would use MemoryManager.
    static std::atomic<uint64_t> next{0x70000000ULL};
    uint64_t base = next.fetch_add((size + 0xFFF) & ~0xFFFULL, std::memory_order_relaxed);
    tls_block_ = base;
    fs_base_ = base;
    return base;
}

Threading::~Threading() {
    stopAll();
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& [tid, gt] : threads_) {
        if (gt && gt->host.joinable()) {
            gt->host.join();
        }
    }
    threads_.clear();
}

void Threading::attachRuntime(ExecutionLoop* loop,
                              const uint8_t* primary_image,
                              size_t primary_len) {
    loop_ = loop;
    primary_image_ = primary_image;
    primary_len_ = primary_len;
}

void Threading::workerMain(GuestThread* gt) {
    ContextSwitch cs;
    cs.restore(gt->ctx);
    ContextSwitch::current().fs_base = gt->fs_base
        ? gt->fs_base
        : tls_.allocate(4096);
    ContextSwitch::current().rsp() = gt->stack;
    ContextSwitch::current().rip = gt->entry;
    current_ = gt->tid;
    gt->alive.store(true, std::memory_order_release);

    Logger::instance().infof(LogCategory::ABI,
                             "guest thread %d started entry=0x%llx sp=0x%llx",
                             gt->tid,
                             (unsigned long long)gt->entry,
                             (unsigned long long)gt->stack);

    if (loop_ && primary_image_ && primary_len_) {
        for (;;) {
            auto res = loop_->resume(ContextSwitch::current(),
                                     primary_image_, primary_len_,
                                     /*max_steps=*/100000);
            if (res.reason == ExitReason::THREAD_EXIT ||
                res.reason == ExitReason::HALT ||
                res.reason == ExitReason::EXCEPTION) {
                gt->exit_code = static_cast<int>(res.syscall_ret);
                break;
            }
            if (loop_->stopRequested()) break;
        }
    } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    if (gt->set_tid_address) {
        Logger::instance().infof(LogCategory::ABI,
                                 "clear-child-tid 0x%llx for tid %d",
                                 (unsigned long long)gt->set_tid_address, gt->tid);
    }

    gt->alive.store(false, std::memory_order_release);
    Logger::instance().infof(LogCategory::ABI, "guest thread %d exited code=%d",
                             gt->tid, gt->exit_code);
}

int Threading::clone(uint64_t flags, uint64_t stack, uint64_t parent_tid,
                     uint64_t child_tid, uint64_t tls, uint64_t entry_pc) {
    (void)parent_tid;
    int tid = next_tid_.fetch_add(1, std::memory_order_relaxed);
    auto gt = std::make_unique<GuestThread>();
    gt->tid = tid;
    gt->stack = stack;
    gt->entry = entry_pc;
    gt->fs_base = (flags & NINE_CLONE_SETTLS) ? tls : 0;
    if (flags & NINE_CLONE_CHILD_CLEARTID) gt->set_tid_address = child_tid;
    if (flags & NINE_CLONE_CHILD_SETTID) {
        gt->set_tid_address = child_tid;
    }

    ContextSwitch().save(gt->ctx);
    gt->ctx.rsp() = stack;
    if (entry_pc) gt->ctx.rip = entry_pc;
    if (gt->fs_base) gt->ctx.fs_base = gt->fs_base;

    GuestThread* raw = gt.get();
    {
        std::lock_guard<std::mutex> lock(mu_);
        threads_[tid] = std::move(gt);
    }

    raw->host = std::thread([this, raw]() { workerMain(raw); });

    Logger::instance().infof(LogCategory::ABI, "clone flags=0x%llx -> tid %d",
                             (unsigned long long)flags, tid);
    return tid;
}

int Threading::createThread(uint64_t start_address, uint64_t /*stack_size*/,
                            uint64_t parameter, uint64_t* out_handle) {
    uint64_t stack = 0x7F000000ULL;
    int tid = clone(NINE_CLONE_VM | NINE_CLONE_FS | NINE_CLONE_FILES |
                    NINE_CLONE_SIGHAND | NINE_CLONE_THREAD,
                    stack, 0, 0, 0, start_address);
    if (tid < 0) return tid;
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = threads_.find(tid);
        if (it != threads_.end()) {
            it->second->ctx.rcx() = parameter;
            it->second->ctx.rdi() = parameter;
        }
    }
    if (out_handle) *out_handle = static_cast<uint64_t>(tid);
    return tid;
}

int Threading::setTidAddress(int tid, uint64_t addr) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = threads_.find(tid);
    if (it == threads_.end()) return -ESRCH;
    it->second->set_tid_address = addr;
    return tid;
}

int Threading::robustFutexWake(uint64_t uaddr) {
    Logger::instance().infof(LogCategory::ABI, "robust futex wake 0x%llx",
                             (unsigned long long)uaddr);
    return 1;
}

int Threading::join(int tid, int* exit_code) {
    std::unique_ptr<GuestThread> owned;
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = threads_.find(tid);
        if (it == threads_.end()) return -ESRCH;
        if (it->second->joined.exchange(true)) return -EINVAL;
        owned = std::move(it->second);
        threads_.erase(it);
    }
    if (owned->host.joinable()) owned->host.join();
    if (exit_code) *exit_code = owned->exit_code;
    return 0;
}

void Threading::exitCurrent(int code) {
    int tid = current_;
    std::lock_guard<std::mutex> lock(mu_);
    auto it = threads_.find(tid);
    if (it != threads_.end()) {
        it->second->exit_code = code;
        it->second->alive.store(false, std::memory_order_release);
    }
    if (loop_) loop_->requestStop();
}

size_t Threading::liveThreadCount() const {
    std::lock_guard<std::mutex> lock(const_cast<Threading*>(this)->mu_);
    size_t n = 0;
    for (auto& [tid, gt] : threads_) {
        if (gt && gt->alive.load(std::memory_order_acquire)) ++n;
    }
    return n;
}

void Threading::stopAll() {
    if (loop_) loop_->requestStop();
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& [tid, gt] : threads_) {
        if (gt) gt->alive.store(false, std::memory_order_release);
    }
}

} // namespace nexus
