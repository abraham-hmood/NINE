#pragma once

#include "../runtime/GuestContext.h"
#include "../runtime/ExecutionLoop.h"
#include <cstdint>
#include <string>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <atomic>
#include <functional>
#include <condition_variable>
#include <vector>
#include <memory>

namespace nexus {

// Guest TLS: x86-64 FS segment base, emulated per host thread.
class GuestTls {
public:
    void setFsBase(uint64_t base);
    uint64_t fsBase() const;
    // Allocate a TLS block of `size` and return its guest address.
    uint64_t allocate(size_t size);
private:
    static thread_local uint64_t fs_base_;
    static thread_local uint64_t tls_block_;
};

// Full guest-thread state. Each maps 1:1 onto a host std::thread that runs
// the execution loop with its own GuestContext (via ContextSwitch::current()).
struct GuestThread {
    int tid = 0;
    uint64_t set_tid_address = 0;   // clear-child-tid
    uint64_t fs_base = 0;
    uint64_t stack = 0;             // guest stack pointer at start
    uint64_t entry = 0;             // guest entry PC
    GuestContext ctx;               // snapshot used when creating / joining
    std::thread host;
    std::atomic<bool> alive{false};
    std::atomic<bool> joined{false};
    int exit_code = 0;
};

// Linux clone flags we honour (subset).
// Prefixed NINE_ to avoid collision with <linux/sched.h> macros of the same name.
constexpr uint64_t NINE_CLONE_VM              = 0x00000100;
constexpr uint64_t NINE_CLONE_FS              = 0x00000200;
constexpr uint64_t NINE_CLONE_FILES           = 0x00000400;
constexpr uint64_t NINE_CLONE_SIGHAND         = 0x00000800;
constexpr uint64_t NINE_CLONE_THREAD          = 0x00010000;
constexpr uint64_t NINE_CLONE_SYSVSEM         = 0x00040000;
constexpr uint64_t NINE_CLONE_SETTLS          = 0x00080000;
constexpr uint64_t NINE_CLONE_PARENT_SETTID   = 0x00100000;
constexpr uint64_t NINE_CLONE_CHILD_CLEARTID  = 0x00200000;
constexpr uint64_t NINE_CLONE_CHILD_SETTID    = 0x01000000;

class Threading {
public:
    Threading() = default;
    ~Threading();

    // Attach the shared runtime pieces so worker threads can run the loop.
    void attachRuntime(ExecutionLoop* loop,
                       const uint8_t* primary_image,
                       size_t primary_len);

    // clone: create a host thread representing a guest thread.
    // flags follow Linux clone(2). Returns guest tid, or -errno.
    int clone(uint64_t flags, uint64_t stack, uint64_t parent_tid,
              uint64_t child_tid, uint64_t tls,
              uint64_t entry_pc = 0);

    // Windows-style CreateThread equivalent.
    int createThread(uint64_t start_address, uint64_t stack_size,
                     uint64_t parameter, uint64_t* out_handle);

    // set_tid_address: record the clear-child-tid address for exit.
    int setTidAddress(int tid, uint64_t addr);

    // Robust futex: owner-died handling. Returns 0 on success.
    int robustFutexWake(uint64_t uaddr);

    // Join / wait for a guest thread to exit.
    int join(int tid, int* exit_code = nullptr);

    // Exit the current guest thread (clears child-tid if set).
    void exitCurrent(int code);

    GuestTls& tls() { return tls_; }
    int currentTid() const { return current_; }
    size_t liveThreadCount() const;

    // Soft-stop all workers (used by process exit).
    void stopAll();

private:
    void workerMain(GuestThread* gt);

    std::mutex mu_;
    std::unordered_map<int, std::unique_ptr<GuestThread>> threads_;
    std::atomic<int> next_tid_{1000};
    int current_ = 1;
    GuestTls tls_;

    ExecutionLoop* loop_ = nullptr;
    const uint8_t* primary_image_ = nullptr;
    size_t primary_len_ = 0;
};

} // namespace nexus
