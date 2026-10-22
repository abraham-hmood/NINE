#pragma once

#include <cstdint>
#include <unordered_map>
#include <string>
#include <mutex>
#include <vector>
#include <array>

namespace nexus {

class MemoryManager;

enum Syscall : int {
    SYS_READ = 0, SYS_WRITE = 1, SYS_OPEN = 2, SYS_CLOSE = 3,
    SYS_STAT = 4, SYS_FSTAT = 5, SYS_LSTAT = 6, SYS_POLL = 7,
    SYS_LSEEK = 8, SYS_MMAP = 9, SYS_MPROTECT = 10, SYS_MUNMAP = 11, SYS_BRK = 12,
    SYS_RT_SIGACTION = 13, SYS_RT_SIGPROCMASK = 14, SYS_IOCTL = 16,
    SYS_PREAD64 = 17, SYS_PWRITE64 = 18, SYS_READV = 19, SYS_WRITEV = 20,
    SYS_ACCESS = 21, SYS_PIPE = 22, SYS_SELECT = 23, SYS_SCHED_YIELD = 24,
    SYS_MREMAP = 25, SYS_MSYNC = 26, SYS_MADVISE = 28,
    SYS_DUP = 32, SYS_DUP2 = 33, SYS_NANOSLEEP = 35,
    SYS_GETPID = 39, SYS_SOCKET = 41, SYS_CONNECT = 42, SYS_ACCEPT = 43,
    SYS_SENDTO = 44, SYS_RECVFROM = 45, SYS_BIND = 49, SYS_LISTEN = 50,
    SYS_CLONE = 56, SYS_FORK = 57, SYS_VFORK = 58, SYS_EXECVE = 59,
    SYS_EXIT = 60, SYS_WAIT4 = 61, SYS_KILL = 62, SYS_UNAME = 63,
    SYS_FCNTL = 72, SYS_FLOCK = 73, SYS_FSYNC = 74, SYS_TRUNCATE = 76,
    SYS_GETCWD = 79, SYS_CHDIR = 80, SYS_RENAME = 82, SYS_MKDIR = 83,
    SYS_RMDIR = 84, SYS_LINK = 86, SYS_UNLINK = 87, SYS_READLINK = 89,
    SYS_CHMOD = 90, SYS_GETTIMEOFDAY = 96, SYS_GETRUSAGE = 98,
    SYS_GETUID = 102, SYS_GETGID = 104, SYS_GETEUID = 107, SYS_GETEGID = 108,
    SYS_GETPPID = 110, SYS_GETPGID = 121, SYS_PRCTL = 157, SYS_ARCH_PRCTL = 158,
    SYS_GETTID = 186, SYS_FUTEX = 202, SYS_SCHED_GETAFFINITY = 204,
    SYS_GETDENTS64 = 217, SYS_SET_TID_ADDRESS = 218,
    SYS_CLOCK_GETTIME = 228, SYS_EXIT_GROUP = 231, SYS_TGKILL = 234,
    SYS_OPENAT = 257, SYS_MKDIRAT = 258, SYS_NEWFSTATAT = 262,
    SYS_UNLINKAT = 263, SYS_RENAMEAT = 264, SYS_READLINKAT = 267, SYS_FACCESSAT = 269,
    SYS_PRLIMIT64 = 302, SYS_GETRANDOM = 318, SYS_RSEQ = 334,
    SYS_SCHED_GETPARAM = 143, SYS_SCHED_SETSCHEDULER = 144,
    SYS_SCHED_GETSCHEDULER = 145, SYS_SCHED_GET_PRIORITY_MAX = 146,
    SYS_SCHED_GET_PRIORITY_MIN = 147, SYS_SYSINFO = 99,
};

class FdTable {
public:
    int alloc(int host_fd);
    int host(int guest_fd) const;
    void close(int guest_fd);
    void set(int guest_fd, int host_fd);
private:
    mutable std::mutex mu_;
    std::unordered_map<int, int> map_;
    int next_ = 3;
};

class SyscallTranslator {
public:
    void setMemoryManager(MemoryManager* mm) { mm_ = mm; }
    void setBrk(uint64_t v) { brk_ = v; }
    uint64_t brk() const { return brk_; }

    // Translate one syscall. Returns value for guest RAX. Unimplemented -> -ENOSYS.
    int64_t translate(int nr, uint64_t a1, uint64_t a2, uint64_t a3,
                      uint64_t a4, uint64_t a5, uint64_t a6);

    FdTable& fds() { return fds_; }
    const FdTable& fds() const { return fds_; }

private:
    void* g2h(uint64_t guest_addr);
    const char* g2h_cstr(uint64_t guest_addr);

    FdTable fds_;
    uint64_t brk_ = 0x40000000;
    MemoryManager* mm_ = nullptr;

    // Guest signal state (NINE delivers no signals; rt_sigaction/rt_sigprocmask
    // keep guest-visible bookkeeping so glibc's init sequences behave).
    uint64_t sig_blocked_ = 0;
    std::array<uint64_t, 64> sig_handler_{};
    std::array<uint64_t, 64> sig_flags_{};
};

} // namespace nexus
