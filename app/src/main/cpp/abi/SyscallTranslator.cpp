#include "SyscallTranslator.h"
#include "../memory/MemoryManager.h"
#include "../diagnostics/Logger.h"
#include "../runtime/GuestContext.h"
#include <ctime>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <optional>
#include <thread>
#include <vector>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <poll.h>
#include <sched.h>

namespace nexus {

int FdTable::alloc(int host_fd) {
    std::lock_guard<std::mutex> lock(mu_);
    int g = next_++;
    map_[g] = host_fd;
    return g;
}
int FdTable::host(int guest_fd) const {
    if (guest_fd >= 0 && guest_fd <= 2) return guest_fd;
    std::lock_guard<std::mutex> lock(mu_);
    auto it = map_.find(guest_fd);
    return it == map_.end() ? -1 : it->second;
}
void FdTable::close(int guest_fd) {
    std::lock_guard<std::mutex> lock(mu_);
    map_.erase(guest_fd);
}
void FdTable::set(int guest_fd, int host_fd) {
    std::lock_guard<std::mutex> lock(mu_);
    map_[guest_fd] = host_fd;
}

namespace {

// Guest x86-64 kernel `struct stat` (uapi, 144 bytes) — layout-stable ABI,
// independent of the host's struct stat padding details.
struct GuestStat {
    uint64_t dev, ino, nlink;
    uint32_t mode, uid, gid, pad0;
    uint64_t rdev;
    int64_t size, blksize, blocks;
    uint64_t atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
    int64_t unused[3];
};
static_assert(sizeof(GuestStat) == 144, "guest struct stat must be 144 bytes");

int64_t copyGuestStat(void* gdst, const struct stat& h) {
    if (!gdst) return -EFAULT;
    GuestStat g{};
    g.dev = h.st_dev;
    g.ino = h.st_ino;
    g.nlink = h.st_nlink;
    g.mode = h.st_mode;
    g.uid = h.st_uid;
    g.gid = h.st_gid;
    g.rdev = h.st_rdev;
    g.size = h.st_size;
    g.blksize = h.st_blksize;
    g.blocks = h.st_blocks;
    g.atime = static_cast<uint64_t>(h.st_atim.tv_sec);
    g.atime_ns = static_cast<uint64_t>(h.st_atim.tv_nsec);
    g.mtime = static_cast<uint64_t>(h.st_mtim.tv_sec);
    g.mtime_ns = static_cast<uint64_t>(h.st_mtim.tv_nsec);
    g.ctime = static_cast<uint64_t>(h.st_ctim.tv_sec);
    g.ctime_ns = static_cast<uint64_t>(h.st_ctim.tv_nsec);
    std::memcpy(gdst, &g, sizeof(g));
    return 0;
}

std::optional<int> resolveDirfd(FdTable& fds, int dirfd) {
    if (dirfd == -100) return AT_FDCWD; // AT_FDCWD
    int h = fds.host(dirfd);
    return h < 0 ? std::nullopt : std::optional<int>(h);
}

} // namespace

void* SyscallTranslator::g2h(uint64_t guest_addr) {
    if (!guest_addr) return nullptr;
    if (mm_) {
        void* p = mm_->guestToHost(guest_addr);
        if (p) return p;
    }
    // Fallback: identity (valid when guest memory is host-mapped 1:1 or tests pass host ptrs)
    return reinterpret_cast<void*>(static_cast<uintptr_t>(guest_addr));
}

const char* SyscallTranslator::g2h_cstr(uint64_t guest_addr) {
    return static_cast<const char*>(g2h(guest_addr));
}

int64_t SyscallTranslator::translate(int nr, uint64_t a1, uint64_t a2, uint64_t a3,
                                     uint64_t a4, uint64_t a5, uint64_t a6) {
    switch (nr) {
        case SYS_READ: {
            int h = fds_.host(static_cast<int>(a1));
            if (h < 0) return -EBADF;
            void* buf = g2h(a2);
            if (!buf) return -EFAULT;
            ssize_t r = ::read(h, buf, static_cast<size_t>(a3));
            return r < 0 ? -errno : r;
        }
        case SYS_WRITE: {
            int fd = static_cast<int>(a1);
            int h = fds_.host(fd);
            if (h < 0) return -EBADF;
            const void* buf = g2h(a2);
            if (!buf) return -EFAULT;
            size_t n = static_cast<size_t>(a3);
            if (fd == 1 || fd == 2) {
                // Ensure stdout/stderr always "succeed" for guest stdio
                ssize_t r = ::write(h, buf, n);
                if (r < 0) r = static_cast<ssize_t>(n); // pretend OK
                return r;
            }
            ssize_t r = ::write(h, buf, n);
            return r < 0 ? -errno : r;
        }
        case SYS_OPEN: {
            const char* path = g2h_cstr(a1);
            if (!path) return -EFAULT;
            int h = ::open(path, static_cast<int>(a2), static_cast<mode_t>(a3));
            return h < 0 ? -errno : fds_.alloc(h);
        }
        case SYS_OPENAT: {
            const char* path = g2h_cstr(a2);
            if (!path) return -EFAULT;
            int dirfd = static_cast<int>(a1);
            if (dirfd == -100 /* AT_FDCWD */) dirfd = AT_FDCWD;
            else {
                int hdir = fds_.host(dirfd);
                if (hdir < 0 && dirfd != AT_FDCWD) return -EBADF;
                if (hdir >= 0) dirfd = hdir;
            }
            int h = ::openat(dirfd, path, static_cast<int>(a3), static_cast<mode_t>(a4));
            return h < 0 ? -errno : fds_.alloc(h);
        }
        case SYS_CLOSE: {
            int h = fds_.host(static_cast<int>(a1));
            if (h < 0) return -EBADF;
            if (h > 2) ::close(h);
            fds_.close(static_cast<int>(a1));
            return 0;
        }
        case SYS_LSEEK: {
            int h = fds_.host(static_cast<int>(a1));
            if (h < 0) return -EBADF;
            off_t r = ::lseek(h, static_cast<off_t>(a2), static_cast<int>(a3));
            return r < 0 ? -errno : r;
        }
        case SYS_MMAP: {
            int prot = static_cast<int>(a3);
            int flags = static_cast<int>(a4);
            int fd = static_cast<int>(a5);
            off_t off = static_cast<off_t>(a6);
            int hfd = (fd >= 0) ? fds_.host(fd) : -1;
            void* p = ::mmap(g2h(a1), static_cast<size_t>(a2), prot, flags,
                             hfd, off);
            if (p == MAP_FAILED) return -errno;
            return static_cast<int64_t>(reinterpret_cast<uintptr_t>(p));
        }
        case SYS_MUNMAP: {
            int r = ::munmap(g2h(a1), static_cast<size_t>(a2));
            return r < 0 ? -errno : 0;
        }
        case SYS_MPROTECT: {
            int r = ::mprotect(g2h(a1), static_cast<size_t>(a2), static_cast<int>(a3));
            return r < 0 ? -errno : 0;
        }
        case SYS_BRK: {
            if (a1 == 0) return static_cast<int64_t>(brk_);
            if (a1 > brk_ && mm_) {
                // Extend guest heap mapping
                uint64_t old = brk_;
                size_t need = static_cast<size_t>(a1 - old);
                if (need) {
                    uint64_t g = mm_->allocate(old, need, PagePerm::READ_WRITE, "brk");
                    if (!g) {
                        // best-effort: still advance pointer so glibc continues
                        Logger::instance().warn(LogCategory::ABI, "brk allocate failed, advancing anyway");
                    }
                }
                brk_ = a1;
            } else if (a1 > brk_) {
                brk_ = a1;
            } else if (a1 != 0 && a1 < brk_) {
                brk_ = a1; // allow shrink
            }
            return static_cast<int64_t>(brk_);
        }
        case SYS_EXIT:
        case SYS_EXIT_GROUP:
            Logger::instance().infof(LogCategory::ABI, "guest exit code=%lld",
                                     (long long)a1);
            return 0;
        case SYS_GETPID: return ::getpid();
        case SYS_GETTID: return static_cast<int64_t>(::syscall(__NR_gettid));
        case SYS_GETPPID: return ::getppid();
        case SYS_GETUID: return ::getuid();
        case SYS_GETEUID: return ::geteuid();
        case SYS_GETGID: return ::getgid();
        case SYS_GETEGID: return ::getegid();
        case SYS_GETTIMEOFDAY: {
            auto* tv = static_cast<timeval*>(g2h(a1));
            if (tv) gettimeofday(tv, nullptr);
            return 0;
        }
        case SYS_CLOCK_GETTIME: {
            auto* ts = static_cast<timespec*>(g2h(a2));
            if (ts) {
                int r = clock_gettime(static_cast<clockid_t>(a1), ts);
                return r < 0 ? -errno : 0;
            }
            return -EFAULT;
        }
        case SYS_NANOSLEEP: {
            auto* req = static_cast<timespec*>(g2h(a1));
            auto* rem = static_cast<timespec*>(g2h(a2));
            if (!req) return -EFAULT;
            int r = nanosleep(req, rem);
            return r < 0 ? -errno : 0;
        }
        case SYS_SCHED_YIELD:
            sched_yield();
            return 0;
        case SYS_FUTEX:
            // Best-effort: WAKE returns 0; WAIT sleeps briefly then returns 0
            // Full futex needs shared guest memory + host futex on mapped page.
            if ((a2 & 0x7F) == 0 /* FUTEX_WAIT */ || (a2 & 0x7F) == 128 /* PRIVATE_WAIT */) {
                timespec ts{0, 1000000}; // 1ms
                nanosleep(&ts, nullptr);
            }
            return 0;
        case SYS_SET_TID_ADDRESS:
            return ::getpid(); // return tid
        case SYS_UNAME: {
            auto* u = static_cast<utsname*>(g2h(a1));
            if (!u) return -EFAULT;
            int r = uname(u);
            if (r == 0) {
                // Present as x86_64 Linux to the guest
                std::strncpy(u->machine, "x86_64", sizeof(u->machine) - 1);
            }
            return r < 0 ? -errno : 0;
        }
        case SYS_ACCESS: {
            const char* path = g2h_cstr(a1);
            if (!path) return -EFAULT;
            int r = ::access(path, static_cast<int>(a2));
            return r < 0 ? -errno : 0;
        }
        case SYS_FACCESSAT: {
            const char* path = g2h_cstr(a2);
            if (!path) return -EFAULT;
            int r = ::faccessat(AT_FDCWD, path, static_cast<int>(a3), static_cast<int>(a4));
            return r < 0 ? -errno : 0;
        }
        case SYS_DUP: {
            int h = fds_.host(static_cast<int>(a1));
            if (h < 0) return -EBADF;
            int nh = ::dup(h);
            return nh < 0 ? -errno : fds_.alloc(nh);
        }
        case SYS_DUP2: {
            int h = fds_.host(static_cast<int>(a1));
            if (h < 0) return -EBADF;
            int nh = ::dup(h);
            if (nh < 0) return -errno;
            fds_.set(static_cast<int>(a2), nh);
            return static_cast<int>(a2);
        }
        case SYS_FCNTL: {
            int h = fds_.host(static_cast<int>(a1));
            if (h < 0) return -EBADF;
            int r = ::fcntl(h, static_cast<int>(a2), a3);
            return r < 0 ? -errno : r;
        }
        case SYS_IOCTL:
            return -ENOTTY;
        case SYS_MADVISE:
            return 0;
        case SYS_GETCWD: {
            char* buf = static_cast<char*>(g2h(a1));
            if (!buf) return -EFAULT;
            if (!getcwd(buf, static_cast<size_t>(a2))) return -errno;
            return static_cast<int64_t>(a1);
        }
        case SYS_CHDIR: {
            const char* path = g2h_cstr(a1);
            if (!path) return -EFAULT;
            int r = ::chdir(path);
            return r < 0 ? -errno : 0;
        }
        case SYS_GETRANDOM: {
            void* buf = g2h(a1);
            if (!buf) return -EFAULT;
            // /dev/urandom fallback
            int h = ::open("/dev/urandom", O_RDONLY);
            if (h < 0) return -errno;
            ssize_t r = ::read(h, buf, static_cast<size_t>(a2));
            ::close(h);
            return r < 0 ? -errno : r;
        }
        case SYS_ARCH_PRCTL: {
            // ARCH_SET_FS = 0x1002, ARCH_GET_FS = 0x1003, ARCH_SET_GS=0x1001, ARCH_GET_GS=0x1004
            auto& ctx = ContextSwitch::current();
            if (a1 == 0x1002) { ctx.fs_base = a2; return 0; }
            if (a1 == 0x1001) { ctx.gs_base = a2; return 0; }
            if (a1 == 0x1003) {
                auto* out = static_cast<uint64_t*>(g2h(a2));
                if (out) *out = ctx.fs_base;
                return out ? 0 : -EFAULT;
            }
            if (a1 == 0x1004) {
                auto* out = static_cast<uint64_t*>(g2h(a2));
                if (out) *out = ctx.gs_base;
                return out ? 0 : -EFAULT;
            }
            return -EINVAL;
        }
        case SYS_RT_SIGACTION: {
            uint64_t sig = a1;
            if (sig == 0 || sig > 64) return -EINVAL;
            auto* act = static_cast<uint64_t*>(g2h(a2));
            auto* old = static_cast<uint64_t*>(g2h(a3));
            if (old) {
                old[0] = sig_handler_[sig - 1];
                old[1] = sig_flags_[sig - 1];
                old[2] = 0; // sa_restorer
                old[3] = 0; // sa_mask
            }
            if (act) {
                sig_handler_[sig - 1] = act[0];
                sig_flags_[sig - 1] = act[1];
            }
            return 0;
        }
        case SYS_RT_SIGPROCMASK: {
            auto* old = static_cast<uint64_t*>(g2h(a3));
            if (old) *old = sig_blocked_;
            auto* set = static_cast<uint64_t*>(g2h(a2));
            if (set) {
                switch (static_cast<int>(a1)) {
                    case 0: sig_blocked_ |= *set; break;  // SIG_BLOCK
                    case 1: sig_blocked_ &= ~*set; break; // SIG_UNBLOCK
                    case 2: sig_blocked_ = *set; break;   // SIG_SETMASK
                    default: return -EINVAL;
                }
            }
            return 0;
        }
        case SYS_STAT:
        case SYS_LSTAT: {
            const char* path = g2h_cstr(a1);
            if (!path) return -EFAULT;
            struct stat hst {};
            int r = (nr == SYS_STAT) ? ::stat(path, &hst) : ::lstat(path, &hst);
            return r < 0 ? -errno : copyGuestStat(g2h(a2), hst);
        }
        case SYS_FSTAT: {
            int h = fds_.host(static_cast<int>(a1));
            if (h < 0) return -EBADF;
            struct stat hst {};
            if (::fstat(h, &hst) < 0) return -errno;
            return copyGuestStat(g2h(a2), hst);
        }
        case SYS_NEWFSTATAT: {
            const char* path = g2h_cstr(a2);
            if (!path) return -EFAULT;
            auto dirfd = resolveDirfd(fds_, static_cast<int>(a1));
            if (!dirfd) return -EBADF;
            struct stat hst {};
            if (::fstatat(*dirfd, path, &hst, static_cast<int>(a4)) < 0) return -errno;
            return copyGuestStat(g2h(a3), hst);
        }
        case SYS_PREAD64: {
            int h = fds_.host(static_cast<int>(a1));
            if (h < 0) return -EBADF;
            void* buf = g2h(a2);
            if (!buf) return -EFAULT;
            ssize_t r = ::pread(h, buf, static_cast<size_t>(a3), static_cast<off_t>(a4));
            return r < 0 ? -errno : r;
        }
        case SYS_READLINKAT: {
            auto dirfd = resolveDirfd(fds_, static_cast<int>(a1));
            if (!dirfd) return -EBADF;
            const char* path = g2h_cstr(a2);
            if (!path) return -EFAULT;
            char tmp[4096];
            ssize_t r = ::readlinkat(*dirfd, path, tmp, sizeof(tmp) - 1);
            if (r < 0) return -errno;
            void* gbuf = g2h(a3);
            if (!gbuf) return -EFAULT;
            std::memcpy(gbuf, tmp, static_cast<size_t>(r));
            return r;
        }
        case SYS_GETDENTS64: {
            int h = fds_.host(static_cast<int>(a1));
            if (h < 0) return -EBADF;
            size_t len = static_cast<size_t>(a3);
            if (len == 0) return -EINVAL;
            if (len > 65536) len = 65536;
            std::vector<char> tmp(len);
            long r = ::syscall(__NR_getdents64, h, tmp.data(), len);
            if (r < 0) return -errno;
            void* gbuf = g2h(a2);
            if (!gbuf) return -EFAULT;
            std::memcpy(gbuf, tmp.data(), static_cast<size_t>(r));
            return r;
        }
        case SYS_SCHED_GETAFFINITY: {
            if (a1 != 0 && static_cast<pid_t>(a1) != ::getpid()) return -ESRCH;
            size_t len = static_cast<size_t>(a2);
            if (len == 0 || len > 4096) return -EINVAL;
            void* gmask = g2h(a3);
            if (!gmask) return -EFAULT;
            std::memset(gmask, 0, len);
            unsigned n = std::thread::hardware_concurrency();
            if (n == 0) n = 4;
            if (n > 64) n = 64;
            uint64_t mask = (n >= 64) ? ~0ull : ((1ull << n) - 1ull);
            if (len >= 8) *static_cast<uint64_t*>(gmask) = mask;
            return static_cast<int64_t>(len);
        }
        case SYS_PRLIMIT64: {
            if (a1 != 0 && static_cast<pid_t>(a1) != ::getpid()) return -ESRCH;
            struct rlimit rl {};
            if (::getrlimit(static_cast<int>(a2), &rl) < 0) return -errno;
            auto* old = static_cast<uint64_t*>(g2h(a3));
            if (old) { old[0] = rl.rlim_cur; old[1] = rl.rlim_max; }
            return 0; // new limits (a4) ignored: never shrink the host process
        }
        case SYS_PRCTL: {
            switch (static_cast<int>(a1)) {
                case 4:  // PR_SET_DUMPABLE
                    return ::prctl(PR_SET_DUMPABLE, a2) < 0 ? -errno : 0;
                case 15: { // PR_SET_NAME
                    const char* nm = g2h_cstr(a2);
                    char tmp[17] = {};
                    if (nm) std::strncpy(tmp, nm, 16);
                    return ::prctl(PR_SET_NAME, tmp) < 0 ? -errno : 0;
                }
                case 16: { // PR_GET_NAME
                    char tmp[17] = {};
                    if (::prctl(PR_GET_NAME, tmp) < 0) return -errno;
                    void* g = g2h(a2);
                    if (!g) return -EFAULT;
                    std::memcpy(g, tmp, 17);
                    return 0;
                }
                case 23: { // PR_GET_DUMPABLE
                    int r = ::prctl(PR_GET_DUMPABLE);
                    return r < 0 ? -errno : r;
                }
                case 0x53564D41: // PR_SET_VMA anon-name — harmless to ignore
                    return 0;
                default:
                    return -EINVAL;
            }
        }
        case SYS_TGKILL:
            // Never deliver host signals from the guest (abort()/raise() paths);
            // the guest exits via its own exit_group.
            Logger::instance().infof(LogCategory::ABI, "tgkill(%lld, %lld, %lld) ignored",
                                     (long long)a1, (long long)a2, (long long)a3);
            return 0;
        case SYS_CLONE:
            Logger::instance().warn(LogCategory::ABI, "clone: use Threading::clone from ABI glue");
            return -ENOSYS;
        case SYS_FORK:
        case SYS_VFORK:
        case SYS_EXECVE:
            return -ENOSYS;
        case SYS_WRITEV:
        case SYS_READV: {
            int h = fds_.host(static_cast<int>(a1));
            if (h < 0) return -EBADF;
            int cnt = static_cast<int>(a3);
            if (cnt < 0 || cnt > 1024) return -EINVAL;
            auto* giov = static_cast<iovec*>(g2h(a2));
            if (!giov && cnt > 0) return -EFAULT;
            std::vector<iovec> hiov(static_cast<size_t>(cnt));
            for (int i = 0; i < cnt; ++i) {
                hiov[i].iov_base = g2h(reinterpret_cast<uint64_t>(giov[i].iov_base));
                hiov[i].iov_len = giov[i].iov_len;
                if (!hiov[i].iov_base && giov[i].iov_len > 0) return -EFAULT;
            }
            ssize_t r = (nr == SYS_WRITEV)
                ? ::writev(h, hiov.data(), cnt)
                : ::readv(h, hiov.data(), cnt);
            return r < 0 ? -errno : r;
        }
        case SYS_POLL: {
            auto* p = static_cast<pollfd*>(g2h(a1));
            if (!p && a2 > 0) return -EFAULT;
            int r = ::poll(p, static_cast<nfds_t>(a2), static_cast<int>(a3));
            return r < 0 ? -errno : r;
        }
        case SYS_MREMAP: {
            // Emulated: allocate new, copy, free old — keeps MemoryManager's
            // region table consistent (guest sees fresh contiguous mapping).
            if (!mm_) return -ENOSYS;
            uint64_t old_addr = a1;
            size_t old_len = static_cast<size_t>(a2);
            size_t new_len = static_cast<size_t>(a3);
            uint64_t flags = a4 & 3; // MREMAP_MAYMOVE | MREMAP_FIXED
            if (new_len <= old_len) return static_cast<int64_t>(old_addr);
            uint64_t src = reinterpret_cast<uint64_t>(mm_->guestToHost(old_addr));
            PagePerm perms = PagePerm::READ_WRITE;
            if (auto reg = mm_->query(old_addr)) perms = reg->perms;
            uint64_t new_va = 0;
            if (flags & 2 /* MREMAP_FIXED */) {
                new_va = mm_->allocate(a5, new_len, PagePerm::READ_WRITE, "mremap");
                if (new_va != a5) {
                    if (new_va) mm_->free(new_va);
                    return -ENOMEM;
                }
            } else {
                new_va = mm_->allocate(old_addr, new_len, PagePerm::READ_WRITE, "mremap");
                if (!new_va) new_va = mm_->allocate(0, new_len, PagePerm::READ_WRITE, "mremap");
                if (!new_va) return -ENOMEM;
            }
            void* dst = mm_->guestToHost(new_va);
            if (!dst) { mm_->free(new_va); return -ENOMEM; }
            size_t copy_n = old_len < new_len ? old_len : new_len;
            if (src && copy_n) std::memcpy(dst, reinterpret_cast<void*>(src), copy_n);
            mm_->free(old_addr);
            if (perms != PagePerm::READ_WRITE)
                mm_->protectRange(new_va, new_len, perms);
            return static_cast<int64_t>(new_va);
        }
        case SYS_SYSINFO: {
            struct GuestSysinfo {
                int64_t uptime;
                uint64_t loads[3];
                uint64_t totalram, freeram, sharedram, bufferram;
                uint64_t totalswap, freeswap;
                uint16_t procs, pad;
                uint64_t totalhigh, freehigh;
                uint32_t mem_unit;
                uint32_t spacer;
            };
            static_assert(sizeof(GuestSysinfo) == 112, "sysinfo layout for x86-64");
            auto* out = static_cast<GuestSysinfo*>(g2h(a1));
            if (!out) return -EFAULT;
            struct sysinfo h {};
            if (::sysinfo(&h) < 0) return -errno;
            std::memset(out, 0, sizeof(*out));
            out->uptime = h.uptime;
            out->loads[0] = static_cast<uint64_t>(h.loads[0]);
            out->loads[1] = static_cast<uint64_t>(h.loads[1]);
            out->loads[2] = static_cast<uint64_t>(h.loads[2]);
            out->totalram = h.totalram;
            out->freeram = h.freeram;
            out->procs = h.procs ? h.procs : 8;
            out->mem_unit = h.mem_unit ? h.mem_unit : 1;
            return 0;
        }
        case SYS_SCHED_GETPARAM: {
            if (a1 != 0 && static_cast<pid_t>(a1) != ::getpid()) return -ESRCH;
            auto* out = static_cast<int32_t*>(g2h(a2));
            if (!out) return -EFAULT;
            *out = 0; // SCHED_OTHER nice-priority 0
            return 0;
        }
        case SYS_SCHED_SETSCHEDULER:
            // Ignored: no permission to change scheduler policy on Android;
            // pretend success so the guest proceeds.
            return 0;
        case SYS_SCHED_GETSCHEDULER:
            return 0; // SCHED_OTHER
        case SYS_SCHED_GET_PRIORITY_MAX:
            return 0; // Linux: SCHED_OTHER max prio is 0
        case SYS_SCHED_GET_PRIORITY_MIN:
            return 0;
        case SYS_RSEQ:
            // Report unavailable — glibc static binaries handle absence
            // gracefully (falls back to no-restartable-sequences mode).
            Logger::instance().errorf(LogCategory::ABI, "rseq: reporting ENOSYS");
            return -ENOSYS;
        default:
            Logger::instance().errorf(LogCategory::ABI, "unimplemented syscall %d", nr);
            return -ENOSYS;
    }
}

} // namespace nexus
