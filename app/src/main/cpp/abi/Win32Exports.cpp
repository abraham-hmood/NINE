// Native implementations behind the Windows ABI thunks.
//
// Every handler here is reached from guest x86-64 code through a real stub
// (see WinAbi.h), receives its arguments already marshalled per the Microsoft
// x64 convention, and returns the value the guest will find in RAX/XMM0.
//
// Nothing in this file is a wrapper around a Windows DLL: the behaviour is
// NINE's own, running on the host's syscalls.

#include "Kernel32.h"
#include "../diagnostics/Logger.h"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <thread>
#include <unistd.h>

namespace nexus {

namespace {

constexpr uint64_t kInvalidHandle = ~0ULL;
constexpr uint64_t kPseudoProcess = ~0ULL;   // (HANDLE)-1
constexpr uint64_t kPseudoThread  = ~2ULL;   // (HANDLE)-2

std::atomic<uint64_t> g_qpc{0};

uint64_t qpcNow() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());
}

// 100 ns intervals since 1601-01-01, the FILETIME epoch.
uint64_t fileTimeNow() {
    using namespace std::chrono;
    const auto since_unix = system_clock::now().time_since_epoch();
    const uint64_t ticks100 = static_cast<uint64_t>(
        duration_cast<nanoseconds>(since_unix).count() / 100);
    return ticks100 + 116444736000000000ULL;
}

void fillSystemTime(uint8_t* p, bool local) {
    if (!p) return;
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    (void)local;             // no timezone database on device yet: UTC only
    gmtime_r(&t, &tm);
    auto w = [&](int i, uint16_t v) { std::memcpy(p + 2 * i, &v, 2); };
    w(0, static_cast<uint16_t>(tm.tm_year + 1900));
    w(1, static_cast<uint16_t>(tm.tm_mon + 1));
    w(2, static_cast<uint16_t>(tm.tm_wday));
    w(3, static_cast<uint16_t>(tm.tm_mday));
    w(4, static_cast<uint16_t>(tm.tm_hour));
    w(5, static_cast<uint16_t>(tm.tm_min));
    w(6, static_cast<uint16_t>(tm.tm_sec));
    w(7, 0);
}

std::string toHostPath(const std::string& win) {
    std::string s = win;
    for (char& c : s)
        if (c == '\\') c = '/';
    // "C:/…" -> "/…": NINE maps drive letters onto the root filesystem.
    if (s.size() >= 2 && s[1] == ':' && std::isalpha(static_cast<unsigned char>(s[0])))
        s.erase(0, 2);
    if (s.empty()) s = "/";
    return s;
}

} // namespace

// ---------------------------------------------------------------------------
// kernel32
// ---------------------------------------------------------------------------

void Kernel32::registerExports(WinAbi& w) {
    // kernelbase forwards to the same implementations (modern binaries import
    // almost everything from kernelbase, not kernel32).
    auto K = [&](const char* name, WinAbi::Handler h) {
        w.add("kernel32.dll", name, h);
        w.add("kernelbase.dll", name, std::move(h));
    };

    // ---- module management ------------------------------------------------
    K("GetModuleHandleA", [this](WinCall& c) -> uint64_t {
        return getModuleHandle(c.ansi(0));
    });
    K("GetModuleHandleW", [this](WinCall& c) -> uint64_t {
        return getModuleHandle(utf16ToUtf8(c.wide(0)));
    });
    K("GetProcAddress", [this](WinCall& c) -> uint64_t {
        return getProcAddress(c.u64(0), c.ansi(1));
    });
    K("LoadLibraryA", [this](WinCall& c) -> uint64_t {
        return loadLibrary(c.ansi(0));
    });
    K("LoadLibraryW", [this](WinCall& c) -> uint64_t {
        return loadLibrary(utf16ToUtf8(c.wide(0)));
    });
    K("FreeLibrary", [](WinCall&) -> uint64_t { return 1; });
    K("GetModuleFileNameA", [this](WinCall& c) -> uint64_t {
        uint64_t hmod = c.u64(0);
        std::string name = "nine.exe";
        for (const auto& e : nt_.ldr())
            if (e.base == hmod) { name = e.name; break; }
        const size_t cap = static_cast<size_t>(c.u32(2));
        if (cap == 0) return 0;
        const size_t n = c.putAnsi(c.u64(1), cap, name);
        return n;
    });
    K("GetModuleFileNameW", [this](WinCall& c) -> uint64_t {
        uint64_t hmod = c.u64(0);
        std::string name = "nine.exe";
        for (const auto& e : nt_.ldr())
            if (e.base == hmod) { name = e.name; break; }
        const size_t cap = static_cast<size_t>(c.u32(2));
        if (cap == 0) return 0;
        return c.putWide(c.u64(1), cap, utf8ToUtf16(name));
    });

    // ---- files ------------------------------------------------------------
    K("CreateFileA", [this](WinCall& c) -> uint64_t {
        const uint64_t h = createFile(toHostPath(c.ansi(0)), c.u32(1),
                                      c.u32(4) ? c.u32(4) : 3);
        return h;
    });
    K("CreateFileW", [this](WinCall& c) -> uint64_t {
        return createFile(toHostPath(utf16ToUtf8(c.wide(0))), c.u32(1),
                          c.u32(4) ? c.u32(4) : 3);
    });
    K("ReadFile", [this](WinCall& c) -> uint64_t {
        const uint64_t h = c.u64(0);
        const uint64_t buf = c.u64(1);
        const uint32_t len = c.u32(2);
        uint32_t got = 0;
        if (!c.writable(buf, len)) { setLastError(87); return 0; }
        if (!readFile(h, mm_.guestToHost(buf), len, &got)) return 0;
        if (c.u64(3)) c.put<uint32_t>(c.u64(3), got);
        return 1;
    });
    K("WriteFile", [this](WinCall& c) -> uint64_t {
        const uint64_t h = c.u64(0);
        const uint64_t buf = c.u64(1);
        const uint32_t len = c.u32(2);
        uint32_t put = 0;
        if (!c.readable(buf, len)) { setLastError(87); return 0; }
        if (!writeFile(h, mm_.guestToHost(buf), len, &put)) return 0;
        if (c.u64(3)) c.put<uint32_t>(c.u64(3), put);
        return 1;
    });
    K("CloseHandle", [this](WinCall& c) -> uint64_t {
        return closeHandle(c.u64(0)) ? 1 : 0;
    });
    K("GetStdHandle", [](WinCall& c) -> uint64_t {
        const int32_t which = c.i32(0);
        if (which == -10) return 0;   // stdin
        if (which == -11) return 1;   // stdout
        if (which == -12) return 2;   // stderr
        return kInvalidHandle;
    });
    K("GetFileType", [](WinCall& c) -> uint64_t {
        return c.u64(0) <= 2 ? 2 /*CHAR*/ : 1 /*DISK*/;
    });
    K("GetFileSize", [this](WinCall& c) -> uint64_t {
        auto* rec = handle(c.u64(0));
        if (!rec || rec->fd < 0) { setLastError(6); return 0xFFFFFFFFu; }
        off_t cur = ::lseek(rec->fd, 0, SEEK_CUR);
        off_t end = ::lseek(rec->fd, 0, SEEK_END);
        ::lseek(rec->fd, cur, SEEK_SET);
        if (end < 0) { setLastError(5); return 0xFFFFFFFFu; }
        if (c.u64(1)) c.put<uint32_t>(c.u64(1), static_cast<uint32_t>(static_cast<uint64_t>(end) >> 32));
        return static_cast<uint64_t>(end) & 0xFFFFFFFFu;
    });
    K("GetFileSizeEx", [this](WinCall& c) -> uint64_t {
        auto* rec = handle(c.u64(0));
        if (!rec || rec->fd < 0) { setLastError(6); return 0; }
        off_t cur = ::lseek(rec->fd, 0, SEEK_CUR);
        off_t end = ::lseek(rec->fd, 0, SEEK_END);
        ::lseek(rec->fd, cur, SEEK_SET);
        if (end < 0) { setLastError(5); return 0; }
        const int64_t v = static_cast<int64_t>(end);
        return c.put<int64_t>(c.u64(1), v) ? 1 : 0;
    });
    K("SetFilePointer", [this](WinCall& c) -> uint64_t {
        auto* rec = handle(c.u64(0));
        if (!rec || rec->fd < 0) { setLastError(6); return 0xFFFFFFFFu; }
        const int32_t lo = c.i32(1);
        const int32_t hi = c.i32(2);
        const uint32_t method = c.u32(3);
        const int64_t delta = (static_cast<int64_t>(hi) << 32) |
                              static_cast<uint32_t>(lo);
        const int whence = method == 1 ? SEEK_CUR : method == 2 ? SEEK_END : SEEK_SET;
        off_t r = ::lseek(rec->fd, static_cast<off_t>(delta), whence);
        if (r < 0) { setLastError(87); return 0xFFFFFFFFu; }
        return static_cast<uint64_t>(r);
    });
    K("SetFilePointerEx", [this](WinCall& c) -> uint64_t {
        auto* rec = handle(c.u64(0));
        if (!rec || rec->fd < 0) { setLastError(6); return 0; }
        int64_t delta = 0;
        c.get<int64_t>(c.u64(1), delta);
        const uint32_t method = c.u32(2);
        const int whence = method == 1 ? SEEK_CUR : method == 2 ? SEEK_END : SEEK_SET;
        off_t r = ::lseek(rec->fd, static_cast<off_t>(delta), whence);
        if (r < 0) { setLastError(87); return 0; }
        if (c.u64(3)) c.put<int64_t>(c.u64(3), static_cast<int64_t>(r));
        return 1;
    });
    K("FlushFileBuffers", [this](WinCall& c) -> uint64_t {
        auto* rec = handle(c.u64(0));
        if (rec && rec->fd >= 0) ::fsync(rec->fd);
        return 1;
    });
    K("DeleteFileA", [this](WinCall& c) -> uint64_t {
        const int r = ::unlink(toHostPath(c.ansi(0)).c_str());
        if (r != 0) { setLastError(2); return 0; }
        return 1;
    });
    K("DeleteFileW", [this](WinCall& c) -> uint64_t {
        const int r = ::unlink(toHostPath(utf16ToUtf8(c.wide(0))).c_str());
        if (r != 0) { setLastError(2); return 0; }
        return 1;
    });

    // ---- memory -----------------------------------------------------------
    K("VirtualAlloc", [this](WinCall& c) -> uint64_t {
        return virtualAlloc(c.u64(0), static_cast<size_t>(c.u64(1)), c.u32(3));
    });
    K("VirtualFree", [this](WinCall& c) -> uint64_t {
        return virtualFree(c.u64(0)) ? 1 : 0;
    });
    K("VirtualProtect", [this](WinCall& c) -> uint64_t {
        const bool ok = virtualProtect(c.u64(0), static_cast<size_t>(c.u64(1)), c.u32(2));
        if (ok && c.u64(3)) c.put<uint32_t>(c.u64(3), c.u32(2));
        return ok ? 1 : 0;
    });
    K("VirtualQuery", [this](WinCall& c) -> uint64_t {
        const uint64_t addr = c.u64(0);
        const uint64_t out = c.u64(1);
        const uint64_t len = c.u64(2);
        if (!out || len < 48) { setLastError(87); return 0; }
        auto region = mm_.query(addr);
        uint8_t buf[48] = {};
        uint32_t protect = 0x04;   // PAGE_READWRITE
        uint64_t base = addr & ~0xFFFULL;
        uint64_t size = 0x1000;
        uint32_t state = 0x10000;  // MEM_FREE
        if (region) {
            base = region->guest_start;
            size = region->guest_end - region->guest_start;
            state = 0x1000;        // MEM_COMMIT
            if (hasPerm(region->perms, PagePerm::EXEC)) protect = 0x20;
            if (region->perms == PagePerm::NONE) protect = 0x01;
        }
        std::memcpy(buf + 0, &base, 8);
        std::memcpy(buf + 8, &base, 8);
        std::memcpy(buf + 16, &protect, 4);
        std::memcpy(buf + 24, &size, 8);
        std::memcpy(buf + 32, &state, 4);
        const uint32_t type = 0x20000;  // MEM_PRIVATE
        std::memcpy(buf + 36, &type, 4);
        std::memcpy(buf + 40, &protect, 4);
        if (!c.writable(out, 48)) { setLastError(87); return 0; }
        std::memcpy(mm_.guestToHost(out), buf, 48);
        return 48;
    });

    // ---- errors, identity, info ------------------------------------------
    K("GetLastError", [this](WinCall&) -> uint64_t { return getLastError(); });
    K("SetLastError", [this](WinCall& c) -> uint64_t { setLastError(c.u32(0)); return 0; });
    K("GetCurrentProcess", [](WinCall&) -> uint64_t { return kPseudoProcess; });
    K("GetCurrentThread", [](WinCall&) -> uint64_t { return kPseudoThread; });
    K("GetCurrentProcessId", [this](WinCall&) -> uint64_t {
        if (!nt_.teb().pid) nt_.teb().pid = static_cast<uint32_t>(::getpid());
        return nt_.teb().pid;
    });
    K("GetCurrentThreadId", [this](WinCall&) -> uint64_t {
        if (!nt_.teb().tid) nt_.teb().tid = static_cast<uint32_t>(::getpid());
        return nt_.teb().tid;
    });
    K("IsDebuggerPresent", [](WinCall&) -> uint64_t { return 0; });
    K("SetUnhandledExceptionFilter", [](WinCall&) -> uint64_t { return 0; });
    K("EncodePointer", [](WinCall& c) -> uint64_t { return c.u64(0); });
    K("DecodePointer", [](WinCall& c) -> uint64_t { return c.u64(0); });
    K("GetACP", [](WinCall&) -> uint64_t { return 1252; });
    K("GetOEMCP", [](WinCall&) -> uint64_t { return 437; });
    K("GetConsoleOutputCP", [](WinCall&) -> uint64_t { return 437; });
    K("GetVersion", [](WinCall&) -> uint64_t { return 0x0A000000ULL | 19041ULL; });
    K("IsProcessorFeaturePresent", [](WinCall& c) -> uint64_t {
        const uint32_t f = c.u32(0);
        // MMX, SSE, SSE2, SSE3, SSE4.1, SSE4.2, AVX, XSAVE: all assumed present.
        switch (f) {
            case 0: case 1: case 10: case 13: case 17: case 19:
            case 20: case 21: case 22: case 39: case 40:
                return 1;
            default:
                return 0;
        }
    });
    K("GetSystemInfo", [](WinCall& c) -> uint64_t {
        const uint64_t out = c.u64(0);
        uint8_t buf[48] = {};
        auto w32 = [&](int off, uint32_t v) { std::memcpy(buf + off, &v, 4); };
        w32(0, 9);                    // PROCESSOR_ARCHITECTURE_AMD64
        w32(4, 4096);                 // dwPageSize
        w32(8, 0x10000);              // dwMinimumApplicationAddress
        w32(12, 0x7FFFFFFE);          // dwMaximumApplicationAddress
        w32(16, 0x00000001);          // dwActiveProcessorMask
        w32(20, 1);                   // dwNumberOfProcessors
        w32(24, 8664);                // dwProcessorType
        w32(28, 0x10000);             // dwAllocationGranularity
        w32(32, 6);                   // dwProcessorLevel
        w32(36, 0x3F);                // dwProcessorRevision
        if (!c.writable(out, 48)) return 0;
        std::memcpy(c.mm.guestToHost(out), buf, 48);
        return 0;
    });
    K("OutputDebugStringA", [](WinCall& c) -> uint64_t {
        Logger::instance().info(LogCategory::ABI,
                                ("DebugString: " + c.ansi(0)).c_str());
        return 0;
    });
    K("OutputDebugStringW", [](WinCall& c) -> uint64_t {
        Logger::instance().info(LogCategory::ABI,
                                ("DebugString: " + utf16ToUtf8(c.wide(0))).c_str());
        return 0;
    });

    // ---- time -------------------------------------------------------------
    K("QueryPerformanceFrequency", [](WinCall& c) -> uint64_t {
        return c.put<int64_t>(c.u64(0), 1000000000LL) ? 1 : 0;
    });
    K("QueryPerformanceCounter", [](WinCall& c) -> uint64_t {
        const int64_t v = static_cast<int64_t>(qpcNow());
        return c.put<int64_t>(c.u64(0), v) ? 1 : 0;
    });
    K("GetTickCount", [](WinCall&) -> uint64_t {
        return static_cast<uint32_t>(qpcNow() / 1000000ULL);
    });
    K("GetTickCount64", [](WinCall&) -> uint64_t {
        return qpcNow() / 1000000ULL;
    });
    K("GetSystemTimeAsFileTime", [](WinCall& c) -> uint64_t {
        const uint64_t ft = fileTimeNow();
        c.put<uint32_t>(c.u64(0), static_cast<uint32_t>(ft));
        c.put<uint32_t>(c.u64(0) + 4, static_cast<uint32_t>(ft >> 32));
        return 0;
    });
    K("GetSystemTime", [](WinCall& c) -> uint64_t {
        if (c.writable(c.u64(0), 16)) fillSystemTime((uint8_t*)c.mm.guestToHost(c.u64(0)), false);
        return 0;
    });
    K("GetLocalTime", [](WinCall& c) -> uint64_t {
        if (c.writable(c.u64(0), 16)) fillSystemTime((uint8_t*)c.mm.guestToHost(c.u64(0)), true);
        return 0;
    });

    // ---- process environment ---------------------------------------------
    K("GetCommandLineA", [this](WinCall&) -> uint64_t {
        if (!cmdline_ptr_a_) {
            cmdline_ptr_a_ = mm_.allocate(0, cmdline_.size() + 1, PagePerm::READ_WRITE,
                                          "cmdline");
            if (cmdline_ptr_a_) std::memcpy(mm_.guestToHost(cmdline_ptr_a_),
                                            cmdline_.c_str(), cmdline_.size() + 1);
        }
        return cmdline_ptr_a_;
    });
    K("GetCommandLineW", [this](WinCall&) -> uint64_t {
        if (!cmdline_ptr_w_) {
            const std::u16string u = utf8ToUtf16(cmdline_);
            cmdline_ptr_w_ = mm_.allocate(0, (u.size() + 1) * 2, PagePerm::READ_WRITE,
                                          "cmdlineW");
            if (cmdline_ptr_w_) {
                auto* p = static_cast<uint8_t*>(mm_.guestToHost(cmdline_ptr_w_));
                for (size_t k = 0; k < u.size(); ++k) {
                    p[2 * k] = static_cast<uint8_t>(u[k] & 0xFF);
                    p[2 * k + 1] = static_cast<uint8_t>(u[k] >> 8);
                }
                p[2 * u.size()] = 0;
                p[2 * u.size() + 1] = 0;
            }
        }
        return cmdline_ptr_w_;
    });
    K("GetEnvironmentVariableA", [this](WinCall& c) -> uint64_t {
        const std::string name = c.ansi(0);
        auto it = env_.find(name);
        if (it == env_.end()) { setLastError(203); return 0; }
        const uint64_t buf = c.u64(1);
        const uint32_t cap = c.u32(2);
        const uint32_t need = static_cast<uint32_t>(it->second.size()) + 1;
        if (cap == 0 || !buf) return need;
        if (cap < need) { setLastError(122); return need; }
        c.putAnsi(buf, cap, it->second);
        return need - 1;
    });
    K("GetEnvironmentVariableW", [this](WinCall& c) -> uint64_t {
        const std::string name = utf16ToUtf8(c.wide(0));
        auto it = env_.find(name);
        if (it == env_.end()) { setLastError(203); return 0; }
        const std::u16string v = utf8ToUtf16(it->second);
        const uint32_t need = static_cast<uint32_t>(v.size()) + 1;
        if (c.u32(2) == 0 || !c.u64(1)) return need;
        if (c.u32(2) < need) { setLastError(122); return need; }
        c.putWide(c.u64(1), c.u32(2), v);
        return need - 1;
    });
    K("SetEnvironmentVariableA", [this](WinCall& c) -> uint64_t {
        const std::string name = c.ansi(0);
        const uint64_t v = c.u64(1);
        if (v) env_[name] = c.ansi(1);
        else env_.erase(name);
        return 1;
    });
    K("SetEnvironmentVariableW", [this](WinCall& c) -> uint64_t {
        const std::string name = utf16ToUtf8(c.wide(0));
        const uint64_t v = c.u64(1);
        if (v) env_[name] = utf16ToUtf8(c.wide(1));
        else env_.erase(name);
        return 1;
    });
    K("GetEnvironmentStringsW", [this](WinCall& c) -> uint64_t {
        (void)c;
        std::u16string block;
        for (const auto& kv : env_) {
            block += utf8ToUtf16(kv.first + "=" + kv.second);
            block.push_back(u'\0');
        }
        block.push_back(u'\0');
        const uint64_t p = mm_.allocate(0, (block.size() + 1) * 2, PagePerm::READ_WRITE,
                                        "env block");
        if (!p) return 0;
        auto* q = static_cast<uint8_t*>(mm_.guestToHost(p));
        for (size_t k = 0; k < block.size(); ++k) {
            q[2 * k] = static_cast<uint8_t>(block[k] & 0xFF);
            q[2 * k + 1] = static_cast<uint8_t>(block[k] >> 8);
        }
        return p;
    });
    K("FreeEnvironmentStringsW", [](WinCall&) -> uint64_t { return 1; });
    K("GetStartupInfoA", [](WinCall& c) -> uint64_t {
        const uint64_t out = c.u64(0);
        if (!c.writable(out, 104)) return 0;
        std::memset(c.mm.guestToHost(out), 0, 104);
        c.put<uint32_t>(out, 104);                    // cb
        c.put<uint32_t>(out + 60, 1);                 // dwFlags = STARTF_USESTDHANDLES
        c.put<uint64_t>(out + 80, 0);                 // hStdInput
        c.put<uint64_t>(out + 88, 1);                 // hStdOutput
        c.put<uint64_t>(out + 96, 2);                 // hStdError
        return 0;
    });
    K("GetStartupInfoW", [](WinCall& c) -> uint64_t {
        const uint64_t out = c.u64(0);
        if (!c.writable(out, 104)) return 0;
        std::memset(c.mm.guestToHost(out), 0, 104);
        c.put<uint32_t>(out, 104);
        c.put<uint32_t>(out + 60, 1);
        return 0;
    });

    // ---- threads, waits, synchronisation ----------------------------------
    K("CreateThread", [this](WinCall& c) -> uint64_t {
        const uint64_t h = createThread(c.u64(2), c.u64(3));
        if (h && c.u64(6)) c.put<uint32_t>(c.u64(6), 0);
        return h;
    });
    K("Sleep", [](WinCall& c) -> uint64_t {
        const uint32_t ms = c.u32(0);
        if (ms == 0xFFFFFFFFu) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        else if (ms) std::this_thread::sleep_for(std::chrono::milliseconds(ms));
        return 0;
    });
    K("SwitchToThread", [](WinCall&) -> uint64_t {
        std::this_thread::yield();
        return 1;
    });
    K("CreateEventA", [this](WinCall& c) -> uint64_t {
        return createEvent(c.z(1), c.z(2), c.ansi(3));
    });
    K("CreateEventW", [this](WinCall& c) -> uint64_t {
        return createEvent(c.z(1), c.z(2), utf16ToUtf8(c.wide(3)));
    });
    K("SetEvent", [this](WinCall& c) -> uint64_t {
        return setEvent(c.u64(0), true) ? 1 : 0;
    });
    K("ResetEvent", [this](WinCall& c) -> uint64_t {
        return setEvent(c.u64(0), false) ? 1 : 0;
    });
    K("WaitForSingleObject", [this](WinCall& c) -> uint64_t {
        return waitForSingleObject(c.u64(0), c.u32(1));
    });

    // ---- critical sections / SRW -----------------------------------------
    K("InitializeCriticalSection", [this](WinCall& c) -> uint64_t {
        nt_.rtlInitializeCriticalSection(c.u64(0));
        return 0;
    });
    K("InitializeCriticalSectionAndSpinCount", [this](WinCall& c) -> uint64_t {
        nt_.rtlInitializeCriticalSection(c.u64(0));
        return 1;
    });
    K("InitializeCriticalSectionEx", [this](WinCall& c) -> uint64_t {
        nt_.rtlInitializeCriticalSection(c.u64(0));
        return 1;
    });
    K("EnterCriticalSection", [this](WinCall& c) -> uint64_t {
        nt_.rtlEnterCriticalSection(c.u64(0));
        return 0;
    });
    K("TryEnterCriticalSection", [this](WinCall& c) -> uint64_t {
        // No contention model yet: the section is always available to us.
        nt_.rtlEnterCriticalSection(c.u64(0));
        return 1;
    });
    K("LeaveCriticalSection", [this](WinCall& c) -> uint64_t {
        nt_.rtlLeaveCriticalSection(c.u64(0));
        return 0;
    });
    K("DeleteCriticalSection", [this](WinCall& c) -> uint64_t {
        (void)c;
        return 0;
    });
    K("AcquireSRWLockExclusive", [this](WinCall& c) -> uint64_t {
        nt_.rtlAcquireSRWLockExclusive(c.u64(0));
        return 0;
    });
    K("ReleaseSRWLockExclusive", [this](WinCall& c) -> uint64_t {
        nt_.rtlReleaseSRWLockExclusive(c.u64(0));
        return 0;
    });
    K("AcquireSRWLockShared", [this](WinCall& c) -> uint64_t {
        nt_.rtlAcquireSRWLockExclusive(c.u64(0));
        return 0;
    });
    K("ReleaseSRWLockShared", [this](WinCall& c) -> uint64_t {
        nt_.rtlReleaseSRWLockExclusive(c.u64(0));
        return 0;
    });

    // ---- TLS --------------------------------------------------------------
    K("TlsAlloc", [this](WinCall&) -> uint64_t { return next_tls_++; });
    K("TlsGetValue", [this](WinCall& c) -> uint64_t {
        auto it = tls_.find(c.u32(0));
        return it == tls_.end() ? 0 : it->second;
    });
    K("TlsSetValue", [this](WinCall& c) -> uint64_t {
        tls_[c.u32(0)] = c.u64(1);
        return 1;
    });
    K("TlsFree", [this](WinCall& c) -> uint64_t {
        tls_.erase(c.u32(0));
        return 1;
    });

    // ---- heap -------------------------------------------------------------
    K("GetProcessHeap", [this](WinCall&) -> uint64_t {
        if (!nt_.peb().process_heap) nt_.rtlAllocateHeap(0, 0, 1);
        return nt_.peb().process_heap;
    });
    K("HeapCreate", [](WinCall& c) -> uint64_t {
        (void)c;
        return 0x00A00000ULL;
    });
    K("HeapDestroy", [](WinCall&) -> uint64_t { return 1; });
    K("HeapAlloc", [this](WinCall& c) -> uint64_t {
        uint64_t p = nt_.rtlAllocateHeap(c.u64(0), c.u32(1), static_cast<size_t>(c.u64(2)));
        if (p && (c.u32(1) & 0x8)) {  // HEAP_ZERO_MEMORY
            std::memset(mm_.guestToHost(p), 0, static_cast<size_t>(c.u64(2)));
        }
        return p;
    });
    K("HeapFree", [this](WinCall& c) -> uint64_t {
        return nt_.rtlFreeHeap(c.u64(0), c.u32(1), c.u64(2)) ? 1 : 0;
    });
    K("HeapReAlloc", [this](WinCall& c) -> uint64_t {
        const uint64_t old = c.u64(2);
        const size_t want = static_cast<size_t>(c.u64(3));
        void* host = mm_.guestToHost(old);
        if (!host) return 0;
        uint64_t p = nt_.rtlAllocateHeap(c.u64(0), c.u32(1), want);
        if (!p) return 0;
        // The old block's extent is not tracked here; copy what the caller
        // asked for and let the new block's zero-fill handle the rest.
        std::memcpy(mm_.guestToHost(p), host, want);
        nt_.rtlFreeHeap(c.u64(0), 0, old);
        return p;
    });
    K("HeapSize", [this](WinCall& c) -> uint64_t {
        auto region = mm_.query(c.u64(2));
        if (!region) return static_cast<uint64_t>(-1);
        return region->guest_end - region->guest_start;
    });

    // ---- text -------------------------------------------------------------
    K("MultiByteToWideChar", [](WinCall& c) -> uint64_t {
        const uint32_t cp = c.u32(0);
        const uint64_t src = c.u64(2);
        const int32_t src_len = c.i32(3);
        const std::string s = c.ansiAt(src, 65536);
        std::u16string u;
        if (cp == 65001) {
            u = utf8ToUtf16(s);
        } else {
            u.reserve(s.size());
            for (unsigned char ch : s) u.push_back(static_cast<char16_t>(ch));
        }
        size_t n = (src_len < 0) ? u.size() + 1 : std::min<size_t>(u.size(), src_len);
        if (c.u32(5) == 0) return n;
        if (c.u32(5) < n) return 0;
        c.putWide(c.u64(4), c.u32(5), u.substr(0, n));
        // With a negative source length the count includes the NUL, which the
        // copy helper does not report.
        return n;
    });
    K("WideCharToMultiByte", [](WinCall& c) -> uint64_t {
        const uint32_t cp = c.u32(0);
        const int32_t src_len = c.i32(2);
        const std::u16string u = c.wideAt(c.u64(1), 65536);
        std::u16string view = (src_len < 0) ? u : u.substr(0, std::min<size_t>(u.size(), src_len));
        std::string s;
        if (cp == 65001) {
            s = utf16ToUtf8(view);
        } else {
            s.reserve(view.size());
            for (char16_t ch : view) s.push_back(ch > 0xFF ? '?' : static_cast<char>(ch));
        }
        size_t n = (src_len < 0) ? s.size() + 1 : s.size();
        if (c.u32(5) == 0) return n;
        if (c.u32(5) < n) return 0;
        c.putAnsi(c.u64(4), c.u32(5), s);
        return n;
    });
    K("lstrlenA", [](WinCall& c) -> uint64_t { return c.ansi(0).size(); });
    K("lstrlenW", [](WinCall& c) -> uint64_t { return c.wide(0).size(); });
    K("lstrcpyA", [](WinCall& c) -> uint64_t {
        c.putAnsi(c.u64(0), 65536, c.ansi(1));
        return c.u64(0);
    });
    K("lstrcpyW", [](WinCall& c) -> uint64_t {
        c.putWide(c.u64(0), 32768, c.wide(1));
        return c.u64(0);
    });
    K("lstrcmpA", [](WinCall& c) -> uint64_t {
        const int r = c.ansi(0).compare(c.ansi(1));
        return static_cast<uint64_t>(static_cast<int64_t>(r < 0 ? -1 : r > 0 ? 1 : 0));
    });

    // ---- interlocked ------------------------------------------------------
    K("InterlockedIncrement", [](WinCall& c) -> uint64_t {
        auto* p = static_cast<int32_t*>(c.mm.guestToHost(c.u64(0)));
        if (!p) return 0;
        return static_cast<uint64_t>(static_cast<uint32_t>(++*p));
    });
    K("InterlockedDecrement", [](WinCall& c) -> uint64_t {
        auto* p = static_cast<int32_t*>(c.mm.guestToHost(c.u64(0)));
        if (!p) return 0;
        return static_cast<uint64_t>(static_cast<uint32_t>(--*p));
    });
    K("InterlockedExchange", [](WinCall& c) -> uint64_t {
        auto* p = static_cast<int32_t*>(c.mm.guestToHost(c.u64(0)));
        if (!p) return 0;
        return static_cast<uint64_t>(static_cast<uint32_t>(*p = static_cast<int32_t>(c.u32(1))));
    });
    K("InterlockedCompareExchange", [](WinCall& c) -> uint64_t {
        auto* p = static_cast<int32_t*>(c.mm.guestToHost(c.u64(0)));
        if (!p) return 0;
        int32_t expected = static_cast<int32_t>(c.u32(2));
        if (*p == expected) *p = static_cast<int32_t>(c.u32(1));
        return static_cast<uint64_t>(static_cast<uint32_t>(expected));
    });

    // ---- termination ------------------------------------------------------
    K("ExitProcess", [this](WinCall& c) -> uint64_t {
        exitProcess(c.u32(0));
        return 0;
    });
    K("ExitThread", [this](WinCall& c) -> uint64_t {
        Logger::instance().infof(LogCategory::ABI, "ExitThread %u", c.u32(0));
        return 0;
    });
    K("GetExitCodeProcess", [](WinCall& c) -> uint64_t {
        if (c.u64(1)) c.put<uint32_t>(c.u64(1), 0);
        return 1;
    });
}

void Kernel32::registerNtdllExports(WinAbi& w) {
    auto N = [&](const char* name, WinAbi::Handler h) {
        w.add("ntdll.dll", name, std::move(h));
    };

    N("RtlAllocateHeap", [this](WinCall& c) -> uint64_t {
        return nt_.rtlAllocateHeap(c.u64(0), c.u32(1), static_cast<size_t>(c.u64(2)));
    });
    N("RtlFreeHeap", [this](WinCall& c) -> uint64_t {
        return nt_.rtlFreeHeap(c.u64(0), c.u32(1), c.u64(2)) ? 1 : 0;
    });
    N("RtlZeroMemory", [](WinCall& c) -> uint64_t {
        const uint64_t dst = c.u64(0);
        const size_t n = static_cast<size_t>(c.u64(1));
        if (c.writable(dst, n)) std::memset(c.mm.guestToHost(dst), 0, n);
        return dst;
    });
    N("RtlFillMemory", [](WinCall& c) -> uint64_t {
        const uint64_t dst = c.u64(0);
        const size_t n = static_cast<size_t>(c.u64(1));
        if (c.writable(dst, n)) std::memset(c.mm.guestToHost(dst), c.u32(2), n);
        return dst;
    });
    N("RtlCopyMemory", [](WinCall& c) -> uint64_t {
        const uint64_t dst = c.u64(0);
        const uint64_t src = c.u64(1);
        const size_t n = static_cast<size_t>(c.u64(2));
        if (c.writable(dst, n) && c.readable(src, n))
            std::memcpy(c.mm.guestToHost(dst), c.mm.guestToHost(src), n);
        return dst;
    });
    N("RtlMoveMemory", [](WinCall& c) -> uint64_t {
        const uint64_t dst = c.u64(0);
        const uint64_t src = c.u64(1);
        const size_t n = static_cast<size_t>(c.u64(2));
        if (c.writable(dst, n) && c.readable(src, n))
            std::memmove(c.mm.guestToHost(dst), c.mm.guestToHost(src), n);
        return dst;
    });
    N("RtlInitializeCriticalSection", [this](WinCall& c) -> uint64_t {
        nt_.rtlInitializeCriticalSection(c.u64(0));
        return 0;
    });
    N("RtlEnterCriticalSection", [this](WinCall& c) -> uint64_t {
        nt_.rtlEnterCriticalSection(c.u64(0));
        return 0;
    });
    N("RtlLeaveCriticalSection", [this](WinCall& c) -> uint64_t {
        nt_.rtlLeaveCriticalSection(c.u64(0));
        return 0;
    });
    N("RtlAcquireSRWLockExclusive", [this](WinCall& c) -> uint64_t {
        nt_.rtlAcquireSRWLockExclusive(c.u64(0));
        return 0;
    });
    N("RtlReleaseSRWLockExclusive", [this](WinCall& c) -> uint64_t {
        nt_.rtlReleaseSRWLockExclusive(c.u64(0));
        return 0;
    });
    N("RtlCaptureStackBackTrace", [](WinCall& c) -> uint64_t {
        if (c.u64(4)) c.put<uint32_t>(c.u64(4), 0);
        return 0;
    });
    N("NtCurrentTeb", [this](WinCall&) -> uint64_t { return nt_.teb().self; });
}

} // namespace nexus
