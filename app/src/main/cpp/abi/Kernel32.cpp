#include "Kernel32.h"
#include "Threading.h"
#include "../diagnostics/Logger.h"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <thread>
#include <unistd.h>

namespace nexus {

namespace {
constexpr uint64_t kInvalidHandle = ~0ULL;
constexpr uint32_t kWaitObject0 = 0;
constexpr uint32_t kWaitTimeout = 0x102;
constexpr uint32_t kWaitFailed = 0xFFFFFFFF;
} // namespace

Kernel32::Kernel32(Ntdll& nt, MemoryManager& mm) : nt_(nt), mm_(mm) {
    nt_.setMemoryManager(&mm);
}

std::string Kernel32::lower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

void Kernel32::ensureAbi() {
    if (abi_) return;
    abi_ = std::make_unique<WinAbi>(mm_);
    registerExports(*abi_);
    registerNtdllExports(*abi_);
    registerShimExports(*abi_);
    Logger::instance().infof(LogCategory::ABI, "winabi: %zu exports, thunks @0x%llx",
                             abi_->exportCount(),
                             static_cast<unsigned long long>(abi_->thunkPage()));
}

bool Kernel32::isShimModule(const std::string& dll) const {
    static const char* kModules[] = {
        "kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
        "advapi32.dll", "shlwapi.dll", "shell32.dll", "comctl32.dll", "comdlg32.dll",
        "msvcrt.dll", "ucrtbase.dll", "ws2_32.dll", "ole32.dll", "oleaut32.dll",
        "version.dll", "userenv.dll", "psapi.dll", "dbghelp.dll", "winmm.dll",
    };
    const std::string l = lower(dll);
    for (const char* m : kModules)
        if (l == m) return true;
    return false;
}

HandleRec* Kernel32::handle(uint64_t h) {
    auto it = handles_.find(h);
    return it == handles_.end() ? nullptr : &it->second;
}

uint64_t Kernel32::getModuleHandle(const std::string& name) {
    if (name.empty()) return module_base_;
    for (const auto& e : nt_.ldr()) {
        if (lower(e.name) == lower(name)) return e.base;
    }
    const std::string l = lower(name);
    if (l == "kernel32.dll" || l == "kernelbase.dll") return module_base_;
    if (l == "ntdll.dll") return 0x7FFE0000;
    setLastError(126);  // ERROR_MOD_NOT_FOUND
    return 0;
}

uint64_t Kernel32::getProcAddress(uint64_t module, const std::string& name) {
    std::string dll = "kernel32.dll";
    for (const auto& e : nt_.ldr()) {
        if (e.base == module) { dll = e.name; break; }
    }
    ensureAbi();
    uint64_t thunk = abi_->resolve(dll, name);
    if (!thunk && lower(dll) != "kernel32.dll")
        thunk = abi_->resolve("kernel32.dll", name);
    if (!thunk) setLastError(127);  // ERROR_PROC_NOT_FOUND
    return thunk;
}

uint64_t Kernel32::loadLibrary(const std::string& name) {
    const std::string l = lower(name);
    for (const auto& e : nt_.ldr())
        if (lower(e.name) == l) return e.base;

    uint64_t base = 0x7FF10000 + nt_.ldr().size() * 0x10000;
    nt_.ldrAdd(l, base, 0x10000);
    ensureAbi();
    if (isShimModule(l)) {
        // Bind the module name itself too: GetProcAddress("user32.dll", …)
        // then resolves against the same registry.
        Logger::instance().infof(LogCategory::ABI, "winabi: module %s @0x%llx",
                                 l.c_str(), static_cast<unsigned long long>(base));
    }
    return base;
}

uint64_t Kernel32::createFile(const std::string& path, uint32_t access, uint32_t disposition) {
    int flags = 0;
    const bool rd = (access & 0x80000000u) != 0;
    const bool wr = (access & 0x40000000u) != 0;
    if (rd && wr) flags = O_RDWR;
    else if (wr) flags = O_WRONLY;
    else flags = O_RDONLY;

    // CREATE_ALWAYS(2) / CREATE_NEW(1) / OPEN_ALWAYS(4) all create.
    if (disposition == 1) flags |= O_CREAT | O_EXCL;
    else if (disposition == 2) flags |= O_CREAT | O_TRUNC;
    else if (disposition == 4) flags |= O_CREAT;

    int fd = ::open(path.c_str(), flags, 0644);
    if (fd < 0 && (disposition == 2 || disposition == 4)) {
        fd = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
    }
    if (fd < 0) {
        setLastError(2);  // ERROR_FILE_NOT_FOUND
        return kInvalidHandle;
    }
    const uint64_t h = next_handle_++;
    HandleRec rec;
    rec.kind = HandleRec::FILE;
    rec.fd = fd;
    rec.path = path;
    handles_[h] = rec;
    return h;
}

bool Kernel32::readFile(uint64_t h, void* buf, uint32_t len, uint32_t* read) {
    if (read) *read = 0;
    HandleRec* rec = handle(h);
    const int fd = rec ? rec->fd : ((h <= 2) ? static_cast<int>(h) : -1);
    if (fd < 0) { setLastError(6); return false; }   // ERROR_INVALID_HANDLE
    ssize_t r = ::read(fd, buf, len);
    if (r < 0) { setLastError(5); return false; }    // ERROR_ACCESS_DENIED
    if (read) *read = static_cast<uint32_t>(r);
    return true;
}

bool Kernel32::writeFile(uint64_t h, const void* buf, uint32_t len, uint32_t* written) {
    if (written) *written = 0;
    HandleRec* rec = handle(h);
    const int fd = rec ? rec->fd : ((h <= 2) ? static_cast<int>(h) : -1);
    if (fd < 0) { setLastError(6); return false; }
    ssize_t r = ::write(fd, buf, len);
    if (r < 0) { setLastError(5); return false; }
    if (written) *written = static_cast<uint32_t>(r);
    return true;
}

bool Kernel32::closeHandle(uint64_t h) {
    auto it = handles_.find(h);
    if (it == handles_.end()) {
        if (h <= 2) return true;   // pseudo console handles
        setLastError(6);
        return false;
    }
    if (it->second.kind == HandleRec::FILE && it->second.fd >= 0) ::close(it->second.fd);
    handles_.erase(it);
    return true;
}

uint64_t Kernel32::virtualAlloc(uint64_t addr, size_t size, uint32_t protect) {
    PagePerm perms = PagePerm::READ_WRITE;
    switch (protect & 0xFF) {
        case 0x01: perms = PagePerm::NONE; break;             // PAGE_NOACCESS
        case 0x02: perms = PagePerm::READ; break;             // PAGE_READONLY
        case 0x04: perms = PagePerm::READ_WRITE; break;       // PAGE_READWRITE
        case 0x10: perms = PagePerm::READ_EXEC; break;        // PAGE_EXECUTE
        case 0x20: perms = PagePerm::READ_WRITE_EXEC; break;  // PAGE_EXECUTE_READ
        case 0x40: perms = PagePerm::READ_WRITE_EXEC; break;  // PAGE_EXECUTE_READWRITE
        case 0x08: perms = PagePerm::READ_WRITE; break;       // PAGE_WRITECOPY
        default: break;
    }
    uint64_t g = mm_.allocate(addr, size, perms, "VirtualAlloc");
    if (!g) setLastError(8);  // ERROR_NOT_ENOUGH_MEMORY
    return g;
}

bool Kernel32::virtualFree(uint64_t addr) {
    if (!mm_.free(addr)) { setLastError(87); return false; }  // ERROR_INVALID_PARAMETER
    return true;
}

bool Kernel32::virtualProtect(uint64_t addr, size_t size, uint32_t protect) {
    PagePerm perms = PagePerm::READ_WRITE;
    switch (protect & 0xFF) {
        case 0x01: perms = PagePerm::NONE; break;
        case 0x02: perms = PagePerm::READ; break;
        case 0x04: perms = PagePerm::READ_WRITE; break;
        case 0x10: perms = PagePerm::READ_EXEC; break;
        case 0x20: perms = PagePerm::READ_WRITE_EXEC; break;
        case 0x40: perms = PagePerm::READ_WRITE_EXEC; break;
        default: break;
    }
    if (!mm_.protectRange(addr, size, perms)) { setLastError(87); return false; }
    return true;
}

uint32_t Kernel32::getLastError() { return nt_.teb().last_error; }
void Kernel32::setLastError(uint32_t err) { nt_.teb().last_error = err; }

void Kernel32::exitProcess(uint32_t code) {
    Logger::instance().infof(LogCategory::ABI, "ExitProcess %u", code);
}

uint64_t Kernel32::createThread(uint64_t start, uint64_t param) {
    Threading t;
    uint64_t h = 0;
    int tid = t.createThread(start, 0x100000, param, &h);
    if (tid < 0) { setLastError(8); return 0; }
    HandleRec rec;
    rec.kind = HandleRec::THREAD;
    rec.tid = static_cast<uint32_t>(tid);
    rec.signaled = false;
    const uint64_t handle = next_handle_++;
    handles_[handle] = rec;
    return handle;
}

uint64_t Kernel32::createEvent(bool manual_reset, bool initial, const std::string&) {
    HandleRec rec;
    rec.kind = HandleRec::EVENT;
    rec.manual_reset = manual_reset;
    rec.signaled = initial;
    const uint64_t h = (next_handle_++ * 4) + 1;
    handles_[h] = rec;
    return h;
}

bool Kernel32::setEvent(uint64_t h, bool state) {
    HandleRec* rec = handle(h);
    if (!rec || rec->kind != HandleRec::EVENT) { setLastError(6); return false; }
    rec->signaled = state;
    return true;
}

uint32_t Kernel32::waitForSingleObject(uint64_t h, uint32_t millis) {
    HandleRec* rec = handle(h);
    if (!rec) {
        // Pseudo handles: -1 (current process) and -2 (current thread) are
        // always signaled; an unknown handle fails.
        if (h == ~1ULL || h == ~2ULL) return kWaitObject0;
        setLastError(6);
        return kWaitFailed;
    }
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(millis == 0xFFFFFFFF ? 0 : millis);
    const bool infinite = (millis == 0xFFFFFFFF);
    for (;;) {
        if (rec->signaled) {
            if (!rec->manual_reset) rec->signaled = false;
            return kWaitObject0;
        }
        if (!infinite && std::chrono::steady_clock::now() >= deadline) return kWaitTimeout;
        if (millis == 0) return kWaitTimeout;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

uint64_t Kernel32::resolve(const std::string& name) {
    ensureAbi();
    uint64_t thunk = abi_->resolve("kernel32.dll", name);
    if (thunk) return thunk;
    // Unimplemented exports of a module we own still get a callable stub, so a
    // guest call is a logged no-op instead of a jump into unmapped memory.
    return abi_->addStub("kernel32.dll", name, 0);
}

} // namespace nexus
