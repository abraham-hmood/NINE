#include "Kernel32.h"
#include "Threading.h"
#include "../diagnostics/Logger.h"
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <chrono>
#include <thread>

namespace nexus {

uint64_t Kernel32::getModuleHandle(const std::string& name) {
    for (const auto& e : nt_.ldr()) {
        if (e.name == name) return e.base;
        // case-insensitive-ish compare for .dll
        if (e.name.size() == name.size()) {
            bool eq = true;
            for (size_t i = 0; i < name.size(); ++i) {
                char a = e.name[i], b = name[i];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) { eq = false; break; }
            }
            if (eq) return e.base;
        }
    }
    if (name.empty() || name == "kernel32.dll" || name == "KERNEL32.DLL")
        return module_base_;
    if (name == "ntdll.dll" || name == "NTDLL.DLL")
        return 0x7FFE0000;
    setLastError(126);
    return 0;
}

uint64_t Kernel32::getProcAddress(uint64_t module, const std::string& name) {
    (void)module;
    return resolve(name);
}

uint64_t Kernel32::loadLibrary(const std::string& name) {
    for (const auto& e : nt_.ldr())
        if (e.name == name) return e.base;
    uint64_t base = 0x7ff10000 + nt_.ldr().size() * 0x10000;
    nt_.ldrAdd(name, base, 0x10000);
    return base;
}

uint64_t Kernel32::createFile(const std::string& path, uint32_t access) {
    int flags = O_RDONLY;
    if (access & 0x40000000) flags = O_RDWR;       // GENERIC_WRITE
    if (access & 0x80000000) flags = O_RDONLY;     // GENERIC_READ
    if ((access & 0xC0000000) == 0xC0000000) flags = O_RDWR;
    int fd = ::open(path.c_str(), flags, 0644);
    if (fd < 0) {
        // try create
        fd = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
    }
    if (fd < 0) { setLastError(2); return ~0ULL; }
    uint64_t h = next_handle_++;
    handles_[h] = fd;
    return h;
}

bool Kernel32::readFile(uint64_t handle, void* buf, uint32_t len, uint32_t* read) {
    auto it = handles_.find(handle);
    if (it == handles_.end()) {
        // std handles
        if (handle == 0 || handle == 1 || handle == 2) {
            ssize_t r = ::read(static_cast<int>(handle), buf, len);
            if (r < 0) { setLastError(5); return false; }
            if (read) *read = static_cast<uint32_t>(r);
            return true;
        }
        setLastError(6);
        return false;
    }
    ssize_t r = ::read(it->second, buf, len);
    if (r < 0) { setLastError(5); return false; }
    if (read) *read = static_cast<uint32_t>(r);
    return true;
}

bool Kernel32::writeFile(uint64_t handle, const void* buf, uint32_t len, uint32_t* written) {
    int fd = -1;
    if (handle <= 2) fd = static_cast<int>(handle);
    else {
        auto it = handles_.find(handle);
        if (it == handles_.end()) { setLastError(6); return false; }
        fd = it->second;
    }
    ssize_t r = ::write(fd, buf, len);
    if (r < 0) { setLastError(5); return false; }
    if (written) *written = static_cast<uint32_t>(r);
    return true;
}

bool Kernel32::closeHandle(uint64_t handle) {
    auto it = handles_.find(handle);
    if (it == handles_.end()) return true;
    ::close(it->second);
    handles_.erase(it);
    return true;
}

uint64_t Kernel32::virtualAlloc(uint64_t addr, size_t size, uint32_t protect) {
    PagePerm perms = PagePerm::READ_WRITE;
    if (protect & 0x10) perms = PagePerm::READ_EXEC;       // PAGE_EXECUTE
    if (protect & 0x20) perms = PagePerm::READ_WRITE_EXEC; // PAGE_EXECUTE_READ
    if (protect & 0x40) perms = PagePerm::READ_WRITE_EXEC; // PAGE_EXECUTE_READWRITE
    uint64_t g = mm_.allocate(addr, size, perms, "VirtualAlloc");
    if (!g) setLastError(8); // ERROR_NOT_ENOUGH_MEMORY
    return g;
}

bool Kernel32::virtualFree(uint64_t addr) {
    return mm_.free(addr);
}

bool Kernel32::virtualProtect(uint64_t addr, size_t size, uint32_t protect) {
    PagePerm perms = PagePerm::READ_WRITE;
    if (protect & 0x10) perms = PagePerm::READ_EXEC;
    if (protect & 0x20) perms = PagePerm::READ_WRITE_EXEC;
    if (protect & 0x40) perms = PagePerm::READ_WRITE_EXEC;
    if (protect == 0x01) perms = PagePerm::NONE; // PAGE_NOACCESS
    if (protect == 0x02) perms = PagePerm::READ;
    return mm_.protectRange(addr, size, perms);
}

uint32_t Kernel32::getLastError() { return nt_.teb().last_error; }
void Kernel32::setLastError(uint32_t err) { nt_.teb().last_error = err; }

void Kernel32::exitProcess(uint32_t code) {
    Logger::instance().infof(LogCategory::ABI, "ExitProcess %u", code);
}

uint64_t Kernel32::createThread(uint64_t start, uint64_t param) {
    Threading t;
    uint64_t handle = 0;
    int tid = t.createThread(start, 0x100000, param, &handle);
    if (tid < 0) { setLastError(8); return 0; }
    return handle ? handle : static_cast<uint64_t>(tid);
}

uint64_t Kernel32::resolve(const std::string& name) {
    // Return stable fake addresses for known exports (IAT patching targets).
    static const std::unordered_map<std::string, uint64_t> kExports = {
        {"GetModuleHandleA", 0x7ff00010}, {"GetModuleHandleW", 0x7ff00018},
        {"GetProcAddress", 0x7ff00020}, {"LoadLibraryA", 0x7ff00028},
        {"LoadLibraryW", 0x7ff00030}, {"CreateFileA", 0x7ff00038},
        {"CreateFileW", 0x7ff00040}, {"ReadFile", 0x7ff00048},
        {"WriteFile", 0x7ff00050}, {"CloseHandle", 0x7ff00058},
        {"VirtualAlloc", 0x7ff00060}, {"VirtualFree", 0x7ff00068},
        {"VirtualProtect", 0x7ff00070}, {"GetLastError", 0x7ff00078},
        {"SetLastError", 0x7ff00080}, {"ExitProcess", 0x7ff00088},
        {"CreateThread", 0x7ff00090}, {"GetStdHandle", 0x7ff00098},
        {"Sleep", 0x7ff000A0}, {"GetCurrentProcessId", 0x7ff000A8},
        {"GetCurrentThreadId", 0x7ff000B0}, {"QueryPerformanceCounter", 0x7ff000B8},
        {"QueryPerformanceFrequency", 0x7ff000C0}, {"GetTickCount", 0x7ff000C8},
        {"GetTickCount64", 0x7ff000D0}, {"HeapAlloc", 0x7ff000D8},
        {"HeapFree", 0x7ff000E0}, {"GetProcessHeap", 0x7ff000E8},
        {"TlsAlloc", 0x7ff000F0}, {"TlsGetValue", 0x7ff000F8},
        {"TlsSetValue", 0x7ff00100}, {"TlsFree", 0x7ff00108},
        {"InitializeCriticalSection", 0x7ff00110},
        {"EnterCriticalSection", 0x7ff00118},
        {"LeaveCriticalSection", 0x7ff00120},
        {"DeleteCriticalSection", 0x7ff00128},
        {"MultiByteToWideChar", 0x7ff00130},
        {"WideCharToMultiByte", 0x7ff00138},
        {"GetCommandLineA", 0x7ff00140},
        {"GetCommandLineW", 0x7ff00148},
        {"GetEnvironmentVariableA", 0x7ff00150},
        {"SetEnvironmentVariableA", 0x7ff00158},
        {"IsDebuggerPresent", 0x7ff00160},
        {"GetSystemTimeAsFileTime", 0x7ff00168},
        {"GetStartupInfoA", 0x7ff00170},
        {"GetStartupInfoW", 0x7ff00178},
    };
    auto it = kExports.find(name);
    if (it != kExports.end()) return it->second;
    Logger::instance().warn(LogCategory::ABI, ("kernel32 unresolved: " + name).c_str());
    return 0;
}

} // namespace nexus
