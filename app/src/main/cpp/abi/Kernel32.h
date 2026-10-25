#pragma once

#include "Ntdll.h"
#include "WinAbi.h"
#include "../memory/MemoryManager.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace nexus {

// A Windows handle. Handles are opaque to the guest, so what lives behind them
// is entirely ours; the important part is that the value never truncates when
// a guest stores it in a DWORD.
struct HandleRec {
    enum Kind : uint8_t { FILE, EVENT, THREAD, SECTION } kind = FILE;
    int fd = -1;
    bool manual_reset = false;
    bool signaled = false;
    uint32_t tid = 0;
    std::string path;
};

class Kernel32 {
public:
    Kernel32(Ntdll& nt, MemoryManager& mm);

    // Lazily builds the thunk table and registers every implemented export.
    WinAbi& abi() { ensureAbi(); return *abi_; }

    uint64_t getModuleHandle(const std::string& name);
    uint64_t getProcAddress(uint64_t module, const std::string& name);
    uint64_t loadLibrary(const std::string& name);

    uint64_t createFile(const std::string& path, uint32_t access, uint32_t disposition = 3);
    bool readFile(uint64_t handle, void* buf, uint32_t len, uint32_t* read);
    bool writeFile(uint64_t handle, const void* buf, uint32_t len, uint32_t* written);
    bool closeHandle(uint64_t handle);

    uint64_t virtualAlloc(uint64_t addr, size_t size, uint32_t protect);
    bool virtualFree(uint64_t addr);
    bool virtualProtect(uint64_t addr, size_t size, uint32_t protect);

    uint32_t getLastError();
    void setLastError(uint32_t err);
    void exitProcess(uint32_t code);

    uint64_t createThread(uint64_t start, uint64_t param);

    // Waitable objects (events today; the wait path is shared).
    uint64_t createEvent(bool manual_reset, bool initial, const std::string& name);
    bool setEvent(uint64_t handle, bool state);
    // Returns a WAIT_* code (0 = OBJECT_0, 0x102 = TIMEOUT, 0xFFFFFFFF = fail).
    uint32_t waitForSingleObject(uint64_t handle, uint32_t millis);

    // Resolve a kernel32 export by name — now a real guest-callable thunk.
    uint64_t resolve(const std::string& name);

    // Called by OtherDlls for unknown modules; 0 means "not one of ours".
    bool isShimModule(const std::string& dll) const;

    MemoryManager& mem() { return mm_; }
    Ntdll& nt() { return nt_; }
    uint64_t moduleBase() const { return module_base_; }
    const std::string& commandLine() const { return cmdline_; }
    void setCommandLine(const std::string& s) { cmdline_ = s; }
    const std::unordered_map<std::string, std::string>& environment() const { return env_; }

    void registerExports(WinAbi& abi);
    void registerNtdllExports(WinAbi& abi);

private:
    Ntdll& nt_;
    MemoryManager& mm_;
    std::unique_ptr<WinAbi> abi_;
    std::unordered_map<uint64_t, HandleRec> handles_;
    uint64_t next_handle_ = 0x100;
    uint64_t module_base_ = 0x7ff00000;
    std::string cmdline_ = "nine.exe";
    std::unordered_map<std::string, std::string> env_;
    std::unordered_map<uint32_t, uint64_t> tls_;
    uint32_t next_tls_ = 1;
    uint64_t next_event_ = 0x1000;
    uint64_t cmdline_ptr_a_ = 0;
    uint64_t cmdline_ptr_w_ = 0;

    void ensureAbi();
    HandleRec* handle(uint64_t h);
    static std::string lower(std::string s);
};

// user32/gdi32/advapi32 handlers live in OtherDlls.cpp but are part of the same
// registry, so every module a PE imports is served by one thunk table.
void registerShimExports(WinAbi& abi);

} // namespace nexus
