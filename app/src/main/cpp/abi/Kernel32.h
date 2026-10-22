#pragma once

#include "Ntdll.h"
#include "../memory/MemoryManager.h"
#include <cstdint>
#include <string>
#include <unordered_map>

namespace nexus {

using WinFn = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t);

class Kernel32 {
public:
    explicit Kernel32(Ntdll& nt, MemoryManager& mm) : nt_(nt), mm_(mm) {}

    uint64_t getModuleHandle(const std::string& name);
    uint64_t getProcAddress(uint64_t module, const std::string& name);
    uint64_t loadLibrary(const std::string& name);

    uint64_t createFile(const std::string& path, uint32_t access);
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

    // Resolve a kernel32 export by name.
    uint64_t resolve(const std::string& name);

private:
    Ntdll& nt_;
    MemoryManager& mm_;
    std::unordered_map<uint64_t, int> handles_; // guest handle -> host fd
    uint64_t next_handle_ = 0x100;
    uint64_t module_base_ = 0x7ff00000;
};

} // namespace nexus
