#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace nexus {

// AT_* auxiliary vector entries (System V).
enum AuxType : uint64_t {
    AT_NULL = 0, AT_PHDR = 3, AT_PHENT = 4, AT_PHNUM = 5,
    AT_PAGESZ = 6, AT_BASE = 7, AT_ENTRY = 9, AT_UID = 11,
    AT_EUID = 12, AT_GID = 13, AT_EGID = 14, AT_CLKTCK = 17,
    AT_RANDOM = 25, AT_EXECFN = 31
};

struct AuxEntry { uint64_t type; uint64_t value; };

class Vdso {
public:
    // A minimal guest vDSO image. Returns the guest base it was placed at.
    // Provides gettimeofday / clock_gettime symbols so the dynamic linker can bind them.
    uint64_t base() const { return base_; }
    void setBase(uint64_t b) { base_ = b; }
    uint64_t gettimeofday() const { return base_ + 0x100; }
    uint64_t clock_gettime() const { return base_ + 0x200; }
private:
    uint64_t base_ = 0x7ffff000;
};

class StackSetup {
public:
    // Build the System V initial stack: argc, argv[], 0, envp[], 0, auxv[], AT_NULL.
    // Writes into `stack` (guest memory) growing down from `sp`. Returns the new SP.
    static uint64_t build(uint8_t* stack_top, uint64_t sp,
                          const std::vector<std::string>& argv,
                          const std::vector<std::string>& envp,
                          const std::vector<AuxEntry>& auxv);
};

} // namespace nexus
