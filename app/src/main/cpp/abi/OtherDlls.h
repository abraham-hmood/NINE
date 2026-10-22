#pragma once

#include "Kernel32.h"
#include <string>
#include <cstdint>

namespace nexus {

// kernelbase forwards to kernel32. user32/gdi32/advapi32 return minimal success
// or failure and log, so a GUI/crypto program does not immediately crash.
class OtherDlls {
public:
    explicit OtherDlls(Kernel32& k32) : k32_(k32) {}

    uint64_t resolve(const std::string& dll, const std::string& name);

private:
    Kernel32& k32_;
    uint64_t user32_base_ = 0x7ff20000;
    uint64_t gdi32_base_ = 0x7ff30000;
    uint64_t advapi32_base_ = 0x7ff40000;
};

} // namespace nexus
