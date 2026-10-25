#pragma once

#include "Kernel32.h"
#include <cstdint>
#include <string>

namespace nexus {

// Every non-kernel32 module NINE serves. Handlers are registered into the same
// WinAbi registry as kernel32, so all of them get real callable thunks.
//
// Unknown exports of a module we own are bound to a logging stub: the guest
// call succeeds (returns 0, i.e. failure) instead of jumping into unmapped
// memory, and every such name lands in the log as the next thing to implement.
class OtherDlls {
public:
    explicit OtherDlls(Kernel32& k32) : k32_(k32) {}

    void registerExports(WinAbi& abi);
    uint64_t resolve(const std::string& dll, const std::string& name);

private:
    Kernel32& k32_;
    bool stub_modules_registered_ = false;
};

} // namespace nexus
