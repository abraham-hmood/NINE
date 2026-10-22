#include "OtherDlls.h"
#include "../diagnostics/Logger.h"

namespace nexus {

uint64_t OtherDlls::resolve(const std::string& dll, const std::string& name) {
    if (dll == "kernelbase.dll") return k32_.resolve(name);
    if (dll == "user32.dll") {
        Logger::instance().infof(LogCategory::ABI, "user32!%s -> minimal", name.c_str());
        if (name == "MessageBoxA") return user32_base_ + 0x10;
        if (name == "GetDesktopWindow") return user32_base_ + 0x20;
        return user32_base_ + 0x30;
    }
    if (dll == "gdi32.dll") {
        Logger::instance().infof(LogCategory::ABI, "gdi32!%s -> minimal", name.c_str());
        return gdi32_base_ + 0x10;
    }
    if (dll == "advapi32.dll") {
        Logger::instance().infof(LogCategory::ABI, "advapi32!%s -> minimal", name.c_str());
        if (name == "RegOpenKeyExA") return 0; // failure, caller checks
        return advapi32_base_ + 0x10;
    }
    return 0;
}

} // namespace nexus
