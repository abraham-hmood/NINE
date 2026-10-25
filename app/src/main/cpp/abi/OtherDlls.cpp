#include "OtherDlls.h"
#include "../diagnostics/Logger.h"
#include <cstring>

namespace nexus {

namespace {

std::string lower(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    return s;
}

} // namespace

void registerShimExports(WinAbi& w) {
    // ---- user32 -----------------------------------------------------------
    w.add("user32.dll", "MessageBoxA", [](WinCall& c) -> uint64_t {
        Logger::instance().info(LogCategory::ABI,
                                ("MessageBoxA: " + c.ansi(1) + " / " + c.ansi(2)).c_str());
        return 1;  // IDOK
    });
    w.add("user32.dll", "MessageBoxW", [](WinCall& c) -> uint64_t {
        Logger::instance().info(LogCategory::ABI,
                                ("MessageBoxW: " + utf16ToUtf8(c.wide(1)) + " / " +
                                 utf16ToUtf8(c.wide(2))).c_str());
        return 1;
    });
    w.add("user32.dll", "GetDesktopWindow", [](WinCall&) -> uint64_t { return 0x10000; });
    w.add("user32.dll", "GetForegroundWindow", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "GetActiveWindow", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "GetSystemMetrics", [](WinCall& c) -> uint64_t {
        switch (c.i32(0)) {
            case 0: return 1920;   // SM_CXSCREEN
            case 1: return 1080;   // SM_CYSCREEN
            default: return 0;
        }
    });
    w.add("user32.dll", "CreateWindowExA", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "CreateWindowExW", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "RegisterClassA", [](WinCall&) -> uint64_t { return 1; });
    w.add("user32.dll", "RegisterClassW", [](WinCall&) -> uint64_t { return 1; });
    w.add("user32.dll", "RegisterClassExA", [](WinCall&) -> uint64_t { return 1; });
    w.add("user32.dll", "RegisterClassExW", [](WinCall&) -> uint64_t { return 1; });
    w.add("user32.dll", "DefWindowProcA", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "DefWindowProcW", [](WinCall&) -> uint64_t { return 0; });
    // No message pump yet: GetMessage returning 0 ends a standard WinMain loop
    // cleanly instead of spinning forever.
    w.add("user32.dll", "GetMessageA", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "GetMessageW", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "PeekMessageA", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "PeekMessageW", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "TranslateMessage", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "DispatchMessageA", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "DispatchMessageW", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "PostQuitMessage", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "ShowWindow", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "UpdateWindow", [](WinCall&) -> uint64_t { return 1; });
    w.add("user32.dll", "DestroyWindow", [](WinCall&) -> uint64_t { return 1; });
    w.add("user32.dll", "InvalidateRect", [](WinCall&) -> uint64_t { return 1; });
    w.add("user32.dll", "GetClientRect", [](WinCall& c) -> uint64_t {
        const uint64_t r = c.u64(1);
        if (c.writable(r, 16)) {
            int32_t v[4] = { 0, 0, 1920, 1080 };
            std::memcpy(c.mm.guestToHost(r), v, sizeof(v));
        }
        return 1;
    });
    w.add("user32.dll", "GetDC", [](WinCall&) -> uint64_t { return 0x30000; });
    w.add("user32.dll", "ReleaseDC", [](WinCall&) -> uint64_t { return 1; });
    w.add("user32.dll", "SetWindowTextA", [](WinCall&) -> uint64_t { return 1; });
    w.add("user32.dll", "SetWindowTextW", [](WinCall&) -> uint64_t { return 1; });
    w.add("user32.dll", "LoadIconA", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "LoadCursorA", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "LoadStringA", [](WinCall&) -> uint64_t { return 0; });
    w.add("user32.dll", "CharUpperA", [](WinCall& c) -> uint64_t { return c.u64(0); });
    w.add("user32.dll", "wsprintfA", [](WinCall&) -> uint64_t { return 0; });

    // ---- gdi32 ------------------------------------------------------------
    w.add("gdi32.dll", "GetStockObject", [](WinCall& c) -> uint64_t {
        return 0x40000 + static_cast<uint64_t>(c.u32(0) & 0xF);
    });
    w.add("gdi32.dll", "CreateSolidBrush", [](WinCall&) -> uint64_t { return 0x41000; });
    w.add("gdi32.dll", "CreatePen", [](WinCall&) -> uint64_t { return 0x41001; });
    w.add("gdi32.dll", "DeleteObject", [](WinCall&) -> uint64_t { return 1; });
    w.add("gdi32.dll", "SelectObject", [](WinCall&) -> uint64_t { return 0x41002; });
    w.add("gdi32.dll", "SetTextColor", [](WinCall&) -> uint64_t { return 0; });
    w.add("gdi32.dll", "SetBkMode", [](WinCall&) -> uint64_t { return 1; });
    w.add("gdi32.dll", "TextOutA", [](WinCall&) -> uint64_t { return 1; });
    w.add("gdi32.dll", "TextOutW", [](WinCall&) -> uint64_t { return 1; });
    w.add("gdi32.dll", "GetDeviceCaps", [](WinCall& c) -> uint64_t {
        switch (c.i32(1)) {
            case 8: return 1920;    // HORZRES
            case 10: return 1080;   // VERTRES
            case 12: return 32;     // BITSPIXEL
            default: return 0;
        }
    });

    // ---- advapi32 (no registry yet: report "not found", never fake success) --
    w.add("advapi32.dll", "RegOpenKeyExA", [](WinCall& c) -> uint64_t {
        (void)c;
        return 2;  // ERROR_FILE_NOT_FOUND
    });
    w.add("advapi32.dll", "RegOpenKeyExW", [](WinCall& c) -> uint64_t {
        (void)c;
        return 2;
    });
    w.add("advapi32.dll", "RegCloseKey", [](WinCall&) -> uint64_t { return 0; });
    w.add("advapi32.dll", "RegQueryValueExA", [](WinCall&) -> uint64_t { return 2; });
    w.add("advapi32.dll", "RegQueryValueExW", [](WinCall&) -> uint64_t { return 2; });
    w.add("advapi32.dll", "RegSetValueExA", [](WinCall&) -> uint64_t { return 5; });
    w.add("advapi32.dll", "RegCreateKeyExA", [](WinCall&) -> uint64_t { return 5; });
    w.add("advapi32.dll", "GetUserNameA", [](WinCall&) -> uint64_t { return 0; });
    w.add("advapi32.dll", "CryptAcquireContextA", [](WinCall&) -> uint64_t { return 0; });
}

void OtherDlls::registerExports(WinAbi& w) { registerShimExports(w); }

uint64_t OtherDlls::resolve(const std::string& dll, const std::string& name) {
    const std::string dl = lower(dll);
    if (dl == "kernelbase.dll") return k32_.resolve(name);

    WinAbi& abi = k32_.abi();
    uint64_t thunk = abi.resolve(dl, name);
    if (thunk) {
        Logger::instance().debug(LogCategory::ABI, ("winabi: " + dl + "!" + name).c_str());
        return thunk;
    }
    if (!k32_.isShimModule(dl)) return 0;

    // A module we own but an export we have not written yet: bind a callable
    // stub so the guest's call is a logged no-op rather than a jump into
    // unmapped memory. This list is the demand-driven backlog.
    if (!stub_modules_registered_) {
        stub_modules_registered_ = true;
        Logger::instance().info(LogCategory::ABI,
                                "winabi: unknown exports of shim modules are stubbed");
    }
    return abi.addStub(dl, name, 0);
}

} // namespace nexus
