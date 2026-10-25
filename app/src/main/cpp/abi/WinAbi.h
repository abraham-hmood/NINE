#pragma once

#include "../runtime/GuestContext.h"
#include "../memory/MemoryManager.h"
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace nexus {

class InsnInterpreter;

// ---------------------------------------------------------------------------
// The Windows ABI boundary.
//
// A guest never sees the kernel: it sees exported names. Every export is
// therefore backed by a *real, callable guest stub* rather than a fake address
// in an unmapped page. Each stub is 16 bytes of x86-64:
//
//     49 89 CA        mov  r10, rcx        ; park arg0 (syscall clobbers RCX)
//     B8 <id>         mov  eax, kCallBase+id
//     0F 05           syscall              ; trap into the runtime
//     C3              ret                  ; back to the guest caller
//     CC CC CC CC CC  int3 padding
//
// The stub performs no stack adjustment, so at dispatch time RSP still points
// at the caller's return address and the 5th+ arguments are exactly where the
// Microsoft x64 convention puts them: [rsp+0x28], [rsp+0x30], ...
//
// Dispatch fills a WinCall, runs the native handler and leaves the result in
// RAX (or XMM0 for floating-point returns), then the guest's own `ret`
// continues. That gives us the whole Windows calling convention — register
// args, stack args, XMM args, shadow space — with no per-API assembly.
// ---------------------------------------------------------------------------

// Return-value class. The Microsoft x64 ABI returns floating-point values in
// XMM0 and everything else in RAX.
enum class WinRetKind : uint8_t { INTEGER, DOUBLE, FLOAT };

// One in-flight call. Handlers read their arguments through this instead of
// taking a C++ signature, so one handler type covers every export shape
// (including varargs, by-value structs and out-pointers).
struct WinCall {
    GuestContext& ctx;
    MemoryManager& mm;

    uint64_t iarg[4] = {};      // RCX, RDX, R8, R9
    uint64_t sarg[4] = {};      // 5th..8th argument slots on the guest stack
    uint8_t  farg[4][16] = {};  // XMM0-XMM3

    WinRetKind ret_kind = WinRetKind::INTEGER;
    double ret_float = 0.0;

    // Used by handlers that return a value through a pointer argument.
    bool faulted = false;       // set when a guest pointer was invalid

    WinCall(GuestContext& c, MemoryManager& m) : ctx(c), mm(m) {}

    // ---- integer argument access (positional, integer class) --------------
    uint64_t u64(int n) const { return n < 4 ? iarg[n] : sarg[n - 4]; }
    uint64_t ptr(int n) const { return u64(n); }
    int64_t  i64(int n) const { return static_cast<int64_t>(u64(n)); }
    uint32_t u32(int n) const { return static_cast<uint32_t>(u64(n)); }
    int32_t  i32(int n) const { return static_cast<int32_t>(u32(n)); }
    bool     z(int n) const { return u64(n) != 0; }

    // ---- floating-point argument access (XMM class) ----------------------
    double f64(int n) const { double d = 0.0; std::memcpy(&d, farg[n & 3], 8); return d; }
    float  f32(int n) const { float f = 0.0f; std::memcpy(&f, farg[n & 3], 4); return f; }

    // ---- guest memory ----------------------------------------------------
    bool readable(uint64_t a, size_t n) const {
        return a && mm.isRangeAccessible(a, n, PagePerm::READ);
    }
    bool writable(uint64_t a, size_t n) const {
        return a && mm.isRangeAccessible(a, n, PagePerm::WRITE);
    }

    template <class T>
    bool get(uint64_t a, T& out) const {
        if (!readable(a, sizeof(T))) return false;
        std::memcpy(&out, mm.guestToHost(a), sizeof(T));
        return true;
    }

    template <class T>
    bool put(uint64_t a, T v) const {
        if (!writable(a, sizeof(T))) return false;
        std::memcpy(mm.guestToHost(a), &v, sizeof(T));
        return true;
    }

    // NUL-terminated ANSI / UTF-16LE strings. Reads stop at the NUL, at the
    // first unmapped byte, or after `cap` units — never unbounded.
    std::string   ansiAt(uint64_t a, size_t cap = 32768) const;
    std::u16string wideAt(uint64_t a, size_t cap = 32768) const;
    std::string   ansi(int n, size_t cap = 32768) const { return ansiAt(u64(n), cap); }
    std::u16string wide(int n, size_t cap = 32768) const { return wideAt(u64(n), cap); }

    // Copy a string into guest memory, honouring the caller's capacity.
    // Returns the number of units written, excluding the terminator.
    size_t putAnsi(uint64_t a, size_t cap, const std::string& s) const;
    size_t putWide(uint64_t a, size_t cap, const std::u16string& s) const;

    uint64_t alloc(size_t n) const {
        return mm.allocate(0, n, PagePerm::READ_WRITE, "winabi scratch");
    }

    // ---- returns ---------------------------------------------------------
    void setDouble(double v) { ret_kind = WinRetKind::DOUBLE; ret_float = v; }
    void setFloat(float v)   { ret_kind = WinRetKind::FLOAT;  ret_float = v; }
    // A floating return still has to leave something in RAX for callers that
    // ignore the XMM half; zero there is what MSVC's own stubs do.
};

// UTF-8 <-> UTF-16 conversions used by the ANSI/Wide pairs and the CP_UTF8
// paths of MultiByteToWideChar/WideCharToMultiByte.
std::u16string utf8ToUtf16(const std::string& s);
std::string   utf16ToUtf8(const std::u16string& s);

class WinAbi {
public:
    // Everything at or above this syscall number is an ABI call, not a Linux
    // syscall. Linux numbers are all far below it.
    static constexpr uint32_t kCallBase = 0x40000000u;
    static constexpr uint32_t kSlotSize = 16;
    static constexpr uint32_t kMaxExports = 8192;

    using Handler = std::function<uint64_t(WinCall&)>;

    explicit WinAbi(MemoryManager& mm);
    ~WinAbi();

    // Register an export and emit its stub. Returns the guest-callable thunk
    // address, or 0 when the thunk page could not be mapped / table is full.
    // Re-registering the same module!name replaces the handler and keeps the
    // address stable (so an already-patched IAT stays valid).
    uint64_t add(const std::string& module, const std::string& name, Handler h);

    // Register a named export that does nothing but return `value`. Used for
    // APIs that must exist (so a call is a safe no-op) but carry no behaviour
    // yet; every call is logged once.
    uint64_t addStub(const std::string& module, const std::string& name,
                     uint64_t value = 0);

    // module + name -> thunk address (0 when unavailable).
    // Names are matched case-sensitively first, then case-insensitively, which
    // is what the Windows loader's export lookup effectively does in practice.
    uint64_t resolve(const std::string& module, const std::string& name);

    bool has(const std::string& module, const std::string& name) const;

    // True when `nr` belongs to this dispatcher (see kCallBase).
    static bool owns(int64_t nr) {
        return nr >= static_cast<int64_t>(kCallBase) &&
               nr < static_cast<int64_t>(kCallBase) + static_cast<int64_t>(kMaxExports);
    }

    // Execute the export selected by `nr`, leaving its result in ctx (RAX or
    // XMM0). Returns false for an unknown id.
    bool dispatch(uint32_t nr, GuestContext& ctx);

    // Native -> guest. Pushes a sentinel return address, fills the Win64
    // argument registers/stack and interprets guest code until it returns to
    // the sentinel. This is the callback direction (window procs, thread
    // entry points, qsort comparators). Nested to a bounded depth.
    //
    // It cannot unwind a guest exception across the native frame yet: a fault
    // inside the callback aborts the call and leaves ctx.rip where it failed.
    bool callGuest(GuestContext& ctx, uint64_t fn,
                   const std::vector<uint64_t>& args = {}, uint64_t* out = nullptr);

    // ---- introspection ---------------------------------------------------
    size_t exportCount() const { return exports_.size(); }
    uint64_t thunkPage() const { return page_; }
    uint64_t thunkOf(uint32_t id) const {
        return id < exports_.size() ? exports_[id].thunk : 0;
    }
    const std::vector<std::string>& missing() const { return missing_; }
    uint64_t callCount(uint32_t id) const {
        return id < exports_.size() ? exports_[id].calls : 0;
    }
    // "winabi: 74 exports, 12 called, 3 stubbed" — one line for the log.
    std::string statsLine() const;

    // The execution loop reads this to decide whether a SYSCALL is ours.
    // Kept explicit so a caller cannot accidentally install a dispatcher that
    // claims Linux numbers.
    bool handleSyscallNumber(int64_t nr, GuestContext& ctx) {
        return owns(nr) ? dispatch(static_cast<uint32_t>(nr), ctx) : false;
    }

private:
    struct Export {
        std::string module;
        std::string name;
        Handler fn;
        uint64_t thunk = 0;
        uint64_t calls = 0;
        bool stub = false;
        bool warned = false;
    };

    MemoryManager& mm_;
    uint64_t page_ = 0;
    uint32_t page_slots_ = 0;
    std::vector<uint64_t> pages_;
    std::vector<Export> exports_;
    std::unordered_map<std::string, uint32_t> index_;
    std::vector<std::string> missing_;

    std::unique_ptr<InsnInterpreter> interp_;
    uint64_t sentinel_ = 0x00007FFFDEAD0000ULL;
    int depth_ = 0;

    uint32_t internExport(const std::string& module, const std::string& name);
    bool growPage();
    void emitStub(uint64_t thunk, uint32_t id);
    static std::string key(const std::string& module, const std::string& name);
};

} // namespace nexus
