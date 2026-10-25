#include "WinAbi.h"

#include "../diagnostics/Logger.h"
#include "../runtime/InsnInterpreter.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>

namespace nexus {

namespace {

std::string lower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

} // namespace

// ---------------------------------------------------------------------------
// UTF-8 <-> UTF-16
// ---------------------------------------------------------------------------

std::u16string utf8ToUtf16(const std::string& s) {
    std::u16string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        uint32_t cp = 0;
        size_t extra = 0;
        if (c < 0x80) { cp = c; extra = 0; }
        else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; extra = 1; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; extra = 2; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; extra = 3; }
        else { ++i; continue; }  // invalid lead byte: drop it
        if (i + extra >= s.size() + (extra ? 1 : 0) && i + extra > s.size() - 1) {
            // truncated sequence: stop
            break;
        }
        bool ok = true;
        for (size_t k = 1; k <= extra; ++k) {
            const unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) { ok = false; break; }
            cp = (cp << 6) | (cc & 0x3F);
        }
        i += extra + 1;
        if (!ok) continue;
        if (cp >= 0x10000) {
            cp -= 0x10000;
            out.push_back(static_cast<char16_t>(0xD800 + (cp >> 10)));
            out.push_back(static_cast<char16_t>(0xDC00 + (cp & 0x3FF)));
        } else {
            out.push_back(static_cast<char16_t>(cp));
        }
    }
    return out;
}

std::string utf16ToUtf8(const std::u16string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        uint32_t cp = s[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < s.size() &&
            s[i + 1] >= 0xDC00 && s[i + 1] <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (s[i + 1] - 0xDC00);
            ++i;
        }
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// String marshalling
// ---------------------------------------------------------------------------

std::string WinCall::ansiAt(uint64_t a, size_t cap) const {
    std::string out;
    while (a && out.size() < cap) {
        const char* p = static_cast<const char*>(mm.guestToHost(a));
        if (!p) break;
        auto region = mm.query(a);
        if (!region) break;
        size_t avail = static_cast<size_t>(region->guest_end - a);
        size_t n = 0;
        while (n < avail && out.size() + n < cap && p[n] != '\0') ++n;
        out.append(p, n);
        if (n < avail) break;          // hit the NUL
        if (n == 0) break;             // no progress (defensive)
        a += n;
    }
    return out;
}

std::u16string WinCall::wideAt(uint64_t a, size_t cap) const {
    std::u16string out;
    while (a && out.size() < cap) {
        const uint8_t* p = static_cast<const uint8_t*>(mm.guestToHost(a));
        if (!p) break;
        auto region = mm.query(a);
        if (!region) break;
        size_t units = static_cast<size_t>(region->guest_end - a) / 2;
        size_t n = 0;
        while (n < units && out.size() + n < cap) {
            const uint16_t u = static_cast<uint16_t>(p[2 * n] | (p[2 * n + 1] << 8));
            if (u == 0) break;
            out.push_back(static_cast<char16_t>(u));
            ++n;
        }
        if (n < units && out.size() < cap) break;
        if (n == 0) break;
        a += static_cast<uint64_t>(n) * 2;
    }
    return out;
}

size_t WinCall::putAnsi(uint64_t a, size_t cap, const std::string& s) const {
    if (!a || cap == 0) return 0;
    size_t n = std::min(s.size(), cap - 1);
    size_t done = 0;
    while (done < n) {
        const uint64_t dst = a + done;
        char* p = static_cast<char*>(mm.guestToHost(dst));
        if (!p) break;
        auto region = mm.query(dst);
        if (!region) break;
        size_t avail = static_cast<size_t>(region->guest_end - dst);
        size_t chunk = std::min(n - done, avail);
        std::memcpy(p, s.data() + done, chunk);
        done += chunk;
    }
    char* term = static_cast<char*>(mm.guestToHost(a + done));
    if (term) *term = '\0';
    return done;
}

size_t WinCall::putWide(uint64_t a, size_t cap, const std::u16string& s) const {
    if (!a || cap == 0) return 0;
    size_t n = std::min(s.size(), cap - 1);
    size_t done = 0;
    while (done < n) {
        const uint64_t dst = a + done * 2;
        uint8_t* p = static_cast<uint8_t*>(mm.guestToHost(dst));
        if (!p) break;
        auto region = mm.query(dst);
        if (!region) break;
        size_t avail = static_cast<size_t>(region->guest_end - dst) / 2;
        size_t chunk = std::min(n - done, avail);
        for (size_t k = 0; k < chunk; ++k) {
            const char16_t u = s[done + k];
            p[2 * k] = static_cast<uint8_t>(u & 0xFF);
            p[2 * k + 1] = static_cast<uint8_t>(u >> 8);
        }
        done += chunk;
    }
    uint8_t* term = static_cast<uint8_t*>(mm.guestToHost(a + done * 2));
    if (term) { term[0] = 0; term[1] = 0; }
    return done;
}

// ---------------------------------------------------------------------------
// WinAbi
// ---------------------------------------------------------------------------

WinAbi::WinAbi(MemoryManager& mm) : mm_(mm) {}

WinAbi::~WinAbi() = default;

std::string WinAbi::key(const std::string& module, const std::string& name) {
    return lower(module) + "!" + name;
}

bool WinAbi::growPage() {
    uint64_t p = mm_.allocate(0, MemoryManager::kPageSize, PagePerm::READ_WRITE_EXEC,
                              "winabi thunks");
    if (!p) {
        Logger::instance().error(LogCategory::ABI, "winabi: thunk page map failed");
        return false;
    }
    pages_.push_back(p);
    if (!page_) page_ = p;
    return true;
}

void WinAbi::emitStub(uint64_t thunk, uint32_t id) {
    uint8_t* p = static_cast<uint8_t*>(mm_.guestToHost(thunk));
    if (!p) return;
    const uint32_t nr = kCallBase + id;
    p[0] = 0x49; p[1] = 0x89; p[2] = 0xCA;          // mov r10, rcx
    p[3] = 0xB8;                                     // mov eax, imm32
    std::memcpy(p + 4, &nr, 4);
    p[8] = 0x0F; p[9] = 0x05;                        // syscall
    p[10] = 0xC3;                                    // ret
    std::memset(p + 11, 0xCC, kSlotSize - 11);       // int3 padding
}

uint32_t WinAbi::internExport(const std::string& module, const std::string& name) {
    const std::string k = key(module, name);
    auto it = index_.find(k);
    if (it != index_.end()) return it->second;
    if (exports_.size() >= kMaxExports) return UINT32_MAX;

    const uint32_t id = static_cast<uint32_t>(exports_.size());
    const uint32_t slot_in_page = id % (MemoryManager::kPageSize / kSlotSize);
    if (slot_in_page == 0 && id > 0) {
        if (!growPage()) return UINT32_MAX;
    }
    if (!page_ && !growPage()) return UINT32_MAX;

    const size_t page_index = id / (MemoryManager::kPageSize / kSlotSize);
    if (page_index >= pages_.size()) return UINT32_MAX;
    const uint64_t thunk = pages_[page_index] + slot_in_page * kSlotSize;

    Export e;
    e.module = lower(module);
    e.name = name;
    e.thunk = thunk;
    exports_.push_back(std::move(e));
    index_[k] = id;
    emitStub(thunk, id);
    return id;
}

uint64_t WinAbi::add(const std::string& module, const std::string& name, Handler h) {
    const uint32_t id = internExport(module, name);
    if (id == UINT32_MAX) return 0;
    exports_[id].fn = std::move(h);
    return exports_[id].thunk;
}

uint64_t WinAbi::addStub(const std::string& module, const std::string& name, uint64_t value) {
    const uint32_t id = internExport(module, name);
    if (id == UINT32_MAX) return 0;
    if (!exports_[id].fn) {
        exports_[id].stub = true;
        const std::string label = lower(module) + "!" + name;
        exports_[id].fn = [label, value](WinCall& c) -> uint64_t {
            Logger::instance().warn(LogCategory::ABI,
                                    ("winabi: stubbed " + label).c_str());
            (void)c;
            return value;
        };
    }
    return exports_[id].thunk;
}

bool WinAbi::has(const std::string& module, const std::string& name) const {
    return index_.count(key(module, name)) != 0;
}

uint64_t WinAbi::resolve(const std::string& module, const std::string& name) {
    const std::string k = key(module, name);
    auto it = index_.find(k);
    if (it != index_.end()) return exports_[it->second].thunk;

    // Case-insensitive fallback: exports are technically case-sensitive, but
    // real binaries and hand-written import tables are not always careful.
    const std::string lname = lower(name);
    const std::string lmod = lower(module);
    for (const auto& e : exports_) {
        if (e.module == lmod && lower(e.name) == lname) return e.thunk;
    }
    if (missing_.size() < 4096) missing_.push_back(lmod + "!" + name);
    Logger::instance().warn(LogCategory::ABI,
                            ("winabi: no export for " + lmod + "!" + name).c_str());
    return 0;
}

bool WinAbi::dispatch(uint32_t nr, GuestContext& ctx) {
    if (!owns(static_cast<int64_t>(nr))) return false;
    const uint32_t id = nr - kCallBase;
    if (id >= exports_.size()) return false;
    Export& e = exports_[id];
    if (!e.fn) return false;

    WinCall c(ctx, mm_);
    c.iarg[0] = ctx.gpr[10];   // R10 held RCX across the stub's syscall
    c.iarg[1] = ctx.gpr[2];    // RDX
    c.iarg[2] = ctx.gpr[8];    // R8
    c.iarg[3] = ctx.gpr[9];    // R9
    for (int k = 0; k < 4; ++k) {
        uint64_t a = 0;
        if (c.get(ctx.gpr[4] + 0x28 + 8ULL * k, a)) c.sarg[k] = a;
    }
    for (int k = 0; k < 4; ++k) std::memcpy(c.farg[k], ctx.ymm[k], 16);

    uint64_t r = 0;
    try {
        r = e.fn(c);
    } catch (const std::exception& ex) {
        Logger::instance().error(LogCategory::ABI,
                                 (std::string("winabi: ") + e.module + "!" + e.name +
                                  " threw: " + ex.what()).c_str());
        r = 0;
    }
    e.calls++;

    if (c.ret_kind != WinRetKind::INTEGER) {
        std::memcpy(ctx.ymm[0], &c.ret_float, 8);
        ctx.rax() = 0;
    } else {
        ctx.rax() = r;
    }
    return true;
}

bool WinAbi::callGuest(GuestContext& ctx, uint64_t fn, const std::vector<uint64_t>& args,
                       uint64_t* out) {
    if (!fn) return false;
    if (depth_ >= 8) {
        Logger::instance().warn(LogCategory::ABI, "winabi: callback depth limit");
        return false;
    }
    if (!interp_) {
        interp_ = std::make_unique<InsnInterpreter>(&mm_, nullptr);
    }

    const uint64_t saved_rsp = ctx.gpr[4];
    const uint64_t saved_rip = ctx.rip;
    const uint64_t saved_iarg[4] = { ctx.gpr[1], ctx.gpr[2], ctx.gpr[8], ctx.gpr[9] };

    // Frame: [shadow 32][stack args][sentinel]. RSP must stay 16-byte aligned
    // at the call site, which the rounding below preserves.
    const size_t n_stack = args.size() > 4 ? args.size() - 4 : 0;
    size_t frame = 0x28 + n_stack * 8;
    frame = (frame + 15) & ~static_cast<size_t>(15);
    uint64_t sp = saved_rsp - frame;
    if (!mm_.isRangeAccessible(sp, frame, PagePerm::READ_WRITE)) {
        Logger::instance().warn(LogCategory::ABI, "winabi: callback stack unmapped");
        return false;
    }
    {
        uint64_t sentinel = sentinel_;
        std::memcpy(mm_.guestToHost(sp), &sentinel, 8);
        // Return address sits at [rsp]; args 5+ begin at [rsp+0x28].
        for (size_t k = 0; k < n_stack; ++k) {
            uint64_t v = args[4 + k];
            std::memcpy(mm_.guestToHost(sp + 0x28 + k * 8), &v, 8);
        }
        uint64_t shadow = 0;
        for (size_t k = 0; k < 4; ++k)
            std::memcpy(mm_.guestToHost(sp + 8 + k * 8), &shadow, 8);
    }

    ctx.gpr[4] = sp;
    if (!args.empty()) ctx.gpr[1] = args[0];
    if (args.size() > 1) ctx.gpr[2] = args[1];
    if (args.size() > 2) ctx.gpr[8] = args[2];
    if (args.size() > 3) ctx.gpr[9] = args[3];
    ctx.rip = fn;

    ++depth_;
    bool ok = true;
    uint64_t steps = 0;
    const uint64_t kMaxSteps = 4'000'000;
    while (ctx.rip != sentinel_) {
        if (++steps > kMaxSteps) {
            Logger::instance().warn(LogCategory::ABI, "winabi: callback step budget");
            ok = false;
            break;
        }
        auto region = mm_.query(ctx.rip);
        const uint8_t* bytes = region
            ? static_cast<const uint8_t*>(mm_.guestToHost(ctx.rip)) : nullptr;
        size_t avail = region
            ? static_cast<size_t>(region->guest_end - ctx.rip) : 0;
        if (!bytes || !avail) {
            ok = false;
            break;
        }
        auto ir = interp_->executeBlock(ctx, bytes, avail, 64);
        if (ir.exit == InterpExit::SYSCALL) {
            int64_t nr = ir.syscall_nr;
            bool handled = owns(nr) ? dispatch(static_cast<uint32_t>(nr), ctx) : false;
            if (!handled) { ok = false; break; }
            ctx.rip = ir.next_pc;
            continue;
        }
        if (ir.exit == InterpExit::EXCEPTION || ir.exit == InterpExit::HALT) {
            Logger::instance().warn(LogCategory::ABI,
                ("winabi: callback fault: " + ir.exception_msg).c_str());
            ok = false;
            break;
        }
    }
    --depth_;

    if (out) *out = ctx.rax();
    ctx.gpr[4] = saved_rsp;
    ctx.rip = saved_rip;
    for (int k = 0; k < 4; ++k) {
        const int reg = (k == 0) ? 1 : (k == 1) ? 2 : (k == 2) ? 8 : 9;
        ctx.gpr[reg] = saved_iarg[k];
    }
    return ok;
}

std::string WinAbi::statsLine() const {
    uint64_t called = 0, stubs = 0;
    for (const auto& e : exports_) {
        if (e.calls) ++called;
        if (e.stub) ++stubs;
    }
    std::ostringstream o;
    o << "winabi: " << exports_.size() << " exports, " << called << " called, "
      << stubs << " stubbed, " << missing_.size() << " missing";
    return o.str();
}

} // namespace nexus
