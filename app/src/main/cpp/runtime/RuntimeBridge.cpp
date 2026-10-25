#include "RuntimeBridge.h"
#include "../loader/elf/ElfParser.h"
#include "../loader/elf/ElfLoader.h"
#include "../loader/elf/ElfRelocator.h"
#include "../loader/pe/PeParser.h"
#include "../loader/pe/PeMapper.h"
#include "../loader/pe/PeImports.h"
#include "../loader/pe/PeRelocator.h"
#include "../memory/MemoryManager.h"
#include "../translator/CodeCache.h"
#include "../translator/Translator.h"
#include "../aot/AotRelink.h"
#include "../abi/SyscallTranslator.h"
#include "../abi/Seh.h"
#include "../abi/Ntdll.h"
#include "../abi/Kernel32.h"
#include "../abi/OtherDlls.h"
#include "../linker/SearchPaths.h"
#include "../linker/ModuleGraph.h"
#include "../linker/SymbolResolver.h"
#include "ExecutionLoop.h"
#include "SmcCoherency.h"
#include "GuestContext.h"
#include "MemHelpers.h"
#include "LinuxStartup.h"
#include "HostTrampoline.h"
#include "../diagnostics/Logger.h"
#include <fstream>
#include <thread>
#include <sstream>
#include <cstring>
#include <csetjmp>
#include <csignal>
#include <atomic>
#include <exception>
#include <algorithm>
#include <unordered_set>
#include <cctype>
#include <cstdio>

namespace nexus {

namespace {
thread_local sigjmp_buf g_jmp;
thread_local volatile sig_atomic_t g_in_guest = 0;
thread_local volatile sig_atomic_t g_crash_sig = 0;

void crash_handler(int sig) {
    if (g_in_guest) {
        g_crash_sig = sig;
        siglongjmp(g_jmp, 1);
    }
    // Not in guest — default terminate path not restorable here
    signal(sig, SIG_DFL);
    raise(sig);
}

struct CrashGuard {
    struct sigaction old_segv{}, old_bus{}, old_ill{};
    CrashGuard() {
        struct sigaction sa{};
        sa.sa_handler = crash_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGSEGV, &sa, &old_segv);
        sigaction(SIGBUS, &sa, &old_bus);
        sigaction(SIGILL, &sa, &old_ill);
    }
    ~CrashGuard() {
        sigaction(SIGSEGV, &old_segv, nullptr);
        sigaction(SIGBUS, &old_bus, nullptr);
        sigaction(SIGILL, &old_ill, nullptr);
    }
};
} // namespace

RuntimeBridge& RuntimeBridge::instance() {
    static RuntimeBridge b;
    return b;
}

void RuntimeBridge::setLogSink(LogSink s) {
    std::lock_guard<std::mutex> lock(sink_mu_);
    log_sink_ = std::move(s);
    // Wire global Logger → same sink so LOADER/DBT lines reach UI.
    // Never clobber a sink already installed by nativeInit (that one owns the
    // GuestLog.onNativeLine bridge); only install this fallback if Logger has none.
    if (!Logger::instance().hasSink()) {
        Logger::instance().setSink([this](LogLevel, LogCategory, const std::string& line) {
            std::lock_guard<std::mutex> lock(sink_mu_);
            if (log_sink_) log_sink_(line);
        });
    }
}

void RuntimeBridge::emitLog(const std::string& s) {
    {
        std::lock_guard<std::mutex> lock(status_.msg_mu);
        status_.last_message = s;
    }
    // Single funnel: Logger (which mirrors to logcat + the Java sink).
    // Do NOT also call log_sink_ here — that double-delivered every line.
    try {
        Logger::instance().info(LogCategory::GENERAL, s);
    } catch (...) {}
}

void RuntimeBridge::requestStop() {
    stop_.store(true);
    status_.pause_requested.store(false);
}
void RuntimeBridge::requestPause() { status_.pause_requested.store(true); }
void RuntimeBridge::requestResume() {
    status_.pause_requested.store(false);
    status_.step_one.store(false);
}
void RuntimeBridge::requestStep() {
    status_.step_one.store(true);
    status_.pause_requested.store(false);
}
void RuntimeBridge::setBreakpoint(uint64_t guest_pc) {
    std::lock_guard<std::mutex> lock(bp_mu_);
    breakpoints_.push_back(guest_pc);
}
void RuntimeBridge::clearBreakpoints() {
    std::lock_guard<std::mutex> lock(bp_mu_);
    breakpoints_.clear();
}

std::string RuntimeBridge::statusSnapshot() {
    std::ostringstream oss;
    oss << "running=" << (status_.running.load() ? 1 : 0)
        << " rip=0x" << std::hex << status_.guest_rip.load()
        << " blocks=" << std::dec << status_.blocks.load()
        << " hits=" << status_.hits.load()
        << " miss=" << status_.misses.load()
        << " xlat=" << status_.translations.load()
        << " sys=" << status_.syscalls.load()
        << " smc=" << status_.smc.load();
    std::lock_guard<std::mutex> lock(status_.msg_mu);
    if (!status_.last_message.empty())
        oss << " | " << status_.last_message;
    return oss.str();
}

static bool isElf(const std::vector<uint8_t>& b) {
    return b.size() >= 4 && b[0]==0x7f && b[1]=='E' && b[2]=='L' && b[3]=='F';
}
static bool isPe(const std::vector<uint8_t>& b) {
    return b.size() >= 2 && b[0]=='M' && b[1]=='Z';
}

std::string RuntimeBridge::loadAndRun(const std::string& path, const std::string& cache_dir) {
    try {
        std::lock_guard<std::mutex> lock(run_mu_);
        if (status_.running.load()) return "already running";

        emitLog("loadAndRun: open " + path);
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            emitLog("cannot open file");
            return "cannot open: " + path;
        }
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)), {});
        emitLog("read " + std::to_string(bytes.size()) + " bytes");
        if (bytes.empty()) return "empty file";

        stop_.store(false);
        status_.running.store(true);
        status_.blocks.store(0);
        status_.hits.store(0);
        status_.misses.store(0);
        status_.translations.store(0);
        status_.syscalls.store(0);

        std::string result;
        if (isElf(bytes)) {
            emitLog("format: ELF64");
            result = runElf(bytes, cache_dir);
        } else if (isPe(bytes)) {
            emitLog("format: PE");
            result = runPe(bytes, cache_dir);
        } else {
            emitLog("format: unknown — raw blob @0x400000");
            result = runRawCode(bytes.data(), bytes.size(), 0x400000, cache_dir);
        }

        status_.running.store(false);
        emitLog(result);
        return result;
    } catch (const std::exception& e) {
        status_.running.store(false);
        std::string m = std::string("exception: ") + e.what();
        emitLog(m);
        return m;
    } catch (...) {
        status_.running.store(false);
        emitLog("unknown C++ exception");
        return "unknown C++ exception";
    }
}

std::string RuntimeBridge::runRawCode(const uint8_t* code, size_t len, uint64_t entry,
                                      const std::string& cache_dir) {
    emitLog("runRawCode entry=0x" + [&]{std::ostringstream o;o<<std::hex<<entry<<" len="<<std::dec<<len;return o.str();}());
    MemoryManager mm;
    CodeCache cache(1 << 20);
    Translator tr;
    SyscallTranslator sys;
    SehDispatcher seh;
    SmcCoherency smc(cache, mm);
    sys.setMemoryManager(&mm);
    MemHelpers_setMM(&mm);

    uint64_t map_sz = (len + 0xFFF) & ~0xFFFULL;
    if (map_sz < 0x1000) map_sz = 0x1000;
    uint64_t base = mm.allocate(entry, map_sz, PagePerm::READ_WRITE, "guest");
    if (!base) {
        emitLog("map failed at preferred VA — trying free VA");
        base = mm.allocate(0, map_sz, PagePerm::READ_WRITE, "guest");
    }
    if (!base) return "map failed";
    emitLog("mapped guest base=0x" + [&]{std::ostringstream o;o<<std::hex<<base;return o.str();}());
    void* host = mm.guestToHost(base);
    if (!host) return "guestToHost null";
    std::memcpy(host, code, len);
    mm.protect(base, PagePerm::READ_EXEC);
    smc.markExecutable(base, base + len);

    uint64_t img_hash = 0;
    for (size_t i = 0; i < std::min(len, size_t(256)); ++i) img_hash = img_hash * 131 + code[i];
    cache.setImageKey(base, img_hash);
    auto cpath = CodeCache::defaultCachePath(cache_dir.empty() ? "/tmp" : cache_dir, base, img_hash);
    cache.loadFromFile(cpath);

    ExecutionLoop loop(cache, tr, sys, seh, &mm, &smc);
    // Prefer interpreter for stability until JIT is proven on this image
    loop.setTranslate(false);
    loop.setInlineSyscalls(true);
    emitLog("execution mode: interpreter-first (safe)");

    loop.setOnSyscall([&](int64_t nr, GuestContext& ctx) -> int64_t {
        try {
            if (nr == 1) {
                int fd = static_cast<int>(ctx.rdi());
                if (fd == 1 || fd == 2) {
                    auto* p = static_cast<const char*>(mm.guestToHost(ctx.rsi()));
                    size_t n = static_cast<size_t>(ctx.rdx());
                    if (p && n) {
                        emitLog(std::string(fd == 1 ? "stdout: " : "stderr: ") +
                                std::string(p, p + std::min(n, size_t(4096))));
                    }
                }
            }
            if (nr == 60 || nr == 231) {
                emitLog("guest exit syscall nr=" + std::to_string(nr) +
                        " code=" + std::to_string(ctx.rdi()));
            }
            return sys.translate(static_cast<int>(nr),
                                 ctx.rdi(), ctx.rsi(), ctx.rdx(),
                                 ctx.gpr[10], ctx.gpr[8], ctx.gpr[9]);
        } catch (const std::exception& e) {
            emitLog(std::string("syscall handler exception: ") + e.what());
            return -1;
        }
    });

    GuestContext& ctx = ContextSwitch::current();
    ctx.clear();
    ctx.rip = base;
    uint64_t stack = mm.allocate(0, 0x20000, PagePerm::READ_WRITE, "stack");
    if (stack) {
        ctx.rsp() = stack + 0x20000 - 16;
        emitLog("stack @0x" + [&]{std::ostringstream o;o<<std::hex<<ctx.rsp();return o.str();}());
    } else {
        emitLog("WARNING: no stack allocated");
    }

    CrashGuard guard;
    uint64_t steps = 0;
    const uint64_t kMax = 500000;
    while (steps < kMax && !stop_.load()) {
        if (status_.pause_requested.load() && !status_.step_one.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            status_.guest_rip.store(ctx.rip);
            continue;
        }
        status_.step_one.store(false);

        if (sigsetjmp(g_jmp, 1) == 0) {
            g_in_guest = 1;
            g_crash_sig = 0;
            auto res = loop.resume(ctx, nullptr, 0, 32);
            g_in_guest = 0;

            status_.guest_rip.store(ctx.rip);
            status_.blocks.store(loop.counters().blocks_executed.load());
            status_.hits.store(loop.counters().cache_hits.load());
            status_.misses.store(loop.counters().cache_misses.load());
            status_.translations.store(loop.counters().translations.load());
            status_.syscalls.store(loop.counters().syscalls.load());
            status_.smc.store(loop.counters().smc_invalidations.load());

            if (steps % 1000 == 0) {
                emitLog("progress steps=" + std::to_string(steps) +
                        " rip=0x" + [&]{std::ostringstream o;o<<std::hex<<ctx.rip;return o.str();}());
            }

            if (res.reason == ExitReason::HALT || res.reason == ExitReason::EXCEPTION) {
                emitLog("exit reason=" + std::to_string(static_cast<int>(res.reason)));
                break;
            }
            if (res.reason == ExitReason::SYSCALL && (res.syscall_nr == 60 || res.syscall_nr == 231))
                break;
        } else {
            g_in_guest = 0;
            int sig = g_crash_sig;
            emitLog("CAUGHT signal " + std::to_string(sig) +
                    " at guest rip=0x" + [&]{std::ostringstream o;o<<std::hex<<ctx.rip;return o.str();}() +
                    " — stopping guest, process continues");
            status_.last_message = "guest crash signal " + std::to_string(sig);
            break;
        }
        ++steps;
    }

    try { cache.saveToFile(cpath); } catch (...) {}
    std::ostringstream oss;
    oss << "done steps=" << steps << " " << statusSnapshot();
    return oss.str();
}

std::string RuntimeBridge::runElf(const std::vector<uint8_t>& bytes, const std::string& cache_dir) {
    emitLog("ELF parse…");
    auto parsed = ElfParser::parse(std::span<const uint8_t>(bytes.data(), bytes.size()));
    if (!parsed) {
        emitLog("ELF parse failed — raw fallback");
        return runRawCode(bytes.data(), bytes.size(), 0x400000, cache_dir);
    }
    emitLog("ELF machine=" + std::to_string(parsed->ehdr.e_machine) +
            " entry=0x" + [&]{std::ostringstream o;o<<std::hex<<parsed->ehdr.e_entry;return o.str();}() +
            " phnum=" + std::to_string(parsed->phdrs.size()));

    if (parsed->ehdr.e_machine != 62 /* EM_X86_64 */) {
        emitLog("unsupported machine (need x86-64)");
        return "unsupported ELF machine";
    }

    MemoryManager mm;
    emitLog("ElfLoader::load…");
    auto loaded = ElfLoader::load(*parsed, mm);
    if (!loaded) {
        emitLog("ElfLoader failed — raw fallback at preferred base");
        uint64_t pref = parsed->ehdr.e_entry & ~0xFFFULL;
        if (!pref) pref = 0x400000;
        return runRawCode(bytes.data(), bytes.size(), pref, cache_dir);
    }
    emitLog("ELF loaded base=0x" + [&]{std::ostringstream o;o<<std::hex<<loaded->base
            <<" entry=0x"<<loaded->entry;return o.str();}());

    CodeCache cache(1 << 20);
    Translator tr;
    SyscallTranslator sys;
    SehDispatcher seh;
    SmcCoherency smc(cache, mm);
    sys.setMemoryManager(&mm);
    MemHelpers_setMM(&mm);
    cache.setImageKey(loaded->base, loaded->entry);
    auto cpath = CodeCache::defaultCachePath(cache_dir.empty() ? "/tmp" : cache_dir,
                                             loaded->base, loaded->entry);
    cache.loadFromFile(cpath);

    ExecutionLoop loop(cache, tr, sys, seh, &mm, &smc);
    loop.setTranslate(false); // interpreter-first
    loop.setInlineSyscalls(true);
    emitLog("ELF execution mode: interpreter-first");

    loop.setOnSyscall([&](int64_t nr, GuestContext& ctx) -> int64_t {
        try {
            if (nr == 1) {
                int fd = static_cast<int>(ctx.rdi());
                if (fd == 1 || fd == 2) {
                    auto* p = static_cast<const char*>(mm.guestToHost(ctx.rsi()));
                    size_t n = static_cast<size_t>(ctx.rdx());
                    if (p && n)
                        emitLog(std::string(fd==1?"stdout: ":"stderr: ") +
                                std::string(p, p+std::min(n,size_t(4096))));
                }
            }
            if (nr == 60 || nr == 231)
                emitLog("exit syscall " + std::to_string(nr));
            return sys.translate(static_cast<int>(nr), ctx.rdi(), ctx.rsi(), ctx.rdx(),
                                 ctx.gpr[10], ctx.gpr[8], ctx.gpr[9]);
        } catch (const std::exception& e) {
            emitLog(std::string("syscall exception: ") + e.what());
            return -1;
        }
    });

    GuestContext& ctx = ContextSwitch::current();
    ctx.clear();
    ctx.rip = loaded->entry;
    auto boot = LinuxStartup::prepare(mm, *loaded, "./hello");
    if (!boot.ok) {
        emitLog("LinuxStartup failed: " + boot.error);
        return "startup failed";
    }
    ctx.rsp() = boot.rsp;
    if (boot.tls_tp) {
        ctx.fs_base = boot.tls_tp;
        emitLog("FS/TLS tp=0x" + [&]{std::ostringstream o;o<<std::hex<<boot.tls_tp;return o.str();}());
    }
    sys.setBrk(boot.brk_start);
    emitLog("stack rsp=0x" + [&]{std::ostringstream o;o<<std::hex<<ctx.rsp()
            <<" brk=0x"<<boot.brk_start;return o.str();}());

    CrashGuard guard;
    uint64_t steps = 0;
    while (steps < 500000 && !stop_.load()) {
        if (status_.pause_requested.load() && !status_.step_one.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            status_.guest_rip.store(ctx.rip);
            continue;
        }
        status_.step_one.store(false);

        if (sigsetjmp(g_jmp, 1) == 0) {
            g_in_guest = 1;
            // Large batch: YIELD means budget hit, keep going; HALT is guest hlt/exit path
            auto res = loop.resume(ctx, nullptr, 0, 4096);
            g_in_guest = 0;
            status_.guest_rip.store(ctx.rip);
            status_.blocks.store(loop.counters().blocks_executed.load());
            status_.syscalls.store(loop.counters().syscalls.load());
            if (steps % 50 == 0) {
                emitLog("ELF progress steps=" + std::to_string(steps) +
                        " rip=0x" + [&]{std::ostringstream o;o<<std::hex<<ctx.rip;return o.str();}() +
                        " reason=" + std::to_string(static_cast<int>(res.reason)) +
                        " sys=" + std::to_string(loop.counters().syscalls.load()));
            }
            if (res.reason == ExitReason::EXCEPTION) {
                emitLog("stop reason=EXCEPTION @" +
                        [&]{std::ostringstream o;o<<std::hex<<ctx.rip;return o.str();}());
                break;
            }
            if (res.reason == ExitReason::HALT) {
                emitLog("guest HALT @" +
                        [&]{std::ostringstream o;o<<std::hex<<ctx.rip;return o.str();}());
                break;
            }
            if (res.reason == ExitReason::SYSCALL && (res.syscall_nr == 60 || res.syscall_nr == 231)) {
                emitLog("guest exit_group/exit nr=" + std::to_string(res.syscall_nr));
                break;
            }
            // NONE / YIELD / SYSCALL(other): continue
        } else {
            g_in_guest = 0;
            emitLog("CAUGHT signal " + std::to_string((int)g_crash_sig) +
                    " @ rip=0x" + [&]{std::ostringstream o;o<<std::hex<<ctx.rip;return o.str();}() +
                    " — guest stopped, app continues");
            break;
        }
        ++steps;
    }
    try { cache.saveToFile(cpath); } catch (...) {}
    return "ELF done " + statusSnapshot();
}

std::string RuntimeBridge::runPe(const std::vector<uint8_t>& bytes, const std::string& cache_dir) {
    emitLog("PE parse…");
    auto parsed = PeParser::parse(bytes.data(), bytes.size());
    if (!parsed) return "PE parse failed";
    MemoryManager mm;
    PeMapper mapper(mm);
    auto mapped = mapper.map(*parsed, bytes.data(), bytes.size());
    if (!mapped) {
        emitLog("PeMapper failed");
        return runRawCode(bytes.data(), bytes.size(), 0x140000000ULL, cache_dir);
    }
    emitLog("PE entry=0x" + [&]{std::ostringstream o;o<<std::hex<<mapped->entry;return o.str();}());

    // ---- Windows ABI: patch the IAT with real callable thunks -----------
    Ntdll nt;
    Kernel32 k32(nt, mm);
    OtherDlls other(k32);
    auto lowerName = [](std::string v) {
        for (char& c : v) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return v;
    };
    nt.ldrAdd("nine.exe", mapped->base, parsed->opt.size_of_image);
    {
        PeImports imp(mm);
        auto ents = imp.walk(*mapped, bytes.data(), bytes.size());
        auto delay = imp.walkDelay(*mapped, bytes.data(), bytes.size());
        ents.insert(ents.end(), delay.begin(), delay.end());
        size_t patched = imp.resolveAndPatch(
            *mapped, ents,
            [&](const std::string& dll) -> uint64_t { return k32.loadLibrary(dll); },
            [&](const std::string& dll, const std::string& name) -> uint64_t {
                const std::string dl = lowerName(dll);
                if (dl == "ntdll.dll" || dl == "kernel32.dll" || dl == "kernelbase.dll")
                    return k32.resolve(name);
                return other.resolve(dl, name);
            });
        emitLog("PE IAT: " + std::to_string(patched) + "/" + std::to_string(ents.size()) +
                " slots -> thunks; " + k32.abi().statsLine());
    }

    // Reuse ELF-style loop via raw is wrong for mapped image; run from mapped entry
    CodeCache cache(1 << 20);
    Translator tr;
    SyscallTranslator sys;
    SehDispatcher seh;
    SmcCoherency smc(cache, mm);
    sys.setMemoryManager(&mm);
    MemHelpers_setMM(&mm);
    ExecutionLoop loop(cache, tr, sys, seh, &mm, &smc);
    loop.setAbiDispatcher([&](int64_t nr, GuestContext& ctx) {
        return k32.abi().handleSyscallNumber(nr, ctx);
    });
    loop.setTranslate(false);
    loop.setInlineSyscalls(true);
    GuestContext& ctx = ContextSwitch::current();
    ctx.clear();
    ctx.rip = mapped->entry;
    CrashGuard guard;
    uint64_t steps = 0;
    while (steps < 200000 && !stop_.load()) {
        if (sigsetjmp(g_jmp, 1) == 0) {
            g_in_guest = 1;
            auto res = loop.resume(ctx, nullptr, 0, 32);
            g_in_guest = 0;
            status_.guest_rip.store(ctx.rip);
            if (res.reason == ExitReason::HALT || res.reason == ExitReason::EXCEPTION) break;
        } else {
            g_in_guest = 0;
            emitLog("PE guest signal " + std::to_string((int)g_crash_sig));
            break;
        }
        ++steps;
    }
    return "PE done " + statusSnapshot();
}

namespace {
std::string dirOfPath(const std::string& p) {
    auto pos = p.find_last_of("/\\");
    return pos == std::string::npos ? std::string(".") : p.substr(0, pos);
}
std::string fileNameOfPath(const std::string& p) {
    auto pos = p.find_last_of("/\\");
    return pos == std::string::npos ? p : p.substr(pos + 1);
}
std::string lowerStr(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// ---- JSON helpers for the nativeRelink contract ----
std::string jsonEscape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\b': o += "\\b"; break;
            case '\f': o += "\\f"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    o += buf;
                } else {
                    o += static_cast<char>(c);
                }
        }
    }
    return o;
}

// Guest-side install root for a library, by binary OS.
const char* installPathFor(const char* os) {
    return (os && std::strcmp(os, "windows") == 0) ? "C:\\Windows\\System32" : "/usr/lib";
}

// Best-effort OS for the input binary. Uses magic bytes when present,
// otherwise falls back to the file extension. Defaults to "linux".
std::string guessOs(const std::string& path, const std::vector<uint8_t>* bytes) {
    if (bytes && bytes->size() >= 2) {
        if ((*bytes)[0] == 'M' && (*bytes)[1] == 'Z') return "windows";
        if (bytes->size() >= 4 && (*bytes)[0] == 0x7f && (*bytes)[1] == 'E' &&
            (*bytes)[2] == 'L' && (*bytes)[3] == 'F') return "linux";
    }
    std::string ext;
    auto dot = path.find_last_of('.');
    if (dot != std::string::npos) ext = lowerStr(path.substr(dot));
    if (ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".ocx" ||
        ext == ".cpl" || ext == ".drv")
        return "windows";
    return "linux";
}

// Filename-safe stem for an AOT sidecar: sonames contain '/' and version
// dashes, which are fine on disk but ugly to smuggle into a payload list.
inline std::string aotFileStem(const std::string& name) {
    std::string out;
    out.reserve(name.size());
    for (char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
        out.push_back(ok ? c : '_');
    }
    while (!out.empty() && out.front() == '.') out.erase(out.begin());
    if (out.empty()) out = "module";
    if (out.size() > 64) out.resize(64);
    return out;
}

struct RelinkJson {
    bool ok = false;
    std::string os = "linux";
    std::string summary;
    std::string error;
    // AOT translation outcome. `ok` means every executable segment of every
    // module produced an image, i.e. the program needs no translator at run
    // time. `unsupported` names the instructions that blocked it.
    struct Aot {
        bool ok = false;
        uint32_t modules = 0;
        uint64_t blocks = 0;
        uint64_t bytes = 0;
        std::string error;
        std::vector<std::string> unsupported;
    } aot;
    struct Lib {
        std::string name;       // DT_NEEDED soname or imported DLL name
        std::string provider;   // "bundled" | "nine-abi"
        std::string path;       // absolute host path, or "" when none
        std::string install;    // guest-side root ("/usr/lib", "C:\\Windows\\System32")
    };
    std::vector<Lib> libraries;
    std::vector<std::string> unresolved;

    std::string serialize() const {
        std::string out;
        out.reserve(256 + libraries.size() * 128 + unresolved.size() * 48);
        out += "{\"ok\":";
        out += ok ? "true" : "false";
        out += ",\"os\":\"" + jsonEscape(os) + "\"";
        out += ",\"summary\":\"" + jsonEscape(summary) + "\"";
        out += ",\"error\":\"" + jsonEscape(error) + "\"";
        out += ",\"libraries\":[";
        for (size_t i = 0; i < libraries.size(); ++i) {
            const auto& L = libraries[i];
            if (i) out += ",";
            out += "{\"name\":\"" + jsonEscape(L.name) + "\"";
            out += ",\"provider\":\"" + jsonEscape(L.provider) + "\"";
            out += ",\"path\":\"" + jsonEscape(L.path) + "\"";
            out += ",\"installPath\":\"" + jsonEscape(L.install) + "\"}";
        }
        out += "]";
        out += ",\"unresolved\":[";
        for (size_t i = 0; i < unresolved.size(); ++i) {
            if (i) out += ",";
            out += "\"" + jsonEscape(unresolved[i]) + "\"";
        }
        out += "]";
        out += ",\"aot\":{\"ok\":";
        out += aot.ok ? "true" : "false";
        out += ",\"modules\":" + std::to_string(aot.modules);
        out += ",\"blocks\":" + std::to_string(aot.blocks);
        out += ",\"bytes\":" + std::to_string(aot.bytes);
        out += ",\"error\":\"" + jsonEscape(aot.error) + "\"";
        out += ",\"unsupported\":[";
        for (size_t i = 0; i < aot.unsupported.size(); ++i) {
            if (i) out += ",";
            out += "\"" + jsonEscape(aot.unsupported[i]) + "\"";
        }
        out += "]}}";
        return out;
    }
};

std::string relinkSummaryLine(size_t bundled, size_t nine_abi) {
    std::ostringstream o;
    const size_t total = bundled + nine_abi;
    o << total << (total == 1 ? " library resolved (" : " libraries resolved (")
     << bundled << " bundled, " << nine_abi << " nine-abi)";
    return o.str();
}

void summarizeAot(RelinkJson& j, const std::vector<aot::ModuleTranslation>& reports) {
    j.aot.ok = !reports.empty();
    for (const auto& r : reports) {
        if (r.ok) {
            ++j.aot.modules;
            j.aot.blocks += r.blocks;
            j.aot.bytes += r.image_bytes;
        } else {
            j.aot.ok = false;
            if (j.aot.error.empty()) j.aot.error = r.name + ": " + r.error;
            for (const auto& u : r.unsupported) {
                if (std::find(j.aot.unsupported.begin(), j.aot.unsupported.end(), u) ==
                    j.aot.unsupported.end())
                    j.aot.unsupported.push_back(u);
            }
        }
    }
    if (j.aot.unsupported.size() > 32) j.aot.unsupported.resize(32);
}

std::string withAotLine(const std::string& base, const RelinkJson& j) {
    if (j.aot.ok) {
        return base + " · AOT ready (" + std::to_string(j.aot.modules) + " image" +
               (j.aot.modules == 1 ? "" : "s") + ", " +
               std::to_string(j.aot.blocks) + " blocks)";
    }
    return base + " · AOT: not translated";
}
} // namespace

std::string RuntimeBridge::relink(const std::string& path, const std::string& lib_dirs) {
    RelinkJson j;
    j.os = guessOs(path, nullptr);
    try {
        emitLog("relink: " + path);
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            emitLog("relink: cannot open " + path);
            j.error = "cannot open " + path;
            return j.serialize();
        }
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)), {});
        j.os = guessOs(path, &bytes);
        if (bytes.empty()) {
            j.error = "empty file";
            return j.serialize();
        }
        if (isPe(bytes)) return relinkPe(path, bytes);
        if (isElf(bytes)) return relinkElf(path, bytes, lib_dirs);
        j.error = "unknown format (ELF or PE expected)";
        return j.serialize();
    } catch (const std::exception& e) {
        RelinkJson err;
        err.os = j.os;
        err.error = std::string("relink exception: ") + e.what();
        emitLog(err.error);
        return err.serialize();
    } catch (...) {
        RelinkJson err;
        err.os = j.os;
        err.error = "relink: unknown exception";
        emitLog(err.error);
        return err.serialize();
    }
}

std::string RuntimeBridge::relinkElf(const std::string& path, const std::vector<uint8_t>& bytes,
                                     const std::string& lib_dirs) {
    RelinkJson j;
    j.os = "linux";
    const char* install = installPathFor("linux");

    auto parsed = ElfParser::parse(std::span<const uint8_t>(bytes.data(), bytes.size()));
    if (!parsed) {
        emitLog("relink[ELF]: parse failed");
        j.error = "relink[ELF]: parse failed";
        return j.serialize();
    }
    emitLog("relink[ELF]: entry=0x" + [&]{std::ostringstream o;o<<std::hex<<parsed->ehdr.e_entry;
            o<<std::dec<<" needed="<<parsed->needed.size();return o.str();}());

    MemoryManager mm;
    SearchPaths sp;
    const std::string origin = dirOfPath(path);
    size_t pos = 0;
    while (pos <= lib_dirs.size()) {
        auto q = lib_dirs.find(':', pos);
        std::string d = lib_dirs.substr(pos, q == std::string::npos ? std::string::npos : q - pos);
        if (!d.empty()) sp.addLdPath(d);
        if (q == std::string::npos) break;
        pos = q + 1;
    }

    ModuleGraph graph;
    SymbolResolver resolver(graph);
    std::vector<std::unique_ptr<LoadedElf>> keep_alive;
    std::vector<std::string> module_names;
    std::unordered_set<std::string> seen;
    size_t bundled = 0, sys_abi = 0, parse_fail = 0;

    // Load the main program
    auto main_loaded = ElfLoader::load(*parsed, mm);
    if (!main_loaded) {
        emitLog("relink[ELF]: main image failed to map");
        j.error = "relink[ELF]: main image failed to map";
        return j.serialize();
    }
    keep_alive.push_back(std::make_unique<LoadedElf>(std::move(*main_loaded)));
    const std::string main_name = parsed->soname.value_or(fileNameOfPath(path));
    graph.add(Module::fromLoadedElf(*keep_alive.back(), main_name));
    module_names.push_back(main_name);

    // Breadth-first DT_NEEDED closure
    std::vector<std::string> queue(parsed->needed.begin(), parsed->needed.end());
    while (!queue.empty()) {
        std::string soname = queue.back();
        queue.pop_back();
        if (!seen.insert(soname).second) continue;

        auto found = sp.find(soname, origin);
        if (!found) {
            ++sys_abi;
            emitLog("relink[ELF]: " + soname + " not bundled -> served by NINE Linux syscall ABI");
            j.libraries.push_back({soname, "nine-abi", "", install});
            continue;
        }
        std::ifstream lf(*found, std::ios::binary);
        std::vector<uint8_t> lb((std::istreambuf_iterator<char>(lf)), {});
        auto lp = ElfParser::parse(std::span<const uint8_t>(lb.data(), lb.size()));
        if (!lp) {
            ++parse_fail;
            emitLog("relink[ELF]: " + soname + " parse failed (" + *found + ")");
            continue;
        }
        auto le = ElfLoader::load(*lp, mm);
        if (!le) {
            ++parse_fail;
            emitLog("relink[ELF]: " + soname + " failed to map (" + *found + ")");
            continue;
        }
        keep_alive.push_back(std::make_unique<LoadedElf>(std::move(*le)));
        const std::string mod_name = lp->soname.value_or(fileNameOfPath(*found));
        graph.add(Module::fromLoadedElf(*keep_alive.back(), mod_name));
        module_names.push_back(mod_name);
        ++bundled;
        emitLog("relink[ELF]: " + soname + " -> bundled " + *found);
        j.libraries.push_back({soname, "bundled", *found, install});
        for (const auto& n : lp->needed) queue.push_back(n);
    }

    // Apply relocations against the module graph
    std::unordered_set<std::string> unresolved;
    size_t applied = 0;
    for (auto& le : keep_alive) {
        applied += ElfRelocator::apply(*le, mm,
            [&](const std::string& name, bool* is_weak) -> uint64_t {
                auto r = resolver.resolve(name);
                if (r && r->address) return r->address;
                if (is_weak) *is_weak = true;
                unresolved.insert(name);
                return 0;
            });
    }

    // ---- relinker-side translation -------------------------------------
    // Every executable segment is compiled to AArch64 now, while the image is
    // mapped and relocated. The images are written beside the program so a
    // light shell can run it without the dynamic binary translator.
    std::vector<aot::ModuleTranslation> aot_reports;
    {
        std::string aot_dir = dirOfPath(path);
        if (aot_dir.empty()) aot_dir = ".";
        for (size_t i = 0; i < keep_alive.size(); ++i) {
            const std::string stem = aotFileStem(i < module_names.size() ? module_names[i]
                                                                        : main_name);
            auto rep = aot::translate(mm, aot::execRanges(*keep_alive[i]),
                                      keep_alive[i]->entry, stem, aot_dir);
            emitLog("relink[ELF]: " + rep.summary());
            aot_reports.push_back(std::move(rep));
        }
        summarizeAot(j, aot_reports);
    }

    std::ostringstream oss;
    oss << "relink[ELF] done: bundled=" << bundled
        << " sys-abi=" << sys_abi
        << " parse-fail=" << parse_fail
        << " relocs-applied=" << applied
        << " unresolved=" << unresolved.size()
        << " modules=" << graph.size();
    if (!unresolved.empty()) {
        size_t shown = 0;
        for (const auto& n : unresolved) {
            if (shown++ >= 8) break;
            emitLog("relink[ELF]: unresolved symbol " + n);
        }
        if (unresolved.size() > 8)
            emitLog("relink[ELF]: … " + std::to_string(unresolved.size() - 8) + " more unresolved");
    }
    emitLog(oss.str());

    j.summary = withAotLine(relinkSummaryLine(bundled, sys_abi), j);
    j.unresolved.assign(unresolved.begin(), unresolved.end());
    std::sort(j.unresolved.begin(), j.unresolved.end());

    if (parse_fail != 0) {
        j.error = "relink[ELF]: " + std::to_string(parse_fail) +
                  " librar" + (parse_fail == 1 ? "y" : "ies") + " failed to parse or map";
    } else if (!j.unresolved.empty()) {
        j.error = "relink[ELF]: " + std::to_string(j.unresolved.size()) +
                  " unresolved symb" + (j.unresolved.size() == 1 ? "y" : "ols");
    } else {
        j.ok = true;
    }
    return j.serialize();
}

std::string RuntimeBridge::relinkPe(const std::string& path, const std::vector<uint8_t>& bytes) {
    RelinkJson j;
    j.os = "windows";
    const char* install = installPathFor("windows");

    auto parsed = PeParser::parse(bytes.data(), bytes.size());
    if (!parsed) {
        j.error = "relink[PE]: parse failed";
        return j.serialize();
    }
    emitLog("relink[PE]: " + path);

    MemoryManager mm;
    Ntdll nt;
    Kernel32 k32(nt, mm);
    OtherDlls other(k32);
    PeMapper mapper(mm);
    auto mapped = mapper.map(*parsed, bytes.data(), bytes.size());
    if (!mapped) {
        emitLog("relink[PE]: image failed to map");
        j.error = "relink[PE]: image failed to map";
        return j.serialize();
    }
    nt.ldrAdd(fileNameOfPath(path), mapped->base, parsed->opt.size_of_image);

    size_t relocs = 0;
    if (mapped->relocated) {
        PeRelocator pr(mm);
        relocs = pr.apply(*mapped, bytes.data(), bytes.size());
        emitLog("relink[PE]: base relocs applied=" + std::to_string(relocs));
    }

    PeImports imports(mm);
    auto ents = imports.walk(*mapped, bytes.data(), bytes.size());
    auto delay = imports.walkDelay(*mapped, bytes.data(), bytes.size());
    ents.insert(ents.end(), delay.begin(), delay.end());
    std::unordered_set<std::string> dlls;
    for (const auto& e : ents) dlls.insert(lowerStr(e.dll));
    emitLog("relink[PE]: " + std::to_string(ents.size()) + " imports from " +
            std::to_string(dlls.size()) + " dll(s) -> NINE Windows ABI (ntdll/kernel32/…)");

    // Every imported DLL is satisfied by NINE's Windows ABI shims — there is no
    // on-disk PE library search, so provider is always "nine-abi".
    for (const auto& d : dlls) j.libraries.push_back({d, "nine-abi", "", install});

    size_t resolved = 0, unresolved = 0;
    size_t patched = imports.resolveAndPatch(*mapped, ents,
        [&](const std::string& dll) -> uint64_t {
            uint64_t base = k32.loadLibrary(dll);
            std::ostringstream o;
            o << "relink[PE]: " << dll << " -> NINE module @0x" << std::hex << base;
            emitLog(o.str());
            return base;
        },
        [&](const std::string& dll, const std::string& name) -> uint64_t {
            std::string dl = lowerStr(dll);
            // A stubbed export is callable but still unimplemented, so it is
            // reported as unresolved even though the IAT gets a real address.
            const bool known = k32.abi().has(dl, name) ||
                               k32.abi().has(dl == "kernelbase.dll" ? "kernel32.dll" : dl, name);
            uint64_t a = 0;
            if (dl == "ntdll.dll" || dl == "kernel32.dll" || dl == "kernelbase.dll")
                a = k32.resolve(name);
            if (!a) a = other.resolve(dl, name);
            if (a && known) {
                ++resolved;
            } else {
                ++unresolved;
                emitLog(std::string("relink[PE]: ") + (a ? "stubbed " : "unresolved ") +
                        dll + "!" + name);
                j.unresolved.push_back(dl + "!" + name);
            }
            return a;
        });

    // ---- relinker-side translation -------------------------------------
    {
        std::string aot_dir = dirOfPath(path);
        if (aot_dir.empty()) aot_dir = ".";
        std::vector<aot::ModuleTranslation> reports;
        auto rep = aot::translate(mm, aot::execRanges(*parsed),
                                  mapped->base + parsed->opt.address_of_entry,
                                  aotFileStem(fileNameOfPath(path)), aot_dir);
        emitLog("relink[PE]: " + rep.summary());
        reports.push_back(std::move(rep));
        summarizeAot(j, reports);
    }

    std::ostringstream oss;
    oss << "relink[PE] done: patched=" << patched << "/" << ents.size()
        << " base-relocs=" << relocs
        << " resolved=" << resolved
        << " unresolved=" << unresolved;
    emitLog(oss.str());

    j.summary = withAotLine(relinkSummaryLine(0, dlls.size()), j);
    std::sort(j.unresolved.begin(), j.unresolved.end());
    j.unresolved.erase(std::unique(j.unresolved.begin(), j.unresolved.end()),
                       j.unresolved.end());
    if (unresolved != 0) {
        j.error = "relink[PE]: " + std::to_string(j.unresolved.size()) +
                  " unresolved import" + (j.unresolved.size() == 1 ? "" : "s");
    } else {
        j.ok = true;
    }
    return j.serialize();
}

} // namespace nexus
