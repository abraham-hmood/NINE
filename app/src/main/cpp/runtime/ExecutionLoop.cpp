#include "ExecutionLoop.h"
#include "HostTrampoline.h"
#include "MemHelpers.h"
#include "../diagnostics/Logger.h"
#include <algorithm>
#include <cstring>

namespace nexus {

uint64_t ExecutionLoop::hashRange(const uint8_t* p, size_t n) const {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

const uint8_t* ExecutionLoop::resolveGuestBytes(uint64_t pc, size_t& out_len,
                                                const uint8_t* fallback,
                                                size_t fallback_len,
                                                uint64_t fallback_base) const {
    if (mm_) {
        void* host = mm_->guestToHost(pc);
        if (host) {
            auto region = mm_->query(pc);
            if (region) {
                size_t off = static_cast<size_t>(pc - region->guest_start);
                out_len = region->host_size > off ? region->host_size - off : 0;
                return static_cast<const uint8_t*>(host);
            }
        }
    }
    if (fallback && fallback_len && pc >= fallback_base &&
        pc < fallback_base + fallback_len) {
        size_t off = static_cast<size_t>(pc - fallback_base);
        out_len = fallback_len - off;
        return fallback + off;
    }
    out_len = 0;
    return nullptr;
}

void ExecutionLoop::ensureTranslated(uint64_t pc, const uint8_t* bytes, size_t avail) {
    if (!do_translate_ || !bytes || !avail) return;
    uint64_t h = hashRange(bytes, std::min<size_t>(64, avail));
    if (cache_.isStale(pc, h)) {
        cache_.invalidate(pc);
        counters_.smc_invalidations.fetch_add(1, std::memory_order_relaxed);
    }
    if (cache_.lookup(pc)) {
        counters_.cache_hits.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    counters_.cache_misses.fetch_add(1, std::memory_order_relaxed);
    auto tu = tr_.translateBlock(bytes, avail, pc);
    if (!tu.arm64.empty()) {
        if (cache_.install(pc, tu.guest_end, tu.arm64.data(), tu.arm64.size(), h)) {
            counters_.translations.fetch_add(1, std::memory_order_relaxed);
            cache_.seal(); // W^X after install
        }
    }
}

int64_t ExecutionLoop::handleSyscall(GuestContext& ctx, int64_t nr) {
    counters_.syscalls.fetch_add(1, std::memory_order_relaxed);
    if (on_syscall_) return on_syscall_(nr, ctx);
    return sys_.translate(static_cast<int>(nr),
                          ctx.rdi(), ctx.rsi(), ctx.rdx(),
                          ctx.gpr[10], ctx.gpr[8], ctx.gpr[9]);
}

ExecResult ExecutionLoop::run(uint64_t entry, const uint8_t* guest_code, size_t len,
                              uint64_t max_steps) {
    GuestContext& ctx = ContextSwitch::current();
    ctx.clear();
    ctx.rip = entry;
    return resume(ctx, guest_code, len, max_steps);
}

ExecResult ExecutionLoop::resume(GuestContext& ctx, const uint8_t* guest_code, size_t len,
                                 uint64_t max_steps) {
    MemHelpers_setMM(mm_);
    ExecResult last;
    uint64_t fallback_base = (guest_code && len) ? ctx.rip : 0;

    for (uint64_t steps = 0; steps < max_steps; ++steps) {
        if (stop_.load(std::memory_order_acquire)) {
            last.reason = ExitReason::HALT;
            last.guest_pc = ctx.rip;
            return last;
        }

        size_t avail = 0;
        const uint8_t* bytes = resolveGuestBytes(ctx.rip, avail, guest_code, len, fallback_base);
        if ((!bytes || !avail) && guest_code && len) {
            bytes = guest_code;
            avail = len;
            fallback_base = ctx.rip;
        }
        if (!bytes || !avail) {
            seh_.dispatch(0xC0000005, ctx.rip, "unmapped guest PC");
            last.reason = ExitReason::EXCEPTION;
            last.guest_pc = ctx.rip;
            counters_.exceptions.fetch_add(1, std::memory_order_relaxed);
            return last;
        }

        // ---- J1.3: translate on miss, then prefer JIT ----
        ensureTranslated(ctx.rip, bytes, avail);

        auto hit = cache_.lookup(ctx.rip);
        if (hit && hit->host_code) {
            auto* fn = reinterpret_cast<TranslatedBlockFn>(hit->host_code);
            uint64_t block_pc = ctx.rip;
            HostTrampoline::invoke(fn, ctx);
            counters_.blocks_executed.fetch_add(1, std::memory_order_relaxed);
            counters_.jit_invokes.fetch_add(1, std::memory_order_relaxed);
            cf_.noteTrampoline();
            cf_.recordEdge(block_pc, ctx.rip);

            switch (ctx.exit_reason) {
                case BlockExitReason::CONTINUE:
                case BlockExitReason::INDIRECT: {
                    // J3: if hot trace exists, note hit (loop still dispatches block-by-block)
                    auto tr = cf_.buildTrace(ctx.rip, 8, 2);
                    if (tr.size() > 1) cf_.noteTraceHit();
                    if (ctx.exit_reason == BlockExitReason::INDIRECT) {
                        if (auto h = cf_.icLookup(block_pc, ctx.rip)) {
                            cf_.noteIcHit();
                        } else {
                            auto hit2 = cache_.lookup(ctx.rip);
                            if (hit2 && hit2->host_code)
                                cf_.icUpdate(block_pc, ctx.rip,
                                    reinterpret_cast<uint64_t>(hit2->host_code));
                        }
                    }
                    last.reason = ExitReason::NONE;
                    last.guest_pc = ctx.rip;
                    continue;
                }

                case BlockExitReason::SYSCALL: {
                    int64_t nr = static_cast<int64_t>(ctx.rax());
                    int64_t ret = handleSyscall(ctx, nr);
                    ctx.rax() = static_cast<uint64_t>(ret);
                    // RIP already advanced by the translated block past SYSCALL
                    if (inline_syscalls_) {
                        last.reason = ExitReason::NONE;
                        last.guest_pc = ctx.rip;
                        last.syscall_nr = nr;
                        last.syscall_ret = ret;
                        continue; // J1.4: resume into JIT
                    }
                    last.reason = ExitReason::SYSCALL;
                    last.syscall_nr = nr;
                    last.syscall_ret = ret;
                    last.guest_pc = ctx.rip;
                    return last;
                }

                case BlockExitReason::IMPORT: {
                    uint64_t addr = ctx.exit_arg0;
                    if (import_) {
                        uint64_t resolved = import_(addr);
                        ctx.rax() = resolved;
                    }
                    if (inline_syscalls_) {
                        last.reason = ExitReason::NONE;
                        last.guest_pc = ctx.rip;
                        last.import_addr = addr;
                        continue;
                    }
                    last.reason = ExitReason::IMPORT;
                    last.import_addr = addr;
                    last.guest_pc = ctx.rip;
                    return last;
                }

                case BlockExitReason::EXCEPTION:
                    seh_.dispatch(ctx.exit_code ? ctx.exit_code : 0xC000001D,
                                  ctx.rip, "JIT exception");
                    last.reason = ExitReason::EXCEPTION;
                    last.guest_pc = ctx.rip;
                    counters_.exceptions.fetch_add(1, std::memory_order_relaxed);
                    return last;

                case BlockExitReason::HALT:
                    last.reason = ExitReason::HALT;
                    last.guest_pc = ctx.rip;
                    return last;
            }
        }

        // ---- No JIT block ----
        if (jit_only_) {
            // J1.4 pure-JIT path: refuse interpreter
            seh_.dispatch(0xC000001D, ctx.rip, "jit_only: no translated block");
            last.reason = ExitReason::EXCEPTION;
            last.guest_pc = ctx.rip;
            counters_.exceptions.fetch_add(1, std::memory_order_relaxed);
            return last;
        }

        counters_.interp_fallbacks.fetch_add(1, std::memory_order_relaxed);
        auto ir = interp_.executeBlock(ctx, bytes, avail, /*max_insns=*/64);
        counters_.blocks_executed.fetch_add(1, std::memory_order_relaxed);
        counters_.insns_executed.fetch_add(1, std::memory_order_relaxed);

        switch (ir.exit) {
            case InterpExit::CONTINUE:
            case InterpExit::BLOCK_END:
                last.reason = ExitReason::NONE;
                last.guest_pc = ctx.rip;
                break;

            case InterpExit::SYSCALL: {
                int64_t nr = ir.syscall_nr;
                int64_t ret = handleSyscall(ctx, nr);
                ctx.rax() = static_cast<uint64_t>(ret);
                ctx.rip = ir.next_pc;
                if (inline_syscalls_) {
                    last.reason = ExitReason::NONE;
                    last.guest_pc = ctx.rip;
                    last.syscall_nr = nr;
                    last.syscall_ret = ret;
                    break; // continue loop
                }
                last.reason = ExitReason::SYSCALL;
                last.syscall_nr = nr;
                last.syscall_ret = ret;
                last.guest_pc = ctx.rip;
                return last;
            }

            case InterpExit::EXCEPTION: {
                seh_.dispatch(ir.exception_code, ctx.rip,
                              ir.exception_msg.empty() ? "exception" : ir.exception_msg.c_str());
                last.reason = ExitReason::EXCEPTION;
                last.guest_pc = ctx.rip;
                counters_.exceptions.fetch_add(1, std::memory_order_relaxed);
                return last;
            }

            case InterpExit::HALT:
                last.reason = ExitReason::HALT;
                last.guest_pc = ctx.rip;
                return last;
        }
    }
    // Step budget exhausted — caller should continue with another resume()
    last.reason = ExitReason::YIELD;
    last.guest_pc = ctx.rip;
    return last;
}

} // namespace nexus
