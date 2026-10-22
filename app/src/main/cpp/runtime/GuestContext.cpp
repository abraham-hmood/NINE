#include "GuestContext.h"

namespace nexus {

static thread_local GuestContext tls_ctx;

GuestContext& ContextSwitch::current() {
    return tls_ctx;
}

void ContextSwitch::save(GuestContext& ctx) {
    ctx = tls_ctx;
}

void ContextSwitch::restore(const GuestContext& ctx) {
    tls_ctx = ctx;
}

bool ContextSwitch::hitsRedZone(const GuestContext& ctx, uint64_t addr, size_t size) {
    if (ctx.rsp() < GuestContext::kRedZone) return false;
    uint64_t rz = ctx.rsp() - GuestContext::kRedZone;
    return addr < ctx.rsp() && (addr + size) > rz;
}

void ContextSwitch::pushExceptionFrame(GuestContext& out) {
    out = tls_ctx;
}

void ContextSwitch::popExceptionFrame(const GuestContext& in) {
    tls_ctx = in;
}

} // namespace nexus
