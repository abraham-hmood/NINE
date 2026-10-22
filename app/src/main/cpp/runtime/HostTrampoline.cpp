#include "HostTrampoline.h"
#include "CtxLayout.h"
#include <cstddef>

namespace nexus {

void HostTrampoline::invoke(TranslatedBlockFn fn, GuestContext& ctx) {
    if (!fn) {
        ctx.exit_reason = BlockExitReason::HALT;
        return;
    }
    ctx.clearExit();
    fn(&ctx);
}

size_t HostTrampoline::emitMovImm64(uint32_t* out, int rd, uint64_t imm) {
    size_t n = 0;
    // MOVZ Xd, #imm16, LSL 0
    out[n++] = 0xD2800000u | (static_cast<uint32_t>(imm & 0xFFFF) << 5) |
               static_cast<uint32_t>(rd);
    for (int hw = 1; hw < 4; ++hw) {
        uint16_t part = static_cast<uint16_t>((imm >> (16 * hw)) & 0xFFFF);
        if (part == 0) continue;
        // MOVK Xd, #imm16, LSL (hw*16)
        out[n++] = 0xF2800000u | (static_cast<uint32_t>(hw) << 21) |
                   (static_cast<uint32_t>(part) << 5) | static_cast<uint32_t>(rd);
    }
    return n;
}

size_t HostTrampoline::emitStoreExitReason(uint32_t* out, BlockExit reason,
                                           int ctx_reg, int scratch) {
    size_t n = 0;
    uint32_t imm = static_cast<uint32_t>(reason);
    out[n++] = 0xD2800000u | ((imm & 0xFFFF) << 5) | static_cast<uint32_t>(scratch);
    std::size_t off = ctx_off::exit_reason();
    // STR Wscratch, [Xctx, #off] — 32-bit, imm12 scaled by 4
    uint32_t imm12 = static_cast<uint32_t>(off / 4);
    out[n++] = 0xB9000000u | (imm12 << 10) | (static_cast<uint32_t>(ctx_reg) << 5) |
               static_cast<uint32_t>(scratch);
    return n;
}

size_t HostTrampoline::emitStoreExitArg0(uint32_t* out, int src_reg, int ctx_reg) {
    std::size_t off = ctx_off::exit_arg0();
    uint32_t imm12 = static_cast<uint32_t>(off / 8);
    out[0] = 0xF9000000u | (imm12 << 10) | (static_cast<uint32_t>(ctx_reg) << 5) |
             static_cast<uint32_t>(src_reg);
    return 1;
}

} // namespace nexus
