#pragma once

#include "GuestContext.h"
#include <cstdint>
#include <cstddef>

namespace nexus {

using BlockExit = BlockExitReason;
using TranslatedBlockFn = void (*)(GuestContext* ctx);

// J1.1 Calling convention:
//   Entry: X0 = GuestContext*
//   Pinned: X19=RIP, X20=RFLAGS, X21..X28=RAX..RDI
//   Scratch: X9..X15
//   Callee-saved X19-X28 saved/restored by block prologue/epilogue
//
// J1.2 Exit protocol:
//   Store BlockExitReason to ctx->exit_reason, optional args to exit_arg*,
//   store updated RIP/GPRs, restore callee-saved, RET to trampoline.
class HostTrampoline {
public:
    static void invoke(TranslatedBlockFn fn, GuestContext& ctx);

    static size_t emitStoreExitReason(uint32_t* out, BlockExit reason,
                                      int ctx_reg = 0, int scratch = 9);
    static size_t emitStoreExitArg0(uint32_t* out, int src_reg, int ctx_reg = 0);
    static size_t emitMovImm64(uint32_t* out, int rd, uint64_t imm);
};

} // namespace nexus
