#pragma once

#include "X86Decoder.h"
#include "RegisterAllocator.h"
#include "FlagState.h"
#include "Arm64Emitter.h"
#include "../runtime/GuestContext.h"
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <mutex>

namespace nexus {

struct TranslationUnit {
    uint64_t guest_start = 0;
    uint64_t guest_end = 0;
    std::vector<uint32_t> arm64;
    std::vector<uint64_t> literals;
    bool ends_with_branch = false;
    bool ends_with_call = false;
    bool ends_with_syscall = false;
    // Set when the block contains an instruction this emitter has no code for
    // and only a nop placeholder was emitted. Callers must not install such a
    // block — the interpreter has to run it instead.
    bool unsupported = false;
};

// J2.2 Coverage process tracker
class OpcodeCoverage {
public:
    static OpcodeCoverage& instance();
    void seenDecode(X86Op op);
    void seenEmit(X86Op op);
    void seenFallback(X86Op op); // went to interpreter / nop
    std::string report() const;
    size_t decodeCount() const;
    size_t emitCount() const;
    size_t missingEmitCount() const;

private:
    mutable std::mutex mu_;
    std::unordered_set<int> decoded_;
    std::unordered_set<int> emitted_;
    std::unordered_set<int> fallback_;
};

class Translator {
public:
    TranslationUnit translateBlock(const uint8_t* code, size_t len, uint64_t guest_pc);
    RegisterAllocator& regs() { return regs_; }
    FlagState& flags() { return flags_; }
    Arm64Emitter& emitter() { return emit_; }

private:
    RegisterAllocator regs_;
    FlagState flags_;
    Arm64Emitter emit_;
    bool unsupported_ = false;   // sticky within one translateBlock() call

    void emitPrologue();
    void emitEpilogueAndReturn();
    void emitBlockExit(BlockExitReason reason, uint64_t next_rip);
    void translateInsn(const Insn& in);

    void emitAlu(const Insn& in);
    void emitShift(const Insn& in);
    void emitMov(const Insn& in);
    void emitLea(const Insn& in);
    void emitPush(const Insn& in);
    void emitPop(const Insn& in);
    void emitLeave(const Insn& in);
    void emitBranch(const Insn& in);
    void emitCall(const Insn& in);
    void emitRet();
    void emitSyscall();
    void emitSetcc(const Insn& in);
    void emitCmov(const Insn& in);
    void emitSimd(const Insn& in);

    // Effective address into Xscratch (X9 by default)
    void emitEA(const Operand& mem, int dest_reg);
    void emitLoadOp(const Operand& src, int dest_reg, int size_bits);
    void emitStoreOp(const Operand& dst, int src_reg, int size_bits);
    void emitHelperCall(uint64_t fn_addr, int arg0_reg, int arg1_reg, int arg2_reg = -1);

    int hostGpr(int guest) const;
};

} // namespace nexus
