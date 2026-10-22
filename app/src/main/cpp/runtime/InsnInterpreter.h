#pragma once
#include <string>

#include "GuestContext.h"
#include "../translator/X86Decoder.h"
#include "../translator/FlagState.h"
#include "../memory/MemoryManager.h"
#include "SmcCoherency.h"
#include <cstdint>

namespace nexus {

enum class InterpExit {
    CONTINUE,       // keep executing next insn
    BLOCK_END,      // hit branch/call/ret that ends a basic block
    SYSCALL,        // guest issued SYSCALL
    EXCEPTION,      // fault
    HALT
};

struct InterpResult {
    InterpExit exit = InterpExit::CONTINUE;
    uint64_t next_pc = 0;
    int64_t syscall_nr = -1;
    uint32_t exception_code = 0;
    std::string exception_msg;
};

// Full software interpreter for decoded x86-64 instructions.
// Updates GuestContext in place. Memory accesses go through MemoryManager
// and trigger SmcCoherency on stores to executable pages.
class InsnInterpreter {
public:
    InsnInterpreter(MemoryManager* mm = nullptr, SmcCoherency* smc = nullptr)
        : mm_(mm), smc_(smc) {}

    void setMemoryManager(MemoryManager* mm) { mm_ = mm; }
    void setSmc(SmcCoherency* smc) { smc_ = smc; }

    InterpResult execute(GuestContext& ctx, const Insn& in);
    InterpResult executeBlock(GuestContext& ctx, const uint8_t* code, size_t len,
                              uint64_t max_insns = 256);

    FlagState& flags() { return flags_; }

private:
    MemoryManager* mm_ = nullptr;
    SmcCoherency* smc_ = nullptr;
    FlagState flags_;

    // Set at the top of execute(): enables correct RIP-relative EAs in
    // readOperand/writeOperand without threading insn_len through ~40 calls.
    int cur_insn_len_ = 0;

    // Memory-access faults (consumed by executeBlock to raise a precise
    // exception instead of silently dropping a failed load/store).
    bool mem_fault_ = false;
    uint64_t mem_fault_addr_ = 0;
    const char* mem_fault_what_ = "";

    uint64_t readOperand(GuestContext& ctx, const Operand& op, int size_bits);
    void writeOperand(GuestContext& ctx, const Operand& op, uint64_t value, int size_bits);
    uint64_t effectiveAddress(GuestContext& ctx, const MemOp& mem, uint64_t rip, int insn_len);

    bool loadMem(uint64_t addr, void* out, size_t n);
    bool storeMem(uint64_t addr, const void* in, size_t n);

    bool evalCondition(GuestContext& ctx, X86Op op);
    bool evalCc(GuestContext& ctx, uint8_t cc);
    void syncFlags(GuestContext& ctx);

    // Last-executed trace ring, dumped with exceptions for post-mortem:
    // rip -> mnemonic, capped to keep log lines bounded.
    std::vector<std::pair<uint64_t, std::string>> trace_;
    static constexpr size_t kTraceCap = 48;

    uint64_t maskSize(uint64_t v, int bits) const {
        if (bits >= 64) return v;
        return v & ((1ULL << bits) - 1);
    }
    uint64_t signExtend(uint64_t v, int bits) const {
        if (bits >= 64) return v;
        uint64_t sign = 1ULL << (bits - 1);
        if (v & sign) return v | (~0ULL << bits);
        return v & ((1ULL << bits) - 1);
    }
};

} // namespace nexus
