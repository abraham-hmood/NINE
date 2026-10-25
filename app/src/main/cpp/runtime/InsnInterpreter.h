#pragma once
#include <string>

#include "GuestContext.h"
#include "Sgx.h"
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
    // SGX (ENCLS/ENCLU/ENCLV) model, enabled by the host bring-up when the
    // guest is allowed to execute privileged SGX leaves. Off by default, which
    // makes ENCLS raise #UD exactly as a CPL-3 guest sees on real silicon.
    void setSgxEnabled(bool on) { sgx_enabled_ = on; }
    bool sgxEnabled() const { return sgx_enabled_; }
    // Ring-0 gate for ENCLS/ENCLV (they are #UD at CPL > 0 on real silicon).
    void setSgxRing0(bool on) { sgx_ring0_ = on; }
    bool sgxRing0() const { return sgx_ring0_; }
    SgxState& sgx() { return sgx_; }

    InterpResult execute(GuestContext& ctx, const Insn& in);
    InterpResult executeBlock(GuestContext& ctx, const uint8_t* code, size_t len,
                              uint64_t max_insns = 256);

    FlagState& flags() { return flags_; }

private:
    MemoryManager* mm_ = nullptr;
    SmcCoherency* smc_ = nullptr;
    FlagState flags_;
    bool sgx_enabled_ = false;
    bool sgx_ring0_ = false;
    SgxState sgx_;

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

    // 128-bit XMM access. GuestContext stores XMM/YMM as byte arrays
    // (ctx.ymm[0..15], 32 bytes each), so SIMD ops cannot use the scalar
    // readOperand path (which caps at 8 bytes).
    void readXmm(GuestContext& ctx, int reg, uint8_t out[16]) const;
    void writeXmm(GuestContext& ctx, int reg, const uint8_t in[16]);
    // Loads `bytes` (4/8/16) of an SSE source into a zeroed 16-byte buffer.
    // Returns false on a guest memory fault (raises mem_fault_).
    bool loadSseSource(GuestContext& ctx, const Operand& src, uint8_t out[16], int bytes);
    // SF/ZF/PF from a byte result; CF/OF/AF left untouched (AAA/AAD/AAM/AAS
    // leave them architecturally undefined).
    void setSzp(GuestContext& ctx, uint8_t value);
    // SF/ZF from a 16/32/64-bit result; every other flag is left untouched.
    void setSz(GuestContext& ctx, uint64_t value, int bits);
    // Clear `clear` flag bits and set `set` bits, leaving the rest alone.
    void setFlagsMasked(GuestContext& ctx, uint64_t clear, uint64_t set);
    // #BR — raise the bound-range exception (STATUS_BOUND_RANGE_EXCEEDED).
    InterpResult raiseBoundRange(InterpResult r) const;

    // #PF raised when a SIMD/conversion helper cannot read its source.
    InterpResult sseFault(const char* what) const {
        InterpResult r;
        r.exit = InterpExit::EXCEPTION;
        r.exception_code = 0xC0000005;
        r.exception_msg = std::string(what) + ": source load fault";
        return r;
    }

    // x87 escape group (D8-DF). Defined in X87Exec.cpp; it needs the private
    // loadMem/storeMem/effectiveAddress helpers, hence the member function.
    InterpResult executeX87(GuestContext& ctx, const Insn& in);

    // VEX/EVEX vector instructions. Defined in VecExec.cpp.
    InterpResult executeVec(GuestContext& ctx, const Insn& in);

    // ENCLS/ENCLU/ENCLV. Defined in Sgx.cpp.
    InterpResult executeSgx(GuestContext& ctx, const Insn& in);

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
