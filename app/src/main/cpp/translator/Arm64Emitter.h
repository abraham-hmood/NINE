#pragma once

#include <cstdint>
#include <vector>
#include <cstddef>

namespace nexus {

// Production AArch64 encoder used by Translator (J2).
class Arm64Emitter {
public:
    void clear() { code_.clear(); literals_.clear(); }
    void emit(uint32_t insn) { code_.push_back(insn); }
    void emitRaw(uint32_t insn) { emit(insn); }

    const std::vector<uint32_t>& code() const { return code_; }
    const std::vector<uint64_t>& literals() const { return literals_; }
    size_t size() const { return code_.size(); }

    // ---- Data processing ----
    void nop();
    void ret();
    void br(int xn);
    void blr(int xn);

    void add_reg(int rd, int rn, int rm, bool sf64 = true);
    void sub_reg(int rd, int rn, int rm, bool sf64 = true);
    void and_reg(int rd, int rn, int rm, bool sf64 = true);
    void orr_reg(int rd, int rn, int rm, bool sf64 = true);
    void eor_reg(int rd, int rn, int rm, bool sf64 = true);
    void mov_reg(int rd, int rm, bool sf64 = true);

    void add_imm(int rd, int rn, unsigned imm12, bool sf64 = true);
    void sub_imm(int rd, int rn, unsigned imm12, bool sf64 = true);

    void lsl_reg(int rd, int rn, int rm, bool sf64 = true);
    void lsr_reg(int rd, int rn, int rm, bool sf64 = true);
    void asr_reg(int rd, int rn, int rm, bool sf64 = true);
    void ror_reg(int rd, int rn, int rm, bool sf64 = true);

    void lsl_imm(int rd, int rn, unsigned sh, bool sf64 = true);
    void lsr_imm(int rd, int rn, unsigned sh, bool sf64 = true);
    void asr_imm(int rd, int rn, unsigned sh, bool sf64 = true);

    void mul(int rd, int rn, int rm, bool sf64 = true);
    void udiv(int rd, int rn, int rm, bool sf64 = true);
    void sdiv(int rd, int rn, int rm, bool sf64 = true);

    void movz(int rd, uint16_t imm, int hw = 0, bool sf64 = true);
    void movk(int rd, uint16_t imm, int hw, bool sf64 = true);
    void mov_imm64(int rd, uint64_t imm);
    void mov_imm32(int rd, uint32_t imm);          // 32-bit form (zero-extends)

    // Branches (offsets are in instructions, relative to this insn)
    void b(int off_insns);
    void b_cond(int cond, int off_insns);
    void cbz(int rt, int off_insns);
    void cbnz(int rt, int off_insns);

    // Bit/half/byte reversal, bit test, and 64-bit "not"
    void rev_x(int rd, int rn);
    void rev_w(int rd, int rn);
    void rev16_w(int rd, int rn);
    void rev32_x(int rd, int rn);
    void tst_reg(int rn, int rm);
    void mvn_reg(int rd, int rm, bool sf64 = true);

    // Patch a previously emitted instruction (branch fixups).
    uint32_t& at(size_t index) { return code_[index]; }

    // Compare / conditional
    void cmp_reg(int rn, int rm, bool sf64 = true);
    void cmp_imm(int rn, unsigned imm12, bool sf64 = true);
    void cset(int rd, int cond); // cond: EQ=0, NE=1, CS=2, ...
    void csel(int rd, int rn, int rm, int cond, bool sf64 = true);

    // Memory (unsigned offset, scaled)
    void ldr_x(int rt, int rn, size_t byte_off);
    void str_x(int rt, int rn, size_t byte_off);
    void ldr_w(int rt, int rn, size_t byte_off);
    void str_w(int rt, int rn, size_t byte_off);
    void ldrb(int rt, int rn, size_t byte_off);
    void strb(int rt, int rn, size_t byte_off);
    void ldrh(int rt, int rn, size_t byte_off);
    void strh(int rt, int rn, size_t byte_off);
    void ldr_x_reg(int rt, int rn, int rm); // [Xn, Xm]
    void str_x_reg(int rt, int rn, int rm);

    // Pair
    void stp_pre(int rt1, int rt2, int imm7_slots);  // [SP, #imm]!
    void ldp_post(int rt1, int rt2, int imm7_slots); // [SP], #imm

    // Atomics (LSE if available; fallback LDXR/STXR sequences for store)
    void ldadd_x(int rs, int rt, int rn); // LDADD Xrs, Xt, [Xn]
    void swp_x(int rs, int rt, int rn);

    // FP/SIMD subset (Q registers as V0-V31 encoded as 0-31)
    void movi_v_zero(int vd);           // MOVI Vd.16B, #0
    void orr_v(int vd, int vn, int vm); // ORR Vd.16B, Vn.16B, Vm.16B
    void fadd_4s(int vd, int vn, int vm);
    void fmul_4s(int vd, int vn, int vm);

    // Literal pool helper: LDR Xt, label ; BR Xt
    void emitLongBranch(uint64_t target);
    size_t addLiteral(uint64_t v);

    // ADRP + LDR for absolute address into register (for helper calls)
    void loadAbs64(int rd, uint64_t abs);

private:
    std::vector<uint32_t> code_;
    std::vector<uint64_t> literals_;
};

// AArch64 condition codes (for B.cond / CSEL / CSET)
enum ArmCond : int {
    EQ = 0, NE = 1, CS = 2, CC = 3, MI = 4, PL = 5, VS = 6, VC = 7,
    HI = 8, LS = 9, GE = 10, LT = 11, GT = 12, LE = 13, AL = 14
};

} // namespace nexus
