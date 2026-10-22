#include "Arm64Emitter.h"

namespace nexus {

void Arm64Emitter::nop() { emit(0xD503201F); }
void Arm64Emitter::ret() { emit(0xD65F03C0); }
void Arm64Emitter::br(int xn) { emit(0xD61F0000 | (xn << 5)); }
void Arm64Emitter::blr(int xn) { emit(0xD63F0000 | (xn << 5)); }

void Arm64Emitter::add_reg(int rd, int rn, int rm, bool sf64) {
    emit((sf64 ? 0x8B000000u : 0x0B000000u) | (rm << 16) | (rn << 5) | rd);
}
void Arm64Emitter::sub_reg(int rd, int rn, int rm, bool sf64) {
    emit((sf64 ? 0xCB000000u : 0x4B000000u) | (rm << 16) | (rn << 5) | rd);
}
void Arm64Emitter::and_reg(int rd, int rn, int rm, bool sf64) {
    emit((sf64 ? 0x8A000000u : 0x0A000000u) | (rm << 16) | (rn << 5) | rd);
}
void Arm64Emitter::orr_reg(int rd, int rn, int rm, bool sf64) {
    emit((sf64 ? 0xAA000000u : 0x2A000000u) | (rm << 16) | (rn << 5) | rd);
}
void Arm64Emitter::eor_reg(int rd, int rn, int rm, bool sf64) {
    emit((sf64 ? 0xCA000000u : 0x4A000000u) | (rm << 16) | (rn << 5) | rd);
}
void Arm64Emitter::mov_reg(int rd, int rm, bool sf64) {
    orr_reg(rd, 31, rm, sf64);
}

void Arm64Emitter::add_imm(int rd, int rn, unsigned imm12, bool sf64) {
    emit((sf64 ? 0x91000000u : 0x11000000u) | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd);
}
void Arm64Emitter::sub_imm(int rd, int rn, unsigned imm12, bool sf64) {
    emit((sf64 ? 0xD1000000u : 0x51000000u) | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd);
}

void Arm64Emitter::lsl_reg(int rd, int rn, int rm, bool sf64) {
    // LSLV
    emit((sf64 ? 0x9AC02000u : 0x1AC02000u) | (rm << 16) | (rn << 5) | rd);
}
void Arm64Emitter::lsr_reg(int rd, int rn, int rm, bool sf64) {
    emit((sf64 ? 0x9AC02400u : 0x1AC02400u) | (rm << 16) | (rn << 5) | rd);
}
void Arm64Emitter::asr_reg(int rd, int rn, int rm, bool sf64) {
    emit((sf64 ? 0x9AC02800u : 0x1AC02800u) | (rm << 16) | (rn << 5) | rd);
}
void Arm64Emitter::ror_reg(int rd, int rn, int rm, bool sf64) {
    emit((sf64 ? 0x9AC02C00u : 0x1AC02C00u) | (rm << 16) | (rn << 5) | rd);
}

void Arm64Emitter::lsl_imm(int rd, int rn, unsigned sh, bool sf64) {
    // UBFM alias for LSL
    unsigned bits = sf64 ? 63 : 31;
    unsigned imms = bits - (sh & bits);
    unsigned immr = (bits + 1 - (sh & bits)) & bits;
    emit((sf64 ? 0xD3400000u : 0x53000000u) | (immr << 16) | (imms << 10) | (rn << 5) | rd);
}
void Arm64Emitter::lsr_imm(int rd, int rn, unsigned sh, bool sf64) {
    unsigned bits = sf64 ? 63 : 31;
    emit((sf64 ? 0xD3400000u : 0x53000000u) | ((sh & bits) << 16) | (bits << 10) | (rn << 5) | rd);
}
void Arm64Emitter::asr_imm(int rd, int rn, unsigned sh, bool sf64) {
    unsigned bits = sf64 ? 63 : 31;
    emit((sf64 ? 0x93400000u : 0x13000000u) | ((sh & bits) << 16) | (bits << 10) | (rn << 5) | rd);
}

void Arm64Emitter::mul(int rd, int rn, int rm, bool sf64) {
    emit((sf64 ? 0x9B007C00u : 0x1B007C00u) | (rm << 16) | (rn << 5) | rd);
}
void Arm64Emitter::udiv(int rd, int rn, int rm, bool sf64) {
    emit((sf64 ? 0x9AC00800u : 0x1AC00800u) | (rm << 16) | (rn << 5) | rd);
}
void Arm64Emitter::sdiv(int rd, int rn, int rm, bool sf64) {
    emit((sf64 ? 0x9AC00C00u : 0x1AC00C00u) | (rm << 16) | (rn << 5) | rd);
}

void Arm64Emitter::movz(int rd, uint16_t imm, int hw, bool sf64) {
    emit((sf64 ? 0xD2800000u : 0x52800000u) | (hw << 21) | (uint32_t(imm) << 5) | rd);
}
void Arm64Emitter::movk(int rd, uint16_t imm, int hw, bool sf64) {
    emit((sf64 ? 0xF2800000u : 0x72800000u) | (hw << 21) | (uint32_t(imm) << 5) | rd);
}
void Arm64Emitter::mov_imm64(int rd, uint64_t imm) {
    movz(rd, uint16_t(imm & 0xFFFF), 0, true);
    for (int hw = 1; hw < 4; ++hw) {
        uint16_t part = uint16_t((imm >> (16 * hw)) & 0xFFFF);
        if (part) movk(rd, part, hw, true);
    }
}

void Arm64Emitter::cmp_reg(int rn, int rm, bool sf64) {
    // SUBS XZR, Rn, Rm
    emit((sf64 ? 0xEB000000u : 0x6B000000u) | (rm << 16) | (rn << 5) | 31);
}
void Arm64Emitter::cmp_imm(int rn, unsigned imm12, bool sf64) {
    emit((sf64 ? 0xF1000000u : 0x71000000u) | ((imm12 & 0xFFF) << 10) | (rn << 5) | 31);
}
void Arm64Emitter::cset(int rd, int cond) {
    // CSINC Wd, WZR, WZR, invert(cond)
    int inv = cond ^ 1;
    emit(0x1A9F07E0u | (inv << 12) | rd);
}
void Arm64Emitter::csel(int rd, int rn, int rm, int cond, bool sf64) {
    emit((sf64 ? 0x9A800000u : 0x1A800000u) | (rm << 16) | (cond << 12) | (rn << 5) | rd);
}

void Arm64Emitter::ldr_x(int rt, int rn, size_t byte_off) {
    emit(0xF9400000u | ((uint32_t(byte_off / 8) & 0xFFF) << 10) | (rn << 5) | rt);
}
void Arm64Emitter::str_x(int rt, int rn, size_t byte_off) {
    emit(0xF9000000u | ((uint32_t(byte_off / 8) & 0xFFF) << 10) | (rn << 5) | rt);
}
void Arm64Emitter::ldr_w(int rt, int rn, size_t byte_off) {
    emit(0xB9400000u | ((uint32_t(byte_off / 4) & 0xFFF) << 10) | (rn << 5) | rt);
}
void Arm64Emitter::str_w(int rt, int rn, size_t byte_off) {
    emit(0xB9000000u | ((uint32_t(byte_off / 4) & 0xFFF) << 10) | (rn << 5) | rt);
}
void Arm64Emitter::ldrb(int rt, int rn, size_t byte_off) {
    emit(0x39400000u | ((uint32_t(byte_off) & 0xFFF) << 10) | (rn << 5) | rt);
}
void Arm64Emitter::strb(int rt, int rn, size_t byte_off) {
    emit(0x39000000u | ((uint32_t(byte_off) & 0xFFF) << 10) | (rn << 5) | rt);
}
void Arm64Emitter::ldrh(int rt, int rn, size_t byte_off) {
    emit(0x79400000u | ((uint32_t(byte_off / 2) & 0xFFF) << 10) | (rn << 5) | rt);
}
void Arm64Emitter::strh(int rt, int rn, size_t byte_off) {
    emit(0x79000000u | ((uint32_t(byte_off / 2) & 0xFFF) << 10) | (rn << 5) | rt);
}
void Arm64Emitter::ldr_x_reg(int rt, int rn, int rm) {
    emit(0xF8600800u | (rm << 16) | (rn << 5) | rt); // LDR Xt, [Xn, Xm]
}
void Arm64Emitter::str_x_reg(int rt, int rn, int rm) {
    emit(0xF8200800u | (rm << 16) | (rn << 5) | rt);
}

void Arm64Emitter::stp_pre(int rt1, int rt2, int imm7_slots) {
    emit(0xA9800000u | ((imm7_slots & 0x7F) << 15) | (rt2 << 10) | (31 << 5) | rt1);
}
void Arm64Emitter::ldp_post(int rt1, int rt2, int imm7_slots) {
    emit(0xA8C00000u | ((imm7_slots & 0x7F) << 15) | (rt2 << 10) | (31 << 5) | rt1);
}

void Arm64Emitter::ldadd_x(int rs, int rt, int rn) {
    // LDADD Xs, Xt, [Xn]  (ARMv8.1 LSE) — may trap on older cores; still correct encoding
    emit(0xF820001Fu | (rs << 16) | (rn << 5) | rt);
}
void Arm64Emitter::swp_x(int rs, int rt, int rn) {
    emit(0xF820801Fu | (rs << 16) | (rn << 5) | rt);
}

void Arm64Emitter::movi_v_zero(int vd) {
    // MOVI Vd.16B, #0
    emit(0x4F00E400u | vd);
}
void Arm64Emitter::orr_v(int vd, int vn, int vm) {
    emit(0x4EA01C00u | (vm << 16) | (vn << 5) | vd);
}
void Arm64Emitter::fadd_4s(int vd, int vn, int vm) {
    emit(0x4E20D400u | (vm << 16) | (vn << 5) | vd);
}
void Arm64Emitter::fmul_4s(int vd, int vn, int vm) {
    emit(0x6E20DC00u | (vm << 16) | (vn << 5) | vd);
}

size_t Arm64Emitter::addLiteral(uint64_t v) {
    literals_.push_back(v);
    return literals_.size() - 1;
}
void Arm64Emitter::emitLongBranch(uint64_t target) {
    addLiteral(target);
    emit(0x58000009); // LDR X9, literal (relocated at install)
    br(9);
}
void Arm64Emitter::loadAbs64(int rd, uint64_t abs) {
    mov_imm64(rd, abs);
}

} // namespace nexus
