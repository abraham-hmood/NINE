#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <optional>

namespace nexus {

enum class X86Op : uint16_t {
    INVALID = 0,
    NOP, MOV, MOVZX, MOVSX, LEA, PUSH, POP, LEAVE,
    ADD, SUB, ADC, SBB, AND, OR, XOR, CMP, TEST, INC, DEC, NEG, NOT,
    IMUL, MUL, IDIV, DIV, XCHG, CMPXCHG, XADD, CDQ,
    SHL, SHR, SAR, ROL, ROR,
    JMP, JE, JNE, JL, JLE, JG, JGE, JB, JBE, JA, JAE, JS, JNS, JO, JNO,
    CALL, RET,
    SYSCALL, INT3, UD2,
    CMOV, SETCC,
    MOVD, SSE_MOV, PXOR, PUNPCKLDQ, PUNPCKLQDQ, PUNPCKHQDQ,
    MOVLPS_LOAD, MOVLPS_STORE, MOVHPS_LOAD, MOVHPS_STORE,  // SSE scalar/128-bit moves + zeroing
    MOVAPS, ADDPS, MULPS,  // SSE samples; full SSE/AVX via VEX path
    VEX_OP, EVEX_OP,
    STOS, LODS, MOVS, SCAS  // string ops (AA-AF); REP/REPNE via prefix flags
};

enum class OperandKind : uint8_t { NONE, REG, MEM, IMM, REL };

struct MemOp {
    int base = -1;       // register index, -1 = none
    int index = -1;
    int scale = 1;
    int64_t disp = 0;
    bool rip_relative = false;
    uint8_t seg = 0;     // 0=none, 1=FS, 2=GS — base added at emit time
};

struct Operand {
    OperandKind kind = OperandKind::NONE;
    int reg = -1;            // 0-15 GPR, 16+ XMM
    int size = 0;            // bits
    int64_t imm = 0;
    MemOp mem;
};

struct Insn {
    X86Op op = X86Op::INVALID;
    uint8_t length = 0;
    uint64_t address = 0;
    Operand dst;
    Operand src;
    Operand src2;
    bool rex_w = false;
    bool lock = false;
    bool rep = false;    // F3 prefix (REP/REPE)
    bool repne = false;  // F2 prefix (REPNE)
    bool o16 = false;    // 0x66 operand-size prefix
    uint8_t cc = 0;      // condition index (0-15) for CMOV/SETCC
    uint8_t seg = 0;     // segment override: 0=none, 1=FS, 2=GS
    uint8_t vex_l = 0;
    std::string mnemonic;
};

class X86Decoder {
public:
    // Decode one instruction at `data` (guest address `addr`). Returns nullopt on failure.
    static std::optional<Insn> decode(const uint8_t* data, size_t len, uint64_t addr);

    // Decode a linear range into IR.
    static std::vector<Insn> decodeRange(const uint8_t* data, size_t len, uint64_t addr);
};

} // namespace nexus
