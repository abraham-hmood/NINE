#include "X86Decoder.h"
#include "VecTable.h"
#include <algorithm>

namespace nexus {

// Compatibility/legacy decode switch (ARPL/BOUND). Off for the normal 64-bit
// pipeline; see X86Decoder::setCompat32.
static thread_local bool g_compat32 = false;

void X86Decoder::setCompat32(bool on) { g_compat32 = on; }
bool X86Decoder::compat32() { return g_compat32; }

static int modrmReg(uint8_t m) { return (m >> 3) & 7; }
static int modrmRm(uint8_t m) { return m & 7; }
static int modrmMod(uint8_t m) { return m >> 6; }

// SIB + displacement tail for a memory operand whose modrm byte was already
// consumed and whose mod != 3. Callers set op.kind = MEM and op.mem.base.
static void parseRmRest(const uint8_t* data, size_t len, size_t& i, uint8_t modrm,
                        int rex_b, int rex_x, Operand& op) {
    int mod = modrmMod(modrm);
    int rm = modrmRm(modrm) + rex_b;
    op.kind = OperandKind::MEM;
    op.mem.base = rm;
    if (mod == 0 && (rm & 7) == 5) { op.mem.rip_relative = true; op.mem.base = -1; }
    if ((rm & 7) == 4 && i < len) {
        uint8_t sib = data[i++];
        op.mem.base = (sib & 7) + rex_b;
        int idx = (sib >> 3) & 7;
        op.mem.index = (idx == 4 && !rex_x) ? -1 : idx + rex_x;
        op.mem.scale = 1 << (sib >> 6);
        if ((sib & 7) == 5 && mod == 0) op.mem.base = -1;
    }
    int disp = (mod == 1) ? 1 : (mod == 2 || op.mem.rip_relative || (op.mem.base < 0 && !op.mem.rip_relative)) ? 4 : 0;
    if (disp && i + static_cast<size_t>(disp) <= len) {
        int64_t d = 0;
        for (int k = 0; k < disp; ++k) d |= static_cast<int64_t>(data[i + k]) << (8 * k);
        if (disp == 1 && (d & 0x80)) d |= ~0xFFLL;
        if (disp == 4 && (d & 0x80000000LL)) d |= ~0xFFFFFFFFLL;
        op.mem.disp = d;
        i += disp;
    }
}

static X86Op mapAlu(uint8_t opc) {
    switch (opc & 0x38) {
        case 0x00: return X86Op::ADD;
        case 0x08: return X86Op::OR;
        case 0x10: return X86Op::ADC;
        case 0x18: return X86Op::SBB;
        case 0x20: return X86Op::AND;
        case 0x28: return X86Op::SUB;
        case 0x30: return X86Op::XOR;
        case 0x38: return X86Op::CMP;
        default: return X86Op::INVALID;
    }
}

// Parses the modrm r/m side (+SIB +disp) into `op`, advancing `i`.
static void parseRm(const uint8_t* data, size_t len, size_t& i, uint8_t modrm,
                    int rex_b, int rex_x, Operand& op) {
    int mod = modrmMod(modrm);
    int rm = modrmRm(modrm) + rex_b;
    if (mod == 3) {
        op.kind = OperandKind::REG;
        op.reg = rm;
        return;
    }
    op.kind = OperandKind::MEM;
    parseRmRest(data, len, i, modrm, rex_b, rex_x, op);
}

// Same, but the mod==3 register encoding names an XMM register (16+n) instead
// of a GPR: SSE/SSE2/SSE3/AES operands.
static void parseSseRm(const uint8_t* data, size_t len, size_t& i, uint8_t modrm,
                       int rex_b, int rex_x, Operand& op) {
    parseRm(data, len, i, modrm, rex_b, rex_x, op);
    if (op.kind == OperandKind::REG) op.reg = 16 + (op.reg & 0xF);
}

// Apply the legacy 8-bit register rule: without any REX prefix, encoding
// numbers 4-7 are AH/CH/DH/BH (the high byte of RAX/RCX/RDX/RBX), not the
// low-byte SPL/BPL/SIL/DIL registers that a REX prefix selects.
static void applyByteReg(Operand& op, bool rex) {
    if (op.kind != OperandKind::REG || rex) return;
    const int n = op.reg & 7;
    if (n >= 4) { op.reg -= 4; op.high8 = true; }
}

static void parseRm8(const uint8_t* data, size_t len, size_t& i, uint8_t modrm,
                     int rex_b, int rex_x, Operand& op, bool rex) {
    parseRm(data, len, i, modrm, rex_b, rex_x, op);
    applyByteReg(op, rex);
}

// ---------------------------------------------------------------------------
// x87 escape group (D8-DF).
//
// Every encoding maps onto X86Op::X87 plus a semantic X87Op, the operands it
// touches (ST(i) via OperandKind::ST, memory via OperandKind::MEM carrying the
// accessed width in .size) and the pop / reverse / integer modifiers in
// x87_flags. One opcode keeps the family in a single interpreter case while
// the mnemonic still names the exact instruction for traces and coverage.
// ---------------------------------------------------------------------------

static void x87St(Operand& o, int idx) {
    o.kind = OperandKind::ST;
    o.reg = idx & 7;
    o.size = 80;
}

static bool decodeX87(const uint8_t* d, size_t len, size_t& i, uint8_t esc, Insn& in,
                      int rex_b, int rex_x) {
    if (i >= len) return false;
    const uint8_t modrm = d[i++];
    const int mod = modrm >> 6;
    const int reg = (modrm >> 3) & 7;
    const int rm = modrm & 7;
    const bool mem = mod != 3;

    in.op = X86Op::X87;
    in.x87op = X87Op::INVALID;
    in.x87_flags = 0;

    Operand m;
    if (mem) {
        m.kind = OperandKind::MEM;
        parseRmRest(d, len, i, modrm, rex_b, rex_x, m);
    }
    // x87 memory forms are all "ST(0) <op> m"; the register forms name an
    // explicit ST(i) on one side.
    auto invalid = [&]() {
        in.op = X86Op::INVALID;
        in.mnemonic = "invalid x87";
        return true;
    };

    switch (esc) {
        // D8: ST(0) arithmetic on m32fp or ST(i).
        case 0xD8: {
            static const X87Op kOp[8] = {X87Op::ADD, X87Op::MUL, X87Op::COM, X87Op::COM,
                                         X87Op::SUB, X87Op::SUB, X87Op::DIV, X87Op::DIV};
            static const char* kName[8] = {"fadd", "fmul", "fcom", "fcomp",
                                           "fsub", "fsubr", "fdiv", "fdivr"};
            x87St(in.dst, 0);
            if (mem) { m.size = 32; in.src = m; }
            else x87St(in.src, rm);
            in.x87op = kOp[reg];
            in.mnemonic = kName[reg];
            if (reg == 3) in.x87_flags |= X87F_POP;                       // FCOMP
            if (reg == 5 || reg == 7) in.x87_flags |= X87F_REV;          // FSUBR/FDIVR
            return true;
        }

        // D9: loads/stores and the control-word + transcendental block.
        case 0xD9: {
            if (mem) {
                in.src = m;
                switch (reg) {
                    case 0: m.size = 32; in.src = m; in.x87op = X87Op::LOAD;  in.mnemonic = "fld"; return true;
                    case 2: m.size = 32; in.dst = m; in.x87op = X87Op::STORE; in.mnemonic = "fst"; return true;
                    case 3: m.size = 32; in.dst = m; in.x87op = X87Op::STORE; in.x87_flags |= X87F_POP; in.mnemonic = "fstp"; return true;
                    case 4: m.size = 28 * 8; in.src = m; in.x87op = X87Op::LDENV;  in.mnemonic = "fldenv"; return true;
                    case 5: m.size = 16; in.src = m; in.x87op = X87Op::FLDCW;  in.mnemonic = "fldcw"; return true;
                    case 6: m.size = 28 * 8; in.dst = m; in.x87op = X87Op::STENV;  in.mnemonic = "fnstenv"; return true;
                    case 7: m.size = 16; in.dst = m; in.x87op = X87Op::STCW;   in.mnemonic = "fnstcw"; return true;
                    default: return invalid();
                }
            }
            switch (modrm) {
                case 0xD0: in.x87op = X87Op::NOP; in.mnemonic = "fnop"; return true;
                case 0xE0: in.x87op = X87Op::CHS; in.mnemonic = "fchs"; return true;
                case 0xE1: in.x87op = X87Op::ABS; in.mnemonic = "fabs"; return true;
                case 0xE4: in.x87op = X87Op::TEST; in.mnemonic = "ftst"; return true;
                case 0xE5: in.x87op = X87Op::EXAM; in.mnemonic = "fxam"; return true;
                case 0xF0: in.x87op = X87Op::F2XM1;   in.mnemonic = "f2xm1"; break;
                case 0xF1: in.x87op = X87Op::FYL2X;   in.mnemonic = "fyl2x"; break;
                case 0xF2: in.x87op = X87Op::FPTAN;   in.mnemonic = "fptan"; break;
                case 0xF3: in.x87op = X87Op::FPATAN;  in.mnemonic = "fpatan"; break;
                case 0xF4: in.x87op = X87Op::XTRACT;  in.mnemonic = "fxtract"; break;
                case 0xF5: in.x87op = X87Op::PREM1;   in.mnemonic = "fprem1"; break;
                case 0xF6: in.x87op = X87Op::DECSTP;  in.mnemonic = "fdecstp"; break;
                case 0xF7: in.x87op = X87Op::INCSTP;  in.mnemonic = "fincstp"; break;
                case 0xF8: in.x87op = X87Op::PREM;    in.mnemonic = "fprem"; break;
                case 0xF9: in.x87op = X87Op::FYL2XP1; in.mnemonic = "fyl2xp1"; break;
                case 0xFA: in.x87op = X87Op::SQRT;    in.mnemonic = "fsqrt"; break;
                case 0xFB: in.x87op = X87Op::SINCOS;  in.mnemonic = "fsincos"; break;
                case 0xFC: in.x87op = X87Op::RNDINT;  in.mnemonic = "frndint"; break;
                case 0xFD: in.x87op = X87Op::SCALE;   in.mnemonic = "fscale"; break;
                case 0xFE: in.x87op = X87Op::SIN;     in.mnemonic = "fsin"; break;
                case 0xFF: in.x87op = X87Op::COS;     in.mnemonic = "fcos"; break;
                default: break;
            }
            if (in.x87op != X87Op::INVALID) return true;
            // 0xC0-0xC7 FLD ST(i), 0xC8-0xCF FXCH, 0xD8-0xDF FSTP, 0xE8-0xEE
            // constants.
            if (modrm >= 0xC0 && modrm <= 0xC7) {
                x87St(in.src, rm);
                in.x87op = X87Op::LOAD;
                in.mnemonic = "fld";
                return true;
            }
            if (modrm >= 0xC8 && modrm <= 0xCF) {
                x87St(in.src, rm);
                in.x87op = X87Op::XCH;
                in.mnemonic = "fxch";
                return true;
            }
            if (modrm >= 0xD8 && modrm <= 0xDF) {
                x87St(in.dst, rm);
                in.x87op = X87Op::STORE;
                in.x87_flags |= X87F_POP;
                in.mnemonic = "fstp";
                return true;
            }
            if (modrm >= 0xE8 && modrm <= 0xEE) {
                in.x87op = X87Op::CONST;
                in.src.kind = OperandKind::IMM;
                in.src.imm = modrm - 0xE8;   // 0=1.0 1=l2t 2=l2e 3=pi 4=lg2 5=ln2 6=0.0
                in.src.size = 8;
                static const char* kConst[7] = {"fld1", "fldl2t", "fldl2e", "fldpi",
                                                "fldlg2", "fldln2", "fldz"};
                in.mnemonic = kConst[modrm - 0xE8];
                return true;
            }
            return invalid();
        }

        // DA: m32int arithmetic; FCMOVcc / FUCOMPP in the register space.
        case 0xDA: {
            if (mem) {
                static const X87Op kOp[8] = {X87Op::ADD, X87Op::MUL, X87Op::COM, X87Op::COM,
                                             X87Op::SUB, X87Op::SUB, X87Op::DIV, X87Op::DIV};
                static const char* kName[8] = {"fiadd", "fimul", "ficom", "ficomp",
                                               "fisub", "fisubr", "fidiv", "fidivr"};
                x87St(in.dst, 0);
                m.size = 32;
                in.src = m;
                in.x87_flags |= X87F_INT;
                in.x87op = kOp[reg];
                in.mnemonic = kName[reg];
                if (reg == 3) in.x87_flags |= X87F_POP;
                if (reg == 5 || reg == 7) in.x87_flags |= X87F_REV;
                return true;
            }
            if (modrm == 0xE9) { in.x87op = X87Op::COM; in.x87_flags |= X87F_POP | X87F_POP2; in.mnemonic = "fucompp"; return true; }
            if (modrm >= 0xC0 && modrm <= 0xDF) {
                x87St(in.src, rm);
                in.x87op = X87Op::CMOV;
                in.cc = static_cast<uint8_t>((modrm - 0xC0) >> 3); // 0=B 1=E 2=BE 3=U
                in.mnemonic = "fcmovb";
                if (in.cc == 1) in.mnemonic = "fcmove";
                else if (in.cc == 2) in.mnemonic = "fcmovbe";
                else if (in.cc == 3) in.mnemonic = "fcmovu";
                return true;
            }
            return invalid();
        }

        // DB: integer loads/stores (m32/m80), FCMOVNcc, FNclex/FNinit, FCOMI.
        case 0xDB: {
            if (mem) {
                in.dst = m;
                in.src = m;
                switch (reg) {
                    case 0: m.size = 32; in.src = m; in.x87_flags |= X87F_INT; in.x87op = X87Op::LOAD; in.mnemonic = "fild"; return true;
                    case 1: m.size = 32; in.dst = m; in.x87_flags |= X87F_INT | X87F_TRUNC; in.x87_flags |= X87F_POP; in.x87op = X87Op::STORE; in.mnemonic = "fisttp"; return true;
                    case 2: m.size = 32; in.dst = m; in.x87_flags |= X87F_INT; in.x87op = X87Op::STORE; in.mnemonic = "fist"; return true;
                    case 3: m.size = 32; in.dst = m; in.x87_flags |= X87F_INT | X87F_POP; in.x87op = X87Op::STORE; in.mnemonic = "fistp"; return true;
                    case 5: m.size = 80; in.src = m; in.x87op = X87Op::LOAD; in.mnemonic = "fld"; return true;
                    case 7: m.size = 80; in.dst = m; in.x87_flags |= X87F_POP; in.x87op = X87Op::STORE; in.mnemonic = "fstp"; return true;
                    default: return invalid();
                }
            }
            if (modrm >= 0xC0 && modrm <= 0xDF) {
                x87St(in.src, rm);
                in.x87op = X87Op::CMOV;
                in.cc = static_cast<uint8_t>(4 + ((modrm - 0xC0) >> 3)); // 4=NB .. 7=NU
                in.mnemonic = "fcmovnb";
                if (in.cc == 5) in.mnemonic = "fcmovne";
                else if (in.cc == 6) in.mnemonic = "fcmovnbe";
                else if (in.cc == 7) in.mnemonic = "fcmovnu";
                return true;
            }
            if (modrm == 0xE2) { in.x87op = X87Op::CLR_EXCEPTIONS; in.mnemonic = "fnclex"; return true; }
            if (modrm == 0xE3) { in.x87op = X87Op::INIT; in.mnemonic = "fninit"; return true; }
            if (modrm >= 0xE8 && modrm <= 0xEF) {
                x87St(in.src, rm);
                in.x87op = X87Op::UCOMI;
                in.mnemonic = "fucomi";
                return true;
            }
            if (modrm >= 0xF0 && modrm <= 0xF7) {
                x87St(in.src, rm);
                in.x87op = X87Op::COMI;
                in.mnemonic = "fcomi";
                return true;
            }
            return invalid();
        }

        // DC: m64fp arithmetic; register forms write ST(i) instead of ST(0).
        case 0xDC: {
            if (mem) {
                static const X87Op kOp[8] = {X87Op::ADD, X87Op::MUL, X87Op::COM, X87Op::COM,
                                             X87Op::SUB, X87Op::SUB, X87Op::DIV, X87Op::DIV};
                static const char* kName[8] = {"fadd", "fmul", "fcom", "fcomp",
                                               "fsub", "fsubr", "fdiv", "fdivr"};
                x87St(in.dst, 0);
                m.size = 64;
                in.src = m;
                in.x87op = kOp[reg];
                in.mnemonic = kName[reg];
                if (reg == 3) in.x87_flags |= X87F_POP;
                if (reg == 5 || reg == 7) in.x87_flags |= X87F_REV;
                return true;
            }
            x87St(in.dst, rm);
            x87St(in.src, 0);
            switch (reg) {
                case 0: in.x87op = X87Op::ADD; in.mnemonic = "fadd"; break;
                case 1: in.x87op = X87Op::MUL; in.mnemonic = "fmul"; break;
                case 2: in.x87op = X87Op::COM; in.mnemonic = "fcom"; break;
                case 3: in.x87op = X87Op::COM; in.x87_flags |= X87F_POP; in.mnemonic = "fcomp"; break;
                case 4: in.x87op = X87Op::SUB; in.x87_flags |= X87F_REV; in.mnemonic = "fsubr"; break;
                case 5: in.x87op = X87Op::SUB; in.mnemonic = "fsub"; break;
                case 6: in.x87op = X87Op::DIV; in.x87_flags |= X87F_REV; in.mnemonic = "fdivr"; break;
                default: in.x87op = X87Op::DIV; in.mnemonic = "fdiv"; break;
            }
            return true;
        }

        // DD: m64fp loads/stores, FRSTOR/FNSAVE, FNSTSW; FFREE/FST/FSTP/FUCOM.
        case 0xDD: {
            if (mem) {
                switch (reg) {
                    case 0: m.size = 64; in.src = m; in.x87op = X87Op::LOAD; in.mnemonic = "fld"; return true;
                    case 1: m.size = 64; in.dst = m; in.x87_flags |= X87F_INT | X87F_TRUNC | X87F_POP; in.x87op = X87Op::STORE; in.mnemonic = "fisttp"; return true;
                    case 2: m.size = 64; in.dst = m; in.x87op = X87Op::STORE; in.mnemonic = "fst"; return true;
                    case 3: m.size = 64; in.dst = m; in.x87_flags |= X87F_POP; in.x87op = X87Op::STORE; in.mnemonic = "fstp"; return true;
                    case 4: m.size = 108 * 8; in.src = m; in.x87op = X87Op::RESTORE; in.mnemonic = "frstor"; return true;
                    case 6: m.size = 108 * 8; in.dst = m; in.x87op = X87Op::SAVE; in.mnemonic = "fnsave"; return true;
                    case 7: m.size = 16; in.dst = m; in.x87op = X87Op::STSW; in.mnemonic = "fnstsw"; return true;
                    default: return invalid();
                }
            }
            if (reg == 0) { x87St(in.src, rm); in.x87op = X87Op::FREE; in.mnemonic = "ffree"; return true; }
            if (reg == 2) { x87St(in.dst, rm); in.x87op = X87Op::STORE; in.mnemonic = "fst"; return true; }
            if (reg == 3) { x87St(in.dst, rm); in.x87op = X87Op::STORE; in.x87_flags |= X87F_POP; in.mnemonic = "fstp"; return true; }
            if (reg == 4) { x87St(in.src, rm); in.x87op = X87Op::UCOM; in.mnemonic = "fucom"; return true; }
            if (reg == 5) { x87St(in.src, rm); in.x87op = X87Op::UCOM; in.x87_flags |= X87F_POP; in.mnemonic = "fucomp"; return true; }
            return invalid();
        }

        // DE: m16int arithmetic; the popping register forms (FADDP .. FDIVP),
        // FCOMPP.
        case 0xDE: {
            if (mem) {
                static const X87Op kOp[8] = {X87Op::ADD, X87Op::MUL, X87Op::COM, X87Op::COM,
                                             X87Op::SUB, X87Op::SUB, X87Op::DIV, X87Op::DIV};
                static const char* kName[8] = {"fiadd", "fimul", "ficom", "ficomp",
                                               "fisub", "fisubr", "fidiv", "fidivr"};
                x87St(in.dst, 0);
                m.size = 16;
                in.src = m;
                in.x87_flags |= X87F_INT;
                in.x87op = kOp[reg];
                in.mnemonic = kName[reg];
                if (reg == 3) in.x87_flags |= X87F_POP;
                if (reg == 5 || reg == 7) in.x87_flags |= X87F_REV;
                return true;
            }
            if (modrm == 0xD9) { in.x87op = X87Op::COM; in.x87_flags |= X87F_POP | X87F_POP2; in.mnemonic = "fcompp"; return true; }
            x87St(in.dst, rm);
            x87St(in.src, 0);
            in.x87_flags |= X87F_POP;
            switch (reg) {
                case 0: in.x87op = X87Op::ADD; in.mnemonic = "faddp"; break;
                case 1: in.x87op = X87Op::MUL; in.mnemonic = "fmulp"; break;
                case 4: in.x87op = X87Op::SUB; in.x87_flags |= X87F_REV; in.mnemonic = "fsubrp"; break;
                case 5: in.x87op = X87Op::SUB; in.mnemonic = "fsubp"; break;
                case 6: in.x87op = X87Op::DIV; in.x87_flags |= X87F_REV; in.mnemonic = "fdivrp"; break;
                case 7: in.x87op = X87Op::DIV; in.mnemonic = "fdivp"; break;
                default: return invalid();
            }
            return true;
        }

        // DF: 16/64-bit integer loads/stores, FBLD/FBSTP, FNSTSW AX, FFREEP,
        // FCOMI/FUCOMI with pop.
        default: {
            if (mem) {
                switch (reg) {
                    case 0: m.size = 16; in.src = m; in.x87_flags |= X87F_INT; in.x87op = X87Op::LOAD; in.mnemonic = "fild"; return true;
                    case 1: m.size = 16; in.dst = m; in.x87_flags |= X87F_INT | X87F_TRUNC | X87F_POP; in.x87op = X87Op::STORE; in.mnemonic = "fisttp"; return true;
                    case 2: m.size = 16; in.dst = m; in.x87_flags |= X87F_INT; in.x87op = X87Op::STORE; in.mnemonic = "fist"; return true;
                    case 3: m.size = 16; in.dst = m; in.x87_flags |= X87F_INT | X87F_POP; in.x87op = X87Op::STORE; in.mnemonic = "fistp"; return true;
                    case 4: m.size = 80; in.src = m; in.x87op = X87Op::BCD_LOAD; in.mnemonic = "fbld"; return true;
                    case 5: m.size = 64; in.src = m; in.x87_flags |= X87F_INT; in.x87op = X87Op::LOAD; in.mnemonic = "fild"; return true;
                    case 6: m.size = 80; in.dst = m; in.x87_flags |= X87F_POP; in.x87op = X87Op::BCD_STORE; in.mnemonic = "fbstp"; return true;
                    default: m.size = 64; in.dst = m; in.x87_flags |= X87F_INT | X87F_POP; in.x87op = X87Op::STORE; in.mnemonic = "fistp"; return true;
                }
            }
            if (reg == 0) { x87St(in.src, rm); in.x87op = X87Op::FREE; in.x87_flags |= X87F_POP; in.mnemonic = "ffreep"; return true; }
            if (modrm == 0xE0) {
                in.x87op = X87Op::STSW;
                in.x87_flags |= X87F_AX;
                in.mnemonic = "fnstsw";
                return true;
            }
            if (reg == 5) { x87St(in.src, rm); in.x87op = X87Op::UCOMI; in.x87_flags |= X87F_POP; in.mnemonic = "fucomip"; return true; }
            if (reg == 6) { x87St(in.src, rm); in.x87op = X87Op::COMI; in.x87_flags |= X87F_POP; in.mnemonic = "fcomip"; return true; }
            return invalid();
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Packed-integer / SSE4.2 decode table (§2.18).
//
// These families share one operand shape — ModRM.reg is an XMM destination,
// the r/m is a 128-bit source, and some forms take an imm8 — so the opcode,
// element width and a couple of flags describe the whole instruction. That
// keeps ~90 encodings out of the hand-written if-chain below.
// ---------------------------------------------------------------------------

namespace {

enum : uint8_t {
    PF_IMM8     = 1,   // trailing imm8 in src2
    PF_DST_GPR  = 2,   // destination is the r/m (GPR or memory), source is XMM
    PF_SRC_GPR  = 4,   // source is the r/m (GPR or memory), destination is XMM
    PF_GPR_REG  = 8,   // destination is the reg-field GPR, source is the r/m XMM
};

struct PackedEntry {
    X86Op op = X86Op::INVALID;
    uint8_t ew = 128;     // element width in bits (128 = whole register)
    uint8_t dstw = 0;     // width for a GPR/mem destination (0 = ew)
    uint8_t flags = 0;
    uint8_t cc = 0;
    const char* mn = "";
};

PackedEntry pe(X86Op op, uint8_t ew, const char* mn, uint8_t flags = 0,
               uint8_t dstw = 0, uint8_t cc = 0) {
    PackedEntry e;
    e.op = op; e.ew = ew; e.mn = mn; e.flags = flags; e.dstw = dstw; e.cc = cc;
    return e;
}

// map: 1 = 0F, 2 = 0F38, 3 = 0F3A. pp: 0 none, 1 = 66, 2 = F3, 3 = F2.
bool packedLookup(int map, uint8_t op, int pp, bool rexw, PackedEntry& out) {
    if (map == 1) {
        if (pp != 1) {
            // PSHUFW (no prefix) and PSHUFHW/PSHUFLW (F3/F2) are the only
            // non-66 forms in this family.
            if (op == 0x70) {
                out = pp == 0 ? pe(X86Op::PSHUF, 16, "pshufw", PF_IMM8, 0, 3)
                    : pp == 2 ? pe(X86Op::PSHUF, 16, "pshufhw", PF_IMM8, 0, 1)
                              : pe(X86Op::PSHUF, 16, "pshuflw", PF_IMM8, 0, 2);
                return true;
            }
            return false;
        }
        switch (op) {
            case 0x60: out = pe(X86Op::PUNPCK, 8,  "punpcklbw", 0, 0, 0); return true;
            case 0x61: out = pe(X86Op::PUNPCK, 16, "punpcklwd", 0, 0, 0); return true;
            case 0x62: out = pe(X86Op::PUNPCK, 32, "punpckldq", 0, 0, 0); return true;
            case 0x68: out = pe(X86Op::PUNPCK, 8,  "punpckhbw", 0, 0, 1); return true;
            case 0x69: out = pe(X86Op::PUNPCK, 16, "punpckhwd", 0, 0, 1); return true;
            case 0x6A: out = pe(X86Op::PUNPCK, 32, "punpckhdq", 0, 0, 1); return true;
            case 0x6C: out = pe(X86Op::PUNPCK, 64, "punpcklqdq", 0, 0, 0); return true;
            case 0x6D: out = pe(X86Op::PUNPCK, 64, "punpckhqdq", 0, 0, 1); return true;
            case 0x64: out = pe(X86Op::PCMPGT, 8,  "pcmpgtb"); return true;
            case 0x65: out = pe(X86Op::PCMPGT, 16, "pcmpgtw"); return true;
            case 0x66: out = pe(X86Op::PCMPGT, 32, "pcmpgtd"); return true;
            case 0x70: out = pe(X86Op::PSHUF, 16, "pshufd", PF_IMM8, 0, 0); return true;
            case 0xD1: out = pe(X86Op::PSHIFT, 16, "psrlw", 0, 0, 1); return true;
            case 0xD2: out = pe(X86Op::PSHIFT, 32, "psrld", 0, 0, 1); return true;
            case 0xD3: out = pe(X86Op::PSHIFT, 64, "psrlq", 0, 0, 1); return true;
            case 0xE1: out = pe(X86Op::PSHIFT, 16, "psraw", 0, 0, 2); return true;
            case 0xE2: out = pe(X86Op::PSHIFT, 32, "psrad", 0, 0, 2); return true;
            case 0xF1: out = pe(X86Op::PSHIFT, 16, "psllw", 0, 0, 0); return true;
            case 0xF2: out = pe(X86Op::PSHIFT, 32, "pslld", 0, 0, 0); return true;
            case 0xF3: out = pe(X86Op::PSHIFT, 64, "psllq", 0, 0, 0); return true;
            case 0xD4: out = pe(X86Op::PADD, 64, "paddq"); return true;
            case 0xD5: out = pe(X86Op::PMUL, 16, "pmullw", 0, 0, 0); return true;
            case 0xE4: out = pe(X86Op::PMUL, 16, "pmulhuw", 0, 0, 2); return true;
            case 0xE5: out = pe(X86Op::PMUL, 16, "pmulhw", 0, 0, 1); return true;
            case 0xE8: out = pe(X86Op::PSUBS, 8, "psubsb"); return true;
            case 0xE9: out = pe(X86Op::PSUBS, 16, "psubsw"); return true;
            case 0xEA: out = pe(X86Op::PMINMAX, 16, "pminsw", 0, 0, 0); return true;
            case 0xEE: out = pe(X86Op::PMINMAX, 16, "pmaxsw", 0, 0, 1); return true;
            case 0xDA: out = pe(X86Op::PMINMAX, 8, "pminub", 0, 0, 2); return true;
            case 0xDE: out = pe(X86Op::PMINMAX, 8, "pmaxub", 0, 0, 3); return true;
            case 0xF4: out = pe(X86Op::PMUL, 32, "pmuludq", 0, 0, 5); return true;
            case 0xF5: out = pe(X86Op::PMUL, 16, "pmaddwd", 0, 0, 8); return true;
            case 0xF6: out = pe(X86Op::PSADBW, 8, "psadbw"); return true;
            case 0xF8: out = pe(X86Op::PSUB, 8, "psubb"); return true;
            case 0xF9: out = pe(X86Op::PSUB, 16, "psubw"); return true;
            case 0xFA: out = pe(X86Op::PSUB, 32, "psubd"); return true;
            case 0xFB: out = pe(X86Op::PSUB, 64, "psubq"); return true;
            case 0xD8: out = pe(X86Op::PSUBUS, 8, "psubusb"); return true;
            case 0xD9: out = pe(X86Op::PSUBUS, 16, "psubusw"); return true;
            case 0xEC: out = pe(X86Op::PADDS, 8, "paddsb"); return true;
            case 0xED: out = pe(X86Op::PADDS, 16, "paddsw"); return true;
            case 0xDC: out = pe(X86Op::PADDUS, 8, "paddusb"); return true;
            case 0xDD: out = pe(X86Op::PADDUS, 16, "paddusw"); return true;
            case 0xD7: out = pe(X86Op::PMOVMSKB, 128, "pmovmskb", PF_GPR_REG, 32); return true;
            case 0xC4: out = pe(X86Op::PINS, 16, "pinsrw", PF_IMM8 | PF_SRC_GPR, 16); return true;
            case 0xC5: out = pe(X86Op::PEXTR, 16, "pextrw", PF_IMM8 | PF_DST_GPR, 16); return true;
            case 0xEB: out = pe(X86Op::POR, 128, "por"); return true;
            default: return false;
        }
    }
    if (map == 2) {
        if (pp != 1) return false;
        switch (op) {
            case 0x00: out = pe(X86Op::PSHUFB, 8, "pshufb"); return true;
            case 0x01: out = pe(X86Op::PHADDSUB, 16, "phaddw", 0, 0, 0); return true;
            case 0x02: out = pe(X86Op::PHADDSUB, 32, "phaddd", 0, 0, 1); return true;
            case 0x03: out = pe(X86Op::PHADDSUB, 16, "phaddsw", 0, 0, 2); return true;
            case 0x04: out = pe(X86Op::PMUL, 8, "pmaddubsw", 0, 0, 9); return true;
            case 0x05: out = pe(X86Op::PHADDSUB, 16, "phsubw", 0, 0, 3); return true;
            case 0x06: out = pe(X86Op::PHADDSUB, 32, "phsubd", 0, 0, 4); return true;
            case 0x07: out = pe(X86Op::PHADDSUB, 16, "phsubsw", 0, 0, 5); return true;
            case 0x08: out = pe(X86Op::PSIGN, 8, "psignb"); return true;
            case 0x09: out = pe(X86Op::PSIGN, 16, "psignw"); return true;
            case 0x0A: out = pe(X86Op::PSIGN, 32, "psignd"); return true;
            case 0x0B: out = pe(X86Op::PMUL, 16, "pmulhrsw", 0, 0, 7); return true;
            case 0x17: out = pe(X86Op::PTEST, 128, "ptest"); return true;
            case 0x20: out = pe(X86Op::PMOVX, 8,  "pmovsxbw", 0, 16, 0); return true;
            case 0x21: out = pe(X86Op::PMOVX, 8,  "pmovsxbd", 0, 32, 0); return true;
            case 0x22: out = pe(X86Op::PMOVX, 8,  "pmovsxbq", 0, 64, 0); return true;
            case 0x23: out = pe(X86Op::PMOVX, 16, "pmovsxwd", 0, 32, 0); return true;
            case 0x24: out = pe(X86Op::PMOVX, 16, "pmovsxwq", 0, 64, 0); return true;
            case 0x25: out = pe(X86Op::PMOVX, 32, "pmovsxdq", 0, 64, 0); return true;
            case 0x28: out = pe(X86Op::PMUL, 32, "pmuldq", 0, 0, 6); return true;
            case 0x29: out = pe(X86Op::PCMPEQ, 64, "pcmpeqq"); return true;
            case 0x30: out = pe(X86Op::PMOVX, 8,  "pmovzxbw", 0, 16, 1); return true;
            case 0x31: out = pe(X86Op::PMOVX, 8,  "pmovzxbd", 0, 32, 1); return true;
            case 0x32: out = pe(X86Op::PMOVX, 8,  "pmovzxbq", 0, 64, 1); return true;
            case 0x33: out = pe(X86Op::PMOVX, 16, "pmovzxwd", 0, 32, 1); return true;
            case 0x34: out = pe(X86Op::PMOVX, 16, "pmovzxwq", 0, 64, 1); return true;
            case 0x35: out = pe(X86Op::PMOVX, 32, "pmovzxdq", 0, 64, 1); return true;
            case 0x37: out = pe(X86Op::PCMPGT, 64, "pcmpgtq"); return true;
            case 0x38: out = pe(X86Op::PMINMAX, 8,  "pminsb", 0, 0, 0); return true;
            case 0x39: out = rexw ? pe(X86Op::PMINMAX, 64, "pminsq", 0, 0, 0)
                                  : pe(X86Op::PMINMAX, 32, "pminsd", 0, 0, 0); return true;
            case 0x3A: out = pe(X86Op::PMINMAX, 16, "pminuw", 0, 0, 2); return true;
            case 0x3B: out = rexw ? pe(X86Op::PMINMAX, 64, "pminuq", 0, 0, 2)
                                  : pe(X86Op::PMINMAX, 32, "pminud", 0, 0, 2); return true;
            case 0x3C: out = pe(X86Op::PMINMAX, 8,  "pmaxsb", 0, 0, 1); return true;
            case 0x3D: out = rexw ? pe(X86Op::PMINMAX, 64, "pmaxsq", 0, 0, 1)
                                  : pe(X86Op::PMINMAX, 32, "pmaxsd", 0, 0, 1); return true;
            case 0x3E: out = pe(X86Op::PMINMAX, 16, "pmaxuw", 0, 0, 3); return true;
            case 0x3F: out = rexw ? pe(X86Op::PMINMAX, 64, "pmaxuq", 0, 0, 3)
                                  : pe(X86Op::PMINMAX, 32, "pmaxud", 0, 0, 3); return true;
            case 0x40: out = rexw ? pe(X86Op::PMUL, 64, "pmullq", 0, 0, 4)
                                  : pe(X86Op::PMUL, 32, "pmulld", 0, 0, 3); return true;
            case 0x41: out = pe(X86Op::PHMINPOSUW, 16, "phminposuw"); return true;
            default: return false;
        }
    }
    if (map == 3) {
        if (pp != 1) return false;
        switch (op) {
            case 0x14: out = pe(X86Op::PEXTR, 8,  "pextrb", PF_IMM8 | PF_DST_GPR, 8); return true;
            case 0x15: out = pe(X86Op::PEXTR, 16, "pextrw", PF_IMM8 | PF_DST_GPR, 16); return true;
            case 0x16: out = rexw ? pe(X86Op::PEXTR, 64, "pextrq", PF_IMM8 | PF_DST_GPR, 64)
                                  : pe(X86Op::PEXTR, 32, "pextrd", PF_IMM8 | PF_DST_GPR, 32); return true;
            case 0x20: out = pe(X86Op::PINS, 8,  "pinsrb", PF_IMM8 | PF_SRC_GPR, 8); return true;
            case 0x22: out = rexw ? pe(X86Op::PINS, 64, "pinsrq", PF_IMM8 | PF_SRC_GPR, 64)
                                  : pe(X86Op::PINS, 32, "pinsrd", PF_IMM8 | PF_SRC_GPR, 32); return true;
            case 0x60: out = pe(X86Op::PCMPSTR, 8, "pcmpestrm", PF_IMM8, 0, 3); return true;
            case 0x61: out = pe(X86Op::PCMPSTR, 8, "pcmpestri", PF_IMM8, 0, 2); return true;
            case 0x62: out = pe(X86Op::PCMPSTR, 8, "pcmpistrm", PF_IMM8, 0, 1); return true;
            case 0x63: out = pe(X86Op::PCMPSTR, 8, "pcmpistri", PF_IMM8, 0, 0); return true;
            default: return false;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// VEX / EVEX vector operands
// ---------------------------------------------------------------------------

// EVEX disp8 is scaled by the tuple size, so one byte covers the common case
// of an access that walks a whole register or element at a time.
static int vecTupleScale(uint8_t tuple, int widthBytes, int elemBits) {
    const int eb = elemBits ? elemBits / 8 : 1;
    switch (tuple) {
        case VT_FV: case VT_FVM: return widthBytes;
        case VT_HV: case VT_HVM: return widthBytes / 2;
        case VT_QV: return widthBytes / 4;
        case VT_EV: return widthBytes / 8;
        case VT_T1S: return eb;
        case VT_T1F: return 16;
        case VT_T2: return 32;
        case VT_T4: return 64;
        case VT_T8: return 128;
        case VT_M128: return 16;
        case VT_T2S: return eb * 2;
        case VT_T4S: return eb * 4;
        case VT_T8S: return eb * 8;
        default: return 1;
    }
}

// Decodes the ModRM byte and its operands for a vector instruction. Returns
// false when no table row matches (the caller then treats the encoding as an
// unsupported VEX/EVEX placeholder, still consuming it exactly).
static bool decodeVectorOp(const uint8_t* data, size_t len, size_t& i, Insn& in,
                           int rex_r, int rex_r2, int rex_x, int rex_b,
                           bool evex, int opcIn = -1) {
    if (i >= len && opcIn < 0) return false;
    const uint8_t opc = opcIn >= 0 ? static_cast<uint8_t>(opcIn) : data[i];
    const uint8_t map = in.vex_map;
    const uint8_t pp = in.vex_pp_bits;
    const bool w = in.vex_w;

    int widthBytes = 0;
    if (evex) {
        if (in.evex_ll == 3) return false;
        widthBytes = 16 << in.evex_ll;
    } else {
        widthBytes = in.vex_l ? 32 : 16;
    }

    const VecEnt* hit = nullptr;
    for (const auto& e : kVecTable) {
        if (e.map != map || e.opc != opc || e.pp != pp) continue;
        if (e.w != 2 && e.w != (w ? 1 : 0)) continue;
        if (evex && (e.flags & VF_VEX)) continue;
        if (!evex && (e.flags & VF_EVEX)) continue;
        if ((e.flags & VF_512) && widthBytes != 64) continue;
        hit = &e;
        break;
    }
    // The 0F 71-73 shift block selects the operation with ModRM.reg.
    const VecGrpEnt* grp = nullptr;
    if (!hit && map == 1 && pp == 1 && i + 1 < len &&
        (opc == 0x71 || opc == 0x72 || opc == 0x73)) {
        const int digit = (data[i] >> 3) & 7;
        for (const auto& g : kVecGroupTable) {
            if (g.opc == opc && g.digit == digit) { grp = &g; break; }
        }
    }
    if (!hit && !grp) return false;

    int width = widthBytes;
    if (hit && (hit->flags & VF_128)) width = 16;
    int dstBytes = width, srcBytes = width;
    const int ratio = hit ? hit->ratio : 1;
    if (ratio == 2) srcBytes = width / 2;
    else if (ratio == 5) dstBytes = width / 2;

    in.op = X86Op::VEC;
    in.vec_bits = static_cast<uint16_t>(width * 8);
    in.vec_op = static_cast<uint16_t>(hit ? hit->op : grp->op);
    in.elem_bits = hit ? hit->elem : grp->elem;
    in.vec_class = hit ? hit->cls : VC_INT;
    in.mnemonic = hit ? hit->name : grp->name;
    if (grp) in.cc = 1;  // marks a grouped shift for the interpreter

    if (opcIn < 0) ++i;  // consume the opcode when the caller has not
    if (hit && hit->shape == VS_1R) return true;
    if (i >= len) return false;
    const uint8_t modrm = data[i++];
    const int mod = modrmMod(modrm);
    const int regField = modrmReg(modrm) + rex_r + rex_r2;
    const int rmField = modrmRm(modrm) + rex_b + (evex ? rex_x : 0);

    auto vecReg = [](int r, int bits) {
        Operand o; o.kind = OperandKind::REG; o.reg = 16 + r; o.size = bits; return o;
    };
    auto kReg = [](int r, int bits) {
        Operand o; o.kind = OperandKind::K; o.reg = r & 7; o.size = bits; return o;
    };
    auto gprOp = [&](int r, int bits) {
        Operand o;
        if (mod == 3) { o.kind = OperandKind::REG; o.reg = r; }
        else o.kind = OperandKind::MEM;
        o.size = bits;
        return o;
    };

    const int dstBits = dstBytes * 8;
    const int srcBits = srcBytes * 8;
    // Broadcast forms read a single element from memory.
    int memBits = in.evex_b && in.elem_bits ? in.elem_bits : srcBits;
    const int dispN = evex
        ? vecTupleScale(hit ? hit->tuple : VT_FV, widthBytes,
                        in.evex_b ? in.elem_bits : (hit ? hit->elem : 0))
        : 1;

    auto rmVec = [&](int accessBits) {
        Operand o;
        o.size = accessBits;
        if (mod == 3) {
            o.kind = OperandKind::REG;
            o.reg = 16 + rmField;
        } else {
            parseRmRest(data, len, i, modrm, rex_b, rex_x, o);
            if (evex && mod == 1 && dispN > 1) o.mem.disp *= dispN;
            o.size = accessBits;
        }
        return o;
    };
    auto rmGpr = [&](int bits) {
        Operand o;
        o.size = bits;
        if (mod == 3) { o.kind = OperandKind::REG; o.reg = rmField; }
        else {
            parseRmRest(data, len, i, modrm, rex_b, rex_x, o);
            if (evex && mod == 1 && dispN > 1) o.mem.disp *= dispN;
            o.size = bits;
        }
        return o;
    };
    auto imm8 = [&]() {
        Operand o; o.kind = OperandKind::IMM; o.size = 8;
        if (i < len) o.imm = data[i++];
        return o;
    };

    // The 0F 71-73 block puts the operation in ModRM.reg. In the VEX/EVEX
    // form the destination moves to vvvv (the non-destructive AVX shape),
    // while the source stays in r/m.
    if (grp) {
        in.src2 = rmVec(width * 8);
        in.src = in.src2;
        in.dst = vecReg(in.vex_v, width * 8);
        in.src3 = imm8();
        return true;
    }

    const uint8_t shape = hit ? hit->shape : VS_2RI;
    switch (shape) {
        case VS_3R: case VS_3RI: case VS_3RG: {
            in.dst = vecReg(regField, dstBits);
            in.src = vecReg(in.vex_v, srcBits);
            in.src2 = (shape == VS_3RG) ? rmGpr(in.elem_bits ? in.elem_bits : in.vec_bits)
                                        : rmVec(memBits);
            if (shape == VS_3RI) in.src3 = imm8();
            break;
        }
        case VS_GATHER: case VS_SCATTER: {
            // VSIB addressing: the SIB index field names a vector register
            // holding the per-lane offsets. Only the memory form exists.
            if (mod == 3) return false;
            Operand m;
            m.kind = OperandKind::MEM;
            m.size = in.elem_bits;
            m.mem.base = -1;
            int rm = modrmRm(modrm) + rex_b;
            if ((rm & 7) == 4 && i < len) {
                const uint8_t sib = data[i++];
                m.mem.base = (sib & 7) + rex_b;
                const int idx = (sib >> 3) & 7;
                if (idx != 4) in.vsib_reg = static_cast<uint8_t>(16 + idx + rex_x);
                in.vsib_scale = static_cast<uint8_t>(1 << (sib >> 6));
                if ((sib & 7) == 5 && mod == 0) m.mem.base = -1;
            }
            const int disp = (mod == 1) ? 1 : (mod == 2 || m.mem.base < 0) ? 4 : 0;
            if (disp && i + static_cast<size_t>(disp) <= len) {
                int64_t dv = 0;
                for (int k = 0; k < disp; ++k) dv |= static_cast<int64_t>(data[i + k]) << (8 * k);
                if (disp == 1 && (dv & 0x80)) dv |= ~0xFFLL;
                if (disp == 4 && (dv & 0x80000000LL)) dv |= ~0xFFFFFFFFLL;
                m.mem.disp = dv * (evex ? dispN : 1);
                i += disp;
            }
            if (shape == VS_GATHER) {
                in.dst = vecReg(regField, dstBits);
                // EVEX gathers take the mask from aaa (in.mask); the VEX form
                // names a vector register in vvvv.
                if (!evex) in.src = vecReg(in.vex_v, dstBits);
                in.src2 = m;
            } else {
                in.src = vecReg(regField, srcBits);
                in.src2 = m;
                if (evex) in.mask = in.mask;  // k aaa is the writemask
            }
            break;
        }
        case VS_2R: case VS_2RI: {
            // VCOMPRESS* names its source in ModRM.reg and writes a memory
            // destination when mod != 3; the register form has both in the
            // usual places.
            if (hit && hit->op == VecOp::COMPRESS && mod != 3) {
                in.dst = rmVec(dstBytes * 8);
                in.src = vecReg(regField, srcBits);
                break;
            }
            in.dst = vecReg(regField, dstBits);
            in.src2 = rmVec(srcBytes * 8);
            // Two-operand vector forms read their single source into the same
            // slot the three-operand forms call src1, so the interpreter's
            // kernels can treat `a` uniformly as "the input vector".
            in.src = in.src2;
            if (shape == VS_2RI) in.src3 = imm8();
            break;
        }
        case VS_ST: case VS_STI: {
            in.dst = rmVec(dstBytes * 8);
            in.src = vecReg(regField, srcBits);
            if (shape == VS_STI) in.src3 = imm8();
            break;
        }
        case VS_EX: {
            in.src = vecReg(regField, srcBits);
            const int bits = in.elem_bits ? in.elem_bits : dstBytes * 8;
            if (bits <= 64) in.dst = rmGpr(bits);
            else in.dst = rmVec(bits);
            in.src3 = imm8();
            break;
        }
        case VS_INS: {
            in.dst = vecReg(regField, dstBits);
            in.src = vecReg(in.vex_v, srcBits);
            const int bits = in.elem_bits ? in.elem_bits : srcBytes * 8;
            if (bits <= 64 && in.elem_bits != 128 && in.elem_bits != 0)
                in.src2 = rmGpr(bits);
            else
                in.src2 = rmVec(bits);
            in.src3 = imm8();
            break;
        }
        case VS_CMPK: case VS_KF: {
            in.dst = kReg(regField, in.elem_bits);
            in.src2 = rmVec(memBits);
            if (shape == VS_CMPK) in.src = vecReg(in.vex_v, srcBits);
            in.src3 = imm8();
            break;
        }
        case VS_G2V: {
            in.dst = vecReg(regField, dstBits);
            in.src2 = rmGpr(in.elem_bits);
            break;
        }
        case VS_V2G: {
            in.dst = rmGpr(in.elem_bits);
            in.src = vecReg(regField, srcBits);
            break;
        }
        default:
            return false;
    }
    return true;
}

} // namespace

std::optional<Insn> X86Decoder::decode(const uint8_t* data, size_t len, uint64_t addr) {
    if (!data || len == 0) return std::nullopt;
    size_t i = 0;
    Insn in;
    in.address = addr;

    bool rex = false;
    int rex_b = 0, rex_x = 0, rex_r = 0;
    bool has_vex = false;

    // Legacy prefixes
    while (i < len) {
        uint8_t b = data[i];
        if (b == 0xF0) { in.lock = true; ++i; continue; }
        if (b == 0xF3) { in.rep = true; ++i; continue; }
        if (b == 0xF2) { in.repne = true; ++i; continue; }
        if (b == 0x64) { in.seg = 1; ++i; continue; } // FS override (TLS: fs_base + addr)
        if (b == 0x65) { in.seg = 2; ++i; continue; } // GS override
        if (b == 0x2E || b == 0x36 || b == 0x3E ||
            b == 0x26 || b == 0x67) { ++i; continue; }
        if (b == 0x66) { in.o16 = true; ++i; continue; }
        break;
    }
    if (i >= len) return std::nullopt;

    // REX
    if ((data[i] & 0xF0) == 0x40) {
        rex = true;
        in.rex_w = (data[i] & 0x8) != 0;
        rex_r = (data[i] & 0x4) ? 8 : 0;
        rex_x = (data[i] & 0x2) ? 8 : 0;
        rex_b = (data[i] & 0x1) ? 8 : 0;
        ++i;
    }
    // VEX (C4 = 3-byte, C5 = 2-byte). In compat/legacy mode those bytes are
    // LES/LDS instead, so the VEX interpretation is gated off.
    else if ((data[i] == 0xC4 || data[i] == 0xC5) && !g_compat32) {
        has_vex = true;
        const bool three = (data[i] == 0xC4);
        if (i + (three ? 2 : 1) >= len) return std::nullopt;
        if (three) {
            // C4 RXB.mmmmm — the extension bits are stored inverted
            uint8_t b1 = data[i + 1];
            uint8_t b2 = data[i + 2];
            rex_r = (b1 & 0x80) ? 0 : 8;
            rex_x = (b1 & 0x40) ? 0 : 8;
            rex_b = (b1 & 0x20) ? 0 : 8;
            in.vex_map = static_cast<uint8_t>(b1 & 0x1F);
            in.vex_w = (b2 & 0x80) != 0;
            in.vex_v = static_cast<uint8_t>((~(b2 >> 3)) & 0x0F);
            in.vex_l = static_cast<uint8_t>((b2 >> 2) & 1);
            in.vex_pp = (b2 & 0x03) != 0;
            in.vex_pp_bits = static_cast<uint8_t>(b2 & 0x03);
            i += 3;
        } else {
            // C5 R.vvvv.L.pp — map is always 0F, W is 0
            uint8_t b1 = data[i + 1];
            rex_r = (b1 & 0x80) ? 0 : 8;
            in.vex_map = 1;
            in.vex_w = false;
            in.vex_v = static_cast<uint8_t>((~(b1 >> 3)) & 0x0F);
            in.vex_l = static_cast<uint8_t>((b1 >> 2) & 1);
            in.vex_pp = (b1 & 0x03) != 0;
            in.vex_pp_bits = static_cast<uint8_t>(b1 & 0x03);
            i += 2;
        }
        in.vex = true;
        in.rex_w = in.vex_w;
    }
    // EVEX (62 P0 P1 P2). In compat/legacy mode 62 is BOUND instead.
    else if (data[i] == 0x62 && !g_compat32) {
        if (i + 3 >= len) return std::nullopt;
        const uint8_t p0 = data[i + 1];
        const uint8_t p1 = data[i + 2];
        const uint8_t p2 = data[i + 3];
        // P0 must have bits 3:2 clear; P1 bit 2 is fixed 1.
        if ((p0 & 0x0C) != 0 || (p1 & 0x04) == 0) return std::nullopt;
        rex_r = (p0 & 0x80) ? 0 : 8;
        rex_x = (p0 & 0x40) ? 0 : 8;
        rex_b = (p0 & 0x20) ? 0 : 8;
        const int rex_r2 = (p0 & 0x10) ? 0 : 8;
        in.vex_map = static_cast<uint8_t>(p0 & 0x03);
        in.vex_w = (p1 & 0x80) != 0;
        in.rex_w = in.vex_w;
        in.vex_v = static_cast<uint8_t>(((~(p1 >> 3)) & 0x0F) |
                                        (((~p2 >> 3) & 1) << 4));
        in.vex_pp_bits = static_cast<uint8_t>(p1 & 0x03);
        in.vex_pp = in.vex_pp_bits != 0;
        in.evex_ll = static_cast<uint8_t>((p2 >> 5) & 0x03);
        in.vex_l = in.evex_ll ? 1 : 0;
        in.evex_b = (p2 & 0x10) != 0;
        in.zeroing = (p2 & 0x80) != 0;
        in.mask = static_cast<uint8_t>(p2 & 0x07);
        in.evex = true;
        in.vex = true;
        i += 4;
        // The opcode follows; the shared vector dispatcher consumes it.
        if (i < len && decodeVectorOp(data, len, i, in, rex_r, rex_r2, rex_x, rex_b, true)) {
            in.length = static_cast<uint8_t>(i);
            return in;
        }
        // Unknown EVEX encoding: keep the stream aligned.
        if (i < len) {
            const uint8_t modrm = data[i++];
            Operand ignored;
            parseRmRest(data, len, i, modrm, rex_b, rex_x, ignored);
            if (in.vex_map == 3 && i < len) ++i;
        }
        in.op = X86Op::EVEX_OP;
        in.length = static_cast<uint8_t>(i);
        in.mnemonic = "evex";
        return in;
    }
    if (i >= len) return std::nullopt;

    uint8_t opc = data[i++];
    int opsize = in.o16 ? 16 : (in.rex_w ? 64 : 32);

    auto finish = [&](X86Op op, const char* mnem) -> std::optional<Insn> {
        in.op = op;
        in.mnemonic = mnem;
        in.length = static_cast<uint8_t>(i);
        if (in.seg) {
            if (in.dst.kind == OperandKind::MEM) in.dst.mem.seg = in.seg;
            if (in.src.kind == OperandKind::MEM) in.src.mem.seg = in.seg;
            if (in.src2.kind == OperandKind::MEM) in.src2.mem.seg = in.seg;
        }
        return in;
    };

    // ---- VEX opcode dispatch -------------------------------------------
    // Only the BMI1 integer subset is decoded semantically today; every other
    // VEX form stays a structural placeholder (still consumed exactly, so the
    // stream stays aligned).
    if (in.vex) {
        const uint8_t vopc = opc;
        // ---- §2.20 VEX forms -------------------------------------------
        // VZEROUPPER / VZEROALL (VEX.NP.0F 77, no ModRM). NINE models no
        // 256/512-bit state, so both retire as no-ops that still end any
        // pending AVX upper-state transaction; the mnemonic keeps them
        // visible in traces.
        if (in.vex_map == 1 && vopc == 0x77 && !in.vex_pp) {
            in.cc = in.vex_l ? 1 : 0;
            return finish(X86Op::VZERO, in.vex_l ? "vzeroall" : "vzeroupper");
        }
        // VEX.F2.0F3A F0 — RORX: rotate right without touching flags.
        if (in.vex_map == 3 && vopc == 0xF0 && in.vex_pp_bits == 3 && i + 1 < len) {
            const int bits = in.vex_w ? 64 : 32;
            uint8_t modrm = data[i++];
            in.dst.kind = OperandKind::REG;
            in.dst.reg = modrmReg(modrm) + rex_r;
            in.dst.size = bits;
            Operand src;
            src.size = bits;
            parseRm(data, len, i, modrm, rex_b, rex_x, src);
            in.src = src;
            in.src2.kind = OperandKind::IMM;
            in.src2.size = 8;
            in.src2.imm = data[i++];
            return finish(X86Op::RORX, bits == 64 ? "rorxq" : "rorxl");
        }
        // VEX.66/ F3/F2 0F38 F7 — SHLX (66), SARX (F3), SHRX (F2). RMV shape:
        // ModRM.reg is the destination, r/m the value, VEX.vvvv the count.
        // None of the three reads or writes EFLAGS.
        if (in.vex_map == 2 && vopc == 0xF7 && in.vex_pp_bits != 0 && i < len) {
            const int bits = in.vex_w ? 64 : 32;
            const uint8_t pp = in.vex_pp_bits;
            uint8_t modrm = data[i++];
            in.dst.kind = OperandKind::REG;
            in.dst.reg = modrmReg(modrm) + rex_r;
            in.dst.size = bits;
            Operand src;
            src.size = bits;
            parseRm(data, len, i, modrm, rex_b, rex_x, src);
            in.src = src;
            in.src2.kind = OperandKind::REG;
            in.src2.reg = in.vex_v;
            in.src2.size = bits;
            if (pp == 1) return finish(X86Op::SHLX, bits == 64 ? "shlxq" : "shlxl");
            if (pp == 2) return finish(X86Op::SARX, bits == 64 ? "sarxq" : "sarxl");
            return finish(X86Op::SHRX, bits == 64 ? "shrxq" : "shrxl");
        }
        // VEX.LZ.NP.0F AE /2,/3 — VLDMXCSR / VSTMXCSR (memory only).
        if (in.vex_map == 1 && vopc == 0xAE && !in.vex_pp && i < len) {
            uint8_t modrm = data[i];
            if (modrmMod(modrm) != 3) {
                const int ext = modrmReg(modrm);
                if (ext == 2 || ext == 3) {
                    ++i;
                    Operand m;
                    m.size = 32;
                    parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
                    if (ext == 2) {
                        in.src = m;
                        return finish(X86Op::LDMXCSR, "vldmxcsr");
                    }
                    in.dst = m;
                    return finish(X86Op::STMXCSR, "vstmxcsr");
                }
            }
        }
        // VEX.128.66.0F F7 — VMASKMOVDQU (register form only).
        if (in.vex_map == 1 && vopc == 0xF7 && in.vex_pp_bits == 1 && i < len) {
            uint8_t modrm = data[i];
            if (modrmMod(modrm) == 3) {
                ++i;
                in.dst.kind = OperandKind::REG;
                in.dst.reg = 16 + (modrmRm(modrm) + rex_b);
                in.dst.size = 128;
                in.src.kind = OperandKind::REG;
                in.src.reg = 16 + (modrmReg(modrm) + rex_r);
                in.src.size = 128;
                return finish(X86Op::MASKMOVDQU, "vmaskmovdqu");
            }
        }
        // VEX.F2/F3.0F38 F5 — PDEP / PEXT (BMI2). Both share the opcode and
        // differ only in the mandatory prefix.
        if (in.vex_map == 2 && vopc == 0xF5 && i < len &&
            (in.vex_pp_bits == 3 || in.vex_pp_bits == 2)) {
            const int bits = in.vex_w ? 64 : 32;
            const uint8_t modrm = data[i++];
            in.dst.kind = OperandKind::REG;
            in.dst.reg = modrmReg(modrm) + rex_r;
            in.dst.size = bits;
            in.src.kind = OperandKind::REG;
            in.src.reg = in.vex_v;
            in.src.size = bits;
            Operand rm;
            rm.size = bits;
            parseRm(data, len, i, modrm, rex_b, rex_x, rm);
            in.src2 = rm;
            return finish(in.vex_pp_bits == 3 ? X86Op::PDEP : X86Op::PEXT,
                          in.vex_pp_bits == 3 ? "pdep" : "pext");
        }
        if (in.vex_map == 2 && !in.vex_pp && i < len &&
            (vopc == 0xF2 || vopc == 0xF3 || vopc == 0xF5 || vopc == 0xF7)) {
            const int bits = in.vex_w ? 64 : 32;
            uint8_t modrm = data[i++];
            const int reg = modrmReg(modrm) + rex_r;
            Operand rmop;
            rmop.size = bits;
            parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
            Operand dst;
            dst.kind = OperandKind::REG;
            dst.size = bits;
            if (vopc == 0xF2) {
                // ANDN r32a, r32b, r/m32 — dst = ~vvvv & r/m
                dst.reg = reg;
                in.dst = dst;
                in.src.kind = OperandKind::REG;
                in.src.reg = in.vex_v;
                in.src.size = bits;
                in.src2 = rmop;
                return finish(X86Op::ANDN, "andn");
            }
            if (vopc == 0xF3) {
                // BLSI (/3) BLSMSK (/2) BLSR (/1): destination is VEX.vvvv
                const int ext = reg & 7;
                if (ext < 1 || ext > 3) return std::nullopt;
                dst.reg = in.vex_v;
                in.dst = dst;
                in.src = rmop;
                return finish(ext == 1 ? X86Op::BLSR :
                              ext == 2 ? X86Op::BLSMSK : X86Op::BLSI,
                              ext == 1 ? "blsr" : ext == 2 ? "blsmsk" : "blsi");
            }
            dst.reg = reg;
            in.dst = dst;
            in.src = rmop;
            in.src2.kind = OperandKind::REG;
            in.src2.reg = in.vex_v;
            in.src2.size = bits;
            if (vopc == 0xF5) return finish(X86Op::BZHI, "bzhi");
            return finish(X86Op::BEXTR, "bextr");
        }
        // VEX.F2.0F38 F6 — MULX: RDX * r/m, low half into ModRM.reg and high
        // half into VEX.vvvv, without touching flags.
        if (in.vex_map == 2 && in.vex_pp_bits == 3 && vopc == 0xF6 && i < len) {
            const int bits = in.vex_w ? 64 : 32;
            uint8_t modrm = data[i++];
            Operand rmop;
            rmop.size = bits;
            parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
            in.dst.kind = OperandKind::REG;
            in.dst.reg = modrmReg(modrm) + rex_r;
            in.dst.size = bits;
            in.src = rmop;
            in.src2.kind = OperandKind::REG;
            in.src2.reg = in.vex_v;
            in.src2.size = bits;
            return finish(X86Op::MULX, "mulx");
        }
        // ---- AVX-512 mask-register group (k0-k7) --------------------------
        // Every mask instruction is a VEX encoding whose element width comes
        // from pp and VEX.W: (pp=0,W=0)=16, (pp=1,W=0)=8, (pp=0,W=1)=64,
        // (pp=1,W=1)=32. The shift and GPR<->k moves use pp=3 (F2) as well as
        // pp=1, so those four opcodes are handled separately.
        if (i < len) {
            const uint8_t kpp = in.vex_pp_bits;
            const uint8_t kmodrm = data[i];
            const int kdst = modrmReg(kmodrm);          // k0-k7 only
            const int krm = modrmRm(kmodrm);
            const bool kreg = modrmMod(kmodrm) == 3;
            int kbits = 0;
            const char* ksuf = "";
            if (kpp == 0) { kbits = in.vex_w ? 64 : 16; ksuf = in.vex_w ? "q" : "w"; }
            else if (kpp == 1) { kbits = in.vex_w ? 32 : 8; ksuf = in.vex_w ? "d" : "b"; }
            std::string knm;

            // dst = k(reg), src = k(vvvv), src2 = k/m — the ternary bitwise
            // and arithmetic forms (KAND/KANDN/KOR/KXOR/KXNOR/KADD).
            auto ktern = [&](X86Op k_op, const char* stem) -> std::optional<Insn> {
                if (kbits == 0) return std::nullopt;
                ++i;
                in.dst.kind = OperandKind::K; in.dst.reg = kdst; in.dst.size = kbits;
                in.src.kind = OperandKind::K; in.src.reg = in.vex_v; in.src.size = kbits;
                if (kreg) {
                    in.src2.kind = OperandKind::K; in.src2.reg = krm; in.src2.size = kbits;
                } else {
                    Operand m; m.size = kbits;
                    parseRmRest(data, len, i, kmodrm, rex_b, rex_x, m);
                    in.src2 = m;
                }
                knm = stem; knm += ksuf;
                return finish(k_op, knm.c_str());
            };
            // dst = k(reg), src = k/m — KNOT, KTEST, KORTEST.
            auto kunary = [&](X86Op k_op, const char* stem) -> std::optional<Insn> {
                if (kbits == 0) return std::nullopt;
                ++i;
                in.dst.kind = OperandKind::K; in.dst.reg = kdst; in.dst.size = kbits;
                if (kreg) {
                    in.src.kind = OperandKind::K; in.src.reg = krm; in.src.size = kbits;
                } else {
                    Operand m; m.size = kbits;
                    parseRmRest(data, len, i, kmodrm, rex_b, rex_x, m);
                    in.src = m;
                }
                knm = stem; knm += ksuf;
                return finish(k_op, knm.c_str());
            };

            if (in.vex_map == 1) {
                if (vopc == 0x41) return ktern(X86Op::KAND, "kand");
                if (vopc == 0x42) return ktern(X86Op::KANDN, "kandn");
                if (vopc == 0x45) return ktern(X86Op::KOR, "kor");
                if (vopc == 0x46) return ktern(X86Op::KXNOR, "kxnor");
                if (vopc == 0x47) return ktern(X86Op::KXOR, "kxor");
                if (vopc == 0x4A) return ktern(X86Op::KADD, "kadd");
                if (vopc == 0x44) return kunary(X86Op::KNOT, "knot");
                if (vopc == 0x98) return kunary(X86Op::KORTEST, "kortest");
                if (vopc == 0x99) return kunary(X86Op::KTEST, "ktest");

                // 4B — KUNPCKBW/WD/DQ: interleave the low halves of two masks.
                // pp/W choose the *source* width; the destination is twice it.
                if (vopc == 0x4B) {
                    int sbits = 0;
                    const char* sfx = "";
                    if (kpp == 1 && !in.vex_w) { sbits = 8; sfx = "bw"; }
                    else if (kpp == 0 && !in.vex_w) { sbits = 16; sfx = "wd"; }
                    else if (kpp == 0 && in.vex_w) { sbits = 32; sfx = "dq"; }
                    else return std::nullopt;
                    if (!kreg) return std::nullopt;
                    ++i;
                    in.dst.kind = OperandKind::K; in.dst.reg = kdst; in.dst.size = sbits * 2;
                    in.src.kind = OperandKind::K; in.src.reg = in.vex_v; in.src.size = sbits;
                    in.src2.kind = OperandKind::K; in.src2.reg = krm; in.src2.size = sbits;
                    knm = "kunpck"; knm += sfx;
                    return finish(X86Op::KUNPCK, knm.c_str());
                }

                // 90/91 — k<->k/m, 92/93 — GPR<->k (F2 encodes the GPR forms).
                if (vopc >= 0x90 && vopc <= 0x93) {
                    if (kpp == 3) {
                        if (!kreg || vopc < 0x92) return std::nullopt;
                        const int gbits = in.vex_w ? 64 : 32;
                        ++i;
                        if (vopc == 0x92) {          // KMOVd/q r32/64, k(reg)
                            in.dst.kind = OperandKind::REG;
                            in.dst.reg = krm + rex_b;
                            in.dst.size = gbits;
                            in.src.kind = OperandKind::K;
                            in.src.reg = kdst;
                            in.src.size = gbits;
                        } else {                     // KMOVd/q k(reg), r32/64
                            in.dst.kind = OperandKind::K;
                            in.dst.reg = kdst;
                            in.dst.size = gbits;
                            in.src.kind = OperandKind::REG;
                            in.src.reg = krm + rex_b;
                            in.src.size = gbits;
                        }
                        knm = "kmov"; knm += in.vex_w ? "q" : "d";
                        return finish(X86Op::KMOV, knm.c_str());
                    }
                    if (kbits == 0) return std::nullopt;
                    ++i;
                    if (vopc == 0x90) {              // KMOVw/b/d/q k(reg), k/m
                        in.dst.kind = OperandKind::K; in.dst.reg = kdst; in.dst.size = kbits;
                        if (kreg) {
                            in.src.kind = OperandKind::K; in.src.reg = krm; in.src.size = kbits;
                        } else {
                            Operand m; m.size = kbits;
                            parseRmRest(data, len, i, kmodrm, rex_b, rex_x, m);
                            in.src = m;
                        }
                    } else {                         // KMOVw/b/d/q k/m, k(reg)
                        in.src.kind = OperandKind::K; in.src.reg = kdst; in.src.size = kbits;
                        if (kreg) {
                            in.dst.kind = OperandKind::K; in.dst.reg = krm; in.dst.size = kbits;
                        } else {
                            Operand m; m.size = kbits;
                            parseRmRest(data, len, i, kmodrm, rex_b, rex_x, m);
                            in.dst = m;
                        }
                    }
                    knm = "kmov"; knm += ksuf;
                    return finish(X86Op::KMOV, knm.c_str());
                }
            }

            // 30-33 — KSHIFTRB/W/D/Q, KSHIFTLB/W/D/Q (VEX.66.0F3A /r ib).
            if (in.vex_map == 3 && vopc >= 0x30 && vopc <= 0x33 && kpp == 1 &&
                kreg && i + 1 < len) {
                const char* stem = (vopc >= 0x32) ? "kshiftl" : "kshiftr";
                int sbits = 0;
                const char* sfx = "";
                if (vopc == 0x30 || vopc == 0x32) { sbits = in.vex_w ? 16 : 8; sfx = in.vex_w ? "w" : "b"; }
                else { sbits = in.vex_w ? 64 : 32; sfx = in.vex_w ? "q" : "d"; }
                const uint8_t kshift = data[i + 1];
                ++i;
                in.dst.kind = OperandKind::K; in.dst.reg = kdst; in.dst.size = sbits;
                in.src.kind = OperandKind::K; in.src.reg = krm; in.src.size = sbits;
                in.src2.kind = OperandKind::IMM; in.src2.imm = kshift; in.src2.size = 8;
                ++i;
                knm = stem; knm += sfx;
                return finish(vopc >= 0x32 ? X86Op::KSHIFTL : X86Op::KSHIFTR,
                              knm.c_str());
            }
        }

        // LDTILECFG (VEX.128.NP.0F38.W0 49 /0) — AMX tile configuration. NINE
        // has no tile file, so it is decoded exactly and then refused with the
        // #UD real silicon raises without XCR0.AMX.
        if (in.vex_map == 2 && in.vex_pp_bits == 0 && vopc == 0x49 && i < len) {
            uint8_t modrm = data[i];
            if (modrmReg(modrm) == 0 && modrmMod(modrm) != 3) {
                ++i;
                Operand m;
                m.size = 512 * 8;
                parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
                in.src = m;
                return finish(X86Op::LDTILECFG, "ldtilecfg");
            }
        }

        // Generic AVX/AVX2 vector dispatch. The BMI1/BMI2 and mask-register
        // forms above already claimed their opcodes; everything else that the
        // table knows about lands here.
        if (decodeVectorOp(data, len, i, in, rex_r, 0, rex_x, rex_b, false, opc)) {
            in.length = static_cast<uint8_t>(i);
            return in;
        }

        // Unsupported VEX form: placeholder with the full instruction length.
        if (i < len) {
            uint8_t modrm = data[i++];
            Operand ignored;
            parseRmRest(data, len, i, modrm, rex_b, rex_x, ignored);
            if (in.vex_map == 3 && i < len) ++i; // imm8
        }
        in.op = X86Op::VEX_OP;
        in.length = static_cast<uint8_t>(i);
        in.mnemonic = "vex";
        return in;
    }

    // NOP / PAUSE / HLT
    // 90 is NOP (or PAUSE with F3). The 66 prefix spells it as xchg ax, ax,
    // which compilers emit as padding; either way it has no effect.
    if (opc == 0x90 && !rex) return finish(X86Op::NOP, in.rep ? "pause" : "nop");
    // XCHG r, rax (91-97, or 90 with REX.B)
    if ((opc == 0x90 && rex) || (opc >= 0x91 && opc <= 0x97)) {
        in.dst.kind = OperandKind::REG;
        in.dst.reg = 0;
        in.dst.size = in.rex_w ? 64 : (in.o16 ? 16 : 32);
        in.src.kind = OperandKind::REG;
        in.src.reg = (opc & 7) + rex_b;
        in.src.size = in.dst.size;
        return finish(X86Op::XCHG, "xchg");
    }
    // HLT (F4). At CPL 3 real hardware raises #GP(0); inside NINE the guest is
    // the only code running, so it stops the machine cleanly instead.
    if (opc == 0xF4) return finish(X86Op::HLT, "hlt");
    // WAIT/FWAIT (9B): no pending x87 exception is ever reported, so it is a
    // no-op. Everything after it is decoded normally.
    if (opc == 0x9B) return finish(X86Op::NOP, "fwait");
    // String ops: STOS/LODS/MOVS/SCAS/CMPS (A4-AF). The F3/F2 prefixes are
    // REP/REPE/REPZ and REPNE/REPNZ; the interpreter repeats the primitive
    // until RCX reaches zero (or, for the compare forms, while ZF keeps the
    // sense of the prefix). Prefixes change only the printed mnemonic here —
    // `in.rep`/`in.repne` already drive the repeat in the interpreter.
    auto stringMnemonic = [&](const char* base, bool compareForm) {
        std::string s;
        if (in.rep) s = compareForm ? "repe " : "rep ";
        else if (in.repne) s = "repne ";
        s += base;
        return s;
    };
    if (opc == 0xAA || opc == 0xAB) {
        in.dst.size = (opc == 0xAA) ? 8 : (in.rex_w ? 64 : (in.o16 ? 16 : 32));
        const char* base = opc == 0xAB ? (in.rex_w ? "stosq" : (in.o16 ? "stosw" : "stosd")) : "stosb";
        const std::string mn = stringMnemonic(base, false);
        return finish(X86Op::STOS, mn.c_str());
    }
    if (opc == 0xAC || opc == 0xAD) {
        in.dst.kind = OperandKind::REG;
        in.dst.reg = 0; // AL / AX / EAX / RAX
        in.dst.size = (opc == 0xAC) ? 8 : (in.rex_w ? 64 : (in.o16 ? 16 : 32));
        const char* base = opc == 0xAC ? "lodsb" : (in.rex_w ? "lodsq" : (in.o16 ? "lodsw" : "lodsd"));
        const std::string mn = stringMnemonic(base, false);
        return finish(X86Op::LODS, mn.c_str());
    }
    if (opc == 0xA4 || opc == 0xA5) {
        in.dst.size = (opc == 0xA4) ? 8 : (in.rex_w ? 64 : (in.o16 ? 16 : 32));
        const char* base = opc == 0xA4 ? "movsb" : (in.rex_w ? "movsq" : (in.o16 ? "movsw" : "movsd"));
        const std::string mn = stringMnemonic(base, false);
        return finish(X86Op::MOVS, mn.c_str());
    }
    if (opc == 0xAE || opc == 0xAF) {
        in.dst.size = (opc == 0xAE) ? 8 : (in.rex_w ? 64 : (in.o16 ? 16 : 32));
        in.src.kind = OperandKind::REG;
        in.src.reg = 0; // AL / AX / EAX / RAX compared against [RDI]
        in.src.size = in.dst.size;
        const char* base = opc == 0xAE ? "scasb" : (in.rex_w ? "scasq" : (in.o16 ? "scasw" : "scasd"));
        const std::string mn = stringMnemonic(base, true);
        return finish(X86Op::SCAS, mn.c_str());
    }
    // CMPS m8/m16/m32/m64 — compare [RSI] with [RDI] (F3 = REPE, F2 = REPNE).
    if (opc == 0xA6 || opc == 0xA7) {
        in.dst.size = (opc == 0xA6) ? 8 : (in.rex_w ? 64 : (in.o16 ? 16 : 32));
        const char* base = opc == 0xA6 ? "cmpsb" : (in.rex_w ? "cmpsq" : (in.o16 ? "cmpsw" : "cmpsd"));
        const std::string mn = stringMnemonic(base, true);
        return finish(X86Op::CMPS, mn.c_str());
    }
    // Legacy ASCII/BCD adjust: AAA (37), AAS (3F), AAM (D4 ib), AAD (D5 ib).
    // Architecturally invalid in 64-bit mode, but NINE has no compat/legacy
    // execution mode — the legacy semantics are executed so old code paths
    // never die with "unimplemented: aaa".
    if (opc == 0x37) return finish(X86Op::AAA, "aaa");
    if (opc == 0x3F) return finish(X86Op::AAS, "aas");
    if (opc == 0x27) return finish(X86Op::DAA, "daa");
    if (opc == 0x2F) return finish(X86Op::DAS, "das");
    if (opc == 0xD4 || opc == 0xD5) {
        if (i >= len) return std::nullopt;                 // mandatory imm8
        uint8_t base = data[i++];
        in.src.kind = OperandKind::IMM;
        in.src.imm = base;
        in.src.size = 8;
        return finish(opc == 0xD4 ? X86Op::AAM : X86Op::AAD,
                      opc == 0xD4 ? "aam" : "aad");
    }

    // TEST r/m, r  (84/85)
    if ((opc == 0x84 || opc == 0x85) && i < len) {
        uint8_t modrm = data[i++];
        int reg = modrmReg(modrm) + rex_r;
        int rm = modrmRm(modrm) + rex_b;
        int mod = modrmMod(modrm);
        in.src.kind = OperandKind::REG;
        in.src.reg = reg;
        in.src.size = (opc == 0x84) ? 8 : opsize;
        if (opc == 0x84) applyByteReg(in.src, rex);
        if (mod == 3) {
            in.dst.kind = OperandKind::REG;
            in.dst.reg = rm;
            in.dst.size = in.src.size;
            if (opc == 0x84) applyByteReg(in.dst, rex);
        } else {
            in.dst.kind = OperandKind::MEM;
            in.dst.size = in.src.size;
            in.dst.mem.base = rm;
            if (mod == 0 && (rm & 7) == 5) { in.dst.mem.rip_relative = true; in.dst.mem.base = -1; }
            if ((rm & 7) == 4 && i < len) {
                uint8_t sib = data[i++];
                in.dst.mem.base = (sib & 7) + rex_b;
                int idx = (sib >> 3) & 7;
                in.dst.mem.index = (idx == 4 && !rex_x) ? -1 : idx + rex_x;
                in.dst.mem.scale = 1 << (sib >> 6);
                if ((sib & 7) == 5 && mod == 0) in.dst.mem.base = -1;
            }
            int disp = (mod == 1) ? 1 : (mod == 2 || in.dst.mem.rip_relative || (in.dst.mem.base < 0 && !in.dst.mem.rip_relative)) ? 4 : 0;
            if (disp && i + disp <= len) {
                int64_t d = 0;
                for (int k = 0; k < disp; ++k) d |= static_cast<int64_t>(data[i + k]) << (8 * k);
                if (disp == 1 && (d & 0x80)) d |= ~0xFFLL;
                if (disp == 4 && (d & 0x80000000LL)) d |= ~0xFFFFFFFFLL;
                in.dst.mem.disp = d;
                i += disp;
            }
        }
        return finish(X86Op::TEST, "test");
    }
    // TEST AL/AX/EAX/RAX, imm  (A8 ib / A9 iz)
    if (opc == 0xA8 || opc == 0xA9) {
        int imm_n = (opc == 0xA8) ? 1 : (in.o16 ? 2 : 4);
        if (i + imm_n > len) return std::nullopt;
        int64_t imm = 0;
        for (int k = 0; k < imm_n; ++k) imm |= static_cast<int64_t>(data[i + k]) << (8 * k);
        if (imm_n == 1 && (imm & 0x80)) imm |= ~0xFFLL;
        if (imm_n == 2 && (imm & 0x8000)) imm |= ~0xFFFFLL;
        if (imm_n == 4 && (imm & 0x80000000LL)) imm |= ~0xFFFFFFFFLL;
        i += imm_n;
        in.dst.kind = OperandKind::REG;
        in.dst.reg = 0; // AL / AX / EAX / RAX
        in.dst.size = (opc == 0xA8) ? 8 : (in.rex_w ? 64 : (in.o16 ? 16 : 32));
        in.src.kind = OperandKind::IMM;
        in.src.imm = imm;
        in.src.size = in.dst.size;
        return finish(X86Op::TEST, "test");
    }
    // MOV with 64-bit moffs absolute address (A0-A3)
    if (opc >= 0xA0 && opc <= 0xA3) {
        if (i + 8 > len) return std::nullopt;
        uint64_t moffs = 0;
        for (int k = 0; k < 8; ++k) moffs |= static_cast<uint64_t>(data[i + k]) << (8 * k);
        i += 8;
        int to_reg = (opc == 0xA0 || opc == 0xA1);
        Operand m;
        m.kind = OperandKind::MEM;
        m.size = (opc == 0xA0 || opc == 0xA2) ? 8 : (in.rex_w ? 64 : (in.o16 ? 16 : 32));
        m.mem.disp = static_cast<int64_t>(moffs); // absolute, no base/index
        Operand r;
        r.kind = OperandKind::REG;
        r.reg = 0;
        r.size = m.size;
        if (to_reg) { in.dst = r; in.src = m; }
        else { in.dst = m; in.src = r; }
        return finish(X86Op::MOV, "mov moffs");
    }
    // Jcc rel32: 0F 8x

    // RET
    if (opc == 0xC3) return finish(X86Op::RET, "ret");
    // LEAVE (0xC9) = MOV RSP,RBP; POP RBP
    if (opc == 0xC9) return finish(X86Op::LEAVE, "leave");
    // ENTER imm16, imm8 — build a stack frame with `level` nested pointers.
    if (opc == 0xC8) {
        if (i + 3 > len) return std::nullopt;
        int64_t frame = data[i] | (data[i + 1] << 8);
        int64_t level = data[i + 2];
        i += 3;
        in.src.kind = OperandKind::IMM;
        in.src.imm = frame;
        in.src.size = 16;
        in.src2.kind = OperandKind::IMM;
        in.src2.imm = level;
        in.src2.size = 8;
        return finish(X86Op::ENTER, "enter");
    }
    // x87 escapes D8-DF (all operands live in the escape byte's modrm).
    if (opc >= 0xD8 && opc <= 0xDF) {
        if (!decodeX87(data, len, i, opc, in, rex_b, rex_x)) return std::nullopt;
        if (in.seg) {
            if (in.dst.kind == OperandKind::MEM) in.dst.mem.seg = in.seg;
            if (in.src.kind == OperandKind::MEM) in.src.mem.seg = in.seg;
        }
        in.length = static_cast<uint8_t>(i);
        return in;
    }
    // SYSCALL
    if (opc == 0x0F && i < len && data[i] == 0x05) { ++i; return finish(X86Op::SYSCALL, "syscall"); }
    // INT3 / UD2
    if (opc == 0xCC) return finish(X86Op::INT3, "int3");
    if (opc == 0x0F && i < len && data[i] == 0x0B) { ++i; return finish(X86Op::UD2, "ud2"); }

    // INT1/F1 and INT n/CD ib. Both raise #UD on silicon at CPL 3 unless a
    // handler is reachable, which the interpreter reports by name.
    if (opc == 0xF1) return finish(X86Op::INT1, "int1");
    if (opc == 0xCD) {
        if (i >= len) return std::nullopt;
        in.src.kind = OperandKind::IMM;
        in.src.imm = data[i++];
        in.src.size = 8;
        return finish(X86Op::INTN, "int");
    }
    // INTO (CE) is invalid in 64-bit mode; compat images may still use it.
    if (opc == 0xCE && g_compat32) return finish(X86Op::INTO, "into");
    // IRET/IRETD/IRETQ (CF): the operand size picks the frame width.
    if (opc == 0xCF) {
        in.dst.size = in.rex_w ? 64 : (in.o16 ? 16 : 32);
        return finish(X86Op::IRET, in.rex_w ? "iretq" : (in.o16 ? "iret" : "iretd"));
    }
    // LAHF (9F) — AH <- SF:ZF:0:AF:0:PF:1:CF
    if (opc == 0x9F) return finish(X86Op::LAHF, "lahf");
    // 9E — SAHF: the inverse direction of LAHF, loading SF:ZF:0:AF:0:PF:1:CF
    // from AH. OF and the reserved bits are left untouched.
    if (opc == 0x9E) return finish(X86Op::SAHF, "sahf");
    // IN AL/eAX, imm8 (E4/E5) and IN AL/eAX, DX (EC/ED). Unprivileged but
    // gated by IOPL, so a CPL-3 guest takes #GP(0).
    if (opc == 0xE4 || opc == 0xE5) {
        if (i >= len) return std::nullopt;
        in.dst.kind = OperandKind::REG;
        in.dst.reg = 0;
        in.dst.size = (opc == 0xE4) ? 8 : (in.o16 ? 16 : 32);
        in.src.kind = OperandKind::IMM;
        in.src.imm = data[i++];
        in.src.size = 16;
        return finish(X86Op::IN, (opc == 0xE4) ? "in al, ib" : "in eax, ib");
    }
    if (opc == 0xEC || opc == 0xED) {
        in.dst.kind = OperandKind::REG;
        in.dst.reg = 0;
        in.dst.size = (opc == 0xEC) ? 8 : (in.o16 ? 16 : 32);
        in.src.kind = OperandKind::REG;
        in.src.reg = 2;   // DX holds the port number
        in.src.size = 16;
        return finish(X86Op::IN, (opc == 0xEC) ? "in al, dx" : "in eax, dx");
    }
    // INS m8/m16/m32, DX (6C/6D)
    if (opc == 0x6C || opc == 0x6D) {
        in.dst.size = (opc == 0x6C) ? 8 : (in.o16 ? 16 : 32);
        return finish(X86Op::INS, opc == 0x6C ? "insb" : (in.o16 ? "insw" : "insd"));
    }
    // OUT imm8/DX (E6/E7/EE/EF) and OUTS (6E/6F): port writes need IOPL >= CPL,
    // so the interpreter raises #GP(0). Decoded for exact length + tracing.
    if (opc == 0xE6 || opc == 0xE7) {
        if (i >= len) return std::nullopt;
        in.dst.kind = OperandKind::IMM;
        in.dst.imm = data[i++];
        in.dst.size = 16;
        return finish(X86Op::OUT, (opc == 0xE6) ? "out ib, al" : "out ib, eax");
    }
    if (opc == 0xEE || opc == 0xEF) {
        in.dst.kind = OperandKind::REG;
        in.dst.reg = 2;   // DX holds the port number
        in.dst.size = 16;
        return finish(X86Op::OUT, (opc == 0xEE) ? "out dx, al" : "out dx, eax");
    }
    if (opc == 0x6E || opc == 0x6F) {
        in.dst.size = (opc == 0x6E) ? 8 : (in.o16 ? 16 : 32);
        return finish(X86Op::OUTS, opc == 0x6E ? "outsb" : (in.o16 ? "outsw" : "outsd"));
    }
    // LOOP/LOOPE/LOOPNE/JRCXZ rel8 (E0-E3). Counter is RCX (NINE has no 32-bit
    // address-size prefix, so the ECX form collapses onto the same counter).
    if (opc >= 0xE0 && opc <= 0xE3) {
        if (i >= len) return std::nullopt;
        const int8_t rel = static_cast<int8_t>(data[i++]);
        in.dst.kind = OperandKind::REL;
        in.dst.imm = static_cast<int64_t>(addr + i) + rel;
        // 0=LOOP (dec, !=0), 1=LOOPE (dec, !=0 && ZF), 2=LOOPNE (dec, !=0 && !ZF),
        // 3=JRCXZ (no decrement, jump when RCX == 0).
        in.cc = (opc == 0xE0) ? 2 : (opc == 0xE1) ? 1 : (opc == 0xE2) ? 0 : 3;
        return finish(X86Op::LOOP, in.cc == 0 ? "loop" : in.cc == 1 ? "loope" :
                                                   in.cc == 2 ? "loopne" : "jrcxz");
    }
    // LES r16/32, m16:16 (C4) — compat mode only; long mode reads it as VEX.
    if (opc == 0xC4 && g_compat32) {
        if (i >= len) return std::nullopt;
        uint8_t modrm = data[i++];
        in.dst.kind = OperandKind::REG;
        in.dst.reg = modrmReg(modrm) + rex_r;
        in.dst.size = in.o16 ? 16 : 32;
        Operand m;
        m.size = 32;
        parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
        if (m.kind != OperandKind::MEM) return std::nullopt;
        in.src = m;
        return finish(X86Op::LES, "les");
    }
    // LDS r16/32, m16:16 (C5) — compat mode only; long mode reads it as VEX.
    if (opc == 0xC5 && g_compat32) {
        if (i >= len) return std::nullopt;
        uint8_t modrm = data[i++];
        in.dst.kind = OperandKind::REG;
        in.dst.reg = modrmReg(modrm) + rex_r;
        in.dst.size = in.o16 ? 16 : 32;
        Operand m;
        m.size = 32;
        parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
        if (m.kind != OperandKind::MEM) return std::nullopt;
        in.src = m;
        return finish(X86Op::LDS, "lds");
    }

    // 60/61 — PUSHA/POPA: invalid in 64-bit mode (the interpreter raises #UD).
    if (opc == 0x60 || opc == 0x61)
        return finish(opc == 0x60 ? X86Op::PUSHA : X86Op::POPA,
                      opc == 0x60 ? "pusha" : "popa");

    // 68/6A — PUSH imm32 / imm8 (sign-extended to the operand size).
    if (opc == 0x68 || opc == 0x6A) {
        const int n = (opc == 0x68) ? (in.o16 ? 2 : 4) : 1;
        if (i + static_cast<size_t>(n) > len) return std::nullopt;
        int64_t v = 0;
        for (int k = 0; k < n; ++k) v |= static_cast<int64_t>(data[i + k]) << (8 * k);
        if (n == 1 && (v & 0x80)) v |= ~0xFFLL;
        if (n == 4 && (v & 0x80000000LL)) v |= ~0xFFFFFFFFLL;
        i += static_cast<size_t>(n);
        in.dst.kind = OperandKind::IMM;
        in.dst.imm = v;
        in.dst.size = in.o16 ? 16 : 64;
        return finish(X86Op::PUSH, "push");
    }

    // 9C/9D — PUSHF/POPF (PUSHFQ/POPFQ in 64-bit mode).
    if (opc == 0x9C || opc == 0x9D) {
        in.dst.size = in.o16 ? 16 : 64;
        return finish(opc == 0x9C ? X86Op::PUSHF : X86Op::POPF,
                      opc == 0x9C ? "pushf" : "popf");
    }

    // PUSH/POP r64
    if (opc >= 0x50 && opc <= 0x57) {
        in.dst.kind = OperandKind::REG;
        in.dst.reg = (opc - 0x50) + rex_b;
        in.dst.size = 64;
        return finish(X86Op::PUSH, "push");
    }
    if (opc >= 0x58 && opc <= 0x5F) {
        in.dst.kind = OperandKind::REG;
        in.dst.reg = (opc - 0x58) + rex_b;
        in.dst.size = 64;
        return finish(X86Op::POP, "pop");
    }

    // Group 1: 80/81/83 ALU r/m, imm  (e.g. 48 83 E4 F0 = and rsp, -16)
    if ((opc == 0x80 || opc == 0x81 || opc == 0x83) && i < len) {
        uint8_t modrm = data[i++];
        int reg = modrmReg(modrm); // opcode extension
        int rm = modrmRm(modrm) + rex_b;
        int mod = modrmMod(modrm);
        static const X86Op grp[] = {
            X86Op::ADD, X86Op::OR, X86Op::ADC, X86Op::SBB,
            X86Op::AND, X86Op::SUB, X86Op::XOR, X86Op::CMP
        };
        X86Op op = grp[reg & 7];
        const bool byteOp = (opc == 0x80);
        const int bsz = byteOp ? 8 : opsize;
        in.dst.kind = (mod == 3) ? OperandKind::REG : OperandKind::MEM;
        if (mod == 3) {
            in.dst.reg = rm;
            in.dst.size = bsz;
            if (byteOp) applyByteReg(in.dst, rex);
        } else {
            in.dst.size = bsz;
            in.dst.mem.base = rm;
            if (mod == 0 && (rm & 7) == 5) { in.dst.mem.rip_relative = true; in.dst.mem.base = -1; }
            if ((rm & 7) == 4 && i < len) {
                uint8_t sib = data[i++];
                in.dst.mem.base = (sib & 7) + rex_b;
                int idx = (sib >> 3) & 7;
                in.dst.mem.index = (idx == 4 && !rex_x) ? -1 : idx + rex_x;
                in.dst.mem.scale = 1 << (sib >> 6);
                if ((sib & 7) == 5 && mod == 0) in.dst.mem.base = -1;
            }
            int disp = (mod == 1) ? 1 : (mod == 2 || in.dst.mem.rip_relative || (in.dst.mem.base < 0 && !in.dst.mem.rip_relative)) ? 4 : 0;
            if (disp && i + disp <= len) {
                int64_t d = 0;
                for (int k = 0; k < disp; ++k) d |= static_cast<int64_t>(data[i + k]) << (8 * k);
                if (disp == 1 && (d & 0x80)) d |= ~0xFFLL;
                if (disp == 4 && (d & 0x80000000LL)) d |= ~0xFFFFFFFFLL;
                in.dst.mem.disp = d;
                i += disp;
            }
        }
        int imm_n = (opc == 0x81) ? (in.o16 ? 2 : 4) : 1; // 81 = Iz, 80/83 = Ib (sign-extend)
        if (opc == 0x81) imm_n = 4;
        if (i + imm_n > len) return std::nullopt;
        int64_t imm = 0;
        for (int k = 0; k < imm_n; ++k) imm |= static_cast<int64_t>(data[i + k]) << (8 * k);
        if (imm_n == 1 && (imm & 0x80)) imm |= ~0xFFLL;
        if (imm_n == 4 && (imm & 0x80000000LL)) imm |= ~0xFFFFFFFFLL;
        i += imm_n;
        in.src.kind = OperandKind::IMM;
        in.src.imm = imm;
        in.src.size = bsz;
        const char* names[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
        return finish(op, names[reg & 7]);
    }

    // C6/C7 /0 MOV r/m, imm  (e.g. 48 C7 C7 imm32 = mov rdi, imm)
    if ((opc == 0xC6 || opc == 0xC7) && i < len) {
        uint8_t modrm = data[i++];
        int reg = modrmReg(modrm);
        // C7 F8 cd — XBEGIN (start a transaction), C6 F8 ib — XABORT. NINE has
        // no transactional-memory model, so a transaction is started and the
        // fallback path is taken immediately (the interpreter reports this by
        // leaving ZF clear and jumping to the fallback target).
        if (modrm == 0xF8) {
            if (opc == 0xC6) {
                if (i >= len) return std::nullopt;
                in.src.kind = OperandKind::IMM;
                in.src.size = 8;
                in.src.imm = data[i++];
                return finish(X86Op::XABORT, "xabort");
            }
            if (i + 4 > len) return std::nullopt;
            int64_t rel = 0;
            for (int k = 0; k < 4; ++k) rel |= static_cast<int64_t>(data[i + k]) << (8 * k);
            if (rel & 0x80000000LL) rel |= ~0xFFFFFFFFLL;
            i += 4;
            in.dst.kind = OperandKind::REL;
            in.dst.imm = static_cast<int64_t>(addr + i) + rel;
            return finish(X86Op::XBEGIN, "xbegin");
        }
        if (reg != 0) {
            // other extensions unimplemented
            in.op = X86Op::INVALID;
            in.length = static_cast<uint8_t>(i);
            in.mnemonic = "grpC6";
            return in;
        }
        int rm = modrmRm(modrm) + rex_b;
        int mod = modrmMod(modrm);
        in.dst.kind = (mod == 3) ? OperandKind::REG : OperandKind::MEM;
        if (mod == 3) {
            in.dst.reg = rm;
            in.dst.size = (opc == 0xC6) ? 8 : (in.o16 ? 16 : opsize);
            if (opc == 0xC6) applyByteReg(in.dst, rex);
        } else {
            in.dst.size = (opc == 0xC6) ? 8 : (in.o16 ? 16 : opsize);
            in.dst.mem.base = rm;
            if (mod == 0 && (rm & 7) == 5) { in.dst.mem.rip_relative = true; in.dst.mem.base = -1; }
            if ((rm & 7) == 4 && i < len) {
                uint8_t sib = data[i++];
                in.dst.mem.base = (sib & 7) + rex_b;
                int idx = (sib >> 3) & 7;
                in.dst.mem.index = (idx == 4 && !rex_x) ? -1 : idx + rex_x;
                in.dst.mem.scale = 1 << (sib >> 6);
                if ((sib & 7) == 5 && mod == 0) in.dst.mem.base = -1;
            }
            int disp = (mod == 1) ? 1 : (mod == 2 || in.dst.mem.rip_relative || (in.dst.mem.base < 0 && !in.dst.mem.rip_relative)) ? 4 : 0;
            if (disp && i + disp <= len) {
                int64_t d = 0;
                for (int k = 0; k < disp; ++k) d |= static_cast<int64_t>(data[i + k]) << (8 * k);
                if (disp == 1 && (d & 0x80)) d |= ~0xFFLL;
                if (disp == 4 && (d & 0x80000000LL)) d |= ~0xFFFFFFFFLL;
                in.dst.mem.disp = d;
                i += disp;
            }
        }
        int imm_n = (opc == 0xC6) ? 1 : (in.o16 ? 2 : 4);
        if (i + imm_n > len) return std::nullopt;
        int64_t imm = 0;
        for (int k = 0; k < imm_n; ++k) imm |= static_cast<int64_t>(data[i + k]) << (8 * k);
        if (imm_n == 1 && (imm & 0x80)) imm |= ~0xFFLL;
        if (imm_n == 4 && (imm & 0x80000000LL)) imm |= ~0xFFFFFFFFLL;
        i += imm_n;
        in.src.kind = OperandKind::IMM;
        in.src.imm = imm;
        return finish(X86Op::MOV, "mov");
    }

    // MOV r8, imm8 (B0+rb). Encoding numbers 4-7 select AH/CH/DH/BH when the
    // instruction carries no REX prefix.
    if (opc >= 0xB0 && opc <= 0xB7) {
        if (i + 1 > len) return std::nullopt;
        in.dst.kind = OperandKind::REG;
        in.dst.reg = (opc - 0xB0) + rex_b;
        in.dst.size = 8;
        applyByteReg(in.dst, rex);
        in.src.kind = OperandKind::IMM;
        in.src.size = 8;
        in.src.imm = data[i++];
        return finish(X86Op::MOV, "mov");
    }

    // MOV r/m, imm  (C7 /0) and MOV r, imm (B8+rd)
    if (opc >= 0xB8 && opc <= 0xBF) {
        in.dst.kind = OperandKind::REG;
        in.dst.reg = (opc - 0xB8) + rex_b;
        in.dst.size = opsize;
        int n = in.rex_w ? 8 : (in.o16 ? 2 : 4);
        if (i + n > len) return std::nullopt;
        int64_t imm = 0;
        for (int k = 0; k < n; ++k) imm |= static_cast<int64_t>(data[i + k]) << (8 * k);
        i += n;
        in.src.kind = OperandKind::IMM;
        in.src.imm = imm;
        return finish(X86Op::MOV, "mov");
    }

    // Short JMP / Jcc
    if (opc == 0xEB || opc == 0xE9) {
        int n = (opc == 0xEB) ? 1 : 4;
        if (i + n > len) return std::nullopt;
        int64_t rel = 0;
        for (int k = 0; k < n; ++k) rel |= static_cast<int64_t>(data[i + k]) << (8 * k);
        if (n == 1 && (rel & 0x80)) rel |= ~0xFFLL;
        if (n == 4 && (rel & 0x80000000)) rel |= ~0xFFFFFFFFLL;
        i += n;
        in.dst.kind = OperandKind::REL;
        in.dst.imm = static_cast<int64_t>(addr + i) + rel;
        return finish(X86Op::JMP, "jmp");
    }
    if (opc == 0xE8) {
        if (i + 4 > len) return std::nullopt;
        int32_t rel = 0;
        for (int k = 0; k < 4; ++k) rel |= static_cast<int32_t>(data[i + k]) << (8 * k);
        i += 4;
        in.dst.kind = OperandKind::REL;
        in.dst.imm = static_cast<int64_t>(addr + i) + rel;
        return finish(X86Op::CALL, "call");
    }
    // Jcc rel8 (70-7F)
    if (opc >= 0x70 && opc <= 0x7F) {
        if (i >= len) return std::nullopt;
        int8_t rel = static_cast<int8_t>(data[i++]);
        in.dst.kind = OperandKind::REL;
        in.dst.imm = static_cast<int64_t>(addr + i) + rel;
        static const X86Op cc[] = {
            X86Op::JO, X86Op::JNO, X86Op::JB, X86Op::JAE, X86Op::JE, X86Op::JNE, X86Op::JBE, X86Op::JA,
            X86Op::JS, X86Op::JNS, X86Op::INVALID, X86Op::INVALID, X86Op::JL, X86Op::JGE, X86Op::JLE, X86Op::JG
        };
        return finish(cc[opc - 0x70], "jcc");
    }

    // ALU eAX, imm  (04/05, 0C/0D, 14/15, 24/25, 2C/2D, 34/35, 3C/3D)
    // e.g. `25 imm32` = and eax, imm32 (alignment-scan mileage in glibc init)
    if (opc <= 0x3D && ((opc & 7) == 4 || (opc & 7) == 5)) {
        int ext = (opc >> 3) & 7; // 0=ADD 1=OR 2=ADC 3=SBB 4=AND 5=SUB 6=XOR 7=CMP
        static const X86Op alu_ext[] = {
            X86Op::ADD, X86Op::OR, X86Op::ADC, X86Op::SBB,
            X86Op::AND, X86Op::SUB, X86Op::XOR, X86Op::CMP
        };
        in.dst.kind = OperandKind::REG;
        in.dst.reg = 0;
        in.dst.size = (opc & 1) ? opsize : 8;
        int n = (opc & 1) ? (in.o16 ? 2 : 4) : 1;
        if (i + n > len) return std::nullopt;
        int64_t imm = 0;
        for (int k = 0; k < n; ++k) imm |= static_cast<int64_t>(data[i + k]) << (8 * k);
        if (n == 1 && (imm & 0x80)) imm |= ~0xFFLL;
        if (n == 2 && (imm & 0x8000)) imm |= ~0xFFFFLL;
        if (n == 4 && (imm & 0x80000000LL)) imm |= ~0xFFFFFFFFLL;
        i += n;
        in.src.kind = OperandKind::IMM;
        in.src.imm = imm;
        in.src.size = in.dst.size;
        const char* names[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
        return finish(alu_ext[ext], names[ext]);
    }

    // XCHG r/m, r (87); XCHG r/m8, r8 (86); POP r/m (8F /0)
    if (opc == 0x86 || opc == 0x87) {
        uint8_t modrm = data[i++];
        Operand regop;
        regop.kind = OperandKind::REG;
        regop.reg = modrmReg(modrm) + rex_r;
        regop.size = (opc == 0x86) ? 8 : opsize;
        Operand rmop;
        rmop.size = regop.size;
        parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
        if (opc == 0x86) { applyByteReg(regop, rex); applyByteReg(rmop, rex); }
        in.dst = rmop;
        in.src = regop;
        return finish(X86Op::XCHG, "xchg");
    }
    // XOP prefix (8F), which is how AMD encodes TBM. The escape is
    // distinguished from POP by map_select >= 8 in the second byte:
    //   8F RXB.mmmmm W.vvvv.L.pp  (mmmmm = 8: 0F, 9: 0F38, 10: 0F3A)
    // Only the two TBM mask builders are modelled; every other XOP map is a
    // legacy (pre-XOP) encoding, so the POP path below still has to run for
    // map_select < 8.
    if (opc == 0x8F && !g_compat32 && i + 2 < len && (data[i] & 0x1F) >= 8) {
        const uint8_t b1 = data[i];
        const uint8_t b2 = data[i + 1];
        const uint8_t xmap = b1 & 0x1F;
        const bool xw = (b2 & 0x80) != 0;
        const uint8_t xpp = b2 & 0x03;
        const int xb = (b1 & 0x20) ? 0 : 8;
        const int xx = (b1 & 0x40) ? 0 : 8;
        const int xr = (b1 & 0x80) ? 0 : 8;
        i += 2;
        const uint8_t xopc = data[i++];
        if (xmap == 9 && xopc == 0x01 && xpp == 0 && i < len) {
            uint8_t modrm = data[i++];
            const int ext = modrmReg(modrm) & 7;
            if (ext == 4 || ext == 7) {
                const int bits = xw ? 64 : 32;
                // TBM is a non-destructive two-operand form: the ModRM.reg
                // digit selects the operation (/4 TZMSK, /7 T1MSKC), so the
                // destination is the XOP.vvvv field, exactly like BLSI/BLSR.
                in.dst.kind = OperandKind::REG;
                in.dst.reg = in.vex_v;
                in.dst.size = bits;
                Operand src;
                src.size = bits;
                parseRm(data, len, i, modrm, xb, xx, src);
                in.src = src;
                in.cc = (ext == 7) ? 0 : 1;
                return finish(X86Op::TBM, ext == 7 ? "t1mskc" : "tzmsk");
            }
        }
        // Any other XOP form: consume it exactly and report it as unsupported.
        if (i < len) {
            uint8_t modrm = data[i++];
            Operand ignored;
            parseRmRest(data, len, i, modrm, xb, xx, ignored);
            if (xmap == 10 && i < len) ++i;   // 0F3A forms carry imm8
        }
        in.op = X86Op::VEX_OP;
        in.length = static_cast<uint8_t>(i);
        in.mnemonic = "xop";
        return in;
    }
    if (opc == 0x8F && i < len) {
        uint8_t modrm = data[i++];
        if ((modrm >> 3) != 0) { in.op = X86Op::INVALID; in.length = (uint8_t)2; in.mnemonic = "grp8F"; return in; }
        Operand rmop;
        rmop.size = in.o16 ? 16 : (in.rex_w ? 64 : 32);
        parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
        in.dst = rmop;
        return finish(X86Op::POP, "pop");
    }
    if (opc == 0x87 && i < len) {
        uint8_t modrm = data[i++];
        Operand regop;
        regop.kind = OperandKind::REG;
        regop.reg = modrmReg(modrm) + rex_r;
        regop.size = opsize;
        Operand rmop;
        parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
        rmop.size = opsize;
        in.dst = rmop;
        in.src = regop;
        return finish(X86Op::XCHG, "xchg");
    }

    // IMUL r, r/m, imm (69 / 6B)
    if ((opc == 0x69 || opc == 0x6B) && i < len) {
        uint8_t modrm = data[i++];
        in.dst.kind = OperandKind::REG;
        in.dst.reg = modrmReg(modrm) + rex_r;
        in.dst.size = opsize;
        int rm = modrmRm(modrm) + rex_b;
        int mod = modrmMod(modrm);
        if (mod == 3) {
            in.src.kind = OperandKind::REG;
            in.src.reg = rm;
            in.src.size = opsize;
        } else {
            in.src.kind = OperandKind::MEM;
            in.src.size = opsize;
            parseRmRest(data, len, i, modrm, rex_b, rex_x, in.src);
        }
        int n = (opc == 0x6B) ? 1 : (in.o16 ? 2 : 4);
        if (i + n > len) return std::nullopt;
        int64_t imm = 0;
        for (int k = 0; k < n; ++k) imm |= static_cast<int64_t>(data[i + k]) << (8 * k);
        if (n == 1 && (imm & 0x80)) imm |= ~0xFFLL;
        if (n == 2 && (imm & 0x8000)) imm |= ~0xFFFFLL;
        if (n == 4 && (imm & 0x80000000LL)) imm |= ~0xFFFFFFFFLL;
        i += n;
        in.src2.kind = OperandKind::IMM;
        in.src2.imm = imm;
        in.src2.size = opsize;
        return finish(X86Op::IMUL, "imul3");
    }

    // CBW (98) / CWDE (98) / CDQE (48 98) and CDQ (99) / CQO (48 99)
    // 98 widens AX→AL, EAX→AX or RAX→EAX; the source size follows the
    // *destination* width, so 66 selects CBW and REX.W selects CDQE.
    if (opc == 0x98) {
        in.dst.kind = OperandKind::REG;
        in.dst.reg = 0;
        in.src.kind = OperandKind::REG;
        in.src.reg = 0;
        if (in.rex_w) {
            in.dst.size = 64; in.src.size = 32;
            return finish(X86Op::CDQE, "cdqe");
        }
        if (in.o16) {
            in.dst.size = 16; in.src.size = 8;
            return finish(X86Op::CBW, "cbw");
        }
        in.dst.size = 32; in.src.size = 16;
        return finish(X86Op::CWDE, "cwde");
    }

    // Flag-control group (F8-FD). CLI/STI only clear/set the shadow IF:
    // the sandbox never delivers interrupts, so no #GP is modelled.
    if (opc == 0xF8) return finish(X86Op::CLC, "clc");
    if (opc == 0xF9) return finish(X86Op::STC, "stc");
    if (opc == 0xFA) return finish(X86Op::CLI, "cli");
    if (opc == 0xFB) return finish(X86Op::STI, "sti");
    if (opc == 0xFC) return finish(X86Op::CLD, "cld");
    if (opc == 0xFD) return finish(X86Op::STD, "std");
    if (opc == 0xF5) return finish(X86Op::CMC, "cmc");

    // BOUND r16/32, m16&16/m32&32 — compat/legacy mode only (62 is EVEX in
    // long mode), hence the g_compat32 gate in the prefix stage above).
    if (opc == 0x62 && g_compat32 && i < len) {
        uint8_t modrm = data[i++];
        Operand rmop;
        rmop.size = opsize;
        parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
        in.dst.kind = OperandKind::REG;
        in.dst.reg = modrmReg(modrm) + rex_r;
        in.dst.size = opsize;
        in.src = rmop;
        return finish(X86Op::BOUND, "bound");
    }

    // ARPL r/m16, r16 — compat/legacy mode only (63 is MOVSXD in long mode).
    if (opc == 0x63 && g_compat32 && !in.rex_w && i < len) {
        uint8_t modrm = data[i++];
        Operand rmop;
        rmop.size = 16;
        parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
        in.dst = rmop;
        in.src.kind = OperandKind::REG;
        in.src.reg = modrmReg(modrm) + rex_r;
        in.src.size = 16;
        return finish(X86Op::ARPL, "arpl");
    }
    if (opc == 0x99) {
        in.dst.kind = OperandKind::REG;
        in.dst.reg = 2; // EDX/RDX = sign ext of EAX/RAX
        in.dst.size = opsize;
        in.src.kind = OperandKind::REG;
        in.src.reg = 0;
        in.src.size = opsize;
        // 99 = CDQ, 66 99 = CWD, REX.W 99 = CQO — same semantics, wider halves.
        return finish(X86Op::CDQ, in.rex_w ? "cqo" : (in.o16 ? "cwd" : "cdq"));
    }

    // ALU reg, r/m  and r/m, reg  (00-3B) and MOV (88/89/8A/8B)
    bool is_mov = (opc == 0x88 || opc == 0x89 || opc == 0x8A || opc == 0x8B);
    // ALU is 00-03,08-0B,...,38-3B only — must NOT match 0x0F (two-byte escape)
    bool is_alu = (opc <= 0x3B) && ((opc & 4) == 0);
    bool is_lea = (opc == 0x8D);
    bool is_movsxd = (opc == 0x63); // REX.W MOVSXD r64, r/m32
    if ((is_mov || is_alu || is_lea || is_movsxd) && i < len) {
        uint8_t modrm = data[i++];
        int reg = modrmReg(modrm) + rex_r;
        int rm = modrmRm(modrm) + rex_b;
        int mod = modrmMod(modrm);
        // 00/02/.../3A and 88/8A are the byte forms of the ALU and MOV
        // groups; their register operands follow the AH/CH/DH/BH rule.
        const bool byteOp = (is_alu || is_mov) && ((opc & 1) == 0);
        const int bsz = byteOp ? 8 : opsize;

        Operand regop;
        regop.kind = OperandKind::REG;
        regop.reg = reg;
        regop.size = bsz;
        if (byteOp) applyByteReg(regop, rex);

        Operand memop;
        if (mod == 3) {
            memop.kind = OperandKind::REG;
            memop.reg = rm;
            memop.size = bsz;
            if (byteOp) applyByteReg(memop, rex);
        } else {
            memop.kind = OperandKind::MEM;
            memop.size = bsz;
            memop.mem.base = rm;
            // RIP-relative: mod=0, rm=5 in 64-bit
            if (mod == 0 && (rm & 7) == 5) {
                memop.mem.rip_relative = true;
                memop.mem.base = -1;
            }
            // SIB
            if ((rm & 7) == 4 && mod != 3 && i < len) {
                uint8_t sib = data[i++];
                memop.mem.base = (sib & 7) + rex_b;
                int idx = (sib >> 3) & 7;
                memop.mem.index = (idx == 4 && !rex_x) ? -1 : idx + rex_x;
                memop.mem.scale = 1 << (sib >> 6);
                if ((sib & 7) == 5 && mod == 0) memop.mem.base = -1;
            }
            int disp = (mod == 1) ? 1 : (mod == 2 || memop.mem.rip_relative || (memop.mem.base < 0 && !memop.mem.rip_relative)) ? 4 : 0;
            if (disp && i + disp <= len) {
                int64_t d = 0;
                for (int k = 0; k < disp; ++k) d |= static_cast<int64_t>(data[i + k]) << (8 * k);
                if (disp == 1 && (d & 0x80)) d |= ~0xFFLL;
                if (disp == 4 && (d & 0x80000000)) d |= ~0xFFFFFFFFLL;
                memop.mem.disp = d;
                i += disp;
            }
        }

        bool reg_is_dst = (opc & 0x02) != 0 || is_lea;
        if (is_lea) { in.dst = regop; in.src = memop; return finish(X86Op::LEA, "lea"); }
        if (is_movsxd) {
            // Source is 32-bit, dest is 64-bit sign-extended
            memop.size = 32;
            regop.size = 64;
            in.dst = regop;
            in.src = memop;
            return finish(X86Op::MOVSX, "movsxd");
        }
        if (is_mov) {
            if (reg_is_dst) { in.dst = regop; in.src = memop; }
            else { in.dst = memop; in.src = regop; }
            return finish(X86Op::MOV, "mov");
        }
        X86Op alu = mapAlu(opc);
        if (reg_is_dst) { in.dst = regop; in.src = memop; }
        else { in.dst = memop; in.src = regop; }
        return finish(alu, "alu");
    }


    // Shift/rotate groups: C0/C1 ib, D0/D1/D2/D3
    if (opc == 0xC0 || opc == 0xC1 || opc == 0xD0 || opc == 0xD1 || opc == 0xD2 || opc == 0xD3) {
        if (i >= len) return std::nullopt;
        uint8_t modrm = data[i++];
        int reg = modrmReg(modrm);
        static const X86Op sht[] = {X86Op::ROL, X86Op::ROR, X86Op::RCL, X86Op::RCR,
                                    X86Op::SHL, X86Op::SHR, X86Op::INVALID, X86Op::SAR};
        X86Op op = (reg < 8) ? sht[reg] : X86Op::INVALID;
        Operand rmop;
        rmop.size = (opc & 1) ? opsize : 8;
        parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
        if (rmop.size == 8) applyByteReg(rmop, rex);
        in.dst = rmop;
        if (opc == 0xC0 || opc == 0xC1) {
            if (i >= len) return std::nullopt;
            in.src.kind = OperandKind::IMM;
            in.src.imm = data[i++];
        } else if (opc == 0xD0 || opc == 0xD1) {
            in.src.kind = OperandKind::IMM;
            in.src.imm = 1;
        } else {
            in.src.kind = OperandKind::REG;
            in.src.reg = 1; // CL
        }
        const char* m = op == X86Op::SHL ? "shl" : op == X86Op::SHR ? "shr" :
                        op == X86Op::SAR ? "sar" : op == X86Op::ROL ? "rol" :
                        op == X86Op::RCL ? "rcl" : op == X86Op::RCR ? "rcr" : "ror";
        return finish(op, m);
    }

    // FE/FF INC/DEC/CALL/JMP/PUSH
    if (opc == 0xFF || opc == 0xFE) {
        if (i >= len) return std::nullopt;
        uint8_t modrm = data[i++];
        int reg = modrmReg(modrm);
        Operand rmop;
        rmop.size = opc == 0xFE ? 8 : opsize;
        parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
        if (opc == 0xFE) applyByteReg(rmop, rex);
        in.dst = rmop;
        if (reg == 0) return finish(X86Op::INC, "inc");
        if (reg == 1) return finish(X86Op::DEC, "dec");
        if (reg == 2 || reg == 3) return finish(X86Op::CALL, "call");
        if (reg == 4 || reg == 5) return finish(X86Op::JMP, "jmp");
        if (reg == 6) return finish(X86Op::PUSH, "push");
    }

    // F6/F7 TEST/NOT/NEG/MUL/IMUL/DIV/IDIV (group 3)
    if (opc == 0xF6 || opc == 0xF7) {
        if (i >= len) return std::nullopt;
        uint8_t modrm = data[i++];
        int reg = modrmReg(modrm);
        static const X86Op grp[] = {X86Op::TEST, X86Op::TEST, X86Op::NOT, X86Op::NEG,
                                    X86Op::MUL, X86Op::IMUL, X86Op::DIV, X86Op::IDIV};
        parseRm(data, len, i, modrm, rex_b, rex_x, in.dst);
        in.dst.size = opc == 0xF6 ? 8 : opsize;
        if (opc == 0xF6) applyByteReg(in.dst, rex);
        if ((reg & 7) == 0 || (reg & 7) == 1) { // TEST r/m, imm (Ib for F6, Iz for F7)
            int imm_n = (opc == 0xF6) ? 1 : 4;
            if (i + imm_n > len) return std::nullopt;
            int64_t imm = 0;
            for (int k = 0; k < imm_n; ++k) imm |= static_cast<int64_t>(data[i + k]) << (8 * k);
            if (imm_n == 1 && (imm & 0x80)) imm |= ~0xFFLL;
            if (imm_n == 4 && (imm & 0x80000000LL)) imm |= ~0xFFFFFFFFLL;
            i += imm_n;
            in.src.kind = OperandKind::IMM;
            in.src.imm = imm;
            in.src.size = in.dst.size;
        }
        return finish(grp[reg & 7], "grp3");
    }

    // 0F 4x CMOV, 0F 9x SETCC
    if (opc == 0x0F && i < len) {
        uint8_t sec = data[i++];

        // ---- §2.18: table-driven packed-integer / SSE4.2 families ---------
        {
            const int pp = in.o16 ? 1 : in.rep ? 2 : in.repne ? 3 : 0;
            int map = 1;
            uint8_t op3 = sec;
            if (sec == 0x38 || sec == 0x3A) {
                if (i >= len) return std::nullopt;
                op3 = data[i];
                map = (sec == 0x38) ? 2 : 3;
            }
            PackedEntry e;
            if (packedLookup(map, op3, pp, in.rex_w, e)) {
                if (map != 1) ++i;              // consume the third opcode byte
                if (i >= len) return std::nullopt;
                const uint8_t modrm = data[i++];
                const int reg = modrmReg(modrm) + rex_r;
                if (e.flags & PF_GPR_REG) {
                    // PMOVMSKB: the GPR is ModRM.reg, the XMM source is r/m.
                    in.dst.kind = OperandKind::REG;
                    in.dst.reg = reg;
                    in.dst.size = e.dstw ? e.dstw : e.ew;
                    Operand sse;
                    sse.size = e.ew;
                    parseSseRm(data, len, i, modrm, rex_b, rex_x, sse);
                    in.src = sse;
                } else if (e.flags & PF_DST_GPR) {
                    Operand rm;
                    rm.size = e.dstw ? e.dstw : e.ew;
                    parseRm(data, len, i, modrm, rex_b, rex_x, rm);
                    in.dst = rm;
                    in.src.kind = OperandKind::REG;
                    in.src.reg = 16 + reg;
                    in.src.size = 128;
                } else if (e.flags & PF_SRC_GPR) {
                    in.dst.kind = OperandKind::REG;
                    in.dst.reg = 16 + reg;
                    in.dst.size = e.ew;
                    Operand rm;
                    rm.size = e.ew;
                    parseRm(data, len, i, modrm, rex_b, rex_x, rm);
                    in.src = rm;
                } else {
                    in.dst.kind = OperandKind::REG;
                    in.dst.reg = 16 + reg;
                    in.dst.size = (e.op == X86Op::PMOVX && e.dstw) ? e.dstw : e.ew;
                    Operand sse;
                    sse.size = 128;
                    parseSseRm(data, len, i, modrm, rex_b, rex_x, sse);
                    in.src = sse;
                    // PMOVSX/PMOVZX read a narrower operand than the destination.
                    if (e.op == X86Op::PMOVX) in.src.size = e.ew;
                }
                if (e.flags & PF_IMM8) {
                    if (i >= len) return std::nullopt;
                    in.src2.kind = OperandKind::IMM;
                    in.src2.size = 8;
                    in.src2.imm = data[i++];
                }
                in.cc = e.cc;
                return finish(e.op, e.mn);
            }
        }

        // ------------------------------------------------------------------
        // §2.20 — the rest of the scalar / system core.
        // ------------------------------------------------------------------

        // 31 — RDTSC: EDX:EAX = time-stamp counter.
        if (sec == 0x31) return finish(X86Op::RDTSC, "rdtsc");

        // 30 — WRMSR: CPL-0 only, so a CPL-3 guest takes #GP(0) (the
        // interpreter raises it; the operand shape is implicit in ECX).
        if (sec == 0x30) return finish(X86Op::WRMSR, "wrmsr");

        // 07 / 34 / 35 — SYSRET, SYSENTER, SYSEXIT. Each performs a
        // privilege-level transition to ring 0, which a CPL-3 guest may not
        // do: #GP(0).
        if (sec == 0x07) return finish(X86Op::SYSRET, in.rex_w ? "sysretq" : "sysretl");
        if (sec == 0x34) return finish(X86Op::SYSENTER, "sysenter");
        if (sec == 0x35) return finish(X86Op::SYSEXIT, in.rex_w ? "sysexitq" : "sysexitl");

        // 09 — WBINVD, and F3 09 — WBNOINVD. Both are CPL-0 cache control.
        if (sec == 0x09) {
            return finish(in.rep ? X86Op::WBNOINVD : X86Op::WBINVD,
                          in.rep ? "wbnoinvd" : "wbinvd");
        }

        // AA — RSM: resume from SMM. #UD outside system-management mode.
        if (sec == 0xAA) return finish(X86Op::RSM, "rsm");

        // B9 / FF — UD1 / UD0: deliberately undefined encodings.
        if (sec == 0xB9) return finish(X86Op::UD, "ud1");
        if (sec == 0xFF) return finish(X86Op::UD, "ud0");

        // 2E — UCOMISS (NP) / UCOMISD (66). Only ZF/PF/CF are written.
        if (sec == 0x2E && i < len) {
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = in.o16 ? 64 : 32;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            return finish(in.o16 ? X86Op::UCOMISD : X86Op::UCOMISS,
                          in.o16 ? "ucomisd" : "ucomiss");
        }

        // 51 — SQRTPS (NP) / SQRTPD (66) / SQRTSS (F3) / SQRTSD (F2).
        if (sec == 0x51 && i < len) {
            uint8_t modrm = data[i++];
            const bool scalar = in.rep || in.repne;
            const bool dbl = in.repne || in.o16;
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = scalar ? (dbl ? 64 : 32) : 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            return finish(scalar ? (dbl ? X86Op::SQRTSD : X86Op::SQRTSS)
                                 : (dbl ? X86Op::SQRTPD : X86Op::SQRTPS),
                          scalar ? (dbl ? "sqrtsd" : "sqrtss")
                                 : (dbl ? "sqrtpd" : "sqrtps"));
        }

        // 5C — SUBPS (NP) / SUBPD (66) / SUBSS (F3) / SUBSD (F2).
        if (sec == 0x5C && i < len) {
            uint8_t modrm = data[i++];
            const bool scalar = in.rep || in.repne;
            const bool dbl = in.repne || in.o16;
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = scalar ? (dbl ? 64 : 32) : 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            return finish(scalar ? (dbl ? X86Op::SUBSD : X86Op::SUBSS)
                                 : (dbl ? X86Op::SUBPD : X86Op::SUBPS),
                          scalar ? (dbl ? "subsd" : "subss")
                                 : (dbl ? "subpd" : "subps"));
        }

        // 14/15 — UNPCKLPS/PD and UNPCKHPS/PD. cc 0 = low, 1 = high; the 66
        // prefix selects the double-precision pair.
        if ((sec == 0x14 || sec == 0x15) && i < len) {
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            // Element width doubles as the PS/PD selector for UNPCKF.
            xmm.size = in.o16 ? 64 : 32;
            Operand src;
            src.size = 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            in.cc = (sec == 0x15) ? 1 : 0;
            return finish(X86Op::UNPCKF, sec == 0x15 ? (in.o16 ? "unpckhpd" : "unpckhps")
                                                    : (in.o16 ? "unpcklpd" : "unpcklps"));
        }

        // 66 0F 71/72/73 — packed shift by imm8 (group 13).
        if (in.o16 && (sec == 0x71 || sec == 0x72 || sec == 0x73) && i < len) {
            const uint8_t modrm = data[i++];
            if (modrmMod(modrm) != 3) return std::nullopt;
            const int ext = modrmReg(modrm);
            in.dst.kind = OperandKind::REG;
            in.dst.reg = 16 + (modrmRm(modrm) + rex_b);
            in.dst.size = (sec == 0x71) ? 16 : (sec == 0x72) ? 32 : 64;
            if (i >= len) return std::nullopt;
            in.src2.kind = OperandKind::IMM;
            in.src2.size = 8;
            in.src2.imm = data[i++];
            if (sec == 0x73 && (ext == 3 || ext == 7)) {
                in.cc = (ext == 7) ? 0 : 1;
                return finish(X86Op::PSHIFTDQ, ext == 7 ? "pslldq" : "psrldq");
            }
            const int cc = (ext == 6) ? 0 : (ext == 2) ? 1 : (ext == 4) ? 2 : -1;
            if (cc < 0) return std::nullopt;
            in.cc = cc;
            const char* mn = (sec == 0x71)
                ? (cc == 0 ? "psllw" : cc == 1 ? "psrlw" : "psraw")
                : (sec == 0x72)
                ? (cc == 0 ? "pslld" : cc == 1 ? "psrld" : "psrad")
                : (cc == 0 ? "psllq" : "psrlq");
            return finish(X86Op::PSHIFT, mn);
        }

        // 0F 18 /0-/3 — PREFETCHNTA/PREFETCHT0/T1/T2. Cache hints do not
        // change architectural state (and never fault), so they are no-ops.
        if (sec == 0x18 && i < len) {
            const uint8_t modrm = data[i++];
            if (modrmMod(modrm) == 3) return std::nullopt;
            Operand m;
            m.size = 8;
            parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
            in.src = m;
            return finish(X86Op::PREFETCH, "prefetch");
        }

        // 0F 0D /0,/1 — PREFETCH / PREFETCHW (AMD); both are hints.
        if (sec == 0x0D && i < len) {
            const uint8_t modrm = data[i++];
            if (modrmMod(modrm) == 3) return std::nullopt;
            Operand m;
            m.size = 8;
            parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
            in.src = m;
            return finish(X86Op::PREFETCH, modrmReg(modrm) == 1 ? "prefetchw" : "prefetch");
        }

        // F3 0F B8 — POPCNT r32/64, r/m
        if (sec == 0xB8 && in.rep && i < len) {
            const uint8_t modrm = data[i++];
            in.dst.kind = OperandKind::REG;
            in.dst.reg = modrmReg(modrm) + rex_r;
            in.dst.size = in.rex_w ? 64 : (in.o16 ? 16 : 32);
            Operand src;
            src.size = in.dst.size;
            parseRm(data, len, i, modrm, rex_b, rex_x, src);
            in.src = src;
            return finish(X86Op::POPCNT, "popcnt");
        }

        // 0F 32/33 — RDMSR/RDPMC are CPL-0 (or CR4.PCE); #GP(0) at CPL 3.
        if (sec == 0x32) return finish(X86Op::RDMSR, "rdmsr");
        if (sec == 0x33) return finish(X86Op::RDPMC, "rdpmc");

        // 06 — CLTS: privileged (CPL 0 only); the interpreter raises #GP(0).
        if (sec == 0x06) return finish(X86Op::CLTS, "clts");

        // 08 — INVD: flushes caches without writeback; privileged, so a CPL-3
        // guest takes #GP(0) (raised by the interpreter).
        if (sec == 0x08) return finish(X86Op::INVD, "invd");

        // 02 — LAR r32/r64, r/m16: load the access-rights dword of the segment
        // selector in the source. ZF=0 when the selector is unusable.
        if (sec == 0x02) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            in.dst.kind = OperandKind::REG;
            in.dst.reg = modrmReg(modrm) + rex_r;
            in.dst.size = in.rex_w ? 64 : (in.o16 ? 16 : 32);
            Operand src;
            src.size = 16;
            parseRm(data, len, i, modrm, rex_b, rex_x, src);
            in.src = src;
            return finish(X86Op::LAR, "lar");
        }

        // F2 0F F0 — LDDQU: unaligned 128-bit load (no alignment check, and no
        // cache-line-split penalty to model).
        if (sec == 0xF0 && in.repne) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            return finish(X86Op::LDDQU, "lddqu");
        }

        // ---- three-byte opcode maps (0F 38 / 0F 3A) ----
        if (sec == 0x38) {
            if (i >= len) return std::nullopt;
            uint8_t op3 = data[i++];

            // ---- §2.20: SHA-1 / SHA-256 and the CET cipher stores --------
            // C8-CD — SHA1NEXTE, SHA1MSG1, SHA1MSG2, SHA256RNDS2,
            // SHA256MSG1, SHA256MSG2. All are NP 0F 38 forms with an explicit
            // XMM operand; SHA256RNDS2 also reads XMM0 implicitly.
            if (op3 >= 0xC8 && op3 <= 0xCD && i < len) {
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = 128;
                Operand src;
                src.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                in.dst = xmm;
                in.src = src;
                int cc = 0;
                const char* mn = "sha1msg1";
                switch (op3) {
                    case 0xC8: cc = 2; mn = "sha1nexte"; break;
                    case 0xC9: cc = 0; mn = "sha1msg1"; break;
                    case 0xCA: cc = 1; mn = "sha1msg2"; break;
                    case 0xCB: cc = 6; mn = "sha256rnds2"; break;
                    case 0xCC: cc = 4; mn = "sha256msg1"; break;
                    default:   cc = 5; mn = "sha256msg2"; break;
                }
                in.cc = static_cast<uint8_t>(cc);
                return finish(X86Op::SHA, mn);
            }

            // F5 (66) — WRUSSD/WRUSSQ, F6 (no prefix) — WRSSD/WRSSQ. The
            // committed cipher stores write the source GPR into memory. With
            // no shadow stack present they behave as ordinary stores, which
            // is exactly what the interpreter does.
            if (op3 == 0xF5 && in.o16 && i < len) {
                uint8_t modrm = data[i++];
                Operand m;
                m.size = in.rex_w ? 64 : 32;
                parseRm(data, len, i, modrm, rex_b, rex_x, m);
                in.dst = m;
                in.src.kind = OperandKind::REG;
                in.src.reg = modrmReg(modrm) + rex_r;
                in.src.size = in.rex_w ? 64 : 32;
                return finish(X86Op::WRUSS, in.rex_w ? "wrussq" : "wrussd");
            }
            if (op3 == 0xF6 && !in.o16 && !in.rep && i < len) {
                uint8_t modrm = data[i++];
                Operand m;
                m.size = in.rex_w ? 64 : 32;
                parseRm(data, len, i, modrm, rex_b, rex_x, m);
                in.dst = m;
                in.src.kind = OperandKind::REG;
                in.src.reg = modrmReg(modrm) + rex_r;
                in.src.size = in.rex_w ? 64 : 32;
                return finish(X86Op::WRSS, in.rex_w ? "wrssq" : "wrssd");
            }

            // 10 — PBLENDVB (66): byte blend selected by the implicit XMM0 mask.
            if (op3 == 0x10 && in.o16 && i < len) {
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = 128;
                Operand src;
                src.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                in.dst = xmm;
                in.src = src;
                return finish(X86Op::PBLENDVB, "pblendvb");
            }

            // 1C-1F — PABSB/W/D/Q (66): element width 8/16/32/64.
            if (op3 >= 0x1C && op3 <= 0x1F && in.o16 && i < len) {
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = (op3 == 0x1C) ? 8 : (op3 == 0x1D) ? 16 : (op3 == 0x1E) ? 32 : 64;
                Operand src;
                src.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                in.dst = xmm;
                in.src = src;
                return finish(X86Op::PABS, op3 == 0x1C ? "pabsb" : op3 == 0x1D ? "pabsw" :
                                          op3 == 0x1E ? "pabsd" : "pabsq");
            }

            // 2A — MOVNTDQA (66): aligned non-temporal load of 128 bits.
            if (op3 == 0x2A && in.o16 && i < len) {
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = 128;
                Operand src;
                src.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                in.dst = xmm;
                in.src = src;
                return finish(X86Op::MOVNTDQA, "movntdqa");
            }

            // 2B — PACKUSDW (66): dwords -> unsigned words, saturating.
            if (op3 == 0x2B && in.o16 && i < len) {
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = 32;
                Operand src;
                src.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                in.dst = xmm;
                in.src = src;
                return finish(X86Op::PACKUS, "packusdw");
            }

            // F0/F1 — MOVBE r, m / m, r: byte-swapping load and store.
            if ((op3 == 0xF0 || op3 == 0xF1) && !in.rep && !in.repne && i < len) {
                uint8_t modrm = data[i++];
                const int bits = in.rex_w ? 64 : (in.o16 ? 16 : 32);
                Operand m;
                m.size = bits;
                parseRm(data, len, i, modrm, rex_b, rex_x, m);
                if (op3 == 0xF0) {
                    in.dst.kind = OperandKind::REG;
                    in.dst.reg = modrmReg(modrm) + rex_r;
                    in.dst.size = bits;
                    in.src = m;
                } else {
                    in.dst = m;
                    in.src.kind = OperandKind::REG;
                    in.src.reg = modrmReg(modrm) + rex_r;
                    in.src.size = bits;
                }
                return finish(X86Op::MOVBE, op3 == 0xF0 ? "movbe" : "movbe_store");
            }

            // F8 — MOVDIR64B (66): 64-byte direct store to [reg] from [rm].
            if (op3 == 0xF8 && in.o16 && i < len) {
                uint8_t modrm = data[i++];
                in.dst.kind = OperandKind::REG;
                in.dst.reg = modrmReg(modrm) + rex_r;
                in.dst.size = 64;
                Operand src;
                src.size = 512;
                parseRmRest(data, len, i, modrm, rex_b, rex_x, src);
                in.src = src;
                return finish(X86Op::MOVDIR64B, "movdir64b");
            }

            // F9 — MOVDIRI: direct dword/qword store of a GPR.
            if (op3 == 0xF9 && !in.o16 && i < len) {
                uint8_t modrm = data[i++];
                const int bits = in.rex_w ? 64 : 32;
                Operand m;
                m.size = bits;
                parseRm(data, len, i, modrm, rex_b, rex_x, m);
                if (m.kind != OperandKind::MEM) return std::nullopt;
                in.dst = m;
                in.src.kind = OperandKind::REG;
                in.src.reg = modrmReg(modrm) + rex_r;
                in.src.size = bits;
                return finish(X86Op::MOVDIRI, "movdiri");
            }

            // DC with F3 — LOADIWKEY: install the internal wrapping key. The
            // SDM encodes it as F3 0F 38 DC 11:rrr:bbb and opens its operation
            // with `IF CPL > 0 THEN #GP(0)`, so a CPL-3 guest always faults.
            // Checked before the Key Locker AES forms that share this byte:
            // those take a memory key handle, so the register form (mod == 11)
            // can only be LOADIWKEY.
            if (op3 == 0xDC && in.rep && i < len && modrmMod(data[i]) == 3) {
                uint8_t modrm = data[i++];
                in.dst.kind = OperandKind::REG;
                in.dst.reg = 16 + (modrmReg(modrm) + rex_r);
                in.dst.size = 128;
                in.src.kind = OperandKind::REG;
                in.src.reg = 16 + (modrmRm(modrm) + rex_b);
                in.src.size = 128;
                return finish(X86Op::LOADIWKEY, "loadiwkey");
            }

            // F6 — ADCX (66) / ADOX (F3): r32/64 += r/m32/64 + CF/OF
            if (op3 == 0xF6) {
                if (!in.o16 && !in.rep) return std::nullopt;
                if (i >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                Operand regop;
                regop.kind = OperandKind::REG;
                regop.reg = modrmReg(modrm) + rex_r;
                regop.size = in.rex_w ? 64 : 32;
                Operand rmop;
                rmop.size = regop.size;
                parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
                in.dst = regop;
                in.src = rmop;
                return finish(in.o16 ? X86Op::ADCX : X86Op::ADOX,
                              in.o16 ? "adcx" : "adox");
            }

            // F0/F1 — CRC32 r32/r64, r/m8 | r/m16/32/64 (F2 mandatory,
            // 66 selects the 16-bit source, REX.W the 64-bit one).
            if ((op3 == 0xF0 || op3 == 0xF1) && in.repne) {
                if (i >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                Operand rmop;
                rmop.size = (op3 == 0xF0) ? 8 : (in.o16 ? 16 : (in.rex_w ? 64 : 32));
                parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
                in.dst.kind = OperandKind::REG;
                in.dst.reg = modrmReg(modrm) + rex_r;
                in.dst.size = in.rex_w ? 64 : 32;
                in.src = rmop;
                return finish(X86Op::CRC32, "crc32");
            }

            // 82 — INVPCID (66): privileged invalidation keyed by a 128-bit
            // descriptor in memory. A CPL-3 guest takes #GP(0).
            if (op3 == 0x82 && in.o16) {
                if (i >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                in.dst.kind = OperandKind::REG;
                in.dst.reg = modrmReg(modrm) + rex_r;
                in.dst.size = in.rex_w ? 64 : 32;
                Operand src;
                src.size = 128;
                parseRm(data, len, i, modrm, rex_b, rex_x, src);
                in.src = src;
                return finish(X86Op::INVPCID, "invpcid");
            }

            // CF — GF2P8MULB (66): byte-wise GF(2^8) multiply, AES polynomial.
            if (op3 == 0xCF && in.o16) {
                if (i >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = 128;
                Operand src;
                src.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                in.dst = xmm;
                in.src = src;
                return finish(X86Op::GF2P8MULB, "gf2p8mulb");
            }

            // F8 — ENQCMD (F2) / ENQCMDS (F3): enqueue a 64-byte work
            // descriptor. Both need CR4.ENQCMD, which NINE never sets, so the
            // interpreter raises #UD like hardware without the feature.
            if (op3 == 0xF8 && (in.rep || in.repne)) {
                if (i >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                in.dst.kind = OperandKind::REG;
                in.dst.reg = modrmReg(modrm) + rex_r;
                in.dst.size = 32;
                Operand src;
                src.size = 512;
                parseRm(data, len, i, modrm, rex_b, rex_x, src);
                in.src = src;
                return finish(in.rep ? X86Op::ENQCMDS : X86Op::ENQCMD,
                              in.rep ? "enqcmds" : "enqcmd");
            }

            // FA/FB — ENCODEKEY128 / ENCODEKEY256 (F3): Key Locker key
            // handoff; requires CR4.KL, so the guest sees #UD.
            if ((op3 == 0xFA || op3 == 0xFB) && in.rep) {
                if (i >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                in.dst.kind = OperandKind::REG;
                in.dst.reg = modrmReg(modrm) + rex_r;
                in.dst.size = 32;
                in.src.kind = OperandKind::REG;
                in.src.reg = modrmRm(modrm) + rex_b;
                in.src.size = 32;
                return finish(op3 == 0xFA ? X86Op::ENCODEKEY128 : X86Op::ENCODEKEY256,
                              op3 == 0xFA ? "encodekey128" : "encodekey256");
            }

            // 15/16 — BLENDVPD / BLENDVPS (66): mask is implicitly XMM0 and
            // the destination is also the first source (legacy SSE form).
            if ((op3 == 0x15 || op3 == 0x16) && in.o16) {
                if (i >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = 128;
                Operand src;
                src.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                in.dst = xmm;
                in.src = src;
                return finish(op3 == 0x15 ? X86Op::BLENDVPD : X86Op::BLENDVPS,
                              op3 == 0x15 ? "blendvpd" : "blendvps");
            }

            // DB — AESIMC (66).
            if (op3 == 0xDB && in.o16) {
                if (i >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = 128;
                Operand src;
                src.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                in.dst = xmm;
                in.src = src;
                return finish(X86Op::AESIMC, "aesimc");
            }

            // DC-DF — AESENC/AESENCLAST/AESDEC/AESDECLAST (66) and the Key
            // Locker single-block bulk forms (F3, memory key handle).
            if (op3 >= 0xDC && op3 <= 0xDF) {
                if (in.o16) {
                    if (i >= len) return std::nullopt;
                    uint8_t modrm = data[i++];
                    Operand xmm;
                    xmm.kind = OperandKind::REG;
                    xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                    xmm.size = 128;
                    Operand src;
                    src.size = 128;
                    parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                    if (src.kind == OperandKind::REG) src.size = 128;
                    in.dst = xmm;
                    in.src = src;
                    X86Op op = op3 == 0xDC ? X86Op::AESENC :
                               op3 == 0xDD ? X86Op::AESENCLAST :
                               op3 == 0xDE ? X86Op::AESDEC : X86Op::AESDECLAST;
                    const char* mn = op3 == 0xDC ? "aesenc" :
                                     op3 == 0xDD ? "aesenclast" :
                                     op3 == 0xDE ? "aesdec" : "aesdeclast";
                    return finish(op, mn);
                }
                if (in.rep) {
                    if (i >= len) return std::nullopt;
                    uint8_t modrm = data[i++];
                    if (modrmMod(modrm) == 3) return std::nullopt; // !(11):rrr:bbb
                    X86Op op = op3 == 0xDC ? X86Op::AESENC128KL :
                               op3 == 0xDD ? X86Op::AESDEC128KL :
                               op3 == 0xDE ? X86Op::AESENC256KL : X86Op::AESDEC256KL;
                    const char* mn = op3 == 0xDC ? "aesenc128kl" :
                                     op3 == 0xDD ? "aesdec128kl" :
                                     op3 == 0xDE ? "aesenc256kl" : "aesdec256kl";
                    Operand xmm;
                    xmm.kind = OperandKind::REG;
                    xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                    xmm.size = 128;
                    Operand handle;
                    handle.size = (op3 >= 0xDE) ? 512 : 384;
                    parseRmRest(data, len, i, modrm, rex_b, rex_x, handle);
                    in.dst = xmm;
                    in.src = handle;
                    return finish(op, mn);
                }
                return std::nullopt;
            }

            // D8-DB — Key Locker WIDE forms (F3, ModRM.reg == 000, XMM0-7).
            if (op3 >= 0xD8 && op3 <= 0xDB && in.rep) {
                if (i >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                if (modrmMod(modrm) == 3 || modrmReg(modrm) != 0) return std::nullopt;
                X86Op op = op3 == 0xD8 ? X86Op::AESENCWIDE128KL :
                           op3 == 0xD9 ? X86Op::AESDECWIDE128KL :
                           op3 == 0xDA ? X86Op::AESENCWIDE256KL : X86Op::AESDECWIDE256KL;
                const char* mn = op3 == 0xD8 ? "aesencwide128kl" :
                                 op3 == 0xD9 ? "aesdecwide128kl" :
                                 op3 == 0xDA ? "aesencwide256kl" : "aesdecwide256kl";
                Operand handle;
                handle.size = (op3 <= 0xD9) ? 384 : 512;
                parseRmRest(data, len, i, modrm, rex_b, rex_x, handle);
                in.src = handle;
                return finish(op, mn);
            }
            return std::nullopt; // other 0F 38 forms are not decoded yet
        }

        if (sec == 0x3A) {
            if (i >= len) return std::nullopt;
            uint8_t op3 = data[i++];

            // 08-0B — ROUNDPS/PD/SS/SD xmm1, xmm2/m128, imm8 (66 required).
            if (op3 >= 0x08 && op3 <= 0x0B && in.o16 && i + 1 < len) {
                uint8_t modrm = data[i++];
                const bool scalar = (op3 == 0x0A || op3 == 0x0B);
                const bool dbl = (op3 == 0x09 || op3 == 0x0B);
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = 128;
                Operand src;
                src.size = scalar ? (dbl ? 64 : 32) : 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                in.dst = xmm;
                in.src = src;
                in.src2.kind = OperandKind::IMM;
                in.src2.size = 8;
                in.src2.imm = data[i++];
                const X86Op op = op3 == 0x08 ? X86Op::ROUNDPS : op3 == 0x09 ? X86Op::ROUNDPD
                                 : op3 == 0x0A ? X86Op::ROUNDSS : X86Op::ROUNDSD;
                return finish(op, op3 == 0x08 ? "roundps" : op3 == 0x09 ? "roundpd"
                                    : op3 == 0x0A ? "roundss" : "roundsd");
            }

            // CC — SHA1RNDS4 xmm1, xmm2/m128, imm8: one SHA-1 round group,
            // with imm8[1:0] selecting the round constant set.
            if (op3 == 0xCC && i + 1 < len) {
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = 128;
                Operand src;
                src.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                in.dst = xmm;
                in.src = src;
                in.cc = 3;
                in.src2.kind = OperandKind::IMM;
                in.src2.size = 8;
                in.src2.imm = data[i++];
                return finish(X86Op::SHA, "sha1rnds4");
            }

            // 0F/0E/42/44 — PALIGNR, PBLENDW, MPSADBW and PCLMULQDQ all take
            // an xmm destination, an xmm/m128 source and an imm8 selector.
            if ((op3 == 0x0F || op3 == 0x0E || op3 == 0x42 || op3 == 0x44) &&
                in.o16 && i + 1 < len) {
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = (op3 == 0x0F || op3 == 0x42) ? 8 : (op3 == 0x0E) ? 16 : 64;
                Operand src;
                src.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                in.dst = xmm;
                in.src = src;
                in.src2.kind = OperandKind::IMM;
                in.src2.imm = data[i++];
                in.src2.size = 8;
                return finish(op3 == 0x0F ? X86Op::PALIGNR :
                              op3 == 0x0E ? X86Op::PBLENDW :
                              op3 == 0x42 ? X86Op::MPSADBW : X86Op::PCLMULQDQ,
                              op3 == 0x0F ? "palignr" :
                              op3 == 0x0E ? "pblendw" :
                              op3 == 0x42 ? "mpsadbw" : "pclmulqdq");
            }

            // 0C/0D — BLENDPS / BLENDPD (66 0F 3A 0C/0D /r ib): one mask bit
            // per element, 1 selects the source lane.
            if ((op3 == 0x0C || op3 == 0x0D) && in.o16) {
                if (i >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = 128;
                Operand src;
                src.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                if (i >= len) return std::nullopt;
                in.dst = xmm;
                in.src = src;
                in.src2.kind = OperandKind::IMM;
                in.src2.imm = data[i++];
                in.src2.size = 8;
                return finish(op3 == 0x0C ? X86Op::BLENDPS : X86Op::BLENDPD,
                              op3 == 0x0C ? "blendps" : "blendpd");
            }

            // DF — AESKEYGENASSIST (66 0F 3A DF /r ib)
            if (op3 == 0xDF && in.o16) {
                if (i >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = 128;
                Operand src;
                src.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                if (i >= len) return std::nullopt;
                in.src2.kind = OperandKind::IMM;
                in.src2.imm = data[i++];
                in.src2.size = 8;
                in.dst = xmm;
                in.src = src;
                return finish(X86Op::AESKEYGENASSIST, "aeskeygenassist");
            }
            // 21 — INSERTPS (66): copy one dword from the source into one lane
            // of the destination, with optional zeroing. imm8[7:6] picks the
            // source lane (0 for a memory operand), imm8[5:4] the destination
            // lane, and imm8[3:0] the lanes to zero.
            if (op3 == 0x21 && in.o16) {
                if (i + 1 >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = 128;
                Operand src;
                src.size = 32;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                in.dst = xmm;
                in.src = src;
                in.src2.kind = OperandKind::IMM;
                in.src2.imm = data[i++];
                in.src2.size = 8;
                return finish(X86Op::INSERTPS, "insertps");
            }

            // 17 — EXTRACTPS (66): r/m32 <- dword imm8[1:0] of the XMM source.
            if (op3 == 0x17 && in.o16) {
                if (i + 1 >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                Operand dst;
                dst.size = 32;
                parseRm(data, len, i, modrm, rex_b, rex_x, dst);
                in.dst = dst;
                in.src.kind = OperandKind::REG;
                in.src.reg = 16 + (modrmReg(modrm) + rex_r);
                in.src.size = 128;
                in.src2.kind = OperandKind::IMM;
                in.src2.imm = data[i++];
                in.src2.size = 8;
                return finish(X86Op::EXTRACTPS, "extractps");
            }

            // 40/41 — DPPS / DPPD (66): horizontal dot product with an imm8
            // mask selecting the source lanes that participate.
            if ((op3 == 0x40 || op3 == 0x41) && in.o16) {
                if (i + 1 >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = 128;
                Operand src;
                src.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                in.dst = xmm;
                in.src = src;
                in.src2.kind = OperandKind::IMM;
                in.src2.imm = data[i++];
                in.src2.size = 8;
                return finish(op3 == 0x40 ? X86Op::DPPS : X86Op::DPPD,
                              op3 == 0x40 ? "dpps" : "dppd");
            }

            // CE/CF — GF2P8AFFINEQB / GF2P8AFFINEINVQB (66): per-byte affine
            // transform; src2 carries the 8x8 bit matrix in imm8 and the
            // second source in the rm operand.
            if ((op3 == 0xCE || op3 == 0xCF) && in.o16) {
                if (i + 1 >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                Operand xmm;
                xmm.kind = OperandKind::REG;
                xmm.reg = 16 + (modrmReg(modrm) + rex_r);
                xmm.size = 128;
                Operand src;
                src.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                if (src.kind == OperandKind::REG) src.size = 128;
                in.dst = xmm;
                in.src = src;
                in.src2.kind = OperandKind::IMM;
                in.src2.imm = data[i++];
                in.src2.size = 8;
                return finish(op3 == 0xCE ? X86Op::GF2P8AFFINEQB : X86Op::GF2P8AFFINEINVQB,
                              op3 == 0xCE ? "gf2p8affineqb" : "gf2p8affineinvqb");
            }

            // F0 — HRESET (F3): system reset request; modrm is fixed at C0 and
            // imm8 is the request bitmap. Needs CR4.HRESET, so a CPL-3 guest
            // takes #GP(0) (raised by the interpreter).
            if (op3 == 0xF0 && in.rep) {
                if (i + 1 >= len) return std::nullopt;
                uint8_t modrm = data[i++];
                if (modrm != 0xC0) return std::nullopt;
                in.src.kind = OperandKind::IMM;
                in.src.imm = data[i++];
                in.src.size = 8;
                return finish(X86Op::HRESET, "hreset");
            }

            return std::nullopt; // other 0F 3A forms are not decoded yet
        }

        // 0F 58 — SSE/SSE2 packed & scalar floating-point add. The mandatory
        // prefix picks the form: none=ADDPS, 66=ADDPD, F3=ADDSS, F2=ADDSD.
        if (sec == 0x58) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            X86Op op;
            const char* mn;
            int scalar_bits = 0;
            if (in.repne) { op = X86Op::ADDSD; mn = "addsd"; scalar_bits = 64; }
            else if (in.rep) { op = X86Op::ADDSS; mn = "addss"; scalar_bits = 32; }
            else if (in.o16) { op = X86Op::ADDPD; mn = "addpd"; }
            else { op = X86Op::ADDPS; mn = "addps"; }
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = scalar_bits ? scalar_bits : 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            return finish(op, mn);
        }

        // 0F D0 — ADDSUBPD (66) / ADDSUBPS (F2): alternating add/sub lanes.
        if (sec == 0xD0) {
            if (!in.o16 && !in.repne) return std::nullopt;
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            return finish(in.repne ? X86Op::ADDSUBPS : X86Op::ADDSUBPD,
                          in.repne ? "addsubps" : "addsubpd");
        }

        // C2 — CMPPS/CMPPD/CMPSS/CMPSD: packed or scalar compare picked by the
        // mandatory prefix, predicate from imm8[2:0].
        if (sec == 0xC2) {
            if (i + 1 >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            X86Op op;
            const char* mn;
            if (in.repne)      { op = X86Op::CMPSD_SSE; mn = "cmpsd"; }
            else if (in.rep)   { op = X86Op::CMPSS; mn = "cmpss"; }
            else if (in.o16)   { op = X86Op::CMPPD; mn = "cmppd"; }
            else               { op = X86Op::CMPPS; mn = "cmpps"; }
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            in.src2.kind = OperandKind::IMM;
            in.src2.imm = data[i++];
            in.src2.size = 8;
            return finish(op, mn);
        }

        // 2F — COMISS (NP) / COMISD (66): ordered scalar compare into ZF/PF/CF.
        if (sec == 0x2F) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = in.o16 ? 64 : 32;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = in.o16 ? 64 : 32;
            in.dst = xmm;
            in.src = src;
            return finish(in.o16 ? X86Op::COMISD : X86Op::COMISS,
                          in.o16 ? "comisd" : "comiss");
        }

        // ---- SSE/SSE2 conversions ----
        // 5A — CVTPS2PD (NP), CVTSS2SD (F3), CVTSD2SS (F2); 66 is CVTPD2PS.
        if (sec == 0x5A) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            X86Op op;
            const char* mn;
            int src_bits;
            if (in.repne)    { op = X86Op::CVTSD2SS; mn = "cvtsd2ss"; src_bits = 64; }
            else if (in.rep) { op = X86Op::CVTSS2SD; mn = "cvtss2sd"; src_bits = 32; }
            else if (in.o16) return std::nullopt;              // CVTPD2PS: not yet
            else             { op = X86Op::CVTPS2PD; mn = "cvtps2pd"; src_bits = 64; }
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = src_bits;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = src_bits;
            in.dst = xmm;
            in.src = src;
            return finish(op, mn);
        }

        // 5B — CVTDQ2PS (NP) / CVTPS2DQ (66); F3/F2 are the CVTT variants.
        if (sec == 0x5B) {
            if (in.rep || in.repne) return std::nullopt;
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            return finish(in.o16 ? X86Op::CVTPS2DQ : X86Op::CVTDQ2PS,
                          in.o16 ? "cvtps2dq" : "cvtdq2ps");
        }

        // E6 — CVTDQ2PD (F3) / CVTTPD2DQ (66); F2 is CVTPD2DQ (not yet).
        if (sec == 0xE6) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            X86Op op;
            const char* mn;
            int src_bits;
            if (in.rep)      { op = X86Op::CVTDQ2PD; mn = "cvtdq2pd"; src_bits = 64; }
            else if (in.o16) { op = X86Op::CVTTPD2DQ; mn = "cvttpd2dq"; src_bits = 128; }
            else return std::nullopt;                          // CVTPD2DQ: not yet
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = src_bits;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = src_bits;
            in.dst = xmm;
            in.src = src;
            return finish(op, mn);
        }

        // 2A — CVTSI2SS (F3) / CVTSI2SD (F2); 66 and NP are the MMX forms
        // CVTPI2PD / CVTPI2PS, which have no register file here.
        if (sec == 0x2A) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            if (!in.rep && !in.repne) {
                Operand mmxsrc;
                mmxsrc.size = 64;
                parseRm(data, len, i, modrm, rex_b, rex_x, mmxsrc);
                return finish(X86Op::MMX_OP, in.o16 ? "cvtpi2pd" : "cvtpi2ps");
            }
            const bool to_double = in.repne;
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = in.rex_w ? 64 : 32;
            parseRm(data, len, i, modrm, rex_b, rex_x, src);
            in.dst = xmm;
            in.src = src;
            return finish(to_double ? X86Op::CVTSI2SD : X86Op::CVTSI2SS,
                          to_double ? "cvtsi2sd" : "cvtsi2ss");
        }

        // 2D — CVTSS2SI (F3) / CVTSD2SI (F2); NP is CVTPS2PI (MMX dest).
        if (sec == 0x2D) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            if (!in.rep && !in.repne) {
                Operand src;
                src.size = 64;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                return finish(X86Op::MMX_OP, in.o16 ? "cvtpd2pi" : "cvtps2pi");
            }
            const bool single = in.rep;
            in.dst.kind = OperandKind::REG;
            in.dst.reg = modrmReg(modrm) + rex_r;
            in.dst.size = in.rex_w ? 64 : 32;
            Operand src;
            src.size = single ? 32 : 64;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = single ? 32 : 64;
            in.src = src;
            return finish(single ? X86Op::CVTSS2SI : X86Op::CVTSD2SI,
                          single ? "cvtss2si" : "cvtsd2si");
        }

        // 2C — CVTTSS2SI (F3) / CVTTSD2SI (F2): truncating scalar convert.
        // NP and 66 are the MMX-destination CVTTPS2PI / CVTTPD2PI.
        if (sec == 0x2C) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            if (!in.rep && !in.repne) {
                Operand src;
                src.size = in.o16 ? 128 : 64;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
                return finish(X86Op::MMX_OP, in.o16 ? "cvttpd2pi" : "cvttps2pi");
            }
            const bool single = in.rep;
            in.dst.kind = OperandKind::REG;
            in.dst.reg = modrmReg(modrm) + rex_r;
            in.dst.size = in.rex_w ? 64 : 32;
            Operand src;
            src.size = single ? 32 : 64;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = single ? 32 : 64;
            in.src = src;
            return finish(single ? X86Op::CVTTSS2SI : X86Op::CVTTSD2SI,
                          single ? "cvttss2si" : "cvttsd2si");
        }

        // 5E — DIVPS (NP) / DIVPD (66) / DIVSS (F3) / DIVSD (F2).
        if (sec == 0x5E) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            X86Op op;
            const char* mn;
            int scalar_bits = 0;
            if (in.repne) { op = X86Op::DIVSD; mn = "divsd"; scalar_bits = 64; }
            else if (in.rep) { op = X86Op::DIVSS; mn = "divss"; scalar_bits = 32; }
            else if (in.o16) { op = X86Op::DIVPD; mn = "divpd"; }
            else { op = X86Op::DIVPS; mn = "divps"; }
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = scalar_bits ? scalar_bits : 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            return finish(op, mn);
        }

        // 77 — EMMS: mark the whole x87/MMX tag word empty.
        if (sec == 0x77) return finish(X86Op::EMMS, "emms");

        // 7C/7D — HADDPD/HADDPS and HSUBPD/HSUBPS (66 = packed double,
        // F2 = packed single).
        if (sec == 0x7C || sec == 0x7D) {
            if (!in.o16 && !in.repne) return std::nullopt;
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            const bool dbl = in.o16;
            return finish(sec == 0x7C ? (dbl ? X86Op::HADDPD : X86Op::HADDPS)
                                      : (dbl ? X86Op::HSUBPD : X86Op::HSUBPS),
                          sec == 0x7C ? (dbl ? "haddpd" : "haddps")
                                     : (dbl ? "hsubpd" : "hsubps"));
        }

        // 54/55 — bitwise SIMD logical AND / AND NOT (legacy two-operand
        // form: the destination is also the first source).
        if (sec == 0x54 || sec == 0x55) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            if (sec == 0x54)
                return finish(in.o16 ? X86Op::ANDPD : X86Op::ANDPS,
                              in.o16 ? "andpd" : "andps");
            return finish(in.o16 ? X86Op::ANDNPD : X86Op::ANDNPS,
                          in.o16 ? "andnpd" : "andnps");
        }

        // A3/AB/B3/BB — BT/BTS/BTR/BTC r/m, r
        if (sec == 0xA3 || sec == 0xAB || sec == 0xB3 || sec == 0xBB) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            Operand rmop;
            rmop.size = opsize;
            parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
            in.dst = rmop;
            in.src.kind = OperandKind::REG;
            in.src.reg = modrmReg(modrm) + rex_r;
            in.src.size = opsize;
            return finish(sec == 0xA3 ? X86Op::BT :
                          sec == 0xAB ? X86Op::BTS :
                          sec == 0xB3 ? X86Op::BTR : X86Op::BTC,
                          sec == 0xA3 ? "bt" : sec == 0xAB ? "bts" :
                          sec == 0xB3 ? "btr" : "btc");
        }

        // BA — group 8: BT/BTS/BTR/BTC r/m, imm8 (/4 ../7)
        if (sec == 0xBA) {
            if (i + 1 >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            const int ext = modrmReg(modrm);
            if (ext < 4) return std::nullopt; // /0-/3 undefined
            Operand rmop;
            rmop.size = opsize;
            parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
            if (i >= len) return std::nullopt;
            in.dst = rmop;
            in.src.kind = OperandKind::IMM;
            in.src.imm = data[i++];
            in.src.size = 8;
            return finish(ext == 4 ? X86Op::BT : ext == 5 ? X86Op::BTS :
                          ext == 6 ? X86Op::BTR : X86Op::BTC,
                          ext == 4 ? "bt" : ext == 5 ? "bts" :
                          ext == 6 ? "btr" : "btc");
        }

        // BC/BD — BSF/BSR, or TZCNT/LZCNT when F3 is present.
        if (sec == 0xBC || sec == 0xBD) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            Operand rmop;
            rmop.size = opsize;
            parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
            in.dst.kind = OperandKind::REG;
            in.dst.reg = modrmReg(modrm) + rex_r;
            in.dst.size = opsize;
            in.src = rmop;
            if (in.rep) {
                return finish(sec == 0xBC ? X86Op::TZCNT : X86Op::LZCNT,
                              sec == 0xBC ? "tzcnt" : "lzcnt");
            }
            return finish(sec == 0xBC ? X86Op::BSF : X86Op::BSR,
                          sec == 0xBC ? "bsf" : "bsr");
        }

        // C8-CF — BSWAP r32/r64
        if (sec >= 0xC8 && sec <= 0xCF) {
            in.dst.kind = OperandKind::REG;
            in.dst.reg = (sec & 7) + rex_b;
            in.dst.size = in.rex_w ? 64 : (in.o16 ? 16 : 32);
            return finish(X86Op::BSWAP, "bswap");
        }

        // 01 — group 7. CA/CB are CLAC/STAC, C8/C9 MONITOR/MWAIT, /2-/3 and
        // /6 the descriptor-table and MSW loads (all CPL-0, so #GP(0)), /7 is
        // INVLPG. The remaining MSR/XSAVE forms stay no-ops for alignment.
        if (sec == 0x01 && i < len) {
            uint8_t modrm = data[i++];
            // SGX entry points (0F 01 /r with mod=3). The leaf number is in
            // EAX at run time; the mnemonic names the instruction, and the
            // interpreter appends the leaf (encls[eadd], enclu[eenter], ...).
            if (modrm == 0xCF && !in.o16) return finish(X86Op::ENCLS, "encls");
            if (modrm == 0xD7) return finish(X86Op::ENCLU, "enclu");
            if (modrm == 0xC0 && !in.o16) return finish(X86Op::ENCLV, "enclv");
            if (modrm == 0xCA) return finish(X86Op::CLAC, "clac");
            if (modrm == 0xCB) return finish(X86Op::STAC, "stac");
            // §2.20 — the remaining group-7 leaves. The 66-prefixed forms are
            // the TDX SEAM transitions (CC/CF/CD) and require the SEAM root
            // module, so a normal guest takes #UD.
            if (modrm == 0xCC && in.o16) return finish(X86Op::SEAMOPS, "seamops");
            if (modrm == 0xCD && in.o16) return finish(X86Op::SEAMRET, "seamret");
            if (modrm == 0xCF && in.o16) return finish(X86Op::SEAMCALL, "seamcall");
            // D0/D1 — XGETBV/XSETBV (XCR access). D5/D6 — XEND/XTEST.
            if (modrm == 0xD0) return finish(X86Op::XGETBV, "xgetbv");
            if (modrm == 0xD1) return finish(X86Op::XSETBV, "xsetbv");
            if (modrm == 0xD5) return finish(X86Op::XEND, "xend");
            if (modrm == 0xD6) return finish(X86Op::XTEST, "xtest");
            // DC/DD — STGI/CLGI: SVM global-interrupt control, CPL 0 only.
            if (modrm == 0xDC) return finish(X86Op::STGI, "stgi");
            if (modrm == 0xDD) return finish(X86Op::CLGI, "clgi");
            // E8 — SERIALIZE: a full pipeline serialisation that also drains
            // the store buffer; the interpreter treats it as a fence.
            if (modrm == 0xE8) return finish(X86Op::SERIALIZE, "serialize");
            // F8/F9 — SWAPGS (CPL-0) and RDTSCP.
            if (modrm == 0xF8) return finish(X86Op::SWAPGS, "swapgs");
            if (modrm == 0xF9) return finish(X86Op::RDTSCP, "rdtscp");
            if (modrm == 0xC8) return finish(X86Op::MONITOR, "monitor");
            if (modrm == 0xC9) return finish(X86Op::MWAIT, "mwait");
            // C5 — PCONFIG: #UD unless CPUID advertises the PCONFIG leaf.
            if (modrm == 0xC5) return finish(X86Op::PCONFIG, "pconfig");
            if (modrm == 0xEE && in.rep) return finish(X86Op::CLUI, "clui");
            // EE without F3 — RDPKRU: #UD while CR4.PKE is clear.
            if (modrm == 0xEE) return finish(X86Op::RDPKRU, "rdpkru");
            // /7 — INVLPG m8: privileged TLB invalidation for one page.
            if (modrmReg(modrm) == 7 && modrmMod(modrm) != 3) {
                Operand m;
                m.size = 8;
                parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
                in.src = m;
                return finish(X86Op::INVLPG, "invlpg");
            }
            // LMSW also takes a register operand (r/m16).
            if (modrmMod(modrm) == 3 && modrmReg(modrm) == 6) {
                Operand r;
                r.size = 16;
                parseRm(data, len, i, modrm, rex_b, rex_x, r);
                in.src = r;
                return finish(X86Op::LMSW, "lmsw");
            }
            if (modrmMod(modrm) != 3) {
                const int ext = modrmReg(modrm);
                // /4 — SMSW m16: the low half of CR0.
                if (ext == 4) {
                    Operand m;
                    m.size = 16;
                    parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
                    in.dst = m;
                    return finish(X86Op::SMSW, "smsw");
                }
                // /0, /1 — SGDT/SIDT: the descriptor-table base and limit.
                // Both are unprivileged reads (subject to UMIP, which NINE
                // leaves disabled because no GDT/IDT is modelled).
                if (ext == 0 || ext == 1) {
                    Operand m;
                    m.size = 80;
                    parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
                    in.dst = m;
                    return finish(ext == 0 ? X86Op::SGDT : X86Op::SIDT,
                                  ext == 0 ? "sgdt" : "sidt");
                }
                // F3 /5 — RSTORSSP m64: restore the shadow-stack pointer from
                // the restore token at the operand. With CET disabled the
                // instruction is a no-op, but the memory operand still has to
                // be consumed (and is read, so a bad pointer still faults).
                if (ext == 5 && in.rep) {
                    Operand m;
                    m.size = 64;
                    parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
                    in.src = m;
                    return finish(X86Op::RSTORSSP, "rstorssp");
                }
                if (ext == 2 || ext == 3 || ext == 6) {
                    Operand m;
                    m.size = (ext == 6) ? 16 : 80;
                    parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
                    in.src = m;
                    return finish(ext == 2 ? X86Op::LGDT : ext == 3 ? X86Op::LIDT : X86Op::LMSW,
                                  ext == 2 ? "lgdt" : ext == 3 ? "lidt" : "lmsw");
                }
                Operand ignored;
                ignored.size = 16;
                parseRmRest(data, len, i, modrm, rex_b, rex_x, ignored);
            }
            // /4 (register form) — SMSW r32/r64: CR0[15:0] zero-extended.
            if (modrmReg(modrm) == 4) {
                in.dst.kind = OperandKind::REG;
                in.dst.reg = modrmRm(modrm) + rex_b;
                in.dst.size = in.rex_w ? 64 : 32;
                return finish(X86Op::SMSW, "smsw");
            }
            return finish(X86Op::NOP, "grp7");
        }

        // 1A/1B — MPX bound-register operations, selected by prefix:
        //   F3 = BNDCL/BNDMK, F2 = BNDCU/BNDCN, 66 = BNDMOV, none = BNDLDX/BNDSTX
        if ((sec == 0x1A || sec == 0x1B) && i < len) {
            uint8_t modrm = data[i++];
            const int bnd = modrmReg(modrm) & 3; // BND4-15 are #UD
            Operand rmop;
            if (in.o16) {
                // 66 forms are BNDMOV: the ModRM.rm register encoding names a
                // bound register (BND0-3), not an XMM register.
                rmop.size = 128;
                parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
            } else {
                rmop.size = in.rex_w ? 64 : 32;
                parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
            }
            Operand bndop;
            bndop.kind = OperandKind::REG;
            bndop.reg = bnd;
            bndop.size = 128;
            if (sec == 0x1A) {
                if (in.rep)  { in.dst = bndop; in.src = rmop; return finish(X86Op::BNDCL, "bndcl"); }
                if (in.repne){ in.dst = bndop; in.src = rmop; return finish(X86Op::BNDCU, "bndcu"); }
                if (in.o16)  { in.dst = bndop; in.src = rmop; return finish(X86Op::BNDMOV_LOAD, "bndmov_load"); }
                in.dst = bndop; in.src = rmop;
                return finish(X86Op::BNDLDX, "bndldx");
            }
            if (in.rep)  { in.dst = bndop; in.src = rmop; return finish(X86Op::BNDMK, "bndmk"); }
            if (in.repne){ in.dst = bndop; in.src = rmop; return finish(X86Op::BNDCN, "bndcn"); }
            if (in.o16)  { in.dst = rmop; in.src = bndop; return finish(X86Op::BNDMOV_STORE, "bndmov_store"); }
            in.dst = rmop; in.src = bndop;
            return finish(X86Op::BNDSTX, "bndstx");
        }

        // 1C /0 — CLDEMOTE (cache hint, no architectural state change)
        if (sec == 0x1C && i < len) {
            uint8_t modrm = data[i++];
            Operand rmop;
            rmop.size = 8;
            parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
            in.dst = rmop;
            return finish(X86Op::CLDEMOTE, "cldemote");
        }

        if (sec >= 0x40 && sec <= 0x4F) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            in.cc = sec & 0xF;
            in.dst.kind = OperandKind::REG;
            in.dst.reg = modrmReg(modrm) + rex_r;
            in.dst.size = opsize;
            Operand rmop;
            rmop.size = opsize;
            parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
            in.src = rmop;
            return finish(X86Op::CMOV, "cmov");
        }
        if (sec >= 0x90 && sec <= 0x9F) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            in.cc = sec & 0xF;
            Operand rmop;
            rmop.size = 8;
            parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
            in.dst = rmop;
            in.dst.size = 8;
            // The sixteen primary mnemonics. The aliases (SETC/SETNC/SETZ/
            // SETNZ/SETNA/SETNAE/SETNB/SETNBE/SETNG/SETNGE/SETNL/SETNLE/
            // SETPE/SETPO) decode to the same condition codes — see evalCc.
            static const char* const kSet[] = {
                "seto", "setno", "setb", "setae", "sete", "setne", "setbe", "seta",
                "sets", "setns", "setp", "setnp", "setl", "setge", "setle", "setg"
            };
            return finish(X86Op::SETCC, kSet[sec & 0xF]);
        }
        // IMUL r, r/m (0F AF)
        if (sec == 0xAF) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            in.dst.kind = OperandKind::REG;
            in.dst.reg = modrmReg(modrm) + rex_r;
            in.dst.size = opsize;
            Operand rmop;
            rmop.size = opsize;
            parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
            in.src = rmop;
            return finish(X86Op::IMUL, "imul2");
        }
        // CMPXCHG r/m, r (0F B0/B1)
        if (sec == 0xB0 || sec == 0xB1) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            int bits = (sec == 0xB0) ? 8 : opsize;
            Operand rmop;
            rmop.size = bits;
            parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
            Operand regop;
            regop.kind = OperandKind::REG;
            regop.reg = modrmReg(modrm) + rex_r;
            regop.size = bits;
            if (bits == 8) { applyByteReg(rmop, rex); applyByteReg(regop, rex); }
            in.dst = rmop;
            in.src = regop;
            return finish(X86Op::CMPXCHG, "cmpxchg");
        }
        // C7 /1 — CMPXCHG8B (NP) / CMPXCHG16B (REX.W). Other group-9 forms
        // (RDRAND/RDSEED/RDPID/…) are not decoded yet.
        if (sec == 0xC7) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            // /6 — RDRAND; /7 with F3 — RDPID (both register forms only).
            if (modrmMod(modrm) == 3 && modrmReg(modrm) == 6) {
                in.dst.kind = OperandKind::REG;
                in.dst.reg = modrmRm(modrm) + rex_b;
                in.dst.size = in.rex_w ? 64 : (in.o16 ? 16 : 32);
                return finish(X86Op::RDRAND, "rdrand");
            }
            if (modrmMod(modrm) == 3 && modrmReg(modrm) == 7 && in.rep) {
                in.dst.kind = OperandKind::REG;
                in.dst.reg = modrmRm(modrm) + rex_b;
                in.dst.size = in.rex_w ? 64 : 32;
                return finish(X86Op::RDPID, "rdpid");
            }
            // /7 (register, no F3) — RDSEED: hardware entropy with CF as the
            // success flag.
            if (modrmMod(modrm) == 3 && modrmReg(modrm) == 7) {
                in.dst.kind = OperandKind::REG;
                in.dst.reg = modrmRm(modrm) + rex_b;
                in.dst.size = in.rex_w ? 64 : (in.o16 ? 16 : 32);
                return finish(X86Op::RDSEED, in.rex_w ? "rdseedq" :
                                       in.o16 ? "rdseedw" : "rdseedl");
            }
            // §2.20 — /3 XRSTORS, /4 XSAVEC, /5 XSAVES (memory forms only).
            if (modrmReg(modrm) >= 3 && modrmReg(modrm) <= 5) {
                const int ext = modrmReg(modrm);
                if (modrmMod(modrm) == 3) return std::nullopt;   // #UD
                Operand m;
                m.size = 576 * 8;
                parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
                if (ext == 3) {
                    in.src = m;
                    return finish(X86Op::XRSTORS, "xrstors");
                }
                in.dst = m;
                return finish(ext == 4 ? X86Op::XSAVEC : X86Op::XSAVES,
                              ext == 4 ? "xsavec" : "xsaves");
            }
            if (modrmReg(modrm) != 1) return std::nullopt;
            if (modrmMod(modrm) == 3) return std::nullopt;      // !(11): #UD
            Operand m;
            m.size = in.rex_w ? 128 : 64;
            parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
            in.dst = m;
            return finish(in.rex_w ? X86Op::CMPXCHG16B : X86Op::CMPXCHG8B,
                          in.rex_w ? "cmpxchg16b" : "cmpxchg8b");
        }

        // XADD r/m, r (0F C0/C1)
        if (sec == 0xC0 || sec == 0xC1) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            int bits = (sec == 0xC0) ? 8 : opsize;
            Operand rmop;
            rmop.size = bits;
            parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
            Operand regop;
            regop.kind = OperandKind::REG;
            regop.reg = modrmReg(modrm) + rex_r;
            regop.size = bits;
            if (bits == 8) { applyByteReg(rmop, rex); applyByteReg(regop, rex); }
            in.dst = rmop;
            in.src = regop;
            return finish(X86Op::XADD, "xadd");
        }
        // Jcc rel32 0F 80-8F
        if (sec >= 0x80 && sec <= 0x8F) {
            if (i + 4 > len) return std::nullopt;
            int32_t rel = 0;
            for (int k = 0; k < 4; ++k) rel |= static_cast<int32_t>(data[i + k]) << (8 * k);
            i += 4;
            in.dst.kind = OperandKind::REL;
            in.dst.imm = static_cast<int64_t>(addr + i) + rel;
            static const X86Op cc[] = {
                X86Op::JO, X86Op::JNO, X86Op::JB, X86Op::JAE, X86Op::JE, X86Op::JNE, X86Op::JBE, X86Op::JA,
                X86Op::JS, X86Op::JNS, X86Op::INVALID, X86Op::INVALID, X86Op::JL, X86Op::JGE, X86Op::JLE, X86Op::JG
            };
            return finish(cc[sec - 0x80], "jcc32");
        }
        // 0F 1F multi-byte NOP — consume modrm + SIB/disp for exact length
        if (sec == 0x1F) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            Operand rm;
            parseRm(data, len, i, modrm, rex_b, rex_x, rm);
            return finish(X86Op::NOP, "nop");
        }
        // CET: F3 0F 1E FA = endbr64, F3 0F 1E FB = endbr32 (prefix F3 already skipped)
        if (sec == 0x1E && i < len && (data[i] == 0xFA || data[i] == 0xFB)) {
            const uint8_t tail = data[i];
            ++i;
            return finish(X86Op::ENDBR, tail == 0xFA ? "endbr64" : "endbr32");
        }
        // F3 0F 1E /1 — RDSSPD/RDSSPQ: read the current shadow-stack pointer.
        // With CET disabled the instruction is architecturally a NOP that
        // leaves the destination untouched, which is what NINE models.
        if (sec == 0x1E && i < len && in.rep) {
            uint8_t modrm = data[i];
            if (modrmReg(modrm) == 1 && modrmMod(modrm) == 3) {
                ++i;
                in.dst.kind = OperandKind::REG;
                in.dst.reg = modrmRm(modrm) + rex_b;
                in.dst.size = in.rex_w ? 64 : 32;
                return finish(X86Op::RDSSP, in.rex_w ? "rdsspq" : "rdsspd");
            }
        }
        // Remaining 0F 1E forms (NOP space) retire as no-ops, consuming the
        // ModRM byte so the stream stays aligned.
        if (sec == 0x1E) {
            if (i < len) ++i; // modrm
            return finish(X86Op::NOP, "nop1e");
        }
        // A4/A5/AC/AD — SHLD/SHRD r/m, r, imm8|CL: a shift of the destination
        // whose vacated bits come from the second register.
        if ((sec == 0xA4 || sec == 0xA5 || sec == 0xAC || sec == 0xAD) && i < len) {
            uint8_t modrm = data[i++];
            const int bits = in.rex_w ? 64 : (in.o16 ? 16 : 32);
            Operand dst;
            dst.size = bits;
            parseRm(data, len, i, modrm, rex_b, rex_x, dst);
            in.dst = dst;
            in.src.kind = OperandKind::REG;
            in.src.reg = modrmReg(modrm) + rex_r;
            in.src.size = bits;
            if (sec == 0xA4 || sec == 0xAC) {
                if (i >= len) return std::nullopt;
                in.src2.kind = OperandKind::IMM;
                in.src2.size = 8;
                in.src2.imm = data[i++];
            } else {
                in.src2.kind = OperandKind::REG;
                in.src2.reg = 1;          // CL
                in.src2.size = 8;
            }
            in.cc = (sec == 0xA4 || sec == 0xA5) ? 0 : 1;
            return finish(X86Op::SHXD, in.cc == 0 ? "shld" : "shrd");
        }

        // 52 — RSQRTPS (NP) / RSQRTSS (F3).
        if (sec == 0x52 && i < len) {
            uint8_t modrm = data[i++];
            const bool scalar = in.rep;
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = scalar ? 32 : 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            return finish(scalar ? X86Op::RSQRTSS : X86Op::RSQRTPS,
                          scalar ? "rsqrtss" : "rsqrtps");
        }

        // 0F AE — memory forms /7 CLFLUSH (66 /7 CLFLUSHOPT, 66 /6 CLWB);
        // the register forms E8/F0/F8 are LFENCE/MFENCE/SFENCE (no-ops here
        // because every guest store is already visible to the runtime).
        if (sec == 0xAE && i < len) {
            uint8_t modrm = data[i++];
            const int ext = modrmReg(modrm);
            // F3 0F AE /0,/1 — RDFSBASE/RDGSBASE (register form).
            if (modrmMod(modrm) == 3 && in.rep && (ext == 0 || ext == 1)) {
                in.dst.kind = OperandKind::REG;
                in.dst.reg = modrmRm(modrm) + rex_b;
                in.dst.size = in.rex_w ? 64 : 32;
                return finish(ext == 0 ? X86Op::RDFSBASE : X86Op::RDGSBASE,
                              ext == 0 ? "rdfsbase" : "rdgsbase");
            }
            // F3 0F AE /2,/3 — WRFSBASE/WRGSBASE: the write half of the
            // segment-base pair (ring 3 allowed when CR4.FSGSBASE is set).
            if (modrmMod(modrm) == 3 && in.rep && (ext == 2 || ext == 3)) {
                Operand r;
                r.size = in.rex_w ? 64 : 32;
                parseRm(data, len, i, modrm, rex_b, rex_x, r);
                in.src = r;
                return finish(ext == 2 ? X86Op::WRFSBASE : X86Op::WRGSBASE,
                              ext == 2 ? "wrfsbase" : "wrgsbase");
            }
            // 66/F3/F2 0F AE /6 (register) — TPAUSE / UMONITOR / UMWAIT. The
            // waiter hints retire immediately (the guest is single-threaded),
            // and UMWAIT reports the timeout path via ZF=1.
            if (modrmMod(modrm) == 3 && ext == 6) {
                if (in.o16) return finish(X86Op::TPAUSE, "tpause");
                if (in.rep) return finish(X86Op::UMONITOR, "umonitor");
                if (in.repne) return finish(X86Op::UMWAIT, "umwait");
            }
            // F3 0F AE /4 — PTWRITE: #UD while CR4.PTW is clear.
            if (modrmMod(modrm) == 3 && in.rep && ext == 4) {
                in.dst.kind = OperandKind::REG;
                in.dst.reg = modrmRm(modrm) + rex_b;
                in.dst.size = in.rex_w ? 64 : 32;
                return finish(X86Op::PTWRITE, "ptwrite");
            }
            // F3 0F AE /5 (register form) — INCSSPD/INCSSPQ: bump the shadow
            // stack pointer by the operand value.
            if (modrmMod(modrm) == 3 && ext == 5 && in.rep) {
                in.dst.kind = OperandKind::REG;
                in.dst.reg = modrmRm(modrm) + rex_b;
                in.dst.size = in.rex_w ? 64 : 32;
                return finish(X86Op::INCSSP, in.rex_w ? "incsspq" : "incsspd");
            }
            if (modrmMod(modrm) != 3) {
                // /2 — LDMXCSR m32: load the SSE control/status word.
                if (ext == 2) {
                    Operand m;
                    m.size = 32;
                    parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
                    in.src = m;
                    return finish(X86Op::LDMXCSR, "ldmxcsr");
                }
                // §2.20 — /3 STMXCSR, /4 XSAVE, /5 XRSTOR. Only the legacy
                // x87/SSE region of the state image is modelled, so an XSAVE
                // area is the 512-byte FXSAVE layout with XSTATE_BV = 3.
                if (ext == 3) {
                    Operand m;
                    m.size = 32;
                    parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
                    in.dst = m;
                    return finish(X86Op::STMXCSR, "stmxcsr");
                }
                if (ext == 4 || ext == 5) {
                    Operand m;
                    m.size = 576 * 8;
                    parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
                    if (ext == 4) {
                        in.dst = m;
                        return finish(X86Op::XSAVE, "xsave");
                    }
                    in.src = m;
                    return finish(X86Op::XRSTOR, "xrstor");
                }
                Operand m;
                m.size = 8;
                parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
                if (ext == 7) {
                    return finish(in.o16 ? X86Op::CLFLUSHOPT : X86Op::CLFLUSH,
                                  in.o16 ? "clflushopt" : "clflush");
                }
                if (ext == 6 && in.o16) return finish(X86Op::CLWB, "clwb");
                // F3 0F AE /6 — CET supervisor shadow-stack token clear.
                if (ext == 6 && in.rep) return finish(X86Op::CLRSSBSY, "clrssbsy");
                // NP 0F AE /6 — XSAVEOPT: an XSAVE that may skip unchanged
                // state. NINE always writes the full legacy region.
                if (ext == 6) {
                    m.size = 576 * 8;
                    in.dst = m;
                    return finish(X86Op::XSAVEOPT, "xsaveopt");
                }
                // /0 and /1 — the 512-byte x87/SSE state image. Both are
                // memory-only forms.
                if (ext == 0) {
                    m.size = 512 * 8;
                    in.dst = m;
                    return finish(X86Op::FXSAVE, "fxsave");
                }
                if (ext == 1) {
                    m.size = 512 * 8;
                    in.src = m;
                    return finish(X86Op::FXRSTOR, "fxrstor");
                }
            }
            // Register forms: E8 = LFENCE, F0 = MFENCE, F8 = SFENCE. The guest
            // runs single-threaded and every store is already visible to the
            // runtime, so they retire as ordered no-ops; the mnemonic is kept
            // distinct so traces and the ISA ledger stay honest.
            if (modrmMod(modrm) == 3) {
                if (modrm == 0xE8) return finish(X86Op::NOP, "lfence");
                if (modrm == 0xF0) return finish(X86Op::NOP, "mfence");
                if (modrm == 0xF8) return finish(X86Op::NOP, "sfence");
            }
            return finish(X86Op::NOP, "fence");
        }
        // A2 — CPUID: the interpreter synthesises a deterministic leaf set so
        // the guest sees the same CPU on every host.
        if (sec == 0xA2) return finish(X86Op::CPUID, "cpuid");
        // 12/13 MOVLPS/MOVLPD, 16/17 MOVHPS/MOVHPD — 64-bit halves load/store.
        // The mandatory prefix selects the other tenants of the same opcode:
        // F2 0F 12 = MOVDDUP, F3 0F 12/16 = MOVSLDUP/MOVSHDUP, and the
        // register-register form of the no-prefix opcode is MOVHLPS/MOVLHPS.
        if (sec == 0x12 || sec == 0x16) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            if (in.repne && sec == 0x12) {              // MOVDDUP
                Operand other;
                other.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, other);
                other.size = (other.kind == OperandKind::REG) ? 128 : 64;
                in.dst = xmm;
                in.src = other;
                return finish(X86Op::MOVDDUP, "movddup");
            }
            if (in.rep) {                               // MOVSLDUP / MOVSHDUP
                Operand other;
                other.size = 128;
                parseSseRm(data, len, i, modrm, rex_b, rex_x, other);
                if (other.kind == OperandKind::REG) other.size = 128;
                in.dst = xmm;
                in.src = other;
                return finish(sec == 0x12 ? X86Op::MOVSLDUP : X86Op::MOVSHDUP,
                              sec == 0x12 ? "movsldup" : "movshdup");
            }
            if (modrmMod(modrm) == 3) {                 // MOVHLPS / MOVLHPS
                in.dst = xmm;
                in.src.kind = OperandKind::REG;
                in.src.reg = 16 + (modrmRm(modrm) + rex_b);
                in.src.size = 128;
                return finish(sec == 0x12 ? X86Op::MOVHLPS : X86Op::MOVLHPS,
                              sec == 0x12 ? "movhlps" : "movlhps");
            }
            Operand other;
            other.size = 64;
            parseRm(data, len, i, modrm, rex_b, rex_x, other);
            if (other.kind == OperandKind::REG) other.reg = 16 + (other.reg & 0xF);
            in.dst = xmm;
            in.dst.size = 64;
            in.src = other;
            return finish(sec == 0x12 ? X86Op::MOVLPS_LOAD : X86Op::MOVHPS_LOAD,
                          sec == 0x12 ? (in.o16 ? "movlpd" : "movlps")
                                      : (in.o16 ? "movhpd" : "movhps"));
        }
        if (sec == 0x13 || sec == 0x17) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand other;
            other.size = 64;
            parseRm(data, len, i, modrm, rex_b, rex_x, other);
            if (other.kind == OperandKind::REG) other.reg = 16 + (other.reg & 0xF);
            in.dst = other;
            in.src = xmm;
            in.src.size = 64;
            return finish(sec == 0x13 ? X86Op::MOVLPS_STORE : X86Op::MOVHPS_STORE,
                          sec == 0x13 ? (in.o16 ? "movlpd_store" : "movlps_store")
                                      : (in.o16 ? "movhpd_store" : "movhps_store"));
        }
        if (sec == 0xD6) {
            // 66 0F D6 = MOVQ xmm -> r/m64; F3 = MOVQ2DQ (MMX source);
            // F2 = MOVDQ2Q (MMX destination). The MMX pair decodes so the
            // stream stays aligned and refuses by name at execute time.
            if (i >= len) return std::nullopt;
            if (in.rep || in.repne) {
                uint8_t modrm = data[i++];
                in.dst.kind = OperandKind::REG;
                in.dst.reg = 16 + (modrmReg(modrm) + rex_r);
                in.dst.size = 128;
                in.src.kind = OperandKind::REG;
                in.src.reg = modrmRm(modrm) + rex_b;
                in.src.size = 128;
                return finish(X86Op::MMX_OP, in.rep ? "movq2dq" : "movdq2q");
            }
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 64;
            Operand other;
            other.size = 64;
            parseRm(data, len, i, modrm, rex_b, rex_x, other);
            if (other.kind == OperandKind::REG) other.reg = 16 + (other.reg & 0xF);
            in.dst = other;
            in.src = xmm;
            return finish(X86Op::SSE_MOV, "movq_store");
        }
        // F3 0F 7E — MOVQ xmm, xmm/m64 (the load half of the MOVQ pair).
        if (sec == 0x7E && in.rep) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 64;
            Operand other;
            other.size = 64;
            parseRm(data, len, i, modrm, rex_b, rex_x, other);
            if (other.kind == OperandKind::REG) other.reg = 16 + (other.reg & 0xF);
            in.dst = xmm;
            in.src = other;
            return finish(X86Op::MOVD, "movq");
        }
        // F3/F2 0F 10/11 — MOVSS/MOVSD. The register form merges into the
        // destination's upper lanes; the memory form zeroes them.
        if ((sec == 0x10 || sec == 0x11) && (in.rep || in.repne)) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            const int bits = in.rep ? 32 : 64;
            const bool load = (sec == 0x10);
            Operand xmm;
            xmm.kind = OperandKind::REG;
            // ModRM.reg is always the XMM operand: the destination on load,
            // the source on store.
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = bits;
            Operand other;
            other.size = bits;
            parseRm(data, len, i, modrm, rex_b, rex_x, other);
            if (other.kind == OperandKind::REG) {
                other.reg = 16 + (other.reg & 0xF);
                other.size = bits;
            }
            if (load) {
                in.dst = xmm;
                in.src = other;
            } else {
                in.dst = other;
                in.src = xmm;
            }
            return finish(in.rep ? X86Op::MOVSS : X86Op::MOVSD_SSE,
                          in.rep ? (load ? "movss" : "movss_store")
                                 : (load ? "movsd" : "movsd_store"));
        }
        if (sec == 0x62 || sec == 0x6C || sec == 0x6D) { // PUNPCKLDQ/LQDQ/HQDQ (66 required)
            if (!in.o16 || i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            in.dst.kind = OperandKind::REG;
            in.dst.reg = 16 + (modrmReg(modrm) + rex_r);
            in.dst.size = 128;
            Operand src;
            src.size = 128;
            parseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.reg = 16 + (src.reg & 0xF);
            in.src = src;
            return finish(sec == 0x62 ? X86Op::PUNPCKLDQ :
                          sec == 0x6C ? X86Op::PUNPCKLQDQ : X86Op::PUNPCKHQDQ,
                          sec == 0x62 ? "punpckldq" :
                          sec == 0x6C ? "punpcklqdq" : "punpckhqdq");
        }
        if (sec == 0x6E || sec == 0x7E || sec == 0x10 || sec == 0x11 ||
            sec == 0x28 || sec == 0x29 || sec == 0x6F || sec == 0x7F || sec == 0xEF) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            bool to_xmm = (sec == 0x6E || sec == 0x10 || sec == 0x28 ||
                           sec == 0x6F || sec == 0xEF);
            // 66 0F 6E/7E are MOVD; adding REX.W makes them MOVQ. The F3
            // form of 0F 7E is the XMM-source MOVQ and is always 64-bit.
            bool is_q = (sec == 0x6E || sec == 0x7E) &&
                        ((in.o16 && in.rex_w) || (sec == 0x7E && in.rep));
            // The XMM operand is always the ModRM.reg field. The r/m side is
            // a GPR for MOVD/MOVQ (0F 6E/7E) and an XMM register for the
            // packed moves. 0F 7E has two shapes: 66 0F 7E stores an XMM to
            // r/m32/64, while the F3 form (MOVQ xmm, xmm/m64) reads an XMM.
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand other;
            other.size = is_q ? 64 : (sec == 0xEF ? 128 : 32);
            parseRm(data, len, i, modrm, rex_b, rex_x, other);
            const bool movqRegForm = (sec == 0x7E && in.rep);
            if (other.kind == OperandKind::REG &&
                sec != 0x6E && !(sec == 0x7E && !movqRegForm)) {
                other.reg = 16 + (other.reg & 0xF);
                other.size = (sec == 0xEF) ? 128 : (is_q ? 64 : 32);
            }
            if (sec == 0x6E) {
                // MOVD/MOVQ xmm, r/m32/64.
                in.dst = xmm;
                in.dst.size = is_q ? 64 : 32;
                in.src = other;
                in.src.size = is_q ? 64 : 32;
            } else if (sec == 0x7E && movqRegForm) {
                // F3 0F 7E: MOVQ xmm, xmm/m64.
                in.dst = xmm;
                in.dst.size = 64;
                in.src = other;
                in.src.size = 64;
            } else if (sec == 0x7E) {
                // MOVD/MOVQ r/m32/64, xmm.
                in.dst = other;
                in.dst.size = is_q ? 64 : 32;
                in.src = xmm;
                in.src.size = is_q ? 64 : 32;
            } else if (sec == 0xEF) {
                in.dst = xmm;
                in.src = other;
            } else if (to_xmm) {
                in.dst = xmm;
                in.src = other;
            } else {
                in.dst = other;
                in.src = xmm;
            }
            const char* mn = sec == 0x6E ? "movd" : sec == 0x7E ? "movq" :
                             sec == 0xEF ? "pxor" :
                             to_xmm ? "sse_load" : "sse_store";
            return finish(sec == 0x6E || sec == 0x7E ? X86Op::MOVD :
                          sec == 0xEF ? X86Op::PXOR : X86Op::SSE_MOV, mn);
        }
        // ---- §2.17: packed / scalar SIMD, direct stores, far pointers ----

        // 00 /2,/3 — LLDT/LTR: load the local descriptor table or task register.
        // Both are CPL-0 operations, so a CPL-3 guest takes #GP(0).
        if (sec == 0x00 && i < len) {
            uint8_t modrm = data[i++];
            const int ext = modrmReg(modrm);
            // §2.20 — /0 SLDT and /1 STR read the selector of the local
            // descriptor table / task register; /4,/5 VERR/VERW test whether
            // a selector is readable/writable.
            if (ext == 0 || ext == 1) {
                if (modrmMod(modrm) == 3) {
                    in.dst.kind = OperandKind::REG;
                    in.dst.reg = modrmRm(modrm) + rex_b;
                    in.dst.size = in.rex_w ? 64 : (in.o16 ? 16 : 32);
                } else {
                    Operand m;
                    m.size = 16;
                    parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
                    in.dst = m;
                }
                return finish(ext == 0 ? X86Op::SLDT : X86Op::STR,
                              ext == 0 ? "sldt" : "str");
            }
            if (ext == 4 || ext == 5) {
                Operand s;
                s.size = 16;
                parseRm(data, len, i, modrm, rex_b, rex_x, s);
                in.src = s;
                return finish(ext == 4 ? X86Op::VERR : X86Op::VERW,
                              ext == 4 ? "verr" : "verw");
            }
            if (ext == 2 || ext == 3) {
                Operand m;
                m.size = 16;
                parseRm(data, len, i, modrm, rex_b, rex_x, m);
                in.src = m;
                return finish(ext == 2 ? X86Op::LLDT : X86Op::LTR,
                              ext == 2 ? "lldt" : "ltr");
            }
        }

        // 03 — LSL r32/r64, r/m16: segment limit, same selector rules as LAR.
        if (sec == 0x03 && i < len) {
            uint8_t modrm = data[i++];
            in.dst.kind = OperandKind::REG;
            in.dst.reg = modrmReg(modrm) + rex_r;
            in.dst.size = in.rex_w ? 64 : (in.o16 ? 16 : 32);
            Operand src;
            src.size = 16;
            parseRm(data, len, i, modrm, rex_b, rex_x, src);
            in.src = src;
            return finish(X86Op::LSL, "lsl");
        }

        // 20-23 — MOV to/from CR/DR. Control/debug registers are kernel state,
        // so the interpreter raises #GP(0); decoding keeps the length exact.
        if (sec >= 0x20 && sec <= 0x23 && i < len) {
            uint8_t modrm = data[i++];
            const bool to_gpr = (sec == 0x20 || sec == 0x21);
            in.dst.kind = OperandKind::REG;
            in.dst.reg = to_gpr ? (modrmRm(modrm) + rex_b) : (modrmReg(modrm) + rex_r);
            in.dst.size = 64;
            in.src.kind = OperandKind::REG;
            in.src.reg = to_gpr ? (modrmReg(modrm) + rex_r) : (modrmRm(modrm) + rex_b);
            in.src.size = 64;
            return finish(X86Op::MOVCR, sec <= 0x21 ? "mov from cr" : "mov to cr");
        }

        // 50 — MOVMSKPS/MOVMSKPD: gather the sign bits of each element.
        if (sec == 0x50 && i < len) {
            uint8_t modrm = data[i++];
            in.dst.kind = OperandKind::REG;
            in.dst.reg = modrmReg(modrm) + rex_r;
            in.dst.size = in.rex_w ? 64 : 32;
            Operand src;
            src.size = 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.src = src;
            return finish(in.o16 ? X86Op::MOVMSKPD : X86Op::MOVMSKPS,
                          in.o16 ? "movmskpd" : "movmskps");
        }

        // 56/59/5D/5F — ORPS/ORPD and the MUL/MIN/MAX families. The mandatory
        // prefix picks the form: none = PS, 66 = PD, F3 = SS, F2 = SD.
        if ((sec == 0x56 || sec == 0x59 || sec == 0x5D || sec == 0x5F) && i < len) {
            uint8_t modrm = data[i++];
            const bool scalar = in.rep || in.repne;
            const bool dbl = in.repne || in.o16;
            if (sec == 0x56 && scalar) return std::nullopt;   // no scalar OR form
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = scalar ? (dbl ? 64 : 32) : 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            X86Op op;
            const char* mn;
            if (sec == 0x56) {
                op = dbl ? X86Op::ORPD : X86Op::ORPS;
                mn = dbl ? "orpd" : "orps";
            } else if (sec == 0x59) {
                op = scalar ? (dbl ? X86Op::MULSD : X86Op::MULSS) : (dbl ? X86Op::MULPD : X86Op::MULPS);
                mn = scalar ? (dbl ? "mulsd" : "mulss") : (dbl ? "mulpd" : "mulps");
            } else if (sec == 0x5D) {
                op = scalar ? (dbl ? X86Op::MINSD : X86Op::MINSS) : (dbl ? X86Op::MINPD : X86Op::MINPS);
                mn = scalar ? (dbl ? "minsd" : "minss") : (dbl ? "minpd" : "minps");
            } else {
                op = scalar ? (dbl ? X86Op::MAXSD : X86Op::MAXSS) : (dbl ? X86Op::MAXPD : X86Op::MAXPS);
                mn = scalar ? (dbl ? "maxsd" : "maxss") : (dbl ? "maxpd" : "maxps");
            }
            return finish(op, mn);
        }

        // 63/67/6B — PACKSSWB/PACKUSWB/PACKSSDW (66). Element width in
        // dst.size: 16 = words packed to bytes, 32 = dwords packed to words.
        if (in.o16 && (sec == 0x63 || sec == 0x67 || sec == 0x6B) && i < len) {
            uint8_t modrm = data[i++];
            const int ebits = (sec == 0x6B) ? 32 : 16;
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = ebits;
            Operand src;
            src.size = 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            const bool us = (sec == 0x67);
            return finish(us ? X86Op::PACKUS : X86Op::PACKSS,
                          sec == 0x63 ? "packsswb" : sec == 0x67 ? "packuswb" : "packssdw");
        }

        // 74/75/76 — PCMPEQB/W/D (66): element widths 8/16/32.
        if (in.o16 && (sec == 0x74 || sec == 0x75 || sec == 0x76) && i < len) {
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = (sec == 0x74) ? 8 : (sec == 0x75) ? 16 : 32;
            Operand src;
            src.size = 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            return finish(X86Op::PCMPEQ, sec == 0x74 ? "pcmpeqb" :
                                          sec == 0x75 ? "pcmpeqw" : "pcmpeqd");
        }

        // DB/DF — PAND/PANDN (66).
        if (in.o16 && (sec == 0xDB || sec == 0xDF) && i < len) {
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = 128;
            Operand src;
            src.size = 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            return finish(sec == 0xDB ? X86Op::PAND : X86Op::PANDN,
                          sec == 0xDB ? "pand" : "pandn");
        }

        // E0/E3 — PAVGB/PAVGW (66).
        if (in.o16 && (sec == 0xE0 || sec == 0xE3) && i < len) {
            uint8_t modrm = data[i++];
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = (sec == 0xE0) ? 8 : 16;
            Operand src;
            src.size = 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            return finish(X86Op::PAVG, sec == 0xE0 ? "pavgb" : "pavgw");
        }

        // FC/FD/FE, D4, DC/DD, EC/ED — PADD/PADDS/PADDUS (66).
        if (in.o16 && (sec == 0xFC || sec == 0xFD || sec == 0xFE || sec == 0xD4 ||
                       sec == 0xDC || sec == 0xDD || sec == 0xEC || sec == 0xED) && i < len) {
            uint8_t modrm = data[i++];
            const int ebits = (sec == 0xFC || sec == 0xDC || sec == 0xEC) ? 8 :
                              (sec == 0xFD || sec == 0xDD || sec == 0xED) ? 16 :
                              (sec == 0xD4) ? 64 : 32;
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (modrmReg(modrm) + rex_r);
            xmm.size = ebits;
            Operand src;
            src.size = 128;
            parseSseRm(data, len, i, modrm, rex_b, rex_x, src);
            if (src.kind == OperandKind::REG) src.size = 128;
            in.dst = xmm;
            in.src = src;
            const X86Op op = (sec == 0xDC || sec == 0xDD) ? X86Op::PADDUS :
                             (sec == 0xEC || sec == 0xED) ? X86Op::PADDS : X86Op::PADD;
            const char* mn = sec == 0xFC ? "paddb" : sec == 0xFD ? "paddw" :
                             sec == 0xFE ? "paddd" : sec == 0xD4 ? "paddq" :
                             sec == 0xDC ? "paddusb" : sec == 0xDD ? "paddusw" :
                             sec == 0xEC ? "paddsb" : "paddsw";
            return finish(op, mn);
        }

        // F7 — MASKMOVDQU (66): masked byte store to [RDI], no write-back.
        if (sec == 0xF7 && in.o16 && i < len) {
            uint8_t modrm = data[i++];
            if (modrmMod(modrm) != 3) return std::nullopt;
            in.dst.kind = OperandKind::REG;
            in.dst.reg = 16 + (modrmReg(modrm) + rex_r);
            in.dst.size = 128;
            in.src.kind = OperandKind::REG;
            in.src.reg = 16 + (modrmRm(modrm) + rex_b);
            in.src.size = 128;
            return finish(X86Op::MASKMOVDQU, "maskmovdqu");
        }

        // 2B — MOVNTPS/MOVNTPD, E7 — MOVNTQ/MOVNTDQ: stores with a cache hint
        // that NINE does not model, so they execute as ordinary stores.
        if ((sec == 0x2B || sec == 0xE7) && i < len) {
            uint8_t modrm = data[i++];
            Operand m;
            m.size = (sec == 0x2B) ? 128 : (in.o16 ? 128 : 64);
            parseRm(data, len, i, modrm, rex_b, rex_x, m);
            in.dst = m;
            in.src.kind = OperandKind::REG;
            in.src.reg = 16 + (modrmReg(modrm) + rex_r);
            in.src.size = m.size;
            if (sec == 0x2B)
                return finish(in.o16 ? X86Op::MOVNTPD : X86Op::MOVNTPS,
                              in.o16 ? "movntpd" : "movntps");
            return finish(in.o16 ? X86Op::MOVNTDQ : X86Op::MOVNTQ,
                          in.o16 ? "movntdq" : "movntq");
        }

        // C3 — MOVNTI: non-temporal store of a GPR.
        if (sec == 0xC3 && i < len) {
            uint8_t modrm = data[i++];
            Operand m;
            m.size = opsize;
            parseRm(data, len, i, modrm, rex_b, rex_x, m);
            in.dst = m;
            in.src.kind = OperandKind::REG;
            in.src.reg = modrmReg(modrm) + rex_r;
            in.src.size = opsize;
            return finish(X86Op::MOVNTI, "movnti");
        }

        // B2/B4/B5 — LSS/LFS/LGS r16/32/64, m16:16/32/64.
        if ((sec == 0xB2 || sec == 0xB4 || sec == 0xB5) && i < len) {
            uint8_t modrm = data[i++];
            if (modrmMod(modrm) == 3) return std::nullopt;
            Operand m;
            m.size = in.rex_w ? 80 : 48;
            parseRmRest(data, len, i, modrm, rex_b, rex_x, m);
            in.dst.kind = OperandKind::REG;
            in.dst.reg = modrmReg(modrm) + rex_r;
            in.dst.size = in.rex_w ? 64 : (in.o16 ? 16 : 32);
            in.src = m;
            return finish(sec == 0xB2 ? X86Op::LSS : sec == 0xB4 ? X86Op::LFS : X86Op::LGS,
                          sec == 0xB2 ? "lss" : sec == 0xB4 ? "lfs" : "lgs");
        }

        if (sec == 0xB6 || sec == 0xB7 || sec == 0xBE || sec == 0xBF) {
            if (i >= len) return std::nullopt;
            uint8_t modrm = data[i++];
            int reg = modrmReg(modrm) + rex_r;
            int rm = modrmRm(modrm) + rex_b;
            int mod = modrmMod(modrm);
            int src_bits = (sec == 0xB6 || sec == 0xBE) ? 8 : 16;
            in.dst.kind = OperandKind::REG;
            in.dst.reg = reg;
            in.dst.size = in.rex_w ? 64 : 32;
            if (mod == 3) {
                in.src.kind = OperandKind::REG;
                in.src.reg = rm;
                in.src.size = src_bits;
                if (src_bits == 8) applyByteReg(in.src, rex);
            } else {
                in.src.kind = OperandKind::MEM;
                in.src.size = src_bits;
                in.src.mem.base = rm;
                if (mod == 0 && (rm & 7) == 5) { in.src.mem.rip_relative = true; in.src.mem.base = -1; }
                if ((rm & 7) == 4 && i < len) {
                    uint8_t sib = data[i++];
                    in.src.mem.base = (sib & 7) + rex_b;
                    int idx = (sib >> 3) & 7;
                    in.src.mem.index = (idx == 4 && !rex_x) ? -1 : idx + rex_x;
                    in.src.mem.scale = 1 << (sib >> 6);
                    if ((sib & 7) == 5 && mod == 0) in.src.mem.base = -1;
                }
                int disp = (mod == 1) ? 1 : (mod == 2 || in.src.mem.rip_relative || (in.src.mem.base < 0 && !in.src.mem.rip_relative)) ? 4 : 0;
                if (disp && i + disp <= len) {
                    int64_t d = 0;
                    for (int k = 0; k < disp; ++k) d |= static_cast<int64_t>(data[i + k]) << (8 * k);
                    if (disp == 1 && (d & 0x80)) d |= ~0xFFLL;
                    if (disp == 4 && (d & 0x80000000LL)) d |= ~0xFFFFFFFFLL;
                    in.src.mem.disp = d;
                    i += disp;
                }
            }
            return finish(sec == 0xB6 || sec == 0xB7 ? X86Op::MOVZX : X86Op::MOVSX,
                          sec == 0xB6 || sec == 0xB7 ? "movzx" : "movsx");
        }
    }

    // Fallback: consume one byte as invalid so the stream can continue
    in.op = X86Op::INVALID;
    in.length = static_cast<uint8_t>(std::max<size_t>(1, i));
    in.mnemonic = "invalid";
    return in;
}

std::vector<Insn> X86Decoder::decodeRange(const uint8_t* data, size_t len, uint64_t addr) {
    std::vector<Insn> out;
    size_t off = 0;
    while (off < len) {
        auto in = decode(data + off, len - off, addr + off);
        if (!in || in->length == 0) break;
        out.push_back(*in);
        if (in->op == X86Op::RET || in->op == X86Op::JMP || in->op == X86Op::SYSCALL) break;
        off += in->length;
    }
    return out;
}

} // namespace nexus




