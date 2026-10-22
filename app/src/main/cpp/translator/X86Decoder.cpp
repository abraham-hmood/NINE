#include "X86Decoder.h"
#include <algorithm>

namespace nexus {

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
    // VEX (C4 / C5)
    else if (data[i] == 0xC4 || data[i] == 0xC5) {
        has_vex = true;
        in.op = X86Op::VEX_OP;
        in.vex_l = 1;
        ++i;
        if (i < len && data[i - 1] == 0xC4) ++i; // 3-byte VEX
        if (i < len) ++i;
        in.length = static_cast<uint8_t>(i);
        in.mnemonic = "vex";
        return in;
    }
    // EVEX (62)
    else if (data[i] == 0x62) {
        in.op = X86Op::EVEX_OP;
        i = std::min(len, i + 4);
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

    // NOP / HLT
    if (opc == 0x90 && !rex && !in.o16) return finish(X86Op::NOP, "nop");
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
    if (opc == 0xF4) return finish(X86Op::UD2, "hlt"); // stop guest cleanly via exception path
    // String ops: STOS/LODS/MOVS/SCAS (AA-AF) — F3 = REP
    if (opc == 0xAA || opc == 0xAB) {
        in.dst.size = (opc == 0xAA) ? 8 : (in.rex_w ? 64 : (in.o16 ? 16 : 32));
        return finish(X86Op::STOS, opc == 0xAB ? (in.rex_w ? "stosq" : (in.o16 ? "stosw" : "stosd")) : "stosb");
    }
    if (opc == 0xAC || opc == 0xAD) {
        in.dst.kind = OperandKind::REG;
        in.dst.reg = 0; // AL / AX / EAX / RAX
        in.dst.size = (opc == 0xAC) ? 8 : (in.rex_w ? 64 : (in.o16 ? 16 : 32));
        return finish(X86Op::LODS, opc == 0xAC ? "lodsb" : (in.rex_w ? "lodsq" : (in.o16 ? "lodsw" : "lodsd")));
    }
    if (opc == 0xA4 || opc == 0xA5) {
        in.dst.size = (opc == 0xA4) ? 8 : (in.rex_w ? 64 : (in.o16 ? 16 : 32));
        return finish(X86Op::MOVS, opc == 0xA4 ? "movsb" : (in.rex_w ? "movsq" : (in.o16 ? "movsw" : "movsd")));
    }
    if (opc == 0xAE || opc == 0xAF) {
        in.dst.size = (opc == 0xAE) ? 8 : (in.rex_w ? 64 : (in.o16 ? 16 : 32));
        in.src.kind = OperandKind::REG;
        in.src.reg = 0; // AL / AX / EAX / RAX compared against [RDI]
        in.src.size = in.dst.size;
        return finish(X86Op::SCAS, opc == 0xAE ? "scasb" : (in.rex_w ? "scasq" : (in.o16 ? "scasw" : "scasd")));
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
        if (mod == 3) {
            in.dst.kind = OperandKind::REG;
            in.dst.reg = rm;
            in.dst.size = in.src.size;
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
    // SYSCALL
    if (opc == 0x0F && i < len && data[i] == 0x05) { ++i; return finish(X86Op::SYSCALL, "syscall"); }
    // INT3 / UD2
    if (opc == 0xCC) return finish(X86Op::INT3, "int3");
    if (opc == 0x0F && i < len && data[i] == 0x0B) { ++i; return finish(X86Op::UD2, "ud2"); }

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
        in.dst.kind = (mod == 3) ? OperandKind::REG : OperandKind::MEM;
        if (mod == 3) {
            in.dst.reg = rm;
            in.dst.size = opsize;
        } else {
            in.dst.size = opsize;
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
        in.src.size = opsize;
        const char* names[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
        return finish(op, names[reg & 7]);
    }

    // C6/C7 /0 MOV r/m, imm  (e.g. 48 C7 C7 imm32 = mov rdi, imm)
    if ((opc == 0xC6 || opc == 0xC7) && i < len) {
        uint8_t modrm = data[i++];
        int reg = modrmReg(modrm);
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
        in.dst = rmop;
        in.src = regop;
        return finish(X86Op::XCHG, "xchg");
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

    // CWDE/CBW/CDQE (98) and CDQ/CQO (99)
    if (opc == 0x98) {
        in.dst.kind = OperandKind::REG;
        in.dst.reg = 0;
        in.dst.size = in.o16 ? 32 : (in.rex_w ? 64 : 32);
        in.src.kind = OperandKind::REG;
        in.src.reg = 0;
        in.src.size = in.o16 ? 16 : (in.rex_w ? 32 : 8);
        return finish(X86Op::MOVSX, "cwde");
    }
    if (opc == 0x99) {
        in.dst.kind = OperandKind::REG;
        in.dst.reg = 2; // EDX/RDX = sign ext of EAX/RAX
        in.dst.size = opsize;
        in.src.kind = OperandKind::REG;
        in.src.reg = 0;
        in.src.size = opsize;
        return finish(X86Op::CDQ, "cdq");
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

        Operand regop;
        regop.kind = OperandKind::REG;
        regop.reg = reg;
        regop.size = opsize;

        Operand memop;
        if (mod == 3) {
            memop.kind = OperandKind::REG;
            memop.reg = rm;
            memop.size = opsize;
        } else {
            memop.kind = OperandKind::MEM;
            memop.size = opsize;
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
        static const X86Op sht[] = {X86Op::ROL, X86Op::ROR, X86Op::INVALID, X86Op::INVALID,
                                    X86Op::SHL, X86Op::SHR, X86Op::INVALID, X86Op::SAR};
        X86Op op = (reg < 8) ? sht[reg] : X86Op::INVALID;
        Operand rmop;
        rmop.size = (opc & 1) ? opsize : 8;
        parseRm(data, len, i, modrm, rex_b, rex_x, rmop);
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
                        op == X86Op::SAR ? "sar" : op == X86Op::ROL ? "rol" : "ror";
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
            return finish(X86Op::SETCC, "setcc");
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
            in.dst = rmop;
            in.src = regop;
            return finish(X86Op::CMPXCHG, "cmpxchg");
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
            ++i;
            return finish(X86Op::NOP, data[i - 1] == 0xFA ? "endbr64" : "endbr32");
        }
        // 0F 1E /0 RDSSP etc. — treat unknown 0F 1E forms as NOP to avoid hard faults
        if (sec == 0x1E) {
            if (i < len) ++i; // modrm
            return finish(X86Op::NOP, "nop1e");
        }
        // 0F AE fence / LFENCE etc. short forms — modrm based; treat as NOP for now
        if (sec == 0xAE && i < len) {
            ++i;
            return finish(X86Op::NOP, "fence");
        }
        // CPUID 0F A2
        if (sec == 0xA2) {
            return finish(X86Op::NOP, "cpuid"); // no-op until ABI fills leaf results
        }
        // 12/13 MOVLPS/MOVLPD, 16/17 MOVHPS/MOVHPD — 64-bit halves load/store
        if (sec == 0x12 || sec == 0x16) {
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
            return finish(sec == 0x12 ? X86Op::MOVLPS_LOAD : X86Op::MOVHPS_LOAD,
                          sec == 0x12 ? "movlps" : "movhps");
        }
        if (sec == 0x13 || sec == 0x17) {
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
            in.dst = other;
            in.src = xmm;
            return finish(sec == 0x13 ? X86Op::MOVLPS_STORE : X86Op::MOVHPS_STORE,
                          sec == 0x13 ? "movlps_store" : "movhps_store");
        }
        if (sec == 0xD6) { // MOVQ xmm -> r/m64 (66 required)
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
            in.dst = other;
            in.src = xmm;
            return finish(X86Op::SSE_MOV, "movq_store");
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
            bool is_q = (in.o16 || in.rep) && (sec == 0x6E || sec == 0x7E);
            Operand xmm;
            xmm.kind = OperandKind::REG;
            xmm.reg = 16 + (to_xmm ? (modrmReg(modrm) + rex_r)
                                   : (modrmRm(modrm) + rex_b));
            xmm.size = 128;
            Operand other;
            other.size = is_q ? 64 : (sec == 0xEF ? 128 : 32);
            parseRm(data, len, i, modrm, rex_b, rex_x, other);
            // For reg-reg SSE forms the parsed reg is an XMM register
            if (other.kind == OperandKind::REG) {
                other.reg = 16 + (other.reg & 0xF);
                other.size = sec == 0x6E || sec == 0x7E ? (is_q ? 64 : 32) : 128;
            }
            if (sec == 0x6E) {
                in.dst = xmm;
                in.dst.size = is_q ? 64 : 32;
                in.src = other;
            } else if (sec == 0x7E) {
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




