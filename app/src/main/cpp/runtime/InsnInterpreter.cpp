#include "InsnInterpreter.h"
#include "../diagnostics/Logger.h"
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>

namespace nexus {

void InsnInterpreter::syncFlags(GuestContext& ctx) {
    ctx.rflags = (ctx.rflags & ~0x8D5ULL) | (flags_.materialize() & 0x8D5ULL);
}

bool InsnInterpreter::loadMem(uint64_t addr, void* out, size_t n) {
    if (!mm_) { mem_fault_ = true; mem_fault_addr_ = addr; mem_fault_what_ = "no memory manager"; return false; }
    if (!mm_->isRangeAccessible(addr, n, PagePerm::READ)) {
        mem_fault_ = true; mem_fault_addr_ = addr; mem_fault_what_ = "read of unmapped page";
        return false;
    }
    void* host = mm_->guestToHost(addr);
    if (!host) {
        mem_fault_ = true; mem_fault_addr_ = addr; mem_fault_what_ = "load mapping";
        return false;
    }
    std::memcpy(out, host, n);
    return true;
}

bool InsnInterpreter::storeMem(uint64_t addr, const void* in, size_t n) {
    if (!mm_) { mem_fault_ = true; mem_fault_addr_ = addr; mem_fault_what_ = "no memory manager"; return false; }
    if (!mm_->isRangeAccessible(addr, n, PagePerm::WRITE)) {
        mem_fault_ = true; mem_fault_addr_ = addr; mem_fault_what_ = "write to non-writable page";
        return false;
    }
    void* host = mm_->guestToHost(addr);
    if (!host) {
        mem_fault_ = true; mem_fault_addr_ = addr; mem_fault_what_ = "store mapping";
        return false;
    }
    std::memcpy(host, in, n);
    if (smc_) smc_->onStore(addr, n);
    return true;
}

uint64_t InsnInterpreter::effectiveAddress(GuestContext& ctx, const MemOp& mem,
                                           uint64_t rip, int insn_len) {
    int64_t addr = mem.disp;
    if (mem.rip_relative) {
        addr += static_cast<int64_t>(rip + insn_len);
    } else {
        if (mem.base >= 0 && mem.base < 16)
            addr += static_cast<int64_t>(ctx.gpr[mem.base]);
        if (mem.index >= 0 && mem.index < 16)
            addr += static_cast<int64_t>(ctx.gpr[mem.index]) * mem.scale;
    }
    // Segment bases (TLS via FS, TCB head / vvar via GS in Linux guests)
    if (mem.seg == 1) addr += static_cast<int64_t>(ctx.fs_base);
    else if (mem.seg == 2) addr += static_cast<int64_t>(ctx.gs_base);
    return static_cast<uint64_t>(addr);
}

uint64_t InsnInterpreter::readOperand(GuestContext& ctx, const Operand& op, int size_bits) {
    if (size_bits <= 0) size_bits = op.size ? op.size : 64;
    switch (op.kind) {
        case OperandKind::REG:
            if (op.reg >= 0 && op.reg < 16)
                return maskSize(ctx.gpr[op.reg], size_bits);
            if (op.reg >= 16 && op.reg < 32) {
                uint64_t v = 0;
                std::memcpy(&v, ctx.ymm[op.reg - 16], std::min<size_t>(8, size_bits / 8));
                return v;
            }
            return 0;
        case OperandKind::IMM:
            return maskSize(static_cast<uint64_t>(op.imm), size_bits);
        case OperandKind::REL:
            return static_cast<uint64_t>(static_cast<int64_t>(ctx.rip) + op.imm);
        case OperandKind::MEM: {
            uint64_t ea = effectiveAddress(ctx, op.mem, ctx.rip, cur_insn_len_);
            uint64_t v = 0;
            size_t n = static_cast<size_t>((size_bits + 7) / 8);
            if (!loadMem(ea, &v, n)) return 0;
            return maskSize(v, size_bits);
        }
        default:
            return 0;
    }
}

void InsnInterpreter::writeOperand(GuestContext& ctx, const Operand& op,
                                   uint64_t value, int size_bits) {
    if (size_bits <= 0) size_bits = op.size ? op.size : 64;
    value = maskSize(value, size_bits);
    switch (op.kind) {
        case OperandKind::REG:
            if (op.reg >= 0 && op.reg < 16) {
                if (size_bits == 32)
                    ctx.gpr[op.reg] = value & 0xFFFFFFFFu;
                else if (size_bits == 64)
                    ctx.gpr[op.reg] = value;
                else if (size_bits == 16)
                    ctx.gpr[op.reg] = (ctx.gpr[op.reg] & ~0xFFFFu) | (value & 0xFFFFu);
                else if (size_bits == 8)
                    ctx.gpr[op.reg] = (ctx.gpr[op.reg] & ~0xFFu) | (value & 0xFFu);
            } else if (op.reg >= 16 && op.reg < 32) {
                std::memcpy(ctx.ymm[op.reg - 16], &value,
                            std::min<size_t>(8, size_bits / 8));
            }
            break;
        case OperandKind::MEM: {
            uint64_t ea = effectiveAddress(ctx, op.mem, ctx.rip, cur_insn_len_);
            size_t n = static_cast<size_t>((size_bits + 7) / 8);
            storeMem(ea, &value, n);
            break;
        }
        default:
            break;
    }
}

bool InsnInterpreter::evalCc(GuestContext& ctx, uint8_t c) {
    uint64_t rf = flags_.isLazy() ? flags_.materialize() : ctx.rflags;
    bool pf = (rf >> 2) & 1;
    bool cf = (rf >> 0) & 1;
    bool zf = (rf >> 6) & 1;
    bool sf = (rf >> 7) & 1;
    bool of = (rf >> 11) & 1;
    switch (c & 0xF) {
        case 0:  return of;               // O
        case 1:  return !of;              // NO
        case 2:  return cf;               // B
        case 3:  return !cf;              // AE
        case 4:  return zf;               // E
        case 5:  return !zf;              // NE
        case 6:  return cf || zf;         // BE
        case 7:  return !cf && !zf;       // A
        case 8:  return sf;               // S
        case 9:  return !sf;              // NS
        case 10: return pf;               // P
        case 11: return !pf;              // NP
        case 12: return sf != of;         // L
        case 13: return sf == of;         // GE
        case 14: return zf || (sf != of); // LE
        default: return !zf && (sf == of);// G
    }
}

bool InsnInterpreter::evalCondition(GuestContext& ctx, X86Op op) {
    switch (op) {
        case X86Op::JO:  return evalCc(ctx, 0);
        case X86Op::JNO: return evalCc(ctx, 1);
        case X86Op::JB:  return evalCc(ctx, 2);
        case X86Op::JAE: return evalCc(ctx, 3);
        case X86Op::JE:  return evalCc(ctx, 4);
        case X86Op::JNE: return evalCc(ctx, 5);
        case X86Op::JBE: return evalCc(ctx, 6);
        case X86Op::JA:  return evalCc(ctx, 7);
        case X86Op::JS:  return evalCc(ctx, 8);
        case X86Op::JNS: return evalCc(ctx, 9);
        case X86Op::JL:  return evalCc(ctx, 12);
        case X86Op::JGE: return evalCc(ctx, 13);
        case X86Op::JLE: return evalCc(ctx, 14);
        case X86Op::JG:  return evalCc(ctx, 15);
        default: return evalCc(ctx, 5);
    }
}

InterpResult InsnInterpreter::execute(GuestContext& ctx, const Insn& in) {
    InterpResult r;
    r.next_pc = ctx.rip + in.length;
    cur_insn_len_ = in.length;
    int bits = in.dst.size ? in.dst.size : (in.rex_w ? 64 : 32);
    if (bits <= 0) bits = 64;

    {
        trace_.emplace_back(ctx.rip, in.mnemonic);
        if (trace_.size() > kTraceCap) trace_.erase(trace_.begin());
    }

    switch (in.op) {
        case X86Op::NOP:
            ctx.rip = r.next_pc;
            return r;

        case X86Op::MOV: {
            uint64_t v = readOperand(ctx, in.src, bits);
            writeOperand(ctx, in.dst, v, bits);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::MOVZX: {
            int src_bits = in.src.size ? in.src.size : 8;
            uint64_t v = readOperand(ctx, in.src, src_bits);
            writeOperand(ctx, in.dst, v, bits);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::MOVSX: {
            int src_bits = in.src.size ? in.src.size : 8;
            uint64_t v = signExtend(readOperand(ctx, in.src, src_bits), src_bits);
            writeOperand(ctx, in.dst, v, bits);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::LEA: {
            uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, in.length);
            writeOperand(ctx, in.dst, ea, 64);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::ADD: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t res = maskSize(a + b, bits);
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromAdd(res, a, b, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::ADC: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t c = (flags_.isLazy() ? flags_.materialize() : ctx.rflags) & 1;
            unsigned __int128 full =
                (unsigned __int128)a + b + c;
            uint64_t res = maskSize(static_cast<uint64_t>(full), bits);
            uint64_t cf = static_cast<uint64_t>(full >> bits) & 1;
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromAdd(res, a, b, static_cast<uint8_t>(bits));
            uint64_t rf = flags_.materialize();
            rf &= ~1ULL;
            if (cf) rf |= 1;
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SBB: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t c = (flags_.isLazy() ? flags_.materialize() : ctx.rflags) & 1;
            int64_t sa = static_cast<int64_t>(signExtend(a, bits));
            int64_t sb = static_cast<int64_t>(signExtend(b, bits));
            int64_t full = sa - sb - static_cast<int64_t>(c);
            uint64_t res = maskSize(static_cast<uint64_t>(full), bits);
            uint64_t cf = full < 0 ? 1 : 0;
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromSub(res, a, b, static_cast<uint8_t>(bits));
            uint64_t rf = flags_.materialize();
            rf &= ~1ULL;
            if (cf) rf |= 1;
            flags_.setRaw(rf);
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SUB:
        case X86Op::CMP: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t res = maskSize(a - b, bits);
            if (in.op == X86Op::SUB) writeOperand(ctx, in.dst, res, bits);
            flags_.setFromSub(res, a, b, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::AND:
        case X86Op::TEST: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t res = maskSize(a & b, bits);
            if (in.op == X86Op::AND) writeOperand(ctx, in.dst, res, bits);
            flags_.setFromLogic(res, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::OR: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t res = maskSize(a | b, bits);
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromLogic(res, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::XOR: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t res = maskSize(a ^ b, bits);
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromLogic(res, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::INC: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t res = maskSize(a + 1, bits);
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromAdd(res, a, 1, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::DEC: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t res = maskSize(a - 1, bits);
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromSub(res, a, 1, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::NEG: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t res = maskSize(~a + 1, bits);
            writeOperand(ctx, in.dst, res, bits);
            flags_.setFromSub(res, 0, a, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::NOT: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            writeOperand(ctx, in.dst, maskSize(~a, bits), bits);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SHL: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t c = readOperand(ctx, in.src, 8) & (bits == 64 ? 63u : 31u);
            uint64_t res = maskSize(a << c, bits);
            writeOperand(ctx, in.dst, res, bits);
            if (c) { flags_.setFromLogic(res, static_cast<uint8_t>(bits)); syncFlags(ctx); }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SHR: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t c = readOperand(ctx, in.src, 8) & (bits == 64 ? 63u : 31u);
            uint64_t res = maskSize(a >> c, bits);
            writeOperand(ctx, in.dst, res, bits);
            if (c) { flags_.setFromLogic(res, static_cast<uint8_t>(bits)); syncFlags(ctx); }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SAR: {
            int64_t a = static_cast<int64_t>(signExtend(readOperand(ctx, in.dst, bits), bits));
            uint64_t c = readOperand(ctx, in.src, 8) & (bits == 64 ? 63u : 31u);
            uint64_t res = maskSize(static_cast<uint64_t>(a >> static_cast<int>(c)), bits);
            writeOperand(ctx, in.dst, res, bits);
            if (c) { flags_.setFromLogic(res, static_cast<uint8_t>(bits)); syncFlags(ctx); }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::MUL: case X86Op::IMUL: {
            if (in.src.kind != OperandKind::NONE) {
                int64_t a, b;
                if (in.src2.kind == OperandKind::IMM) {
                    // IMUL r, r/m, imm (69/6B): dest register NOT multiplied in
                    a = static_cast<int64_t>(signExtend(readOperand(ctx, in.src, bits), bits));
                    b = in.src2.imm;
                } else {
                    // IMUL r, r/m (0F AF): signed multiply
                    a = static_cast<int64_t>(signExtend(readOperand(ctx, in.dst, bits), bits));
                    b = static_cast<int64_t>(signExtend(readOperand(ctx, in.src, bits), bits));
                }
                int64_t res = a * b;
                writeOperand(ctx, in.dst, static_cast<uint64_t>(res), bits);
                flags_.setFromLogic(static_cast<uint64_t>(res), static_cast<uint8_t>(bits));
            } else {
                // one-operand form (F7 /4 MUL, /5 IMUL): RDX:RAX = RAX * r/m
                unsigned __int128 prod;
                if (in.op == X86Op::MUL) {
                    unsigned __int128 a = maskSize(ctx.rax(), bits);
                    unsigned __int128 b = maskSize(readOperand(ctx, in.dst, bits), bits);
                    prod = a * b;
                } else {
                    __int128 a = static_cast<__int128>(static_cast<int64_t>(signExtend(ctx.rax(), bits)));
                    __int128 b = static_cast<__int128>(static_cast<int64_t>(signExtend(readOperand(ctx, in.dst, bits), bits)));
                    prod = static_cast<unsigned __int128>(a * b);
                }
                uint64_t lo = static_cast<uint64_t>(prod);
                uint64_t hi = static_cast<uint64_t>(prod >> 64);
                if (bits == 8) {
                    ctx.rax() = (ctx.rax() & ~0xFFFFull) | (lo & 0xFF) | ((hi & 0xFF) << 8);
                } else if (bits == 16) {
                    ctx.rax() = (ctx.rax() & ~0xFFFFull) | (lo & 0xFFFF);
                    ctx.rdx() = (ctx.rdx() & ~0xFFFFull) | (hi & 0xFFFF);
                } else if (bits == 32) {
                    ctx.rax() = static_cast<uint32_t>(lo);
                    ctx.rdx() = static_cast<uint32_t>(hi);
                } else {
                    ctx.rax() = lo;
                    ctx.rdx() = hi;
                }
            }
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::DIV: case X86Op::IDIV: {
            // one-operand: (RDX:RAX) / r/m -> quotient RAX, remainder RDX
            const bool sgnd = (in.op == X86Op::IDIV);
            uint64_t den = maskSize(readOperand(ctx, in.dst, bits), bits);
            if (den == 0) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000094;
                r.exception_msg = sgnd ? "idiv: divide by zero" : "div: divide by zero";
                return r;
            }
            if (bits == 8) {
                uint16_t n = static_cast<uint16_t>(ctx.rax() & 0xFFFF);
                if (sgnd) {
                    int16_t ns = static_cast<int8_t>(n & 0xFF);
                    int16_t ds = static_cast<int8_t>(den);
                    int16_t q = static_cast<int16_t>(ns / ds);
                    int16_t rem = static_cast<int16_t>(ns % ds);
                    if (q < -128 || q > 127) {
                        r.exit = InterpExit::EXCEPTION;
                        r.exception_code = 0xC0000094;
                        r.exception_msg = "idiv: quotient overflow";
                        return r;
                    }
                    ctx.rax() = (ctx.rax() & ~0xFFFFull) |
                                static_cast<uint16_t>(static_cast<uint8_t>(q)) |
                                (static_cast<uint16_t>(static_cast<uint8_t>(rem)) << 8);
                } else {
                    uint16_t q = static_cast<uint16_t>(n / den);
                    uint16_t rem = static_cast<uint16_t>(n % den);
                    if (q > 0xFF) {
                        r.exit = InterpExit::EXCEPTION;
                        r.exception_code = 0xC0000094;
                        r.exception_msg = "div: quotient overflow";
                        return r;
                    }
                    ctx.rax() = (ctx.rax() & ~0xFFFFull) | q | (rem << 8);
                }
            } else {
                uint64_t mask = (bits == 16) ? 0xFFFFull : (bits == 32) ? 0xFFFFFFFFull : ~0ull;
                uint64_t hi = ctx.rdx() & mask;
                uint64_t lo = ctx.rax() & mask;
                auto sext = [&](uint64_t v) -> __int128 {
                    int shift = 64 - bits;
                    return static_cast<__int128>(static_cast<int64_t>(v << shift) >> shift);
                };
                if (sgnd) {
                    __int128 n = (sext(hi) << bits) | static_cast<__int128>(lo);
                    __int128 d = sext(den);
                    __int128 q = n / d;
                    __int128 rem = n % d;
                    __int128 qmin = static_cast<__int128>(1) << (bits - 1);
                    if (q < -qmin || q >= qmin) {
                        r.exit = InterpExit::EXCEPTION;
                        r.exception_code = 0xC0000094;
                        r.exception_msg = "idiv: quotient overflow";
                        return r;
                    }
                    ctx.rax() = static_cast<uint64_t>(q) & mask;
                    ctx.rdx() = static_cast<uint64_t>(rem) & mask;
                } else {
                    unsigned __int128 n = (static_cast<unsigned __int128>(hi) << bits) | lo;
                    unsigned __int128 d = den;
                    unsigned __int128 q = n / d;
                    if (q > static_cast<unsigned __int128>(mask)) {
                        r.exit = InterpExit::EXCEPTION;
                        r.exception_code = 0xC0000094;
                        r.exception_msg = "div: quotient overflow";
                        return r;
                    }
                    ctx.rax() = static_cast<uint64_t>(q) & mask;
                    ctx.rdx() = static_cast<uint64_t>(n % d) & mask;
                }
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::PUSH: {
            const Operand& src = in.src.kind != OperandKind::NONE ? in.src : in.dst;
            uint64_t v = readOperand(ctx, src, 64);
            ctx.rsp() -= 8;
            if (!storeMem(ctx.rsp(), &v, 8)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "push: stack fault";
                return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::POP: {
            uint64_t v = 0;
            if (!loadMem(ctx.rsp(), &v, 8)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "pop: stack fault";
                return r;
            }
            ctx.rsp() += 8;
            const Operand& dst = in.dst.kind != OperandKind::NONE ? in.dst : in.src;
            writeOperand(ctx, dst, v, 64);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::LEAVE: {
            ctx.rsp() = ctx.rbp();
            uint64_t v = 0;
            if (!loadMem(ctx.rsp(), &v, 8)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "leave: stack fault";
                return r;
            }
            ctx.rsp() += 8;
            ctx.rbp() = v;
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::JMP: {
            if (in.src.kind == OperandKind::REL || in.dst.kind == OperandKind::REL) {
                // Decoder stores absolute target in .imm
                const Operand& rel = in.src.kind == OperandKind::REL ? in.src : in.dst;
                r.next_pc = static_cast<uint64_t>(rel.imm);
            } else {
                const Operand& t = in.src.kind != OperandKind::NONE ? in.src : in.dst;
                r.next_pc = readOperand(ctx, t, 64);
            }
            ctx.rip = r.next_pc;
            r.exit = InterpExit::BLOCK_END;
            return r;
        }

        case X86Op::JE: case X86Op::JNE: case X86Op::JL: case X86Op::JLE:
        case X86Op::JG: case X86Op::JGE: case X86Op::JB: case X86Op::JBE:
        case X86Op::JA: case X86Op::JAE: case X86Op::JS: case X86Op::JNS:
        case X86Op::JO: case X86Op::JNO: {
            const Operand& rel = in.src.kind == OperandKind::REL ? in.src :
                                 (in.dst.kind == OperandKind::REL ? in.dst : in.src);
            if (evalCondition(ctx, in.op)) {
                r.next_pc = static_cast<uint64_t>(rel.imm); // absolute target from decoder
            } else {
                r.next_pc = ctx.rip + in.length;
            }
            ctx.rip = r.next_pc;
            r.exit = InterpExit::BLOCK_END;
            return r;
        }

        case X86Op::CALL: {
            uint64_t ret_addr = ctx.rip + in.length;
            ctx.rsp() -= 8;
            if (!storeMem(ctx.rsp(), &ret_addr, 8)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "call: stack fault";
                return r;
            }
            if (in.src.kind == OperandKind::REL || in.dst.kind == OperandKind::REL) {
                const Operand& rel = in.src.kind == OperandKind::REL ? in.src : in.dst;
                r.next_pc = static_cast<uint64_t>(rel.imm); // absolute
            } else {
                const Operand& t = in.src.kind != OperandKind::NONE ? in.src : in.dst;
                r.next_pc = readOperand(ctx, t, 64);
            }
            ctx.rip = r.next_pc;
            r.exit = InterpExit::BLOCK_END;
            return r;
        }

        case X86Op::RET: {
            uint64_t ret = 0;
            if (!loadMem(ctx.rsp(), &ret, 8)) {
                r.exit = InterpExit::EXCEPTION;
                r.exception_code = 0xC0000005;
                r.exception_msg = "ret: stack fault";
                return r;
            }
            ctx.rsp() += 8;
            if (in.src.kind == OperandKind::IMM)
                ctx.rsp() += static_cast<uint64_t>(in.src.imm);
            ctx.rip = ret;
            r.next_pc = ret;
            r.exit = InterpExit::BLOCK_END;
            return r;
        }


        case X86Op::STOS: {
            // STOSB/W/D/Q: store AL/AX/EAX/RAX to [RDI], ±1/2/4/8 RDI; REP uses RCX
            int size = (in.dst.size == 8) ? 1 : (in.dst.size == 16) ? 2 : (in.dst.size == 32) ? 4 : 8;
            auto do_one = [&]() {
                uint64_t val = (size == 8) ? ctx.rax() : maskSize(ctx.rax(), size);
                uint64_t di = ctx.rdi();
                if (!storeMem(di, &val, static_cast<size_t>(size))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "stos fault";
                    return false;
                }
                bool df = (ctx.rflags & (1ULL << 10)) != 0;
                ctx.rdi() = di + (df ? -size : size);
                return true;
            };
            if (in.rep) {
                while (ctx.rcx() != 0) {
                    if (!do_one()) return r;
                    ctx.rcx() -= 1;
                }
            } else {
                if (!do_one()) return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }
        case X86Op::LODS: {
            int size = (in.dst.size == 8) ? 1 : (in.dst.size == 16) ? 2 : (in.dst.size == 32 ? 4 : 8);
            auto do_one = [&]() {
                uint64_t val = 0;
                uint64_t si = ctx.rsi();
                if (!loadMem(si, &val, static_cast<size_t>(size))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "lods fault";
                    return false;
                }
                writeOperand(ctx, in.dst, val, size);
                bool df = (ctx.rflags & (1ULL << 10)) != 0;
                ctx.rsi() = si + (df ? -size : size);
                return true;
            };
            if (in.rep) {
                while (ctx.rcx() != 0) {
                    if (!do_one()) return r;
                    ctx.rcx() -= 1;
                }
            } else {
                if (!do_one()) return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }
        case X86Op::MOVS: {
            int size = (in.dst.size == 8) ? 1 : (in.dst.size == 16) ? 2 : (in.dst.size == 32 ? 4 : 8);
            auto do_one = [&]() {
                uint64_t val = 0;
                uint64_t si = ctx.rsi();
                uint64_t di = ctx.rdi();
                if (!loadMem(si, &val, static_cast<size_t>(size))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "movs load fault";
                    return false;
                }
                if (!storeMem(di, &val, static_cast<size_t>(size))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "movs store fault";
                    return false;
                }
                bool df = (ctx.rflags & (1ULL << 10)) != 0;
                ctx.rsi() = si + (df ? -size : size);
                ctx.rdi() = di + (df ? -size : size);
                return true;
            };
            if (in.rep) {
                while (ctx.rcx() != 0) {
                    if (!do_one()) return r;
                    ctx.rcx() -= 1;
                }
            } else {
                if (!do_one()) return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }
        case X86Op::SCAS: {
            int size = (in.dst.size == 8) ? 1 : (in.dst.size == 16) ? 2 : (in.dst.size == 32 ? 4 : 8);
            auto do_one = [&]() {
                uint64_t val = 0;
                uint64_t di = ctx.rdi();
                if (!loadMem(di, &val, static_cast<size_t>(size))) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "scas fault";
                    return false;
                }
                uint64_t al = readOperand(ctx, in.src, size);
                uint64_t res = maskSize(al - val, size);
                flags_.setFromSub(res, al, val, static_cast<uint8_t>(size));
                syncFlags(ctx);
                bool df = (ctx.rflags & (1ULL << 10)) != 0;
                ctx.rdi() = di + (df ? -size : size);
                return true;
            };
            if (in.rep) {
                while (ctx.rcx() != 0) {
                    if (!do_one()) return r;
                    if (flags_.isZero()) break; // REPNE/REPE logic usually depends on flags
                    ctx.rcx() -= 1;
                }
            } else {
                if (!do_one()) return r;
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::XCHG: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            writeOperand(ctx, in.dst, b, bits);
            writeOperand(ctx, in.src, a, bits);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CMPXCHG: {
            // cmpxchg r/m, r: compare acc (AL/AX/EAX/RAX) with r/m
            Operand acc_op;
            acc_op.kind = OperandKind::REG;
            acc_op.reg = 0;
            acc_op.size = bits;
            uint64_t acc = readOperand(ctx, acc_op, bits);
            uint64_t rm = readOperand(ctx, in.dst, bits);
            uint64_t res = maskSize(rm - acc, bits);
            flags_.setFromSub(res, rm, acc, static_cast<uint8_t>(bits));
            if (res == 0) {
                writeOperand(ctx, in.dst, readOperand(ctx, in.src, bits), bits);
            } else {
                writeOperand(ctx, in.src, rm, bits);
            }
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::XADD: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t b = readOperand(ctx, in.src, bits);
            uint64_t res = maskSize(a + b, bits);
            writeOperand(ctx, in.dst, res, bits);
            writeOperand(ctx, in.src, a, bits);
            flags_.setFromAdd(res, a, b, static_cast<uint8_t>(bits));
            syncFlags(ctx);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CDQ: {
            // CDQ/CQO: RDX = sign fill of RAX at src width
            int w = in.src.size ? in.src.size : 32;
            uint64_t v = maskSize(ctx.rax(), w);
            if (w == 32)
                ctx.rdx() = (v & 0x80000000ULL) ? 0xFFFFFFFFULL : 0;
            else if (w == 64)
                ctx.rdx() = (v & (1ULL << 63)) ? ~0ULL : 0;
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::ROL: case X86Op::ROR: {
            uint64_t a = readOperand(ctx, in.dst, bits);
            uint64_t c = readOperand(ctx, in.src, 8) & (bits == 64 ? 63u : 31u);
            if (c) {
                int sh = static_cast<int>(c % static_cast<uint64_t>(bits));
                uint64_t res;
                if (in.op == X86Op::ROL)
                    res = maskSize((a << sh) | (a >> (bits - sh)), bits);
                else
                    res = maskSize((a >> sh) | (a << (bits - sh)), bits);
                writeOperand(ctx, in.dst, res, bits);
                // CF/OF per rotate definition; keep other flags
                uint64_t rf = flags_.materialize();
                uint64_t cf = (in.op == X86Op::ROL) ? (res & 1)
                                                    : ((res >> (bits - 1)) & 1);
                uint64_t of = (in.op == X86Op::ROL)
                    ? ((res >> (bits - 1)) & 1) ^ cf
                    : (((res >> (bits - 1)) ^ (res >> (bits - 2))) & 1);
                rf &= ~(1ULL << 0);
                if (cf) rf |= 1ULL << 0;
                rf &= ~(1ULL << 11);
                if (of) rf |= 1ULL << 11;
                flags_.setRaw(rf);
                syncFlags(ctx);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::CMOV: {
            if (evalCc(ctx, in.cc)) {
                uint64_t v = readOperand(ctx, in.src, bits);
                writeOperand(ctx, in.dst, v, bits);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SETCC: {
            writeOperand(ctx, in.dst, evalCc(ctx, in.cc) ? 1 : 0, 8);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::MOVD: {
            // Decoder encodes direction via operand sizes/kinds:
            // reg(16+) dst + imm/mem/reg src = load; mem dst = store.
            int n = in.dst.size ? in.dst.size : 64;
            auto set_xmm = [&](int reg, uint64_t v) {
                uint64_t z = 0;
                std::memcpy(ctx.ymm[reg - 16], &z, 8);   // MOVD clears upper bits
                std::memcpy(ctx.ymm[reg - 16], &v, n / 8);
            };
            if (in.dst.kind == OperandKind::REG && in.dst.reg >= 16) {
                uint64_t v;
                if (in.src.kind == OperandKind::REG && in.src.reg >= 16) {
                    std::memcpy(&v, ctx.ymm[in.src.reg - 16], n / 8);
                } else {
                    v = readOperand(ctx, in.src, n);
                }
                set_xmm(in.dst.reg, v);
            } else {
                // store: dst = mem/gpr, src = xmm
                uint64_t v = 0;
                std::memcpy(&v, ctx.ymm[in.src.reg - 16], n / 8);
                writeOperand(ctx, in.dst, v, n);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SSE_MOV: {
            // 128-bit move: xmm <-> mem, or xmm <-> xmm
            if (in.dst.kind == OperandKind::REG && in.dst.reg >= 16) {
                if (in.src.kind == OperandKind::MEM) {
                    uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, in.length);
                    uint8_t buf[16]{};
                    if (!loadMem(ea, buf, 16)) {
                        r.exit = InterpExit::EXCEPTION;
                        r.exception_code = 0xC0000005;
                        r.exception_msg = "sse load fault";
                        return r;
                    }
                    std::memcpy(ctx.ymm[in.dst.reg - 16], buf, 16);
                } else if (in.src.kind == OperandKind::REG && in.src.reg >= 16) {
                    std::memcpy(ctx.ymm[in.dst.reg - 16], ctx.ymm[in.src.reg - 16], 16);
                }
            } else {
                // store xmm -> mem/reg (16-byte or 8-byte MOVQ store)
                size_t n = (in.dst.size && in.dst.size <= 64) ? in.dst.size / 8 : 16;
                if (in.dst.kind == OperandKind::MEM) {
                    uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
                    if (!storeMem(ea, ctx.ymm[in.src.reg - 16], n)) {
                        r.exit = InterpExit::EXCEPTION;
                        r.exception_code = 0xC0000005;
                        r.exception_msg = "sse store fault";
                        return r;
                    }
                } else if (in.dst.kind == OperandKind::REG && in.dst.reg >= 16) {
                    int d = in.dst.reg - 16, s = in.src.reg - 16;
                    if (d != s) std::memcpy(ctx.ymm[d], ctx.ymm[s], 16);
                }
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::PXOR: {
            // dst ^= src over all 128 bits
            int dreg = in.dst.reg - 16, sreg = in.src.reg - 16;
            if (dreg != sreg) {
                uint64_t tmp[2];
                std::memcpy(tmp, ctx.ymm[sreg], 16);
                uint64_t* d = reinterpret_cast<uint64_t*>(ctx.ymm[dreg]);
                d[0] ^= tmp[0];
                d[1] ^= tmp[1];
            } else {
                std::memset(ctx.ymm[dreg], 0, 16);
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::PUNPCKLDQ: {
            // PUNPCKLDQ: preserves dwords 0/1 of dst, interleaves src low dwords
            int dreg = in.dst.reg - 16, sreg = in.src.reg - 16;
            uint64_t dst0, dst1, src0, src1;
            std::memcpy(&dst0, &ctx.ymm[dreg], 8);
            std::memcpy(&dst1, &ctx.ymm[dreg] + 8, 8);
            std::memcpy(&src0, &ctx.ymm[sreg], 8);
            std::memcpy(&src1, &ctx.ymm[sreg] + 8, 8);
            uint64_t lo = (src0 & 0xFFFFFFFF) << 32 | (dst0 & 0xFFFFFFFF);
            uint64_t hi = (src1 & 0xFFFFFFFF) << 32 | (dst1 & 0xFFFFFFFF);
            std::memcpy(ctx.ymm[dreg], &lo, 8);
            std::memcpy(ctx.ymm[dreg] + 8, &hi, 8);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::PUNPCKLQDQ: case X86Op::PUNPCKHQDQ: {
            int dreg = in.dst.reg - 16, sreg = in.src.reg - 16;
            uint64_t dst0, dst1, src0, src1;
            std::memcpy(&dst0, &ctx.ymm[dreg], 8);
            std::memcpy(&dst1, ctx.ymm[dreg] + 8, 8);
            std::memcpy(&src0, &ctx.ymm[sreg], 8);
            std::memcpy(&src1, ctx.ymm[sreg] + 8, 8);
            uint64_t lo, hi;
            if (in.op == X86Op::PUNPCKLQDQ) { lo = dst0; hi = src0; }
            else { lo = dst1; hi = src1; }
            std::memcpy(ctx.ymm[dreg], &lo, 8);
            std::memcpy(ctx.ymm[dreg] + 8, &hi, 8);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::MOVLPS_LOAD: case X86Op::MOVHPS_LOAD: {
            int d = in.dst.reg - 16;
            uint8_t tmp[8];
            int off = (in.op == X86Op::MOVHPS_LOAD) ? 8 : 0;
            if (in.src.kind == OperandKind::MEM) {
                uint64_t ea = effectiveAddress(ctx, in.src.mem, ctx.rip, in.length);
                if (!loadMem(ea, tmp, 8)) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "fault";
                    return r;
                }
            } else if (in.src.kind == OperandKind::REG && in.src.reg >= 16) {
                std::memcpy(tmp, ctx.ymm[in.src.reg - 16] + off, 8);
            } else {
                return InterpResult{};
            }
            std::memcpy(ctx.ymm[d] + off, tmp, 8);
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::MOVLPS_STORE: case X86Op::MOVHPS_STORE: {
            int s = in.src.reg - 16;
            int off = (in.op == X86Op::MOVHPS_STORE) ? 8 : 0;
            uint8_t tmp[8];
            std::memcpy(tmp, ctx.ymm[s] + off, 8);
            if (in.dst.kind == OperandKind::MEM) {
                uint64_t ea = effectiveAddress(ctx, in.dst.mem, ctx.rip, in.length);
                if (!storeMem(ea, tmp, 8)) {
                    r.exit = InterpExit::EXCEPTION;
                    r.exception_code = 0xC0000005;
                    r.exception_msg = "fault";
                    return r;
                }
            }
            ctx.rip = r.next_pc;
            return r;
        }

        case X86Op::SYSCALL: {
            r.exit = InterpExit::SYSCALL;
            r.syscall_nr = static_cast<int64_t>(ctx.rax());
            r.next_pc = ctx.rip + in.length;
            return r;
        }

        case X86Op::INT3:
        case X86Op::UD2: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0x80000003;
            r.exception_msg = in.op == X86Op::INT3 ? "int3" : "ud2";
            return r;
        }

        case X86Op::INVALID:
        default: {
            r.exit = InterpExit::EXCEPTION;
            r.exception_code = 0xC000001D;
            r.exception_msg = std::string("unimplemented: ") + in.mnemonic;
            return r;
        }
    }
}

InterpResult InsnInterpreter::executeBlock(GuestContext& ctx, const uint8_t* code, size_t len,
                                           uint64_t max_insns) {
    InterpResult last;
    for (uint64_t i = 0; i < max_insns; ++i) {
        if (!code || len == 0) {
            last.exit = InterpExit::EXCEPTION;
            last.exception_code = 0xC0000005;
            last.exception_msg = "no code bytes";
            last.next_pc = ctx.rip;
            return last;
        }
        auto in = X86Decoder::decode(code, len, ctx.rip);
        if (!in || in->length == 0) {
            last.exit = InterpExit::EXCEPTION;
            last.exception_code = 0xC000001D;
            last.exception_msg = "decode failed";
            last.next_pc = ctx.rip;
            return last;
        }
        last = execute(ctx, *in);
        if (mem_fault_) {
            // A load/store inside a handler failed — surface it (prevents
            // silent corruption racing through linear interpretation).
            last = InterpResult{};
            last.exit = InterpExit::EXCEPTION;
            last.exception_code = 0xC0000005;
            std::string msg = std::string("memory fault (") + mem_fault_what_ +
                              ") ea=0x" +
                              [&]{std::ostringstream o;o<<std::hex<<mem_fault_addr_;return o.str();}() +
                              " trace:";
            for (auto& t : trace_) {
                std::ostringstream o;
                o << " " << std::hex << t.first << ":" << t.second;
                msg += o.str();
            }
            last.exception_msg = msg;
            last.next_pc = ctx.rip;
            mem_fault_ = false;
            return last;
        }
        if (last.exit != InterpExit::CONTINUE) return last;
        size_t consumed = in->length;
        if (consumed >= len) break;
        code += consumed;
        len -= consumed;
    }
    last.exit = InterpExit::BLOCK_END;
    last.next_pc = ctx.rip;
    return last;
}

} // namespace nexus
