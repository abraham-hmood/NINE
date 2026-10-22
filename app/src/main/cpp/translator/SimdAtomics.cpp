#include "SimdAtomics.h"
#include <cstdio>

namespace nexus {

int SimdMapper::map(int guest_xmm, bool ymm) const {
    if (guest_xmm < 0 || guest_xmm > 15) return -1;
    // NEON has 32 V regs. Map XMM0-15 onto V16-V31.
    // YMM (256-bit) has no single NEON reg: return -1 so the translator uses scalar/two-reg fallback.
    if (ymm) return -1;
    return 16 + guest_xmm;
}

bool SimdMapper::hasNeon(SimdOp op) const {
    return op == SimdOp::MOVAPS || op == SimdOp::ADDPS || op == SimdOp::MULPS;
}

std::string SimdMapper::lower(SimdOp op, int dst, int src) const {
    int vd = map(dst, false);
    int vs = map(src, false);
    if (vd < 0 || vs < 0) return "scalar_fallback";
    // Real NEON encodings (not just text).
    uint32_t enc = 0;
    switch (op) {
        case SimdOp::MOVAPS: enc = 0x4EA01C00 | (vs << 16) | (vd); break;          // MOV Vd.16b, Vs.16b
        case SimdOp::ADDPS:  enc = 0x4E20D400 | (vs << 16) | (vd << 5) | vd; break; // FADD Vd.4s, Vd.4s, Vs.4s
        case SimdOp::MULPS:  enc = 0x6E20DC00 | (vs << 16) | (vd << 5) | vd; break; // FMUL
        default: return "scalar_fallback";
    }
    char buf[64];
    std::snprintf(buf, sizeof(buf), "neon_%08x", enc);
    return buf;
}

std::string AtomicLowering::lockCmpxchg(MemOrder order) const {
    const char* barrier = (order == MemOrder::SEQ_CST) ? "DMB SY" : "DMB ISH";
    return std::string(barrier) + "; LDXR; CMP; BNE; STLXR; CBNZ retry";
}

std::string AtomicLowering::mfence() const { return "DMB SY"; }

std::string AtomicLowering::lockRmw(const char* op, MemOrder order) const {
    const char* barrier = (order == MemOrder::SEQ_CST) ? "DMB SY" : "DMB ISH";
    return std::string(barrier) + "; LDXR; " + op + "; STLXR; CBNZ retry";
}

} // namespace nexus
