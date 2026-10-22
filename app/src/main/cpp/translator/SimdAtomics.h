#pragma once

#include <cstdint>
#include <string>

namespace nexus {

// SIMD: map SSE/AVX XMM/YMM onto NEON. Missing ops fall back to scalar.
enum class SimdOp { MOVAPS, ADDPS, MULPS, UNKNOWN };

struct SimdMapping {
    int guest_xmm = -1;     // 0-15
    int host_v = -1;        // NEON V register, or -1 if spilled
    bool is_ymm = false;    // AVX 256-bit: uses two NEON regs or scalar fallback
};

class SimdMapper {
public:
    // Map guest XMM/YMM n to a NEON register. Returns -1 if we must use scalar fallback.
    int map(int guest_xmm, bool ymm) const;

    // True if this op has a direct NEON equivalent.
    bool hasNeon(SimdOp op) const;

    // Emit a description of the lowering (used by the translator).
    std::string lower(SimdOp op, int dst, int src) const;
};

// Atomics: correct ordering for lock-prefixed ops and fences.
enum class MemOrder { RELAXED, ACQUIRE, RELEASE, ACQ_REL, SEQ_CST };

class AtomicLowering {
public:
    // lock cmpxchg -> LDXR/STLXR loop with the requested order.
    std::string lockCmpxchg(MemOrder order) const;
    // mfence -> DMB SY
    std::string mfence() const;
    // lock xadd / lock add
    std::string lockRmw(const char* op, MemOrder order) const;
};

} // namespace nexus
