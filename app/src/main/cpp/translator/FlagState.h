#pragma once

#include <cstdint>
#include <optional>

namespace nexus {

// Lazy x86-64 flags. We do not write RFLAGS until a consumer needs them.
enum class FlagId : uint8_t { CF = 0, PF, AF, ZF, SF, OF, COUNT };

struct FlagProducer {
    bool valid = false;
    uint64_t result = 0;
    uint64_t op1 = 0;
    uint64_t op2 = 0;
    uint8_t size_bits = 64;
    enum Kind { NONE, ADD, SUB, LOGIC, INC, DEC } kind = NONE;
};

class FlagState {
public:
    void invalidate();
    void setFromAdd(uint64_t result, uint64_t a, uint64_t b, uint8_t bits);
    void setFromSub(uint64_t result, uint64_t a, uint64_t b, uint8_t bits);
    void setFromLogic(uint64_t result, uint8_t bits);

    // Materialize a single flag. Computes from the last producer if lazy.
    bool get(FlagId id);
    // ZF shortcut (used by the interpreter's string-op repeat logic).
    bool isZero() { return get(FlagId::ZF); }
    // Materialize the full RFLAGS image.
    uint64_t materialize();
    // Import a pre-computed RFLAGS image (used for CF/OF games like ROL/ROR).
    void setRaw(uint64_t rflags);

    bool isLazy() const { return producer_.valid; }

private:
    FlagProducer producer_;
    uint64_t rflags_ = 0x202; // IF set
    bool materialized_ = true;

    static bool parity(uint8_t v);
    void compute();
};

} // namespace nexus
