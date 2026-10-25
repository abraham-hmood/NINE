#include "FlagState.h"

namespace nexus {

void FlagState::invalidate() {
    producer_.valid = false;
    materialized_ = false;
}

void FlagState::setFromAdd(uint64_t result, uint64_t a, uint64_t b, uint8_t bits) {
    producer_ = { true, result, a, b, bits, FlagProducer::ADD };
    materialized_ = false;
}

void FlagState::setFromSub(uint64_t result, uint64_t a, uint64_t b, uint8_t bits) {
    producer_ = { true, result, a, b, bits, FlagProducer::SUB };
    materialized_ = false;
}

void FlagState::setFromLogic(uint64_t result, uint8_t bits) {
    producer_ = { true, result, 0, 0, bits, FlagProducer::LOGIC };
    materialized_ = false;
}

bool FlagState::parity(uint8_t v) {
    v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
    return (v & 1) == 0;
}

void FlagState::compute() {
    if (!producer_.valid || materialized_) return;
    const uint8_t bits = producer_.size_bits;
    const uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1);
    const uint64_t res = producer_.result & mask;
    const uint64_t a = producer_.op1 & mask;
    const uint64_t b = producer_.op2 & mask;
    const uint64_t sign = 1ULL << (bits - 1);

    bool cf = false, of = false, af = false;
    switch (producer_.kind) {
        case FlagProducer::ADD:
            cf = res < a;
            of = ((~(a ^ b) & (a ^ res)) & sign) != 0;
            af = ((a ^ b ^ res) & 0x10) != 0;
            break;
        case FlagProducer::SUB:
            cf = a < b;
            of = ((a ^ b) & (a ^ res) & sign) != 0;
            af = ((a ^ b ^ res) & 0x10) != 0;
            break;
        case FlagProducer::LOGIC:
            cf = false; of = false; af = false;
            break;
        default: break;
    }
    bool zf = res == 0;
    bool sf = (res & sign) != 0;
    bool pf = parity(static_cast<uint8_t>(res));

    // Preserve everything the arithmetic producer does not own (IF, DF, AC,
    // IOPL, ...) so a CLI/STD/STAC before this instruction is not undone by
    // lazily computing the arithmetic flags afterwards.
    rflags_ = (rflags_ & ~0x8D5ULL) | 0x2;
    if (cf) rflags_ |= 1ULL << 0;
    if (pf) rflags_ |= 1ULL << 2;
    if (af) rflags_ |= 1ULL << 4;
    if (zf) rflags_ |= 1ULL << 6;
    if (sf) rflags_ |= 1ULL << 7;
    if (of) rflags_ |= 1ULL << 11;
    materialized_ = true;
}

bool FlagState::get(FlagId id) {
    compute();
    static const int bit[] = { 0, 2, 4, 6, 7, 11 };
    return (rflags_ & (1ULL << bit[static_cast<int>(id)])) != 0;
}

uint64_t FlagState::materialize() {
    compute();
    producer_.valid = false;
    return rflags_;
}

void FlagState::setRaw(uint64_t rflags) {
    producer_.valid = false;
    // Bit 1 is reserved-set; IF and the other system flags are owned by the
    // caller (CLC/STC/CLI/STI/CLD/STD/STAC/CLAC), not forced on here.
    rflags_ = rflags | 0x2;
    materialized_ = true;
}

} // namespace nexus
