#pragma once
#include <cstdint>
#include "GuestContext.h"

namespace nexus {

class MemoryManager;

// Runtime helpers called from JIT-emitted code for guest memory access.
// Linked as C symbols so the emitter can load their absolute addresses.
void MemHelpers_setMM(MemoryManager* mm);

extern "C" {
uint64_t nine_load8 (GuestContext* ctx, uint64_t ea);
uint64_t nine_load16(GuestContext* ctx, uint64_t ea);
uint64_t nine_load32(GuestContext* ctx, uint64_t ea);
uint64_t nine_load64(GuestContext* ctx, uint64_t ea);
void     nine_store8 (GuestContext* ctx, uint64_t ea, uint64_t val);
void     nine_store16(GuestContext* ctx, uint64_t ea, uint64_t val);
void     nine_store32(GuestContext* ctx, uint64_t ea, uint64_t val);
void     nine_store64(GuestContext* ctx, uint64_t ea, uint64_t val);
}

} // namespace nexus
