#include "MemHelpers.h"
#include "../memory/MemoryManager.h"
#include <cstring>

namespace nexus {

static MemoryManager* g_mm = nullptr;

void MemHelpers_setMM(MemoryManager* mm) { g_mm = mm; }

static void* resolve(uint64_t ea) {
    if (g_mm) {
        void* p = g_mm->guestToHost(ea);
        if (p) return p;
    }
    return reinterpret_cast<void*>(static_cast<uintptr_t>(ea));
}

extern "C" {

uint64_t nine_load8(GuestContext*, uint64_t ea) {
    auto* p = static_cast<uint8_t*>(resolve(ea));
    return p ? *p : 0;
}
uint64_t nine_load16(GuestContext*, uint64_t ea) {
    auto* p = static_cast<uint16_t*>(resolve(ea));
    return p ? *p : 0;
}
uint64_t nine_load32(GuestContext*, uint64_t ea) {
    auto* p = static_cast<uint32_t*>(resolve(ea));
    return p ? *p : 0;
}
uint64_t nine_load64(GuestContext*, uint64_t ea) {
    auto* p = static_cast<uint64_t*>(resolve(ea));
    return p ? *p : 0;
}
void nine_store8(GuestContext*, uint64_t ea, uint64_t val) {
    auto* p = static_cast<uint8_t*>(resolve(ea));
    if (p) *p = static_cast<uint8_t>(val);
}
void nine_store16(GuestContext*, uint64_t ea, uint64_t val) {
    auto* p = static_cast<uint16_t*>(resolve(ea));
    if (p) *p = static_cast<uint16_t>(val);
}
void nine_store32(GuestContext*, uint64_t ea, uint64_t val) {
    auto* p = static_cast<uint32_t*>(resolve(ea));
    if (p) *p = static_cast<uint32_t>(val);
}
void nine_store64(GuestContext*, uint64_t ea, uint64_t val) {
    auto* p = static_cast<uint64_t*>(resolve(ea));
    if (p) *p = val;
}

} // extern "C"
} // namespace nexus
