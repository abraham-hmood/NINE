// ---------------------------------------------------------------------------
// SGX execution: ENCLS (0F 01 CF), ENCLU (0F 01 D7), ENCLV (0F 01 C0).
//
// The leaves follow the SDM's register conventions where they are stable:
//   ENCLS  RBX = page / SECS, RCX = second pointer, RDX = value or flags
//   ENCLU  RBX = TCS or output buffer, RCX = input structure
//   ENCLV  RBX = SECS, RCX = context value
// Every leaf returns an SGX error code in RAX (0 = SGX_SUCCESS).
//
// Page bookkeeping is a software EPCM: one SgxPage per 4 KiB enclave page,
// keyed by its guest address, plus the SECS record it belongs to. SECS layout
// used by the model (4 KiB, little endian):
//   0x000 SIZE          0x008 BASEADDR      0x010 SSAFRAMESIZE
//   0x090 ATTRIBUTES    0x098 MISCSELECT    0x1E0 MRENCLAVE[32]
// TCS layout: 0x008 OSSA, 0x010 CSSA, 0x014 NSSA, 0x018 OENTRY.
// ---------------------------------------------------------------------------

#include "Sgx.h"
#include "InsnInterpreter.h"

#include <cstring>

namespace nexus {

const char* sgxEnclsName(uint16_t leaf) {
    switch (leaf) {
        case SGX_ECREATE: return "encls[ecreate]";
        case SGX_EADD: return "encls[eadd]";
        case SGX_EINIT: return "encls[einit]";
        case SGX_EREMOVE: return "encls[eremove]";
        case SGX_EDBGRD: return "encls[edbgrd]";
        case SGX_EDBGWR: return "encls[edbgwr]";
        case SGX_EEXTEND: return "encls[eextend]";
        case SGX_ELDB: return "encls[eldb]";
        case SGX_ELDU: return "encls[eldu]";
        case SGX_EBLOCK: return "encls[eblock]";
        case SGX_EPA: return "encls[epa]";
        case SGX_EWB: return "encls[ewb]";
        case SGX_ETRACK: return "encls[etrack]";
        case SGX_EAUG: return "encls[eaug]";
        case SGX_EMODPR: return "encls[emodpr]";
        case SGX_EMODT: return "encls[emodt]";
        case SGX_ERDINFO: return "encls[erdinfo]";
        case SGX_ELDBC: return "encls[eldbc]";
        case SGX_ELDUC: return "encls[elduc]";
        case SGX_ETRACKC: return "encls[etrackc]";
        default: return "encls[?]";
    }
}

const char* sgxEncluName(uint16_t leaf) {
    switch (leaf) {
        case SGX_EREPORT: return "enclu[ereport]";
        case SGX_EGETKEY: return "enclu[egetkey]";
        case SGX_EENTER: return "enclu[eenter]";
        case SGX_ERESUME: return "enclu[eresume]";
        case SGX_EEXIT: return "enclu[eexit]";
        case SGX_EACCEPT: return "enclu[eaccept]";
        case SGX_EMODPE: return "enclu[emodpe]";
        case SGX_EACCEPTCOPY: return "enclu[eacceptcopy]";
        case SGX_EDECCSSA: return "enclu[edecssa]";
        default: return "enclu[?]";
    }
}

const char* sgxEnclvName(uint16_t leaf) {
    switch (leaf) {
        case SGX_EINCVIRTCHILD: return "enclv[eincvirtchild]";
        case SGX_EDECVIRTCHILD: return "enclv[edecvirtchild]";
        case SGX_ESETCONTEXT: return "enclv[esetcontext]";
        default: return "enclv[?]";
    }
}

SgxPage* SgxState::page(uint64_t addr) {
    auto it = pages.find(addr & ~0xFFFULL);
    return it == pages.end() ? nullptr : &it->second;
}

SgxEnclave* SgxState::enclaveOf(uint64_t addr) {
    SgxPage* p = page(addr);
    if (!p) return nullptr;
    auto it = enclaves.find(p->enclave);
    return it == enclaves.end() ? nullptr : &it->second;
}

SgxPage* SgxState::addPage(uint64_t addr, SgxPage p) {
    auto& slot = pages[addr & ~0xFFFULL];
    slot = p;
    return &slot;
}

bool SgxState::removePage(uint64_t addr) { return pages.erase(addr & ~0xFFFULL) != 0; }

namespace {

constexpr uint64_t kPageSize = 0x1000;

uint64_t fnv1a(uint64_t h, const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

} // namespace

InterpResult InsnInterpreter::executeSgx(GuestContext& ctx, const Insn& in) {
    InterpResult r;
    r.next_pc = ctx.rip + in.length;

    // SGX absent: every leaf is #UD, which is what CPUID.SGX = 0 means.
    if (!sgx_enabled_) {
        r.exit = InterpExit::EXCEPTION;
        r.exception_code = 0xC000001D;
        r.exception_msg = std::string(in.mnemonic) + ": #UD (SGX not available)";
        return r;
    }
    // ENCLS/ENCLV are ring-0 only. NINE's guest runs at CPL 3, so the
    // privileged entry points fault even when the model is present.
    if ((in.op == X86Op::ENCLS || in.op == X86Op::ENCLV) && !sgx_ring0_) {
        r.exit = InterpExit::EXCEPTION;
        r.exception_code = 0xC000001D;
        r.exception_msg = std::string(in.mnemonic) + ": #UD (CPL > 0)";
        return r;
    }

    const uint16_t leaf = static_cast<uint16_t>(ctx.rax() & 0xFFFF);
    const uint64_t rbx = ctx.rbx(), rcx = ctx.rcx(), rdx = ctx.rdx();
    uint64_t result = SGX_SUCCESS;

    auto readU64 = [&](uint64_t addr, uint64_t& v) {
        return loadMem(addr, &v, 8);
    };
    auto writeU64 = [&](uint64_t addr, uint64_t v) {
        return storeMem(addr, &v, 8);
    };

    if (in.op == X86Op::ENCLS) {
        switch (leaf) {
            case SGX_ECREATE: {
                if (rbx & 0xFFF) { result = SGX_INVALID_SECS; break; }
                if (sgx_.pages.count(rbx)) { result = SGX_EPC_PAGE_CONFLICT; break; }
                SgxEnclave e;
                e.secs = rbx;
                readU64(rbx + 0x00, e.size);
                uint64_t attrs = 0;
                readU64(rbx + 0x98, attrs);
                e.attributes = static_cast<uint32_t>(attrs);
                e.debug = (e.attributes & 0x2) != 0;
                // A fresh SECS is a valid zero-filled page with MRENCLAVE
                // seeded from its base and size.
                uint8_t zero[kPageSize] = {};
                if (!storeMem(rbx, zero, kPageSize)) { result = SGX_INVALID_SECS; break; }
                uint8_t seed[16] = {};
                std::memcpy(seed, &e.size, 8);
                std::memcpy(seed + 8, &rbx, 8);
                e.measurement = fnv1a(0xCBF29CE484222325ULL, seed, sizeof(seed));
                sgx_.enclaves[rbx] = e;
                SgxPage p;
                p.enclave = rbx;
                p.type = SgxPageType::SECS;
                p.perm = 0;
                p.blocked = true;          // uninitialized SECS is blocked
                sgx_.addPage(rbx, p);
                break;
            }
            case SGX_EADD: case SGX_EAUG: {
                if (rbx & 0xFFF) { result = SGX_INVALID_SECS; break; }
                auto en = sgx_.enclaves.find(rcx);
                if (en == sgx_.enclaves.end()) { result = SGX_INVALID_SECS; break; }
                if (leaf == SGX_EAUG && !en->second.initialized) { result = SGX_INVALID_SECS; break; }
                if (sgx_.pages.count(rbx)) { result = SGX_EPC_PAGE_CONFLICT; break; }
                const SgxPageType type = static_cast<SgxPageType>((rdx >> 8) & 0xFF);
                SgxPage p;
                p.enclave = rcx;
                p.type = type == SgxPageType::NONE ? SgxPageType::REG : type;
                p.perm = 0x7;
                p.pending = (leaf == SGX_EAUG);
                sgx_.addPage(rbx, p);
                break;
            }
            case SGX_EEXTEND: {
                SgxPage* p = sgx_.page(rbx);
                if (!p) { result = SGX_EPC_PAGE_CONFLICT; break; }
                auto en = sgx_.enclaves.find(p->enclave);
                if (en == sgx_.enclaves.end()) { result = SGX_INVALID_SECS; break; }
                uint8_t chunk[256];
                const uint64_t off = rcx & 0xFFF;
                if ((off & 0xFF) || off + 256 > kPageSize) { result = SGX_INVALID_PARAMETER; break; }
                if (!loadMem((rbx & ~0xFFFULL) + off, chunk, sizeof(chunk))) {
                    result = SGX_INVALID_MEASUREMENT;
                    break;
                }
                en->second.measurement = fnv1a(en->second.measurement, chunk, sizeof(chunk));
                break;
            }
            case SGX_EINIT: {
                auto en = sgx_.enclaves.find(rbx);
                if (en == sgx_.enclaves.end()) { result = SGX_INVALID_SECS; break; }
                en->second.initialized = true;
                SgxPage* p = sgx_.page(rbx);
                if (p) p->blocked = false;
                uint64_t m = en->second.measurement;
                storeMem(rbx + 0x1E0, &m, 8);
                break;
            }
            case SGX_EREMOVE: {
                SgxPage* p = sgx_.page(rbx);
                if (!p) { result = SGX_EPC_PAGE_CONFLICT; break; }
                if (p->type == SgxPageType::SECS) sgx_.enclaves.erase(p->enclave);
                sgx_.removePage(rbx);
                break;
            }
            case SGX_EDBGRD: case SGX_EDBGWR: {
                SgxPage* p = sgx_.page(rbx);
                if (!p) { result = SGX_EPC_PAGE_CONFLICT; break; }
                if (!p->perm) { result = SGX_PAGE_NOT_DEBUGGABLE; break; }
                const uint64_t addr = (rbx & ~0xFFFULL) + (rcx & 0xFFF);
                if (leaf == SGX_EDBGRD) {
                    uint64_t v = 0;
                    if (!readU64(addr, v)) { result = SGX_INVALID_PARAMETER; break; }
                    ctx.rax() = v;
                    ctx.rip = r.next_pc;
                    return r;
                }
                if (!writeU64(addr, rdx)) { result = SGX_INVALID_PARAMETER; break; }
                break;
            }
            case SGX_EBLOCK: {
                SgxPage* p = sgx_.page(rbx);
                if (!p) { result = SGX_EPC_PAGE_CONFLICT; break; }
                if (p->blocked) { result = SGX_PAGE_ALREADY_BLOCKED; break; }
                p->blocked = true;
                break;
            }
            case SGX_ETRACK: case SGX_ETRACKC: {
                auto en = sgx_.enclaves.find(rbx);
                if (en == sgx_.enclaves.end()) { result = SGX_INVALID_SECS; break; }
                en->second.tracker++;
                break;
            }
            case SGX_EWB: {
                SgxPage* p = sgx_.page(rbx);
                if (!p) { result = SGX_EPC_PAGE_CONFLICT; break; }
                if (!p->blocked) { result = SGX_NOT_BLOCKED; break; }
                p->pending = true;   // evicted; the data lives in the paging image
                break;
            }
            case SGX_ELDB: case SGX_ELDU: case SGX_ELDBC: case SGX_ELDUC: {
                SgxPage* p = sgx_.page(rbx);
                if (!p) { result = SGX_EPC_PAGE_CONFLICT; break; }
                if (!p->pending) { result = SGX_INVALID_PAGE_TYPE; break; }
                p->pending = false;
                p->blocked = false;
                break;
            }
            case SGX_EPA: {
                if (rbx & 0xFFF) { result = SGX_INVALID_SECS; break; }
                SgxPage p;
                p.type = SgxPageType::VA;
                p.enclave = rcx;
                sgx_.addPage(rbx, p);
                break;
            }
            case SGX_EMODPR: {
                SgxPage* p = sgx_.page(rbx);
                if (!p) { result = SGX_EPC_PAGE_CONFLICT; break; }
                if (p->blocked) { result = SGX_PAGE_ALREADY_BLOCKED; break; }
                p->perm = static_cast<uint8_t>(rcx & 7);
                p->modified = true;
                break;
            }
            case SGX_EMODT: {
                SgxPage* p = sgx_.page(rbx);
                if (!p) { result = SGX_EPC_PAGE_CONFLICT; break; }
                p->type = static_cast<SgxPageType>(rcx & 0xFF);
                p->modified = true;
                break;
            }
            case SGX_ERDINFO: {
                SgxPage* p = sgx_.page(rbx);
                if (!p) { result = SGX_EPC_PAGE_CONFLICT; break; }
                // struct sgx_erdinfo: 0 flags, 1 type, 2 perm, 4 va slot
                uint8_t info[64] = {};
                info[0] = static_cast<uint8_t>((p->blocked ? 1 : 0) | (p->pending ? 2 : 0) |
                                               (p->modified ? 4 : 0));
                info[1] = static_cast<uint8_t>(p->type);
                info[2] = p->perm;
                info[4] = p->vaSlot;
                if (!storeMem(rcx, info, sizeof(info))) { result = SGX_INVALID_PARAMETER; break; }
                break;
            }
            default:
                result = SGX_INVALID_ATTRIBUTE;
                break;
        }
    } else if (in.op == X86Op::ENCLU) {
        switch (leaf) {
            case SGX_EENTER: case SGX_ERESUME: {
                if (rbx & 0xFFF) { result = SGX_INVALID_TCS; break; }
                SgxPage* p = sgx_.page(rbx);
                if (!p || (p->type != SgxPageType::TCS && p->type != SgxPageType::REG)) {
                    result = SGX_INVALID_TCS;
                    break;
                }
                auto en = sgx_.enclaves.find(p->enclave);
                if (en == sgx_.enclaves.end() || !en->second.initialized) {
                    result = SGX_INVALID_SECS;
                    break;
                }
                uint64_t entry = 0;
                if (!readU64((rbx & ~0xFFFULL) + 0x18, entry)) { result = SGX_INVALID_TCS; break; }
                ctx.rax() = SGX_SUCCESS;
                ctx.rip = entry;
                return r;
            }
            case SGX_EEXIT: {
                ctx.rax() = SGX_SUCCESS;
                ctx.rip = rbx;
                return r;
            }
            case SGX_EGETKEY: {
                uint64_t req = 0;
                if (!readU64(rcx, req)) { result = SGX_INVALID_PARAMETER; break; }
                const uint16_t keyname = static_cast<uint16_t>(req & 0xFFFF);
                if (keyname > 4) { result = SGX_INVALID_KEYNAME; break; }
                uint8_t key[32];
                uint64_t h = 0x9E3779B97F4A7C15ULL ^ (keyname * 0x100000001B3ULL);
                for (int i = 0; i < 4; ++i) {
                    h = fnv1a(h, reinterpret_cast<const uint8_t*>(&req), 8);
                    std::memcpy(key + i * 8, &h, 8);
                }
                if (!storeMem(rbx, key, sizeof(key))) { result = SGX_INVALID_PARAMETER; break; }
                break;
            }
            case SGX_EREPORT: {
                // 432-byte report from the target info and the current enclave.
                uint8_t target[64] = {};
                loadMem(rcx, target, sizeof(target));
                uint8_t report[432] = {};
                SgxPage* p = sgx_.page(rbx);
                uint64_t m = 0;
                if (p) {
                    auto en = sgx_.enclaves.find(p->enclave);
                    if (en != sgx_.enclaves.end()) m = en->second.measurement;
                }
                std::memcpy(report, target, 32);
                std::memcpy(report + 0x40, &m, 8);
                std::memcpy(report + 0x80, target + 32, 32);
                if (!storeMem(rbx, report, sizeof(report))) { result = SGX_INVALID_PARAMETER; break; }
                break;
            }
            case SGX_EACCEPT: case SGX_EMODPE: {
                SgxPage* p = sgx_.page(rbx);
                if (!p) { result = SGX_EPC_PAGE_CONFLICT; break; }
                if (p->pending) { p->pending = false; p->blocked = false; }
                uint64_t secinfo = 0;
                if (readU64(rcx, secinfo)) {
                    if (leaf == SGX_EMODPE) p->perm = static_cast<uint8_t>(secinfo & 7);
                    else p->perm |= static_cast<uint8_t>(secinfo & 7);
                }
                break;
            }
            case SGX_EACCEPTCOPY: {
                SgxPage* dst = sgx_.page(rbx);
                SgxPage* src = sgx_.page(rdx);
                if (!dst || !src) { result = SGX_EPC_PAGE_CONFLICT; break; }
                dst->pending = false;
                dst->blocked = false;
                dst->perm = src->perm;
                dst->type = src->type;
                break;
            }
            case SGX_EDECCSSA: {
                SgxPage* p = sgx_.page(rbx);
                if (!p) { result = SGX_INVALID_TCS; break; }
                uint32_t cssa = 0;
                loadMem((rbx & ~0xFFFULL) + 0x10, &cssa, 4);
                if (cssa) { --cssa; storeMem((rbx & ~0xFFFULL) + 0x10, &cssa, 4); }
                break;
            }
            default:
                result = SGX_INVALID_ATTRIBUTE;
                break;
        }
    } else {  // ENCLV
        switch (leaf) {
            case SGX_EINCVIRTCHILD: {
                auto en = sgx_.enclaves.find(rbx);
                if (en == sgx_.enclaves.end()) { result = SGX_INVALID_SECS; break; }
                ++en->second.childCount;
                break;
            }
            case SGX_EDECVIRTCHILD: {
                auto en = sgx_.enclaves.find(rbx);
                if (en == sgx_.enclaves.end()) { result = SGX_INVALID_SECS; break; }
                if (en->second.childCount == 0) { result = SGX_INVALID_ATTRIBUTE; break; }
                --en->second.childCount;
                break;
            }
            case SGX_ESETCONTEXT: {
                auto en = sgx_.enclaves.find(rbx);
                if (en == sgx_.enclaves.end()) { result = SGX_INVALID_SECS; break; }
                en->second.attributes = static_cast<uint32_t>(rcx);
                break;
            }
            default:
                result = SGX_INVALID_ATTRIBUTE;
                break;
        }
    }

    ctx.rax() = result;
    ctx.rip = r.next_pc;
    return r;
}

} // namespace nexus
