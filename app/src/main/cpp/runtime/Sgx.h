#pragma once

// ---------------------------------------------------------------------------
// Intel SGX software model.
//
// NINE cannot talk to the real SGX instruction set (no EPC, no MEE, no
// microcode leaves), so ENCLS/ENCLU/ENCLV are backed by a small architectural
// model: a table of enclave pages (EPCM entries), SECS bookkeeping, debug
// access, measurement accumulation and the leaf return codes from the SDM.
//
// Privilege: ENCLS is ring-0 only (#UD at CPL > 0), ENCLU is ring-3, ENCLV is
// ring-0. The interpreter exposes setSgxEnabled() so a ring-0 bring-up (or the
// host test harness) can drive the privileged leaves; with it off, every SGX
// instruction raises #UD like a CPU that reports CPUID.SGX = 0.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <string>
#include <unordered_map>

namespace nexus {

// ENCLS leaf numbers (EAX at entry).
enum SgxEncls : uint16_t {
    SGX_ECREATE = 0x00,
    SGX_EADD = 0x01,
    SGX_EINIT = 0x02,
    SGX_EREMOVE = 0x03,
    SGX_EDBGRD = 0x04,
    SGX_EDBGWR = 0x05,
    SGX_EEXTEND = 0x06,
    SGX_ELDB = 0x07,
    SGX_ELDU = 0x08,
    SGX_EBLOCK = 0x09,
    SGX_EPA = 0x0A,
    SGX_EWB = 0x0B,
    SGX_ETRACK = 0x0C,
    SGX_EAUG = 0x0D,
    SGX_EMODPR = 0x0E,
    SGX_EMODT = 0x0F,
    SGX_ERDINFO = 0x10,
    SGX_ELDBC = 0x11,
    SGX_ELDUC = 0x12,
    SGX_ETRACKC = 0x13,
};

// ENCLU leaf numbers.
enum SgxEnclu : uint16_t {
    SGX_EREPORT = 0x00,
    SGX_EGETKEY = 0x01,
    SGX_EENTER = 0x02,
    SGX_ERESUME = 0x03,
    SGX_EEXIT = 0x04,
    SGX_EACCEPT = 0x05,
    SGX_EMODPE = 0x06,
    SGX_EACCEPTCOPY = 0x07,
    SGX_EDECCSSA = 0x09,
};

// ENCLV leaf numbers.
enum SgxEnclv : uint16_t {
    SGX_EINCVIRTCHILD = 0x00,
    SGX_EDECVIRTCHILD = 0x01,
    SGX_ESETCONTEXT = 0x02,
};

// Architected leaf return codes (RAX).
enum SgxError : uint16_t {
    SGX_SUCCESS = 0,
    SGX_INVALID_SIG_STRUCT = 1,
    SGX_INVALID_ATTRIBUTE = 2,
    SGX_INVALID_MEASUREMENT = 3,
    SGX_NOT_BLOCKED = 4,
    SGX_PAGE_ALREADY_BLOCKED = 5,
    SGX_INVALID_PAGE_TYPE = 6,
    SGX_INVALID_PERM = 7,
    SGX_NO_EPC = 8,
    SGX_EPC_PAGE_CONFLICT = 9,
    SGX_PAGE_NOT_MODIFIED = 10,
    SGX_PAGE_NOT_DEBUGGABLE = 11,
    SGX_INVALID_SECS = 12,
    SGX_INVALID_CPUSVN = 13,
    SGX_INVALID_ISVSVN = 14,
    SGX_INVALID_KEYNAME = 15,
    SGX_INVALID_TCS = 16,
    SGX_INVALID_SIGNATURE = 17,
    SGX_ENTRY_NOT_FOUND = 18,
    SGX_INVALID_PARAMETER = 0x20,
};

const char* sgxEnclsName(uint16_t leaf);
const char* sgxEncluName(uint16_t leaf);
const char* sgxEnclvName(uint16_t leaf);

// Page classes tracked by the model (EPCM page types).
enum class SgxPageType : uint8_t {
    NONE = 0,
    SECS = 1,
    TCS = 2,
    REG = 3,
    VA = 4,
    TRIM = 5,
};

struct SgxPage {
    uint64_t enclave = 0;          // SECS base address
    SgxPageType type = SgxPageType::NONE;
    uint8_t perm = 0;              // R=1 W=2 X=4
    bool blocked = false;
    bool modified = false;
    bool pending = false;          // EAUG'd but not yet accepted
    uint8_t vaSlot = 0;            // version-array slot
};

struct SgxEnclave {
    uint64_t secs = 0;
    uint64_t size = 0;
    uint32_t attributes = 0;
    uint32_t miscselect = 0;
    bool initialized = false;
    bool debug = false;
    uint64_t measurement = 0xCBF29CE484222325ULL;  // FNV-1a over EEXTEND chunks
    uint64_t childCount = 0;
    uint64_t tracker = 0;
};

class SgxState {
public:
    std::unordered_map<uint64_t, SgxPage> pages;
    std::unordered_map<uint64_t, SgxEnclave> enclaves;
    uint64_t nextVa = 0x1000;

    SgxPage* page(uint64_t addr);
    SgxEnclave* enclaveOf(uint64_t addr);
    SgxPage* addPage(uint64_t addr, SgxPage p);
    bool removePage(uint64_t addr);
};

} // namespace nexus
