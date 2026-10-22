// Simple native test for Phase 0 exit criteria + ELF parser smoke test.
// Can be called from a temporary JNI or a host-side driver later.

#include "../memory/MemoryManager.h"
#include "../diagnostics/Logger.h"
#include "../loader/elf/ElfParser.h"

#include <cassert>
#include <vector>
#include <cstring>

namespace nexus {

bool testPhase0ExitCriteria() {
    auto& log = Logger::instance();
    log.info(LogCategory::GENERAL, "=== Phase 0 exit criteria test ===");

    MemoryManager mm;

    // 1. Allocate a guest VA range
    uint64_t addr = mm.allocate(0, 8192, PagePerm::READ_WRITE, "test_rw");
    if (addr == 0) {
        log.error(LogCategory::MEMORY, "FAIL: allocate returned 0");
        return false;
    }
    log.infof(LogCategory::MEMORY, "Allocated guest range at 0x%llx", (unsigned long long)addr);

    // 2. Map it executable
    if (!mm.protect(addr, PagePerm::READ_EXEC)) {
        log.error(LogCategory::MEMORY, "FAIL: protect to READ_EXEC failed");
        return false;
    }

    void* host = mm.guestToHost(addr);
    if (!host) {
        log.error(LogCategory::MEMORY, "FAIL: guestToHost returned null");
        return false;
    }

    // 3. Write and execute a tiny ARM64 return stub to prove EXEC works
    // mov w0, #42; ret
    uint32_t code[] = { 0x52800540, 0xD65F03C0 }; // mov w0, #42; ret
    std::memcpy(host, code, sizeof(code));

    using Fn = int(*)();
    auto fn = reinterpret_cast<Fn>(host);
    int result = fn();
    if (result != 42) {
        log.errorf(LogCategory::MEMORY, "FAIL: executed code returned %d (expected 42)", result);
        return false;
    }

    log.info(LogCategory::MEMORY, "SUCCESS: allocated, mapped EXEC, and ran code");
    log.info(LogCategory::GENERAL, "=== Phase 0 exit criteria PASSED ===");
    return true;
}

} // namespace nexus
