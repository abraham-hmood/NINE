#include "LinuxStartup.h"
#include "../diagnostics/Logger.h"
#include <cstring>
#include <random>
#include <algorithm>

namespace nexus {

// AT_* values
enum : uint64_t {
    AT_NULL = 0,
    AT_PHDR = 3,
    AT_PHENT = 4,
    AT_PHNUM = 5,
    AT_PAGESZ = 6,
    AT_BASE = 7,
    AT_FLAGS = 8,
    AT_ENTRY = 9,
    AT_UID = 11,
    AT_EUID = 12,
    AT_GID = 13,
    AT_EGID = 14,
    AT_CLKTCK = 17,
    AT_HWCAP = 16,
    AT_RANDOM = 25,
    AT_HWCAP2 = 26,
    AT_SECURE = 23,
    AT_EXECFN = 31,
};

LinuxStartupResult LinuxStartup::prepare(MemoryManager& mm, const LoadedElf& loaded,
                                         const std::string& argv0) {
    LinuxStartupResult r;
    auto& log = Logger::instance();

    const size_t stack_size = 0x200000; // 2 MiB
    uint64_t stack_base = mm.allocate(0, stack_size, PagePerm::READ_WRITE, "linux_stack");
    if (!stack_base) {
        r.error = "stack allocate failed";
        return r;
    }
    uint64_t stack_top = stack_base + stack_size;

    // TLS: allocate template size + TCB-ish header (glibc expects TP past TCB)
    uint64_t tls_tp = 0;
    if (loaded.tls.present && loaded.tls.template_memsz) {
        size_t tls_sz = static_cast<size_t>(loaded.tls.template_memsz + 0x100);
        uint64_t tls_base = mm.allocate(0, tls_sz, PagePerm::READ_WRITE, "tls");
        if (tls_base) {
            void* host = mm.guestToHost(tls_base);
            if (host) {
                std::memset(host, 0, tls_sz);
                // Copy TLS template from guest VA if mapped
                void* tmpl = mm.guestToHost(loaded.tls.template_vaddr);
                if (tmpl && loaded.tls.template_filesz) {
                    std::memcpy(host, tmpl,
                                static_cast<size_t>(std::min(loaded.tls.template_filesz,
                                                             loaded.tls.template_memsz)));
                }
            }
            // x86-64 ABI: FS points to end of TCB; for minimal glibc, TP = tls_base + memsz
            tls_tp = tls_base + loaded.tls.template_memsz;
            log.infof(LogCategory::LOADER, "TLS tp=0x%llx memsz=%llu",
                      (unsigned long long)tls_tp,
                      (unsigned long long)loaded.tls.template_memsz);
        }
    }

    // Strings at top of stack (grow down): argv0, then random 16 bytes for AT_RANDOM
    uint64_t sp = stack_top;
    auto push_bytes = [&](const void* p, size_t n) {
        sp -= n;
        sp &= ~0xFULL; // keep aligned-ish
        void* h = mm.guestToHost(sp);
        if (h && p) std::memcpy(h, p, n);
        return sp;
    };
    auto push_u64 = [&](uint64_t v) {
        sp -= 8;
        void* h = mm.guestToHost(sp);
        if (h) *static_cast<uint64_t*>(h) = v;
        return sp;
    };

    uint8_t rnd[16];
    {
        std::random_device rd;
        for (int i = 0; i < 16; ++i) rnd[i] = static_cast<uint8_t>(rd());
    }
    uint64_t at_random = push_bytes(rnd, 16);
    uint64_t argv0_guest = push_bytes(argv0.c_str(), argv0.size() + 1);

    // Build auxv, envp, argv, argc below strings
    // Layout at final RSP (low address): argc | argv[] | 0 | envp[] | 0 | auxv... | AT_NULL

    // We'll collect pairs then write from low to high ending at original sp after strings
    // AT_PHDR: program headers guest VA (file e_phoff mapped via first LOAD at preferred base)
    uint64_t at_phdr = loaded.load_bias + loaded.parsed.ehdr.e_phoff;
    if (loaded.base && !loaded.parsed.is_pie)
        at_phdr = loaded.base + loaded.parsed.ehdr.e_phoff; // when base is preferred VA of image
    // Non-PIE hello: base 0x400000, e_phoff 64 → 0x400040
    if (!loaded.parsed.is_pie && loaded.base)
        at_phdr = loaded.base + loaded.parsed.ehdr.e_phoff;

    std::vector<std::pair<uint64_t, uint64_t>> aux = {
        {AT_PHDR, at_phdr},
        {AT_PHENT, loaded.parsed.ehdr.e_phentsize},
        {AT_PHNUM, loaded.parsed.ehdr.e_phnum},
        {AT_PAGESZ, 4096},
        {AT_BASE, loaded.parsed.is_pie ? loaded.base : 0},
        {AT_FLAGS, 0},
        {AT_ENTRY, loaded.entry},
        {AT_UID, 1000},
        {AT_EUID, 1000},
        {AT_GID, 1000},
        {AT_EGID, 1000},
        {AT_CLKTCK, 100},
        {AT_HWCAP, 0},   // no advertised CPU features — glibc picks baseline ifuncs
        {AT_SECURE, 0},
        {AT_RANDOM, at_random},
        {AT_HWCAP2, 0},
        {AT_EXECFN, argv0_guest},
    };

    // Push auxv (high addresses first): AT_NULL then pairs in reverse
    push_u64(0);
    push_u64(0); // AT_NULL pair
    for (int i = static_cast<int>(aux.size()) - 1; i >= 0; --i) {
        push_u64(aux[i].second);
        push_u64(aux[i].first);
    }
    // envp NULL
    push_u64(0);
    // argv NULL terminator then argv[0]
    push_u64(0);
    push_u64(argv0_guest);
    // argc
    push_u64(1);

    // 16-byte align RSP as ABI requires before _start
    sp &= ~0xFULL;

    r.rsp = sp;
    r.tls_tp = tls_tp;
    // brk just past last mapped LOADs
    uint64_t high = loaded.base;
    for (auto& ph : loaded.parsed.phdrs) {
        if (ph.p_type != 1) continue;
        high = std::max(high, loaded.load_bias + ph.p_vaddr + ph.p_memsz);
    }
    r.brk_start = (high + 0xFFF) & ~0xFFFULL;
    r.ok = true;
    log.infof(LogCategory::LOADER, "LinuxStartup rsp=0x%llx tls=0x%llx brk=0x%llx argc=1",
              (unsigned long long)r.rsp, (unsigned long long)r.tls_tp,
              (unsigned long long)r.brk_start);
    return r;
}

} // namespace nexus
