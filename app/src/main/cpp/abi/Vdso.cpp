#include "Vdso.h"
#include <cstring>

namespace nexus {

uint64_t StackSetup::build(uint8_t* stack_top, uint64_t sp,
                           const std::vector<std::string>& argv,
                           const std::vector<std::string>& envp,
                           const std::vector<AuxEntry>& auxv) {
    // Place strings at the top, then the pointer arrays below them.
    auto place = [&](const std::string& s) {
        sp -= s.size() + 1;
        std::memcpy(stack_top - (reinterpret_cast<uintptr_t>(stack_top) - sp), s.c_str(), s.size() + 1);
        return sp;
    };
    // Simpler: write relative to stack_top which is the host pointer for `sp`.
    uint8_t* p = stack_top;
    std::vector<uint64_t> argv_addrs, env_addrs;
    for (auto it = argv.rbegin(); it != argv.rend(); ++it) {
        p -= it->size() + 1;
        std::memcpy(p, it->c_str(), it->size() + 1);
        argv_addrs.push_back(sp - (stack_top - p));
    }
    for (auto it = envp.rbegin(); it != envp.rend(); ++it) {
        p -= it->size() + 1;
        std::memcpy(p, it->c_str(), it->size() + 1);
        env_addrs.push_back(sp - (stack_top - p));
    }
    auto push = [&](uint64_t v) {
        p -= 8;
        std::memcpy(p, &v, 8);
    };
    push(0); // AT_NULL terminator already included by caller, but ensure
    for (auto it = auxv.rbegin(); it != auxv.rend(); ++it) {
        push(it->value);
        push(it->type);
    }
    push(0);
    for (auto a : env_addrs) push(a);
    push(0);
    for (auto a : argv_addrs) push(a);
    push(static_cast<uint64_t>(argv.size()));
    return sp - (stack_top - p);
}

} // namespace nexus
