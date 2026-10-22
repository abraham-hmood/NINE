#pragma once

#include "ModuleGraph.h"
#include <cstdint>
#include <string>
#include <optional>
#include <unordered_map>

namespace nexus {

struct ResolvedSymbol {
    uint64_t address = 0;
    const Module* module = nullptr;
    const Symbol* symbol = nullptr;
    bool is_weak = false;
};

class SymbolResolver {
public:
    explicit SymbolResolver(ModuleGraph& graph) : graph_(graph) {}

    // Resolve a symbol by name, optionally versioned.
    // Search order: defining module first (if given), then dependency order, then all modules.
    // Weak symbols lose to strong ones. Hidden symbols are not interposed.
    // Results are cached.
    std::optional<ResolvedSymbol> resolve(const std::string& name,
                                          const std::string& version = "",
                                          const Module* from = nullptr);

    void clearCache() { cache_.clear(); }
    size_t cacheSize() const { return cache_.size(); }

private:
    ModuleGraph& graph_;
    std::unordered_map<std::string, ResolvedSymbol> cache_;

    static std::string cacheKey(const std::string& name, const std::string& version, const Module* from);
    bool matches(const Symbol& s, const std::string& name, const std::string& version) const;
};

} // namespace nexus
