#include "SymbolResolver.h"
#include "../diagnostics/Logger.h"

namespace nexus {

std::string SymbolResolver::cacheKey(const std::string& name, const std::string& version,
                                     const Module* from) {
    std::string k = version.empty() ? name : name + "@" + version;
    if (from) k += "#" + from->name;
    return k;
}

bool SymbolResolver::matches(const Symbol& s, const std::string& name, const std::string& version) const {
    if (s.name != name) return false;
    if (!version.empty() && s.version != version) return false;
    return s.defined;
}

std::optional<ResolvedSymbol> SymbolResolver::resolve(const std::string& name,
                                                      const std::string& version,
                                                      const Module* from) {
    auto key = cacheKey(name, version, from);
    auto it = cache_.find(key);
    if (it != cache_.end()) return it->second;

    std::vector<Module*> order;
    if (!graph_.topologicalOrder(order)) {
        // fall back to insertion order
        order.clear();
        for (const auto& m : graph_.modules()) order.push_back(m.get());
    }

    const Symbol* best = nullptr;
    const Module* best_mod = nullptr;

    auto consider = [&](const Module* mod) {
        if (!mod) return;
        const Symbol* s = version.empty() ? mod->findSymbol(name)
                                          : mod->findSymbol(name, version);
        if (!s || !matches(*s, name, version)) return;
        // Hidden/internal: only visible to the defining module
        if ((s->vis == 2 || s->vis == 1) && from && from != mod) return;
        if (!best) {
            best = s;
            best_mod = mod;
            return;
        }
        // Strong beats weak (interposition)
        if (best->is_weak && !s->is_weak) {
            best = s;
            best_mod = mod;
        }
    };

    // Prefer the requesting module's own definition first
    consider(from);
    for (Module* m : order) consider(m);

    if (!best) {
        Logger::instance().errorf(LogCategory::LINKER, "Unresolved symbol: %s", name.c_str());
        return std::nullopt;
    }

    ResolvedSymbol rs;
    rs.address = best->value;
    rs.module = best_mod;
    rs.symbol = best;
    rs.is_weak = best->is_weak;
    cache_[key] = rs;

    Logger::instance().infof(LogCategory::LINKER, "Resolved %s -> 0x%llx (%s)",
                             name.c_str(), (unsigned long long)rs.address,
                             best_mod ? best_mod->name.c_str() : "?");
    return rs;
}

} // namespace nexus
