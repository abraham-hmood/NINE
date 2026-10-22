#include "ModuleGraph.h"
#include "../diagnostics/Logger.h"

namespace nexus {

const Symbol* Module::findSymbol(const std::string& name) const {
    auto it = symbol_index.find(name);
    if (it == symbol_index.end()) return nullptr;
    return &symbols[it->second];
}

const Symbol* Module::findSymbol(const std::string& name, const std::string& version) const {
    if (version.empty()) return findSymbol(name);
    auto it = symbol_index.find(name + "@" + version);
    if (it != symbol_index.end()) return &symbols[it->second];
    return findSymbol(name);
}

void Module::addSymbol(Symbol s) {
    size_t idx = symbols.size();
    symbols.push_back(std::move(s));
    const Symbol& stored = symbols.back();
    symbol_index[stored.name] = idx;
    if (!stored.version.empty()) {
        symbol_index[stored.name + "@" + stored.version] = idx;
    }
}

std::unique_ptr<Module> Module::fromLoadedElf(const LoadedElf& loaded, const std::string& name) {
    auto m = std::make_unique<Module>();
    m->name = name.empty()
        ? (loaded.parsed.soname ? *loaded.parsed.soname : name)
        : name;
    m->base = loaded.base;
    m->load_bias = loaded.load_bias;
    m->needed = loaded.parsed.needed;
    m->is_executable = (loaded.parsed.ehdr.e_type == ET_EXEC || loaded.parsed.ehdr.e_type == ET_DYN);

    for (size_t i = 0; i < loaded.parsed.symbols.size(); ++i) {
        const auto& es = loaded.parsed.symbols[i];
        if (es.st_name == 0 && es.st_shndx == 0) continue;
        Symbol s;
        s.name = (i < loaded.parsed.symbol_names.size()) ? loaded.parsed.symbol_names[i] : "";
        if (s.name.empty()) continue;
        s.value = es.st_value + loaded.load_bias;
        s.size = es.st_size;
        s.bind = es.st_info >> 4;
        s.type = es.st_info & 0xf;
        s.vis = es.st_other & 0x3;
        s.defined = es.st_shndx != 0;
        s.is_weak = (s.bind == 2); // STB_WEAK
        if (i < loaded.parsed.symbol_versions.size()) {
            s.version = loaded.parsed.symbol_versions[i].version_name;
        }
        m->addSymbol(std::move(s));
    }
    return m;
}

Module* ModuleGraph::add(std::unique_ptr<Module> m) {
    Module* raw = m.get();
    by_name_[raw->name] = raw;
    modules_.push_back(std::move(m));
    return raw;
}

Module* ModuleGraph::findByName(const std::string& name) {
    auto it = by_name_.find(name);
    return it == by_name_.end() ? nullptr : it->second;
}

const Module* ModuleGraph::findByName(const std::string& name) const {
    auto it = by_name_.find(name);
    return it == by_name_.end() ? nullptr : it->second;
}

bool ModuleGraph::dfs(Module* m,
                      std::unordered_map<Module*, int>& state,
                      std::vector<Module*>& out) const {
    int& st = state[m];
    if (st == 1) return false; // cycle
    if (st == 2) return true;
    st = 1;
    for (const auto& dep : m->needed) {
        auto it = by_name_.find(dep);
        if (it == by_name_.end()) continue; // unresolved dep handled later
        if (!dfs(it->second, state, out)) return false;
    }
    st = 2;
    out.push_back(m);
    return true;
}

bool ModuleGraph::topologicalOrder(std::vector<Module*>& out) const {
    out.clear();
    std::unordered_map<Module*, int> state;
    for (const auto& m : modules_) {
        if (!dfs(m.get(), state, out)) {
            Logger::instance().error(LogCategory::LINKER, "Cycle in module graph");
            return false;
        }
    }
    return true;
}

} // namespace nexus
