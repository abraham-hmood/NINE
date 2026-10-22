#pragma once

#include "../loader/elf/ElfParser.h"
#include "../loader/elf/ElfLoader.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

namespace nexus {

struct Symbol {
    std::string name;
    std::string version;     // empty if unversioned
    uint64_t value = 0;      // guest address
    uint64_t size = 0;
    uint8_t bind = 0;        // STB_*
    uint8_t type = 0;        // STT_*
    uint8_t vis = 0;         // STV_*
    bool defined = false;
    bool is_weak = false;
};

class Module {
public:
    std::string name;                        // soname or filename
    std::string path;
    uint64_t base = 0;
    uint64_t load_bias = 0;
    std::vector<std::string> needed;         // DT_NEEDED names
    std::vector<Symbol> symbols;
    std::unordered_map<std::string, size_t> symbol_index; // name -> index
    bool is_executable = false;
    int load_order = -1;

    const Symbol* findSymbol(const std::string& name) const;
    const Symbol* findSymbol(const std::string& name, const std::string& version) const;
    void addSymbol(Symbol s);

    // Build a module from a loaded ELF. Caller sets name if soname is empty.
    static std::unique_ptr<Module> fromLoadedElf(const LoadedElf& loaded, const std::string& name);
};

class ModuleGraph {
public:
    // Add a module. Returns pointer owned by the graph.
    Module* add(std::unique_ptr<Module> m);

    Module* findByName(const std::string& name);
    const Module* findByName(const std::string& name) const;

    // Build dependency edges from DT_NEEDED and return modules in topological order
    // (dependencies before dependents). Returns false if a cycle is detected.
    bool topologicalOrder(std::vector<Module*>& out) const;

    const std::vector<std::unique_ptr<Module>>& modules() const { return modules_; }
    size_t size() const { return modules_.size(); }

private:
    std::vector<std::unique_ptr<Module>> modules_;
    std::unordered_map<std::string, Module*> by_name_;

    bool dfs(Module* m,
             std::unordered_map<Module*, int>& state,
             std::vector<Module*>& out) const;
};

} // namespace nexus
