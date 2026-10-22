#include "SearchPaths.h"
#include <fstream>

namespace nexus {

std::vector<std::string> SearchPaths::split(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ':' || c == ';') {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else cur.push_back(c);
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::string SearchPaths::expand(const std::string& path, const std::string& origin) {
    const std::string token = "$ORIGIN";
    auto pos = path.find(token);
    if (pos == std::string::npos) return path;
    return path.substr(0, pos) + origin + path.substr(pos + token.size());
}

void SearchPaths::setLdLibraryPath(const std::string& colon_separated) {
    ld_paths_ = split(colon_separated);
}

void SearchPaths::addLdPath(const std::string& path) {
    if (!path.empty()) ld_paths_.push_back(path);
}

void SearchPaths::setRpath(const std::string& rpath) { rpath_ = split(rpath); }
void SearchPaths::setRunpath(const std::string& runpath) { runpath_ = split(runpath); }

std::vector<std::string> SearchPaths::ordered(const std::string& origin_dir) const {
    std::vector<std::string> out;
    // RUNPATH replaces RPATH when present (ELF rule)
    const auto& embedded = runpath_.empty() ? rpath_ : runpath_;
    for (const auto& p : embedded) out.push_back(expand(p, origin_dir));
    for (const auto& p : ld_paths_) out.push_back(expand(p, origin_dir));
    if (!system_dir_.empty()) out.push_back(system_dir_);
    return out;
}

std::optional<std::string> SearchPaths::find(const std::string& soname, const std::string& origin_dir) const {
    for (const auto& dir : ordered(origin_dir)) {
        std::string full = dir;
        if (!full.empty() && full.back() != '/') full.push_back('/');
        full += soname;
        std::ifstream f(full);
        if (f.good()) return full;
    }
    return std::nullopt;
}

} // namespace nexus
