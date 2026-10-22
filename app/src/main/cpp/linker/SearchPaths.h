#pragma once

#include <string>
#include <vector>
#include <optional>

namespace nexus {

class SearchPaths {
public:
    // Guest LD_LIBRARY_PATH equivalent (colon-separated on input).
    void setLdLibraryPath(const std::string& colon_separated);
    void addLdPath(const std::string& path);

    // Embedded RPATH / RUNPATH from the requesting module.
    void setRpath(const std::string& rpath);
    void setRunpath(const std::string& runpath);

    // Host directory of reimplemented system libraries (our libc/libm stubs, etc.).
    void setSystemDir(const std::string& dir) { system_dir_ = dir; }
    const std::string& systemDir() const { return system_dir_; }

    // Ordered search: RUNPATH (if set) else RPATH, then LD_LIBRARY_PATH, then system dir.
    // $ORIGIN is expanded against origin_dir.
    std::vector<std::string> ordered(const std::string& origin_dir) const;

    // Find a library by soname. Returns full path or nullopt.
    std::optional<std::string> find(const std::string& soname, const std::string& origin_dir) const;

private:
    std::vector<std::string> ld_paths_;
    std::vector<std::string> rpath_;
    std::vector<std::string> runpath_;
    std::string system_dir_ = "/system/nine/lib";

    static std::vector<std::string> split(const std::string& s);
    static std::string expand(const std::string& path, const std::string& origin);
};

} // namespace nexus
