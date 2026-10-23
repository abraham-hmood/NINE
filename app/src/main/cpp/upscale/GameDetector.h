#pragma once

#include <string>
#include <vector>

namespace nexus {

/**
 * Heuristic game detection for guest binaries (ELF or PE).
 * Demand-driven per REVERSE_TECHNIQUE.md: no forking giant game databases;
 * byte-level token scoring against imports/strings that games realistically
 * carry (D3D, GL, Vulkan, SDL/GLFW, XInput, engine names, fullscreen loops).
 */
struct GameReport {
    bool isGame = false;
    double score = 0.0;                       // >= 35.0 → game
    std::vector<std::string> reasons;         // matched tokens
    std::string os;                            // "linux" | "windows"
};

class GameDetector {
public:
    // Scans the binary file at [path], returns scored report.
    static GameReport analyzeFile(const std::string& path);

    // Convenience: returns the report as compact JSON.
    static std::string analyzeJson(const std::string& path);
};

} // namespace nexus
