#include "GameDetector.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>

namespace nexus {

namespace {

struct Token {
    const char* needle;
    double weight;
};

// Scored tokens; needle matched case-insensitively over the first 2 MiB of
// the image plus its imports string table region. Weights chosen so one
// strong identifier (engine/d3d) alone marks a game, and several weak ones
// (fullscreen + fps + shaders) accumulate past the threshold.
static const Token kTokens[] = {
    {"unreal", 40}, {"unrealengine", 40}, {"ue4", 25}, {"ue5", 25},
    {"unrealengine.com", 45}, {"unity", 30}, {"unityengine", 45},
    {"unitycontent", 45}, {"godot", 40}, {"godotengine", 40},
    {"cryengine", 40}, {"idtech", 40}, {"gamemaker", 40},
    {"sdl2", 30}, {"sdl_", 25}, {"glfw", 35}, {"sfml", 30},
    {"d3d9.dll", 30}, {"d3d10.dll", 30}, {"d3d11.dll", 30}, {"d3d12.dll", 30},
    {"dxgi.dll", 28}, {"xinput1_", 32}, {"xinput9", 32}, {"dinput8.dll", 30},
    {"directinput", 30}, {"xaudio2", 28}, {"opengl32.dll", 32},
    {"wgl", 20}, {"wglchoosepixelformat", 30}, {"swapbuffers", 30},
    {"libvulkan", 35}, {"vkcreateinstance", 35}, {"libgles", 30},
    {"libegl", 25}, {"libgl", 22}, {"libgl.so", 30}, {"libx11", 15},
    {"openal", 22}, {"fmodex", 35}, {"wwise", 32},
    {"vsync", 12}, {"fullscreen", 10}, {"framerate", 12},
    {"shaders", 14}, {"vertexbuffer", 18}, {"fragment shader", 16},
    {"940_16", 0}, {"loadrunner", 0},
    {"graphics dose", 0}, {"double_buffering", 18}, {"doublebuffer", 18},
};

// "unity" and "sdl" style short needles over-match productivity docs;
// require double confirmation below a token-length idiom: strings 3–5 chars
// score only when at least two distinct ones hit (handled in scorer via
// weak-passes accumulation).
static const Token kWeakTokens[] = {
    {"game", 12}, {"player", 10}, {"high score", 14}, {"level", 6},
    {"fps", 8}, {"render", 6}, {"texture", 10}, {"gpu", 6},
    {"directx", 20}, {"vulkan", 20}, {"opengl", 18},
};

bool lowerContains(const std::vector<char>& hay, const char* needle) {
    size_t n = std::strlen(needle);
    if (n == 0 || hay.size() < n) return false;
    if (n >= 3) {
        for (size_t i = 0; i + n <= hay.size(); ++i) {
            size_t j = 0;
            while (j < n &&
                   std::tolower(static_cast<unsigned char>(hay[i + j])) ==
                       static_cast<unsigned char>(needle[j])) ++j;
            if (j == n) return true;
        }
    } else {
        // tiny needles only counted as substrings inside obvious word spots
        for (size_t i = 0; i + n <= hay.size(); ++i) {
            size_t j = 0;
            while (j < n &&
                   std::tolower(static_cast<unsigned char>(hay[i + j])) ==
                       static_cast<unsigned char>(needle[j])) ++j;
            if (j == n) return true;
        }
    }
    return false;
}

std::string lowerExt(const std::string& p) {
    auto d = p.find_last_of('.');
    if (d == std::string::npos) return "";
    std::string e = p.substr(d + 1);
    for (auto& c : e) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return e;
}

} // namespace

GameReport GameDetector::analyzeFile(const std::string& path) {
    GameReport r;
    r.os = [&](const std::string& p) {
        std::string e = lowerExt(p);
        if (e == "exe" || e == "dll" || e == "sys") return std::string("windows");
        return std::string("linux");
    }(path);

    std::ifstream in(path, std::ios::binary);
    if (!in) return r;
    // Scan budget: first 2 MiB usually covers headers, import tables, .rodata
    // start and engine magic strings.
    static constexpr size_t kScan = 2u * 1024u * 1024u;
    std::vector<char> buf(kScan);
    in.read(buf.data(), kScan);
    buf.resize(static_cast<size_t>(in.gcount()), 0);
    std::vector<char>::size_type n = buf.size();
    if (n == 0) return r;
    for (std::vector<char>::size_type i = 0; i < n; ++i) {
        char c = buf[i];
        buf[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    double score = 0.0;
    int weakHits = 0;
    for (const auto& t : kTokens) {
        if (lowerContains(buf, t.needle)) {
            score += t.weight;
            r.reasons.push_back(t.needle);
        }
    }
    for (const auto& t : kWeakTokens) {
        if (lowerContains(buf, t.needle)) {
            ++weakHits;
            if (weakHits <= 4) score += t.weight;   // saturate weak signals
        }
    }
    r.score = score;
    r.isGame = score >= 35.0;
    return r;
}

std::string GameDetector::analyzeJson(const std::string& path) {
    GameReport rep = analyzeFile(path);
    std::string out;
    out.reserve(128 + rep.reasons.size() * 24);
    char head[96];
    std::snprintf(head, sizeof head, "{\"isGame\":%s,\"score\":%.1f,\"os\":\"%s\",\"reasons\":[",
                  rep.isGame ? "true" : "false", rep.score, rep.os.c_str());
    out += head;
    for (size_t i = 0; i < rep.reasons.size(); ++i) {
        if (i) out += ",";
        out += "\"";
        for (char c : rep.reasons[i]) {
            if (c == '"' || c == '\\') out += '\\';
            out += c;
        }
        out += "\"";
    }
    out += "]}";
    return out;
}

} // namespace nexus
