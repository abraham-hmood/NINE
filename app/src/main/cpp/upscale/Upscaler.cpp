#include "Upscaler.h"
#include "../diagnostics/Logger.h"
#include <dirent.h>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <ctime>
#include <algorithm>

namespace nexus {

static const char* kTag = "upscale";

Upscaler& Upscaler::instance() {
    static Upscaler inst;
    return inst;
}

namespace {
std::string baseName(const std::string& p) {
    auto s = p.find_last_of('/');
    s = s == std::string::npos ? 0 : s + 1;
    auto d = p.find_last_of('.');
    if (d == std::string::npos || d < s) return p.substr(s);
    return p.substr(s, d - s);
}
std::string lowerExt(const std::string& p) {
    auto d = p.find_last_of('.');
    if (d == std::string::npos) return "";
    std::string e = p.substr(d + 1);
    for (auto& c : e) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return e;
}
bool readAll(const std::string& path, std::vector<uint8_t>& out) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    if (n < 0) { fclose(f); return false; }
    fseek(f, 0, SEEK_SET);
    out.resize(static_cast<size_t>(n));
    size_t got = fread(out.data(), 1, out.size(), f);
    fclose(f);
    return n == 0 || got == out.size();
}
} // namespace

bool Upscaler::tryLoadN9up(const std::string& file, UpscaleModel& out) {
    std::vector<uint8_t> data;
    if (!readAll(file, data)) return false;
    if (data.size() < 16) return false;
    if (std::memcmp(data.data(), "N9UP", 4) != 0) return false;
    auto u32 = [&](size_t at) -> uint32_t {
        return uint32_t(data[at]) | (uint32_t(data[at+1]) << 8) |
               (uint32_t(data[at+2]) << 16) | (uint32_t(data[at+3]) << 24);
    };
    uint32_t version = u32(4);
    if (version != 1) {
        Logger::instance().errorf(nexus::LogCategory::GENERAL,
            "upscaler model %s: unsupported version %u", file.c_str(), version);
        return false;
    }
    out.valid = true;
    out.path = file;
    out.name = baseName(file);
    out.format = "n9up";
    out.scale = std::clamp(u32(8), uint32_t{2}, uint32_t{8});
    uint32_t tn = std::clamp(u32(12), uint32_t{1}, uint32_t{64});
    out.taps.assign(tn, 0.f);
    size_t need = 16u + tn * 4u;
    if (data.size() >= need) {
        for (uint32_t i = 0; i < tn; ++i) {
            uint32_t raw = u32(16 + i * 4);
            float f; std::memcpy(&f, &raw, 4);
            out.taps[i] = f;
        }
    }
    time_t t = time(nullptr);
    char buf[32];
    strftime(buf, sizeof buf, "%Y-%m-%d %H:%M", localtime(&t));
    out.importedAt = buf;
    Logger::instance().infof(nexus::LogCategory::GENERAL,
        "upscaler model loaded: %s (%ux, %u taps)", out.name.c_str(), out.scale, tn);
    return true;
}

bool Upscaler::setModelFile(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(mu_);
    UpscaleModel m;
    if (tryLoadN9up(filePath, m)) { model_ = m; return true; }
    std::string ext = lowerExt(filePath);
    if (ext == "tflite" || ext == "flatbuffer" || ext == "onnx") {
        // Opaque NN graph payload: record import, keep built-in kernel until
        // the TFLite delegate path is wired into upscaleFrame.
        std::vector<uint8_t> data;
        if (!readAll(filePath, data)) return false;
        model_.valid = true;
        model_.path = filePath;
        model_.name = baseName(filePath);
        model_.format = ext;
        model_.scale = 2;
        model_.taps.clear();
        time_t t = time(nullptr);
        char buf[32];
        strftime(buf, sizeof buf, "%Y-%m-%d %H:%M", localtime(&t));
        model_.importedAt = buf;
        Logger::instance().infof(nexus::LogCategory::GENERAL,
            "upscaler NN payload registered: %s (%zu bytes, format %s) "
            "- edge-adaptive kernel active until the TFLite delegate lands",
            model_.name.c_str(), data.size(), ext.c_str());
        return true;
    }
    Logger::instance().errorf(nexus::LogCategory::GENERAL,
        "upscaler: %s is not a recognized model file", filePath.c_str());
    return false;
}

bool Upscaler::setModelDir(const std::string& dirPath) {
    DIR* d = opendir(dirPath.c_str());
    if (!d) {
        Logger::instance().errorf(nexus::LogCategory::GENERAL,
            "upscaler model dir open failed: %s", dirPath.c_str());
        return false;
    }
    std::string found;
    // Prefer .n9up (own format), then .tflite / .onnx payloads.
    std::string n9up, payload;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_type == DT_DIR) continue;
        std::string f = dirPath + "/" + e->d_name;
        std::string ext = lowerExt(f);
        if (ext == "n9up" && n9up.empty()) n9up = f;
        else if ((ext == "tflite" || ext == "onnx") && payload.empty()) payload = f;
    }
    closedir(d);
    if (!n9up.empty()) return setModelFile(n9up);
    if (!payload.empty()) return setModelFile(payload);
    Logger::instance().errorf(nexus::LogCategory::GENERAL,
        "upscaler: no model file found in %s", dirPath.c_str());
    return false;
}

bool Upscaler::upscaleFrame(const uint8_t* src, uint32_t sw, uint32_t sh,
                            uint8_t* dst, uint32_t dw, uint32_t dh) {
    if (!src || !dst || sw == 0 || sh == 0 || dw == 0 || dh == 0) return false;
    if (dw < sw || dh < sh) return false;

    const float xs = static_cast<float>(sw) / static_cast<float>(dw);
    const float ys = static_cast<float>(sh) / static_cast<float>(dh);

    // Weights: model taps when valid, otherwise a baked-in mild sharpening
    // kernel (center heavy).  Weights are normalized to sum 1 to keep average
    // luminance stable.
    std::vector<float> w(9);
    if (model_.valid && model_.taps.size() == 9) {
        w = model_.taps;
    } else {
        w = { -0.10f, -0.10f, -0.10f,
              -0.10f,  1.90f, -0.10f,
              -0.10f, -0.10f, -0.10f };
    }
    float wsum = 0.f; for (float v : w) wsum += v;
    if (std::abs(wsum) < 0.01f) wsum = 1.f;
    for (auto& v : w) v /= wsum;

    // Pass 1: bilinear base upscale into the destination buffer.
    // Pass 2: edge-adaptive unsharp refinement — gradient magnitude modulates
    //         kernel strength so flat areas stay clean (DLSS-inspired).
    std::vector<uint8_t> base(size_t(dw) * dh * 4);
    for (uint32_t y = 0; y < dh; ++y) {
        float sy = std::min(static_cast<float>(sh - 1),
                            std::max(0.f, (y + 0.5f) * ys - 0.5f));
        uint32_t y0 = static_cast<uint32_t>(sy);
        uint32_t y1 = std::min(y0 + 1, sh - 1);
        float fy = sy - y0;
        for (uint32_t x = 0; x < dw; ++x) {
            float sx = std::min(static_cast<float>(sw - 1),
                                std::max(0.f, (x + 0.5f) * xs - 0.5f));
            uint32_t x0 = static_cast<uint32_t>(sx);
            uint32_t x1 = std::min(x0 + 1, sw - 1);
            float fx = sx - x0;
            for (int c = 0; c < 4; ++c) {
                float a = src[(size_t(y0) * sw + x0) * 4 + c];
                float b = src[(size_t(y0) * sw + x1) * 4 + c];
                float p = src[(size_t(y1) * sw + x0) * 4 + c];
                float q = src[(size_t(y1) * sw + x1) * 4 + c];
                float top = a + (b - a) * fx;
                float bot = p + (q - p) * fx;
                base[(size_t(y) * dw + x) * 4 + c] =
                    static_cast<uint8_t>(std::clamp(top + (bot - top) * fy, 0.f, 255.f));
            }
        }
    }
    for (uint32_t y = 0; y < dh; ++y) {
        for (uint32_t x = 0; x < dw; ++x) {
            int cx = static_cast<int>(x), cy = static_cast<int>(y);
            // edge magnitude from luminance neighbours
            auto lum = [&](int px, int py) -> float {
                int ix = std::clamp(px, 0, int(dw - 1));
                int iy = std::clamp(py, 0, int(dh - 1));
                const uint8_t* p = &base[(size_t(iy) * dw + ix) * 4];
                return 0.299f * p[0] + 0.587f * p[1] + 0.114f * p[2];
            };
            float lx = std::abs(lum(cx+1, cy) - lum(cx-1, cy));
            float ly = std::abs(lum(cx, cy+1) - lum(cx, cy-1));
            float edge = std::clamp((lx + ly) / 255.f, 0.f, 1.f);
            for (int c = 0; c < 4; ++c) {
                float acc = 0.f;
                const uint8_t* cpx = &base[(size_t(cy) * dw + cx) * 4 + c];
                int t = 0;
                for (int dy = -1; dy <= 1; ++dy) {
                    for (int dx = -1; dx <= 1; ++dx) {
                        int ix = std::clamp(cx+dx, 0, int(dw - 1));
                        int iy = std::clamp(cy+dy, 0, int(dh - 1));
                        acc += w[t++] * base[(size_t(iy) * dw + ix) * 4 + c];
                    }
                }
                float mixed = *cpx * (1.f - edge * 0.5f) + acc * edge * 0.5f;
                dst[(size_t(y) * dw + x) * 4 + c] =
                    static_cast<uint8_t>(std::clamp(mixed + 0.5f, 0.f, 255.f));
            }
        }
    }
    return true;
}

std::string Upscaler::statusJson() const {
    char buf[512];
    std::snprintf(buf, sizeof buf,
        "{\"enabled\":%s,\"model\":\"%s\",\"format\":\"%s\",\"scale\":%u,\"imported\":\"%s\"}",
        enabled_ ? "true" : "false",
        model_.valid ? model_.name.c_str() : "",
        model_.valid ? model_.format.c_str() : "",
        scale(),
        model_.importedAt.c_str());
    return buf;
}

} // namespace nexus
