#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <mutex>

namespace nexus {

/**
 * One imported image-upscaling model ("DLSS-style" super-resolution model).
 *
 * NINE's own format (.n9up) is deliberately tiny and self-describing:
 *   bytes 0..3   magic "N9UP"
 *   bytes 4..7   version (1)
 *   bytes 8..11  upsacale scale factor (2..8)
 *   bytes 12..15 tap count N (1..64)
 *   bytes 16..   N float32 per-tap edge-adaptive weights (little endian)
 *   remainder    opaque payload reserved for future on-device NN runtimes
 *
 * A folder may also hold an opaque `.tflite`/`.onnx` file; NINE records it as a
 * payload-only import (scale guesses 2x) and logs that NN graph execution is
 * routed to a future run: the edge-adaptive path runs with default sharpness
 * until the TFLite delegate is wired into `upscaleFrame`.
 */
struct UpscaleModel {
    bool valid = false;
    std::string path;       // imported model file (inside the app's data dir)
    std::string name;       // base name without extension
    std::string format;     // "n9up" | "tflite" | "onnx" | "raw"
    uint32_t scale = 2;
    std::vector<float> taps; // per-tap weights (n9up) — empty for opaque formats
    std::string importedAt;  // human readable import timestamp
};

/**
 * First-party DLSS-style image upscaler for guest graphics output.
 *
 * Pipeline (all in-process, no cloud):
 *   1. bilinear/mitchell upsample base pass  (scale factor from model)
 *   2. edge-adaptive unsharp refinement pass — per-pixel edge magnitude gates
 *      the strength and the tap weights (imported model) tune the kernel;
 *      without an imported model a baked-in default kernel is used
 *
 * This is the semantic target for the guest framebuffer hook: once a guest
 * produces RGBA frames (G1/G2), every present call goes through
 * `upscaleFrame` when the DLSS setting is ON and the binary was detected as a
 * game by GameDetector.
 */
class Upscaler {
public:
    static Upscaler& instance();

    // Import a model. [dirPath] is a directory the app imported the user's
    // picked folder into; the first suitable file found becomes the model.
    bool setModelDir(const std::string& dirPath);

    // Direct single-file variant (used by runtimes that keep model bytes).
    bool setModelFile(const std::string& filePath);

    const UpscaleModel& model() const { return model_; }
    bool hasModel() const { return model_.valid; }

    void setEnabled(bool v) { enabled_ = v; }
    bool enabled() const { return enabled_; }

    // Scale factor applied when upscaling frames (model scale or default 2).
    uint32_t scale() const { return model_.valid ? model_.scale : 2; }

    /**
     * Upscale one RGBA8888 frame.
     * src: sw*sh*4 bytes. dst: dw*dh*4 bytes (caller sized via scale()).
     * Returns false (dst untouched format-wise) on null/bad args.
     */
    bool upscaleFrame(const uint8_t* src, uint32_t sw, uint32_t sh,
                      uint8_t* dst, uint32_t dw, uint32_t dh);

    // Diagnostics for the Settings screen (JSON: enabled/model/format/scale).
    std::string statusJson() const;

private:
    Upscaler() = default;
    UpscaleModel model_;
    bool enabled_ = false;
    std::mutex mu_;
    static bool tryLoadN9up(const std::string& file, UpscaleModel& out);
};

} // namespace nexus
