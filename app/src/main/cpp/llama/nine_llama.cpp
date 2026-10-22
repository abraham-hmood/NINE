#include <jni.h>
#include <string>
#include <vector>
#include <mutex>
#include <cstring>
#include <android/log.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "NineLlama", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "NineLlama", __VA_ARGS__)

// llama.cpp headers (present when LLAMA_AVAILABLE is set by CMake)
#if __has_include("llama.h")
#include "llama.h"
#define NINE_HAS_LLAMA 1
#else
#define NINE_HAS_LLAMA 0
#endif

static std::mutex g_mu;
#if NINE_HAS_LLAMA
static llama_model* g_model = nullptr;
static llama_context* g_ctx = nullptr;
#endif

extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_nine_dbt_LlamaRuntime_nativeAvailable(JNIEnv*, jclass) {
#if NINE_HAS_LLAMA
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jstring JNICALL
Java_com_nine_dbt_LlamaRuntime_nativeLoad(JNIEnv* env, jclass, jstring jpath) {
    std::lock_guard<std::mutex> lock(g_mu);
    const char* path = env->GetStringUTFChars(jpath, nullptr);
#if NINE_HAS_LLAMA
    if (g_ctx) { llama_free(g_ctx); g_ctx = nullptr; }
    if (g_model) { llama_free_model(g_model); g_model = nullptr; }
    llama_model_params mp = llama_model_default_params();
    g_model = llama_load_model_from_file(path, mp);
    if (!g_model) {
        env->ReleaseStringUTFChars(jpath, path);
        return env->NewStringUTF("failed to load model");
    }
    llama_context_params cp = llama_context_default_params();
    cp.n_ctx = 2048;
    g_ctx = llama_new_context_with_model(g_model, cp);
    env->ReleaseStringUTFChars(jpath, path);
    if (!g_ctx) return env->NewStringUTF("failed to create context");
    LOGI("loaded %s", path);
    return env->NewStringUTF("ok");
#else
    env->ReleaseStringUTFChars(jpath, path);
    return env->NewStringUTF("llama.cpp not linked");
#endif
}

JNIEXPORT jstring JNICALL
Java_com_nine_dbt_LlamaRuntime_nativeGenerate(JNIEnv* env, jclass, jstring jprompt, jint maxTokens) {
    std::lock_guard<std::mutex> lock(g_mu);
    const char* prompt = env->GetStringUTFChars(jprompt, nullptr);
#if NINE_HAS_LLAMA
    if (!g_model || !g_ctx) {
        env->ReleaseStringUTFChars(jprompt, prompt);
        return env->NewStringUTF("model not loaded");
    }
    const llama_vocab* vocab = llama_model_get_vocab(g_model);
    const int n = -llama_tokenize(vocab, prompt, (int)strlen(prompt), nullptr, 0, true, true);
    std::vector<llama_token> tokens(n > 0 ? n : 0);
    if (n > 0) llama_tokenize(vocab, prompt, (int)strlen(prompt), tokens.data(), n, true, true);

    llama_batch batch = llama_batch_get_one(tokens.data(), tokens.size());
    if (llama_decode(g_ctx, batch) != 0) {
        env->ReleaseStringUTFChars(jprompt, prompt);
        return env->NewStringUTF("decode failed");
    }
    std::string out;
    for (int i = 0; i < maxTokens; ++i) {
        auto* logits = llama_get_logits_ith(g_ctx, -1);
        const int n_vocab = llama_n_vocab(vocab);
        int best = 0;
        for (int t = 1; t < n_vocab; ++t) if (logits[t] > logits[best]) best = t;
        if (llama_token_is_eog(vocab, best)) break;
        char buf[128];
        int len = llama_token_to_piece(vocab, best, buf, sizeof(buf), 0, true);
        if (len > 0) out.append(buf, len);
        llama_token tok = best;
        llama_batch nb = llama_batch_get_one(&tok, 1);
        if (llama_decode(g_ctx, nb) != 0) break;
    }
    env->ReleaseStringUTFChars(jprompt, prompt);
    return env->NewStringUTF(out.c_str());
#else
    env->ReleaseStringUTFChars(jprompt, prompt);
    return env->NewStringUTF("llama.cpp not linked");
#endif
}

JNIEXPORT void JNICALL
Java_com_nine_dbt_LlamaRuntime_nativeFree(JNIEnv*, jclass) {
    std::lock_guard<std::mutex> lock(g_mu);
#if NINE_HAS_LLAMA
    if (g_ctx) { llama_free(g_ctx); g_ctx = nullptr; }
    if (g_model) { llama_free_model(g_model); g_model = nullptr; }
#endif
}

} // extern "C"
