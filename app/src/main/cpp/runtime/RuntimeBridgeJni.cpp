#include "RuntimeBridge.h"
#include "../diagnostics/Logger.h"
#include <jni.h>
#include <android/log.h>
#include <string>
#include <thread>
#include <cctype>

#define NINE_JNI_TAG "NINE-JNI"

static JavaVM* g_vm = nullptr;
static jclass g_guestLogCls = nullptr;
static jmethodID g_guestLogAdd = nullptr;
static jmethodID g_guestLogInit = nullptr;

// FindClass/GetMethodID once (guarded by caller), cache globals for the process
// lifetime. Returns true when at least one GuestLog entry point is usable.
static bool ensureGuestLog(JNIEnv* env) {
    if (!g_guestLogCls) {
        jclass local = env->FindClass("com/nine/dbt/GuestLog");
        if (!local) {
            env->ExceptionClear();
            __android_log_print(ANDROID_LOG_WARN, NINE_JNI_TAG,
                                "GuestLog class not found");
            return false;
        }
        g_guestLogCls = (jclass)env->NewGlobalRef(local);
        env->DeleteLocalRef(local);
    }
    if (!g_guestLogAdd) {
        jmethodID m = env->GetStaticMethodID(g_guestLogCls, "add",
                                             "(Ljava/lang/String;)V");
        if (env->ExceptionCheck()) { env->ExceptionClear(); m = nullptr; }
        g_guestLogAdd = m;
    }
    if (!g_guestLogInit) {
        jmethodID m = env->GetStaticMethodID(g_guestLogCls, "onNativeLine",
                                             "(Ljava/lang/String;)V");
        if (env->ExceptionCheck()) { env->ExceptionClear(); m = nullptr; }
        g_guestLogInit = m;
    }
    return g_guestLogAdd || g_guestLogInit;
}

static JNIEnv* acquireEnv(bool* attached) {
    *attached = false;
    if (!g_vm) return nullptr;
    JNIEnv* env = nullptr;
    if (g_vm->GetEnv((void**)&env, JNI_VERSION_1_6) == JNI_OK) return env;
    if (g_vm->AttachCurrentThread(&env, nullptr) != 0 || !env) return nullptr;
    *attached = true;
    return env;
}

// Deliver one line to Java. Prefers GuestLog.onNativeLine (nativeInit path),
// falls back to GuestLog.add, then to logcat. Safe from non-Java threads.
static void pushLog(const std::string& s) {
    bool attached = false;
    JNIEnv* env = acquireEnv(&attached);
    if (!env) {
        __android_log_print(ANDROID_LOG_INFO, NINE_JNI_TAG, "%s", s.c_str());
        return;
    }
    if (!ensureGuestLog(env) || (!g_guestLogInit && !g_guestLogAdd)) {
        __android_log_print(ANDROID_LOG_INFO, NINE_JNI_TAG, "%s", s.c_str());
    } else {
        jmethodID target = g_guestLogInit ? g_guestLogInit : g_guestLogAdd;
        jstring js = env->NewStringUTF(s.c_str());
        env->CallStaticVoidMethod(g_guestLogCls, target, js);
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(js);
    }
    if (attached) g_vm->DetachCurrentThread();
}

extern "C" {

// Called from Seh.cpp's JNI_OnLoad so the VM is known before any native call.
void nine_cache_jvm(void* vm) {
    if (!g_vm && vm) g_vm = static_cast<JavaVM*>(vm);
}

// JNI_OnLoad lives in Seh.cpp; capture VM on first call if needed.
static void ensureVm(JNIEnv* env) {
    if (!g_vm && env) env->GetJavaVM(&g_vm);
}

// GuestRuntime.nativeInit(): Unit
// Installs the Logger -> GuestLog.onNativeLine sink. Must be called once from
// Java at startup so every subsequent load/run/relink line reaches the UI.
JNIEXPORT void JNICALL
Java_com_nine_dbt_GuestRuntime_nativeInit(JNIEnv* env, jclass) {
    ensureVm(env);
    ensureGuestLog(env);

    nexus::Logger::instance().setSink([](nexus::LogLevel, nexus::LogCategory,
                                         const std::string& line) {
        pushLog(line);
    });

    if (g_guestLogInit) {
        pushLog("nativeInit: Logger sink -> GuestLog.onNativeLine");
    } else {
        pushLog("nativeInit: onNativeLine missing; falling back to GuestLog.add");
    }
}

JNIEXPORT jstring JNICALL
Java_com_nine_dbt_GuestRuntime_nativeLoadAndRun(JNIEnv* env, jclass, jstring jpath, jstring jcache) {
    ensureVm(env);
    const char* path = env->GetStringUTFChars(jpath, nullptr);
    const char* cache = jcache ? env->GetStringUTFChars(jcache, nullptr) : "";
    auto& rt = nexus::RuntimeBridge::instance();
    rt.setLogSink([](const std::string& s) { pushLog(s); });
    std::string path_s(path);
    std::string cache_s(cache ? cache : "");
    env->ReleaseStringUTFChars(jpath, path);
    if (jcache) env->ReleaseStringUTFChars(jcache, cache);

    // J5.3: run on background thread; this JNI blocks until done OR we spawn
    // For UI non-blocking, Kotlin launches a thread that calls this.
    std::string result;
    try {
        result = rt.loadAndRun(path_s, cache_s);
    } catch (const std::exception& e) {
        result = std::string("jni exception: ") + e.what();
        pushLog(result);
    } catch (...) {
        result = "jni unknown exception";
        pushLog(result);
    }
    return env->NewStringUTF(result.c_str());
}

// Minimal JSON escape + failure body for the nativeRelink contract, used only
// when RuntimeBridge::relink itself throws (it normally never does).
static std::string jsonEscapeLite(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        if (c == '"') o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else if (c < 0x20) o += ' ';
        else o += static_cast<char>(c);
    }
    return o;
}

static std::string relinkFailJson(const std::string& os, const std::string& err) {
    return "{\"ok\":false,\"os\":\"" + jsonEscapeLite(os) +
           "\",\"summary\":\"\",\"error\":\"" + jsonEscapeLite(err) +
           "\",\"libraries\":[],\"unresolved\":[]}";
}

static std::string osFromPath(const std::string& p) {
    auto dot = p.find_last_of('.');
    if (dot == std::string::npos) return "linux";
    std::string e = p.substr(dot);
    for (auto& c : e) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (e == ".exe" || e == ".dll" || e == ".sys" || e == ".ocx" || e == ".cpl" ||
        e == ".drv")
        return "windows";
    return "linux";
}

JNIEXPORT jstring JNICALL
Java_com_nine_dbt_GuestRuntime_nativeRelink(JNIEnv* env, jclass, jstring jpath, jstring jlibs) {
    ensureVm(env);
    const char* path = jpath ? env->GetStringUTFChars(jpath, nullptr) : nullptr;
    const char* libs = jlibs ? env->GetStringUTFChars(jlibs, nullptr) : nullptr;
    const std::string path_s = path ? path : "";
    const std::string os = osFromPath(path_s);
    auto& rt = nexus::RuntimeBridge::instance();
    rt.setLogSink([](const std::string& s) { pushLog(s); });
    std::string result;
    try {
        result = rt.relink(path_s, libs ? libs : "");
    } catch (const std::exception& e) {
        result = relinkFailJson(os, std::string("relink jni exception: ") + e.what());
        nexus::Logger::instance().error(nexus::LogCategory::GENERAL, result);
    } catch (...) {
        result = relinkFailJson(os, "relink jni unknown exception");
        nexus::Logger::instance().error(nexus::LogCategory::GENERAL, result);
    }
    // Contract: nativeRelink ALWAYS returns JSON. If the bridge ever handed
    // back human text, wrap it rather than break the Kotlin parser.
    if (result.empty() || result[0] != '{') {
        result = relinkFailJson(os, result.empty() ? "relink produced no output" : result);
    }
    if (jpath && path) env->ReleaseStringUTFChars(jpath, path);
    if (jlibs && libs) env->ReleaseStringUTFChars(jlibs, libs);
    return env->NewStringUTF(result.c_str());
}

JNIEXPORT void JNICALL
Java_com_nine_dbt_GuestRuntime_nativeStop(JNIEnv*, jclass) {
    nexus::RuntimeBridge::instance().requestStop();
}

JNIEXPORT void JNICALL
Java_com_nine_dbt_GuestRuntime_nativePause(JNIEnv*, jclass) {
    nexus::RuntimeBridge::instance().requestPause();
}

JNIEXPORT void JNICALL
Java_com_nine_dbt_GuestRuntime_nativeResume(JNIEnv*, jclass) {
    nexus::RuntimeBridge::instance().requestResume();
}

JNIEXPORT void JNICALL
Java_com_nine_dbt_GuestRuntime_nativeStep(JNIEnv*, jclass) {
    nexus::RuntimeBridge::instance().requestStep();
}

JNIEXPORT void JNICALL
Java_com_nine_dbt_GuestRuntime_nativeSetBreakpoint(JNIEnv*, jclass, jlong pc) {
    nexus::RuntimeBridge::instance().setBreakpoint(static_cast<uint64_t>(pc));
}

JNIEXPORT void JNICALL
Java_com_nine_dbt_GuestRuntime_nativeClearBreakpoints(JNIEnv*, jclass) {
    nexus::RuntimeBridge::instance().clearBreakpoints();
}

JNIEXPORT jstring JNICALL
Java_com_nine_dbt_GuestRuntime_nativeStatus(JNIEnv* env, jclass) {
    ensureVm(env);
    auto s = nexus::RuntimeBridge::instance().statusSnapshot();
    return env->NewStringUTF(s.c_str());
}

} // extern "C"
