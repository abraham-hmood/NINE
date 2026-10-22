#include "Seh.h"
#include "../diagnostics/Logger.h"
#include <jni.h>
#include <cstdio>

namespace nexus {

static JavaVM* g_vm = nullptr;
static jclass g_log_cls = nullptr;

void SehDispatcher::setJvm(void* vm) { g_vm = static_cast<JavaVM*>(vm); }

bool SehDispatcher::dispatch(uint32_t code, uint64_t address, const std::string& message) {
    GuestException ex{ code, address, message };
    bool found = false;
    for (const auto& f : info_.functions) {
        if (address >= f.begin && address < f.end) { found = true; break; }
    }
    Logger::instance().errorf(LogCategory::ABI, "SEH 0x%x at 0x%llx: %s (frame=%d)",
                              code, (unsigned long long)address, message.c_str(), found ? 1 : 0);
    if (sink_) sink_(ex);
    if (g_vm) {
        JNIEnv* env = nullptr;
        if (g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK && env) {
            jclass cls = env->FindClass("com/nine/dbt/GuestLog");
            if (cls) {
                jmethodID m = env->GetStaticMethodID(cls, "add", "(Ljava/lang/String;)V");
                if (m) {
                    char buf[256];
                    std::snprintf(buf, sizeof(buf), "SEH 0x%x @ 0x%llx %s",
                                  code, (unsigned long long)address, message.c_str());
                    jstring js = env->NewStringUTF(buf);
                    env->CallStaticVoidMethod(cls, m, js);
                }
            }
        }
    }
    return found;
}

} // namespace nexus

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    nexus::SehDispatcher::setJvm(vm);
    // Cache the VM in RuntimeBridgeJni so the Logger sink (installed by
    // nativeInit) can attach from DBT/worker threads without a JNI call first.
    extern void nine_cache_jvm(void*);
    nine_cache_jvm(vm);
    return JNI_VERSION_1_6;
}
