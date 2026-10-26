#include <jni.h>
#include <pthread.h>
#include <unistd.h>
#include <cstdlib>
#include "engine/string_obfs.h"

namespace shield::security {
    bool isDebuggerDetected();
    bool isHookingDetected();
    bool verifyAppSignature(JNIEnv* env, jobject context, uint32_t expectedHash);
}

namespace {

void* watchdogRoutine(void*) {
    while (true) {
        if (shield::security::isDebuggerDetected() || shield::security::isHookingDetected()) {
            _exit(0);
        }
        sleep(3);
    }
    return nullptr;
}

jboolean JNICALL nativeVerifyAndInit(JNIEnv* env, jobject /*thiz*/, jobject context) {
    if (shield::security::isDebuggerDetected() || shield::security::isHookingDetected()) {
        return JNI_FALSE;
    }
    if (!shield::security::verifyAppSignature(env, context, 0)) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

} // namespace

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    // Khởi tạo luồng ngầm Watchdog
    pthread_t pt;
    pthread_create(&pt, nullptr, watchdogRoutine, nullptr);
    pthread_detach(pt);

    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_secure_stub_StubApp_a(JNIEnv* env, jobject thiz, jobject context) {
    return nativeVerifyAndInit(env, thiz, context);
}
