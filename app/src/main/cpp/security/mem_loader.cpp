// app/src/main/cpp/engine/mem_loader.cpp
#include <jni.h>
#include <vector>
#include <cstdint>
#include "string_obfs.h"

namespace shield::engine {

jobject loadDexFromMemory(JNIEnv* env, const std::vector<uint8_t>& dexBytes, jobject parentLoader) {
    if (dexBytes.empty()) return parentLoader;

    // Tạo DirectByteBuffer trỏ vào vùng nhớ chứa DEX đã giải mã
    jclass byteBufferClass = env->FindClass(OBFS_STR("java/nio/ByteBuffer").c_str());
    jmethodID allocateDirectId = env->GetStaticMethodID(byteBufferClass,
        OBFS_STR("allocateDirect").c_str(),
        OBFS_STR("(I)Ljava/nio/ByteBuffer;").c_str());
    jobject byteBuffer = env->CallStaticObjectMethod(byteBufferClass, allocateDirectId,
        static_cast<jint>(dexBytes.size()));

    void* directPtr = env->GetDirectBufferAddress(byteBuffer);
    if (!directPtr) return parentLoader;
    std::memcpy(directPtr, dexBytes.data(), dexBytes.size());

    // Gọi InMemoryDexClassLoader(ByteBuffer, ClassLoader)
    jclass inMemDexClass = env->FindClass(OBFS_STR("dalvik/system/InMemoryDexClassLoader").c_str());
    jmethodID ctorId = env->GetMethodID(inMemDexClass,
        OBFS_STR("<init>").c_str(),
        OBFS_STR("(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V").c_str());

    return env->NewObject(inMemDexClass, ctorId, byteBuffer, parentLoader);
}

} // namespace shield::engine
