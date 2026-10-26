#include <jni.h>
#include <string>
#include "../engine/string_obfs.h"

namespace shield::security {

// Tính mã băm FNV-1a 32-bit của mảng byte chứng chỉ APK
uint32_t fnv1aHash(const jbyte* data, jsize len) {
    uint32_t hash = 2166136261u;
    for (jsize i = 0; i < len; ++i) {
        hash ^= static_cast<uint8_t>(data[i]);
        hash *= 16777619u;
    }
    return hash;
}

bool verifyAppSignature(JNIEnv* env, jobject context, uint32_t expectedHash) {
    if (!context) return false;

    jclass contextClass = env->GetObjectClass(context);
    jmethodID getPmId = env->GetMethodID(contextClass,
        OBFS_STR("getPackageManager").c_str(),
        OBFS_STR("()Landroid/content/pm/PackageManager;").c_str());
    jobject pm = env->CallObjectMethod(context, getPmId);

    jmethodID getPkgNameId = env->GetMethodID(contextClass,
        OBFS_STR("getPackageName").c_str(),
        OBFS_STR("()Ljava/lang/String;").c_str());
    auto pkgName = static_cast<jstring>(env->CallObjectMethod(context, getPkgNameId));

    jclass pmClass = env->GetObjectClass(pm);
    jmethodID getPkgInfoId = env->GetMethodID(pmClass,
        OBFS_STR("getPackageInfo").c_str(),
        OBFS_STR("(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;").c_str());

    // 0x00000040 = GET_SIGNATURES
    jobject pkgInfo = env->CallObjectMethod(pm, getPkgInfoId, pkgName, 0x00000040);
    if (!pkgInfo) return false;

    jclass pkgInfoClass = env->GetObjectClass(pkgInfo);
    jfieldID sigsFieldId = env->GetFieldID(pkgInfoClass,
        OBFS_STR("signatures").c_str(),
        OBFS_STR("[Landroid/content/pm/Signature;").c_str());
    auto sigArray = static_cast<jobjectArray>(env->GetObjectField(pkgInfo, sigsFieldId));
    if (!sigArray || env->GetArrayLength(sigArray) == 0) return false;

    jobject sigObj = env->GetObjectArrayElement(sigArray, 0);
    jclass sigClass = env->GetObjectClass(sigObj);
    jmethodID toByteArrayId = env->GetMethodID(sigClass,
        OBFS_STR("toByteArray").c_str(),
        OBFS_STR("()[B").c_str());
    auto sigBytes = static_cast<jbyteArray>(env->CallObjectMethod(sigObj, toByteArrayId));

    jsize len = env->GetArrayLength(sigBytes);
    jbyte* rawBytes = env->GetByteArrayElements(sigBytes, nullptr);
    uint32_t currentHash = fnv1aHash(rawBytes, len);
    env->ReleaseByteArrayElements(sigBytes, rawBytes, JNI_ABORT);

    // Nếu expectedHash == 0 (chế độ khởi tạo ban đầu), cho phép chạy
    if (expectedHash == 0) return true;
    return currentHash == expectedHash;
}

} // namespace shield::security
