#include <jni.h>
#include <dlfcn.h>
#include "memory/fake_dlfcn.h"
#include "util/log.h"
#include "art_hook/art_13_0.h"
#include "memory/executable_mem.h"
#include "inline_hook/shellcode_arm64.h"
#include "memory/memory_scanner.h"
#include "phook.h"
#include "art_hook/art_hook.h"

static struct PHookHandle *pHookHandle = nullptr;

extern "C" jdouble StrictMathCosHookDelegate(jdouble d) {
    LOGD("StrictMath_cos() hook delegate called!");
    LOGD("native input: %0.2f", d);
    //invoke origin func
    jdouble result = ((jdouble (*)(jdouble d)) pHookHandle->backup)(d);
    jdouble mock = 671.123;
    LOGD("input: %0.2f, output:%0.2f, mock:%0.2f", d, result, mock);
    return mock;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_park_pnhook_NativeBridge_inlineHook(JNIEnv *env, jclass clazz) {
    LOGD("inline hook start");
    const char *libName = "libopenjdk.so";
    const char *methodName = "StrictMath_cos";
    void *hookDelegatePtr = (void *) StrictMathCosHookDelegate;
    pHookHandle = hookMethod(libName, methodName, hookDelegatePtr);
    if (pHookHandle != nullptr) {
        return JNI_TRUE;
    } else {
        return JNI_FALSE;
    }
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_park_pnhook_NativeBridge_injectTrampoline(JNIEnv *env, jclass clazz, jobject method) {
    if (hookArtMethod(env, method)) {
        return JNI_TRUE;
    } else {
        return JNI_FALSE;
    }
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_park_pnhook_NativeBridge_initEnv(JNIEnv *env, jclass clazz, jobject m1, jobject m2) {
    if (initArtHook(env, m1, m2)) {
        return JNI_TRUE;
    } else {
        return JNI_FALSE;
    }
}