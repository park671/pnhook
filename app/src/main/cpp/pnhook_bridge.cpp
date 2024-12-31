#include <jni.h>
#include <dlfcn.h>
#include "memory/memory_dlfcn.h"
#include "util/log.h"
#include "art_hook/art_13_0.h"
#include "memory/executable_mem.h"
#include "inline_hook/shellcode_arm64.h"
#include "memory/memory_scanner.h"
#include "phook.h"
#include "art_hook/art_hook.h"

const char *PNHOOK_BRIDGE_TAG = "pnhook_bridge";

static struct PHookHandle *strictMathCosHookHandle = nullptr;
static struct PHookHandle *threadCreateHookHandle = nullptr;

extern "C" jdouble StrictMathCosHookDelegate(jdouble d) {
    const char *TEST_TAG = "strict_math_hook";
    logd(TEST_TAG, "StrictMath_cos() hook delegate called!");
    logd(TEST_TAG, "native input: %0.2f", d);
    //invoke origin func
    jdouble result = ((jdouble (*)(jdouble d)) strictMathCosHookHandle->backup)(d);
    jdouble mock = 671.123;
    logd(TEST_TAG, "input: %0.2f, output:%0.2f, mock:%0.2f", d, result, mock);
    return mock;
}

bool hookStrictMathCos() {
    logd(PNHOOK_BRIDGE_TAG, "inline hook start");
    const char *libName = "libopenjdk.so";
    const char *methodName = "StrictMath_cos";
    void *hookDelegatePtr = (void *) StrictMathCosHookDelegate;
    strictMathCosHookHandle = hookMethod(libName, methodName, hookDelegatePtr);
    if (strictMathCosHookHandle != nullptr) {
        return true;
    } else {
        return false;
    }
}

extern "C" void artThreadNativeCreate(
        JNIEnv *env,
        jclass jclazz,
        jobject java_thread,
        jlong stack_size,
        jboolean daemon
) {
    const char *TEST_TAG = "art_thread_create";
    logd(TEST_TAG, "art::Thread_nativeCreate() hook delegate called!");
    ((void (*)(
            JNIEnv *,
            jclass,
            jobject,
            jlong,
            jboolean
    )) threadCreateHookHandle->backup)(env, jclazz, java_thread, stack_size, daemon);
    logd(TEST_TAG, "after call origin");
}

bool hookArtThreadCreate() {
    logd(PNHOOK_BRIDGE_TAG, "inline hook start");
    const char *libName = "libart.so";
    const char *methodName = "_ZN3artL19Thread_nativeCreateEP7_JNIEnvP7_jclassP8_jobjectlh";
    void *hookDelegatePtr = (void *) artThreadNativeCreate;
    threadCreateHookHandle = hookMethod(libName, methodName, hookDelegatePtr);
    if (threadCreateHookHandle != nullptr) {
        return true;
    } else {
        return false;
    }
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_park_pnhook_NativeBridge_inlineHook(JNIEnv *env, jclass clazz) {
    if (hookStrictMathCos() && hookArtThreadCreate()) {
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