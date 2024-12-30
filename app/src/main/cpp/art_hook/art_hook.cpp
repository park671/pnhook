//
// Created by Park Yu on 2024/12/30.
//

#include <jni.h>
#include "art_hook.h"
#include "art_13_0.h"
#include "log.h"
#include "../inline_hook/shellcode_arm64.h"


static void *GetArtMethod(JNIEnv *env, jobject method) {
    jclass methodClass = env->GetObjectClass(method);
    jfieldID artMethodFieldID = env->GetFieldID(methodClass, "artMethod", "J");
    if (artMethodFieldID == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<void *>(env->GetLongField(method, artMethodFieldID));
}

static constexpr uint32_t kAccPublic = 0x0001;  // class, field, method, ic
static constexpr uint32_t kAccPrivate = 0x0002;  // field, method, ic
static constexpr uint32_t kAccProtected = 0x0004;  // field, method, ic
static uint32_t kAccPreCompiled = 0x00200000;
static uint32_t kAccCompileDontBother = 0x02000000;

bool verifyMethodSize(JNIEnv *env, jobject method1, jobject method2) {
    void *artMethod1 =
            GetArtMethod(env, method1);
    void *artMethod2 =
            GetArtMethod(env, method2);
    LOGD("ArtMethod1 addr=%p\n", artMethod1);
    LOGD("ArtMethod2 addr=%p\n", artMethod2);
    size_t artMethodCompileSize = sizeof(art::mirror::ArtMethod);
    size_t artMethodRuntimeSize = ((uint64_t) artMethod2 - (uint64_t) artMethod1);
    LOGD("ArtMethod compile size=%zu\n", artMethodCompileSize);
    LOGD("ArtMethod runtime size=%zu\n", artMethodRuntimeSize);

    unsigned char *copiedArtMethod = (unsigned char *) malloc(artMethodRuntimeSize);
    memcpy(copiedArtMethod, artMethod1, artMethodRuntimeSize);
    for (int i = 0; i < artMethodRuntimeSize; i++) {
        LOGD("%02X", copiedArtMethod[i]);
    }
    art::mirror::ArtMethod *artMethod = static_cast<art::mirror::ArtMethod *>(artMethod1);
    LOGD("ptr_sized_fields_.data_=%p", artMethod->ptr_sized_fields_.data_);
    LOGD("ptr_sized_fields_.quick=%p",
         artMethod->ptr_sized_fields_.entry_point_from_quick_compiled_code_);
    return artMethodCompileSize == artMethodRuntimeSize;
}

static void *backup_method_ptr;
static void *hook_stub_method_ptr;

static void (*shell_code_func)();

static art::mirror::ArtMethod *inHookArtMethod;

extern "C" Addr getBackupMethodPtr() {
    return ((Addr) shell_code_func);
}

extern "C" void
printRegister(uint64_t p0, uint64_t p1, uint64_t p2, uint64_t p3, uint64_t p4, uint64_t p5,
              uint64_t p6, uint64_t p7) {
    LOGD("reg: [%02lX,%02lX,%02lX,%02lX,%02lX,%02lX,%02lX,%02lX]", p0, p1, p2, p3, p4, p5, p6, p7);
}

extern "C" void parkHookBefore() {
    asm("bl printRegister");
    inHookArtMethod->ptr_sized_fields_.entry_point_from_quick_compiled_code_ = backup_method_ptr;
    LOGD("parkHookBefore()");
}

extern "C" void parkHookAfter() {
    LOGD("parkHookAfter()");
    inHookArtMethod->ptr_sized_fields_.entry_point_from_quick_compiled_code_ = hook_stub_method_ptr;
}

extern "C" void
hookStub(void *p0, void *p1, void *p2, void *p3, void *p4, void *p5, void *p6, void *p7);


bool hookArtMethod(JNIEnv *env, jobject method) {
    void *artMethod1 = GetArtMethod(env, method);
    inHookArtMethod = static_cast<art::mirror::ArtMethod *>(artMethod1);

    inHookArtMethod->access_flags_ |= kAccCompileDontBother;
    inHookArtMethod->access_flags_ &= ~kAccPreCompiled;

    backup_method_ptr = inHookArtMethod->ptr_sized_fields_.entry_point_from_quick_compiled_code_;
    LOGD("origin quick=%p", backup_method_ptr);
    Addr origin_addr_val = (Addr) backup_method_ptr;
    shell_code_func = (void (*)()) createDirectJumpShellCode(9, origin_addr_val);
    hook_stub_method_ptr = (void *) hookStub;
    LOGD("hook addr=%p, shell code=%p", hook_stub_method_ptr, shell_code_func);
    inHookArtMethod->ptr_sized_fields_.entry_point_from_quick_compiled_code_ = hook_stub_method_ptr;
    return JNI_TRUE;
}

bool initArtHook(JNIEnv *env, jobject m1, jobject m2) {
    if (verifyMethodSize(env, m1, m2)) {
        return true;
    } else {
        return false;
    }
}