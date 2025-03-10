//
// Created by Park Yu on 2024/12/27.
//
#include "phook.h"
#include "jni.h"
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "memory/memory_dlfcn.h"
#include "util/log.h"
#include "memory/memory_scanner.h"
#include "inline_hook/shellcode_arm64.h"
#include "inline_hook/method_analyzer.h"

const char *PNHOOK_TAG = "pnhook";

void *methodForName(const char *libName, const char *methodName) {
    void *libHandle = dlopen_ex(libName, RTLD_NOW);
    if (libHandle == NULL) {
        loge(PNHOOK_TAG, "%s can not found in memory", libName);
        return NULL;
    }
    void *func = dlsym_ex(libHandle, methodName);
    logd(PNHOOK_TAG, "backup address=%p", func);
    dlclose_ex(libHandle);
    return func;
}

struct PHookHandle *hookMethodPtr(void *methodPtr, void *hookDelegate) {
    logd(PNHOOK_TAG, "backup address=%p", methodPtr);
    if (methodPtr == 0) {
        return NULL;
    }
    const size_t shellCodeByte = (sizeof(Inst) * 2) + (sizeof(Addr) * 1);

    if (setMethodWritable(methodPtr)) {
        logi(PNHOOK_TAG, "make func writable success");
    } else {
        loge(PNHOOK_TAG, "make func writable fail");
        return NULL;
    }
    Addr backAddr = ((Addr) methodPtr) + shellCodeByte;
    //analysis method head inst
    //branch inst need relocation!
    if (isMethodHeadContainBranch(methodPtr, shellCodeByte)) {
        logi(PNHOOK_TAG, "backup head contains branch inst! need relocation");
    }
    if (!needJumpBack(methodPtr, shellCodeByte)) {
        //delegate method, hook without jump back
        logd(PNHOOK_TAG, "small method, instruction too few to jump back");
        backAddr = 0;
    }

    void *copiedBackupHeadInst = malloc(shellCodeByte);
    Addr beforeHookAddr = (Addr) hookDelegate;

    void *jumpBackFuncPtr = createInlineHookJumpBack(methodPtr, shellCodeByte, backAddr, 9);
    if (jumpBackFuncPtr == NULL) {
        loge(PNHOOK_TAG, "can not create jump back code");
        return NULL;
    }
    logd(PNHOOK_TAG, "inline hook jump back ptr:%p", jumpBackFuncPtr);
    void *jumpCodePtr = createDirectJumpShellCode(9, ((Addr) beforeHookAddr));
    if (jumpCodePtr == NULL) {
        loge(PNHOOK_TAG, "can not create direct jump shell code");
        return NULL;
    }
    logd(PNHOOK_TAG, "shell code ptr:%p", jumpCodePtr);
    memcpy(methodPtr, jumpCodePtr, shellCodeByte);
    logi(PNHOOK_TAG, "origin func rewrite success");
    struct PHookHandle *pHookHandle = (struct PHookHandle *) malloc(sizeof(struct PHookHandle));
    pHookHandle->backup = jumpBackFuncPtr;
    restoreMethodPermission();
    return pHookHandle;
}

struct PHookHandle *hookMethod(const char *libName, const char *methodName, void *hookDelegate) {
    void *func = methodForName(libName, methodName);
    return hookMethodPtr(func, hookDelegate);
}

bool unhookMethod(struct PHookHandle *) {
    //todo impl unhook
}