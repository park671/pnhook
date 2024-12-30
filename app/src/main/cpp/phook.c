//
// Created by Park Yu on 2024/12/27.
//


#include "phook.h"
#include "jni.h"
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "memory/fake_dlfcn.h"
#include "util/log.h"
#include "memory/memory_scanner.h"
#include "inline_hook/shellcode_arm64.h"
#include "inline_hook/method_analyzer.h"

struct PHookHandle *hookMethod(const char *libName, const char *methodName, void *hookDelegate) {
    void *libHandle = dlopen_ex(libName, RTLD_NOW);
    if (libHandle == NULL) {
        LOGE("%s can not found in memory", libName);
        return NULL;
    }
    void *func = dlsym_ex(libHandle, methodName);
    LOGD("backup address=%p", func);
    dlclose_ex(libHandle);
    if (func == 0) {
        return NULL;
    }
    const size_t shellCodeByte = (sizeof(Inst) * 2) + (sizeof(Addr) * 1);
    setTextWritable(libName);
    uint64_t funcAddr = (uint64_t) func;
    if (isFuncWritable(funcAddr)) {
        LOGI("make func writable success");
    } else {
        LOGE("make func writable fail");
        return NULL;
    }

    Addr backAddr = funcAddr + shellCodeByte;
    //analysis method head inst
    //branch inst need relocation!
    if (isMethodHeadContainBranch(func, shellCodeByte)) {
        LOGI("backup head contains branch inst! need relocation");
        if (isDelegateMethod(func, shellCodeByte)) {
            //delegate method, hook without jump back
            LOGD("delegate method, instruction too less to jump back!");
            backAddr = 0;
        } else {
            //todo
        }
    }

    void *copiedBackupHeadInst = malloc(shellCodeByte);
    Addr beforeHookAddr = (Addr) hookDelegate;

    void *jumpBackFuncPtr = createInlineHookJumpBack(func, shellCodeByte, backAddr, 9);
    if (jumpBackFuncPtr == NULL) {
        LOGE("can not create jump back code");
        return NULL;
    }
//    void *inlineHookPtr = createInlineHookStub(func, shellCodeByte, beforeHookAddr, backAddr, 9);
    LOGD("inline hook jump back ptr:%p", jumpBackFuncPtr);
    void *jumpCodePtr = createDirectJumpShellCode(9, ((Addr) beforeHookAddr));
    if (jumpCodePtr == NULL) {
        LOGE("can not create direct jump shell code");
        return NULL;
    }
    LOGD("shell code ptr:%p", jumpCodePtr);
    memcpy(func, jumpCodePtr, shellCodeByte);
    LOGI("origin func rewrite success");
    struct PHookHandle *pHookHandle = (struct PHookHandle *) malloc(sizeof(struct PHookHandle));
    pHookHandle->backup = jumpBackFuncPtr;
    return pHookHandle;
}

bool unhookMethod(struct PHookHandle *) {
    //todo impl unhook
}