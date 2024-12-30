//
// Created by Park Yu on 2024/12/26.
//

#include <string.h>
#include <stdlib.h>
#include "shellcode_arm64.h"
#include "../memory/executable_mem.h"
#include "stdint.h"
#include "../util/log.h"

void *createDirectJumpShellCode(
        uint8_t regIndex,
        Addr targetAddress
) {
    if (regIndex & ~0x1F) {
        LOGE("invalid reg: %d", regIndex);
        return NULL;
    }
    Inst instLdr = 0x58000040 | regIndex;
    Inst instBr = 0xD61F0000 | (regIndex << 5);
    size_t shellcode_size = sizeof(Inst) * 4;
    Inst *shellCode = (Inst *) malloc(shellcode_size);//2 instLdr + 1 addr
    shellCode[0] = instLdr;
    shellCode[1] = instBr;
    ((Addr *) shellCode)[1] = targetAddress;
    void *result = createExecutableMemory((unsigned char *) shellCode, shellcode_size);
    free(shellCode);
    return result;
}

/**
 * this stub can not modify the params.
 * only trigger
 */
void *createInlineHookStub(
        void *backupFuncPtr,
        size_t copySize,
        Addr hookBeforeFuncAddr,
        Addr backAddr,
        uint8_t regIndex
) {
    if (regIndex & ~0x1F) {
        LOGE("invalid reg: %d", regIndex);
        return NULL;
    }
    /**
     * code structure:
         A,
         B,
         C,
         D,
         [sub sp, sp, #256]
         [str X0~7, sp, #imm] x8
         [ldr Xn, before+13]
         [blr Xn]
         [ldr X0~7, sp, #imm] x8
         [add sp, sp, #256]
         [ldr Xn, back]
         [br Xn]
         before_low,//27
         before_high,
         back_low,//29
         back_high
     **/
    size_t inlineHookStubSize = copySize + sizeof(Inst) * 26;//copy data + hook stub 4+ 4
    LOGD("inlineHookStubSize=%zu", inlineHookStubSize);
    Inst *inlineHookStub = (Inst *) malloc(inlineHookStubSize);
    memcpy(inlineHookStub, backupFuncPtr, copySize);

    int stubInstStartIndex = copySize / 4;
    const int spRegIndex = 31;
    const Inst instNop = 0xd503201f;//todo debug only

    //1 + 8 = 9 inst * 4byte = 36 byte
    inlineHookStub[stubInstStartIndex++] = 0xd10403ff;//sub	sp, sp, #0x100
    for (int i = 0; i <= 7; i++) {
        //str x0~x7 to [sp, #imm]
        Inst instStr = 0xF90003E0;
        instStr |= i;
        instStr |= i << 10;
        inlineHookStub[stubInstStartIndex++] = instStr;
    }

    //[ldr Xn, before]
    Inst instLdrBefore = 0x58000000;
    instLdrBefore |= regIndex;
    instLdrBefore |= 13 << 5;//13 pc offset(inst line count)
    inlineHookStub[stubInstStartIndex++] = instLdrBefore;

    //[blr Xn]
    Inst instBlr = 0xD63F0000;
    instBlr |= regIndex << 5;
    inlineHookStub[stubInstStartIndex++] = instBlr;

    for (int i = 0; i <= 7; i++) {
        //ldr x0~x7 from [sp, #imm]
        Inst instStr = 0xF94003E0;
        instStr |= i;
        instStr |= i << 10;
        inlineHookStub[stubInstStartIndex++] = instStr;
    }
    inlineHookStub[stubInstStartIndex++] = 0x910403ff;//add	sp, sp, #0x100

    //[ldr Xn, back]
    Inst instLdrBack = 0x58000000;
    instLdrBack |= regIndex;
    instLdrBack |= 4 << 5;//4 pc offset
    inlineHookStub[stubInstStartIndex++] = instLdrBack;

    //[br Xn]
    Inst instBr = 0xD61F0000;
    instBr |= regIndex << 5;
    inlineHookStub[stubInstStartIndex++] = instBr;

    int addrBeforeIndex = stubInstStartIndex / 2;

    //before
    ((uint64_t *) inlineHookStub)[addrBeforeIndex] = hookBeforeFuncAddr;

    //back
    ((uint64_t *) inlineHookStub)[addrBeforeIndex + 1] = backAddr;

    void *result = createExecutableMemory((unsigned char *) inlineHookStub, inlineHookStubSize);
    free(inlineHookStub);
    return result;
}

/**
 * this stub real impl hook delegate
 */
void *createInlineHookJumpBack(
        void *backupFuncAddr,
        size_t copySize,
        Addr backAddr,
        uint8_t regIndex
) {
    if (regIndex & ~0x1F) {
        LOGE("invalid reg: %d", regIndex);
        return NULL;
    }
    /**
     * code structure:
         A,
         B,
         C,
         D,
         [ldr Xn, back]
         [br Xn]
         back_low,//29
         back_high
     **/
    size_t inlineHookStubSize = copySize + sizeof(Inst) * 4;//copy data + hook stub 4
    LOGD("createInlineHookJumpBack=%zu", inlineHookStubSize);
    Inst *inlineHookStub = (Inst *) malloc(inlineHookStubSize);
    memcpy(inlineHookStub, backupFuncAddr, copySize);

    int stubInstStartIndex = copySize / 4;
    const int spRegIndex = 31;
    const Inst instNop = 0xd503201f;//todo debug only

    //[ldr Xn, back]
    Inst instLdrBack = 0x58000000;
    instLdrBack |= regIndex;
    instLdrBack |= 2 << 5;//4 pc offset
    inlineHookStub[stubInstStartIndex++] = instLdrBack;

    //[br Xn]
    Inst instBr = 0xD61F0000;
    instBr |= regIndex << 5;
    inlineHookStub[stubInstStartIndex++] = instBr;

    int addrBeforeIndex = stubInstStartIndex / 2;
    //back
    ((uint64_t *) inlineHookStub)[addrBeforeIndex] = backAddr;

    void *result = createExecutableMemory((unsigned char *) inlineHookStub, inlineHookStubSize);
    free(inlineHookStub);
    return result;
}
