//
// Created by Park Yu on 2024/12/26.
//

#include <string.h>
#include "shellcode_arm64.h"
#include "../memory/executable_mem.h"
#include "../util/log.h"
#include "method_analyzer.h"

const char *SHELL_CODE_TAG = "shell_code";

const Inst instNop = 0xd503201f;//todo debug only

//size 4
void *generateDirectJumpShellCode(
        uint8_t regIndex,
        Addr targetAddress
) {
    if (regIndex & ~0x1F) {
        loge(SHELL_CODE_TAG, "invalid reg: %d", regIndex);
        return NULL;
    }
    Inst instLdr = 0x58000040 | regIndex;
    Inst instBr = 0xD61F0000 | (regIndex << 5);
    size_t shellCodeSize = sizeof(Inst) * 4;
    Inst *shellCode = (Inst *) malloc(shellCodeSize);//2 instLdr + 1 addr
    shellCode[0] = instLdr;
    shellCode[1] = instBr;
    ((Addr *) shellCode)[1] = targetAddress;
    return shellCode;
}

//size 6
void *generateDirectJumpShellCodeWithLink(
        uint8_t regIndex,
        Addr targetAddress
) {
    if (regIndex & ~0x1F) {
        loge(SHELL_CODE_TAG, "invalid reg: %d", regIndex);
        return NULL;
    }
    Inst instLdr = 0x58000040 | regIndex;
    Inst instBr = 0xD63F0000 | (regIndex << 5);
    Inst instB = 0x14000000 | 4;//must jump over addr
    size_t shellCodeSize = sizeof(Inst) * 6;
    Inst *shellCode = (Inst *) malloc(shellCodeSize);//2 instLdr + 1 addr
    shellCode[0] = instLdr;
    shellCode[1] = instBr;
    shellCode[2] = instB;
    shellCode[3] = instNop;
    ((Addr *) shellCode)[2] = targetAddress;
    return shellCode;
}

void *createDirectJumpShellCode(
        uint8_t regIndex,
        Addr targetAddress
) {
    size_t shellCodeSize = sizeof(Inst) * 4;
    void *directJumpShellCode = generateDirectJumpShellCode(regIndex, targetAddress);
    void *result = createExecutableMemory((unsigned char *) directJumpShellCode, shellCodeSize);
    free(directJumpShellCode);
    return result;
}

bool branchWithLink(Inst inst) {
    if ((inst & (~0x3FFFFFF)) == 0x14000000) {
        //B label
        return false;
    }
    if ((inst & (~0x3FFFFFF)) == 0x94000000) {
        //Bl label
        return true;
    }
    //todo
    return 0;
}

int getBranchOffset(Inst inst) {
    if ((inst & (~0x3FFFFFF)) == 0x14000000) {
        //B label
        int imm26 = inst & 0x3FFFFFF;
        return (imm26 << 6) >> 6;
    }
    if ((inst & (~0x3FFFFFF)) == 0x94000000) {
        //Bl label
        return inst & 0x3FFFFFF;
    }
    return 0;
}

/**
 * this stub real impl hook delegate
 */
void *createInlineHookJumpBack(
        void *backupFuncPtr,
        size_t copySize,
        Addr backAddr,
        uint8_t regIndex
) {
    if (regIndex & ~0x1F) {
        loge(SHELL_CODE_TAG, "invalid reg: %d", regIndex);
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
    if (backAddr == 0) {
        logd(SHELL_CODE_TAG, "inline hook without jump back");
        inlineHookStubSize = copySize;
    }

    Inst *backupInstPtr = backupFuncPtr;
    for (int i = 0; i < copySize / 4; i++) {
        //relocation branch inst will increase the code size.
        if (isInstBranch(backupInstPtr[i])) {
            if (branchWithLink(backupInstPtr[i])) {
                inlineHookStubSize += (sizeof(Inst) * 5);//6 - 1
            } else {
                inlineHookStubSize += (sizeof(Inst) * 3);//4 - 1
            }
        }
    }
    logd(SHELL_CODE_TAG, "copied jump back = %p(%zu byte)", backupFuncPtr, inlineHookStubSize);
    Inst *inlineHookStub = (Inst *) malloc(inlineHookStubSize);
    Inst *inlineHookStubIterator = inlineHookStub;
    for (int i = 0; i < copySize / 4; i++) {
        //relocation branch inst
        if (isInstBranch(backupInstPtr[i])) {
            int backupOffset = getBranchOffset(backupInstPtr[i]) * 4;
            logd(SHELL_CODE_TAG, "backupOffset=0x%02X", backupOffset);
            Addr backupEntryAddr = (Addr) backupFuncPtr;
            Addr targetAddr = backupEntryAddr + backupOffset;
            logd(SHELL_CODE_TAG, "branch binary[%d]: 0x%02X, target=0x%02lX", i, backupInstPtr[i], targetAddr);
            void *directJumpShellCode = NULL;
            if (branchWithLink(backupInstPtr[i])) {
                directJumpShellCode = generateDirectJumpShellCodeWithLink(regIndex, targetAddr);
                const size_t shellCodeSize = sizeof(Inst) * 6;
                memcpy(inlineHookStubIterator, directJumpShellCode, shellCodeSize);
                free(directJumpShellCode);
                inlineHookStubIterator += 6;
            } else {
                directJumpShellCode = generateDirectJumpShellCode(regIndex, targetAddr);
                const size_t shellCodeSize = sizeof(Inst) * 4;
                memcpy(inlineHookStubIterator, directJumpShellCode, shellCodeSize);
                free(directJumpShellCode);
                inlineHookStubIterator += 4;
            }
        } else {
            logd(SHELL_CODE_TAG, "copy binary[%d]: 0x%02X", i, backupInstPtr[i]);
            *inlineHookStubIterator = backupInstPtr[i];
            inlineHookStubIterator++;
        }
    }
    logi(SHELL_CODE_TAG, "copied backup relocation success");

    if (backAddr != 0) {
        logd(SHELL_CODE_TAG, "generate jump back to 0x%02lx", backAddr);
        //need jump back, generate inst & addr
        int stubInstStartIndex = inlineHookStubIterator - inlineHookStub;
        const int spRegIndex = 31;

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
    }
    void *result = createExecutableMemory((unsigned char *) inlineHookStub, inlineHookStubSize);
    free(inlineHookStub);
    return result;
}
