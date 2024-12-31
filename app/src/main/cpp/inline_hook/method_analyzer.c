//
// Created by Park Yu on 2024/12/30.
//

#include "method_analyzer.h"
#include "stdbool.h"
#include "shellcode_arm64.h"
#include "stdio.h"
#include "stdlib.h"
#include "log.h"

const char *METHOD_ANALYZER_TAG = "method_analyzer";

bool isInstBranch(Inst inst) {
    Inst branchMask = 0x1C000000;
    if ((branchMask & inst) == 0x14000000) {
        return true;
    } else {
        return false;
    }
}

bool isMethodHeadContainBranch(void *methodPtr, size_t size) {
    Inst *instPtr = (Inst *) methodPtr;
    for (int i = 0; i < size / 4; i++) {
        if (isInstBranch(instPtr[i])) {
            logd(METHOD_ANALYZER_TAG, "branch inst=0x%02X", instPtr[i]);
            return true;
        }
    }
    return false;
}

bool isDelegateMethod(void *methodPtr, size_t shellCodeSize) {
    Inst *instPtr = (Inst *) methodPtr;
    if (isInstBranch(instPtr[0])) {
        for (int i = 1; i < shellCodeSize / 4; i++) {
            if (instPtr[i] != 0) {
                return false;
            }
        }
        return true;
    }
    return false;
}

bool needJumpBack(void *methodPtr, size_t shellCodeSize) {
    Inst *instPtr = (Inst *) methodPtr;
    for (int i = 0; i < shellCodeSize / 4; i++) {
        if (instPtr[i] == 0) {
            return false;
        }
    }
    return true;
}

void *hasSpaceForShellCode(void *methodPtr, size_t size) {
    Inst *instPtr = (Inst *) methodPtr;
    if (isInstBranch(instPtr[1])) {
        //1st inst is branch, this may be a delegate
        bool hasSpaceForShellCode = true;
        for (int i = 2; i < 6; i++) {
            //align 8byte
            if (instPtr[i]) {
                hasSpaceForShellCode = false;
                break;
            }
        }
        if (hasSpaceForShellCode) {
            return instPtr + 2;
        }
    }
    return NULL;
}