//
// Created by Park Yu on 2024/12/30.
//

#include "method_analyzer.h"
#include "stdbool.h"
#include "shellcode_arm64.h"
#include "stdio.h"
#include "stdlib.h"

bool isInstBranch(Inst inst) {
    Inst branchMask = 0x14000000;
    if (branchMask & inst) {
        return true;
    } else {
        return false;
    }
}

bool isMethodHeadContainBranch(void *methodPtr, size_t size) {
    Inst *instPtr = (Inst *) methodPtr;
    for (int i = 0; i < size; i++) {
        if (isInstBranch(instPtr[i])) {
            return true;
        }
    }
    return false;
}

bool isDelegateMethod(void *methodPtr, size_t shellCodeSize) {
    Inst *instPtr = (Inst *) methodPtr;
    if (isInstBranch(instPtr[0])) {
        for (int i = 1; i < shellCodeSize; i++) {
            if (instPtr[1] != 0) {
                return false;
            }
        }
        return true;
    }
    return false;
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