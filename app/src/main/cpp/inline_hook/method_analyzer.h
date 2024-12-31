//
// Created by Park Yu on 2024/12/30.
//

#ifndef PNHOOK_METHOD_ANALYZER_H
#define PNHOOK_METHOD_ANALYZER_H

#include "stdbool.h"
#include "shellcode_arm64.h"
#include "stdio.h"
#include "stdlib.h"

#ifdef __cplusplus
extern "C" {
#endif

bool isMethodHeadContainBranch(void *methodPtr, size_t size);

bool isDelegateMethod(void *methodPtr, size_t shellCodeSize);

bool needJumpBack(void *methodPtr, size_t shellCodeSize);

bool isInstBranch(Inst inst);

#ifdef __cplusplus
};
#endif

#endif //PNHOOK_METHOD_ANALYZER_H
