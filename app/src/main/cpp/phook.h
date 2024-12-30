//
// Created by Park Yu on 2024/12/27.
//

#ifndef MEM_DLFUNC_PHOOK_H
#define MEM_DLFUNC_PHOOK_H

#include "stdbool.h"

struct PHookHandle {
    void *backup;
};

#ifdef __cplusplus
extern "C" {
#endif

struct PHookHandle *hookMethod(const char *libName, const char *methodName, void *hookDelegate);

bool unhookMethod(struct PHookHandle *);

#ifdef __cplusplus
};
#endif

#endif //MEM_DLFUNC_PHOOK_H
