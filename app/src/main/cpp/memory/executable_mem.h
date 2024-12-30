//
// Created by Park Yu on 2024/1/25.
//

#ifndef JIT_DEMO_EXECUTABLE_MEM_H
#define JIT_DEMO_EXECUTABLE_MEM_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void *createExecutableMemory(unsigned char *binary, size_t size);

int releaseExecutableMemory(void *memory, size_t size);

#ifdef __cplusplus
};
#endif

#endif //JIT_DEMO_EXECUTABLE_MEM_H
