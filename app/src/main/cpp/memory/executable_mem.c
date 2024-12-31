//
// Created by Park Yu on 2024/1/25.
//

#include "executable_mem.h"
#include "../util/log.h"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

const char *EXECUTABLE_MEMORY_TAG = "executable_memory";

void *createExecutableMemory(unsigned char *binary, size_t size) {
    int permission = PROT_READ | PROT_WRITE;
    void *mem = mmap(NULL, size, permission,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    logd(EXECUTABLE_MEMORY_TAG, "executable memory addr=%p[%zu byte]\n", mem, size);
    if (size % 4) {
        loge(EXECUTABLE_MEMORY_TAG, "executable memory must alignment to 4Byte (32bit)");
        return NULL;
    }
    memset(mem, 0, size);
    memcpy(mem, binary, size);
    logd(EXECUTABLE_MEMORY_TAG, "---binary(high 2 low)---\n");
    for (int i = 0; i < size; i += 4) {
        logd(EXECUTABLE_MEMORY_TAG, "%p:[0x %02X %02X %02X %02X]\n", (mem + i), binary[i + 3],
             binary[i + 2], binary[i + 1],
             binary[i]);
    }
    if (mprotect(mem, size, PROT_READ | PROT_EXEC) != 0) {
        loge(EXECUTABLE_MEMORY_TAG, "memory permission exec fail");
        releaseExecutableMemory(mem, size);
        return NULL;
    }
    return mem;
}

int releaseExecutableMemory(void *memory, size_t size) {
    return munmap(memory, size);
}