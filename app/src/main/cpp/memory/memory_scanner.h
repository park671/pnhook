//
// Created by Park Yu on 2024/12/27.
//

#ifndef MEM_DLFUNC_MEMORY_SCANNER_H
#define MEM_DLFUNC_MEMORY_SCANNER_H

#include <unistd.h>
#include "../util/log.h"
#include "../inline_hook/shellcode_arm64.h"
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/mman.h>
#include "../util/stack.h"

struct MemStructNode {
    uint64_t start;
    uint64_t end;

    char *permission;

    uint64_t offset;

    int main_dev;
    int sub_dev;

    uint64_t inode;

    char *elf_path;
};

#ifdef __cplusplus
extern "C" {
#endif

bool setMethodWritable(const char *libName, uint64_t addr);

Addr findShortJumpMemory(void *ptr);

bool releaseMapStack(struct Stack *mapStack);
struct Stack *travelMemStruct();

#ifdef __cplusplus
};
#endif

#endif //MEM_DLFUNC_MEMORY_SCANNER_H
