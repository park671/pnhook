//
// Created by Park Yu on 2024/12/27.
//

#ifndef MEM_DLFUNC_MEMORY_SCANNER_H
#define MEM_DLFUNC_MEMORY_SCANNER_H

#include <unistd.h>
#include "../util/log.h"
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/mman.h>

struct MemStructNode {
    uint64_t start;
    uint64_t end;

    char *permission;

    uint64_t offset;

    int main_dev;
    int sub_dev;

    uint64_t inode;

    char *elf_path;

    struct MemStructNode *next;
};

#ifdef __cplusplus
extern "C" {
#endif

void setTextWritable(const char *libName);

bool isFuncWritable(uint64_t addr);

#ifdef __cplusplus
};
#endif

#endif //MEM_DLFUNC_MEMORY_SCANNER_H
