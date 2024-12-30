//
// Created by Park Yu on 2024/12/27.
//

#include "memory_scanner.h"
#include "../util/stack.h"
#include "../inline_hook/shellcode_arm64.h"

#define BUFFER_SIZE 4096

const char *MEMORY_SCANNER_TAG = "memory_scanner";

const char *currentLibName = NULL;
struct Stack *writableMemoryNodeStack = NULL;

void printNode(struct MemStructNode *node) {
    LOGI("[%lx, %lx], %s, offset=%lx, dev=%x:%x, inode=%lu, elf=%s",
         node->start,
         node->end,
         node->permission,
         node->offset,
         node->main_dev,
         node->sub_dev,
         node->inode,
         node->elf_path);
}

bool setMemoryWritable(struct MemStructNode *p) {
    int originFlag = PROT_NONE;
    if (strstr(p->permission, "r")) {
        originFlag |= PROT_READ;
    }
    if (strstr(p->permission, "w")) {
        originFlag |= PROT_WRITE;
    }
    if (strstr(p->permission, "x")) {
        originFlag |= PROT_EXEC;
    }
    if (strstr(p->elf_path, currentLibName) != NULL) {
        if ((originFlag & PROT_READ) == 0) {
            LOGW("unreadable memory, skip");
            return false;
        }
        if (strstr(p->elf_path, "/dev") != NULL) {
            LOGW("dev memory, skip");
            return false;
        }

        void *addr = (void *) p->start;
        size_t size = p->end - p->start;
        printNode(p);
        if ((originFlag & PROT_WRITE) != 0) {
            LOGD("already writable");
            return true;
        }
        originFlag |= PROT_WRITE;
        if (mprotect(addr, size, originFlag) == 0) {
            LOGD("set writable success");
            return true;
        } else {
            LOGW("set writable fail");
        }
    }
    return false;
}

void freeMemStructNode(struct MemStructNode *node) {
    free(node->permission);
    free(node->elf_path);
    free(node);
}

struct MemStructNode *parse_line(char *line) {
    struct MemStructNode *node = malloc(sizeof(struct MemStructNode));
    if (node == NULL) {
        LOGE("Failed to allocate memory for node");
        return NULL;
    }
    node->permission = (char *) malloc(4096);
    memset(node->permission, 0, 4096);
    node->elf_path = (char *) malloc(4096);
    memset(node->elf_path, 0, 4096);
    sscanf(line, "%lx-%lx %s %lx %x:%x %lu %s",
           &node->start, &node->end, node->permission, &node->offset,
           &node->main_dev, &node->sub_dev, &node->inode, node->elf_path);
    return node;
}

struct Stack *travel_mem_struct() {
    struct Stack *resultStack = createStack(MEMORY_SCANNER_TAG);
    pid_t pid, ppid, tid;
    pid = getpid();
    ppid = getppid();
    tid = gettid();
    uid_t uid = getuid();
    LOGD("pid=%d, ppid=%d, tid=%d, uid=%d\n", pid, ppid, tid, uid);
    if (pid == tid) {
        LOGD("[+] main thread");
    }
    char mem_map_path[1024];
    sprintf(mem_map_path, "/proc/%d/maps", pid);
    FILE *source = fopen(mem_map_path, "rb");
    if (source == NULL) {
        releaseStack(resultStack);
        return NULL;
    }
    char read_buffer[BUFFER_SIZE];
    char line[BUFFER_SIZE * 3];
    int idx = 0;
    size_t bytes;
    while ((bytes = fread(read_buffer, sizeof(char), BUFFER_SIZE, source)) > 0) {
        int i = 0;
        for (i = 0; i < bytes; i++) {
            char current = read_buffer[i];
            if (current != '\n') {
                if (idx >= (BUFFER_SIZE * 3)) {
                    line[(BUFFER_SIZE * 3) - 1] = '\0';
                    resultStack->push(resultStack, parse_line(line));
                    idx = 0;
                    continue;
                }
                line[idx++] = current;
            } else {
                line[idx++] = '\0';
                resultStack->push(resultStack, parse_line(line));
                idx = 0;
            }
        }
    }
    fclose(source);
    return resultStack;
}

bool isFuncWritable(uint64_t addr) {
    if (writableMemoryNodeStack == NULL) {
        LOGE("memory have not been scan.");
        return false;
    }
    writableMemoryNodeStack->resetIterator(writableMemoryNodeStack);
    struct MemStructNode *node = writableMemoryNodeStack->iteratorNext(writableMemoryNodeStack);
    while (node != NULL) {
        LOGD("node:[%02lX - %02lX]", node->start, node->end);
        if (node->start <= addr && addr <= node->end) {
            return true;
        }
        node = writableMemoryNodeStack->iteratorNext(writableMemoryNodeStack);
    }
    return false;
}

void setTextWritable(const char *libName) {
    currentLibName = libName;
    if (writableMemoryNodeStack != NULL) {
        free(writableMemoryNodeStack);
    }
    writableMemoryNodeStack = createStack(MEMORY_SCANNER_TAG);
    struct Stack *memoryStructStack = travel_mem_struct();
    memoryStructStack->resetIterator(memoryStructStack);
    struct MemStructNode *node = memoryStructStack->iteratorNext(memoryStructStack);
    while (node != NULL) {
        if (setMemoryWritable(node)) {
            writableMemoryNodeStack->push(writableMemoryNodeStack, node);
        }
        node = memoryStructStack->iteratorNext(memoryStructStack);
    }
    LOGD("[+] travel_mem_struct return");
}

struct MarginMemory {
    void *start;
    size_t size;
};

void *methodPtr = NULL;

bool recordMemory(struct MemStructNode *p) {
//    struct MemStructNode *node = writableMemoryNodeStack->iteratorNext(writableMemoryNodeStack);
//    while (node != NULL) {
//        LOGD("node:[%02lX - %02lX]", node->start, node->end);
//        if (node->start <= addr && addr <= node->end) {
//            return true;
//        }
//        node = writableMemoryNodeStack->iteratorNext(writableMemoryNodeStack);
//    }
}

Addr findShortJumpMemory(void *ptr) {
//    Inst *instPtr = ptr;
//    if (instPtr[0])
//
//
//    struct Stack *memoryStructStack = travel_mem_struct();
//    memoryStructStack->resetIterator(memoryStructStack);
//    struct MemStructNode *node = memoryStructStack->iteratorNext(memoryStructStack);
//    while (node != NULL) {
//        if (recordMemory(node)) {
//
//        }
//        node = memoryStructStack->iteratorNext(memoryStructStack);
//    }
//    LOGD("[+] travel_mem_struct return");
    return 0;
}
