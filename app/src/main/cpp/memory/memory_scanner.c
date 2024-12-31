//
// Created by Park Yu on 2024/12/27.
//

#include "memory_scanner.h"
#include "../inline_hook/shellcode_arm64.h"

#define BUFFER_SIZE 4096

const char *MEMORY_SCANNER_TAG = "memory_scanner";

const char *currentLibName = NULL;

void printNode(struct MemStructNode *node) {
    logi(MEMORY_SCANNER_TAG, "[%lx, %lx], %s, offset=%lx, dev=%x:%x, inode=%lu, elf=%s",
         node->start,
         node->end,
         node->permission,
         node->offset,
         node->main_dev,
         node->sub_dev,
         node->inode,
         node->elf_path);
}

struct MemoryPermissionBackup {
    void *addr;
    size_t size;
    int flag;
};

struct MemoryPermissionBackup *setMemoryWritable(struct MemStructNode *p) {
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
    if (strstr(p->elf_path, currentLibName) == NULL) {
        return NULL;
    }
    if ((originFlag & PROT_READ) == 0) {
        logw(MEMORY_SCANNER_TAG, "unreadable memory, skip");
        return NULL;
    }
    if (strstr(p->elf_path, "/dev") != NULL) {
        logw(MEMORY_SCANNER_TAG, "dev memory, skip");
        return NULL;
    }
    void *addr = (void *) p->start;
    size_t size = p->end - p->start;
    printNode(p);
    if ((originFlag & PROT_WRITE) != 0) {
        logd(MEMORY_SCANNER_TAG, "already writable");
        struct MemoryPermissionBackup *memoryPermissionBackup = malloc(
                sizeof(struct MemoryPermissionBackup));
        memoryPermissionBackup->addr = addr;
        memoryPermissionBackup->size = size;
        memoryPermissionBackup->flag = originFlag;
        return memoryPermissionBackup;
    }
    int newFlag = originFlag | PROT_WRITE;
    if (mprotect(addr, size, newFlag) == 0) {
        logd(MEMORY_SCANNER_TAG, "set writable success");
        struct MemoryPermissionBackup *memoryPermissionBackup = malloc(
                sizeof(struct MemoryPermissionBackup));
        memoryPermissionBackup->addr = addr;
        memoryPermissionBackup->size = size;
        memoryPermissionBackup->flag = originFlag;
        return memoryPermissionBackup;
    } else {
        logw(MEMORY_SCANNER_TAG, "set writable fail");
    }
    return NULL;
}

void freeMemStructNode(struct MemStructNode *node) {
    free(node->permission);
    free(node->elf_path);
    free(node);
}

struct MemStructNode *parseLine(char *line) {
    struct MemStructNode *node = malloc(sizeof(struct MemStructNode));
    if (node == NULL) {
        loge(MEMORY_SCANNER_TAG, "Failed to allocate memory for node");
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

struct Stack *travelMemStruct() {
    struct Stack *resultStack = createStack(MEMORY_SCANNER_TAG);
    pid_t pid, ppid, tid;
    pid = getpid();
    ppid = getppid();
    tid = gettid();
    uid_t uid = getuid();
    logd(MEMORY_SCANNER_TAG, "pid=%d, ppid=%d, tid=%d, uid=%d\n", pid, ppid, tid, uid);
    if (pid == tid) {
        logd(MEMORY_SCANNER_TAG, "[+] main thread");
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
                    resultStack->push(resultStack, parseLine(line));
                    idx = 0;
                    continue;
                }
                line[idx++] = current;
            } else {
                line[idx++] = '\0';
                resultStack->push(resultStack, parseLine(line));
                idx = 0;
            }
        }
    }
    fclose(source);
    return resultStack;
}

bool releaseMapStack(struct Stack *mapStack) {
    if (mapStack == NULL) {
        return false;
    }
    mapStack->resetIterator(mapStack);
    struct MemStructNode *node = mapStack->iteratorNext(mapStack);
    while (node != NULL) {
        freeMemStructNode(node);
        node = mapStack->iteratorNext(mapStack);
    }
    releaseStack(mapStack);
    return true;
}

struct Stack *writableMemoryPermissionBackupStack = NULL;

bool setMethodWritable(const char *libName, uint64_t addr) {
    currentLibName = libName;
    if (writableMemoryPermissionBackupStack == NULL) {
        writableMemoryPermissionBackupStack = createStack(MEMORY_SCANNER_TAG);
    }
    struct Stack *memoryStructStack = travelMemStruct();
    memoryStructStack->resetIterator(memoryStructStack);
    struct MemStructNode *node = memoryStructStack->iteratorNext(memoryStructStack);
    while (node != NULL) {
        struct MemoryPermissionBackup *permissionBackup = setMemoryWritable(node);
        if (permissionBackup != NULL) {
            writableMemoryPermissionBackupStack->push(
                    writableMemoryPermissionBackupStack,
                    permissionBackup
            );
        }
        node = memoryStructStack->iteratorNext(memoryStructStack);
    }
    logd(MEMORY_SCANNER_TAG, "[+] travelMemStruct return");
    if (writableMemoryPermissionBackupStack == NULL) {
        loge(MEMORY_SCANNER_TAG, "memory have not been scan.");
        return false;
    }
    writableMemoryPermissionBackupStack->resetIterator(writableMemoryPermissionBackupStack);
    struct MemoryPermissionBackup *permissionBackup = writableMemoryPermissionBackupStack->iteratorNext(
            writableMemoryPermissionBackupStack);
    bool result = false;
    while (permissionBackup != NULL) {
        Addr startAddr = (Addr) permissionBackup->addr;
        Addr endAddr = (Addr) (permissionBackup->addr + permissionBackup->size);
        logd(MEMORY_SCANNER_TAG, "node:[0x%02lX - 0x%02lX]", startAddr, endAddr);
        if (startAddr <= addr && addr <= endAddr) {
            result = true;
            break;
        }
        permissionBackup = writableMemoryPermissionBackupStack->iteratorNext(
                writableMemoryPermissionBackupStack);
    }
    releaseMapStack(memoryStructStack);
    return result;
}

void restoreMethodPermission() {
    if (writableMemoryPermissionBackupStack == NULL ||
        writableMemoryPermissionBackupStack->stackSize == 0) {
        logw(MEMORY_SCANNER_TAG, "no permission backup");
        return;
    }
    writableMemoryPermissionBackupStack->resetIterator(writableMemoryPermissionBackupStack);
    struct MemoryPermissionBackup *permissionBackup = writableMemoryPermissionBackupStack->iteratorNext(
            writableMemoryPermissionBackupStack);
    while (permissionBackup != NULL) {
        if (mprotect(permissionBackup->addr, permissionBackup->size, permissionBackup->flag) == 0) {
            logd(MEMORY_SCANNER_TAG, "restore permission:%p", permissionBackup->addr);
        } else {
            loge(MEMORY_SCANNER_TAG, "restore permission fail:%p", permissionBackup->addr);
        }
        permissionBackup = writableMemoryPermissionBackupStack->iteratorNext(
                writableMemoryPermissionBackupStack);
    }
    releaseStack(writableMemoryPermissionBackupStack);
    writableMemoryPermissionBackupStack = NULL;
}