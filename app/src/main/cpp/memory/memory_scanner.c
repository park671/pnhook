//
// Created by Park Yu on 2024/12/27.
//

#include "memory_scanner.h"
#include "../util/stack.h"

#define BUFFER_SIZE 4096

const char *MEMORY_SCANNER_TAG = "memory_scanner";

const char *currentLibName = NULL;
struct Stack *stack = NULL;

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

bool processMemoryNode(struct MemStructNode *p) {
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
    node->next = NULL;

    sscanf(line, "%lx-%lx %s %lx %x:%x %lu %s",
           &node->start, &node->end, node->permission, &node->offset,
           &node->main_dev, &node->sub_dev, &node->inode, node->elf_path);
    if (processMemoryNode(node)) {
        stack->push(stack, node);
    } else {
        free(node->permission);
        free(node->elf_path);
        free(node);
    }
    return NULL;
}

void travel_mem_struct(pid_t pid) {
    char mem_map_path[1024];
    sprintf(mem_map_path, "/proc/%d/maps", pid);
    FILE *source = fopen(mem_map_path, "rb");
    if (source == NULL) {
        return;
    }
    struct MemStructNode *head, *p;
    head = (struct MemStructNode *) malloc(sizeof(struct MemStructNode));
    p = head;

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
                    parse_line(line);
                    idx = 0;
                    continue;
                }
                line[idx++] = current;
            } else {
                line[idx++] = '\0';
                parse_line(line);
                idx = 0;
            }
        }
    }
    fclose(source);
}

bool isFuncWritable(uint64_t addr) {
    if (stack == NULL) {
        LOGE("memory have not been scan.");
        return false;
    }
    stack->resetIterator(stack);
    struct MemStructNode *node = stack->iteratorNext(stack);
    while (node != NULL) {
        LOGD("node:[%02lX - %02lX]", node->start, node->end);
        if (node->start <= addr && addr <= node->end) {
            return true;
        }
        node = stack->iteratorNext(stack);
    }
    return false;
}

void setTextWritable(const char *libName) {
    currentLibName = libName;
    if (stack != NULL) {
        free(stack);
    }
    stack = createStack(MEMORY_SCANNER_TAG);
    pid_t pid, ppid, tid;
    pid = getpid();
    ppid = getppid();
    tid = gettid();
    uid_t uid = getuid();
    LOGD("pid=%d, ppid=%d, tid=%d, uid=%d\n", pid, ppid, tid, uid);
    if (pid == tid) {
        LOGD("[+] main thread");
    }
    travel_mem_struct(pid);
    LOGD("[+] travel_mem_struct return");
}
