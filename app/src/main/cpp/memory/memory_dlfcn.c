#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#include "../util/log.h"
#include "memory_dlfcn.h"
#include "memory_scanner.h"

const char *MEMORY_DLFCN_TAG = "memory_dlfcn";

//#define LOG_DBG

#ifdef LOG_DBG
#define log_err(fmt, args...) loge(MEMORY_DLFCN_TAG, (const char *) fmt, ##args)
#else
#define log_err(fmt, args...)
#endif

struct fake_dl_context {
    void *load_addr;
    void *strtab;
    void *dynstr;
    void *dynsym;
    void *symtab;
    int ndynsyms;
    int nsymtabs;
    off_t bias;
};

unsigned char feature_code[] = {0x7F, 0x45, 0x4C, 0x46};

const unsigned int feature_code_len = 4;

//verify if the memory contains elf header
static bool verifyElfHeader(void *start, void *end) {
    int64_t memorySize = end - start;
    if (memorySize < feature_code_len) {
        return false;
    }
    unsigned char *startBytePtr = start;
    for (int i = 0; i < feature_code_len; i++) {
        if (startBytePtr[i] != feature_code[i]) {
            return false;
        }
    }
    return true;
}

static int fake_dlclose(void *handle) {
    if (handle) {
        struct fake_dl_context *ctx = (struct fake_dl_context *) handle;
        if (ctx->dynsym) free(ctx->dynsym);    /* we're saving dynsym and strtab */
        if (ctx->dynstr) free(ctx->dynstr);    /* from library file just in case */
        if (ctx->symtab) free(ctx->symtab);    /* from library file just in case */
        if (ctx->strtab) free(ctx->strtab);    /* from library file just in case */
        free(ctx);
    }
    return 0;
}

/* flags are ignored */
static void *fake_dlopen(const char *libpath, int flags) {
    struct fake_dl_context *pContext = 0;
    off_t load_addr, size;
    int index, fd = -1;
    bool found = false;
    char *shoff;
    Elf64_Ehdr *elf = (Elf64_Ehdr *) MAP_FAILED;

#define fatal(fmt, args...) do { log_err(fmt,##args); goto err_exit; } while(0)

    struct Stack *mapStack = travelMemStruct();
    load_addr = INT64_MAX;
    mapStack->resetIterator(mapStack);
    struct MemStructNode *loadStartNode = NULL;
    struct MemStructNode *memStructNode = mapStack->iteratorNext(mapStack);
    while (memStructNode != NULL) {
        if (strstr(memStructNode->elf_path, libpath)) {
            if (!found) {
                found = true;
                loadStartNode = memStructNode;
                libpath = memStructNode->elf_path;
                load_addr = memStructNode->start;
            } else {
                if (strcmp(libpath, memStructNode->elf_path) != 0) {
                    fatal("duplicated lib matched: %s, %s", libpath, memStructNode->elf_path);
                }
                if (load_addr > memStructNode->start) {
                    load_addr = memStructNode->start;
                    loadStartNode = memStructNode;
                }
            }
        }
        memStructNode = mapStack->iteratorNext(mapStack);
    }

    if (!found) fatal("%s not found in my userspace", libpath);
    /* Now, mmap the same library once again */

    if (verifyElfHeader((void *) loadStartNode->start, (void *) loadStartNode->end)) {
        logi(MEMORY_DLFCN_TAG, "load addr elf header verification success");
    } else {
        logw(MEMORY_DLFCN_TAG, "load addr elf header verification fail");
    }

    fd = open(libpath, O_RDONLY);
    if (fd < 0) fatal("failed to open %s", libpath);

    size = lseek(fd, 0, SEEK_END);
    if (size <= 0) fatal("lseek() failed for %s", libpath);

    elf = (Elf64_Ehdr *) mmap(0, size, PROT_READ, MAP_SHARED, fd, 0);
    logd(MEMORY_DLFCN_TAG, "target so size=%ld", size);
    close(fd);
    fd = -1;

    if (elf == MAP_FAILED) fatal("mmap() failed for %s", libpath);

    pContext = (struct fake_dl_context *) calloc(1, sizeof(struct fake_dl_context));
    if (!pContext) fatal("no memory for %s", libpath);

    pContext->load_addr = (void *) load_addr;
    logd(MEMORY_DLFCN_TAG, "lib loaded addr=0x%02lX, section num=%d", load_addr, elf->e_shnum);

    //found .shstrtab first
    shoff = ((char *) elf) + elf->e_shoff;
    for (index = 0; index < elf->e_shstrndx; index++, shoff += elf->e_shentsize) {
        //skip
    }
    Elf64_Shdr *shstrtab = (Elf64_Shdr *) shoff;
    if (shstrtab->sh_type != SHT_STRTAB) {
        fatal("shstrtab error");
    }
    //fill info
    shoff = ((char *) elf) + elf->e_shoff;
    bool progbitsFound = false;
    for (index = 0; index < elf->e_shnum; index++, shoff += elf->e_shentsize) {
        Elf64_Shdr *sh = (Elf64_Shdr *) shoff;
        switch (sh->sh_type) {
            case SHT_SYMTAB: {
                logd(MEMORY_DLFCN_TAG, "symtab found");
                if (pContext->symtab) {
                    //skip
                    break;
                }
                pContext->symtab = malloc(sh->sh_size);
                if (!pContext->symtab) fatal("%s: no memory for .symtab", libpath);
                memcpy(pContext->symtab, ((char *) elf) + sh->sh_offset, sh->sh_size);
                pContext->nsymtabs = (sh->sh_size / sizeof(Elf64_Sym));
                break;
            }

            case SHT_DYNSYM: {
                logd(MEMORY_DLFCN_TAG, "dynsym found");
                if (pContext->dynsym) {
                    //skip
                    break;
                }
                pContext->dynsym = malloc(sh->sh_size);
                if (!pContext->dynsym) fatal("%s: no memory for .dynsym", libpath);
                memcpy(pContext->dynsym, ((char *) elf) + sh->sh_offset, sh->sh_size);
                pContext->ndynsyms = (sh->sh_size / sizeof(Elf64_Sym));
                break;
            }
            case SHT_STRTAB: {
                if (strcmp(((((char *) elf) + shstrtab->sh_offset) + sh->sh_name), ".dynstr") ==
                    0) {
                    logd(MEMORY_DLFCN_TAG, "dynstr found");
                    pContext->dynstr = malloc(sh->sh_size);
                    if (!pContext->dynstr) fatal("%s: no memory for .dynstr", libpath);
                    memcpy(pContext->dynstr, ((char *) elf) + sh->sh_offset, sh->sh_size);
                } else if (
                        strcmp(((((char *) elf) + shstrtab->sh_offset) + sh->sh_name), ".strtab") ==
                        0) {
                    logd(MEMORY_DLFCN_TAG, "strtab found");
                    pContext->strtab = malloc(sh->sh_size);
                    if (!pContext->strtab) fatal("%s: no memory for .strtab", libpath);
                    memcpy(pContext->strtab, ((char *) elf) + sh->sh_offset, sh->sh_size);
                }
                break;
            }

            case SHT_PROGBITS: {
                if (strcmp(((((char *) elf) + shstrtab->sh_offset) + sh->sh_name), ".text") == 0) {
                    logd(MEMORY_DLFCN_TAG, "progbits(.text) found");
                    pContext->bias = (off_t) sh->sh_addr - (off_t) sh->sh_offset;
                }
                break;
            }
        }
    }
    munmap(elf, size);
    elf = 0;
    if (!pContext->dynstr || !pContext->dynsym) {
        fatal("dynamic sections not found");
    }

    if (!pContext->symtab || !pContext->strtab) {
        logw(MEMORY_DLFCN_TAG, "symtab can not found, maybe stripped");
    }

#undef fatal
    releaseMapStack(mapStack);
    return pContext;

    err_exit:
    releaseMapStack(mapStack);
    if (fd >= 0) close(fd);
    if (elf != MAP_FAILED) munmap(elf, size);
    fake_dlclose(pContext);
    return 0;
}

static void *fake_dlsym(void *handle, const char *name) {
    if (handle == NULL) {
        loge(MEMORY_DLFCN_TAG, "handle is null");
        return NULL;
    }
    int index;
    struct fake_dl_context *pContext = (struct fake_dl_context *) handle;
    Elf64_Sym *sym = (Elf64_Sym *) pContext->dynsym;
    char *strings = (char *) pContext->dynstr;
    for (index = 0; index < pContext->ndynsyms; index++, sym++) {
        if (strcmp(strings + sym->st_name, name) == 0) {
            logd(MEMORY_DLFCN_TAG, "dynsym:[%d]%s", index, strings + sym->st_name);
            /*  NB: sym->st_value is an offset into the section for relocatables,
            but a VMA for shared libs or exe files, so we have to subtract the bias */
            void *ret = (char *) pContext->load_addr + sym->st_value - pContext->bias;
            return ret;
        }
    }
    sym = (Elf64_Sym *) pContext->symtab;
    strings = (char *) pContext->strtab;
    for (index = 0; index < pContext->nsymtabs; index++, sym++) {
        if (strcmp(strings + sym->st_name, name) == 0) {
            /*  NB: sym->st_value is an offset into the section for relocatables,
            but a VMA for shared libs or exe files, so we have to subtract the bias */
            logd(MEMORY_DLFCN_TAG, "symtab(equal):[%d]%s", index, strings + sym->st_name);
            void *ret = (char *) pContext->load_addr + sym->st_value - pContext->bias;
            return ret;
        }
    }
    sym = (Elf64_Sym *) pContext->symtab;
    strings = (char *) pContext->strtab;
    for (index = 0; index < pContext->nsymtabs; index++, sym++) {
        if (strstr(strings + sym->st_name, name) != NULL) {
            logd(MEMORY_DLFCN_TAG, "symtab(substring):[%d]%s", index, strings + sym->st_name);
            /*  NB: sym->st_value is an offset into the section for relocatables,
            but a VMA for shared libs or exe files, so we have to subtract the bias */
            void *ret = (char *) pContext->load_addr + sym->st_value - pContext->bias;
            return ret;
        }
    }
    return 0;
}


static const char *fake_dlerror() {
    return NULL;
}

int dlclose_ex(void *handle) {
    struct DlHandle *pDlHandle = (struct DlHandle *) handle;
    if (pDlHandle->fakeDyLib) {
        bool result = fake_dlclose(pDlHandle->handlePtr);
        free(pDlHandle);
        return result;
    } else {
        bool result = dlclose(pDlHandle->handlePtr);
        free(pDlHandle);
        return result;
    }
}

void *dlopen_ex(const char *filename, int flags) {
    struct DlHandle *handle = (struct DlHandle *) malloc(sizeof(struct DlHandle));
    void *result = dlopen(filename, flags);
    if (result != NULL) {
        handle->handlePtr = result;
        handle->fakeDyLib = false;
        return handle;
    }
    result = fake_dlopen(filename, flags);
    if (result != NULL) {
        handle->handlePtr = result;
        handle->fakeDyLib = true;
        return handle;
    }
    free(handle);
    return NULL;
}

void *dlsym_ex(void *handle, const char *symbol) {
    struct DlHandle *pDlHandle = (struct DlHandle *) handle;
    if (pDlHandle->fakeDyLib) {
        return fake_dlsym(pDlHandle->handlePtr, symbol);
    } else {
        return dlsym(pDlHandle->handlePtr, symbol);
    }
}

const char *dlerror_ex() {
    return fake_dlerror();
}
