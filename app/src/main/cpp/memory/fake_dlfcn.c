// Copyright (c) 2016 avs333
// Updated 2024 park671
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
//		of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
//		to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//		copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
//		The above copyright notice and this permission notice shall be included in all
//		copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// 		AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#include <android/log.h>
#include "../util/log.h"

#define log_err(fmt, args...) LOGE((const char *) fmt, ##args)

struct ctx {
    void *load_addr;
    void *strtab;
    void *dynstr;
    void *dynsym;
    void *symtab;
    int ndynsyms;
    int nsymtabs;
    off_t bias;
};

static int fake_dlclose(void *handle) {
    if (handle) {
        struct ctx *ctx = (struct ctx *) handle;
        if (ctx->dynsym) free(ctx->dynsym);    /* we're saving dynsym and strtab */
        if (ctx->dynstr) free(ctx->dynstr);    /* from library file just in case */
        if (ctx->symtab) free(ctx->symtab);    /* from library file just in case */
        if (ctx->strtab) free(ctx->strtab);    /* from library file just in case */
        free(ctx);
    }
    return 0;
}

/* flags are ignored */
static void *fake_dlopen_with_path(const char *libpath, int flags) {
    FILE *maps;
    char buff[256];
    struct ctx *ctx = 0;
    off_t load_addr, size;
    int k, fd = -1, found = 0;
    char *shoff;
    Elf64_Ehdr *elf = (Elf64_Ehdr *) MAP_FAILED;

#define fatal(fmt, args...) do { log_err(fmt,##args); goto err_exit; } while(0)

    maps = fopen("/proc/self/maps", "r");
    if (!maps) fatal("failed to open maps");

    while (!found && fgets(buff, sizeof(buff), maps)) {
        if (strstr(buff, libpath) && (strstr(buff, "r-xp") || strstr(buff, "r--p"))) found = 1;
    }
    fclose(maps);

    if (!found) fatal("%s not found in my userspace", libpath);

    if (sscanf(buff, "%lx", &load_addr) != 1)
        fatal("failed to read load address for %s", libpath);

    /* Now, mmap the same library once again */

    fd = open(libpath, O_RDONLY);
    if (fd < 0) fatal("failed to open %s", libpath);

    size = lseek(fd, 0, SEEK_END);
    if (size <= 0) fatal("lseek() failed for %s", libpath);

    elf = (Elf64_Ehdr *) mmap(0, size, PROT_READ, MAP_SHARED, fd, 0);
    LOGD("target so size=%ld", size);
    close(fd);
    fd = -1;

    if (elf == MAP_FAILED) fatal("mmap() failed for %s", libpath);

    ctx = (struct ctx *) calloc(1, sizeof(struct ctx));
    if (!ctx) fatal("no memory for %s", libpath);

    ctx->load_addr = (void *) load_addr;

    LOGD("section num=%d", elf->e_shnum);

    //found .shstrtab first
    shoff = ((char *) elf) + elf->e_shoff;
    for (k = 0; k < elf->e_shstrndx; k++, shoff += elf->e_shentsize) {
        //skip
    }
    Elf64_Shdr *shstrtab = (Elf64_Shdr *) shoff;
    if (shstrtab->sh_type != SHT_STRTAB) {
        fatal("shstrtab error");
    }
    //fill info
    shoff = ((char *) elf) + elf->e_shoff;
    bool progbitsFound = false;
    for (k = 0; k < elf->e_shnum; k++, shoff += elf->e_shentsize) {
        Elf64_Shdr *sh = (Elf64_Shdr *) shoff;
        switch (sh->sh_type) {
            case SHT_SYMTAB: {
                LOGD("symtab found");
                if (ctx->symtab) {
                    //skip
                    break;
                }
                ctx->symtab = malloc(sh->sh_size);
                if (!ctx->symtab) fatal("%s: no memory for .symtab", libpath);
                memcpy(ctx->symtab, ((char *) elf) + sh->sh_offset, sh->sh_size);
                ctx->nsymtabs = (sh->sh_size / sizeof(Elf64_Sym));
                break;
            }

            case SHT_DYNSYM: {
                LOGD("dynsym found");
                if (ctx->dynsym) {
                    //skip
                    break;
                }
                ctx->dynsym = malloc(sh->sh_size);
                if (!ctx->dynsym) fatal("%s: no memory for .dynsym", libpath);
                memcpy(ctx->dynsym, ((char *) elf) + sh->sh_offset, sh->sh_size);
                ctx->ndynsyms = (sh->sh_size / sizeof(Elf64_Sym));
                break;
            }
            case SHT_STRTAB: {
                if (strcmp(((((char *) elf) + shstrtab->sh_offset) + sh->sh_name), ".dynstr") ==
                    0) {
                    LOGD("dynstr found");
                    ctx->dynstr = malloc(sh->sh_size);
                    if (!ctx->dynstr) fatal("%s: no memory for .dynstr", libpath);
                    memcpy(ctx->dynstr, ((char *) elf) + sh->sh_offset, sh->sh_size);
                } else if (
                        strcmp(((((char *) elf) + shstrtab->sh_offset) + sh->sh_name), ".strtab") ==
                        0) {
                    LOGD("strtab found");
                    ctx->strtab = malloc(sh->sh_size);
                    if (!ctx->strtab) fatal("%s: no memory for .strtab", libpath);
                    memcpy(ctx->strtab, ((char *) elf) + sh->sh_offset, sh->sh_size);
                }
                break;
            }

            case SHT_PROGBITS: {
                if (strcmp(((((char *) elf) + shstrtab->sh_offset) + sh->sh_name), ".text") == 0) {
                    LOGD("progbits(.text) found");
                    ctx->bias = (off_t) sh->sh_addr - (off_t) sh->sh_offset;
                }
                break;
            }
        }
    }
    munmap(elf, size);
    elf = 0;
    if (!ctx->dynstr || !ctx->dynsym) {
        fatal("dynamic sections not found");
    }

    if (!ctx->symtab || !ctx->strtab) {
        LOGW("symtab can not found, maybe stripped");
    }

#undef fatal

    return ctx;

    err_exit:
    if (fd >= 0) close(fd);
    if (elf != MAP_FAILED) munmap(elf, size);
    fake_dlclose(ctx);
    return 0;
}

static const char *const kSystemLibDir = "/system/lib64/";
static const char *const kOdmLibDir = "/odm/lib64/";
static const char *const kVendorLibDir = "/vendor/lib64/";
static const char *const kApexLibDir = "/apex/com.android.runtime/lib64/";
static const char *const kApexArtNsLibDir = "/apex/com.android.art/lib64/";

static void *fake_dlopen(const char *filename, int flags) {
    if (strlen(filename) > 0 && filename[0] == '/') {
        return fake_dlopen_with_path(filename, flags);
    } else {
        char buf[512] = {0};
        void *handle = NULL;
        //sysmtem
        strcpy(buf, kSystemLibDir);
        strcat(buf, filename);
        handle = fake_dlopen_with_path(buf, flags);
        if (handle) {
            return handle;
        }

        // apex in ns com.android.runtime
        memset(buf, 0, sizeof(buf));
        strcpy(buf, kApexLibDir);
        strcat(buf, filename);
        handle = fake_dlopen_with_path(buf, flags);
        if (handle) {
            return handle;
        }

        // apex in ns com.android.art
        memset(buf, 0, sizeof(buf));
        strcpy(buf, kApexArtNsLibDir);
        strcat(buf, filename);
        handle = fake_dlopen_with_path(buf, flags);
        if (handle) {
            return handle;
        }

        //odm
        memset(buf, 0, sizeof(buf));
        strcpy(buf, kOdmLibDir);
        strcat(buf, filename);
        handle = fake_dlopen_with_path(buf, flags);
        if (handle) {
            return handle;
        }

        //vendor
        memset(buf, 0, sizeof(buf));
        strcpy(buf, kVendorLibDir);
        strcat(buf, filename);
        handle = fake_dlopen_with_path(buf, flags);
        if (handle) {
            return handle;
        }

        return fake_dlopen_with_path(filename, flags);
    }
}

static void *fake_dlsym(void *handle, const char *name) {
    if (handle == NULL) {
        LOGE("handle is null");
        return NULL;
    }
    int k;
    struct ctx *ctx = (struct ctx *) handle;
    Elf64_Sym *sym = (Elf64_Sym *) ctx->dynsym;
    char *strings = (char *) ctx->dynstr;
    for (k = 0; k < ctx->ndynsyms; k++, sym++) {
        if (strcmp(strings + sym->st_name, name) == 0) {
            LOGD("dynsym:[%d]%s", k, strings + sym->st_name);
            /*  NB: sym->st_value is an offset into the section for relocatables,
            but a VMA for shared libs or exe files, so we have to subtract the bias */
            void *ret = (char *) ctx->load_addr + sym->st_value - ctx->bias;
            return ret;
        }
    }
    sym = (Elf64_Sym *) ctx->symtab;
    strings = (char *) ctx->strtab;
    for (k = 0; k < ctx->nsymtabs; k++, sym++) {
        if (strcmp(strings + sym->st_name, name) == 0) {
            /*  NB: sym->st_value is an offset into the section for relocatables,
            but a VMA for shared libs or exe files, so we have to subtract the bias */
            LOGD("symtab(equal):[%d]%s", k, strings + sym->st_name);
            void *ret = (char *) ctx->load_addr + sym->st_value - ctx->bias;
            return ret;
        }
    }
    sym = (Elf64_Sym *) ctx->symtab;
    strings = (char *) ctx->strtab;
    for (k = 0; k < ctx->nsymtabs; k++, sym++) {
        if (strstr(strings + sym->st_name, name) != NULL) {
            LOGD("symtab(substring):[%d]%s", k, strings + sym->st_name);
            /*  NB: sym->st_value is an offset into the section for relocatables,
            but a VMA for shared libs or exe files, so we have to subtract the bias */
            void *ret = (char *) ctx->load_addr + sym->st_value - ctx->bias;
            return ret;
        }
    }
    return 0;
}


static const char *fake_dlerror() {
    return NULL;
}

// =============== implementation for compat ==========
static int SDK_INT = -1;

static int get_sdk_level() {
    if (SDK_INT > 0) {
        return SDK_INT;
    }
    char sdk[PROP_VALUE_MAX] = {0};;
    __system_property_get("ro.build.version.sdk", sdk);
    SDK_INT = atoi(sdk);
    return SDK_INT;
}

int dlclose_ex(void *handle) {
    if (get_sdk_level() >= 24) {
        return fake_dlclose(handle);
    } else {
        return dlclose(handle);
    }
}

void *dlopen_ex(const char *filename, int flags) {
    if (get_sdk_level() >= 24) {
        return fake_dlopen(filename, flags);
    } else {
        return dlopen(filename, flags);
    }
}

void *dlsym_ex(void *handle, const char *symbol) {
    if (get_sdk_level() >= 24) {
        return fake_dlsym(handle, symbol);
    } else {
        return dlsym(handle, symbol);
    }
}

const char *dlerror_ex() {
    if (get_sdk_level() >= 24) {
        return fake_dlerror();
    } else {
        return dlerror();
    }
}
