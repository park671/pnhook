#ifndef PNHOOK_DLFCN_H
#define PNHOOK_DLFCN_H

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct DlHandle {
    bool fakeDyLib;
    void *handlePtr;
};

void *dlopen_ex(const char *filename, int flags);

void *dlsym_ex(void *handle, const char *symbol);

int dlclose_ex(void *handle);

const char *dlerror_ex();

#ifdef __cplusplus
}
#endif

#endif //PNHOOK_DLFCN_H
