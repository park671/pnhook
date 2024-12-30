//
// Created by Park Yu on 2024/12/30.
//

#ifndef PNHOOK_ART_HOOK_H
#define PNHOOK_ART_HOOK_H

#include "jni.h"

bool initArtHook(JNIEnv *env, jobject m1, jobject m2);
bool hookArtMethod(JNIEnv *env, jobject method);

#endif //PNHOOK_ART_HOOK_H
