//
// Created by Park Yu on 2024/6/18.
//

#ifndef PLUSFRIEND_LOG_H
#define PLUSFRIEND_LOG_H

#include <android/log.h>

#define logd(tag, ...) ((void)__android_log_print(ANDROID_LOG_DEBUG, tag, __VA_ARGS__))
#define logi(tag, ...) ((void)__android_log_print(ANDROID_LOG_INFO, tag, __VA_ARGS__))
#define logv(tag, ...) ((void)__android_log_print(ANDROID_LOG_VERBOSE, tag, __VA_ARGS__))
#define logw(tag, ...) ((void)__android_log_print(ANDROID_LOG_WARN, tag, __VA_ARGS__))
#define loge(tag, ...) ((void)__android_log_print(ANDROID_LOG_ERROR, tag, __VA_ARGS__))

#endif //PLUSFRIEND_LOG_H
