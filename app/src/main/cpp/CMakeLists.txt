cmake_minimum_required(VERSION 3.22.1)
project("pnhook")

enable_language(ASM)
set(CMAKE_ASM_SOURCE_FILE_EXTENSIONS S)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_FLAGS -O0)
set(CMAKE_CXX_FLAGS -O0)

include_directories("memory" "util")

file(GLOB_RECURSE UTIL_DIR "util/*.c" "util/*.cpp" "util/*.cc" "util/*.s" "util/*.S")
file(GLOB_RECURSE MEMORY_DIR "memory/*.c" "memory/*.cpp" "memory/*.cc" "memory/*.s" "memory/*.S")
file(GLOB_RECURSE INLINE_HOOK_DIR "inline_hook/*.c" "inline_hook/*.cpp" "inline_hook/*.cc" "inline_hook/*.s" "inline_hook/*.S")
file(GLOB_RECURSE ART_HOOK_DIR "art_hook/*.c" "art_hook/*.cpp" "art_hook/*.cc" "art_hook/*.s" "art_hook/*.S")

file(GLOB_RECURSE MAIN_DIR "*.c" "*.cpp" "*.cc" "*.S" "*.s")


add_library(${CMAKE_PROJECT_NAME}
        SHARED
        ${UTIL_DIR}
        ${MEMORY_DIR}
        ${INLINE_HOOK_DIR}
        ${ART_HOOK_DIR}
        ${MAIN_DIR}
)

target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log)
