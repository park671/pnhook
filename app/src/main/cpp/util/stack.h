//
// Created by Park Yu on 2024/11/26.
//

#ifndef PCC_STACK_H
#define PCC_STACK_H

#include "stdbool.h"

#ifdef __cplusplus
extern "C" {
#endif

struct StackNode;

struct Stack {
    const char *spaceTag;
    struct StackNode *stackTop;
    struct StackNode *it;
    int stackSize;

    void (*push)(struct Stack *stack, void *data);

    void *(*top)(struct Stack *stack);

    void *(*pop)(struct Stack *stack);

    bool (*remove)(struct Stack *stack, void *data);

    int (*size)(struct Stack *stack);

    void *(*get)(struct Stack *stack, int index);

    void (*resetIterator)(struct Stack *stack);

    void *(*iteratorNext)(struct Stack *stack);
};

struct Stack *createStack(const char *spaceTag);

void releaseStack(struct Stack *stack);

#ifdef __cplusplus
}
#endif

#endif //PCC_STACK_H
