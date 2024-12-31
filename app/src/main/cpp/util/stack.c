//
// Created by Park Yu on 2024/11/26.
//

#include "stack.h"
#include "stdlib.h"

#ifdef __cplusplus
extern "C" {
#endif

static const char *STACK_TAG = "writableMemoryNodeStack";

struct StackNode {
    void *data;
    struct StackNode *next;
};

void push(struct Stack *stack, void *data) {
    struct StackNode *newNode = (struct StackNode *) malloc(sizeof(struct StackNode));
    newNode->data = data;
    newNode->next = NULL;

    if (stack->stackTop != NULL) {
        newNode->next = stack->stackTop;
    }
    stack->stackTop = newNode;
    stack->stackSize++;
}

void *top(struct Stack *stack) {
    if (stack->stackTop == NULL) {
        return NULL;
    }
    return stack->stackTop->data;
}

void *pop(struct Stack *stack) {
    if (stack->stackTop == NULL) {
        return NULL;
    }
    struct StackNode *topNode = stack->stackTop;
    void *data = topNode->data;

    stack->stackTop = topNode->next;

    free(topNode);
    stack->stackSize--;
    return data;
}

bool removeData(struct Stack *stack, void *data) {
    if (stack->stackTop == NULL) {
        return NULL;
    }
    struct StackNode *node = stack->stackTop;
    struct StackNode *preNode = NULL;
    while (node != NULL && node->data != data) {
        preNode = node;
        node = node->next;
    }
    if (node == NULL) {
        return false;
    }
    if (preNode == NULL) {
        //match top, need change top before free
        stack->stackTop = stack->stackTop->next;
    } else {
        preNode->next = node->next;
    }
    free(node);
    stack->stackSize--;
    return true;
}

int size(struct Stack *stack) {
    return stack->stackSize;
}

void *get(struct Stack *stack, int index) {
    if (index < 0 || index >= stack->stackSize) {
        return NULL;
    }

    struct StackNode *current = stack->stackTop;
    for (int i = 0; i < index; i++) {
        current = current->next;
    }
    return current->data;
}

void resetIterator(struct Stack *stack) {
    stack->it = stack->stackTop;
}

void *iteratorNext(struct Stack *stack) {
    if (stack->it == NULL) {
        return NULL;
    }
    void *result = stack->it->data;
    stack->it = stack->it->next;
    return result;
}

void releaseStack(struct Stack *stack) {
    resetIterator(stack);
    struct StackNode *p = stack->it;
    while (p != NULL) {
        struct StackNode *current = p;
        p = p->next;
        free(current);
    }
    free(stack);
}

struct Stack *createStack(const char *spaceTag) {
    struct Stack *stack = (struct Stack *) malloc(sizeof(struct Stack));
    stack->spaceTag = spaceTag;
    stack->push = push;
    stack->top = top;
    stack->pop = pop;
    stack->remove = removeData;
    stack->size = size;
    stack->get = get;
    stack->it = NULL;
    stack->resetIterator = resetIterator;
    stack->iteratorNext = iteratorNext;
    stack->stackTop = NULL;
    return stack;
}

#ifdef __cplusplus
}
#endif
