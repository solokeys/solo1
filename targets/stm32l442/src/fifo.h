#ifndef _FIFO_H_
#define _FIFO_H_

#include "app.h"

#define TEST_FIFO 0

#define FIFO_CREATE(NAME,LENGTH,BYTES)\
int __##NAME##_WRITE_PTR = 0;\
int __##NAME##_READ_PTR = 0;\
int __##NAME##_SIZE = 0;\
static uint8_t __##NAME##_WRITE_BUF[BYTES * LENGTH];\
\
int fifo_##NAME##_add(uint8_t * c)\
{\
    if (__##NAME##_WRITE_PTR != __##NAME##_READ_PTR || !__##NAME##_SIZE)\
    {\
        memmove(__##NAME##_WRITE_BUF + __##NAME##_WRITE_PTR * BYTES, c, BYTES);\
        __##NAME##_WRITE_PTR ++;\
        if (__##NAME##_WRITE_PTR >= LENGTH)\
            __##NAME##_WRITE_PTR = 0;\
        __##NAME##_SIZE++;\
        return 0;\
    }\
    return -1;\
}\
\
int fifo_##NAME##_take(uint8_t * c)\
{\
    memmove(c, __##NAME##_WRITE_BUF + __##NAME##_READ_PTR * BYTES, BYTES);\
    if (__##NAME##_READ_PTR != __##NAME##_WRITE_PTR || __##NAME##_SIZE)\
    {\
        __##NAME##_READ_PTR ++;\
        if (__##NAME##_READ_PTR >= LENGTH)\
            __##NAME##_READ_PTR = 0;\
        __##NAME##_SIZE --;\
        return 0;\
    }\
    return -1;\
}\
\
uint32_t fifo_##NAME##_size()\
{\
    return (__##NAME##_SIZE);\
}\

#define FIFO_CREATE_H(NAME,LENGTH,BYTES)\
int fifo_##NAME##_add(uint8_t * c);\
int fifo_##NAME##_take(uint8_t * c);\
uint32_t fifo_##NAME##_size();\

FIFO_CREATE_H(hidmsg,10,64)

FIFO_CREATE_H(debug,1024,1)

FIFO_CREATE_H(test,100,100)

void fifo_test();

#endif
