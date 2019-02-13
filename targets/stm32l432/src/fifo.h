// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _FIFO_H_
#define _FIFO_H_

#include APP_CONFIG

#ifndef TEST_FIFO
#define TEST_FIFO 0
#endif

#define FIFO_CREATE(NAME,LENGTH,BYTES)\
int __##NAME##_WRITE_PTR = 0;\
int __##NAME##_READ_PTR = 0;\
int __##NAME##_SIZE = 0;\
static uint8_t __##NAME##_WRITE_BUF[BYTES * LENGTH];\
\
int fifo_##NAME##_add(uint8_t * c)\
{\
    if (__##NAME##_SIZE < LENGTH)\
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
    if ( __##NAME##_SIZE > 0)\
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
uint32_t fifo_##NAME##_rhead()\
{\
    return (__##NAME##_READ_PTR);\
}\
uint32_t fifo_##NAME##_whead()\
{\
    return (__##NAME##_WRITE_PTR);\
}\

#define FIFO_CREATE_H(NAME)\
int fifo_##NAME##_add(uint8_t * c);\
int fifo_##NAME##_take(uint8_t * c);\
uint32_t fifo_##NAME##_size();\
uint32_t fifo_##NAME##_rhead();\
uint32_t fifo_##NAME##_whead();\

FIFO_CREATE_H(hidmsg)

FIFO_CREATE_H(debug)

FIFO_CREATE_H(test)

void fifo_test();

#endif
