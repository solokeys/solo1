/*
 * Copyright (C) 2018 SoloKeys, Inc. <https://solokeys.com/>
 * 
 * This file is part of Solo.
 * 
 * Solo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Solo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Solo.  If not, see <https://www.gnu.org/licenses/>
 * 
 * This code is available under licenses for commercial use.
 * Please contact SoloKeys for more information.
 */
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
