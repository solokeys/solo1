/*
   Copyright 2018 Conor Patrick

   Permission is hereby granted, free of charge, to any person obtaining a copy of
   this software and associated documentation files (the "Software"), to deal in
   the Software without restriction, including without limitation the rights to
   use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
   of the Software, and to permit persons to whom the Software is furnished to do
   so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/
#ifndef _LOG_H
#define _LOG_H

#include "app.h"
#include <stdint.h>

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif

#define ENABLE_FILE_LOGGING

void LOG(uint32_t tag, const char * filename, int num, const char * fmt, ...);
void LOG_HEX(uint32_t tag, uint8_t * data, int length);
void set_logging_mask(uint32_t mask);
void set_logging_tag(uint32_t tag);

typedef enum
{
    TAG_GEN = (1 << 0),
    TAG_MC = (1 << 1),
    TAG_GA = (1 << 2),
    TAG_CP = (1 << 3),
    TAG_ERR = (1 << 4),
    TAG_PARSE= (1 << 5),
    TAG_CTAP = (1 << 6),
    TAG_U2F = (1 << 7),
    TAG_DUMP = (1 << 8),
    TAG_GREEN = (1 << 9),
    TAG_RED= (1 << 10),
    TAG_TIME= (1 << 11),
    TAG_HID = (1 << 12),
    TAG_USB = (1 << 13),
    TAG_WALLET = (1 << 14),
    TAG_STOR = (1 << 15),
    TAG_DUMP2 = (1 << 16),

    TAG_FILENO = (1<<31)
} LOG_TAG;

#if DEBUG_LEVEL == 1

#define printf1(tag,fmt, ...) LOG(tag & ~(TAG_FILENO), NULL, 0, fmt, ##__VA_ARGS__)
#define printf2(tag,fmt, ...) LOG(tag | TAG_FILENO,__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define printf3(tag,fmt, ...) LOG(tag | TAG_FILENO,__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define dump_hex1(tag,data,len) LOG_HEX(tag,data,len)

#else

#define printf1(fmt, ...)
#define printf2(fmt, ...)
#define printf3(fmt, ...)
#define dump_hex1(tag,data,len)

#endif

#endif
