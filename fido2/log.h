// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _LOG_H
#define _LOG_H

#ifdef APP_CONFIG
#include APP_CONFIG
#endif 

#include <stdint.h>

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif

#define ENABLE_FILE_LOGGING

void LOG(uint32_t tag, const char * filename, int num, const char * fmt, ...);
void LOG_HEX(uint32_t tag, uint8_t * data, int length);

void set_logging_tag(uint32_t tag);

typedef enum
{
    TAG_GEN      = (1 << 0),
    TAG_MC       = (1 << 1),
    TAG_GA       = (1 << 2),
    TAG_CP       = (1 << 3),
    TAG_ERR      = (1 << 4),
    TAG_PARSE    = (1 << 5),
    TAG_CTAP     = (1 << 6),
    TAG_U2F      = (1 << 7),
    TAG_DUMP     = (1 << 8),
    TAG_GREEN    = (1 << 9),
    TAG_RED      = (1 << 10),
    TAG_TIME     = (1 << 11),
    TAG_HID      = (1 << 12),
    TAG_USB      = (1 << 13),
    TAG_WALLET   = (1 << 14),
    TAG_STOR     = (1 << 15),
    TAG_DUMP2    = (1 << 16),
    TAG_BOOT     = (1 << 17),
    TAG_EXT      = (1 << 18),
    TAG_NFC      = (1 << 19),
    TAG_NFC_APDU = (1 << 20),
    TAG_CCID     = (1 << 21),
    TAG_CM       = (1 << 22),

    TAG_NO_TAG   = (1UL << 30),
    TAG_FILENO   = (1UL << 31)
} LOG_TAG;

#if defined(DEBUG_LEVEL) && DEBUG_LEVEL > 0

void set_logging_mask(uint32_t mask);
#define printf1(tag,fmt, ...) LOG(tag & ~(TAG_FILENO), NULL, 0, fmt, ##__VA_ARGS__)
#define printf2(tag,fmt, ...) LOG(tag | TAG_FILENO,__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define printf3(tag,fmt, ...) LOG(tag | TAG_FILENO,__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define dump_hex1(tag,data,len) LOG_HEX(tag,data,len)

uint32_t timestamp();

#else

#define set_logging_mask(mask)
#define printf1(tag,fmt, ...)
#define printf2(tag,fmt, ...)
#define printf3(tag,fmt, ...)
#define dump_hex1(tag,data,len)
#define timestamp()

#endif

#endif
