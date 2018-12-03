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
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "log.h"
#include "util.h"

#if DEBUG_LEVEL > 0

static uint32_t LOGMASK = TAG_FILENO;


void set_logging_mask(uint32_t mask)
{
    LOGMASK = mask;
}


struct logtag
{
    uint32_t tagn;
    const char * tag;
};

struct logtag tagtable[] = {
    {TAG_GEN,""},
    {TAG_MC,"MC"},
    {TAG_GA,"GA"},
    {TAG_CP,"CP"},
    {TAG_ERR,"ERR"},
    {TAG_PARSE,"PARSE"},
    {TAG_CTAP,"CTAP"},
    {TAG_U2F,"U2F"},
    {TAG_DUMP,"DUMP"},
    {TAG_DUMP2,"DUMP2"},
    {TAG_HID,"HID"},
    {TAG_USB,"USB"},
    {TAG_GREEN,"[1;32mDEBUG[0m"},
    {TAG_RED,"[1;31mDEBUG[0m"},
    {TAG_TIME,"[1;33mTIME[0m"},
    {TAG_WALLET,"[1;34mWALLET[0m"},
    {TAG_STOR,"[1;35mSTOR[0m"},
    {TAG_BOOT,"[1;36mBOOT[0m"},
};


__attribute__((weak)) void set_logging_tag(uint32_t tag)
{
    // nothing
}

void LOG(uint32_t tag, const char * filename, int num, const char * fmt, ...)
{
    int i;

    if (((tag & 0x7fffffff) & LOGMASK) == 0)
    {
        return;
    }
    for (i = 0; i < sizeof(tagtable)/sizeof(struct logtag); i++)
    {
        if (tag & tagtable[i].tagn)
        {
            if (tagtable[i].tag[0]) printf("[%s] ", tagtable[i].tag);
            i = 0;
            break;
        }
    }
    if (i != 0)
    {
        printf2(TAG_ERR,"INVALID LOG TAG\n");
        exit(1);
    }
    set_logging_tag(tag);
#ifdef ENABLE_FILE_LOGGING
    if (tag & TAG_FILENO)
    {
        printf("%s:%d: ", filename, num);
    }
#endif
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void LOG_HEX(uint32_t tag, uint8_t * data, int length)
{
    if (((tag & 0x7fffffff) & LOGMASK) == 0)
    {
        return;
    }
    set_logging_tag(tag);
    dump_hex(data,length);
}
#endif
