#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "log.h"
#include "util.h"

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
    {TAG_MC,"MC"},
    {TAG_GA,"GA"},
    {TAG_CP,"CP"},
    {TAG_ERR,"ERR"},
    {TAG_PARSE,"PARSE"},
    {TAG_CTAP,"CTAP"},
    {TAG_U2F,"U2F"},
    {TAG_DUMP,"DUMP"},
    {TAG_GREEN,"\x1b[32mDEBUG\x1b[0m"},
    {TAG_RED,"\x1b[31mDEBUG\x1b[0m"},
};

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
            printf("[%s] ", tagtable[i].tag);
            i = 0;
            break;
        }
    }
    if (i != 0)
    {
        printf("INVALID LOG TAG\n");
        exit(1);
    }
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
    dump_hex(data,length);
}
