#include <stdio.h>
#include <stdarg.h>
#include "log.h"

void LOG(const char * tag, int num, const char * fmt, ...)
{
#ifdef ENABLE_FILE_LOGGING
    printf("%s:%d: ", tag, num);
#endif
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}
