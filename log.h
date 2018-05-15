#ifndef _LOG_H
#define _LOG_H

#define DEBUG_LEVEL 1
#define ENABLE_FILE_LOGGING

void LOG(const char * tag, int num, const char * fmt, ...);

#if DEBUG_LEVEL == 1

#define printf1           printf
#define printf2(fmt, ...) LOG(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define printf3(fmt, ...) LOG(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#else

#define printf1(fmt, ...)
#define printf2(fmt, ...)
#define printf3(fmt, ...)

#endif

#endif
