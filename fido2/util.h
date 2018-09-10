#ifndef _UTIL_H
#define _UTIL_H

#include <stdint.h>

void dump_hex(uint8_t * buf, int size);

#ifndef MIN
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#endif

#endif
