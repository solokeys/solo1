#ifndef _RNG_H_
#define _RNG_H_
#include <stdint.h>

void rng_get_bytes(uint8_t * dst, size_t sz);
float shannon_entropy(float * p, size_t sz);
float rng_test(size_t n);

#endif
