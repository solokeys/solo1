// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#ifndef _RNG_H_
#define _RNG_H_
#include <stdint.h>

void rng_get_bytes(uint8_t * dst, size_t sz);
float shannon_entropy(float * p, size_t sz);
float rng_test(size_t n);

#endif
