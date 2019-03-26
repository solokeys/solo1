// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "stm32l4xx_ll_rng.h"

#include "rng.h"
#include "log.h"

int __errno = 0;

void rng_get_bytes(uint8_t * dst, size_t sz)
{
    uint8_t r[4];
    unsigned int i,j;
    for (i = 0; i < sz; i += 4)
    {
        while( !LL_RNG_IsActiveFlag_DRDY(RNG) )
            ;
        *(uint32_t*)&r = LL_RNG_ReadRandData32(RNG);

        if (RNG->SR & 0x66)
        {
            printf2(TAG_ERR,"Error RNG: %02lx\r\n", RNG->SR);
            exit(1);
        }

        for (j = 0; j < 4; j++)
        {
            if ((i + j) >= sz)
            {
                return;
            }
            dst[i + j] = r[j];
        }
    }
}

float shannon_entropy(float * p, size_t sz)
{

    unsigned int i;
    float entropy = 0.0f;

    for(i=0; i < sz; i++)
    {
        if (p[i] > 0.0)
        {
            entropy -= p[i] * (float) log( (double) p[i]);
        }
    }

    entropy = entropy / (float) log ((double) 2.0);

    return entropy;
}

// Measure shannon entropy of RNG
float rng_test(size_t n)
{
    unsigned int i;
    int sz = 0;
    uint8_t buf[4];
    int counts[256];
    float p[256];

    memset(counts, 0, sizeof(counts));

    for(i=0; i < n; i+=4)
    {
        rng_get_bytes(buf, 4);
        sz += 4;

        counts[buf[0]]++;
        counts[buf[1]]++;
        counts[buf[2]]++;
        counts[buf[3]]++;
    }

    for (i = 0; i < 256; i++)
    {
        p[i] = ((float)counts[i])/sz;
    }

    return shannon_entropy(p, 256);
}
