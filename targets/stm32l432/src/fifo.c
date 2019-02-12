// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "fifo.h"
#include "log.h"


FIFO_CREATE(debug,4096,1)

FIFO_CREATE(hidmsg,100,64)

#if TEST_FIFO
FIFO_CREATE(test,10,100)
void fifo_test()
{
    int ret;
    uint8_t data[10][100];
    uint8_t verif[10][100];

    printf1(TAG_GREEN,"init\r\n");
    for (int i = 0; i < 10; i++)
    {
        memset(data[i],i,100);
    }

    for (int i = 0; i < 10; i++)
    {
        printf1(TAG_GREEN,"rhead: %d, whead: %d\r\n", fifo_test_rhead(), fifo_test_whead());
        ret = fifo_test_add(data[i]);
        printf1(TAG_GREEN,"%d\r\n",i);
        if (ret != 0)
        {
            printf1(TAG_GREEN,"fifo_test_add fail\r\n");
            goto fail;
        }
    }

    for (int i = 0; i < 10; i++)
    {
        printf1(TAG_GREEN,"rhead: %d, whead: %d\r\n", fifo_test_rhead(), fifo_test_whead());
        ret = fifo_test_take(verif[i]);
        printf1(TAG_GREEN,"%d\r\n",i );
        if (ret != 0)
        {
            printf1(TAG_GREEN,"fifo_test_take fail\r\n");
            goto fail;
        }

        if (memcmp(verif[i], data[i], 100) != 0)
        {
            printf1(TAG_GREEN,"fifo_test_take result fail\r\n");
            dump_hex1(TAG_GREEN,data[i],100);
            dump_hex1(TAG_GREEN,verif[i],100);
            goto fail;
        }
    }

    for (int i = 0; i < 10; i++)
    {
        printf1(TAG_GREEN,"rhead: %d, whead: %d\r\n", fifo_test_rhead(), fifo_test_whead());
        ret = fifo_test_add(data[i]);
        if (ret != 0)
        {
            printf1(TAG_GREEN,"fifo_test_add 2 fail\r\n");
            goto fail;
        }
    }

    ret = fifo_test_add(data[0]);
    if (ret == 0)
    {
        printf1(TAG_GREEN,"fifo_test_add should have failed\r\n");
        goto fail;
    }



    for (int i = 0; i < 10; i++)
    {
        printf1(TAG_GREEN,"rhead: %d, whead: %d\r\n", fifo_test_rhead(), fifo_test_whead());
        ret = fifo_test_take(verif[i]);
        if (ret != 0)
        {
            printf1(TAG_GREEN,"fifo_test_take fail\r\n");
            goto fail;
        }

        if (memcmp(verif[i], data[i], 100) != 0)
        {
            printf1(TAG_GREEN,"fifo_test_take result fail\r\n");
            goto fail;
        }
    }

    ret = fifo_test_take(verif[0]);
    if (ret == 0)
    {
        printf1(TAG_GREEN,"fifo_test_take should have failed\r\n");
        goto fail;
    }

    printf1(TAG_GREEN,"test pass!\r\n");
    return ;
    fail:
    while(1)
        ;
}
#endif
