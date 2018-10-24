#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "fifo.h"




FIFO_CREATE(hidmsg,100,100)

#if TEST_FIFO
FIFO_CREATE(test,10,100)
void fifo_test()
{
    int ret;
    uint8_t data[10][100];
    uint8_t verif[10][100];

    printf("init\r\n");
    for (int i = 0; i < 10; i++)
    {
        memset(data[i],i,100);
    }

    for (int i = 0; i < 10; i++)
    {
        ret = fifo_test_add(data[i]);
        printf("%d\r\n",i);
        if (ret != 0)
        {
            printf("fifo_test_add fail\r\n");
            goto end;
        }
    }

    for (int i = 0; i < 10; i++)
    {
        ret = fifo_test_take(verif[i]);
        printf("%d\r\n",i );
        if (ret != 0)
        {
            printf("fifo_test_take fail\r\n");
            goto end;
        }

        if (memcmp(verif[i], data[i], 100) != 0)
        {
            printf("fifo_test_take result fail\r\n");
            dump_hex(data[i],100);
            dump_hex(verif[i],100);
            goto end;
        }
    }

    for (int i = 0; i < 10; i++)
    {
        ret = fifo_test_add(data[i]);
        if (ret != 0)
        {
            printf("fifo_test_add 2 fail\r\n");
            goto end;
        }
    }

    ret = fifo_test_add(data[0]);
    if (ret == 0)
    {
        printf("fifo_test_add should have failed\r\n");
        goto end;
    }

    for (int i = 0; i < 10; i++)
    {
        ret = fifo_test_take(verif[i]);
        if (ret != 0)
        {
            printf("fifo_test_take fail\r\n");
            goto end;
        }

        if (memcmp(verif[i], data[i], 100) != 0)
        {
            printf("fifo_test_take result fail\r\n");
            goto end;
        }
    }

    ret = fifo_test_take(verif[0]);
    if (ret == 0)
    {
        printf("fifo_test_take should have failed\r\n");
        goto end;
    }

    printf("test pass!\r\n");

    end:
    while(1)
        ;
}
#endif
