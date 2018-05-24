/*
 *  Device specific functionality defined here
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbor.h"

#include "util.h"
#include "usbhid.h"


void ctaphid_write_block(uint8_t * data)
{
    printf("<< "); dump_hex(data, 64);
    usbhid_send(data);
}


int ctap_user_presence_test()
{
    return 1;
}

int ctap_user_verification(uint8_t arg)
{
    return 1;
}


uint32_t ctap_atomic_count(int sel)
{
    static uint32_t counter1 = 25;
    static uint32_t counter2 = 25;
    if (sel == 0)
    {
        return counter1++;
    }
    else
    {
        return counter2++;
    }
    return 44;
}

int ctap_generate_rng(uint8_t * dst, size_t num)
{
    FILE * urand = fopen("/dev/urandom","r");
    if (urand == NULL)
    {
        perror("fopen");
        exit(1);
    }
    fread(dst, 1, num, urand);
    fclose(urand);
    return 1;
}

