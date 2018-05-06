/*
 *  Device specific functionality defined here
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbor.h"

#include "util.h"
#include "usbhid.h"


void ctap_write_block(uint8_t * data)
{
    printf("<< "); dump_hex(data, 64);
    usbhid_send(data);
}

void ctap_write(void * _data, int len)
{
    static uint8_t buf[HID_MESSAGE_SIZE];
    static int offset = 0;

    uint8_t * data = (uint8_t *) _data;

    if (len == 0)
    {
        if (offset > 0)
        {
            memset(buf + offset, 0, HID_MESSAGE_SIZE - offset);
            ctap_write_block(buf);
        }
        offset = 0;
        return;
    }
    else if (len == -1)
    {
        memset(buf, 0, HID_MESSAGE_SIZE);
        offset = 0;
    }

    int i;
    for (i = 0; i < len; i++)
    {
        buf[offset++] = data[i];
        if (offset == HID_MESSAGE_SIZE)
        {
            ctap_write_block(buf);
            offset = 0;
        }
    }
}

int ctap_user_presence_test()
{
    return 1;
}

int ctap_user_verification(uint8_t arg)
{
    return 1;
}


uint32_t ctap_atomic_count()
{
    static uint32_t counter = 25;
    return counter++;
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
}
