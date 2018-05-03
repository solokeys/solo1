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


