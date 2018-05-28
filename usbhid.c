
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "usbhid.h"
#include "udp_bridge.h"


static int serverfd = 0;

void usbhid_init()
{
    // just bridge to UDP for now for pure software testing
    serverfd = udp_server();
}

// Receive 64 byte USB HID message, don't block, return size of packet, return 0 if nothing
int usbhid_recv(uint8_t * msg)
{
    int l = udp_recv(serverfd, msg, HID_MESSAGE_SIZE);
    /*if (l && l != HID_MESSAGE_SIZE)*/
    /*{*/
        /*printf("Error, recv'd message of wrong size %d", l);*/
        /*exit(1);*/
    /*}*/
    return l;
}


// Send 64 byte USB HID message
void usbhid_send(uint8_t * msg)
{
    udp_send(serverfd, msg, HID_MESSAGE_SIZE);
}

void usbhid_close()
{
    udp_close(serverfd);
}
