
#include <stdint.h>

#include "usbhid.h"
#include "udp_bridge.h"


static int serverfd = 0;

void usbhid_init()
{
    // just bridge to UDP for now for pure software testing
    serverfd = udp_server();
}

// Receive 64 byte USB HID message
void usbhid_recv(uint8_t * msg)
{
    udp_recv(serverfd, msg, HID_MESSAGE_SIZE);
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
