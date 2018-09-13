#ifndef _USB_H
#define _USB_H

#include "app_fifo.h"

void usb_init(void);

extern app_fifo_t USBHID_RECV_FIFO;

#endif
