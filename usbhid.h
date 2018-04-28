#ifndef _USBHID_H
#define _USBHID_H


// HID message size in bytes
#define HID_MESSAGE_SIZE        64

void usbhid_init();

void usbhid_recv(uint8_t * msg);

void usbhid_send(uint8_t * msg);

void usbhid_close();

#endif
