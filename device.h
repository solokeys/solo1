#ifndef _DEVICE_H
#define _DEVICE_H

void device_init();

uint64_t millis();

// HID message size in bytes
#define HID_MESSAGE_SIZE        64

void usbhid_init();

int usbhid_recv(uint8_t * msg);

void usbhid_send(uint8_t * msg);

void usbhid_close();

void main_loop_delay();

void heartbeat();

#endif
