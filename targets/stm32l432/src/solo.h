#ifndef _SOLO_H_
#define _SOLO_H_

void device_init();

void main_loop_delay();
void usbhid_init();
void usbhid_close();
int usbhid_recv(uint8_t * msg);

void heartbeat();

// Called each main loop.  Doesn't need to do anything.
void device_manage();

void device_init_button();

// For Solo hacker
void boot_solo_bootloader();
void boot_st_bootloader();


void delay(uint32_t ms);

#endif
