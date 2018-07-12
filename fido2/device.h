#ifndef _DEVICE_H
#define _DEVICE_H

#include "storage.h"

void device_init();

uint32_t millis();

// HID message size in bytes
#define HID_MESSAGE_SIZE        64

void usbhid_init();

int usbhid_recv(uint8_t * msg);

void usbhid_send(uint8_t * msg);

void usbhid_close();

void main_loop_delay();

void heartbeat();

void authenticator_read_state(AuthenticatorState * );

void authenticator_read_backup_state(AuthenticatorState * );

// Return 1 yes backup is init'd, else 0
//void authenticator_initialize()
int authenticator_is_backup_initialized();

void authenticator_write_state(AuthenticatorState *, int backup);


// Test for user presence
// Return 1 for user is present, 0 user not present
extern int ctap_user_presence_test();

// Generate @num bytes of random numbers to @dest
// return 1 if success, error otherwise
extern int ctap_generate_rng(uint8_t * dst, size_t num);

// Increment atomic counter and return it.
// Must support two counters, @sel selects counter0 or counter1.
uint32_t ctap_atomic_count(int sel);

// Verify the user
// return 1 if user is verified, 0 if not
extern int ctap_user_verification(uint8_t arg);

// Must be implemented by application
// data is HID_MESSAGE_SIZE long in bytes
extern void ctaphid_write_block(uint8_t * data);

#endif
