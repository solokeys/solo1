/*
 * app.h
 *
 *  Created on: Jun 26, 2018
 *      Author: conor
 */

#ifndef SRC_APP_H_
#define SRC_APP_H_

#define IS_BOOTLOADER

#define PRINTING_USE_VCOM

#define USING_DEV_BOARD

#define BRIDGE_TO_WALLET

#define JUMP_LOC	0x8000

#define PUSH_BUTTON		gpioPortF,6

#define DISABLE_CTAPHID_PING
#define DISABLE_CTAPHID_WINK
#define DISABLE_CTAPHID_CBOR

void printing_init();

int bootloader_bridge(uint8_t klen, uint8_t * keyh);

int is_authorized_to_boot();

#endif /* SRC_APP_H_ */
