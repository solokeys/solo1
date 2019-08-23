// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _MEMORY_LAYOUT_H_
#define _MEMORY_LAYOUT_H_

#define PAGE_SIZE		2048
#define PAGES			128

// Pages 119-127 are data
// Location of counter page and it's backup page
// The flash is wear leveled and counter should be fault tolerant
#define	COUNTER2_PAGE	(PAGES - 4)
#define	COUNTER1_PAGE	(PAGES - 3)

// State of FIDO2 application
#define	STATE2_PAGE		(PAGES - 2)
#define	STATE1_PAGE		(PAGES - 1)

// Storage of FIDO2 resident keys
#define RK_NUM_PAGES    10
#define RK_START_PAGE   (PAGES - 14)
#define RK_END_PAGE     (PAGES - 14 + RK_NUM_PAGES)     // not included

// Start of application code
#ifndef APPLICATION_START_PAGE
#define APPLICATION_START_PAGE	(10)
#endif
#define APPLICATION_START_ADDR	(0x08000000 + ((APPLICATION_START_PAGE)*PAGE_SIZE))

// where attestation key is located
#define ATTESTATION_KEY_PAGE    (PAGES - 15)
#define ATTESTATION_KEY_ADDR    (0x08000000 + ATTESTATION_KEY_PAGE*PAGE_SIZE)

// End of application code.  Leave some extra room for future data storage.
// NOT included in application
#define APPLICATION_END_PAGE	((PAGES - 20))
#define APPLICATION_END_ADDR	((0x08000000 + ((APPLICATION_END_PAGE)*PAGE_SIZE))-8)

// Bootloader state.
#define AUTH_WORD_ADDR          (APPLICATION_END_ADDR)

#define LAST_ADDR       (APPLICATION_END_ADDR-2048 + 8)
#define NEW_FW_VERSION_ADDR    (AUTH_WORD_ADDR-8)
#define BOOT_VERSION_PAGE    (APPLICATION_END_PAGE)
#define BOOT_VERSION_ADDR    (0x08000000 + BOOT_VERSION_PAGE*FLASH_PAGE_SIZE)
#define LAST_PAGE       (APPLICATION_END_PAGE-1)


struct flash_memory_st{
  uint8_t bootloader[20*1024];
  uint8_t application[196*1024-16];
  uint8_t app_version[8];
  uint8_t auth_word[8];
  uint8_t bootloader_data[2*1024];
  uint8_t user_data[38*1024];
} __attribute__((packed));

typedef struct flash_memory_st flash_memory_st;

static_assert(sizeof(flash_memory_st) == 256*1024, "Data structure doesn't match flash size");


#endif
