// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _APP_H_
#define _APP_H_
#include <stdint.h>
#include "version.h"
#include "solo.h"

#define SOLO

#define DEBUG_UART      USART1

#ifndef DEBUG_LEVEL
// Enable the CDC ACM USB interface & debug logs (DEBUG_LEVEL > 0)
#define DEBUG_LEVEL     0
#endif

// Enable the CCID USB interface
// #define ENABLE_CCID

#define NON_BLOCK_PRINTING 0


#define BOOT_TO_DFU         0

//#define USING_DEV_BOARD

#define ENABLE_U2F_EXTENSIONS
    // #define ENABLE_WALLET

#define ENABLE_U2F

// #define DISABLE_CTAPHID_PING
// #define DISABLE_CTAPHID_WINK
// #define DISABLE_CTAPHID_CBOR

// #define ENABLE_SERIAL_PRINTING

#if defined(SOLO_HACKER)
#define SOLO_PRODUCT_NAME "Solo Hacker " SOLO_VERSION
#else
#define SOLO_PRODUCT_NAME "Solo " SOLO_VERSION
#endif

void printing_init();
void hw_init(int lf);

// Return 1 if Solo is secure/locked.
int solo_is_locked();

//#define TEST
//#define TEST_POWER

//                              0xRRGGBB
#define LED_INIT_VALUE			0x000800
#define LED_WINK_VALUE			0x000010
#define LED_MAX_SCALER          15
#define LED_MIN_SCALER          1
// # of ms between each change in LED
#define HEARTBEAT_PERIOD        150
// Each LED channel will be multiplied by a integer between LED_MAX_SCALER
// and LED_MIN_SCALER to cause the slow pulse.  E.g.
// #define LED_INIT_VALUE			0x301000
// #define LED_MAX_SCALER          30
// #define LED_MIN_SCALER          1
// #define HEARTBEAT_PERIOD        8
// Will pulse from 0x301000 to 0x903000 to 0x301000 ...
// Which will take ~8 * (30)*2 ms

// Button
#define SOLO_BUTTON_PORT        GPIOA
#define SOLO_BUTTON_PIN         LL_GPIO_PIN_0

#define SOLO_AMS_CS_PORT        GPIOB
#define SOLO_AMS_CS_PIN         LL_GPIO_PIN_0

#define SOLO_AMS_IRQ_PORT       GPIOC
#define SOLO_AMS_IRQ_PIN        LL_GPIO_PIN_15

#define SKIP_BUTTON_CHECK_WITH_DELAY        0
#define SKIP_BUTTON_CHECK_FAST              0

#endif
