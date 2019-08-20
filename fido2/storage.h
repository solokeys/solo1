// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _STORAGE_H
#define _STORAGE_H

#include "ctap.h"

#define KEY_SPACE_BYTES     128
#define MAX_KEYS            (1)
#define PIN_SALT_LEN        (32)
#define STATE_VERSION        (1)


#define BACKUP_MARKER       0x5A
#define INITIALIZED_MARKER  0xA5

#define ERR_NO_KEY_SPACE    (-1)
#define ERR_KEY_SPACE_TAKEN (-2)
#define ERR_KEY_SPACE_EMPTY (-2)

typedef struct
{
  // Pin information
  uint8_t is_initialized;
  uint8_t is_pin_set;
  uint8_t pin_code[NEW_PIN_ENC_MIN_SIZE];
  int pin_code_length;
  int8_t remaining_tries;

  uint16_t rk_stored;

  uint16_t key_lens[MAX_KEYS];
  uint8_t key_space[KEY_SPACE_BYTES];
} AuthenticatorState_0xFF;


typedef struct
{
    // Pin information
    uint8_t is_initialized;
    uint8_t is_pin_set;
    uint8_t PIN_CODE_HASH[32];
    uint8_t PIN_SALT[PIN_SALT_LEN];
    int _reserved;
    int8_t remaining_tries;

    uint16_t rk_stored;

    uint16_t key_lens[MAX_KEYS];
    uint8_t key_space[KEY_SPACE_BYTES];
    uint8_t data_version;
} AuthenticatorState_0x01;

typedef AuthenticatorState_0x01 AuthenticatorState;


typedef struct
{
    uint32_t addr;
    uint8_t * filename;
    uint32_t count;
} AuthenticatorCounter;

extern AuthenticatorState STATE;

#endif
