/*
 * Copyright (C) 2018 SoloKeys, Inc. <https://solokeys.com/>
 * 
 * This file is part of Solo.
 * 
 * Solo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Solo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Solo.  If not, see <https://www.gnu.org/licenses/>
 * 
 * This code is available under licenses for commercial use.
 * Please contact SoloKeys for more information.
 */
#ifndef _STORAGE_H
#define _STORAGE_H

#include "ctap.h"

#define KEY_SPACE_BYTES     128
#define MAX_KEYS            (1)

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
} AuthenticatorState;


typedef struct
{
    uint32_t addr;
    uint8_t * filename;
    uint32_t count;
} AuthenticatorCounter;

extern AuthenticatorState STATE;

#endif
