/*
   Copyright 2018 Conor Patrick

   Permission is hereby granted, free of charge, to any person obtaining a copy of
   this software and associated documentation files (the "Software"), to deal in
   the Software without restriction, including without limitation the rights to
   use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
   of the Software, and to permit persons to whom the Software is furnished to do
   so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
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
