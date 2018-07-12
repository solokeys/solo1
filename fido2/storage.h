#ifndef _STORAGE_H
#define _STORAGE_H

#include "ctap.h"

#define KEY_SPACE_BYTES     128
#define MAX_KEYS            (KEY_SPACE_BYTES/1)

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
    uint8_t pin_code[NEW_PIN_ENC_MAX_SIZE];
    uint8_t remaining_tries;

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
