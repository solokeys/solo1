// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#include "data_migration.h"
#include "log.h"
#include "device.h"
#include "crypto.h"

// TODO move from macro to function/assert for better readability?
#define check(x) assert(state_prev_0xff->x == state_tmp_ptr->x);
#define check_buf(x) assert(memcmp(state_prev_0xff->x, state_tmp_ptr->x, sizeof(state_tmp_ptr->x)) == 0);

bool migrate_from_FF_to_01(AuthenticatorState_0xFF* state_prev_0xff, AuthenticatorState_0x01* state_tmp_ptr){
    // Calculate PIN hash, and replace PIN raw storage with it; add version to structure
    // other ingredients do not change
    if (state_tmp_ptr->data_version != 0xFF)
        return false;

    static_assert(sizeof(AuthenticatorState_0xFF) <= sizeof(AuthenticatorState_0x01), "New state structure is smaller, than current one, which is not handled");

    if (ctap_generate_rng(state_tmp_ptr->PIN_SALT, sizeof(state_tmp_ptr->PIN_SALT)) != 1) {
        printf2(TAG_ERR, "Error, rng failed\n");
        return false;
    }
    if (state_prev_0xff->is_pin_set){
        crypto_sha256_init();
        crypto_sha256_update(state_prev_0xff->pin_code, state_prev_0xff->pin_code_length);
        uint8_t intermediateHash[32];
        crypto_sha256_final(intermediateHash);

        crypto_sha256_init();
        crypto_sha256_update(intermediateHash, 16);
        memset(intermediateHash, 0, sizeof(intermediateHash));
        crypto_sha256_update(state_tmp_ptr->PIN_SALT, sizeof(state_tmp_ptr->PIN_SALT));
        crypto_sha256_final(state_tmp_ptr->PIN_CODE_HASH);
    }

    assert(state_tmp_ptr->_reserved == state_prev_0xff->pin_code_length);
    state_tmp_ptr->_reserved = 0xFF;
    state_tmp_ptr->data_version = 1;

    check(is_initialized);
    check(is_pin_set);
    check(remaining_tries);
    check(rk_stored);
    check_buf(key_lens);
    check_buf(key_space);
    assert(state_tmp_ptr->data_version != 0xFF);

    return true;
}

void save_migrated_state(AuthenticatorState *state_tmp_ptr) {
    memmove(&STATE, state_tmp_ptr, sizeof(AuthenticatorState));
    authenticator_write_state(state_tmp_ptr);
}

void do_migration_if_required(AuthenticatorState* state_current){
    // Currently handles only state structures with the same size, or bigger
    // FIXME rework to raw buffers with fixed size to allow state structure size decrease
    if(!state_current->is_initialized)
        return;

    AuthenticatorState state_tmp;
    AuthenticatorState state_previous;
    authenticator_read_state(&state_previous);
    authenticator_read_state(&state_tmp);
    if(state_current->data_version == 0xFF){
        printf2(TAG_ERR, "Running migration\n");
        bool success = migrate_from_FF_to_01((AuthenticatorState_0xFF *) &state_previous, &state_tmp);
        if (!success){
            printf2(TAG_ERR, "Failed migration from 0xFF to 1\n");
            // FIXME discuss migration failure behavior
            goto return_cleanup;
        }
        dump_hex1(TAG_ERR, (void*)&state_tmp, sizeof(state_tmp));
        dump_hex1(TAG_ERR, (void*)&state_previous, sizeof(state_previous));
        save_migrated_state(&state_tmp);
    }

    assert(state_current->data_version == STATE_VERSION);

    return_cleanup:
    memset(&state_tmp, 0, sizeof(AuthenticatorState));
    memset(&state_previous, 0, sizeof(AuthenticatorState));
}
