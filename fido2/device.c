// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/** device.c
 *
 * This contains (weak) implementations
 * to get FIDO2 working initially on a device.  They probably
 * aren't what you want to keep, but are designed to be replaced
 * with some other platform specific implementation.
 *
 * For real examples, see the STM32L4 implementation and the PC implementation of device.c.
 *
*/
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ctaphid.h"
#include "log.h"
#include APP_CONFIG

#define RK_NUM  50

__attribute__((weak)) struct ResidentKeyStore {
    CTAP_residentKey rks[RK_NUM];
} RK_STORE;


static bool _up_disabled = false;

static uint8_t _attestation_cert_der[] =
"\x30\x82\x01\xfb\x30\x82\x01\xa1\xa0\x03\x02\x01\x02\x02\x01\x00\x30\x0a\x06\x08"
"\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\x2c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
"\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x10\x30\x0e"
"\x06\x03\x55\x04\x0a\x0c\x07\x54\x45\x53\x54\x20\x43\x41\x30\x20\x17\x0d\x31\x38"
"\x30\x35\x31\x30\x30\x33\x30\x36\x32\x30\x5a\x18\x0f\x32\x30\x36\x38\x30\x34\x32"
"\x37\x30\x33\x30\x36\x32\x30\x5a\x30\x7c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
"\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x0f\x30\x0d"
"\x06\x03\x55\x04\x07\x0c\x06\x4c\x61\x75\x72\x65\x6c\x31\x15\x30\x13\x06\x03\x55"
"\x04\x0a\x0c\x0c\x54\x45\x53\x54\x20\x43\x4f\x4d\x50\x41\x4e\x59\x31\x22\x30\x20"
"\x06\x03\x55\x04\x0b\x0c\x19\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x6f\x72"
"\x20\x41\x74\x74\x65\x73\x74\x61\x74\x69\x6f\x6e\x31\x14\x30\x12\x06\x03\x55\x04"
"\x03\x0c\x0b\x63\x6f\x6e\x6f\x72\x70\x70\x2e\x63\x6f\x6d\x30\x59\x30\x13\x06\x07"
"\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00"
"\x04\x45\xa9\x02\xc1\x2e\x9c\x0a\x33\xfa\x3e\x84\x50\x4a\xb8\x02\xdc\x4d\xb9\xaf"
"\x15\xb1\xb6\x3a\xea\x8d\x3f\x03\x03\x55\x65\x7d\x70\x3f\xb4\x02\xa4\x97\xf4\x83"
"\xb8\xa6\xf9\x3c\xd0\x18\xad\x92\x0c\xb7\x8a\x5a\x3e\x14\x48\x92\xef\x08\xf8\xca"
"\xea\xfb\x32\xab\x20\xa3\x62\x30\x60\x30\x46\x06\x03\x55\x1d\x23\x04\x3f\x30\x3d"
"\xa1\x30\xa4\x2e\x30\x2c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31"
"\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x10\x30\x0e\x06\x03\x55\x04"
"\x0a\x0c\x07\x54\x45\x53\x54\x20\x43\x41\x82\x09\x00\xf7\xc9\xec\x89\xf2\x63\x94"
"\xd9\x30\x09\x06\x03\x55\x1d\x13\x04\x02\x30\x00\x30\x0b\x06\x03\x55\x1d\x0f\x04"
"\x04\x03\x02\x04\xf0\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x03\x48\x00"
"\x30\x45\x02\x20\x18\x38\xb0\x45\x03\x69\xaa\xa7\xb7\x38\x62\x01\xaf\x24\x97\x5e"
"\x7e\x74\x64\x1b\xa3\x7b\xf7\xe6\xd3\xaf\x79\x28\xdb\xdc\xa5\x88\x02\x21\x00\xcd"
"\x06\xf1\xe3\xab\x16\x21\x8e\xd8\xc0\x14\xaf\x09\x4f\x5b\x73\xef\x5e\x9e\x4b\xe7"
"\x35\xeb\xdd\x9b\x6d\x8f\x7d\xf3\xc4\x3a\xd7";


__attribute__((weak)) void device_attestation_read_cert_der(uint8_t * dst){
    memmove(dst, _attestation_cert_der, device_attestation_cert_der_get_size());
}

__attribute__((weak)) uint8_t * device_get_attestation_key(){
    static uint8_t attestation_key[] =
        "\xcd\x67\xaa\x31\x0d\x09\x1e\xd1\x6e\x7e\x98\x92\xaa"
        "\x07\x0e\x19\x94\xfc\xd7\x14\xae\x7c\x40\x8f\xb9\x46"
        "\xb7\x2e\x5f\xe7\x5d\x30";
    return attestation_key;
}

__attribute__((weak)) uint16_t device_attestation_cert_der_get_size(){
    return sizeof(_attestation_cert_der)-1;
}

__attribute__((weak)) void device_reboot()
{
    printf1(TAG_RED, "REBOOT command recieved!\r\n");
    exit(100);
}

__attribute__((weak)) void device_set_status(uint32_t status)
{
    static uint32_t __device_status = 0;
    if (status != CTAPHID_STATUS_IDLE && __device_status != status)
    {
        ctaphid_update_status(status);
    }
    __device_status = status;
}


__attribute__((weak)) void usbhid_close(){/**/}


__attribute__((weak)) void device_init(int argc, char *argv[]){/**/}

__attribute__((weak)) void device_disable_up(bool disable)
{
    _up_disabled = disable;
}

__attribute__((weak)) int ctap_user_presence_test(uint32_t d)
{
    if (_up_disabled)
    {
        return 2;
    }
    return 1;
}

__attribute__((weak)) int ctap_user_verification(uint8_t arg)
{
    return 1;
}

__attribute__((weak)) uint32_t ctap_atomic_count(uint32_t amount)
{
    static uint32_t counter1 = 25;
    counter1 += (amount + 1);
    return counter1;
}


__attribute__((weak)) int ctap_generate_rng(uint8_t * dst, size_t num)
{
    int i;
    printf1(TAG_ERR, "Insecure RNG being used.\r\n");
    for (i = 0; i < num; i++){
        dst[i] = (uint8_t)rand();
    }
}

__attribute__((weak)) int device_is_nfc()
{
    return 0;
}

__attribute__((weak)) void device_wink()
{
    printf1(TAG_GREEN,"*WINK*\n");
}

__attribute__((weak)) void device_set_clock_rate(DEVICE_CLOCK_RATE param){/**/}

static  AuthenticatorState _tmp_state = {0};
__attribute__((weak)) int authenticator_read_state(AuthenticatorState * s){
    if (_tmp_state.is_initialized != INITIALIZED_MARKER){
        return 0;
    }
    else {
        memmove(s, &_tmp_state, sizeof(AuthenticatorState));
        return 1;
    }
}

__attribute__((weak)) void authenticator_write_state(AuthenticatorState * s){
    memmove(&_tmp_state, s, sizeof(AuthenticatorState));
}

__attribute__((weak)) void ctap_reset_rk()
{
    memset(&RK_STORE,0xff,sizeof(RK_STORE));
}

__attribute__((weak)) uint32_t ctap_rk_size()
{
    return RK_NUM;
}


__attribute__((weak)) void ctap_store_rk(int index, CTAP_residentKey * rk)
{
    if (index < RK_NUM)
    {
        memmove(RK_STORE.rks + index, rk, sizeof(CTAP_residentKey));
    }
    else
    {
        printf1(TAG_ERR,"Out of bounds for store_rk\r\n");
    }

}

__attribute__((weak)) void ctap_delete_rk(int index)
{
    CTAP_residentKey rk;
    memset(&rk, 0xff, sizeof(CTAP_residentKey));

    if (index < RK_NUM)
    {
        memmove(RK_STORE.rks + index, &rk, sizeof(CTAP_residentKey));
    }
    else
    {
        printf1(TAG_ERR,"Out of bounds for delete_rk\r\n");
    }

}

__attribute__((weak)) void ctap_load_rk(int index, CTAP_residentKey * rk)
{
    memmove(rk, RK_STORE.rks + index, sizeof(CTAP_residentKey));
}

__attribute__((weak)) void ctap_overwrite_rk(int index, CTAP_residentKey * rk)
{
    if (index < RK_NUM)
    {
        memmove(RK_STORE.rks + index, rk, sizeof(CTAP_residentKey));
    }
    else
    {
        printf1(TAG_ERR,"Out of bounds for store_rk\r\n");
    }
}

__attribute__((weak)) void device_read_aaguid(uint8_t * dst){
    uint8_t * aaguid = (uint8_t *)"\x00\x76\x63\x1b\xd4\xa0\x42\x7f\x57\x73\x0e\xc7\x1c\x9e\x02\x79";
    memmove(dst, aaguid, 16);
}
