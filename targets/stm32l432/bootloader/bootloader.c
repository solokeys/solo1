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
#include <stdint.h>
#include <stdlib.h>

#include APP_CONFIG
#include "uECC.h"
#include "u2f.h"
#include "device.h"
#include "flash.h"
#include "crypto.h"
#include "led.h"
#include "memory_layout.h"
#include "ctap_errors.h"
#include "log.h"


extern uint8_t REBOOT_FLAG;

typedef enum
{
    BootWrite = 0x40,
    BootDone = 0x41,
    BootCheck = 0x42,
    BootErase = 0x43,
    BootVersion = 0x44,
    BootReboot = 0x45,
    BootBootloader = 0x46,
    BootDisable = 0x47,
} BootOperation;


typedef struct {
    uint8_t op;
    uint8_t addr[3];
    uint8_t tag[4];
    uint8_t lenh;
    uint8_t lenl;
    uint8_t payload[255 - 10];
} __attribute__((packed)) BootloaderReq;


static void erase_application()
{
    int page;
    for(page = APPLICATION_START_PAGE; page < APPLICATION_END_PAGE; page++)
    {
        flash_erase_page(page);
    }
}

#define LAST_ADDR       (APPLICATION_END_ADDR-2048 + 8)
#define LAST_PAGE       (APPLICATION_END_PAGE-1)
static void disable_bootloader()
{
    uint8_t page[PAGE_SIZE];
    memmove(page, (uint8_t*)LAST_ADDR, PAGE_SIZE);
    memset(page+PAGE_SIZE -4, 0, 4);
    flash_erase_page(LAST_PAGE);
    flash_write(LAST_ADDR, page, PAGE_SIZE);
}

static void authorize_application()
{
    // uint32_t zero = 0;
    // uint32_t * ptr;
    // ptr = (uint32_t *)AUTH_WORD_ADDR;
    // flash_write((uint32_t)ptr, (uint8_t *)&zero, 4);
    uint8_t page[PAGE_SIZE];
    if (is_authorized_to_boot())
        return;
    memmove(page, (uint8_t*)LAST_ADDR, PAGE_SIZE);
    memset(page+PAGE_SIZE -8, 0, 4);
    flash_erase_page(LAST_PAGE);
    flash_write(LAST_ADDR, page, PAGE_SIZE);
}

int is_authorized_to_boot()
{
    uint32_t * auth = (uint32_t *)AUTH_WORD_ADDR;
    return *auth == 0;
}

int is_bootloader_disabled()
{
    uint32_t * auth = (uint32_t *)(AUTH_WORD_ADDR+4);
    return *auth == 0;
}

int bootloader_bridge(int klen, uint8_t * keyh)
{
    static int has_erased = 0;
    int i;
    BootloaderReq * req =  (BootloaderReq *  )keyh;
    uint8_t hash[32];
    uint8_t version = 1;
    uint16_t len = (req->lenh << 8) | (req->lenl);

    if (len > klen-10)
    {
        printf1(TAG_BOOT,"Invalid length %d / %d\r\n", len, klen-9);
        return CTAP1_ERR_INVALID_LENGTH;
    }

    uint8_t * pubkey = (uint8_t*)"\xd2\xa4\x2f\x8f\xb2\x31\x1c\xc1\xf7\x0c\x7e\x64\x32\xfb\xbb\xb4\xa3\xdd\x32\x20\x0f\x1b\x88\x9c\xda\x62\xc2\x83\x25\x93\xdd\xb8\x75\x9d\xf9\x86\xee\x03\x6c\xce\x34\x47\x71\x36\xb3\xb2\xad\x6d\x12\xb7\xbe\x49\x3e\x20\xa4\x61\xac\xc7\x71\xc7\x1f\xa8\x14\xf2";
    const struct uECC_Curve_t * curve = NULL;

    uint32_t addr = ((*((uint32_t*)req->addr)) & 0xffffff) | 0x8000000;

    uint32_t * ptr = (uint32_t *)addr;

    switch(req->op){
        case BootWrite:
            printf1(TAG_BOOT, "BootWrite: %08lx\r\n",(uint32_t)ptr);
            if ((uint32_t)ptr < APPLICATION_START_ADDR || (uint32_t)ptr >= APPLICATION_END_ADDR
                || ((uint32_t)ptr+len) > APPLICATION_END_ADDR)
            {
                printf1(TAG_BOOT,"Bound exceeded [%08lx, %08lx]\r\n",APPLICATION_START_ADDR,APPLICATION_END_ADDR);
                return CTAP2_ERR_NOT_ALLOWED;
            }

            if (!has_erased || is_authorized_to_boot())
            {
                erase_application();
                has_erased = 1;
            }
            if (is_authorized_to_boot())
            {
                printf2(TAG_ERR, "Error, boot check bypassed\n");
                exit(1);
            }

            flash_write((uint32_t)ptr,req->payload, len);


            break;
        case BootDone:
            printf1(TAG_BOOT, "BootDone: ");
#ifndef SOLO_HACKER
            if (len != 64)
            {
                printf1(TAG_BOOT,"Invalid length for signature\r\n");
                return CTAP1_ERR_INVALID_LENGTH;
            }
            dump_hex1(TAG_BOOT, req->payload, 32);
            ptr = (uint32_t *)APPLICATION_START_ADDR;
            crypto_sha256_init();
            crypto_sha256_update((uint8_t*)ptr, APPLICATION_END_ADDR-APPLICATION_START_ADDR);
            crypto_sha256_final(hash);
            curve = uECC_secp256r1();

            if (! uECC_verify(pubkey,
                        hash,
                        32,
                        req->payload,
                        curve))
            {
                return CTAP2_ERR_OPERATION_DENIED;
            }
#endif
            authorize_application();
            REBOOT_FLAG = 1;
            break;
        case BootCheck:
            return 0;
            break;
        case BootErase:
            printf1(TAG_BOOT, "BootErase.\r\n");
            erase_application();
            return 0;
            break;
        case BootVersion:
            has_erased = 0;
            printf1(TAG_BOOT, "BootVersion.\r\n");
            version = BOOT_VERSION_MAJ;
            u2f_response_writeback(&version,1);
            version = BOOT_VERSION_MIN;
            u2f_response_writeback(&version,1);
            break;
        case BootReboot:
            printf1(TAG_BOOT, "BootReboot.\r\n");
            REBOOT_FLAG = 1;
            break;
        case BootDisable:
            printf1(TAG_BOOT, "BootDisable %08lx.\r\n", *(uint32_t *)(AUTH_WORD_ADDR+4));
            if (req->payload[0] == 0xcd && req->payload[1] == 0xde
               && req->payload[2] == 0xba && req->payload[3] == 0xaa)
            {
                disable_bootloader();
                version = 0;
                u2f_response_writeback(&version,1);
            }
            else
            {
                version = CTAP2_ERR_OPERATION_DENIED;
                u2f_response_writeback(&version,1);
            }
            break;
#ifdef SOLO_HACKER
        case BootBootloader:
            printf1(TAG_BOOT, "BootBootloader.\r\n");
            flash_option_bytes_init(1);
            boot_st_bootloader();
            break;
#endif
        default:
            return CTAP1_ERR_INVALID_COMMAND;
    }
    return 0;
}

void bootloader_heartbeat()
{
    static int state = 0;
    static uint32_t val = (LED_MAX_SCALER - LED_MIN_SCALER)/2;
    uint8_t r = (LED_INIT_VALUE >> 16) & 0xff;
    uint8_t g = (LED_INIT_VALUE >> 8) & 0xff;
    uint8_t b = (LED_INIT_VALUE >> 0) & 0xff;

    if (state)
    {
        val--;
    }
    else
    {
        val++;
    }

    if (val > LED_MAX_SCALER || val < LED_MIN_SCALER)
    {
        state = !state;
    }

    led_rgb(((val * g)<<8) | ((val*r) << 16) | (val*b));
}
