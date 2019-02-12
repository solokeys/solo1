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
#include "extensions.h"
#include "u2f.h"
#include "wallet.h"
#include "device.h"
#include "ctap.h"
#include "ctap_errors.h"

#include "log.h"
#include APP_CONFIG

int16_t bridge_u2f_to_solo(uint8_t * _chal, uint8_t * _appid, uint8_t klen, uint8_t * keyh)
{
    static uint8_t msg_buf[72];
    int reqlen = klen;
    int i;
    int8_t ret = 0;

    wallet_request * req = (wallet_request *) keyh;

    printf1(TAG_WALLET, "u2f-solo [%d]: ", reqlen); dump_hex1(TAG_WALLET, keyh, reqlen);

    switch(req->operation)
    {
        case WalletVersion:
            msg_buf[0] = SOLO_VERSION_MAJ;
            msg_buf[1] = SOLO_VERSION_MIN;
            msg_buf[2] = SOLO_VERSION_PATCH;
            u2f_response_writeback(msg_buf, 3);
            break;
        case WalletRng:
            printf1(TAG_WALLET,"SoloRng\n");

            ret = ctap_generate_rng(msg_buf, 72);
            if (ret != 1)
            {
                printf1(TAG_WALLET,"Rng failed\n");
                ret = CTAP2_ERR_PROCESSING;
                goto cleanup;
            }
            ret = 0;

            u2f_response_writeback((uint8_t *)msg_buf,72);
            break;

        default:
            printf2(TAG_ERR,"Invalid wallet command: %x\n",req->operation);
            ret = CTAP1_ERR_INVALID_COMMAND;
            break;
    }

cleanup:

    return ret;
}
