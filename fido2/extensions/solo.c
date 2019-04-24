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



// output must be at least 71 bytes
int16_t bridge_u2f_to_solo(uint8_t * output, uint8_t * keyh, int keylen)
{
    int8_t ret = 0;

    wallet_request * req = (wallet_request *) keyh;
    extension_writeback_init(output, 71);

    printf1(TAG_WALLET, "u2f-solo [%d]: ", keylen); dump_hex1(TAG_WALLET, keyh, keylen);

    switch(req->operation)
    {
        case WalletVersion:
            output[0] = SOLO_VERSION_MAJ;
            output[1] = SOLO_VERSION_MIN;
            output[2] = SOLO_VERSION_PATCH;
            break;
        case WalletRng:
            printf1(TAG_WALLET,"SoloRng\n");

            ret = ctap_generate_rng(output, 71);
            if (ret != 1)
            {
                printf1(TAG_WALLET,"Rng failed\n");
                ret = CTAP2_ERR_PROCESSING;
                goto cleanup;
            }
            ret = 0;

            break;

#ifdef ENABLE_WALLET
        case WalletSign:
        case WalletRegister:
        case WalletPin:
        case WalletReset:
            return bridge_to_wallet(keyh, keylen);
#endif

        default:
            printf2(TAG_ERR,"Invalid wallet command: %x\n",req->operation);
            ret = CTAP1_ERR_INVALID_COMMAND;
            break;
    }

cleanup:

    return ret;
}
