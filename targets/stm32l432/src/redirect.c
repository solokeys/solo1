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
#include "stm32l4xx_ll_usart.h"
#include "usbd_cdc_if.h"

#include APP_CONFIG
#include "fifo.h"

#if DEBUG_LEVEL>0

void _putchar(char c)
{
#if NON_BLOCK_PRINTING
    fifo_debug_add(&c);
#else
    while (! LL_USART_IsActiveFlag_TXE(DEBUG_UART))
        ;
    LL_USART_TransmitData8(DEBUG_UART,c);
#endif
}


int _write (int fd, const void *buf, long int len)
{
    uint8_t * data = (uint8_t *) buf;


    // Send out USB serial
    CDC_Transmit_FS(data, len);


    // Send out UART serial
    while(len--)
    {
        // _putchar(*data++);
    }
    return 0;
}
#endif
