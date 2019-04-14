// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
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


int _write (int fd, const void *buf, unsigned long int len)
{
    uint8_t * data = (uint8_t *) buf;
#if DEBUG_LEVEL>0
	// static uint8_t logbuf[1000] = {0};
	// static int logbuflen = 0;
	// if (logbuflen + len > sizeof(logbuf)) {
	// 	int mlen = logbuflen + len - sizeof(logbuf);
	// 	memmove(logbuf, &logbuf[mlen], sizeof(logbuf) - mlen);
	// 	logbuflen -= mlen;
	// }
	// memcpy(&logbuf[logbuflen], data, len);
	// logbuflen += len;

	// Send out USB serial
	CDC_Transmit_FS(data, len);
	// if (res == USBD_OK)
	// 	logbuflen = 0;
#endif
#ifdef ENABLE_SERIAL_PRINTING
    // Send out UART serial
    while(len--)
    {
        _putchar(*data++);
    }
#endif
    return 0;

}
#endif
