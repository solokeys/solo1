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
#include <SI_EFM8UB1_Register_Enums.h>
#include "InitDevice.h"
#include "efm8_usb.h"
#include "uart_1.h"
#include "printing.h"
#include "eeprom.h"

#define BUFFER_SIZE	12

#ifdef USING_DEVELOPMENT_BOARD
#define RW_PIN 			P2_B3
#define BUSY_PIN 		P1_B2
#define MSG_RDY_PIN		P1_B1
#else
#define RW_PIN 			P0_B1
#define BUSY_PIN 		P0_B2
#define MSG_RDY_PIN		P0_B3
#endif

#define SIGNAL_WRITE_BSY()		BUSY_PIN = 0 	 // Set P1 low
#define SIGNAL_WRITE_RDY()		BUSY_PIN = 1 	 // Set P1 high



data uint8_t write_ptr = 0;
data uint8_t read_ptr = 0;
data uint8_t i_ptr = 0;
data uint8_t count = 0;
data uint8_t writebackbuf_count = 0;

uint8_t hidmsgbuf[64*BUFFER_SIZE];
//uint8_t debugR[64];
//uint8_t debugRi;
//uint8_t debugW[64];
//uint8_t debugW2[64];
//uint8_t debugWi;
data uint8_t writebackbuf[64];

void usb_transfer_complete()
{
	count++;
//	memmove(debugR, hidmsgbuf + write_ptr*64, 64);
//	debugRi = write_ptr;
	write_ptr++;

	if (write_ptr == BUFFER_SIZE)
	{
		write_ptr = 0;
	}


//	MSG_RDY_INT_PIN = 0;
//	MSG_RDY_INT_PIN = 1;

}

uint16_t USB_TX_COUNT = 0;

void usb_writeback_complete()
{
//	if (USB_TX_COUNT >= 511/2)
//	{
//		USB_TX_COUNT -= 64;
//		if (USB_TX_COUNT < 511)
//		{
//			SIGNAL_WRITE_RDY();
//		}
//	}
//	else
//	{
//		USB_TX_COUNT -= 64;
//	}
	USB_TX_COUNT -= 64;
}

void spi_transfer_complete()
{

	if (count > 0) count--;
	i_ptr = 0;
	read_ptr++;
	if (read_ptr == BUFFER_SIZE)
	{
		read_ptr = 0;
	}

}



void usb_write()
{
	data uint8_t errors = 0;
	USB_TX_COUNT += 64;
	while (USB_STATUS_OK != (USBD_Write(OUTPUT_ENDPOINT, writebackbuf, 64, true)))
	{
		delay(2);
		if (errors++ > 30)
		{
			cprints("ERROR USB WRITE\r\n");
			break;
		}
	}
}
extern USBD_Device_TypeDef  myUsbDevice;

int main(void) {
	data uint8_t k;
	data uint16_t last_efm32_pin = 0;
	uint16_t t1 = 0;
	uint8_t lastcount = count;

	int reset;
	data int lastwritecount = writebackbuf_count;

	enter_DefaultMode_from_RESET();


	eeprom_init();


	SCON0_TI = 1;
//	P2_B0 = 1;

	MSG_RDY_PIN = 1;

	// enable SPI interrupts
//	SPI0FCN1 = SPI0FCN1 | (1<<4);
	IE_EA = 1;
//	IE_ESPI0 = 1;

	SPI0FCN0 = SPI0FCN0 | (1<<2); // flush RX fifo
	SPI0FCN0 = SPI0FCN0 | (1<<6); // flush TX fifo
//	SPI0FCN0 &= ~3; // FIFO threshold 0x0
	SPI0FCN1 |= (1); // Enable RX fifo

//	cprints("hello,world\r\n");


	reset = RSTSRC;
	cprintx("reset source: ", 1, reset);
	if (reset != 0x10)
	{
		RSTSRC = (1<<4);
	}

	MSG_RDY_PIN = 1;
	SIGNAL_WRITE_BSY();

	while (1) {

		if (RW_PIN == 0)
		{
			i_ptr = 0;
			SPI0FCN0 |= (1<<6); // Flush TX fifo buffer

			while (SPI0CN0 & (1 << 1)) 	// While TX FIFO has room
				SPI0DAT = (hidmsgbuf+read_ptr*64)[i_ptr++];

			SIGNAL_WRITE_RDY();
			while (i_ptr<64)
			{
				while(! (SPI0CN0 & (1 << 1)))
					;
				SPI0DAT = (hidmsgbuf+read_ptr*64)[i_ptr++];
			}

			while(RW_PIN == 0)
			{
			}

//			cprints(">> ");
//			dump_hex(hidmsgbuf+read_ptr*64,64);
			spi_transfer_complete();
			if (count == 0)
			{
				MSG_RDY_PIN = 1;
			}

			SPI0FCN0 = SPI0FCN0 | (1<<2); // flush RX fifo

			while ((SPI0CFG & (0x1)) == 0)
			{
				k = SPI0DAT;
			}

			SIGNAL_WRITE_BSY();


		}
		else
		{
			// Did we RX data and have room?
			if ((SPI0CFG & (0x1)) == 0 && USB_TX_COUNT < 511/2)
			{

				writebackbuf[writebackbuf_count++] = SPI0DAT;
				SIGNAL_WRITE_RDY();

				while(writebackbuf_count < 64)
				{
					while((SPI0CFG & (0x1)) == 1)
						;
					writebackbuf[writebackbuf_count++] = SPI0DAT;
				}

//				cprints("<< ");
//				dump_hex(writebackbuf,64);

				usb_write();
				writebackbuf_count = 0;
				SPI0FCN0 = SPI0FCN0 | (1<<2); // flush RX fifo

				SIGNAL_WRITE_BSY();
			}
		}

		if (millis() - t1 > 1500)
		{
#ifdef USING_DEVELOPMENT_BOARD
			P1_B5 = k++&1;
#endif
			t1 = millis();
		}
//		if (!USBD_EpIsBusy(EP2OUT) && !USBD_EpIsBusy(EP3IN) && lastcount==count)
		if (!USBD_EpIsBusy(INPUT_ENDPOINT)  && lastcount==count)
//		if (lastcount==count)
		{
//			cprintd("sched read to ",1,(int)(hidmsgbuf + write_ptr*64));
			if (count == BUFFER_SIZE)
			{
//				cprints("Warning, USB buffer full\r\n");
			}
			else
			{
//				cprints("sched read\r\n");
				USBD_Read(INPUT_ENDPOINT, hidmsgbuf + write_ptr*64, 64, true);
			}
		}

//		cprints("it\r\n");

		if (lastcount != count)
		{
			if (count > lastcount)
			{
//				cputd(debugRi); cprints(">> ");
//				dump_hex(debugR,64);
				MSG_RDY_PIN = 0;
			}
			else
			{
//				cputd(debugWi); cprints(">>>> ");
//				dump_hex(debugW,64);
//				dump_hex(debugW2,64);
			}
			lastcount = count;
		}

	}
}
