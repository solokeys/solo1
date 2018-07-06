#include <SI_EFM8UB1_Register_Enums.h>
#include "InitDevice.h"
#include "efm8_usb.h"
#include "uart_1.h"
#include "printing.h"

#define BUFFER_SIZE	12

#define SIGNAL_WRITE_BSY()		P1 = P1 & (~(1<<2)) // Set P1 low
#define SIGNAL_WRITE_RDY()		P1 = P1 | (1<<2) 	 // Set P1 high

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
	if (count == 1 && i_ptr == 0)
	{
		SPI0DAT = (hidmsgbuf+read_ptr*64)[i_ptr++];
	}


//	MSG_RDY_INT_PIN = 0;
//	MSG_RDY_INT_PIN = 1;

}

uint16_t USB_TX_COUNT = 0;

void usb_writeback_complete()
{
	if (USB_TX_COUNT >= 511/2)
	{
		USB_TX_COUNT -= 64;
		if (USB_TX_COUNT < 511)
		{
			SIGNAL_WRITE_RDY();
		}
	}
	else
	{
		USB_TX_COUNT -= 64;
	}
}

void spi_transfer_complete()
{
	count--;
	i_ptr = 0;
	SPI0FCN0 |= (1<<2); // Flush rx fifo buffer

//	debugWi = read_ptr;

	read_ptr++;

	if (read_ptr == BUFFER_SIZE)
	{
		read_ptr = 0;
	}
	if (count)
	{
		SPI0DAT = (hidmsgbuf+read_ptr*64)[i_ptr++];
	}
//	cprints("sent hid msg\r\n");
}
data int overrun = 0;
SI_INTERRUPT (SPI0_ISR, SPI0_IRQn)
{
	data uint8_t byt;
   if (SPI0CN0_WCOL == 1)
   {
		// Write collision occurred
		SPI0CN0_WCOL = 0;
//		cprints("SPI0CN0_WCOL\r\n");
   }
   else if(SPI0CN0_RXOVRN == 1)
   {
		// Receive overrun occurred
		SPI0CN0_RXOVRN = 0;
		overrun = 1;
//		cprints("SPI0CN0_RXOVRN\r\n");
   }
   else
   {
	   if (EFM32_RW_PIN)
	   {
		   if (writebackbuf_count < 64)
		   {
			   writebackbuf[writebackbuf_count++] = SPI0DAT;
			   SIGNAL_WRITE_BSY();
		   }
		   else
		   {
			   cprints("overflow\r\n");
		   }
	   }
	   else
	   {
		   if (count)
		   {
			   if (i_ptr < 64)
			   {
//				   debugW[i_ptr] = (hidmsgbuf+read_ptr*64)[i_ptr];
//				   debugW2[i_ptr] = read_ptr;
//				   if (i_ptr == 63)
//					   debugW2[i_ptr] = 0xaa;
				   SPI0DAT = (hidmsgbuf+read_ptr*64)[i_ptr++];
				   byt = SPI0DAT;
			   }
			   else
			   {
				   spi_transfer_complete();
			   }
		   }
	   }
	   SPI0CN0_SPIF = 0;
   }
}


void usb_write()
{
	data uint8_t errors = 0;
	USB_TX_COUNT += 64;
	while (USB_STATUS_OK != (USBD_Write(EP3IN, writebackbuf, 64, true)))
	{
		delay(2);
		if (errors++ > 30)
		{
			cprints("ERROR USB WRITE\r\n");
			break;
		}
	}
}


int main(void) {
	uint8_t k;
	uint16_t t1 = 0;
	uint8_t lastcount = count;

	int reset;
	data int lastwritecount = writebackbuf_count;

	enter_DefaultMode_from_RESET();

	eeprom_init();

	SCON0_TI = 1;
	P2_B0 = 1;

	MSG_RDY_INT_PIN = 1;

	// enable SPI interrupts
	SPI0FCN1 = SPI0FCN1 | (1<<4);
	IE_EA = 1;
	IE_ESPI0 = 1;

	SIGNAL_WRITE_RDY();

	cprints("hello,world\r\n");

	reset = RSTSRC;
	cprintx("reset source: ", 1, reset);

	while (1) {
//		delay(1500);
		if (overrun)
		{
			cprints("O\r\n");
			overrun = 0;
		}
		if (millis() - t1 > 1500)
		{
			P1_B5 = k++&1;
//			if (k&1)
//				SIGNAL_WRITE_RDY();
//			else
//				SIGNAL_WRITE_BSY();
			t1 = millis();
		}
		if (!USBD_EpIsBusy(EP2OUT) && !USBD_EpIsBusy(EP3IN) && lastcount==count)
		{
//			cprintd("sched read to ",1,(int)(hidmsgbuf + write_ptr*64));
			if (count == BUFFER_SIZE)
			{
//				cprints("Warning, USB buffer full\r\n");
			}
			else
			{
				USBD_Read(EP2OUT, hidmsgbuf + write_ptr*64, 64, true);
			}
		}

		if (writebackbuf_count == 64)
		{
//			cprints("<< ");
//			dump_hex(writebackbuf,64);
//			while (USBD_EpIsBusy(EP1IN))
//				;
			usb_write();
			writebackbuf_count = 0;
			if (USB_TX_COUNT < 511/2)
			{
				SIGNAL_WRITE_RDY();
			}
		}

		if (lastcount != count)
		{
			if (count > lastcount)
			{
//				cputd(debugRi); cprints(">> ");
//				dump_hex(debugR,64);

				MSG_RDY_INT_PIN = 0;
				MSG_RDY_INT_PIN = 1;
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
