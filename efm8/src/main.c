#include <SI_EFM8UB1_Register_Enums.h>
#include "InitDevice.h"
#include "efm8_usb.h"
#include "uart_1.h"
#include "printing.h"

#define BUFFER_SIZE	13

data uint8_t write_ptr = 0;
data uint8_t read_ptr = 0;
data uint8_t i_ptr = 0;
data uint8_t count = 0;
data uint8_t writebackbuf_count = 0;

uint8_t hidmsgbuf[64][BUFFER_SIZE];
data uint8_t writebackbuf[64];

void usb_transfer_complete()
{
	count++;
	write_ptr++;
	if (write_ptr == BUFFER_SIZE)
	{
		write_ptr = 0;
	}
	if (count == 1 && i_ptr == 0)
	{
		SPI0DAT = hidmsgbuf[read_ptr][i_ptr++];
	}


//	MSG_RDY_INT_PIN = 0;
//	MSG_RDY_INT_PIN = 1;

}

void spi_transfer_complete()
{
	count--;
	i_ptr = 0;
	SPI0FCN0 |= (1<<2); // Flush rx fifo buffer
	if (count)
	{
		SPI0DAT = hidmsgbuf[read_ptr][i_ptr++];
	}
	read_ptr++;

	if (read_ptr == BUFFER_SIZE)
	{
		read_ptr = 0;
	}

//	cprints("sent hid msg\r\n");
}

SI_INTERRUPT (SPI0_ISR, SPI0_IRQn)
{
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
//		cprints("SPI0CN0_RXOVRN\r\n");
   }
   else
   {
	   if (EFM32_RW_PIN)
	   {
		   if (writebackbuf_count < 64) writebackbuf[writebackbuf_count++] = SPI0DAT;
		   else cprints("overflow\r\n");
	   }
	   else
	   {
		   if (count)
		   {
			   if (i_ptr < 64)
			   {
				   SPI0DAT = hidmsgbuf[read_ptr][i_ptr++];

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
	while (USB_STATUS_OK != (USBD_Write(EP1IN, writebackbuf, 64, false)))
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

	cprints("hello,world\r\n");

	reset = RSTSRC;
	cprintx("reset source: ", 1, reset);

	while (1) {
//		delay(1500);
		if (millis() - t1 > 1500)
		{
			P1_B5 = k++&1;
			t1 = millis();
		}
		if (!USBD_EpIsBusy(EP1OUT) && !USBD_EpIsBusy(EP1IN))
		{
//			cprintd("sched read to ",1,reset);
			if (count == BUFFER_SIZE)
			{
				cprints("Warning, USB buffer full\r\n");
			}
			else
			{
				USBD_Read(EP1OUT, hidmsgbuf[write_ptr], 64, true);
			}
		}

		if (writebackbuf_count == 64)
		{
//			cprints("<< ");
//			dump_hex(writebackbuf,64);
			writebackbuf_count = 0;
//			while (USBD_EpIsBusy(EP1IN))
//				;
			usb_write();
		}

		if (lastcount != count)
		{
			if (count > lastcount)
			{
//				cprints(">> ");
//				dump_hex(writebackbuf,64);

				MSG_RDY_INT_PIN = 0;
				MSG_RDY_INT_PIN = 1;
			}
			else
			{
//				cprints("efm32 read hid msg\r\n>> ");
//				dump_hex(debug,64);
			}
			lastcount = count;
		}

	}
}
