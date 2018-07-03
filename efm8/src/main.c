#include <SI_EFM8UB1_Register_Enums.h>
#include "InitDevice.h"
#include "efm8_usb.h"
#include "uart_1.h"
#include "printing.h"

#define BUFFER_SIZE	10

uint8_t write_ptr = 0;
uint8_t read_ptr = 0;
uint8_t count = 0;

uint8_t hidmsgbuf[64][BUFFER_SIZE];

void usb_transfer_complete()
{
	count++;
	write_ptr++;
	if (write_ptr == BUFFER_SIZE)
	{
		write_ptr = 0;
	}
	cprints("read hid msg\r\n");
}

void spi_transfer_complete()
{
	count--;
	read_ptr++;
	if (read_ptr == BUFFER_SIZE)
	{
		read_ptr = 0;
	}
	cprints("sent hid msg\r\n");
}

SI_INTERRUPT (SPI0_ISR, SPI0_IRQn)
{

   static unsigned char command;
   static unsigned char array_index = 0;
   static unsigned char state = 0;
   char arr[2];

   if (SPI0CN0_WCOL == 1)
   {
      // Write collision occurred
      SPI0CN0_WCOL = 0;                 // Clear the Write collision flag
   }
   else if(SPI0CN0_RXOVRN == 1)
   {
      // Receive overrun occurred
      SPI0CN0_RXOVRN = 0;               // Clear the Receive Overrun flag
   }
   else
   {
      // SPI0CN0_SPIF caused the interrupt

    	 arr[0] = SPI0DAT;            // Read the command
    	 arr[1] = 0;

    	 cprints("got data: ");
    	 cprints(arr);
    	 cprints("\n\r");



      SPI0CN0_SPIF = 0;                 // Clear the SPIF0 flag
   }
}



int main(void) {
	volatile int xdata i,j,k;
	uint8_t lastcount = count;
	enter_DefaultMode_from_RESET();
	IE_EA = 1;
	SCON0_TI = 1;
	P2_B0 = 1;
	cprints("hello,world\r\n");



	while (1) {
		k++;
		for (i = 0; i < 1000; i++)
		{
			for (j = 0; j < 100; j++)
			{

			}
			P1_B4 = i&1;
		}
		P1_B5 = k&1;
		if (!USBD_EpIsBusy(EP1OUT) && !USBD_EpIsBusy(EP1IN))
		{
			if (count == BUFFER_SIZE)
			{
				cprints("Warning, USB buffer full\r\n");
			}
			else
			{
				USBD_Read(EP1OUT, hidmsgbuf[write_ptr], 64, true);
			}
		}
		if (count != lastcount)
		{
			cprints("+1 to count \r\n");
			lastcount = count;
		}

	}
}
