#include <SI_EFM8UB1_Register_Enums.h>
#include "InitDevice.h"
#include "efm8_usb.h"
#include "printing.h"




int main(void) {
	volatile int xdata i,j,k;
	enter_DefaultMode_from_RESET();

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

	}
}
