#include <SI_EFM8UB1_Register_Enums.h>
#include "InitDevice.h"
#include "efm8_usb.h"
#include "printing.h"




int main(void) {
	enter_DefaultMode_from_RESET();

	cprints("hello,world\r\n");

	while (1) {

	}
}
