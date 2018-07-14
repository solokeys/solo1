#include "em_device.h"
#include "em_chip.h"
#include "device.h"
#include "app.h"
#include "InitDevice.h"

void bootloader_init(void);

int main(void)
{
  /* Chip errata */
	CHIP_Init();

	EMU_enter_DefaultMode_from_RESET();
	CMU_enter_DefaultMode_from_RESET();
//	ADC0_enter_DefaultMode_from_RESET();
	USART0_enter_DefaultMode_from_RESET();
	USART1_enter_DefaultMode_from_RESET();
	LDMA_enter_DefaultMode_from_RESET();
	CRYOTIMER_enter_DefaultMode_from_RESET();
	PORTIO_enter_DefaultMode_from_RESET();

	bootloader_init();

	/* Infinite loop */
	while (1) {
	}
}
