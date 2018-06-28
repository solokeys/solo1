/*
 * device.c
 *
 *  Created on: Jun 27, 2018
 *      Author: conor
 */
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#include "em_chip.h"
#include "em_gpio.h"

#include "cbor.h"
#include "log.h"
#include "ctaphid.h"
#include "util.h"

// Generate @num bytes of random numbers to @dest
// return 1 if success, error otherwise
int ctap_generate_rng(uint8_t * dst, size_t num)
{
	int i;
	for (i = 0; i < num; i++)
	{
		*dst++ = rand();
	}
	return 1;
}

uint32_t _c1 = 0, _c2 = 0;
uint32_t ctap_atomic_count(int sel)
{
	if (sel == 0)
	{
		_c1++;
		return _c1;
	}
	else
	{
		_c2++;
		return _c2;
	}
}

// Verify the user
// return 1 if user is verified, 0 if not
int ctap_user_verification(uint8_t arg)
{
	return 1;
}

// Test for user presence
// Return 1 for user is present, 0 user not present
int ctap_user_presence_test()
{
	return 1;
}

// Must be implemented by application
// data is HID_MESSAGE_SIZE long in bytes
void ctaphid_write_block(uint8_t * data)
{
	dump_hex(data, HID_MESSAGE_SIZE);
}

void heartbeat()
{
	static int beat = 0;
	GPIO_PinOutToggle(gpioPortF,4);
	GPIO_PinOutToggle(gpioPortF,5);
//	printf("heartbeat %d\r\n", CRYOTIMER->CNT);
}

uint64_t millis()
{
	return CRYOTIMER->CNT;
}


void usbhid_init()
{

}

int usbhid_recv(uint8_t * msg)
{
	return 0;
}

void usbhid_send(uint8_t * msg)
{
}

void usbhid_close()
{
}

void main_loop_delay()
{
}


void device_init(void)
{
  /* Chip errata */
  CHIP_Init();
  enter_DefaultMode_from_RESET();

  GPIO_PinModeSet(gpioPortF,
                       4,
					   gpioModePushPull,
                       0);

  GPIO_PinModeSet(gpioPortF,
                       5,
					   gpioModePushPull,
                       1);




  printing_init();

  CborEncoder test;
  uint8_t buf[20];
  cbor_encoder_init(&test, buf, 20, 0);

  printf("Device init\r\n");

}
