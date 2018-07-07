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
#include "em_usart.h"

#include "cbor.h"
#include "log.h"
#include "ctaphid.h"
#include "util.h"

#define MSG_AVAIL_PIN	gpioPortC,9
#define RDY_PIN			gpioPortC,10
#define RW_PIN			gpioPortD,11

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
	printf1(TAG_DUMP,"<< "); dump_hex1(TAG_DUMP, data, HID_MESSAGE_SIZE);
	usbhid_send(data);
}

void heartbeat()
{
	static int beat = 0;
	GPIO_PinOutToggle(gpioPortF,4);
	GPIO_PinOutToggle(gpioPortF,5);

//	printf("heartbeat %d %d\r\n", beat++,CRYOTIMER->CNT);
}

uint32_t millis()
{
	return CRYOTIMER->CNT;
}


void usbhid_init()
{

}

static int msgs_to_recv = 0;

static void wait_for_efm8_ready()
{
	// Wait for efm8 to be ready
	while (GPIO_PinInGet(RDY_PIN) == 0)
		;
}

static void wait_for_efm8_busy()
{
	// Wait for efm8 to be ready
	while (GPIO_PinInGet(RDY_PIN) != 0)
		;
}

int usbhid_recv(uint8_t * msg)
{
	int i;

	if (GPIO_PinInGet(MSG_AVAIL_PIN) == 0)
	{
		GPIO_PinOutClear(RW_PIN);	// Drive low to indicate READ
		wait_for_efm8_ready();


		for (i = 0; i < 64; i++)
		{
			msg[i] = USART_SpiTransfer(USART1, 'A');
//			delay(1);
		}

		GPIO_PinOutSet(RW_PIN);

		wait_for_efm8_busy();


//		msgs_to_recv--;
//		printf(">> ");
//		dump_hex(msg,64);
		return 64;
	}

	return 0;
}

void usbhid_send(uint8_t * msg)
{
	int i;
//	uint32_t t1 = millis();
	USART_SpiTransfer(USART1, *msg++); // Send 1 byte
	wait_for_efm8_ready();

	for (i = 1; i < HID_MESSAGE_SIZE; i++)
	{
		USART_SpiTransfer(USART1, *msg++);
	}
	wait_for_efm8_busy();
//	uint32_t t2 = millis();
//	printf("wait time: %u\n", (uint32_t)(t2-t1));

}

void usbhid_close()
{
}

void main_loop_delay()
{
}

void delay(int ms)
{
	int t1 = millis();
	while(millis() - t1 < ms)
		;
}

void GPIO_ODD_IRQHandler()
{
	uint32_t flag = GPIO->IF;
	GPIO->IFC = flag;
	if (flag & (1<<9))
	{
//		printf("pin 9 interrupt\r\n");
		msgs_to_recv++;
	}
	else
	{
		printf1(TAG_ERR,"wrong pin int %x\r\n",flag);
	}


}

void device_init(void)
{
  /* Chip errata */
  CHIP_Init();
  enter_DefaultMode_from_RESET();

  // status LEDS
  GPIO_PinModeSet(gpioPortF,
                       4,
					   gpioModePushPull,
                       0);

  GPIO_PinModeSet(gpioPortF,
                       5,
					   gpioModePushPull,
                       1);

  // EFM8 RDY/BUSY
  GPIO_PinModeSet(RDY_PIN, gpioModeInput, 0);

  // EFM8 MSG Available
  GPIO_PinModeSet(MSG_AVAIL_PIN, gpioModeInput, 0);

  // SPI R/w Indicator
  GPIO_PinModeSet(RW_PIN, gpioModePushPull, 1);

  // USB message rdy ext int
//  GPIO_ExtIntConfig(gpioPortC, 9, 9, 1, 0,1);
//  NVIC_EnableIRQ(GPIO_ODD_IRQn);


  printing_init();

  CborEncoder test;
  uint8_t buf[20];
  cbor_encoder_init(&test, buf, 20, 0);

  printf("Device init\r\n");
  int i=0;


}
