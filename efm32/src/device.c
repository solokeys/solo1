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
#include "em_adc.h"
#include "em_cmu.h"
#include "em_msc.h"

#include "InitDevice.h"
#include "cbor.h"
#include "log.h"
#include "ctaphid.h"
#include "util.h"
#include "app.h"

#define MSG_AVAIL_PIN	gpioPortC,9
#define RDY_PIN			gpioPortC,10
#define RW_PIN			gpioPortD,11

#define PAGE_SIZE		2048
#define PAGES			128
#define	COUNTER_PAGE	125
#define	STATE1_PAGE		126
#define	STATE2_PAGE		127



static void init_atomic_counter()
{
    int offset = 0;
    uint32_t count;
    uint32_t one = 1;
    uint32_t * ptr = PAGE_SIZE * COUNTER_PAGE;

    for (offset = 0; offset < PAGE_SIZE/4; offset += 1)
    {
        count = *(ptr+offset);
        if (count != 0xffffffff)
        {
            return;
        }
    }
    MSC_WriteWordFast(ptr,&one,4);
}


uint32_t ctap_atomic_count(int sel)
{
    int offset = 0;
    uint32_t count;
    uint32_t zero = 0;
    uint32_t * ptr = PAGE_SIZE * COUNTER_PAGE;

    if (sel != 0)
    {
        printf2(TAG_ERR,"counter2 not imple\n");
        exit(1);
    }

    for (offset = 0; offset < PAGE_SIZE/4; offset += 1) // wear-level the flash
    {
        count = *(ptr+offset);
        if (count != 0)
        {
            count++;
            offset++;
            if (offset == PAGE_SIZE/4)
            {
                offset = 0;
                MSC_ErasePage(ptr);
                /*printf("RESET page counter\n");*/
            }
            else
            {
                MSC_WriteWordFast(ptr+offset-1,&zero,4);
            }
            MSC_WriteWordFast(ptr+offset,&count,4);

            break;
        }
    }

    return count;
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
        // printf("pin 9 interrupt\r\n");
        msgs_to_recv++;
    }
    else
    {
        printf1(TAG_ERR,"wrong pin int %x\r\n",flag);
    }


}

void init_adc()
{
   /* Enable ADC Clock */
   CMU_ClockEnable(cmuClock_ADC0, true);
   ADC_Init_TypeDef init = ADC_INIT_DEFAULT;
   ADC_InitSingle_TypeDef singleInit = ADC_INITSINGLE_DEFAULT;

   /* Initialize the ADC with the required values */
   init.timebase = ADC_TimebaseCalc(0);
   init.prescale = ADC_PrescaleCalc(7000000, 0);
   ADC_Init(ADC0, &init);

   /* Initialize for single conversion specific to RNG */
   singleInit.reference = adcRefVEntropy;
   singleInit.diff = true;
   singleInit.posSel = adcPosSelVSS;
   singleInit.negSel = adcNegSelVSS;
   ADC_InitSingle(ADC0, &singleInit);

   /* Set VINATT to maximum value and clear FIFO */
   ADC0->SINGLECTRLX |= _ADC_SINGLECTRLX_VINATT_MASK;
   ADC0->SINGLEFIFOCLEAR = ADC_SINGLEFIFOCLEAR_SINGLEFIFOCLEAR;
}



static uint8_t _STATE1[sizeof(AuthenticatorState)];
static uint8_t _STATE2[sizeof(AuthenticatorState)];

void authenticator_read_state(AuthenticatorState * state)
{
	uint32_t * ptr = PAGE_SIZE*STATE1_PAGE;
    memmove(state,ptr,sizeof(AuthenticatorState));
}

void authenticator_read_backup_state(AuthenticatorState * state )
{
	uint32_t * ptr = PAGE_SIZE*STATE2_PAGE;
    memmove(state,ptr,sizeof(AuthenticatorState));
}

void authenticator_write_state(AuthenticatorState * state, int backup)
{
    uint32_t * ptr;
    int i;
    if (! backup)
    {
        ptr = PAGE_SIZE*STATE1_PAGE;
        MSC_ErasePage(ptr);
        //    	for (i = 0; i < sizeof(AuthenticatorState)/4; i++ )
        MSC_WriteWordFast(ptr,state,sizeof(AuthenticatorState) + (sizeof(AuthenticatorState)%4));
    }
    else
    {
        ptr = PAGE_SIZE*STATE2_PAGE;
        MSC_ErasePage(ptr);
        //    	for (i = 0; i < sizeof(AuthenticatorState)/4; i++ )
        MSC_WriteWordFast(ptr,state,sizeof(AuthenticatorState) + (sizeof(AuthenticatorState)%4));
    }
}

// Return 1 yes backup is init'd, else 0
int authenticator_is_backup_initialized()
{
    uint8_t header[16];
    uint32_t * ptr = PAGE_SIZE*STATE2_PAGE;
    memmove(header,ptr,16);
    AuthenticatorState * state = (AuthenticatorState*)header;
    return state->is_initialized == INITIALIZED_MARKER;
}



uint8_t adc_rng(void);

void bootloader_init(void)
{
    /* Chip errata */



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


    MSC_Init();



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

    init_adc();

    MSC_Init();

    init_atomic_counter();
    if (sizeof(AuthenticatorState) > PAGE_SIZE)
    {
        printf2(TAG_ERR, "not enough room in page\n");
        exit(1);
    }

    CborEncoder test;
    uint8_t buf[64];
    cbor_encoder_init(&test, buf, 20, 0);

    printf("Device init\r\n");
    int i=0;

    for (i = 0; i < sizeof(buf); i++)
    {
        buf[i] = adc_rng();
    }
    dump_hex(buf,sizeof(buf));


}
