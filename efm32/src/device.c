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
#include "em_i2c.h"
#include "em_timer.h"

#include "InitDevice.h"
#include "cbor.h"
#include "log.h"
#include "ctaphid.h"
#include "util.h"
#include "app.h"
#include "uECC.h"
#include "crypto.h"
#include "nfc.h"

#ifdef USING_DEV_BOARD

#define MSG_AVAIL_PIN	gpioPortC,9
#define RDY_PIN			gpioPortC,10
#define RW_PIN			gpioPortD,11
#define RESET_PIN		gpioPortB,13
#define LED1_PIN		gpioPortF,4
#define LED2_PIN		gpioPortF,5

#else

#define MSG_AVAIL_PIN	gpioPortA,1
#define RDY_PIN			gpioPortA,0
#define RW_PIN			gpioPortD,15
#define RESET_PIN		gpioPortB,15
#define LED1_PIN		gpioPortD,9
#define LED2_PIN		gpioPortD,10
#define LED3_PIN		gpioPortD,14
#define BUTTON_PIN		gpioPortD,13

#endif

#define PAGE_SIZE		2048
#define PAGES			64
#define	COUNTER_PAGE	(PAGES - 3)
#define	STATE1_PAGE		(PAGES - 2)
#define	STATE2_PAGE		(PAGES - 1)

#define APPLICATION_START_ADDR	0x4000
#define APPLICATION_START_PAGE	(0x4000/PAGE_SIZE)

#define APPLICATION_END_ADDR	(PAGE_SIZE*(PAGES - 3)-4)		// NOT included in application
#define APPLICATION_END_PAGE	((PAGES - 3))					// 125 is NOT included in application

#define AUTH_WORD_ADDR          (PAGE_SIZE*(PAGES - 3)-4)



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

static uint32_t _color;
uint32_t get_RBG()
{
	return _color;
}

void RGB(uint32_t hex)
{
	uint16_t r = 256 - ((hex & 0xff0000) >> 16);
	uint16_t g = 256 - ((hex & 0xff00) >> 8);
	uint16_t b = 256 - ((hex & 0xff) >> 0);

    TIMER_CompareBufSet(TIMER0, 0, g);		// green
    TIMER_CompareBufSet(TIMER0, 1, r);		// red
    TIMER_CompareBufSet(TIMER0, 2, b);		// blue
    _color = hex;
}


#define IS_BUTTON_PRESSED()		(GPIO_PinInGet(BUTTON_PIN) == 0)

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
	uint32_t t1 = millis();
	RGB(0x304010);
	while (IS_BUTTON_PRESSED())
	{
		if (t1 + 5000 < millis())
			return 0;
	}

	t1 = millis();

	do
	{
		if (t1 + 5000 < millis())
			return 0;
		if (! IS_BUTTON_PRESSED())
			continue;
		delay(1);
	}
	while (! IS_BUTTON_PRESSED());

	RGB(0x001040);

	delay(50);

    return 1;
}

// Must be implemented by application
// data is HID_MESSAGE_SIZE long in bytes
#ifndef TEST_POWER
void ctaphid_write_block(uint8_t * data)
{
    printf1(TAG_DUMP,"<< "); dump_hex1(TAG_DUMP, data, HID_MESSAGE_SIZE);
    usbhid_send(data);
}
#endif

#ifdef IS_BOOTLOADER	// two different colors between bootloader and app
void heartbeat()
{
	static int state = 0;
	static uint32_t val = (LED_INIT_VALUE >> 8) & 0xff;
	int but = IS_BUTTON_PRESSED();


	if (state)
	{
		val--;
	}
	else
	{
		val++;
	}

	if (val > 30 || val < 1)
	{
		state = !state;
	}

//	if (but) RGB(val * 2);
//	else
		RGB((val << 16) | (val*2 << 8));

}
#else
void heartbeat()
{
	static int state = 0;
	static uint32_t val = (LED_INIT_VALUE >> 8) & 0xff;
	int but = IS_BUTTON_PRESSED();


	if (state)
	{
		val--;
	}
	else
	{
		val++;
	}

	if (val > 30 || val < 1)
	{
		state = !state;
	}

	if (but) RGB(val * 2);
	else RGB(val << 8);

}
#endif
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

#ifndef TEST_POWER
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


//        //		msgs_to_recv--;
//        		printf(">> ");
//        		dump_hex(msg,64);
        return 64;
    }

    return 0;
}

#endif

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

    delay(10);
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

void reset_efm8()
{
    // Reset EFM8
	GPIO_PinOutClear(RESET_PIN);
	delay(2);
	GPIO_PinOutSet(RESET_PIN);
}

void bootloader_init(void)
{
    /* Chip errata */

    // Reset EFM8
    GPIO_PinModeSet(RESET_PIN, gpioModePushPull, 1);

    // status LEDS
    GPIO_PinModeSet(LED1_PIN,
            gpioModePushPull,
            1);		// red

    GPIO_PinModeSet(LED2_PIN,
            gpioModePushPull,
            1);		// green
    GPIO_PinModeSet(LED3_PIN,
            gpioModePushPull,
            1);		// blue

    // EFM8 RDY/BUSY
    GPIO_PinModeSet(RDY_PIN, gpioModeInput, 0);

    // EFM8 MSG Available
    GPIO_PinModeSet(MSG_AVAIL_PIN, gpioModeInput, 0);

    // SPI R/w Indicator
    GPIO_PinModeSet(RW_PIN, gpioModePushPull, 1);


    printing_init();


    MSC_Init();

}



void device_init(void)
{
    /* Chip errata */

    CHIP_Init();
    enter_DefaultMode_from_RESET();

    // status LEDS
    GPIO_PinModeSet(LED1_PIN,
            gpioModePushPull,
            1);		// red

    GPIO_PinModeSet(LED2_PIN,
            gpioModePushPull,
            1);		// green
    GPIO_PinModeSet(LED3_PIN,
            gpioModePushPull,
            1);		// blue

    // EFM8 RDY/BUSY
    GPIO_PinModeSet(RDY_PIN, gpioModeInput, 0);

    // EFM8 MSG Available
    GPIO_PinModeSet(MSG_AVAIL_PIN, gpioModeInput, 0);

    // SPI R/w Indicator
    GPIO_PinModeSet(RW_PIN, gpioModePushPull, 1);

    // Reset EFM8
    GPIO_PinModeSet(RESET_PIN, gpioModePushPull, 1);

    TIMER_TopSet(TIMER0, 255);

    RGB(LED_INIT_VALUE);

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

    reset_efm8();

    printf1(TAG_GEN,"Device init\r\n");
    int i=0;

    for (i = 0; i < sizeof(buf); i++)
    {
        buf[i] = adc_rng();
    }

}
#ifdef IS_BOOTLOADER
typedef enum
{
    BootWrite = 0x40,
    BootDone = 0x41,
    BootCheck = 0x42,
    BootErase = 0x43,
} WalletOperation;


typedef struct {
    uint8_t op;
    uint8_t addr[3];
    uint8_t tag[4];
    uint8_t len;
    uint8_t payload[255 - 9];
} __attribute__((packed)) BootloaderReq;

//#define APPLICATION_START_ADDR	0x8000
//#define APPLICATION_START_PAGE	(0x8000/PAGE_SIZE)

//#define APPLICATION_END_ADDR	(PAGE_SIZE*125-4)		// NOT included in application

static void erase_application()
{
    int page;
    uint32_t * ptrpage;
    for(page = APPLICATION_START_PAGE; page < APPLICATION_END_PAGE; page++)
    {
        ptrpage = page * PAGE_SIZE;
        MSC_ErasePage(ptrpage);
    }
}

static void authorize_application()
{
    uint32_t zero = 0;
    uint32_t * ptr;
    ptr = AUTH_WORD_ADDR;
    MSC_WriteWordFast(ptr,&zero, 4);
}
int bootloader_bridge(uint8_t klen, uint8_t * keyh)
{
    static int has_erased = 0;
    BootloaderReq * req =  (BootloaderReq *  )keyh;
    uint8_t payload[256];
    uint8_t hash[32];
    uint8_t * pubkey = (uint8_t*)"\x57\xe6\x80\x39\x56\x46\x2f\x0c\x95\xac\x72\x71\xf0\xbc\xe8\x2d\x67\xd0\x59\x29\x2e\x15\x22\x89\x6a\xbd\x3f\x7f\x27\xf3\xc0\xc6\xe2\xd7\x7d\x8a\x9f\xcc\x53\xc5\x91\xb2\x0c\x9c\x3b\x4e\xa4\x87\x31\x67\xb4\xa9\x4b\x0e\x8d\x06\x67\xd8\xc5\xef\x2c\x50\x4a\x55";
    const struct uECC_Curve_t * curve = NULL;

    /*printf("bootloader_bridge\n");*/
    if (req->len > 255-9)
    {
        return CTAP1_ERR_INVALID_LENGTH;
    }

    memset(payload, 0xff, sizeof(payload));
    memmove(payload, req->payload, req->len);

    uint32_t addr = (*((uint32_t*)req->addr)) & 0xffffff;

    uint32_t * ptr = addr;

    switch(req->op){
        case BootWrite:
            /*printf("BootWrite 0x%08x\n", addr);*/
            if (ptr < APPLICATION_START_ADDR || ptr >= APPLICATION_END_ADDR)
            {
                return CTAP2_ERR_NOT_ALLOWED;
            }

            if (!has_erased)
            {
                erase_application();
                has_erased = 1;
            }
            if (is_authorized_to_boot())
            {
                printf2(TAG_ERR, "Error, boot check bypassed\n");
                exit(1);
            }
            MSC_WriteWordFast(ptr,payload, req->len + (req->len%4));
            break;
        case BootDone:
//            printf("BootDone\n");
            ptr = APPLICATION_START_ADDR;
            crypto_sha256_init();
            crypto_sha256_update(ptr, APPLICATION_END_ADDR-APPLICATION_START_ADDR);
            crypto_sha256_final(hash);
//            printf("hash: "); dump_hex(hash, 32);
//            printf("sig: "); dump_hex(payload, 64);
            curve = uECC_secp256r1();

            if (! uECC_verify(pubkey,
                hash,
                32,
                payload,
                curve))
            {
                return CTAP2_ERR_OPERATION_DENIED;
            }
            authorize_application();
            REBOOT_FLAG = 1;
            break;
        case BootCheck:
            /*printf("BootCheck\n");*/
            return 0;
            break;
        case BootErase:
            /*printf("BootErase\n");*/
            erase_application();
            return 0;
            break;
        default:
            return CTAP1_ERR_INVALID_COMMAND;
    }
    return 0;
}

int is_authorized_to_boot()
{
    uint32_t * auth = AUTH_WORD_ADDR;
    return *auth == 0;
}

#endif
