#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "stm32l4xx.h"
#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_rcc.h"
#include "stm32l4xx_ll_system.h"
#include "stm32l4xx_ll_pwr.h"
#include "stm32l4xx_ll_utils.h"
#include "stm32l4xx_ll_cortex.h"
#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_usart.h"
#include "stm32l4xx_ll_bus.h"
#include "stm32l4xx_ll_usb.h"

#include "stm32l4xx_hal_pcd.h"

#include "usbd_core.h"
#include "usbd_desc.h"
#include "usbd_hid.h"
/*#include "usbd_hid.h"*/

#include "app.h"
#include "flash.h"
#include "rng.h"
#include "led.h"
#include "device.h"
#include "util.h"
#include "fifo.h"
#include "log.h"

#define IS_BUTTON_PRESSED()         (0  == (LL_GPIO_ReadInputPort(SOLO_BUTTON_PORT) & SOLO_BUTTON_PIN))

#ifdef TEST_SOLO_STM32
#define Error_Handler() _Error_Handler(__FILE__,__LINE__)
#define PAGE_SIZE		2048
#define PAGES			128
// Pages 119-127 are data
#define	COUNTER2_PAGE	(PAGES - 4)
#define	COUNTER1_PAGE	(PAGES - 3)
#define	STATE2_PAGE		(PAGES - 2)
#define	STATE1_PAGE		(PAGES - 1)

void test_atomic_counter()
{
    // flash_erase_page(COUNTER1_PAGE);
    // flash_erase_page(COUNTER2_PAGE);
    int i;
    uint32_t c0 = ctap_atomic_count(0);
    for (i = 0; i < 128; i++)
    {
        uint32_t c1 = ctap_atomic_count(0);
        if (c1 <= (c0 ))
        {
            printf("error, count failed  %lu <= %lu\r\n",c1,c0);
            while(1)
            ;
        }
        printf("%lu\r\n", c1);
        c0 = c1;
    }

    printf("test faults\r\n");

    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));

    flash_erase_page(COUNTER1_PAGE);

    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));

    flash_erase_page(COUNTER1_PAGE);
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));

    flash_erase_page(COUNTER1_PAGE);
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));

    flash_erase_page(COUNTER1_PAGE);

    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));

    flash_erase_page(COUNTER2_PAGE);

    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));

    flash_erase_page(COUNTER2_PAGE);

    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));

    flash_erase_page(COUNTER2_PAGE);

    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));

    flash_erase_page(COUNTER2_PAGE);

    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));

    flash_erase_page(COUNTER1_PAGE);

    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));

    flash_erase_page(COUNTER1_PAGE);

    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));
    printf("%lu\r\n", ctap_atomic_count(0));

    flash_erase_page(COUNTER1_PAGE);

}

void test_peripherals()
{
    uint8_t str[] = "YouCompleteMe: a code-completion engine for Vim";
    uint8_t buf[sizeof(str)];
    float ent;
    printf("hello solo\r\n");

    // Test flash
    flash_erase_page(60);
    flash_write(flash_addr(60), str, sizeof(str));
    memmove(buf,(uint8_t*)flash_addr(60),sizeof(str));
    printf("flash: \"%s\"\r\n", buf);
    // test_atomic_counter();


    // Note that 4 byte aligned addresses won't get written correctly.
    flash_erase_page(60);
    uint32_t count = 0;
    flash_write(flash_addr(60) + 0,(uint8_t*)&count,4);
    count += 1;
    flash_write(flash_addr(60) + 4,(uint8_t*)&count,4);
    count += 1;
    flash_write(flash_addr(60) + 8,(uint8_t*)&count,4);
    count += 1;
    flash_write(flash_addr(60) + 12,(uint8_t*)&count,4);
    count += 1;
    flash_write(flash_addr(60) + 16,(uint8_t*)&count,4);
    dump_hex((uint8_t *)flash_addr(60), 20);


    // test timer
    uint32_t t1 = millis();
    delay(100);
    uint32_t t2 = millis();
    printf("100 ms delay (%lu)\r\n",t2-t1);

    // test rng
    ent = rng_test(64 * 1024);

    printf("entropy of 64KB from RNG: %.6f\r\n", ent);

    /*// Test PWM + weighting of RGB*/
    /*led_test_colors();*/
    fifo_test();
}

int main(void)
{
    uint32_t i = 5;

    hw_init();

    LL_GPIO_SetPinMode(SOLO_BUTTON_PORT,SOLO_BUTTON_PIN,LL_GPIO_MODE_INPUT);
    LL_GPIO_SetPinPull(SOLO_BUTTON_PORT,SOLO_BUTTON_PIN,LL_GPIO_PULL_UP);
    flash_option_bytes_init(1);

    set_logging_mask(
            /*0*/
           // TAG_GEN|
            TAG_MC |
            TAG_GA |
            // TAG_WALLET |
            TAG_STOR |
            TAG_CP |
            TAG_CTAP|
//            TAG_HID|
            /*TAG_U2F|*/
            TAG_PARSE |
           //TAG_TIME|
            // TAG_DUMP|
            TAG_GREEN|
            TAG_RED|
            TAG_ERR
            );


    while (1)
    {
        uint32_t t0 = millis() % 750;
        if (! IS_BUTTON_PRESSED())
        {
            if (t0 < 750*1/3)
            {
                led_rgb(0 | (0 << 8) | (i << 17));
            }
            else if (t0 < 750*2/3)
            {
                led_rgb(0 | (i << 8) | (0 << 16));
            }
            else
            {
                led_rgb(i | (0 << 8) | (0 << 16));
            }
        }
        else
        {
            led_rgb(0x151515);
        }


    }
}

#endif
