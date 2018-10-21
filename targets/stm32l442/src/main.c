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

#include "app.h"
#include "flash.h"
#include "rng.h"
#include "led.h"
#include "device.h"

#define Error_Handler() _Error_Handler(__FILE__,__LINE__)


int main(void)
{
    uint8_t str[] = "YouCompleteMe: a code-completion engine for Vim";
    uint8_t buf[5000];
    uint32_t i = 0;
    float ent;
    float test = 1235.889944f;

    hw_init();

    printf("hello solo\r\n");

    // Test flash
    flash_erase_page(60);
    flash_write(flash_addr(60), str, sizeof(str));
    memmove(buf,(uint8_t*)flash_addr(60),sizeof(str));
    printf("flash: \"%s\"\r\n", buf);

    // test timer
    uint32_t t1 = millis();
    delay(100);
    uint32_t t2 = millis();
    printf("100 ms delay (%lu)\r\n",t2-t1);

    // test rng
    ent = rng_test(64 * 1024);

    printf("entropy of 64KB from RNG: %.6f\r\n", ent);
    printf("test float: %.2f\r\n", test);

    // Test PWM + weighting of RGB
    led_test_colors();

    while (1)
    {
        led_rgb(i | (i << 8) | (i << 16));

        delay(1000);
        printf("%lu: %lu\r\n", i+=50, millis());
    }
}


void _Error_Handler(char *file, int line)
{

    printf("Error: %s: %d\r\n", file, line);
    while(1)
    {
    }
}


