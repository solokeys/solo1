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
#include "stm32l4xx_ll_tim.h"

#include "app.h"
#include "flash.h"

#define Error_Handler() _Error_Handler(__FILE__,__LINE__)

#define LED_PIN_G     LL_GPIO_PIN_0
#define LED_PIN_B     LL_GPIO_PIN_1
#define LED_PIN_R     LL_GPIO_PIN_2
#define LED_PORT    GPIOA

void hw_init(void);

void delay(uint32_t ms)
{
    uint32_t time = millis();
    while ((millis() - time) < ms)
        ;
}

void rgb(uint32_t hex)
{
    uint32_t r = hex >> 16;
    uint32_t g = (hex >> 8)&0xff;
    uint32_t b = hex & 0xff;

    // CCR2 == blue
    // CCR3 == red
    // CCR4 == green

    // map and scale colors
    TIM2->CCR2 = 1000 - (b * 1000)/(256);
    TIM2->CCR3 = 1000 - (r * 1000)/(256*6);
    TIM2->CCR4 = 1000 - (g * 1000)/(256);
}

void test_colors()
{
    // Should produce pulsing of various colors
    int i = 0;
    int j = 0;
    int inc = 1;
    uint32_t time = 0;
#define update() do {\
        i += inc;\
        if (i > 254)\
        {\
            inc *= -1;\
        }\
        else if (i == 0)\
        {\
            inc *= -1;\
        }\
        delay(2);\
        }while(0);

    while(1)
    {

        printf("%d: %lu\r\n", j++, millis());

        printf("white pulse\r\n");
        time = millis();
        while((millis() - time) < 5000)
        {
            update();
            rgb(i | (i << 8) | (i << 16));
        }

        printf("blue pulse\r\n");
        time = millis();
        while((millis() - time) < 5000)
        {
            update();
            rgb(i);
        }

        printf("green pulse\r\n");
        time = millis();
        while((millis() - time) < 5000)
        {
            update();
            rgb(i<<8);
        }

        printf("red pulse\r\n");
        time = millis();
        while((millis() - time) < 5000)
        {
            update();
            rgb(i<<16);
        }

        printf("purple pulse\r\n");
        time = millis();
        while((millis() - time) < 5000)
        {
            update();
            rgb((i<<16) | i);
        }

        printf("orange pulse\r\n");
        time = millis();
        while((millis() - time) < 5000)
        {
            update();
            rgb((i<<16) | (i<<8));
        }

        printf("yellow pulse\r\n");
        time = millis();
        while((millis() - time) < 5000)
        {
            update();
            rgb((i<<8) | (i<<0));
        }
    }
}


uint32_t __65_seconds = 0;
void TIM6_DAC_IRQHandler()
{
    // timer is only 16 bits, so roll it over here
    TIM6->SR = 0;
    __65_seconds += 1;
}

int main(void)
{
    uint8_t str[] = "YouCompleteMe: a code-completion engine for Vim";
    uint8_t buf[500];
    uint32_t i = 0;
    hw_init();
    printf("hello solo\r\n");


    /*LL_GPIO_SetPinMode(LED_PORT, LED_PIN_R, LL_GPIO_MODE_OUTPUT);*/
    /*LL_GPIO_SetPinMode(LED_PORT, LED_PIN_G, LL_GPIO_MODE_OUTPUT);*/
    /*LL_GPIO_SetPinMode(LED_PORT, LED_PIN_B, LL_GPIO_MODE_OUTPUT);*/

    /*LL_GPIO_SetOutputPin(LED_PORT, LED_PIN_R);*/
    /*LL_GPIO_SetOutputPin(LED_PORT, LED_PIN_G);*/
    /*LL_GPIO_SetOutputPin(LED_PORT, LED_PIN_B);*/

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

    // Test PWM + weighting of RGB
    test_colors();

    while (1)
    {
        rgb(i | (i << 8) | (i << 16));

        delay(1000);
        printf("%lu: %lu\r\n", i+=50, millis());
    }
}


void _Error_Handler(char *file, int line)
{

    while(1)
    {
    }
}


