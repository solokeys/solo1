
#include "device.h"

uint32_t __65_seconds = 0;
void TIM6_DAC_IRQHandler()
{
    // timer is only 16 bits, so roll it over here
    TIM6->SR = 0;
    __65_seconds += 1;
}


void delay(uint32_t ms)
{
    uint32_t time = millis();
    while ((millis() - time) < ms)
        ;
}


