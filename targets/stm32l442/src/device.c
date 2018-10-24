
#include "device.h"
#include "usbd_def.h"

uint32_t __65_seconds = 0;
void TIM6_DAC_IRQHandler()
{
    // timer is only 16 bits, so roll it over here
    TIM6->SR = 0;
    __65_seconds += 1;
}

extern PCD_HandleTypeDef hpcd;
// Global USB interrupt handler
void USB_IRQHandler(void)
{
  HAL_PCD_IRQHandler(&hpcd);
}

void delay(uint32_t ms)
{
    uint32_t time = millis();
    while ((millis() - time) < ms)
        ;
}
