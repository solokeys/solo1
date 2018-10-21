#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <stdint.h>
#include "stm32l4xx_ll_tim.h"

void delay(uint32_t ms);

#define millis()    (((uint32_t)TIM6->CNT) | (__65_seconds<<16))
extern uint32_t __65_seconds;

#endif
