#ifndef _APP_H_
#define _APP_H_
#include <stdint.h>

#define DEBUG_UART      USART1

extern uint32_t __65_seconds;

#define millis()    (((uint32_t)TIM6->CNT) | (__65_seconds<<16))

#endif
