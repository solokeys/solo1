#include "stm32l4xx_ll_usart.h"

#include "app.h"

void _putchar(char c)
{
    while (! LL_USART_IsActiveFlag_TXE(DEBUG_UART))
        ;
    LL_USART_TransmitData8(DEBUG_UART,c);
}

int _write (int fd, const void *buf, long int len)
{
    uint8_t * data = (uint8_t *) buf;
    while(len--)
    {
        _putchar(*data++);
    }
    return 0;
}

