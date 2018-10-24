#include "stm32l4xx_ll_usart.h"

#include "app.h"

int WRITE_PTR = 0;
int READ_PTR = 0;
#define BUF_SIZE    20000
static uint8_t WRITE_BUF[BUF_SIZE];

void add2buf(uint8_t c)
{
    WRITE_BUF[WRITE_PTR++] = c;
    if (WRITE_PTR >= BUF_SIZE)
        WRITE_PTR = 0;
}

uint8_t takebuf()
{
    uint8_t c;
    c = WRITE_BUF[READ_PTR++];
    if (READ_PTR >= BUF_SIZE)
        READ_PTR = 0;
    return c;
}

uint8_t bufavail()
{
    return (READ_PTR < WRITE_PTR);
}
void _putchar(char c)
{
    // add2buf(c);
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
