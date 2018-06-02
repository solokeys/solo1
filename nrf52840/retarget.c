#include "nrf.h"
#include "SEGGER_RTT.h"

int _SEGGER_TERM = 0;

void set_logging_tag(uint32_t tag)
{
    int term = 0;
    while (tag)
    {
        if (tag & 1)
            break;
        term++;
        tag = tag >> 1;
    }
}

#if defined(__CC_ARM)
int fgetc(FILE * p_file)
{
    return '0';
}

int fputc(int ch, FILE * p_file)
{
    SEGGER_RTT_PutChar(_SEGGER_TERM, ch);
    return ch;
}

#elif defined(__GNUC__) && defined(__SES_ARM)

int __getchar(FILE * p_file)
{
    return '0';
}

int __putchar(int ch, FILE * p_file)
{
    SEGGER_RTT_PutChar(_SEGGER_TERM, ch);
    return ch;
}
#elif defined(__GNUC__) && !defined(__SES_ARM)

int _write(int file, const char * p_char, int len)
{
    int i;

    UNUSED_PARAMETER(file);

    for (i = 0; i < len; i++)
    {
        SEGGER_RTT_PutChar(_SEGGER_TERM, *p_char++);
    }

    return len;
}

int _read(int file, char * p_char, int len)
{
    *p_char = '0';
    /*UNUSED_PARAMETER(file);*/
    /*while (app_uart_get((uint8_t *)p_char) == NRF_ERROR_NOT_FOUND)*/
    /*{*/
        /*// No implementation needed.*/
    /*}*/
    return 1;
}

#else
/*#elif defined(__ICCARM__)*/
#error "No read/write for printing implemented for compiler"
#endif

