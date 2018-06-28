/*
 * printing.c
 *
 *  Created on: Jun 25, 2018
 *      Author: conor
 */

#include <SI_EFM8UB1_Register_Enums.h>
#include <efm8_usb.h>
#include <stdarg.h>
#include <stdio.h>
#include "printing.h"

void putf(char c)
{
	uint8_t i;
	SBUF0 = c;
	// Blocking delay that works for 115200 baud on this device (<1ms)
	for (i=0; i<200; i++){}
	for (i=0; i<200; i++){}
	for (i=0; i<190; i++){}
	watchdog();
}


void dump_hex(uint8_t* hex, uint8_t len)
{
	uint8_t i;
	for (i=0 ; i < len ; i++)
	{
		if (hex[i]<0x10)
		{
			putf('0');
		}
		cputb(hex[i]);
	}
	cprints("\r\n");
}


void cprints(char* d)
{
	while(*d)
	{
		// UART0 output queue
		putf(*d++);
	}
}

static void int2str_reduce_n(char ** snum, uint32_t copy, uint8_t n)
{
    do
    {
        copy /= n;
    }while(copy);
}


static const char * __digits = "0123456789abcdef";
static char xdata __int2str_buf[9];

static void int2str_map_n(char ** snum, uint32_t i, uint8_t n)
{
    do
    {
        *--*snum = __digits[i % n];
        i /= n;
    }while(i);
}

#define dint2str(i)     __int2strn(i,10)
#define xint2str(i)     __int2strn(i,16)

char * __int2strn(int32_t i, uint8_t n)
{
    char * snum = __int2str_buf;
    if (i<0) *snum++ = '-';
    int2str_reduce_n(&snum, i, n);
    *snum = '\0';
    int2str_map_n(&snum, i, n);
    return snum;
}

void cputd(int32_t i)
{
	cprints(dint2str((int32_t)i));
}

void cputx(int32_t i)
{
	cprints(xint2str(i));
}

static void put_space()
{
	cprints(" ");
}
static void put_line()
{
	cprints("\r\n");
}

void cprintd(const char * tag, uint8_t c, ...)
{
	va_list args;
	cprints(tag);
    va_start(args,c);
    while(c--)
    {
        cputd((int32_t)va_arg(args, int16_t));

    }
    put_line();
    va_end(args);
}

void cprintl(const char * tag, uint8_t c, ...)
{
    va_list args;
    cprints(tag);
    va_start(args,c);
    while(c--)
    {
        cputl(va_arg(args, int32_t));
        cprints(" ");
    }
    put_line();
    va_end(args);
}

void cprintx(const char * tag, uint8_t c, ...)
{
    va_list args;
    cprints(tag);
    va_start(args,c);
    while(c--)
    {
        cputx((int32_t)va_arg(args, uint16_t));
        cprints(" ");
    }
    put_line();
    va_end(args);
}

void cprintb(const char * tag, uint8_t c, ...)
{
	va_list args;
    cprints(tag);
    va_start(args,c);
    while(c--)
    {
        cputb(va_arg(args, uint8_t));
        put_space();
    }
    put_line();
    va_end(args);
}

void cprintlx(const char * tag, uint8_t c, ...)
{
    va_list args;
    cprints(tag);
    va_start(args,c);
    while(c--)
    {
        cputlx(va_arg(args, int32_t));
        put_space();
    }
    put_line();
    va_end(args);
}
