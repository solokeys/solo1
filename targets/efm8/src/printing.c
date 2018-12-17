/*
 * Copyright (C) 2018 SoloKeys, Inc. <https://solokeys.com/>
 * 
 * This file is part of Solo.
 * 
 * Solo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Solo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Solo.  If not, see <https://www.gnu.org/licenses/>
 * 
 * This code is available under licenses for commercial use.
 * Please contact SoloKeys for more information.
 */
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

void delay(uint16_t ms)
{
	uint16_t m1 = millis();
	while (millis() - m1 < ms)
		;
}
#ifdef USE_PRINTING
void putf(char c)
{
	uint8_t i;
	SBUF0 = c;
	// Blocking delay that works for 115200 baud on this device (<1ms)
	for (i=0; i<200; i++){}
	for (i=0; i<200; i++){}
	for (i=0; i<190; i++){}
}




void dump_hex(uint8_t* hex, uint8_t len)
{
	uint8_t i;
	uint8_t b;
	const char lut[] = "0123456789abcdef";
	for (i=0 ; i < len ; i++)
	{
		b = ((*hex) & 0xf0)>>4;
		putf(lut[b]);
		b = ((*hex) & 0x0f);
		putf(lut[b]);
		putf(' ');
		hex++;
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
        ++*snum;
    }while(copy);
}


static const char * __digits = "0123456789abcdef";
static char xdata __int2str_buf[9];

static void int2str_map_n(char ** snum, uint32_t i, uint8_t n)
{
	int c = 0;
    do
    {
    	if (*snum <__int2str_buf) break;
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
#endif
