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
#include <SI_EFM8UB1_Register_Enums.h>
#include <stdint.h>

#include "eeprom.h"
#include "printing.h"

char __erase_mem[3];

static void erase_ram()
{
	data uint16_t i;
	data uint8_t xdata * clear = 0;
	for (i=0; i<0x400;i++)
	{
		*(clear++) = 0x0;
	}
}


void eeprom_init()
{
	uint8_t secbyte;
	eeprom_read(0xFBFF,&secbyte,1);
	if (secbyte == 0xff)
	{
		eeprom_erase(0xFBC0);
		secbyte = -32;
		eeprom_write(0xFBFF, &secbyte, 1);
		erase_ram();
		// Reboot
		cprints("rebooting\r\n");
		RSTSRC = (1<<4);
	}
	else
	{
//		cprints("no reboot\r\n");
	}
}

void eeprom_read(uint16_t addr, uint8_t * buf, uint8_t len)
{
	uint8_t code * eepaddr =  (uint8_t code *) addr;
	bit old_int;

	while(len--)
	{
		old_int = IE_EA;
		IE_EA = 0;
		*buf++ = *eepaddr++;
		IE_EA = old_int;
	}
}

void _eeprom_write(uint16_t addr, uint8_t * buf, uint8_t len, uint8_t flags)
{
	uint8_t xdata * data eepaddr = (uint8_t xdata *) addr;
	bit old_int;

	while(len--)
	{
		old_int = IE_EA;
		IE_EA = 0;
		// Enable VDD monitor
		VDM0CN = 0x80;
		RSTSRC = 0x02;

		// unlock key
		FLKEY  = 0xA5;
		FLKEY  = 0xF1;
		PSCTL |= flags;

		*eepaddr = *buf;
		PSCTL &= ~flags;
		IE_EA = old_int;

		eepaddr++;
		buf++;
	}
}
