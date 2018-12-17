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
#ifndef PRINTING_H_
#define PRINTING_H_

#include <SI_EFM8UB1_Register_Enums.h>
#include <efm8_usb.h>
#include <stdint.h>
#include "app.h"

#define watchdog()	(WDTCN = 0xA5)

#define reboot()	(RSTSRC = 1 << 4)

#define millis() ((uint16_t)(TMR3L | (TMR3H << 8)))

void u2f_delay(uint32_t ms);

void usb_write();



#ifdef USE_PRINTING

	void dump_hex(uint8_t* hex, uint8_t len);

	void cputd(uint32_t i);
	void cputx(uint32_t i);

#define cputb(x)	cputx((uint8_t) (x))
#define cputl(x)	cputd((uint32_t) (x))
#define cputlx(x)	cputx((uint32_t) (x))

	void cprints(const char * str);
	void cprintb(const char * tag, uint8_t c, ...);
	void cprintd(const char * tag, uint8_t c, ...);
	void cprintx(const char * tag, uint8_t c, ...);
	void cprintl(const char * tag, uint8_t c, ...);
	void cprintlx(const char * tag, uint8_t c, ...);

#else

	#define cprintx(x)
	#define cprintb(x)
	#define cprintlx(x)
	#define cprintl(x)
	#define cprintd(x)
	#define cprints(x)

	#define cputx(x)
	#define cputb(x)
	#define cputl(x)
	#define cputlx(x)

	#define putf(x)
	#define dump_hex(x)

#endif




#endif /* BSP_H_ */
