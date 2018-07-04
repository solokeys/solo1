/*
 * Copyright (c) 2016, Conor Patrick
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
