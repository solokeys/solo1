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
#ifndef _MEMORY_LAYOUT_H_
#define _MEMORY_LAYOUT_H_

#define PAGE_SIZE		2048
#define PAGES			128

// Pages 119-127 are data
// Location of counter page and it's backup page
// The flash is wear leveled and counter should be fault tolerant
#define	COUNTER2_PAGE	(PAGES - 4)
#define	COUNTER1_PAGE	(PAGES - 3)

// State of FIDO2 application
#define	STATE2_PAGE		(PAGES - 2)
#define	STATE1_PAGE		(PAGES - 1)

// Storage of FIDO2 resident keys
#define RK_NUM_PAGES    10
#define RK_START_PAGE   (PAGES - 14)
#define RK_END_PAGE     (PAGES - 14 + RK_NUM_PAGES)     // not included

// Start of application code
#ifndef APPLICATION_START_PAGE
#define APPLICATION_START_PAGE	(10)
#endif
#define APPLICATION_START_ADDR	(0x08000000 + ((APPLICATION_START_PAGE)*PAGE_SIZE))

// where attestation key is located
#define ATTESTATION_KEY_PAGE    (PAGES - 15)
#define ATTESTATION_KEY_ADDR    (0x08000000 + ATTESTATION_KEY_PAGE*PAGE_SIZE)

// End of application code.  Leave some extra room for future data storage.
// NOT included in application
#define APPLICATION_END_PAGE	((PAGES - 19))
#define APPLICATION_END_ADDR	((0x08000000 + ((APPLICATION_END_PAGE)*PAGE_SIZE))-8)

// Bootloader state.
#define AUTH_WORD_ADDR          (APPLICATION_END_ADDR)

#endif
