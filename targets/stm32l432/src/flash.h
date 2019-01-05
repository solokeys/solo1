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
#ifndef _FLASH_H_
#define _FLASH_H_

void flash_erase_page(uint8_t page);
void flash_write_dword(uint32_t addr, uint64_t data);
void flash_write(uint32_t addr, uint8_t * data, size_t sz);
void flash_write_fast(uint32_t addr, uint32_t * data);
void flash_option_bytes_init(int boot_from_dfu);

#define FLASH_PAGE_SIZE     2048

#define flash_addr(page)    (0x08000000 + ((page)*FLASH_PAGE_SIZE))

#define FLASH_PAGE_START    0
#define FLASH_PAGE_END      127

#endif
