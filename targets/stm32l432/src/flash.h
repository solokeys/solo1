// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
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
