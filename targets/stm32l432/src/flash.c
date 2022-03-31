// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "stm32l4xx.h"

#include APP_CONFIG
#include "flash.h"
#include "log.h"
#include "util.h"
#include "device.h"

static void flash_lock(void)
{
    FLASH->CR |= (1U<<31);
}

static void flash_unlock(void)
{
    if (FLASH->CR & FLASH_CR_LOCK)
    {
        FLASH->KEYR = 0x45670123;
        FLASH->KEYR = 0xCDEF89AB;
    }
}

// Locks flash and turns off DFU
void flash_option_bytes_init(int boot_from_dfu)
{
    uint32_t val = 0xfffff8aa;

    if (boot_from_dfu){
        val &= ~(1<<27); // nBOOT0 = 0  (boot from system rom)
    }
    else {
        if (solo_is_locked())
        {
            val = 0xfffff8cc;
        }
    }

    val &= ~(1<<26); // nSWBOOT0 = 0  (boot from nBoot0)
    val &= ~(1<<25); // SRAM2_RST = 1 (erase sram on reset)
    val &= ~(1<<24); // SRAM2_PE = 1 (parity check en)

    if ((FLASH->OPTR & 0xb3f77ff) == (val & 0xb3f77ff))
    {
        return;
    }

    __disable_irq();
    while (FLASH->SR & (1<<16))
        ;
    flash_unlock();
    if (FLASH->CR & (1<<30))
    {
        FLASH->OPTKEYR = 0x08192A3B;
        FLASH->OPTKEYR = 0x4C5D6E7F;
    }

    FLASH->OPTR =val;
    FLASH->CR |= (1<<17);

    while (FLASH->SR & (1<<16))
        ;

    if (FLASH->CR & (1<<30))
    {
        FLASH->OPTKEYR = 0x08192A3B;
        FLASH->OPTKEYR = 0x4C5D6E7F;
    }

    /* Perform option byte loading which triggers a device reset. */
    FLASH->CR |= FLASH_CR_OBL_LAUNCH;

    while (true)
        ;
}

void flash_erase_page(uint8_t page)
{
    __disable_irq();

    // Wait if flash is busy
    while (FLASH->SR & FLASH_SR_BSY)
        ;
    flash_unlock();

    FLASH->SR = FLASH->SR;

    // enable flash erase and select page
    FLASH->CR &= ~((0xff<<3) | 7);
    FLASH->CR |= (page<<3) | (1<<1);

    // Go!
    FLASH->CR |= FLASH_CR_STRT;
    while (FLASH->SR & FLASH_SR_BSY)
        ;

    if(FLASH->SR & FLASH_SR_OPERR)
    {
        printf2(TAG_ERR,"erase NOT successful %lx\r\n", FLASH->SR);
    }

    FLASH->CR &= ~(0x7);
    __enable_irq();
}

void flash_write_dword(uint32_t addr, uint64_t data)
{
    // check if we try to write the same data
    if (data == *((uint64_t *)addr)) 
        return;
    
    __disable_irq();
    while (FLASH->SR & FLASH_SR_BSY)
        ;
    FLASH->SR = FLASH->SR;

    // Select program action
    FLASH->CR |= FLASH_CR_PG;

    *(volatile uint32_t*)addr = data;
    *(volatile uint32_t*)(addr+4) = data>>32;

    while (FLASH->SR & FLASH_SR_BSY)
        ;

    if(FLASH->SR & FLASH_SR_OPERR)
    {
        printf2(TAG_ERR,"program NOT successful %lx\r\n", FLASH->SR);
    }

    FLASH->SR = (1<<0);
    FLASH->CR &= ~(1<<0);
    __enable_irq();
}

void flash_write(uint32_t addr, uint8_t * data, size_t sz)
{
    unsigned int i;
    uint8_t buf[8];
    while (FLASH->SR & FLASH_SR_BSY)
        ;
    flash_unlock();

    // dword align
    addr &= ~(0x07);

    for(i = 0; i < sz; i+=8)
    {
        memmove(buf, data + i, (sz - i) > 8 ? 8 : sz - i);
        if (sz - i < 8)
        {
            memset(buf + sz - i, 0xff, 8 - (sz - i));
        }
        flash_write_dword(addr, *(uint64_t*)buf);
        addr += 8;
    }

}

uint64_t get_data_block(uint8_t blockn, uint8_t delta, uint8_t *data, size_t sz) {
    uint8_t buf[8];
    if ((sz == 0) || (data == NULL) || (blockn > (sz + delta) / 8))
        return 0;

    if (blockn == 0) {
        memset(buf, 0xff, sizeof(buf));
        size_t tsize = MIN(sz, ABS(8U - delta)); 
        memcpy(&buf[delta], data, tsize);
        return *(uint64_t*)buf;
    }

    if (blockn == (sz + delta) / 8) {
        if ((sz + delta) % 8 == 0)
            return 0;
        memset(buf, 0xff, sizeof(buf));
        size_t tsize = (sz + delta) % 8; 
        memcpy(buf, &data[blockn * 8 - delta], tsize);
        return *(uint64_t*)buf;
    }
    
    memcpy(buf, &data[blockn * 8 - delta], 8);
    return *(uint64_t*)buf;
}

void flash_write_ex(uint32_t addr, uint8_t * data, size_t sz) 
{
    uint8_t delta = addr & 0x07;
    uint32_t addr_bg = addr & ~(0x07);
    uint32_t addr_en = ((addr + sz - 1) & ~(0x07)) + 0x07;
    size_t blocks_cnt = (sz + delta + 7) / 8;
    
    bool needs_erase = false;
    
    uint32_t blockn = 0;
    for (uint32_t block_address = addr_bg; block_address < addr_en; block_address += 8){
        uint64_t d_flash = *(uint64_t *)block_address;
        uint64_t d_ram = get_data_block(blockn, delta, data, sz);
        blockn++;

        if (d_flash == d_ram)
            continue;
        
        if (d_flash == 0xffffffffffffffffULL)
            continue;
        
        needs_erase = true;
        break;
    }
    
    if (!needs_erase) {
        while (FLASH->SR & (1<<16))
            ;
        flash_unlock();
        
        for(uint32_t i = 0; i < blocks_cnt; i++)
            flash_write_dword(addr_bg + i * 8, get_data_block(i, delta, data, sz));        
    } else {
        uint8_t eeprom_data[2048];
        memset(eeprom_data, 0xff, sizeof(eeprom_data));
        uint8_t page = flash_page(addr_bg);
        uint32_t p_addr = flash_addr(page);

        memcpy(eeprom_data, (uint8_t *)p_addr, 2048);
        memcpy(&eeprom_data[addr - p_addr], data, sz);

        flash_erase_page(page);
         
        // if we switch off power here - flash will corrupt....
        flash_write(p_addr, eeprom_data, 2048);       
    }
}

// NOT YET working
void flash_write_fast(uint32_t addr, uint32_t * data)
{
    __disable_irq();
    while (FLASH->SR & (1<<16))
        ;
    FLASH->SR = FLASH->SR;

    // Select fast program action
    FLASH->CR |= (1<<18);

    int i;
    for(i = 0; i < 64; i++)
    {
        *(volatile uint32_t*)addr = (*data);
        addr+=4;
        data++;
    }

    while (FLASH->SR & (1<<16))
        ;

    if(FLASH->SR & (1<<1))
    {
        printf2(TAG_ERR,"program NOT successful %lx\r\n", FLASH->SR);
    }

    FLASH->SR = (1<<0);
    FLASH->CR &= ~(1<<18);
    __enable_irq();

}
