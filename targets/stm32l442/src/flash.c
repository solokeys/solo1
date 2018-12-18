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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "stm32l4xx.h"

#include APP_CONFIG
#include "flash.h"
#include "log.h"
#include "device.h"

static void flash_unlock()
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
#ifndef FLASH_ROP
#define FLASH_ROP 0
#endif
#if FLASH_ROP == 0
    uint32_t val = 0xfffff8aa;
#elif FLASH_ROP == 2
    uint32_t val = 0xfffff8cc;
#else
    uint32_t val = 0xfffff8b9;
#endif

    if (boot_from_dfu)
    {
        val &= ~(1<<27); // nBOOT0 = 0  (boot from system rom)
    }
    val &= ~(1<<26); // nSWBOOT0 = 0  (boot from nBoot0)
    val &= ~(1<<25); // SRAM2_RST = 1 (erase sram on reset)
    val &= ~(1<<24); // SRAM2_PE = 1 (parity check en)

    if (FLASH->OPTR == val)
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

    flash_lock();

    __enable_irq();
}

void flash_erase_page(uint8_t page)
{
    __disable_irq();

    // Wait if flash is busy
    while (FLASH->SR & (1<<16))
        ;
    flash_unlock();

    FLASH->SR = FLASH->SR;

    // enable flash erase and select page
    FLASH->CR &= ~((0xff<<3) | 7);
    FLASH->CR |= (page<<3) | (1<<1);

    // Go!
    FLASH->CR |= (1<<16);
    while (FLASH->SR & (1<<16))
        ;

    if(FLASH->SR & (1<<1))
    {
        printf2(TAG_ERR,"erase NOT successful %lx\r\n", FLASH->SR);
    }

    FLASH->CR &= ~(0x7);
    __enable_irq();
}

void flash_write_dword(uint32_t addr, uint64_t data)
{
    __disable_irq();
    while (FLASH->SR & (1<<16))
        ;
    FLASH->SR = FLASH->SR;

    // Select program action
    FLASH->CR |= (1<<0);

    *(volatile uint32_t*)addr = data;
    *(volatile uint32_t*)(addr+4) = data>>32;

    while (FLASH->SR & (1<<16))
        ;

    if(FLASH->SR & (1<<1))
    {
        printf2(TAG_ERR,"program NOT successful %lx\r\n", FLASH->SR);
    }

    FLASH->SR = (1<<0);
    FLASH->CR &= ~(1<<0);
    __enable_irq();
}

void flash_write(uint32_t addr, uint8_t * data, size_t sz)
{
    int i;
    uint8_t buf[8];
    while (FLASH->SR & (1<<16))
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

void flash_lock()
{
    FLASH->CR |= (1U<<31);
}
