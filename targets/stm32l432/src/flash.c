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
    unsigned int i;
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
