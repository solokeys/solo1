#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "stm32l4xx.h"

#include "app.h"
#include "flash.h"

static void flash_unlock()
{
    if (FLASH->CR & FLASH_CR_LOCK)
    {
        FLASH->KEYR = 0x45670123;
        FLASH->KEYR = 0xCDEF89AB;
    }
}
void flash_erase_page(uint8_t page)
{
    __disable_irq();
    // Wait if flash is busy
    while (FLASH->SR & (1<<16))
        ;
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
        printf("erase NOT successful %lx\r\n", FLASH->SR);
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
        printf("program NOT successful %lx\r\n", FLASH->SR);
    }

    FLASH->SR = (1<<0);
    FLASH->CR &= ~(1<<0);
    __enable_irq();
}

void flash_write(uint32_t addr, uint8_t * data, size_t sz)
{
    int i;
    uint8_t buf[8];

    // dword align
    addr &= ~(0x7);

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

void flash_lock()
{
    FLASH->CR |= (1U<<31);
}
