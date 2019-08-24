/* Copyright 2019 SoloKeys Developers */
/* */
/* Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or */
/* http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or */
/* http://opensource.org/licenses/MIT>, at your option. This file may not be */
/* copied, modified, or distributed except according to those terms. */

ENTRY(Reset_Handler)

/* End of RAM */
_estack = 0x2000c000;

_MIN_STACK_SIZE = 0x400;

/*
flash_cfg is for storing bootloader data, like last used firmware version.
bootloader_configuration should be equal to (APPLICATION_END_PAGE) page address, from targets/stm32l432/src/memory_layout.h:30; and equal to flash_cfg origin
*/

bootloader_configuration = 0x08000000 + 216*1024+8;

MEMORY
{
    flash (rx)      : ORIGIN = 0x08000000, LENGTH = 20K
    flash_cfg (rx)  : ORIGIN = 0x08000000 + 216*1024+8, LENGTH = 2K-8
    ram (xrw)       : ORIGIN = 0x20000000, LENGTH = 48K
    sram2 (rw)      : ORIGIN = 0x10000000, LENGTH = 16K
}

SECTIONS
{
    .isr_vector :
    {
        . = ALIGN(8);
        KEEP(*(.isr_vector))
        . = ALIGN(8);
    } >flash

    .text :
    {
        . = ALIGN(8);
        *(.text*)
        *(.rodata*)
        KEEP(*(.init))
        KEEP(*(.finit))
        . = ALIGN(8);
        _etext = .;
    } >flash

    .flag2 bootloader_configuration :
    {
      KEEP(*(.flag2)) ;
    } > flash_cfg

    _sidata = LOADADDR(.data);

    .data :
    {
        . = ALIGN(8);
        _sdata = .;
        *(.data*)
        . = ALIGN(8);
        _edata = .;
    } >ram AT> flash

    .bss :
    {
        . = ALIGN(4);
        _sbss = .;
        __bss_start__ = _sbss;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
        __bss_end__ = _ebss;
    } > ram

    ._stack :
    {
        . = ALIGN(8);
        end = .;
        _end = .;
        . = . + _MIN_STACK_SIZE;
        . = ALIGN(8);
    } > ram

}
