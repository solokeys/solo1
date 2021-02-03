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
len  |   20 KB/10p|      196KB-8-8/98p   |        2kB/1p         |      38 KB/19p  |
pos  |   0->20 KB |     20->216KB-8-8    |   216kB -> 218 kB     |   218->256 KB   |
posp |    0-10    |      10-113          |        113-114        |       113-128   |
desc | bootloader |       application    | bootloader data       |  secrets/data   |

    Last 8 bytes in application space are occupied by bootloader flags - app
    authorization and bootloader activation flag.
 */

/* Current firmware version number is concatenated to the firmware code - see .flag marker */
/* flash length is (APPLICATION_END_PAGE-20*1024), where 20K is bootloader */

MEMORY
{
    flash (rx)      : ORIGIN = 0x08000000 + 20K, LENGTH = 216K - 20K - 8
    ram (xrw)       : ORIGIN = 0x20000000, LENGTH = 48K
    sram2 (rw)      : ORIGIN = 0x10000000, LENGTH = 16K
}

SECTIONS
{

    /DISCARD/ :
    {
        /* Unused exception info */
        *(.ARM.exidx);
        *(.ARM.exidx.*);
        *(.ARM.extab.*);
    }

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

    _sidata = LOADADDR(.data);

    .data :
    {
        . = ALIGN(8);
        _sdata = .;
        *(.data*)
        . = ALIGN(8);
        _edata = .;
    } >sram2 AT> flash

    .flag :
    {
        . = ALIGN(8);
      KEEP(*(.flag)) ;
    } > flash

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
