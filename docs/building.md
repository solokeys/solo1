To build, develop and debug the firmware for the STM32L442 (WIP!) via cross-compilation on Linux, no vendor-specific software is necessary.

There exists a development board [NUCLEO-L432KC](https://www.st.com/en/evaluation-tools/nucleo-l432kc.html) you can use; the L432 chip differs from the L442 used for Solo only in that it lacks a cryptographic accelerator. The board does contain a debugger, so all you need is a USB cable :)

You will need the following packages (naming given for Arch Linux):

- arm-none-eabi-gcc
- arm-none-eabi-newlib
- arm-none-eabi-binutils

and one of

- [openocd](http://openocd.org)
- [stlink](https://github.com/texane/stlink)

If you remove the `.exe` extensions in the [Makefile](https://github.com/SoloKeysSec/solo/blob/master/targets/stm32l442/Makefile), and possibly add a `-g` flag, compilation runs through.

To flash and step through the code:

* connect the Nucleo to your PC
* attach one of the debuggers: `st-util` (for stlink), or `openocd -f interface/stlink-v2-1.cfg -f target/stm32l4x.cfg` (for openocd)
* launch `gdb` via `arm-none-eabi-gdb -q solo.elf`
* connect gdb to the debugger via `target extended-remote :4242` (for stlink), or `target remote :3333` (for openocd)
* flash the firmware via `load`
* optionally set a breakpoint via `break main`
* `continue`, and start stepping 🙌

Note that the code for `targets/stm32l442` currently consists of only a blinky hello world...
