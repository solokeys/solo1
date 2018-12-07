To build, develop and debug the firmware for the STM32L432.  This will work
for Solo Hacker, the Nucleo development board, or you own homemade Solo.

There exists a development board [NUCLEO-L432KC](https://www.st.com/en/evaluation-tools/nucleo-l432kc.html) you can use;  The board does contain a debugger, so all you need is a USB cable (and some [udev](/udev) [rules](https://rust-embedded.github.io/book/intro/install/linux.html#udev-rules)).

# Prerequisites

Install the [latest ARM compiler toolchain](https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads) for your system.

You can also install the ARM toolchain  using a package manage like `apt-get` or `pacman`,
but be warned they might be out of date.  Typically it will be called `gcc-arm-none-eabi binutils-arm-none-eabi`.

To program your build, you'll need one of the following programs.

- [openocd](http://openocd.org)
- [stlink](https://github.com/texane/stlink)
- [STM32CubeProg](https://www.st.com/en/development-tools/stm32cubeprog.html)

# Compilation

Enter the `stm32l4xx` target directory.

```
cd targets/stm32l442
```

Build the cbor library.

```bash
make cbor
```

Now build the Solo bootloader.

```
make clean
make boot
# Or to make a Solo Hacker build:
# make boot-hacker
```

Now build the Solo application.

```
make clean
make
# Or to make a Solo Hacker build:
# make all-hacker
```

Note that for hacker builds, the bootloader must be built using the `boot-hacker` recipe.

Merge the two files together.  This script also patches a spot in memory to
allow the bootloader to boot the application.  This memory spot is later used for
signed firmware updates.

```
python merge_hex.py solo.hex bootloader.hex all.hex
```

You can now program Solo with `all.hex`.

# Solo Hacker

A Solo Hacker build is more friendly for development.  If you just want to test your
solo build or do any sort of development, you should start with this.

It is the same build as a production Solo, but it has extra commands available.

* Allows updates at any time without pressing button.
* Opens a USB emulated serial port for printing.
* Doesn't lock the flash or debugger at all.

You if build with Solo Hacker, you can always completely overwrite it and start over.
If it's not a hacker build, you cannot reprogram Solo as easily.

* `all-hacker`: can be reprogrammed again over USB or via wire with a programmer.
* `all`: can be reprogrammed using only signed updates or via wire with a programmer.
* `all-locked`: Can only be reprogrammed via signed updates unless they are disabled.

# Programming

It's recommended to test a debug/hacker build first to make sure Solo is working as expected.
Then you can switch to a locked down build, which cannot be reprogrammed as easily (or not at all!).

## ST USB DFU

If your Solo has never been programmed, it will boot the ST USB DFU.  You can program
it via USB.  After you program it, it will still be in ST USB DFU mode.  You additionally
need to supply a command to tell the DFU program to "detach" and boot the application.

If you power cycle Solo, it will return to DFU mode so you can reprogram it.  If you don't
want it to do this, you must set the option bytes bit `nBOOT0=1`.  Now it will always boot the application.

Example using STM32CubeProg.

```
# Program all.hex
STM32_Programmer_CLI -c port=usb1 -halt -d all.hex

# If you want it to always boot application, set nBOOT0=1
STM32_Programmer_CLI -c port=usb1 -ob nBOOT0=1
```

If Solo has been programmed with a hacker build, you can return it to ST DFU mode using just USB.

```
# Use our programmer script

# Makes it boot to ST DFU once
python tools/programmer.py --st-dfu

# OR
# Make it boot to ST DFU every boot (initial state basically)
python tools/programmer.py --enter-bootloader
python tools/programmer.py --st-dfu
```

## Solo / Solo Hacker updates

To program a Solo Hacker device, run the following.  Note you should only specify the application
firmware, not the combined bootloader+application!  I.e. not `all.hex` from above.

```bash
python tools/programmer.py target/stm32l442/solo.hex
```

A Solo hacker device doesn't need to be in bootloader mode to be programmed, it will automatically switch.
If the application gets bricked, you can hold down the button for 2 seconds while
plugging it in the token make it stay in the bootloader.  Holding the button an additional 5 seconds
will return it to the ST DFU.

If this is not a device with a hacker build, you can only program signed updates.

```
python tools/programmer.py /path/to/firmware.json
```

If you've provisioned the Solo bootloader with your own secp256r1 public key, you can sign your
firmware by running the following command.

```
python tools/sign_firmware.py /path/to/signing-key.pem /path/to/solo.hex /output-path/to/firmware.json
```

If your Solo isn't locked, you can always reprogram it using a debugger connected directly
to the token.

# Permanently locking the device

If you plan to be using your Solo for real, you should lock it permanently.  This prevents
someone from connecting a debugger to your token and stealing credentials.

To do this, build the non-hacker bootloader and locked version of the firmware.
```
make clean
make boot
make clean
make all-locked
python merge_hex.py solo.hex bootloader.hex all.hex
```

Now when you program `all.hex`, the device will lock itself when it first boots.  You can only update it
with signed updates.

If you'd like to also permanently disable signed updates, plug in your programmed Solo and run the following:

```
# No more signed updates.
python tools/programmer.py --disable
```
