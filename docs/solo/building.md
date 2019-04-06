To build, develop and debug the firmware for the STM32L432.  This will work
for Solo Hacker, the Nucleo development board, or your own homemade Solo.

There exists a development board [NUCLEO-L432KC](https://www.st.com/en/evaluation-tools/nucleo-l432kc.html) you can use;  The board does contain a debugger, so all you need is a USB cable (and some [udev](/udev) [rules](https://rust-embedded.github.io/book/intro/install/linux.html#udev-rules)).

# Prerequisites

Install the [latest ARM compiler toolchain](https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads) for your system.  We recommend getting the latest compilers from ARM.

You can also install the ARM toolchain  using a package manager like `apt-get` or `pacman`,
but be warned they might be out of date.  Typically it will be called `gcc-arm-none-eabi binutils-arm-none-eabi`.

To program your build, you'll need one of the following programs.

- [openocd](http://openocd.org)
- [stlink](https://github.com/texane/stlink)
- [STM32CubeProg](https://www.st.com/en/development-tools/stm32cubeprog.html)

# Compilation

Enter the `stm32l4xx` target directory.

```
cd targets/stm32l432
```

Now build Solo.

```
make build-hacker
```

The `build-hacker` recipe does a few things.  First it builds the bootloader, with
signature checking disabled.  Then it builds the Solo application with "hacker" features
enabled, like being able to jump to the bootloader on command.  It then merges bootloader
and solo builds into the same binary.  I.e. it combines `bootloader.hex` and `solo.hex`
into `all.hex`.

If you're just planning to do development, please don't try to reprogram the bootloader,
as this can be risky if done often.  Just use `solo.hex`.

### Building with debug messages

If you're developing, you probably want to see debug messages!  Solo has a USB
Serial port that it will send debug messages through (from `printf`).  You can read them using
a normal serial terminal like `picocom` or `putty`.

Just add `DEBUG=1` or `DEBUG=2` to your build recipe, like this.

```
make build-hacker DEBUG=1
```

If you use `DEBUG=2`, that means Solo will not boot until something starts reading
its debug messages.  So it basically waits to tether to a serial terminal so that you don't
miss any debug messages.

We recommend using our `solo` tool as a serial emulator since it will automatically
reconnect each time you program Solo.

```
solo monitor <serial-port>
```

#### Linux Users:

[See issue 62](https://github.com/solokeys/solo/issues/62).

### Building a Solo release

If you want to build a release of Solo, we recommend trying a Hacker build first
just to make sure that it's working.  Otherwise it may not be as easy or possible to
fix any mistakes.

If you're ready to program a full release, run this recipe to build.

```
make build-release-locked
```

Programming `all.hex` will cause the device to permanently lock itself.


# Programming

It's recommended to test a debug/hacker build first to make sure Solo is working as expected.
Then you can switch to a locked down build, which cannot be reprogrammed as easily (or not at all!).

We recommend using our `solo` tool to manage programming.  It is cross platform.  First you must
install the prerequisites:

```
pip3 install -r tools/requirements.txt
```

If you're on Windows, you must also install [libusb](https://sourceforge.net/projects/libusb-win32/files/libusb-win32-releases/1.2.6.0/).

## Pre-programmed Solo Hacker

If your Solo device is already programmed (it flashes green when powered), we recommend
programming it using the Solo bootloader.

```
solo program aux enter-bootloader
solo program bootloader solo.hex
```

Make sure to program `solo.hex` and not `all.hex`.  Nothing bad would happen, but you'd
see errors.

If something bad happens, you can always boot the Solo bootloader by doing the following.

1. Unplug device.
2. Hold down button.
3. Plug in device while holding down button.
4. Wait about 2 seconds for flashing yellow light.  Release button.

If you hold the button for an additional 5 seconds, it will boot to the ST DFU (device firmware update).
Don't use the ST DFU unless you know what you're doing.

## ST USB DFU

If your Solo has never been programmed, it will boot the ST USB DFU.  The LED is turned
off and it enumerates as "STM BOOTLOADER".

You can program it by running the following.

```
solo program aux enter-bootloader
solo program aux enter-dfu
# powercycle key
solo program dfu all.hex
```

Make sure to program `all.hex`, as this contains both the bootloader and the Solo application.

If all goes well, you should see a slow-flashing green light.

##  Solo Hacker vs Solo

A Solo hacker device doesn't need to be in bootloader mode to be programmed, it will automatically switch.

Solo (locked) needs the button to be held down when plugged in to boot to the bootloader.

A locked Solo will only accept signed updates.

## Signed updates

If this is not a device with a hacker build, you can only program signed updates.

```
solo program bootloader /path/to/firmware.json
```

If you've provisioned the Solo bootloader with your own secp256r1 public key, you can sign your
firmware by running the following command.

```
solo sign /path/to/signing-key.pem /path/to/solo.hex /output-path/to/firmware.json
```

If your Solo isn't locked, you can always reprogram it using a debugger connected directly
to the token.

# Permanently locking the device

If you plan to be using your Solo for real, you should lock it permanently.  This prevents
someone from connecting a debugger to your token and stealing credentials.

To do this, build the locked release firmware.
```
make build-release-locked
```

Now when you program `all.hex`, the device will lock itself when it first boots.  You can only update it
with signed updates.

If you'd like to also permanently disable signed updates, plug in your programmed Solo and run the following:

```
# WARNING: No more signed updates.
solo program disable-bootloader
```
