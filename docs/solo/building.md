# Building solo

To build, develop and debug the firmware for the STM32L432.  This will work
for Solo Hacker, the Nucleo development board, or your own homemade Solo.

There exists a development board [NUCLEO-L432KC](https://www.st.com/en/evaluation-tools/nucleo-l432kc.html) you can use;  The board does contain a debugger, so all you need is a USB cable (and some [udev](/udev) [rules](https://rust-embedded.github.io/book/intro/install/linux.html#udev-rules)).

## Prerequisites

Install the [latest ARM compiler toolchain](https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads) for your system.  We recommend getting the latest compilers from ARM.

You can also install the ARM toolchain  using a package manager like `apt-get` or `pacman`,
but be warned they might be out of date.  Typically it will be called `gcc-arm-none-eabi binutils-arm-none-eabi`.

Install `solo-python` usually with `pip3 install solo-python`. The `solo` python application may also be used for [programming](#programming).

## Obtain source code and solo tool

Source code can be downloaded from:

-   [github releases list](https://github.com/solokeys/solo/releases)
-   [github repository](https://github.com/solokeys/solo)

**solo** tool can be downloaded from:

-   from python programs [repository](https://pypi.org/project/solo-python/) `pip install solo-python`
-   from installing prerequisites `pip3 install -r tools/requirements.txt`
-   github repository: [repository](https://github.com/solokeys/solo-python)
-   installation python enviroment with command `make venv` from root directory of source code

## Compilation

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

If you're just planning to do development, **please don't try to reprogram the bootloader**,
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

To build Solo

If you want to build a release of Solo, we recommend trying a Hacker build first
just to make sure that it's working.  Otherwise it may not be as easy or possible to
fix any mistakes.

If you're ready to program a full release, run this recipe to build.

```
make build-release-locked
```

This outputs bootloader.hex, solo.hex, and the combined all.hex.

Programming `all.hex` will cause the device to permanently lock itself.  This means debuggers cannot be used and signature checking
will be enforced on all future updates.

Note if you program a secured `solo.hex` file onto a Solo Hacker, it will lock the flash, but the bootloader
will still accept unsigned firmware updates.  So you can switch it back to being a hacker, but you will
not be able to replace the unlocked bootloader anymore, since the permanently locked flash also disables the DFU.
[Read more on Solo's boot stages](/solo/bootloader-mode).

