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

Now build the Solo application.

```
make firmware
```

The `firmware` recipe builds the solo application, and outputs `solo.hex`.  You can use this
to reprogram any unlocked/hacker Solo model.  Note that it does not include the Solo bootloader,
so it is not a full reprogram.

<!-- First it builds the bootloader, with
signature checking disabled.  Then it builds the Solo application with "hacker" features
enabled, like being able to jump to the bootloader on command.  It then merges bootloader
and solo builds into the same binary.  I.e. it combines `bootloader.hex` and `solo.hex`
into `all.hex`. -->

If you're just planning to do development, **please don't try to reprogram the bootloader**,
as this can be risky if done often.  Just use `solo.hex`.

### Building with debug messages

If you're developing, you probably want to see debug messages!  Solo has a USB
Serial port that it will send debug messages through (from `printf`).  You can read them using
a normal serial terminal like `picocom` or `putty`.

Just add `-debug-1` or `-debug-2` to your build recipe, like this.

```
make firmware-debug-1
```

If you use `debug-2`, that means Solo will not boot until something starts reading
its debug messages.  So it basically waits to tether to a serial terminal so that you don't
miss any debug messages.

We recommend using our `solo` tool as a serial emulator since it will automatically
reconnect each time you program Solo.

```
solo monitor <serial-port>
```

#### Linux Users:

[See issue 62](https://github.com/solokeys/solo/issues/62).

### Building a complete Solo build (application + bootloader + certificate)

To make a complete Solo build, you need to build the bootloader.  We provide
two easy recipes:

* `bootloader-nonverifying`: bootloader with no signature checking on updates.  I.e. "unlocked".
* `bootloader-verifying`: bootloader with signature checking enforced on updated.  I.e. "Locked".

To be safe, let's use the `-nonverifying` build.

```
make bootloader-nonverifying
```

This outputs `bootloader.hex`.  We can then merge the bootloader and application.

```
solo mergehex bootloader.hex solo.hex bundle.hex
```

`bundle.hex` is our complete firmware build.  Note it is in this step that you can
include a custom attestation certificate or lock the device from debugging/DFU.
By default the "hacker" attestation certifcate and key is used.  Use the `--lock` flag
to make this permanent.

```
solo mergehex  \
    --attestation-key "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" \
    --attestation-cert attestation.der \
    solo.hex \
    bootloader.hex \
    bundle.hex
```

**Warning**: If you use `--lock`, this will permanently lock the device to this new bootloader.  You
won't be able to program the bootloader again or be able to connect a hardware debugger.
The new bootloader may be able to accept (signed) updates still, depending on how you configured it.

```
# Permanent!
solo mergehex  \
    --attestation-key "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" \
    --attestation-cert attestation.der \
    --lock \
    solo.hex \
    bootloader.hex \
    bundle.hex
```

See [here for more information on custom attestation](/customization/).

To learn more about normal updates or a "full" update, you should [read more on Solo's boot stages](/bootloader-mode).

