# Programming

This page documents how to update or program your Solo.

## Prerequisites

To program Solo, you'll likely only need to use our Solo tool.

```python
pip3 install solo-python
```

## Updating the firmware

If you just want to update the firmware, you can run:

```bash
solo key update
```

You can manually install the [latest release](https://github.com/solokeys/solo/releases), or use a build that you made.

```bash
solo program bootloader <firmware.hex | firmware.json>
```

Note you won't be able to use `all.hex` or the `bundle-*.hex` builds, as these include the solo bootloader.  You shouldn't
risk changing the Solo bootloader unless you want to make it a secure device, or [make other customizations](/customization/).

## Updating a Hacker to a Secure Solo

Updating a hacker to be a secure build overwrites the [Solo bootloader](/bootloader-mode#solo-bootloader).
So it's important to not mess this up or you may brick your device.

You can use a firmware build from the [latest release](https://github.com/solokeys/solo/releases) or use
a build that you made yourself.

You need to use a firmware file that has the combined bootloader, application, and attestation key pair (bootloader + firmware + key).
This means using the `bundle-*.hex` file or the `bundle.hex` from your build.

#### *Warning*

* **Any DFU update erases everything! If you overwrite the Solo flash with a missing bootloader, it will be bricked.**
* **If you program bootloader and firmware with no attestation, you will run into FIDO registration issues.**

We provide two types of bundled builds.  The `bundle-hacker-*.hex` build is the hacker build.  If you update with this,
you will update the bootloader and application, but nothing will be secured.  The `bundle-secure-non-solokeys.hex`
is a secured build that will lock your device and it will behave just like a Secure Solo.  The main difference is that
it uses a "default" attestation key in the device, rather than the SoloKeys attestation key.  There is no security
concern with using our default attestation key, aside from a small privacy implication that services can distinguish it from Solo Secure.

### Procedure

1. Boot into DFU mode.

        # Enter Solo bootloader
        solo program aux enter-bootloader

        # Enter DFU
        solo program aux enter-dfu

    The device should be turned off.

2. Program the device

        solo program dfu <bundle-secure-non-solokeys.hex | bundle.hex>

    Double check you programmed it with bootloader + application (or just bootloader).
    If you messed it up, simply don't do the next step and repeat this step correctly.

3. Boot the device

    Once Solo boots a secure build, it will lock the flash permantly from debugger access.  Also the bootloader
    will only accept signed firmware updates.

        solo program aux leave-dfu

If you are having problems with solo tool and DFU mode, you could alternatively try booting into DFU
by holding down the button while Solo is in bootloader mode.  Then try another programming tool that works
with ST DFU:

* STM32CubeProg
* openocd
* stlink

Windows users need to install [libusb](https://sourceforge.net/projects/libusb-win32/files/libusb-win32-releases/1.2.6.0/)
for solo-python to work with Solo's DFU.


## Programming a Solo that hasn't been programmed

A Solo that hasn't been programmed will boot into DFU mode.  You can program
it by following a bootloader, or combined bootloader + application.

```
solo program dfu <bundle-*.hex | all.hex>
```

Then boot the device.  Make sure it has a bootloader to boot to.

```
solo program aux leave-dfu
```

## Disable signed firmware updates

If you'd like to also permanently disable signed updates, plug in your programmed Solo and run the following:

```bash
# WARNING: No more signed updates.
solo program disable-bootloader
```

You won't be able to update to any new releases.

