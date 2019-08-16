# Booting into bootloader mode

You can put Solo into bootloader mode by holding down the button, and plugging in Solo.  After 2 seconds, bootloader mode will activate.
You'll see a yellowish flashing light and you can let go of the button.

Now Solo is ready to [accept firmware updates](/solo/signed-updates).  If the Solo is a secured model, it can only accept signed updates, typically in the `firmware-*.json` format.

If Solo is running a hacker build, it can be put into bootloader mode on command.  This makes it easier for development.

```bash
solo program aux enter-bootloader
```

# The boot stages of Solo

Solo has 3 boot stages.

## DFU

The first stage is the DFU (Device Firmware Update) which is in a ROM on Solo.  It is baked into the chip and is not implemented by us.
This is what allows the entire firmware of Solo to be programmed.  **It's not recommended to develop for Solo using the DFU because 
if you program broken firmware, you could brick your device**.

On hacker devices, you can boot into the DFU by holding down the button for 5 seconds, when Solo is already in bootloader mode.

You can also run this command when Solo is in bootloader mode to put it in DFU mode.

```bash
solo program aux enter-dfu
```

Note it will stay in DFU mode until to tell it to boot again.  You can boot it again by running the following.

```bash
solo program aux leave-dfu
```

*Warning*: If you change the firmware to something broken, and you tell the DFU to boot it, you could brick your device.

## Solo Bootloader

The next boot stage is the "Solo bootloader".  So when we say to put your Solo into bootloader mode, it is this stage.
This bootloader is written by us and allows signed firmware updates to be written.  On Solo Hackers, there is no signature checking
and will allow any firmware updates.

It is safe to develop for Solo using our Solo bootloader.  If broken firmware is uploaded to the device, then the Solo
bootloader can always be booted again by holding down the button when plugging in.

## Solo application

This is what contains all the important functionality of Solo.  FIDO2, U2F, etc.  This is what Solo will boot to by default.
