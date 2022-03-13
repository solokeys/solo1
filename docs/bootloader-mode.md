# Booting into bootloader mode

If you have a recent version of Solo, you can put it into bootloader mode by running this command.

```bash
solo program aux enter-bootloader
```

If your Solo is a bit older (<=2.5.3) You can put Solo into bootloader mode by using the button method:
Hold down button first and keep pressed, then plug in Solo.  After 2 seconds, bootloader mode will activate.
You'll see a yellowish flashing light and you can let go of the button.

Now Solo is ready to [accept firmware updates](/signed-updates).  If the Solo is a secured model, it can only accept signed updates, typically in the `firmware-*.json` format.

# The boot stages of Solo

Solo has 3 boot stages.

## DFU

The first stage is the DFU (Device Firmware Update) which is in a ROM on Solo.  It is baked into the chip and is not implemented by us.
This is what allows the entire firmware of Solo to be programmed.  **It's not recommended to develop for Solo using the DFU because
if you program broken firmware, you could brick your device**.

On hacker/nonverifying-bootloader devices, you can boot into the DFU by holding down the button for 5 seconds,
when Solo is already in bootloader mode.

You can also run this command when Solo is in bootloader mode to put it in DFU mode.

```bash
solo program aux enter-dfu
```

Note it will stay in DFU mode until you to tell it to boot again.  You can boot it again by running the following.

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
