# STM32L4xx Solo

This documents how to build the firmware for Solo for the STM32L4xx microcontroller.

# Building

First build the cbor library.

```bash
make cbor
```

Now build the Solo bootloader.

```
make boot
```

Now build the Solo application.

```
make clean      # remove object files from bootloader, keep bootloader.hex
make
```

Merge the two files together.  This script also patches a spot in memory to
allow the bootloader to boot the application.  This memory spot is later used for
signed firmware updates.

```
python merge_hex.py solo.hex bootloader.hex all.hex
```

You can now program Solo with `all.hex`.
