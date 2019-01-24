
Solo has a bootloader that's fixed in memory to allow for signed firmware updates.  It is not a built-in bootloader provided by the chip
manufacturer, it is our own. We plan to use Ed25519 signatures, which have [efficient constant-time implementations on Cortex-M4 chips](http://www.cs.haifa.ac.il/~orrd/LC17/paper39.pdf).

On the STM32L432, there is 256 KB of memory.  The first 14 KB of memory is reserved for the bootloader.
The bootloader is the first thing that boots, and if the button of the device is not held for 2 seconds, the
application is immediately booted.

Consider the following memory layout of the device.

| 14 KB  | 226 KB  | 16KB  |
|---|---|---|
| --boot--  | -------application-------  | --data--  |

Our bootloader resides at address 0, followed by the application, and then the final 16 KB allocated for secret data.

The bootloader is allowed to replace any data in the application segment.  When the application is first written to,
a mass erase of the application segment is triggered and a flag in the data segment is set indicating the application
is not safe to boot.

In order to boot the application, a valid signature must be provided to the bootloader.  The bootloader will verify the
signature using a public key stored in the bootloader section, and the data in the application section.  If the signature
is valid, the boot flag in the data section will be changed to allow boot.

We are working to make the signature checking process redundantly to make glitching attacks more difficult.  Also random delays
between redundant checks.
