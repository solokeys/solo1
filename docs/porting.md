# Usage and Porting

Solo is designed to be used as a library or ported to other platforms easily.  Here is an example
`main()` function.

```c
int main()
{
    uint8_t hidmsg[64];
    uint32_t t1 = 0;

    device_init();
    memset(hidmsg,0,sizeof(hidmsg));

    while(1)
    {

        if (usbhid_recv(hidmsg) > 0)
        {
            ctaphid_handle_packet(hidmsg);      // pass into libsolo!
            memset(hidmsg, 0, sizeof(hidmsg));
        }


        ctaphid_check_timeouts();
    }

}

```

`ctaphid_handle_packet(hidmsg);` is the entrance into the HID layer of libsolo, and will buffer packets and pass them
into FIDO2 or U2F layers.

Everything in the library is cross-platform, but it needs some functions implemented that are usually
platform specific.  For example, how should libsolo implement an atomic counter?  Where should it save state?
For all of these platform specific functions, the library contains it's own `weak` definition, so the library will compile and run.
LibSolo by default will not try to use an atomic
counter or save data persistently -- that needs to be implemented externally.

If you are using libsolo on another platform,
you should take a look at these possibly platform specific functions.  They are listed in `fido2/device.h`.
If you'd like to reimplement any of the functions, then simply implement the function and compile normally.
GCC will replace libsolo's `weak` defined functions (everything in `fido2/device.h`) with your functions.  By doing this, you 
are replacing the function that is used by libsolo.

To get the library to compile
and run, you only need to implement one function for libsolo: `usbhid_send(uint8_t * send)`, which
is called by the library to send a 64 byte packet over a USB HID endpoint.  In essence, you are giving
libsolo a function to write to USB.

The rest of the definitions in `fido2/device.h` are not required to compile and run so you can
immediately hit the ground running and iterative add what else you need.  You'll definitely want
to continue implementing other functions in `fido2/device.h`.  For example, no data will be stored
persistently until you define how it can be done!

For examples, check out the build for STM32L4 and PC (check out `pc/device` and `targets/stm32l432/src/device.c`).

If there's something that doesn't work for you -- send a pull request!  It's better if we can
work together off of the same repo and not fork.