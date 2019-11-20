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

Everything in the library is cross-platform, and it makes calls to functions defined
in `fido2/device.h` to do possibly platform specific things.  To get the library to compile
and run, you only need to implement one of these functions: `usbhid_send(uint8_t * send)`, which
is called by the library to send a 64 byte packet over a USB HID endpoint.

The rest of the definitions in `fido2/device.h` are not required to compile and run so you can
immediately hit the ground running and iterative add what else you need.  You'll definitely want
to continue implementing other functions in `fido2/device.h`.  For example, no data will be stored
persistently until you define how it can be done!

For examples, check out the build for STM32L4 and PC.

If there's something that doesn't work for you -- send a pull request!  It's better if we can
work together off of the same repo and not fork.