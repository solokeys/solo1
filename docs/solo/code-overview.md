# Overview of firmware

This is a high level overview of the code.  We aim to make the code self documenting
and easy to understand, especially when paired with a high level overview.

## FIDO2 codebase

* `main.c` - calls high level functions and implements event loop.

* `ctaphid.c` - implements [USBHID protocol](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#usb) for FIDO.

* `u2f.c` - implements [U2F protocol](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html).

* `ctap.c` - implements [CTAP2 protocol](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html).

* `ctap_parse.c` - implements parsing for CTAP protocol.
    * this could use some work minimizing.

* `log.c` - embedded friendly debug logging.

* `crypto.c` - software implementation of the crypto needs of the application.   Generally this will be copied and edited for different platforms.  API defined in `crypto.h` should be the same.

* `device.h` - definitions of functions that are platform specific and should be implemented separately.  See `device.c` in any of the implementations to see examples.

## Data flow

The main loop will poll the USB peripheral to see if any messages arrived,
and then pass each one to the USBHID layer.

Once a USBHID message is fully buffered, it will be acted on, unless there was a previous error.
This will get passed up to U2F or CTAP2 layer.  The response is buffered and then written out to USB.

Depending on platform, there should be a minimum number of interrupts configured.  USB will need interrupts,
and possibly timer interrupts for keeping track of time.  ST implementation users a 16-bit timer to track time,
and interrupts to count overflows.

If the application is waiting on user input in CTAP2, then USBHID messages need to be continued to be polled,
to catch any [cancel command](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#usb-hid-cancel).
Also, every 100ms or so, an update needs to be sent via USBHID if the CTAP2 application is still processing a getAssertion request,
a makeCredential request, or is waiting on user input.  ST leverages same 16-bit timer interrupt for this.
