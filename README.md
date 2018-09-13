# Solo

This is the source code for Solo.  Solo is a security key that implements FIDO2/U2F and supports USB, NFC, and extensions.  Extensions
include SSH, GPG, and cryptocurrency.  Solo is a work in progress.

![](https://i.imgur.com/O7qPR3o.png)
![](https://i.imgur.com/vwFbsQW.png?1)

The Solo FIDO2/U2F code base is designed to be easily ported to different embedded systems.
Right now, it has been ported to the NRF52840 and EFM32J.  Soon to be supported is the SAM L11.

No hardware is needed for development.  You can run and extend the FIDO2 code base
using just your PC.

# Security

Solo is based on the SAM L11 secure microcontroller.  It offers the following security features.

- True random number generation to guarantee random keys.
- Side channel resistant RAM and AES for physically secure key derivation.
- ARM TrustZone to provide security isolation for master key.
- Scrambled key storage to prevent invasive flash readout methods.
- Secure boot to ensure application integrity.

The SAM L11 is one of the best chips for this application in terms of security,
when considering the NDA-free market.

The firmware can be readout using a debugger to verify that a Solo is running
the code posted publicly.  The secret information is of course inaccessible.

# Setting up

Clone and Compile CBOR library and FIDO 2 client library.

```bash
git clone https://github.com/conorpp/u2f-one
cd u2f-one/
git submodule update --init

cd tinycbor && make
cd ..

cd python-fido2/
python setup.py install

```

Note that our python-fido2 fork will only connect to the software FIDO2 application,
not a hardware authenticator.  Install Yubico's fork to do that.


Open `crypto/tiny-AES-c/aes.h` in a text editor and make sure AES256 is selected as follows.

```
//#define AES128 1
//#define AES192 1
#define AES256 1
```

Now compile FIDO 2.0 and U2F authenticator.

```bash
make
```

# Testing and development

The application is set up to send and recv USB HID messages over UDP to ease
development and reduce need for hardware.

Testing can be done using Yubico's client software.  Note that the client
software is also a work in progress and the [FIDO 2.0
specification](https://fidoalliance.org/specs/fido-v2.0-ps-20170927/fido-client-to-authenticator-protocol-v2.0-ps-20170927.html)
is ultimate.  Some small changes to Yubico's Client software make it send
USB HID over UDP to the authenticator application.

Run FIDO 2 / U2F application.

```bash
./main
```

Run example client software.  This runs through a registration and authentication.

```
python python-fido2/examples/credential.py
```

Run the FIDO2 tests.

```
python tools/ctap_test.py
```

Follow specifications to really dig in.

[https://fidoalliance.org/specs/fido-v2.0-ps-20170927/fido-client-to-authenticator-protocol-v2.0-ps-20170927.html](https://fidoalliance.org/specs/fido-v2.0-ps-20170927/fido-client-to-authenticator-protocol-v2.0-ps-20170927.html)

## Extensions

Extensions can be added to FIDO2/U2F to support things like SSH, GPG, and cryptocurrency.
Right now, an experimental cryptocurrency extension can be found in `fido2/extensions` and `web/index.html`.
More documentation to come.

## Porting

The main code base is in `fido2/`.  See `targets/nrf52840`, `targets/efm32/src`, and `pc/`
for examples of FIDO2/U2F ports.  In essence, you need to reimplement `device.c`.
More documentation to come.

# Contributors

Contributors are welcome.  The ultimate goal is to have a FIDO 2 hardware token
capable of USB, Bluetooth, and NFC interfaces.  There could be multiple tokens
for each interface.  [Hardware is still being decided
    on](https://github.com/conorpp/u2f-zero/issues/76).
    
Look at the issues to see what is currently being worked on.  Feel free to add issues as well.

This is an upgrade to [U2F
Zero](https://github.com/conorpp/u2f-zero).







