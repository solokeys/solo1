![GitHub](https://img.shields.io/github/license/mashape/apistatus.svg)
[![Kickstarter](https://img.shields.io/badge/kickstarter-back%20us-red.svg)](https://solokeys.com/kickstarter)
[![Build Status](https://travis-ci.com/SoloKeysSec/solo.svg?branch=master)](https://travis-ci.com/SoloKeysSec/solo)
[![Discourse Status](https://img.shields.io/discourse/https/meta.discourse.org/status.svg)](https://discourse.solokeys.com)
[![Keybase Chat](https://img.shields.io/badge/chat-on%20keybase-brightgreen.svg)](https://keybase.io/team/solokeys.public)


# Solo

Solo is an affordable security key that implements FIDO2/U2F and supports USB, NFC, and extensions.  Extensions
include SSH, GPG, and cryptocurrency.  Solo is an upgrade to [U2F Zero](https://github.com/conorpp/u2f-zero) and is a work in progress.

> Technical documentation for this project is contained in [docs/](https://github.com/SoloKeysSec/solo/tree/master/docs), built with [MkDocs](https://solo.solokeys.io/documenting/) and deployed automatically to <https://solo.solokeys.io>, part of our technical documentation suite hosted at <https://docs.solokeys.io>.

![](https://i.imgur.com/cXWtI1D.png)
![](https://i.imgur.com/vwFbsQW.png?1)

The Solo FIDO2/U2F code base is designed to be easily ported to different embedded systems.
Right now, it has been ported to the NRF52840 and EFM32J.  Soon to be supported is the STM32L442.

No hardware is needed for development.  You can run and extend the FIDO2 code base
using just your PC.

# Security

Solo is based on the STM32L442 microcontroller.  It offers the following security features.

- True random number generation to guarantee random keys.
- Firewall feature for code and secret data isolation.
- Locked flash

It also has up to 256 KB of memory, meaning it has room for side channel and fault resistant crypto implementations, plus other features.

Each chip ships with a read-only USB bootloader, put in place by ST.  This can be leveraged to completely reset and reprogram the device, to make sure you can trust it's running the right code.  The bootloader can be disabled.

# How do I get one?

We are still working on open sourcing an implementation that anyone can cheaply
build and program, just like with U2F Zero.  This will be released soon.  It will be easy to solder :)

In the meantime, you can port the code to your favorite microcontroller, or support
us by [signing up for our Kickstarter](https://solokeys.com/kickstarter).  Our aim is to crowdfund enough to make an economic
bulk order and provide open source security tokens for everyone that is interested.  We will offer 
"hackable" tokens that come with USB bootloaders and are reprogrammable.

[Sign up here](https://solokeys.com/kickstarter)!


# Setting up

Clone solo and build it

```bash
git clone https://github.com/SoloKeysSec/solo
cd solo/
make all

```

This builds our FIDO 2.0 and the U2F authenticator, as well as making a virtualenv in venv/
that has our python-fido2 fork installed.

Note that our python-fido2 fork will only connect to the software FIDO2 application,
not a hardware authenticator.  Install Yubico's fork to do that.


# Testing and development

The application is set up to send and recv USB HID messages over UDP to ease
development and reduce need for hardware.

Testing can be done using our fork of Yubico's client software, `python-fido2`.  
Our fork of `python-fido2` has small changes to make it send
USB HID over UDP to the authenticator application.

Run FIDO 2 / U2F application.

```bash
./main
```

Run example client software.  This runs through a registration and authentication.

```
./venv/bin/python python-fido2/examples/credential.py
```

Run the FIDO2 tests.

```
make fido2-test
```

Follow specifications to really dig in.

[https://fidoalliance.org/specs/fido-v2.0-ps-20170927/fido-client-to-authenticator-protocol-v2.0-ps-20170927.html](https://fidoalliance.org/specs/fido-v2.0-ps-20170927/fido-client-to-authenticator-protocol-v2.0-ps-20170927.html)

## Extensions

Extensions can be added to FIDO2/U2F to support things like SSH, GPG, and cryptocurrency.
Right now, an experimental cryptocurrency extension can be found in `fido2/extensions` and `web/index.html`.
More documentation to come.

The main goal is to expose an extensible API on Solo, like the following:
- Command to store private key
- Command to sign arbitrary hash
- Command to derive a public key
- Commands for setting/changing/authenticating a pin code (like in FIDO2)
- Command to expose entropy from TRNG.

Using these generic commands, various external programs can be implemented for the security key.
Since FIDO2/U2F are implemented, these programs can potentially work in the browser on desktops
and mobile devices, with no drivers needed to be installed.


## Porting

The main code base is in `fido2/`.  See `targets/nrf52840`, `targets/efm32/src`, and `pc/`
for examples of FIDO2/U2F ports.  In essence, you just need to reimplement `device.c`.  Optionally you can
re-implement `crypto.c` to accelerate operations and/or add other security features.


More documentation to come.

# Documentation

Check out our [official documentation](https://solo.solokeys.io/).

# Contributors

Contributors are welcome.  The ultimate goal is to have a FIDO 2 hardware token
capable of USB, Bluetooth, and NFC interfaces.  There could be multiple tokens
for each interface.
    
Look at the issues to see what is currently being worked on.  Feel free to add issues as well.

This is an upgrade to [U2F Zero](https://github.com/conorpp/u2f-zero).

# License

Everything in this repo is open source and licensed under the MIT License.

