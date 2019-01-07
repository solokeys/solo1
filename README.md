[![License](https://img.shields.io/github/license/solokeys/solo.svg)](https://github.com/solokeys/solo/blob/master/LICENSE)
[![Build Status](https://travis-ci.com/solokeys/solo.svg?branch=master)](https://travis-ci.com/solokeys/solo)
[![Discourse Users](https://img.shields.io/discourse/https/discourse.solokeys.com/users.svg)](https://discourse.solokeys.com)
[![Keybase Chat](https://img.shields.io/badge/chat-on%20keybase-brightgreen.svg)](https://keybase.io/team/solokeys.public)


# Solo

Solo is an open source security key, and you can get one at [solokeys.com](https://solokeys.com).

Solo supports FIDO2 and U2F standards for strong two-factor authentication and password-less login, and it will protect you against phishing and other online attacks. With colored cases and multilingual guides we want to make secure login more personable and accessible to everyone around the globe.

<img src="https://solokeys.com/images/photos/hero-on-white-cropped.png" width="600">

This repo contains the Solo firmware, including implementations of FIDO2 and U2F (CTAP2 and CTAP) over USB and NFC. The main implementation is for STM32L432, and it's ported to NRF52840 and EFM32J.

For development no hardware is needed, Solo also runs as a standalone application for Windows, Linux, and Mac OSX. If you like (or want to learn) hardware instead, you can run Solo on the NUCLEO-L432KC development board, or we make Solo for Hacker, an unlocked version of Solo that lets you customize its firmware.


# Security

Solo is based on the STM32L432 microcontroller. It offers the following security features.

- True random number generation to guarantee random keys.
- Security isolation so only simple & secure parts of code can handle keys.
- Flash protection from both external use and untrusted code segments.
- 256 KB of memory to support hardened crypto implementations and, later, additional features such as OpenPGP or SSH.
- No NDA needed to develop for.


# Solo for Hackers

Solo for Hacker is a special version of Solo that let you customize its firmware, for example you can change the LED color, and even build advanced applications.

You can only buy Solo for Hacker at [solokeys.com](https://solokeys.com), as we don't sell it on Amazon and other places to avoid confusing customers. If you buy a Hacker, you can permanently lock it into a regular Solo, but viceversa you can NOT take a regular Solo and turn it a Hacker.

If you have a Solo for Hacker, here's how you can load your own code on it. You can find more details, including how to permanently lock it, in our [documentation](https://docs.solokeys.io/solo/building/).

```bash
git clone --recurse-submodules https://github.com/solokeys/solo
cd solo

cd targets/stm32l432
make cbor
make all-hacker
cd ../..

make env3
source env3/bin/activate
python tools/solotool.py program targets/stm32l432/solo.hex
```

If you forgot the `--recurse-submodules` when cloning, simply `git submodule update --init --recursive`.

For example, if you want to turn off any blue light emission, you can edit [`led_rgb()`](https://github.com/solokeys/solo/blob/master/targets/stm32l432/src/led.c#L15) and force:
```
uint32_t b = 0;
```

Then recompile, load your new firmware, and enjoy a blue-light-free version of Solo.

In the Hacker version, hardware is the same and firmware is unlocked, in the sense that you can 1) load an unsigned application, or 2) entirely reflash the key. By contrast, in a regular Solo you can only upgrade to a firmware signed by SoloKeys, and flash is locked and debug disabled permanently.

A frequently asked question is whether Solo for Hacker is less secure than regular Solo. The answer is certainly yes, and therefore we only recommend to use Solo for Hacker for development, experimentation, and fun. An attacker with physical access to a Solo for Hacker can reflash it following the steps above, and even a malware on your computer could possibly reflash it.


# Developing Solo (No Hardware Needed)

Clone Solo and build it

```bash
git clone --recurse-submodules https://github.com/solokeys/solo
cd solo
make all
```

This builds Solo as a standalone application. Solo application is set up to send and recv USB HID messages over UDP to ease development and reduce need for hardware.

Testing can be done using our fork of Yubico's client software, python-fido2. Our fork of python-fido2 has small changes to make it send USB HID over UDP to the authenticator application. You can install our fork by running the following:

```bash
cd python-fido2 && python setup.py install
```

Run the Solo application:
```bash
./main
```

In another shell, you can run client software, for example our tests:
```bash
python tools/ctap_test.py
```

Or any client example such as:
```bash
python python-fido2/examples/credential.py
```

You can find more details in our [documentation](https://docs.solokeys.io/solo/), including how to build on the the NUCLEO-L432KC development board.


# Documentation

Check out our [official documentation](https://docs.solokeys.io/solo/).


# Contributors

Solo is an upgrade to [U2F Zero](https://github.com/conorpp/u2f-zero). It was born from Conor's passion for making secure hardware, and from our shared belief that security should be open to be trustworthy, in hardware like in software.

Contributors are welcome. The ultimate goal is to have a FIDO2 security key supporting USB, NFC, and BLE interfaces, that can run on a variety of MCUs.

Look at the issues to see what is currently being worked on. Feel free to add issues as well.


# License

Solo is fully open source.
All software is licensed under GPLv3, and hardware under CC BY-SA 4.0.
Software and hardware are available under licenses for commercial use. Please contact SoloKeys for more information.


# Where To Buy Solo

You can buy Solo, Solo Tap, and Solo for Hackers at [solokeys.com](https://solokeys.com).
