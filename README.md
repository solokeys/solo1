# Solo

This is the source code for Solo.  It implements the authenticator U2F and FIDO2 protocols.  It is designed 
to be easily ported to lightweight embedded platforms, as well as run on the PC.

No hardware is needed for development.

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

Run client software.

```
python python-fido2/examples/credential.py
```

You should see messages exchange between the client and the authenticator but that's it.  Follow specifications to develop further.

[https://fidoalliance.org/specs/fido-v2.0-ps-20170927/fido-client-to-authenticator-protocol-v2.0-ps-20170927.html](https://fidoalliance.org/specs/fido-v2.0-ps-20170927/fido-client-to-authenticator-protocol-v2.0-ps-20170927.html)

# Contributors

Contributors are welcome.  The ultimate goal is to have a FIDO 2 hardware token
capable of USB, Bluetooth, and NFC interfaces.  There could be multiple tokens
for each interface.  [Hardware is still being decided
    on](https://github.com/conorpp/u2f-zero/issues/76).

This is an upgrade to [U2F
Zero](https://github.com/conorpp/u2f-zero).  A lot of the hardware and software
will be different so I think it's best to start a new repository.








