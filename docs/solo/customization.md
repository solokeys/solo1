# Customization

If you are interested in customizing parts of your Solo, and you have a Solo Hacker, this page is for you.

## Custom Attestation key

The attestation key is used in the FIDO2 *makeCredential* or U2F *register* requests.  It signs
newly generated credentials.  The certificate associated with the attestation key is output with newly created credentials.

Platforms or services can use the attestation feature to enforce specific authenticators to be used.
This is typically a use case for organizations and isn't seen in the wild for consumer use cases.

Attestation keys are typically the same for at least 100K units of a particular authenticator model.
This is so they don't contribute a significant fingerprint that platforms could use to identify the user.

If you don't want to use the default attestation key that Solo builds with, you can create your own
and program it.

### Creating your attestation key pair

Since we are generating keys, it's important to use a good entropy source.
You can use the [True RNG on your Solo](/solo/solo-extras) to generate some good random numbers.

```
# Run for 1 second, then hit control-c
solo key rng raw > seed.bin
```

First we will create a self signed key pair that acts as the root of trust.  This
won't go on the authenticator, but will sign the keypair that does.

Please change the root certification information as needed.  You may change the ECC curve.

```
curve=prime256v1

country=US
state=Maine
organization=OpenSourceSecurity
unit="Root CA"
CN=example.com
email=example@example.com

# generate EC private key
openssl ecparam -genkey -name "$curve" -out root_key.pem -rand seed.bin

# generate a "signing request"
openssl req -new -key root_key.pem -out root_key.pem.csr  -subj "/C=$country/ST=$state/O=$organization/OU=$unit/CN=$CN/emailAddress=$email"

# self sign the request
openssl x509 -trustout -req -days 18250  -in root_key.pem.csr -signkey root_key.pem -out root_cert.pem -sha256

# convert to smaller size format DER
openssl  x509 -in root_cert.pem -outform der -out root_cert.der

# print out information and verify
openssl x509 -in root_cert.pem -text -noout
```

You need to create a extended certificate for the device certificate to work with FIDO2.  You need to create this
file, `v3.ext`, and add these options to it.

```
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
```

Now to generate & sign the attestation key pair that will go on your device, or maybe 100,000 devices :).
Note you must use a prime256v1 curve for this step, and you must leave the unit/OU as "Authenticator Attestation".

```
country=US
state=Maine
organization=OpenSourceSecurity
unit="Authenticator Attestation"    # MUST KEEP THIS AS "Authenticator Attestation" for FIDO2.
CN=example.com
email=example@example.com

# generate EC private key
openssl ecparam -genkey -name "$curve" -out device_key.pem -rand seed.bin

# generate a "signing request"
openssl req -new -key device_key.pem -out device_key.pem.csr -subj "/C=$country/ST=$state/O=$organization/OU=$unit/CN=$CN/emailAddress=$email"

# sign the request
openssl x509 -req -days 18250  -in device_key.pem.csr -extfile v3.ext -CA root_cert.pem -CAkey root_key.pem -set_serial 01 -out device_cert.pem -sha256

# convert to smaller size format DER
openssl  x509 -in device_cert.pem  -outform der -out device_cert.der

# Verify the device certificate details
openssl x509 -in device_cert.pem -text -noout
```

Let's verify that the attestation key and certificate are valid, and that they can be verified with the root key pair.

```
echo 'challenge $RANDOM' > chal.txt

# check that they are valid key pairs
openssl dgst -sha256 -sign device_key.pem -out sig.txt chal.txt
openssl dgst -sha256 -verify  <(openssl x509 -in device_cert.pem  -pubkey -noout)  -signature sig.txt chal.txt

openssl dgst -sha256 -sign "root_key.pem" -out sig.txt chal.txt
openssl dgst -sha256 -verify  <(openssl x509 -in root_cert.pem  -pubkey -noout)  -signature sig.txt chal.txt

# Check they are a chain
openssl verify -verbose -CAfile "root_cert.pem" "device_cert.pem"
```

If the checks succeed, you are ready to program the device attestation key and certificate.

### Programming an attestation key and certificate

First, [Build your solo application and bootloader](/solo/building).

Print your attestation key in a hex string format.  Using our utility script:

```
python3 tools/gencert/print_x_y.py device_key.pem
```

Merge the `bootloader.hex`, `solo.hex`, attestion key, and certificate into one firmware file.

```
solo mergehex  \
    --attestation-key "(The 32-byte hex string extracted from device_key.pem)" \
    --attestation-cert device_cert.der \
    --lock \
    solo.hex \
    bootloader.hex \
    bundle.hex
```

**Warning**: Using the `--lock` flag prevents the DFU from being accessed on the device again.  It's recommended to try first without the `--lock` flag to make sure it works.

Now you have a newly created `bundle.hex` file with a custom attestation key and cert.  You can [program this `bundle.hex` file
with Solo in DFU mode](/solo/programming#procedure).

Are you interested in customizing in bulk?  Contact hello@solokeys.com and we can help.

## Custom application signing

You can customize the bootloader to only accept application updates that are signed by a private key that only you hold.

For this, we first need a key pair.  If you are using custom attestation keys following the instructions above then you can use your `root_key.pem`.  Simply use that file instead of `firmware_key.pem` in the commands below.  Otherwise, generate `firmware_key.pem`:

```
# Run for 1 second, then hit control-c
solo key rng raw > seed.bin
openssl ecparam -genkey -name prime256v1 -out firmware_key.pem -rand seed.bin
```

Now, extract the public key from `firmware_key.pem`:

```
openssl ec -noout -text -in firmware_key.pem | grep '^pub:' -A 5 | tail -n 5 | sed 's/:/\\\x/g' | tr -d ' \n' | cut -c 3-
```

Note that we cut the `04` prefix from the public key.  This is important.  The prefix just indicates that the key is uncompressed but the bootloader functions expect a key format without this prefix.

Now, replace the public key in the `targets/stm32l432/bootloader/pubkey_bootloader.c` file with the pulic key you obtained from `firmware.pem`.  Double check that everything went well by comparing the public key from `openssl ec -noout -text -in firmware_key.pem` to the one you now have in `pubkey_bootloader.c`.

With this change, [build your application and verifying bootloader](/solo/building) and [program the resulting `bundle.hex` file with Solo in DFU mode](/solo/programming#procedure).  You can also combine this step with your custom attestation key and cert as described above.

At this point, your Solo is locked and accepts application updates only if they are signed by you.  To update the application, [build your application](/solo/building) to get a `solo.hex` and then sign it:

```
solo sign firmware_key.pem solo.hex firmware.json
```

Now, you can program the signed `firmware.json`:

```
solo program aux enter-bootloader
solo program bootloader firmware.json
```

Make sure to safely store your `firmware_key.pem` because without this file you cannot update your Solo application anymore.
