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
openssl req -new -key root_key.pem -out root_key.pem.csr  -subj "/C=$country/ST=$state/O=$organization/OU=$unit/CN=example.com/emailAddress=$email"

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
unit="Authenticator Attestation"
CN=example.com
email=example@example.com

# generate EC private key
openssl ecparam -genkey -name "$curve" -out device_key.pem -rand seed.bin

# generate a "signing request"
openssl req -new -key device_key.pem -out device_key.pem.csr -subj "/C=$country/ST=$state/O=$organization/OU=$unit/CN=example.com/emailAddress=$email"

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

Convert the DER format of the device attestation certificate to "C" bytes using our utility script.  You may first need to
first install prerequisite python modules (pip install -r tools/requirements.txt).

```
python tools/gencert/cbytes.py device_cert.der
```

Copy the byte string portion into the [`attestation.c` source file of Solo](https://github.com/solokeys/solo/blob/master/targets/stm32l432/src/attestation.c).  Overwrite the development or "default" certificate that is already there.

Now [build the Solo firmware](/solo/building), either a secure or hacker build.  You will need to produce a bootloader.hex file and a solo.hex file.

Print your attestation key in a hex string format.

```
python tools/print_x_y.py device_key.pem
```

Merge the bootloader.hex, solo.hex, and attestion key into one firmware file.

```
solo mergehex --attestation-key <attestation-key-hex-string> bootloader.hex solo.hex all.hex
```

Now you have a newly create `all.hex` file with a custom attestation key.  You can [program this all.hex file
with Solo in DFU mode](/solo/programming#procedure).