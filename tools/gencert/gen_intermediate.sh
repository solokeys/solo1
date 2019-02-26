#!/bin/bash
#
keyname=interkey.pem
certname=intercert.pem
smallcertname=intercert.der
curve=prime256v1

[[ "$#" != 2 ]] && echo "usage: $0 <signing-key> <root-ca>" && exit 1

# generate EC private key
openssl ecparam -genkey -name "$curve" -out "$keyname" -rand seed.txt

# generate a "signing request"
openssl req -new -key "$keyname" -out "$keyname".csr -subj "/C=US/ST=Maryland/O=SOLO HACKER/OU=Authenticator Attestation/CN=solokeys.com/emailAddress=hello@solokeys.com"

# sign the request
openssl x509 -req -days 18250  -in "$keyname".csr -extfile v3.ext -CA "$2" -CAkey "$1" -set_serial 01 -out "$certname" -sha256

# convert to smaller size format DER
openssl  x509 -in $certname  -outform der -out $smallcertname

openssl x509 -in $certname -text -noout
