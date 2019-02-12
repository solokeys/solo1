#!/bin/bash
#
keyname=key.pem
certname=cert.pem
smallcertname=cert.der
curve=prime256v1

# generate EC private key
openssl ecparam -genkey -name "$curve" -out "$keyname" -rand seed.txt
# generate a "signing request"
openssl req -new -key "$keyname" -out "$keyname".csr  -subj "/C=US/ST=Maryland/O=SOLO HACKER/OU=Root CA/CN=solokeys.com/emailAddress=hello@solokeys.com"
# self sign the request
openssl x509 -trustout -req -days 18250  -in "$keyname".csr -signkey "$keyname" -out "$certname" -sha256

# convert to smaller size format DER
openssl  x509 -in $certname  -outform der -out $smallcertname

openssl x509 -in $certname -text -noout
