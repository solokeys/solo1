#
# Copyright (C) 2018 SoloKeys, Inc. <https://solokeys.com/>
#
#

# verify that the root CA/keypair and intermediate CA/keypairs are set up correctly.

[[ "$#" != 4 ]] && echo "usage: $0 <inter-key> <inter-cert> <root-key> <root-cert>" && exit 1

ikey=$1
icert=$2

rkey=$3
rcert=$4

echo 'challenge $RANDOM' > chal.txt

# check that they are actual key pairs
openssl dgst -sha256 -sign "$ikey" -out sig.txt chal.txt
openssl dgst -sha256 -verify  <(openssl x509 -in "$icert"  -pubkey -noout)  -signature sig.txt chal.txt

openssl dgst -sha256 -sign "$rkey" -out sig.txt chal.txt
openssl dgst -sha256 -verify  <(openssl x509 -in "$rcert"  -pubkey -noout)  -signature sig.txt chal.txt

# Check they are a chain
openssl verify -verbose -CAfile "$rcert" "$icert"
