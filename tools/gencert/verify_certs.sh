#
# Copyright (C) 2018 SoloKeys, Inc. <https://solokeys.com/>
# 
# This file is part of Solo.
# 
# Solo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# Solo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with Solo.  If not, see <https://www.gnu.org/licenses/>
# 
# This code is available under licenses for commercial use.
# Please contact SoloKeys for more information.
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
