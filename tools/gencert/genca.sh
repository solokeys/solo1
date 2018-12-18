#!/bin/bash
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
