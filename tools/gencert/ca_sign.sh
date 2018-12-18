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
[[ "$#" != 4 ]] && echo "usage: $0 <private-key> <CA-cert> <signing-key> <output-cert>" && exit 1

# generate a "signing request"
echo "generate request"
openssl req -new -key "$1" -out "$1".csr

# CA sign the request
echo "sign request with CA key"
openssl x509 -days 18250 -req -in "$1".csr -extfile v3.ext -CA "$2" -CAkey "$3" -out "$4" -set_serial 0

echo "output as der"
openssl  x509 -in "$4" -outform der -out "$4".der
