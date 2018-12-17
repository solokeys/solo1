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
from ecdsa import SigningKey, NIST256p
from ecdsa.util import randrange_from_seed__trytryagain
import sys

if len(sys.argv) > 1:
    print('using input seed file ', sys.argv[1])
    rng = open(sys.argv[1],'rb').read()
    secexp = randrange_from_seed__trytryagain(rng, NIST256p.order)
    sk = SigningKey.from_secret_exponent(secexp,curve = NIST256p)
else:
    sk = SigningKey.generate(curve = NIST256p)



sk_name = 'signing_key.pem'
print('Signing key for signing device firmware: '+sk_name)
open(sk_name,'wb+').write(sk.to_pem())

vk = sk.get_verifying_key()

print('Public key in various formats:')
print()
print([c for c in vk.to_string()])
print()
print(''.join(['%02x'%c for c in vk.to_string()]))
print()
print('"\\x' + '\\x'.join(['%02x'%c for c in vk.to_string()]) + '"')
print()


