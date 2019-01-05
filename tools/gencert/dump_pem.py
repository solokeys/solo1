#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
from __future__ import print_function
import sys, fileinput, binascii

try:
    import ecdsa
except:
    print('python ecdsa module is required')
    print('try running: ')
    print('     pip install ecdsa')
    sys.exit(1)


if len(sys.argv) not in [2]:
    print('usage: %s <key.pem>' % sys.argv[0])
    sys.exit(1)

pemkey = sys.argv[1]
attestkey = ecdsa.SigningKey.from_pem(open(pemkey).read())

hstr = binascii.hexlify(attestkey.to_string())
print(hstr)

cstr = ''
it = iter(hstr)
for d1 in it:
    d2 = next(it)
    cstr += '\\x' + d1 + d2

print('"%s"' % cstr)
