#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
