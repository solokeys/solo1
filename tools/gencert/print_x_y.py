#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
import sys
from ecdsa import SigningKey, NIST256p

sk = SigningKey.from_pem(open(sys.argv[1]).read())


print('Private key in various formats:')
print()
print([c for c in sk.to_string()])
print()
print(''.join(['%02x' % c for c in sk.to_string()]))
print()
print('"\\x' + '\\x'.join(['%02x' % c for c in sk.to_string()]) + '"')
print()
