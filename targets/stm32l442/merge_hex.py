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

# Merges bootloader and application into 1 file for ST Solo
#
# Patches settings in flash so bootloader will boot application.

from intelhex import IntelHex
import sys
from binascii import unhexlify

if len(sys.argv) < 3:
    print('usage: %s <file1.hex> <file2.hex> [...] [-s <secret_attestation_key>] <output.hex>')
    sys.exit(1)

def flash_addr(num):
    return 0x08000000 + num * 2048

args = sys.argv[:]

# generic / hacker attestation key
secret_attestation_key = "1b2626ecc8f69b0f69e34fb236d76466ba12ac16c3ab5750ba064e8b90e02448"

# user supplied, optional
for i,x in enumerate(args):
    if x == '-s':
        secret_attestation_key = args[i+1]
        args = args[:i] + args[i+2:]
        break


# TODO put definitions somewhere else
PAGES = 128
APPLICATION_END_PAGE = PAGES - 19
AUTH_WORD_ADDR       = (flash_addr(APPLICATION_END_PAGE)-8)
ATTEST_ADDR          = (flash_addr(PAGES - 15))

first = IntelHex(args[1])
for i in range(2, len(args)-1):
    print('merging %s with ' % (args[1]), args[i])
    first.merge(IntelHex( args[i] ), overlap = 'replace')

first[AUTH_WORD_ADDR]   = 0
first[AUTH_WORD_ADDR+1] = 0
first[AUTH_WORD_ADDR+2] = 0
first[AUTH_WORD_ADDR+3] = 0

first[AUTH_WORD_ADDR+4] = 0xff
first[AUTH_WORD_ADDR+5] = 0xff
first[AUTH_WORD_ADDR+6] = 0xff
first[AUTH_WORD_ADDR+7] = 0xff

if secret_attestation_key is not None:
    key = unhexlify(secret_attestation_key)


    for i,x in enumerate(key):
        first[ATTEST_ADDR + i] = x

first.tofile(args[len(args)-1], format='hex')
