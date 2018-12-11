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
