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
secret_attestation_key = "cd67aa310d091ed16e7e9892aa070e1994fcd714ae7c408fb946b72e5fe75d30"

# user supplied, optional
for i,x in enumerate(args):
    if x == '-s':
        secret_attestation_key = args[i+1]
        break

if secret_attestation_key is not None:
    args = args[:i] + args[i+2:]

# TODO put definitions somewhere else
PAGES = 128
APPLICATION_END_PAGE = PAGES - 19
AUTH_WORD_ADDR       = (flash_addr(APPLICATION_END_PAGE)-8)
ATTEST_ADDR          = (flash_addr(PAGES - 15))

first = IntelHex(args[1])
for i in range(2, len(args)-1):
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
    print('using key ',key)
    for i,x in enumerate(key):
        print(hex(ATTEST_ADDR + i))
        first[ATTEST_ADDR + i] = x

first.tofile(args[len(args)-1], format='hex')
