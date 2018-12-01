# Merges bootloader and application into 1 file for ST Solo
#
# Patches settings in flash so bootloader will boot application.

from intelhex import IntelHex
import sys

if len(sys.argv) < 3:
    print('usage: %s <file1.hex> <file2.hex> [...] <output.hex>')
    sys.exit(1)

def flash_addr(num):
    return 0x08000000 + num * 2048

PAGES = 128
APPLICATION_END_PAGE = PAGES - 19
AUTH_WORD_ADDR       = (flash_addr(APPLICATION_END_PAGE)-8)

first = IntelHex(sys.argv[1])
for i in range(2, len(sys.argv)-1):
    first.merge(IntelHex( sys.argv[i] ), overlap = 'replace')

first[AUTH_WORD_ADDR]   = 4
first[AUTH_WORD_ADDR+1] = 5
first[AUTH_WORD_ADDR+2] = 6
first[AUTH_WORD_ADDR+3] = 7

first.tofile(sys.argv[len(sys.argv)-1], format='hex')
