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
import sys
import json,base64,array,binascii
from hashlib import sha256

from ecdsa import SigningKey, NIST256p
from intelhex import IntelHex

def to_websafe(data):
    data = data.replace('+','-')
    data = data.replace('/','_')
    data = data.replace('=','')
    return data

def from_websafe(data):
    data = data.replace('-','+')
    data = data.replace('_','/')
    return data + '=='[:(3*len(data)) % 4]

def get_firmware_object(sk_name, hex_file):
    sk = SigningKey.from_pem(open(sk_name).read())
    fw = open(hex_file,'r').read()
    fw = base64.b64encode(fw.encode())
    fw = to_websafe(fw.decode())
    ih = IntelHex()
    ih.fromfile(hex_file, format='hex')
    # start of firmware and the size of the flash region allocated for it.
    # TODO put this somewhere else.
    START = ih.segments()[0][0]
    END = ((0x08000000 + ((128-19)*2048))-8)

    ih = IntelHex(hex_file)
    segs = ih.segments()
    arr = ih.tobinarray(start = START, size = END-START)

    im_size = END-START

    print('im_size: ', im_size)
    print('firmware_size: ', len(arr))

    byts = (arr).tobytes() if hasattr(arr,'tobytes') else (arr).tostring()
    h = sha256()
    h.update(byts)
    sig = binascii.unhexlify(h.hexdigest())
    print('hash', binascii.hexlify(sig))
    sig = sk.sign_digest(sig)

    print('sig', binascii.hexlify(sig))

    sig = base64.b64encode(sig)
    sig = to_websafe(sig.decode())

    #msg = {'data': read()}
    msg = {'firmware': fw, 'signature':sig}
    return msg

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('usage: %s <signing-key.pem> <app.hex> <output.json>' % sys.argv[0])
    msg = get_firmware_object(sys.argv[1],sys.argv[2])
    print('Saving signed firmware to', sys.argv[3])
    wfile = open(sys.argv[3],'wb+')
    wfile.write(json.dumps(msg).encode())
    wfile.close()
