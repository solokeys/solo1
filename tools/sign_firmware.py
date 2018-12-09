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
