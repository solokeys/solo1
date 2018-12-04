# Programs solo using the Solo bootloader
# Requires python-fido2, intelhex

import sys,os,time,struct
import array,struct,socket,json,base64
import tempfile
from binascii import hexlify

from fido2.hid import CtapHidDevice, CTAPHID
from fido2.client import Fido2Client, ClientError
from fido2.ctap import CtapError
from fido2.ctap1 import CTAP1

from intelhex import IntelHex

from sign_firmware import *

class SoloBootloader:
    write = 0x40
    done = 0x41
    check = 0x42
    erase = 0x43
    version = 0x44

    TAG = b'\x8C\x27\x90\xf6'

class Programmer():

    def __init__(self,):
        self.origin = 'https://example.org'

    def find_device(self,):
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            raise RuntimeError('No FIDO device found')
        self.dev = dev
        self.ctap1 = CTAP1(dev)

    @staticmethod
    def format_request(cmd,addr = 0,data = b'A'*16):
        arr = b'\x00'*9
        addr = struct.pack('<L', addr)
        cmd = struct.pack('B', cmd)
        length = struct.pack('B', len(data))

        return cmd + addr[:3] + SoloBootloader.TAG + length + data

    def exchange(self,cmd,addr=0,data=b'A'*16):
        appid = b'A'*32
        chal = b'B'*32

        req = Programmer.format_request(cmd,addr,data)

        res = self.ctap1.authenticate(chal,appid, req)

        ret = res.signature[0]
        if ret != CtapError.ERR.SUCCESS:
            raise RuntimeError('Device returned non-success code %02x' % ret)

        return res.signature[1:]

    def version(self,):
        data = self.exchange(SoloBootloader.version)
        return data[0]

    def write_flash(self,addr,data):
        self.exchange(SoloBootloader.write,addr,data)


    def verify_flash(self,sig):
        """
        Tells device to check signature against application.  If it passes,
        the application will boot.
        Exception raises if signature fails.
        """
        self.exchange(SoloBootloader.done,0,sig)

    def program_file(self,name):
        data = json.loads(open(name,'r').read())
        fw = base64.b64decode(from_websafe(data['firmware']).encode())
        sig = base64.b64decode(from_websafe(data['signature']).encode())

        ih = IntelHex()
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(fw)
        tmp.seek(0)
        tmp.close()
        ih.fromfile(tmp.name, format='hex')

        chunk = 240
        seg = ih.segments()[0]
        size = seg[1] - seg[0]
        total = 0
        t1 = time.time()*1000
        for i in range(seg[0], seg[1], chunk):
            s = i
            e = min(i+chunk,seg[1])
            data = ih.tobinarray(start=i,size = e-s)
            self.write_flash(i,data)
            total += chunk
            progress = total/float(size)*100
            sys.stdout.write('downloading %.2f%%...\r' % progress)
        sys.stdout.write('downloading 100%           \r\n')
        t2 = time.time()*1000
        print('time: %.2f s' % ((t2-t1)/1000.0))

        print('Verifying...')
        self.verify_flash(sig)



if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage: %s <firmware.json>' % sys.argv[0])
        sys.exit(1)

    p = Programmer()
    p.find_device()

    print('version is ', p.version())

    p.program_file(sys.argv[1])
