# Programs solo using the Solo bootloader
# Requires python-fido2, intelhex

import sys,os,time,struct,argparse
import array,struct,socket,json,base64
import tempfile
from binascii import hexlify

from fido2.hid import CtapHidDevice, CTAPHID
from fido2.client import Fido2Client, ClientError
from fido2.ctap import CtapError
from fido2.ctap1 import CTAP1, ApduError
from fido2.utils import Timeout

from intelhex import IntelHex

from sign_firmware import *

class SoloBootloader:
    write = 0x40
    done = 0x41
    check = 0x42
    erase = 0x43
    version = 0x44
    reboot = 0x45
    st_dfu = 0x46

    HIDCommandBoot = 0x50
    HIDCommandEnterBoot = 0x51
    HIDCommandEnterSTBoot = 0x52

    TAG = b'\x8C\x27\x90\xf6'

class Programmer():

    def __init__(self,):
        self.origin = 'https://example.org'
        self.exchange = self.exchange_hid
        self.reboot = True

    def use_u2f(self,):
        self.exchange = self.exchange_u2f

    def use_hid(self,):
        self.exchange = self.exchange_hid

    def set_reboot(self,val):
        """ option to reboot after programming """
        self.reboot = val

    def reboot(self,val):
        """ option to reboot after programming """
        try:
            self.exchange(SoloBootloader.reboot)
        except OSError:
            pass

    def find_device(self,):
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            raise RuntimeError('No FIDO device found')
        self.dev = dev
        self.ctap1 = CTAP1(dev)

        if self.exchange == self.exchange_hid:
            self.send_data_hid(CTAPHID.INIT, '\x11\x11\x11\x11\x11\x11\x11\x11')

    @staticmethod
    def format_request(cmd,addr = 0,data = b'A'*16):
        arr = b'\x00'*9
        addr = struct.pack('<L', addr)
        cmd = struct.pack('B', cmd)
        length = struct.pack('>H', len(data))

        return cmd + addr[:3] + SoloBootloader.TAG + length + data

    def send_only_hid(self, cmd, data):
        if type(data) != type(b''):
            data = struct.pack('%dB' % len(data), *[ord(x) for x in data])
        self.dev._dev.InternalSend(0x80 | cmd, bytearray(data))

    def send_data_hid(self, cmd, data):
        if type(data) != type(b''):
            data = struct.pack('%dB' % len(data), *[ord(x) for x in data])
        with Timeout(1.0) as event:
            return self.dev.call(cmd, data,event)

    def exchange_hid(self,cmd,addr=0,data=b'A'*16):
        req = Programmer.format_request(cmd,addr,data)

        data = self.send_data_hid(SoloBootloader.HIDCommandBoot, req)

        ret = data[0]
        if ret != CtapError.ERR.SUCCESS:
            raise RuntimeError('Device returned non-success code %02x' % ret)

        return data[1:]

    def exchange_u2f(self,cmd,addr=0,data=b'A'*16):
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

    def enter_solo_bootloader(self,):
        """
        If solo is configured as solo hacker or something similar,
        this command will tell the token to boot directly to the bootloader
        so it can be reprogrammed
        """
        if self.exchange != self.exchange_hid:
            self.send_data_hid(CTAPHID.INIT, '\x11\x11\x11\x11\x11\x11\x11\x11')
        self.send_data_hid(SoloBootloader.HIDCommandEnterBoot, '')

    def enter_st_dfu(self,):
        """
        If solo is configured as solo hacker or something similar,
        this command will tell the token to boot directly to the st DFU
        so it can be reprogrammed.  Warning, you could brick your device.
        """
        soloboot = False
        try:
            p.version()
            soloboot = True
        except CtapError as e:
            if e.code == CtapError.ERR.INVALID_COMMAND:
                pass
            else:
                raise (e)

        if soloboot or self.exchange == self.exchange_u2f:
            req = Programmer.format_request(SoloBootloader.st_dfu)
            self.send_only_hid(SoloBootloader.HIDCommandBoot, req)
        else:
            self.send_only_hid(SoloBootloader.HIDCommandEnterSTBoot, '')

    def program_file(self,name):

        if name.lower().endswith('.json'):
            data = json.loads(open(name,'r').read())
            fw = base64.b64decode(from_websafe(data['firmware']).encode())
            sig = base64.b64decode(from_websafe(data['signature']).encode())
            ih = IntelHex()
            tmp = tempfile.NamedTemporaryFile(delete=False)
            tmp.write(fw)
            tmp.seek(0)
            tmp.close()
            ih.fromfile(tmp.name, format='hex')
        else:
            if not name.lower().endswith('.hex'):
                print('Warning, assuming "%s" is an Intel Hex file.' % name)
            sig = None
            ih = IntelHex()
            ih.fromfile(name, format='hex')

        if self.exchange == self.exchange_hid:
            chunk = 2048
        else:
            chunk = 240

        seg = ih.segments()[0]
        size = seg[1] - seg[0]
        total = 0
        t1 = time.time()*1000
        print('erasing...')
        for i in range(seg[0], seg[1], chunk):
            s = i
            e = min(i+chunk,seg[1])
            data = ih.tobinarray(start=i,size = e-s)
            self.write_flash(i,data)
            total += chunk
            progress = total/float(size)*100
            sys.stdout.write('downloading %.2f%%...\r' % progress)
        sys.stdout.write('downloaded 100%             \r\n')
        t2 = time.time()*1000
        print('time: %.2f s' % ((t2-t1)/1000.0))

        print('Verifying...')
        if self.reboot:
            if sig is not None:
                self.verify_flash(sig)
            else:
                self.verify_flash(b'A'*64)

def attempt_to_find_device(p):
    found = False
    for i in range(0,5):
        try:
            p.find_device()
            found = True
            break
        except RuntimeError:
            time.sleep(0.2)
    return found

def attempt_to_boot_bootloader(p):
    print('Bootloader not active.  Attempting to boot into bootloader mode...')
    try:
        p.enter_solo_bootloader()
    except OSError:
        pass
    except CtapError as e:
        if e.code == CtapError.ERR.INVALID_COMMAND:
            print('Solo appears to not be a solo hacker.  Try holding down the button for 2 while you plug token in.')
            sys.exit(1)
        else:
            raise(e)
    print('Solo rebooted.  Reconnecting...')
    time.sleep(.500)
    if not attempt_to_find_device(p):
        print('Failed to reconnect!')
        sys.exit(1)

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("[firmware]", nargs='?', default='', help = 'firmware file.  Either a JSON or hex file.  JSON file contains signature while hex does not.')
    parser.add_argument("--use-hid", action="store_true", help = 'Programs using custom HID command (default).  Quicker than using U2F authenticate which is what a browser has to use.')
    parser.add_argument("--use-u2f", action="store_true", help = 'Programs using U2F authenticate. This is what a web application will use.')
    parser.add_argument("--no-reset", action="store_true", help = 'Don\'t reset after writing firmware.  Stay in bootloader mode.')
    parser.add_argument("--reset-only", action="store_true", help = 'Don\'t write anything, try to boot without a signature.')
    parser.add_argument("--reboot", action="store_true", help = 'Tell bootloader to reboot.')
    parser.add_argument("--enter-bootloader", action="store_true", help = 'Don\'t write anything, try to enter bootloader.  Typically only supported by Solo Hacker builds.')
    parser.add_argument("--st-dfu", action="store_true", help = 'Don\'t write anything, try to enter ST DFU.  Warning, you could brick your Solo if you overwrite everything.  You should reprogram the option bytes just to be safe (boot to Solo bootloader first, then run this command).')
    args = parser.parse_args()
    print()

    p = Programmer()
    p.find_device()

    if args.use_u2f:
        p.use_u2f()

    if args.no_reset:
        p.set_reboot(False)

    if args.enter_bootloader:
        attempt_to_boot_bootloader(p)
        sys.exit(0)

    if args.reboot:
        p.reboot()
        sys.exit(0)

    if args.st_dfu:
        print('Sending command to boot into ST DFU...')
        p.enter_st_dfu()
        sys.exit(0)

    try:
        print('version is ', p.version())
    except CtapError as e:
        if e.code == CtapError.ERR.INVALID_COMMAND:
            attempt_to_boot_bootloader(p)
        else:
            raise(e)
    except ApduError:
        attempt_to_boot_bootloader(p)

    if not args.reset_only:
        fw = args.__dict__['[firmware]']
        if fw == '':
            print('Need to supply firmware filename.')
            args.print_help()
            sys.exit(1)
        p.program_file(fw)
    else:
        p.exchange(SoloBootloader.done,0,b'A'*64)
