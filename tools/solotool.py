#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.
#

# Programs solo using the Solo bootloader
# Requires python-fido2, intelhex

import sys, os, time, struct, argparse
import array, struct, socket, json, base64, binascii
import tempfile
from binascii import hexlify, unhexlify
from hashlib import sha256

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from fido2.hid import CtapHidDevice, CTAPHID
from fido2.client import Fido2Client, ClientError
from fido2.ctap import CtapError
from fido2.ctap1 import CTAP1, ApduError
from fido2.ctap2 import CTAP2
from fido2.utils import Timeout
from fido2.attestation import Attestation

import usb.core
import usb.util
import usb._objfinalizer

from intelhex import IntelHex
import serial


def to_websafe(data):
    data = data.replace('+', '-')
    data = data.replace('/', '_')
    data = data.replace('=', '')
    return data


def from_websafe(data):
    data = data.replace('-', '+')
    data = data.replace('_', '/')
    return data + '=='[: (3 * len(data)) % 4]


def get_firmware_object(sk_name, hex_file):
    from ecdsa import SigningKey, NIST256p

    sk = SigningKey.from_pem(open(sk_name).read())
    fw = open(hex_file, 'r').read()
    fw = base64.b64encode(fw.encode())
    fw = to_websafe(fw.decode())
    ih = IntelHex()
    ih.fromfile(hex_file, format='hex')
    # start of firmware and the size of the flash region allocated for it.
    # TODO put this somewhere else.
    START = ih.segments()[0][0]
    END = (0x08000000 + ((128 - 19) * 2048)) - 8

    ih = IntelHex(hex_file)
    segs = ih.segments()
    arr = ih.tobinarray(start=START, size=END - START)

    im_size = END - START

    print('im_size: ', im_size)
    print('firmware_size: ', len(arr))

    byts = (arr).tobytes() if hasattr(arr, 'tobytes') else (arr).tostring()
    h = sha256()
    h.update(byts)
    sig = binascii.unhexlify(h.hexdigest())
    print('hash', binascii.hexlify(sig))
    sig = sk.sign_digest(sig)

    print('sig', binascii.hexlify(sig))

    sig = base64.b64encode(sig)
    sig = to_websafe(sig.decode())

    # msg = {'data': read()}
    msg = {'firmware': fw, 'signature': sig}
    return msg

class SoloExtension:
    version= 0x14
    rng = 0x15

class SoloBootloader:
    write = 0x40
    done = 0x41
    check = 0x42
    erase = 0x43
    version = 0x44
    reboot = 0x45
    st_dfu = 0x46
    disable = 0x47

    HIDCommandBoot = 0x50
    HIDCommandEnterBoot = 0x51
    HIDCommandEnterSTBoot = 0x52
    HIDCommandRNG = 0x60

    TAG = b'\x8C\x27\x90\xf6'


class SoloClient:
    def __init__(self,):
        self.origin = 'https://example.org'
        self.host = 'example.org'
        self.exchange = self.exchange_hid
        self.do_reboot = True

    def use_u2f(self,):
        self.exchange = self.exchange_u2f

    def use_hid(self,):
        self.exchange = self.exchange_hid

    def set_reboot(self, val):
        """ option to reboot after programming """
        self.do_reboot = val

    def reboot(self,):
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
        self.ctap2 = CTAP2(dev)
        self.client = Fido2Client(dev, self.origin)

        if self.exchange == self.exchange_hid:
            self.send_data_hid(CTAPHID.INIT, '\x11\x11\x11\x11\x11\x11\x11\x11')

    @staticmethod
    def format_request(cmd, addr=0, data=b'A' * 16):
        arr = b'\x00' * 9
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
            return self.dev.call(cmd, data, event)

    def exchange_hid(self, cmd, addr=0, data=b'A' * 16):
        req = SoloClient.format_request(cmd, addr, data)

        data = self.send_data_hid(SoloBootloader.HIDCommandBoot, req)

        ret = data[0]
        if ret != CtapError.ERR.SUCCESS:
            str = ''
            if ret == CtapError.ERR.NOT_ALLOWED:
                str = 'Out of bounds write'
            raise RuntimeError('Device returned non-success code %02x: %s' % (ret, str))

        return data[1:]

    def exchange_u2f(self, cmd, addr=0, data=b'A' * 16):
        appid = b'A' * 32
        chal = b'B' * 32

        req = SoloClient.format_request(cmd, addr, data)

        res = self.ctap1.authenticate(chal, appid, req)

        ret = res.signature[0]
        if ret != CtapError.ERR.SUCCESS:
            str = ''
            if ret == CtapError.ERR.NOT_ALLOWED:
                str = 'Out of bounds write'
            raise RuntimeError('Device returned non-success code %02x: %s' % (ret, str))

        return res.signature[1:]

    def bootloader_version(self,):
        data = self.exchange(SoloBootloader.version)
        if len(data) > 2:
            return (data[0],data[1],data[2])
        return data[0]

    def solo_version(self,):
        data = self.exchange_u2f(SoloExtension.version)
        return (data[0],data[1],data[2])

    def write_flash(self, addr, data):
        self.exchange(SoloBootloader.write, addr, data)

    def get_rng(self, num=0):
        ret = self.send_data_hid(SoloBootloader.HIDCommandRNG, struct.pack('B', num))
        return ret

    def verify_flash(self, sig):
        """
        Tells device to check signature against application.  If it passes,
        the application will boot.
        Exception raises if signature fails.
        """
        self.exchange(SoloBootloader.done, 0, sig)

    def wink(self,):
        self.send_data_hid(CTAPHID.WINK, b'')

    def reset(self,):
        self.ctap2.reset()

    def make_credential(self,):
        rp = {'id': self.host, 'name': 'example site'}
        user = {'id': b'abcdef', 'name': 'example user'}
        challenge = 'Y2hhbGxlbmdl'
        attest, data = self.client.make_credential(
            rp, user, challenge, exclude_list=[]
        )
        try:
            attest.verify(data.hash)
        except AttributeError:
            verifier = Attestation.for_type(attest.fmt)
            verifier().verify(
                attest.att_statement,
                attest.auth_data,
                data.hash
            )
        print('Register valid')
        x5c = attest.att_statement['x5c'][0]
        cert = x509.load_der_x509_certificate(x5c, default_backend())

        return cert


    def enter_solo_bootloader(self,):
        """
        If solo is configured as solo hacker or something similar,
        this command will tell the token to boot directly to the bootloader
        so it can be reprogrammed
        """
        if self.exchange != self.exchange_hid:
            self.send_data_hid(CTAPHID.INIT, '\x11\x11\x11\x11\x11\x11\x11\x11')
        self.send_data_hid(SoloBootloader.HIDCommandEnterBoot, '')

    def is_solo_bootloader(self,):
        try:
            self.bootloader_version()
            return True
        except CtapError as e:
            if e.code == CtapError.ERR.INVALID_COMMAND:
                pass
            else:
                raise (e)
        return False

    def enter_st_dfu(self,):
        """
        If solo is configured as solo hacker or something similar,
        this command will tell the token to boot directly to the st DFU
        so it can be reprogrammed.  Warning, you could brick your device.
        """
        soloboot = self.is_solo_bootloader()

        if soloboot or self.exchange == self.exchange_u2f:
            req = SoloClient.format_request(SoloBootloader.st_dfu)
            self.send_only_hid(SoloBootloader.HIDCommandBoot, req)
        else:
            self.send_only_hid(SoloBootloader.HIDCommandEnterSTBoot, '')

    def disable_solo_bootloader(self,):
        """
        Disables the Solo bootloader.  Only do this if you want to void the possibility
        of any updates.
        If you've started from a solo hacker, make you you've programmed a final/production build!
        """
        ret = self.exchange(
            SoloBootloader.disable, 0, b'\xcd\xde\xba\xaa'
        )  # magic number
        if ret[0] != CtapError.ERR.SUCCESS:
            print('Failed to disable bootloader')
            return False
        time.sleep(0.1)
        self.exchange(SoloBootloader.do_reboot)
        return True

    def program_file(self, name):

        if name.lower().endswith('.json'):
            data = json.loads(open(name, 'r').read())
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
        t1 = time.time() * 1000
        print('erasing...')
        for i in range(seg[0], seg[1], chunk):
            s = i
            e = min(i + chunk, seg[1])
            data = ih.tobinarray(start=i, size=e - s)
            self.write_flash(i, data)
            total += chunk
            progress = total / float(size) * 100
            sys.stdout.write('downloading %.2f%%...\r' % progress)
        sys.stdout.write('downloaded 100%             \r\n')
        t2 = time.time() * 1000
        print('time: %.2f s' % ((t2 - t1) / 1000.0))

        print('Verifying...')
        if self.do_reboot:
            if sig is not None:
                self.verify_flash(sig)
            else:
                self.verify_flash(b'A' * 64)


class DFU:
    class type:
        SEND = 0x21
        RECEIVE = 0xA1

    class bmReq:
        DETACH = 0x00
        DNLOAD = 0x01
        UPLOAD = 0x02
        GETSTATUS = 0x03
        CLRSTATUS = 0x04
        GETSTATE = 0x05
        ABORT = 0x06

    class state:
        APP_IDLE = 0x00
        APP_DETACH = 0x01
        IDLE = 0x02
        DOWNLOAD_SYNC = 0x03
        DOWNLOAD_BUSY = 0x04
        DOWNLOAD_IDLE = 0x05
        MANIFEST_SYNC = 0x06
        MANIFEST = 0x07
        MANIFEST_WAIT_RESET = 0x08
        UPLOAD_IDLE = 0x09
        ERROR = 0x0A

    class status:
        def __init__(self, s):
            self.status = s[0]
            self.timeout = s[1] + (s[2] << 8) + (s[3] << 16)
            self.state = s[4]
            self.istring = s[5]


# hot patch for windows libusb backend
olddel = usb._objfinalizer._AutoFinalizedObjectBase.__del__


def newdel(self):
    try:
        olddel(self)
    except OSError:
        pass


usb._objfinalizer._AutoFinalizedObjectBase.__del__ = newdel


class DFUDevice:
    def __init__(self,):
        pass

    @staticmethod
    def addr2list(a):
        return [a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF]

    @staticmethod
    def addr2block(addr, size):
        addr -= 0x08000000
        addr //= size
        addr += 2
        return addr

    @staticmethod
    def block2addr(addr, size):
        addr -= 2
        addr *= size
        addr += 0x08000000
        return addr

    def find(self, altsetting=0, ser=None):

        self.dev = None
        if ser:
            devs = usb.core.find(idVendor=0x0483, idProduct=0xDF11, find_all=1)
            for x in devs:
                if ser == (usb.util.get_string(x, x.iSerialNumber)):
                    print('connecting to ', ser)
                    self.dev = x
                    break
        else:
            self.dev = usb.core.find(idVendor=0x0483, idProduct=0xDF11)

        if self.dev is None:
            raise RuntimeError('No ST DFU devices found.')
        self.dev.set_configuration()

        for cfg in self.dev:
            for intf in cfg:
                if intf.bAlternateSetting == altsetting:
                    intf.set_altsetting()
                    self.intf = intf
                    self.intNum = intf.bInterfaceNumber
                    return self.dev

        raise RuntimeError('No ST DFU alternate-%d found.' % altsetting)

    def init(self,):
        if self.state() == DFU.state.ERROR:
            self.clear_status()

    def close(self,):
        pass

    def get_status(self,):
        # bmReqType, bmReq, wValue, wIndex, data/size
        s = self.dev.ctrl_transfer(
            DFU.type.RECEIVE, DFU.bmReq.GETSTATUS, 0, self.intNum, 6
        )
        return DFU.status(s)

    def state(self,):
        return self.get_status().state

    def clear_status(self,):
        # bmReqType, bmReq, wValue, wIndex, data/size
        s = self.dev.ctrl_transfer(
            DFU.type.SEND, DFU.bmReq.CLRSTATUS, 0, self.intNum, None
        )

    def upload(self, block, size):
        """
        address is  ((block – 2) × size) + 0x08000000
        """
        # bmReqType, bmReq, wValue, wIndex, data/size
        return self.dev.ctrl_transfer(
            DFU.type.RECEIVE, DFU.bmReq.UPLOAD, block, self.intNum, size
        )

    def set_addr(self, addr):
        # must get_status after to take effect
        return self.dnload(0x0, [0x21] + DFUDevice.addr2list(addr))

    def dnload(self, block, data):
        # bmReqType, bmReq, wValue, wIndex, data/size
        return self.dev.ctrl_transfer(
            DFU.type.SEND, DFU.bmReq.DNLOAD, block, self.intNum, data
        )

    def erase(self, a):
        d = [0x41, a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF]
        return self.dnload(0x0, d)

    def mass_erase(self):
        # self.set_addr(0x08000000)
        # self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        # assert(DFU.state.DOWNLOAD_IDLE == self.state())
        self.dnload(0x0, [0x41])
        self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        assert DFU.state.DOWNLOAD_IDLE == self.state()

    def write_page(self, addr, data):
        if self.state() not in (DFU.state.IDLE, DFU.state.DOWNLOAD_IDLE):
            self.clear_status()
            self.clear_status()
        if self.state() not in (DFU.state.IDLE, DFU.state.DOWNLOAD_IDLE):
            raise RuntimeError('DFU device not in correct state for writing memory.')

        oldaddr = addr
        addr = DFUDevice.addr2block(addr, len(data))
        # print('flashing %d bytes to block %d/%08x...' % (len(data), addr,oldaddr))

        self.dnload(addr, data)
        self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        assert DFU.state.DOWNLOAD_IDLE == self.state()

    def read_mem(self, addr, size):
        addr = DFUDevice.addr2block(addr, size)

        if self.state() not in (DFU.state.IDLE, DFU.state.UPLOAD_IDLE):
            self.clear_status()
            self.clear_status()
        if self.state() not in (DFU.state.IDLE, DFU.state.UPLOAD_IDLE):
            raise RuntimeError('DFU device not in correct state for reading memory.')

        return self.upload(addr, size)

    def block_on_state(self, state):
        s = self.get_status()
        while s.state == state:
            time.sleep(s.timeout / 1000.0)
            s = self.get_status()

    def detach(self,):
        if self.state() not in (DFU.state.IDLE, DFU.state.DOWNLOAD_IDLE):
            self.clear_status()
            self.clear_status()
        if self.state() not in (DFU.state.IDLE, DFU.state.DOWNLOAD_IDLE):
            raise RuntimeError('DFU device not in correct state for detaching.')
        # self.set_addr(0x08000000)
        # self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        # assert(DFU.state.DOWNLOAD_IDLE == self.state())
        self.dnload(0x0, [])
        return self.get_status()
        # return self.dev.ctrl_transfer(DFU.type.SEND, DFU.bmReq.DETACH, 0, self.intNum, None)


def attempt_to_find_device(p):
    found = False
    for i in range(0, 5):
        try:
            p.find_device()
            found = True
            break
        except RuntimeError:
            time.sleep(0.2)
    return found


def attempt_to_boot_bootloader(p):

    try:
        p.enter_solo_bootloader()
    except OSError:
        pass
    except CtapError as e:
        if e.code == CtapError.ERR.INVALID_COMMAND:
            print(
                'Solo appears to not be a solo hacker.  Try holding down the button for 2 while you plug token in.'
            )
            sys.exit(1)
        else:
            raise (e)
    print('Solo rebooted.  Reconnecting...')
    time.sleep(0.500)
    if not attempt_to_find_device(p):
        raise RuntimeError('Failed to reconnect!')


def solo_main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--rng",
        action="store_true",
        help='Continuously dump random numbers generated from Solo.',
    )
    parser.add_argument("--wink", action="store_true", help='HID Wink command.')
    parser.add_argument("--reset", action="store_true", help='Issue a FIDO2 reset command.  Warning: your credentials will be lost.')
    parser.add_argument("--verify-solo", action="store_true", help='Verify that the Solo firmware is from SoloKeys.  Check firmware version.')
    args = parser.parse_args()

    p = SoloClient()
    p.find_device()

    if args.reset:
        p.reset()

    if args.rng:
        while True:
            r = p.get_rng(255)
            sys.stdout.buffer.write(r)
        sys.exit(0)

    if args.wink:
        p.wink()
        sys.exit(0)

    if args.verify_solo:
        cert = p.make_credential()

        solo_fingerprint = b'r\xd5\x831&\xac\xfc\xe9\xa8\xe8&`\x18\xe6AI4\xc8\xbeJ\xb8h_\x91\xb0\x99!\x13\xbb\xd42\x95'
        hacker_fingerprint = b"\xd0ml\xcb\xda}\xe5j\x16'\xc2\xa7\x89\x9c5\xa2\xa3\x16\xc8Q\xb3j\xd8\xed~\xd7\x84y\xbbx~\xf7"

        if (cert.fingerprint(hashes.SHA256()) == solo_fingerprint):
            print('Valid SOLO firmware from SoloKeys')
        elif (cert.fingerprint(hashes.SHA256()) == hacker_fingerprint):
            print('Valid HACKER firmware')
        else:
            print('Unknown fingerprint! ', cert.fingerprint(hashes.SHA256()))

        try:
            v = p.solo_version()
            print('Version: ', v)
        except ApduError:
            print('Firmware is out of date.')


def asked_for_help():
    for i, v in enumerate(sys.argv):
        if v == '-h' or v == '--help':
            return True
    return False


def monitor_main():
    if asked_for_help() or len(sys.argv) != 2:
        print(
            """
    Reads serial output from USB serial port on Solo hacker.  Automatically reconnects.
    usage: %s <serial-port> [-h]
          * <serial-port> will look like COM10 or /dev/ttyACM0 or something.
          * baud is 115200.
    """
            % sys.argv[0]
        )
        sys.exit(1)

    port = sys.argv[1]

    ser = serial.Serial(port, 115200, timeout=0.05)

    def reconnect():
        while 1:
            time.sleep(0.02)
            try:
                ser = serial.Serial(port, 115200, timeout=0.05)
                return ser
            except serial.SerialException:
                pass

    while 1:
        try:
            d = ser.read(1)
        except serial.SerialException:
            print('reconnecting...')
            ser = reconnect()
            print('done')
        sys.stdout.buffer.write(d)
        sys.stdout.flush()


def genkey_main():
    from ecdsa import SigningKey, NIST256p
    from ecdsa.util import randrange_from_seed__trytryagain

    if asked_for_help() or len(sys.argv) not in (2, 3):
        print(
            """
    Generates key pair that can be used for Solo's signed firmware updates.
    usage: %s <output-pem-file> [input-seed-file] [-h]
          * Generates NIST P256 keypair.
          * Public key must be copied into correct source location in solo bootloader
          * The private key can be used for signing updates.
          * You may optionally supply a file to seed the RNG for key generating.
    """
            % sys.argv[0]
        )
        sys.exit(1)

    if len(sys.argv) > 2:
        seed = sys.argv[2]
        print('using input seed file ', seed)
        rng = open(seed, 'rb').read()
        secexp = randrange_from_seed__trytryagain(rng, NIST256p.order)
        sk = SigningKey.from_secret_exponent(secexp, curve=NIST256p)
    else:
        sk = SigningKey.generate(curve=NIST256p)

    sk_name = sys.argv[1]
    print('Signing key for signing device firmware: ' + sk_name)
    open(sk_name, 'wb+').write(sk.to_pem())

    vk = sk.get_verifying_key()

    print('Public key in various formats:')
    print()
    print([c for c in vk.to_string()])
    print()
    print(''.join(['%02x' % c for c in vk.to_string()]))
    print()
    print('"\\x' + '\\x'.join(['%02x' % c for c in vk.to_string()]) + '"')
    print()


def sign_main():

    if asked_for_help() or len(sys.argv) != 4:
        print(
            'Signs a firmware hex file, outputs a .json file that can be used for signed update.'
        )
        print('usage: %s <signing-key.pem> <app.hex> <output.json> [-h]' % sys.argv[0])
        print()
        sys.exit(1)
    msg = get_firmware_object(sys.argv[1], sys.argv[2])
    print('Saving signed firmware to', sys.argv[3])
    wfile = open(sys.argv[3], 'wb+')
    wfile.write(json.dumps(msg).encode())
    wfile.close()


def use_dfu(args):
    fw = args.__dict__['[firmware]']

    for i in range(0, 8):
        dfu = DFUDevice()
        try:
            dfu.find(ser=args.dfu_serial)
        except RuntimeError:
            time.sleep(0.25)
            dfu = None

    if dfu is None:
        print('No STU DFU device found. ')
        if args.dfu_serial:
            print('Serial number used: ', args.dfu_serial)
        sys.exit(1)
    dfu.init()

    if fw:
        ih = IntelHex()
        ih.fromfile(fw, format='hex')

        chunk = 2048
        seg = ih.segments()[0]
        size = sum([max(x[1] - x[0], chunk) for x in ih.segments()])
        total = 0
        t1 = time.time() * 1000

        print('erasing...')
        try:
            dfu.mass_erase()
        except usb.core.USBError:
            dfu.write_page(0x08000000 + 2048 * 10, 'ZZFF' * (2048 // 4))
            dfu.mass_erase()

        page = 0
        for start, end in ih.segments():
            for i in range(start, end, chunk):
                page += 1
                s = i
                data = ih.tobinarray(start=i, size=chunk)
                dfu.write_page(i, data)
                total += chunk
                progress = total / float(size) * 100

                sys.stdout.write(
                    'downloading %.2f%%  %08x - %08x ...         \r'
                    % (progress, i, i + page)
                )
                # time.sleep(0.100)

            # print('done')
            # print(dfu.read_mem(i,16))
        t2 = time.time() * 1000
        print()
        print('time: %d ms' % (t2 - t1))
        print('verifying...')
        progress = 0
        for start, end in ih.segments():
            for i in range(start, end, chunk):
                data1 = dfu.read_mem(i, 2048)
                data2 = ih.tobinarray(start=i, size=chunk)
                total += chunk
                progress = total / float(size) * 100
                sys.stdout.write(
                    'reading %.2f%%  %08x - %08x ...         \r'
                    % (progress, i, i + page)
                )
                if (end - start) == chunk:
                    assert data1 == data2
        print()
        print('firmware readback verified.')
    if args.detach:
        dfu.detach()


def programmer_main():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "[firmware]",
        nargs='?',
        default='',
        help='firmware file.  Either a JSON or hex file.  JSON file contains signature while hex does not.',
    )
    parser.add_argument(
        "--use-hid",
        action="store_true",
        help='Programs using custom HID command (default).  Quicker than using U2F authenticate which is what a browser has to use.',
    )
    parser.add_argument(
        "--use-u2f",
        action="store_true",
        help='Programs using U2F authenticate. This is what a web application will use.',
    )
    parser.add_argument(
        "--no-reset",
        action="store_true",
        help='Don\'t reset after writing firmware.  Stay in bootloader mode.',
    )
    parser.add_argument(
        "--reset-only",
        action="store_true",
        help='Don\'t write anything, try to boot without a signature.',
    )
    parser.add_argument(
        "--reboot", action="store_true", help='Tell bootloader to reboot.'
    )
    parser.add_argument(
        "--enter-bootloader",
        action="store_true",
        help='Don\'t write anything, try to enter bootloader.  Typically only supported by Solo Hacker builds.',
    )
    parser.add_argument(
        "--st-dfu",
        action="store_true",
        help='Don\'t write anything, try to enter ST DFU.  Warning, you could brick your Solo if you overwrite everything.  You should reprogram the option bytes just to be safe (boot to Solo bootloader first, then run this command).',
    )
    parser.add_argument(
        "--disable",
        action="store_true",
        help='Disable the Solo bootloader.  Cannot be undone.  No future updates can be applied.',
    )
    parser.add_argument(
        "--detach",
        action="store_true",
        help='Detach from ST DFU and boot from main flash.  Must be in DFU mode.',
    )
    parser.add_argument(
        "--dfu-serial",
        default='',
        help='Specify a serial number for a specific DFU device to connect to.',
    )
    parser.add_argument(
        "--use-dfu", action="store_true", help='Boot to ST-DFU before continuing.'
    )
    args = parser.parse_args()

    fw = args.__dict__['[firmware]']

    p = SoloClient()

    try:
        p.find_device()
        if args.use_dfu:
            print('entering dfu..')
            try:
                attempt_to_boot_bootloader(p)
                p.enter_st_dfu()
            except RuntimeError:
                # already in DFU mode?
                pass
    except RuntimeError:
        print('No Solo device detected.')
        if fw or args.detach:
            use_dfu(args)
            sys.exit(0)
        else:
            sys.exit(1)

    if args.detach:
        use_dfu(args)
        sys.exit(0)

    if args.use_u2f:
        p.use_u2f()

    if args.no_reset:
        p.set_reboot(False)

    if args.enter_bootloader:
        print('Attempting to boot into bootloader mode...')
        attempt_to_boot_bootloader(p)
        sys.exit(0)

    if args.reboot:
        p.reboot()
        sys.exit(0)

    if args.st_dfu:
        print('Sending command to boot into ST DFU...')
        p.enter_st_dfu()
        sys.exit(0)

    if args.disable:
        p.disable_solo_bootloader()
        sys.exit(0)

    if fw == '' and not args.reset_only:
        print('Need to supply firmware filename, or see help for more options.')
        parser.print_help()
        sys.exit(1)

    try:
        p.bootloader_version()
    except CtapError as e:
        if e.code == CtapError.ERR.INVALID_COMMAND:
            print('Bootloader not active.  Attempting to boot into bootloader mode...')
            attempt_to_boot_bootloader(p)
        else:
            raise (e)
    except ApduError:
        print('Bootloader not active.  Attempting to boot into bootloader mode...')
        attempt_to_boot_bootloader(p)

    if args.reset_only:
        p.exchange(SoloBootloader.done, 0, b'A' * 64)
    else:
        p.program_file(fw)


def main_mergehex():
    if len(sys.argv) < 3:
        print(
            'usage: %s <file1.hex> <file2.hex> [...] [-s <secret_attestation_key>] <output.hex>'
        )
        sys.exit(1)

    def flash_addr(num):
        return 0x08000000 + num * 2048

    args = sys.argv[:]

    # generic / hacker attestation key
    secret_attestation_key = (
        "1b2626ecc8f69b0f69e34fb236d76466ba12ac16c3ab5750ba064e8b90e02448"
    )

    # user supplied, optional
    for i, x in enumerate(args):
        if x == '-s':
            secret_attestation_key = args[i + 1]
            args = args[:i] + args[i + 2 :]
            break

    # TODO put definitions somewhere else
    PAGES = 128
    APPLICATION_END_PAGE = PAGES - 19
    AUTH_WORD_ADDR = flash_addr(APPLICATION_END_PAGE) - 8
    ATTEST_ADDR = flash_addr(PAGES - 15)

    first = IntelHex(args[1])
    for i in range(2, len(args) - 1):
        print('merging %s with ' % (args[1]), args[i])
        first.merge(IntelHex(args[i]), overlap='replace')

    first[flash_addr(APPLICATION_END_PAGE - 1)] = 0x41
    first[flash_addr(APPLICATION_END_PAGE - 1) + 1] = 0x41

    first[AUTH_WORD_ADDR - 4] = 0
    first[AUTH_WORD_ADDR - 1] = 0
    first[AUTH_WORD_ADDR - 2] = 0
    first[AUTH_WORD_ADDR - 3] = 0

    first[AUTH_WORD_ADDR] = 0
    first[AUTH_WORD_ADDR + 1] = 0
    first[AUTH_WORD_ADDR + 2] = 0
    first[AUTH_WORD_ADDR + 3] = 0

    first[AUTH_WORD_ADDR + 4] = 0xFF
    first[AUTH_WORD_ADDR + 5] = 0xFF
    first[AUTH_WORD_ADDR + 6] = 0xFF
    first[AUTH_WORD_ADDR + 7] = 0xFF

    if secret_attestation_key is not None:
        key = unhexlify(secret_attestation_key)

        for i, x in enumerate(key):
            first[ATTEST_ADDR + i] = x

    first.tofile(args[len(args) - 1], format='hex')


if __name__ == '__main__':

    if sys.version_info[0] < 3:
        print('Sorry, python3 is required.')
        sys.exit(1)

    if len(sys.argv) < 2 or (len(sys.argv) == 2 and asked_for_help()):
        print('Diverse command line tool for working with Solo')
        print('usage: %s <command> [options] [-h]' % sys.argv[0])
        print('commands: program, solo, monitor, sign, genkey, mergehex')
        print(
            """
Examples:
    {0} program <filename.hex|filename.json>
    {0} program <all.hex> --use-dfu
    {0} program --reboot
    {0} program --enter-bootloader
    {0} program --st-dfu
    {0} solo --wink
    {0} solo --rng
    {0} monitor <serial-port>
    {0} sign <key.pem> <firmware.hex> <output.json>
    {0} genkey <output-pem-file> [rng-seed-file]
    {0} mergehex bootloader.hex solo.hex combined.hex
""".format(
                sys.argv[0]
            )
        )
        sys.exit(1)

    c = sys.argv[1]
    sys.argv = sys.argv[:1] + sys.argv[2:]
    sys.argv[0] = sys.argv[0] + ' ' + c

    if c == 'program':
        programmer_main()
    elif c == 'solo':
        solo_main()
    elif c == 'monitor':
        monitor_main()
    elif c == 'sign':
        sign_main()
    elif c == 'genkey':
        genkey_main()
    elif c == 'mergehex':
        main_mergehex()
    else:
        print('invalid command: %s' % c)
