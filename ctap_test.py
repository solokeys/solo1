# Script for testing correctness of CTAP2/CTAP1 security token

from __future__ import print_function, absolute_import, unicode_literals

from fido2.hid import CtapHidDevice, CTAPHID
from fido2.client import Fido2Client
from fido2.ctap import CtapError
from fido2.ctap1 import CTAP1
from fido2.ctap2 import *
from fido2.cose import *
from fido2.utils import Timeout
import sys,os
from random import randint
from binascii import hexlify
import array,struct,socket

# Set up a FIDO 2 client using the origin https://example.com


def ForceU2F(client,device):
    client.ctap = CTAP1(device)
    client.pin_protocol = None
    client._do_make_credential = client._ctap1_make_credential
    client._do_get_assertion = client._ctap1_get_assertion


class Packet(object):
    def __init__(self,data):
        self.data = data

    def ToWireFormat(self,):
        return self.data

    @staticmethod
    def FromWireFormat(pkt_size,data):
        return Packet(data)



class Tester():
    def __init__(self,):
        self.origin = 'https://examplo.org'

    def find_device(self,):
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            raise RuntimeError('No FIDO device found')
        self.dev = dev
        self.ctap = CTAP2(dev)

        # consume timeout error
        cmd,resp = self.recv_raw()

    def send_data(self, cmd, data):
        #print('<<', hexlify(data))
        if type(data) != type(b''):
            data = struct.pack('%dB' % len(data), *[ord(x) for x in data])
        with Timeout(1.0) as event:
            return self.dev.call(cmd, data,event)

    def send_raw(self, data, cid = None):
        if cid is None:
            cid = self.dev._dev.cid
        if type(data) != type(b''):
            data = struct.pack('%dB' % len(data), *[ord(x) for x in data])
        self.dev._dev.InternalSendPacket(Packet(cid + data))

    def cid(self,):
        return self.dev._dev.cid

    def recv_raw(self,):
        cmd,payload = self.dev._dev.InternalRecv()
        return cmd, payload

    def check_error(self,data,err=None):
        assert(len(data) == 1)
        if err is None:
            if data[0] != 0:
                raise CtapError(data[0])
        elif data[0] != err:
            raise ValueError('Unexpected error: %02x' % data[0])


    def test_hid(self,):
        print('Test idle')
        try:
            cmd,resp = self.recv_raw()
        except socket.timeout:
            print('Pass: Idle')

        print('Test init')
        r = self.send_data(CTAPHID.INIT, '\x11\x11\x11\x11\x11\x11\x11\x11')

        pingdata = os.urandom(100)
        try:
            r = self.send_data(CTAPHID.PING, pingdata)
            if (r != pingdata):
                raise ValueError('Ping data not echo\'d')
        except CtapError as e:
            print('100 byte Ping failed:', e)
        print('PASS: 100 byte ping')

        pingdata = os.urandom(7609)
        try:
            r = self.send_data(CTAPHID.PING, pingdata)
            if (r != pingdata):
                raise ValueError('Ping data not echo\'d')
        except CtapError as e:
            print('7609 byte Ping failed:', e)
        print('PASS: 7609 byte ping')

        print('Test non-active cid')

        try:
            r = self.send_data(CTAPHID.WINK, '')
        except CtapError as e:
            print('wink failed:', e)
        print('PASS: wink')

        try:
            r = self.send_data(CTAPHID.WINK, 'we9gofrei8g')
            raise RuntimeError('Wink is not supposed to have payload')
        except CtapError as e:
            assert(e.code == CtapError.ERR.INVALID_LENGTH)
        print('PASS: malformed wink')

        try:
            r = self.send_data(CTAPHID.CBOR, '')
            raise RuntimeError('Cbor is supposed to have payload')
        except CtapError as e:
            assert(e.code == CtapError.ERR.INVALID_LENGTH)
        print('PASS: no data cbor')

        try:
            r = self.send_data(CTAPHID.MSG, '')
            raise RuntimeError('MSG is supposed to have payload')
        except CtapError as e:
            assert(e.code == CtapError.ERR.INVALID_LENGTH)
        print('PASS: no data msg')

        try:
            r = self.send_data(CTAPHID.INIT, '\x11\x22\x33\x44\x55\x66\x77\x88')
        except CtapError as e:
            raise RuntimeError('resync fail: ', e)
        print('PASS: resync')

        try:
            r = self.send_data(0x66, '')
            raise RuntimeError('Invalid command did not return error')
        except CtapError as e:
            assert(e.code == CtapError.ERR.INVALID_COMMAND)
        print('PASS: invalid HID command')


        print('Sending packet with too large of a length.')
        self.send_raw('\x80\x1d\xba\x00')
        cmd,resp = self.recv_raw()
        self.check_error(resp, CtapError.ERR.INVALID_LENGTH)
        print('PASS: invalid length')

        print('Sending packets that skip a sequence number.')
        self.send_raw('\x81\x10\x00')
        self.send_raw('\x00')
        self.send_raw('\x01')
        self.send_raw('\x02')
        # skip 3
        self.send_raw('\x04')
        cmd,resp = self.recv_raw()
        self.check_error(resp, CtapError.ERR.INVALID_SEQ)
        print('PASS: invalid sequence')

        print('Resync and send ping')
        try:
            r = self.send_data(CTAPHID.INIT, '\x11\x22\x33\x44\x55\x66\x77\x88')
            pingdata = os.urandom(100)
            r = self.send_data(CTAPHID.PING, pingdata)
            if (r != pingdata):
                raise ValueError('Ping data not echo\'d')
        except CtapError as e:
            raise RuntimeError('resync fail: ', e)
        print('PASS: resync and ping')

        print('Send ping and abort it')
        self.send_raw('\x81\x10\x00')
        self.send_raw('\x00')
        self.send_raw('\x01')
        try:
            r = self.send_data(CTAPHID.INIT, '\x11\x22\x33\x44\x55\x66\x77\x88')
        except CtapError as e:
            raise RuntimeError('resync fail: ', e)
        print('PASS: interrupt ping with resync')


        print('Send ping and abort it')

if __name__ == '__main__':
    t = Tester()
    t.find_device()
    t.test_hid()


