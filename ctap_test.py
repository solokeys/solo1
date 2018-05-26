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
import array,struct

# Set up a FIDO 2 client using the origin https://example.com


def ForceU2F(client,device):
    client.ctap = CTAP1(device)
    client.pin_protocol = None
    client._do_make_credential = client._ctap1_make_credential
    client._do_get_assertion = client._ctap1_get_assertion


class Tester():
    def __init__(self,):
        self.origin = 'https://examplo.org'

    def find_device(self,):
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            raise RuntimeError('No FIDO device found')
        self.dev = dev
        self.ctap = CTAP2(dev)


    def send_data(self, cmd, data):
        #print('<<', hexlify(data))
        if type(data) != type(b''):
            data = data.encode()
        with Timeout(1.0) as event:
            return self.dev.call(cmd, data,event)

    def test_hid(self,):
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
            r = self.send_data(CTAPHID.INIT, '')
        except CtapError as e:
            print('resync fail: ', e)
            return
        print('PASS: resync')





if __name__ == '__main__':
    t = Tester()
    t.find_device()
    t.test_hid()


