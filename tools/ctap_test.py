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

# Script for testing correctness of CTAP2/CTAP1 security token

from __future__ import print_function, absolute_import, unicode_literals
import sys, os, time, math
from random import randint
from binascii import hexlify
import array, struct, socket

from fido2.hid import CtapHidDevice, CTAPHID
from fido2.client import Fido2Client, ClientError
from fido2.ctap import CtapError
from fido2.ctap1 import CTAP1, ApduError, APDU
from fido2.ctap2 import ES256, PinProtocolV1
from fido2.utils import Timeout, sha256, hmac_sha256
from fido2.attestation import Attestation

from solo.fido2 import force_udp_backend
from solo.client import SoloClient


# Set up a FIDO 2 client using the origin https://example.com


def ForceU2F(client, device):
    client.ctap = CTAP1(device)
    client.pin_protocol = None
    client._do_make_credential = client._ctap1_make_credential
    client._do_get_assertion = client._ctap1_get_assertion


def VerifyAttestation(attest, data):
    verifier = Attestation.for_type(attest.fmt)
    verifier().verify(attest.att_statement, attest.auth_data, data.hash)


class Packet(object):
    def __init__(self, data):
        l = len(data)
        self.data = data

    def ToWireFormat(self,):
        return self.data

    @staticmethod
    def FromWireFormat(pkt_size, data):
        return Packet(data)


class Tester:
    def __init__(self,):
        self.origin = "https://examplo.org"
        self.host = "examplo.org"
        self.user_count = 10
        self.is_sim = False

    def find_device(self,):
        print(list(CtapHidDevice.list_devices()))
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            raise RuntimeError("No FIDO device found")
        self.dev = dev
        self.client = Fido2Client(dev, self.origin)
        self.ctap = self.client.ctap2
        self.ctap1 = CTAP1(dev)

        # consume timeout error
        # cmd,resp = self.recv_raw()

    def set_user_count(self, count):
        self.user_count = count

    def set_sim(self, b):
        self.is_sim = b

    def send_data(self, cmd, data):
        if type(data) != type(b""):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        with Timeout(1.0) as event:
            return self.dev.call(cmd, data, event)

    def send_raw(self, data, cid=None):
        if cid is None:
            cid = self.dev._dev.cid
        elif type(cid) != type(b""):
            cid = struct.pack("%dB" % len(cid), *[ord(x) for x in cid])
        if type(data) != type(b""):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        data = cid + data
        l = len(data)
        if l != 64:
            pad = "\x00" * (64 - l)
            pad = struct.pack("%dB" % len(pad), *[ord(x) for x in pad])
            data = data + pad
        data = list(data)
        assert len(data) == 64
        self.dev._dev.InternalSendPacket(Packet(data))

    def send_magic_reboot(self,):
        """
        For use in simulation and testing.  Random bytes that authentictor should detect
        and then restart itself.
        """
        magic_cmd = (
            b"\xac\x10\x52\xca\x95\xe5\x69\xde\x69\xe0\x2e\xbf"
            + b"\xf3\x33\x48\x5f\x13\xf9\xb2\xda\x34\xc5\xa8\xa3"
            + b"\x40\x52\x66\x97\xa9\xab\x2e\x0b\x39\x4d\x8d\x04"
            + b"\x97\x3c\x13\x40\x05\xbe\x1a\x01\x40\xbf\xf6\x04"
            + b"\x5b\xb2\x6e\xb7\x7a\x73\xea\xa4\x78\x13\xf6\xb4"
            + b"\x9a\x72\x50\xdc"
        )
        self.dev._dev.InternalSendPacket(Packet(magic_cmd))

    def cid(self,):
        return self.dev._dev.cid

    def set_cid(self, cid):
        if type(cid) not in [type(b""), type(bytearray())]:
            cid = struct.pack("%dB" % len(cid), *[ord(x) for x in cid])
        self.dev._dev.cid = cid

    def recv_raw(self,):
        with Timeout(1.0) as t:
            cmd, payload = self.dev._dev.InternalRecv()
        return cmd, payload

    def check_error(self, data, err=None):
        assert len(data) == 1
        if err is None:
            if data[0] != 0:
                raise CtapError(data[0])
        elif data[0] != err:
            raise ValueError("Unexpected error: %02x" % data[0])

    def test_long_ping(self):
        amt = 1000
        pingdata = os.urandom(amt)
        try:
            t1 = time.time() * 1000
            r = self.send_data(CTAPHID.PING, pingdata)
            t2 = time.time() * 1000
            delt = t2 - t1
            # if (delt < 140 ):
            # raise RuntimeError('Fob is too fast (%d ms)' % delt)
            if delt > 555 * (amt / 1000):
                raise RuntimeError("Fob is too slow (%d ms)" % delt)
            if r != pingdata:
                raise ValueError("Ping data not echo'd")
            print("1000 byte ping time: %s ms" % delt)
        except CtapError as e:
            print("7609 byte Ping failed:", e)
            raise RuntimeError("ping failed")
        print("PASS: 7609 byte ping")
        # sys.flush(sys.sto)
        sys.stdout.flush()

    def test_hid(self, check_timeouts=False):
        if check_timeouts:
            print("Test idle")
            try:
                cmd, resp = self.recv_raw()
            except socket.timeout:
                print("Pass: Idle")

        print("Test init")
        r = self.send_data(CTAPHID.INIT, "\x11\x11\x11\x11\x11\x11\x11\x11")

        pingdata = os.urandom(100)
        try:
            r = self.send_data(CTAPHID.PING, pingdata)
            if r != pingdata:
                raise ValueError("Ping data not echo'd")
        except CtapError as e:
            print("100 byte Ping failed:", e)
            raise RuntimeError("ping failed")
        print("PASS: 100 byte ping")

        self.test_long_ping()

        try:
            r = self.send_data(CTAPHID.WINK, "")
            print(hexlify(r))
            # assert(len(r) == 0)
        except CtapError as e:
            print("wink failed:", e)
            raise RuntimeError("wink failed")
        print("PASS: wink")

        # try:
        # r = self.send_data(CTAPHID.WINK, 'we9gofrei8g')
        # raise RuntimeError('Wink is not supposed to have payload')
        # except CtapError as e:
        # assert(e.code == CtapError.ERR.INVALID_LENGTH)
        # print('PASS: malformed wink')

        try:
            r = self.send_data(CTAPHID.CBOR, "")
            if len(r) > 1 or r[0] == 0:
                raise RuntimeError("Cbor is supposed to have payload")
        except CtapError as e:
            assert e.code == CtapError.ERR.INVALID_LENGTH
        print("PASS: no data cbor")

        try:
            r = self.send_data(CTAPHID.MSG, "")
            print(hexlify(r))
            if len(r) > 2:
                raise RuntimeError("MSG is supposed to have payload")
        except CtapError as e:
            assert e.code == CtapError.ERR.INVALID_LENGTH
        print("PASS: no data msg")

        try:
            r = self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
        except CtapError as e:
            raise RuntimeError("resync fail: ", e)
        print("PASS: resync")

        try:
            r = self.send_data(0x66, "")
            raise RuntimeError("Invalid command did not return error")
        except CtapError as e:
            assert e.code == CtapError.ERR.INVALID_COMMAND
        print("PASS: invalid HID command")

        print("Sending packet with too large of a length.")
        self.send_raw("\x81\x1d\xba\x00")
        cmd, resp = self.recv_raw()
        self.check_error(resp, CtapError.ERR.INVALID_LENGTH)
        print("PASS: invalid length")

        r = self.send_data(CTAPHID.PING, "\x44" * 200)
        print("Sending packets that skip a sequence number.")
        self.send_raw("\x81\x04\x90")
        self.send_raw("\x00")
        self.send_raw("\x01")
        # skip 2
        self.send_raw("\x03")
        cmd, resp = self.recv_raw()
        self.check_error(resp, CtapError.ERR.INVALID_SEQ)
        if check_timeouts:
            cmd, resp = self.recv_raw()
            assert cmd == 0xBF  # timeout
        print("PASS: invalid sequence")

        print("Resync and send ping")
        try:
            r = self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
            pingdata = os.urandom(100)
            r = self.send_data(CTAPHID.PING, pingdata)
            if r != pingdata:
                raise ValueError("Ping data not echo'd")
        except CtapError as e:
            raise RuntimeError("resync fail: ", e)
        print("PASS: resync and ping")

        print("Send ping and abort it")
        self.send_raw("\x81\x04\x00")
        self.send_raw("\x00")
        self.send_raw("\x01")
        try:
            r = self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
        except CtapError as e:
            raise RuntimeError("resync fail: ", e)
        print("PASS: interrupt ping with resync")

        print("Send ping and abort it with different cid, expect timeout")
        oldcid = self.cid()
        newcid = "\x11\x22\x33\x44"
        self.send_raw("\x81\x10\x00")
        self.send_raw("\x00")
        self.send_raw("\x01")
        self.set_cid(newcid)
        self.send_raw(
            "\x86\x00\x08\x11\x22\x33\x44\x55\x66\x77\x88"
        )  # init from different cid
        print("wait for init response")
        cmd, r = self.recv_raw()  # init response
        assert cmd == 0x86
        self.set_cid(oldcid)
        if check_timeouts:
            # print('wait for timeout')
            cmd, r = self.recv_raw()  # timeout response
            assert cmd == 0xBF

        print("PASS: resync and timeout")

        print("Test timeout")
        self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
        t1 = time.time() * 1000
        self.send_raw("\x81\x04\x00")
        self.send_raw("\x00")
        self.send_raw("\x01")
        cmd, r = self.recv_raw()  # timeout response
        t2 = time.time() * 1000
        delt = t2 - t1
        assert cmd == 0xBF
        assert r[0] == CtapError.ERR.TIMEOUT
        assert delt < 1000 and delt > 400
        print("Pass timeout")

        print("Test not cont")
        self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
        self.send_raw("\x81\x04\x00")
        self.send_raw("\x00")
        self.send_raw("\x01")
        self.send_raw("\x81\x10\x00")  # init packet
        cmd, r = self.recv_raw()  # timeout response
        assert cmd == 0xBF
        assert r[0] == CtapError.ERR.INVALID_SEQ
        print("PASS: Test not cont")

        if check_timeouts:
            print("Check random cont ignored")
            self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
            self.send_raw("\x01\x10\x00")
            try:
                cmd, r = self.recv_raw()  # timeout response
            except socket.timeout:
                pass
            print("PASS: random cont")

        print("Check busy")
        t1 = time.time() * 1000
        self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
        oldcid = self.cid()
        newcid = "\x11\x22\x33\x44"
        self.send_raw("\x81\x04\x00")
        self.set_cid(newcid)
        self.send_raw("\x81\x04\x00")
        cmd, r = self.recv_raw()  # busy response
        t2 = time.time() * 1000
        assert t2 - t1 < 100
        assert cmd == 0xBF
        assert r[0] == CtapError.ERR.CHANNEL_BUSY

        self.set_cid(oldcid)
        cmd, r = self.recv_raw()  # timeout response
        assert cmd == 0xBF
        assert r[0] == CtapError.ERR.TIMEOUT
        print("PASS: busy")

        print("Check busy interleaved")
        cid1 = "\x11\x22\x33\x44"
        cid2 = "\x01\x22\x33\x44"
        self.set_cid(cid2)
        self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
        self.set_cid(cid1)
        self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
        self.send_raw("\x81\x00\x63")  # echo 99 bytes first channel

        self.set_cid(cid2)  # send ping on 2nd channel
        self.send_raw("\x81\x00\x63")
        self.send_raw("\x00")

        cmd, r = self.recv_raw()  # busy response

        self.set_cid(cid1)  # finish 1st channel ping
        self.send_raw("\x00")

        self.set_cid(cid2)

        assert cmd == 0xBF
        assert r[0] == CtapError.ERR.CHANNEL_BUSY

        self.set_cid(cid1)
        cmd, r = self.recv_raw()  # ping response
        assert cmd == 0x81
        assert len(r) == 0x63

        if check_timeouts:
            cmd, r = self.recv_raw()  # timeout
            assert cmd == 0xBF
            assert r[0] == CtapError.ERR.TIMEOUT
        print("PASS: busy interleaved")

        if check_timeouts:
            print("Test idle, wait for timeout")
            sys.stdout.flush()
            try:
                cmd, resp = self.recv_raw()
            except socket.timeout:
                print("Pass: Idle")

        print("Test cid 0 is invalid")
        self.set_cid("\x00\x00\x00\x00")
        self.send_raw(
            "\x86\x00\x08\x11\x22\x33\x44\x55\x66\x77\x88", cid="\x00\x00\x00\x00"
        )
        cmd, r = self.recv_raw()  # timeout
        assert cmd == 0xBF
        assert r[0] == CtapError.ERR.INVALID_CHANNEL
        print("Pass: cid 0")

        print("Test invalid broadcast cid use")
        self.set_cid("\xff\xff\xff\xff")
        self.send_raw(
            "\x81\x00\x08\x11\x22\x33\x44\x55\x66\x77\x88", cid="\xff\xff\xff\xff"
        )
        cmd, r = self.recv_raw()  # timeout
        assert cmd == 0xBF
        assert r[0] == CtapError.ERR.INVALID_CHANNEL
        print("Pass: cid broadcast")

    def test_u2f(self,):
        chal = sha256(b"AAA")
        appid = sha256(b"BBB")
        lastc = 0

        regs = []

        print("Check version")
        assert self.ctap1.get_version() == "U2F_V2"
        print("Pass")

        print("Check bad INS")
        try:
            res = self.ctap1.send_apdu(0, 0, 0, 0, b"")
        except ApduError as e:
            assert e.code == 0x6D00
        print("Pass")

        print("Check bad CLA")
        try:
            res = self.ctap1.send_apdu(1, CTAP1.INS.VERSION, 0, 0, b"abc")
        except ApduError as e:
            assert e.code == 0x6E00
        print("Pass")

        for i in range(0, self.user_count):
            reg = self.ctap1.register(chal, appid)
            reg.verify(appid, chal)
            auth = self.ctap1.authenticate(chal, appid, reg.key_handle)
            auth.verify(appid, chal, reg.public_key)

            regs.append(reg)
            # check endianness
            if lastc:
                assert (auth.counter - lastc) < 10
            lastc = auth.counter
            if lastc > 0x80000000:
                print("WARNING: counter is unusually high: %04x" % lastc)
                assert 0

            print(
                "U2F reg + auth pass %d/%d (count: %02x)"
                % (i + 1, self.user_count, lastc)
            )

        print("Checking previous registrations...")
        for i in range(0, self.user_count):
            auth = self.ctap1.authenticate(chal, appid, regs[i].key_handle)
            auth.verify(appid, chal, regs[i].public_key)
            print("Auth pass %d/%d" % (i + 1, self.user_count))

        print("Check that all previous credentials are registered...")
        for i in range(0, self.user_count):
            try:
                auth = self.ctap1.authenticate(
                    chal, appid, regs[i].key_handle, check_only=True
                )
            except ApduError as e:
                # Indicates that key handle is registered
                assert e.code == APDU.USE_NOT_SATISFIED

            print("Check pass %d/%d" % (i + 1, self.user_count))

        print("Check an incorrect key handle is not registered")
        kh = bytearray(regs[0].key_handle)
        kh[0] = kh[0] ^ (0x40)
        try:
            self.ctap1.authenticate(chal, appid, kh, check_only=True)
            assert 0
        except ApduError as e:
            assert e.code == APDU.WRONG_DATA
            print("Pass")

        print("Try to sign with incorrect key handle")
        try:
            self.ctap1.authenticate(chal, appid, kh)
            assert 0
        except ApduError as e:
            assert e.code == APDU.WRONG_DATA
            print("Pass")

        print("Try to sign using an incorrect keyhandle length")
        try:
            kh = regs[0].key_handle
            self.ctap1.authenticate(chal, appid, kh[: len(kh) // 2])
            assert 0
        except ApduError as e:
            assert e.code == APDU.WRONG_DATA
            print("Pass")

        print("Try to sign using an incorrect appid")
        badid = bytearray(appid)
        badid[0] = badid[0] ^ (0x40)
        try:
            auth = self.ctap1.authenticate(chal, badid, regs[0].key_handle)
            assert 0
        except ApduError as e:
            assert e.code == APDU.WRONG_DATA
            print("Pass")

    def test_fido2_simple(self, pin_token=None):
        creds = []
        exclude_list = []
        rp = {"id": self.host, "name": "ExaRP"}
        user = {"id": b"usee_od", "name": "AB User"}
        challenge = "Y2hhbGxlbmdl"
        PIN = pin_token

        fake_id1 = array.array("B", [randint(0, 255) for i in range(0, 150)]).tobytes()
        fake_id2 = array.array("B", [randint(0, 255) for i in range(0, 73)]).tobytes()

        exclude_list.append({"id": fake_id1, "type": "public-key"})
        exclude_list.append({"id": fake_id2, "type": "public-key"})

        print("MC")
        t1 = time.time() * 1000
        attest, data = self.client.make_credential(
            rp, user, challenge, pin=PIN, exclude_list=[]
        )
        t2 = time.time() * 1000
        VerifyAttestation(attest, data)
        print("Register valid (%d ms)" % (t2 - t1))

        cred = attest.auth_data.credential_data
        creds.append(cred)

        allow_list = [{"id": creds[0].credential_id, "type": "public-key"}]
        t1 = time.time() * 1000
        assertions, client_data = self.client.get_assertion(
            rp["id"], challenge, allow_list, pin=PIN
        )
        t2 = time.time() * 1000
        assertions[0].verify(client_data.hash, creds[0].public_key)

        print("Assertion valid (%d ms)" % (t2 - t1))

    def test_fido2_brute_force(self):
        creds = []
        exclude_list = []
        rp = {"id": self.host, "name": "ExaRP"}
        user = {"id": b"usee_od", "name": "AB User"}
        PIN = None
        abc = "abcdefghijklnmopqrstuvwxyz"
        abc += abc.upper()

        self.ctap.reset()

        for i in range(0, 2048 ** 2):
            creds = []

            challenge = "".join([abc[randint(0, len(abc) - 1)] for x in range(0, 32)])

            fake_id1 = array.array(
                "B", [randint(0, 255) for i in range(0, 150)]
            ).tostring()
            fake_id2 = array.array(
                "B", [randint(0, 255) for i in range(0, 73)]
            ).tostring()

            exclude_list.append({"id": fake_id1, "type": "public-key"})
            exclude_list.append({"id": fake_id2, "type": "public-key"})

            # for i in range(0,2048**2):
            for i in range(0, 1):
                t1 = time.time() * 1000
                attest, data = self.client.make_credential(
                    rp, user, challenge, pin=PIN, exclude_list=[]
                )
                print(attest.auth_data.counter)
                t2 = time.time() * 1000
                VerifyAttestation(attest, data)
                print("Register valid (%d ms)" % (t2 - t1))
            sys.stdout.flush()

            cred = attest.auth_data.credential_data
            creds.append(cred)

            # for i in range(0,2048**2):
            for i in range(0, 1):
                allow_list = [{"id": creds[0].credential_id, "type": "public-key"}]
                t1 = time.time() * 1000
                assertions, client_data = self.client.get_assertion(
                    rp["id"], challenge, allow_list, pin=PIN
                )
                t2 = time.time() * 1000
                assertions[0].verify(client_data.hash, creds[0].public_key)
                print(assertions[0].auth_data.counter)

                print("Assertion valid (%d ms)" % (t2 - t1))
                sys.stdout.flush()

    def test_fido2(self):
        def test(self, pincode=None):
            creds = []
            exclude_list = []
            rp = {"id": self.host, "name": "ExaRP"}
            user = {"id": b"usee_od", "name": "AB User"}
            challenge = "Y2hhbGxlbmdl"
            PIN = pincode

            fake_id1 = array.array(
                "B", [randint(0, 255) for i in range(0, 150)]
            ).tostring()
            fake_id2 = array.array(
                "B", [randint(0, 255) for i in range(0, 73)]
            ).tostring()

            exclude_list.append({"id": fake_id1, "type": "public-key"})
            exclude_list.append({"id": fake_id2, "type": "public-key"})

            # test make credential
            print("make %d credentials" % self.user_count)
            lastc = 0
            for i in range(0, self.user_count):
                attest, data = self.client.make_credential(
                    rp, user, challenge, pin=PIN, exclude_list=[]
                )
                VerifyAttestation(attest, data)

                # verify counter is correct
                if lastc > 0:
                    assert attest.auth_data.counter - lastc < 10
                    assert attest.auth_data.counter - lastc > 0
                assert attest.auth_data.counter < 0x10000
                lastc = attest.auth_data.counter

                cred = attest.auth_data.credential_data
                creds.append(cred)
                print(cred)
            print("PASS")

            if PIN is not None:
                print("make credential with wrong pin code")
                try:
                    attest, data = self.client.make_credential(
                        rp, user, challenge, pin=PIN + " ", exclude_list=[]
                    )
                except CtapError as e:
                    assert e.code == CtapError.ERR.PIN_INVALID
                except ClientError as e:
                    assert e.cause.code == CtapError.ERR.PIN_INVALID
                print("PASS")

            print("make credential with exclude list")
            attest, data = self.client.make_credential(
                rp, user, challenge, pin=PIN, exclude_list=exclude_list
            )
            VerifyAttestation(attest, data)
            cred = attest.auth_data.credential_data
            creds.append(cred)
            print("PASS")

            print("make credential with exclude list including real credential")
            real_excl = [{"id": cred.credential_id, "type": "public-key"}]
            try:
                attest, data = self.client.make_credential(
                    rp, user, challenge, pin=PIN, exclude_list=exclude_list + real_excl
                )
                raise RuntimeError("Exclude list did not return expected error")
            except CtapError as e:
                assert e.code == CtapError.ERR.CREDENTIAL_EXCLUDED
            except ClientError as e:
                assert e.cause.code == CtapError.ERR.CREDENTIAL_EXCLUDED
            print("PASS")

            for i, x in enumerate(creds):
                print("get assertion %d" % i)
                allow_list = [{"id": x.credential_id, "type": "public-key"}]
                assertions, client_data = self.client.get_assertion(
                    rp["id"], challenge, allow_list, pin=PIN
                )
                assertions[0].verify(client_data.hash, x.public_key)
                print("PASS")

            if PIN is not None:
                print("get assertion with wrong pin code")
                try:
                    assertions, client_data = self.client.get_assertion(
                        rp["id"], challenge, allow_list, pin=PIN + " "
                    )
                except CtapError as e:
                    assert e.code == CtapError.ERR.PIN_INVALID
                except ClientError as e:
                    assert e.cause.code == CtapError.ERR.PIN_INVALID
                print("PASS")

            print("get multiple assertions")
            allow_list = [{"id": x.credential_id, "type": "public-key"} for x in creds]
            assertions, client_data = self.client.get_assertion(
                rp["id"], challenge, allow_list, pin=PIN
            )

            for ass, cred in zip(assertions, creds):
                i += 1

                ass.verify(client_data.hash, cred.public_key)
                print("%d verified" % i)
            print("PASS")

        print("Reset device")
        try:
            self.ctap.reset()
        except CtapError as e:
            print("Warning, reset failed: ", e)
            pass
        print("PASS")

        test(self, None)

        print("Set a pin code")
        PIN = "1122aabbwfg0h9g !@#=="
        self.client.pin_protocol.set_pin(PIN)
        print("PASS")

        print("Illegally set pin code again")
        try:
            self.client.pin_protocol.set_pin(PIN)
        except CtapError as e:
            assert e.code == CtapError.ERR.NOT_ALLOWED
        print("PASS")

        print("Change pin code")
        PIN2 = PIN + "_pin2"
        self.client.pin_protocol.change_pin(PIN, PIN2)
        PIN = PIN2
        print("PASS")

        print("Change pin code using wrong pin")
        try:
            self.client.pin_protocol.change_pin(PIN.replace("a", "b"), "1234")
        except CtapError as e:
            assert e.code == CtapError.ERR.PIN_INVALID
        print("PASS")

        print("MC using wrong pin")
        try:
            self.test_fido2_simple("abcd3")
        except ClientError as e:
            assert e.cause.code == CtapError.ERR.PIN_INVALID
        print("PASS")

        print("get info")
        inf = self.ctap.get_info()
        print("PASS")

        self.test_fido2_simple(PIN)

        print("Re-run make_credential and get_assertion tests with pin code")
        test(self, PIN)

        print("Reset device")
        try:
            self.ctap.reset()
        except CtapError as e:
            print("Warning, reset failed: ", e)
        print("PASS")

    def test_fido2_other(self,):

        creds = []
        exclude_list = []
        rp = {"id": self.host, "name": "ExaRP"}
        rp2 = {"id": "solokeys.com", "name": "ExaRP"}
        user = {"id": b"usee_od", "name": "AB User"}
        user1 = {"id": b"1234567890", "name": "Conor Patrick"}
        user2 = {"id": b"oiewhfoi", "name": "Han Solo"}
        user3 = {"id": b"23ohfpjwo@@", "name": "John Smith"}
        challenge = "Y2hhbGxlbmdl"
        pin_protocol = 1
        key_params = [{"type": "public-key", "alg": ES256.ALGORITHM}]
        cdh = b"123456789abcdef0123456789abcdef0"

        def testFunc(func, test, *args, **kwargs):
            print(test)
            res = None
            expectedError = kwargs.get("expectedError", None)
            otherArgs = kwargs.get("other", {})
            try:
                res = func(*args, **otherArgs)
                if expectedError != CtapError.ERR.SUCCESS:
                    raise RuntimeError("Expected error to occur for test: %s" % test)
            except CtapError as e:
                if expectedError is not None:
                    if e.code != expectedError:
                        raise RuntimeError(
                            "Got error code 0x%x, expected %x" % (e.code, expectedError)
                        )
                else:
                    print(e)
            print("Pass")
            return res

        def testReset():
            print("Resetting Authenticator...")
            self.ctap.reset()

        def testMC(test, *args, **kwargs):
            return testFunc(self.ctap.make_credential, test, *args, **kwargs)

        def testGA(test, *args, **kwargs):
            return testFunc(self.ctap.get_assertion, test, *args, **kwargs)

        def testCP(test, *args, **kwargs):
            return testFunc(self.ctap.client_pin, test, *args, **kwargs)

        def testPP(test, *args, **kwargs):
            return testFunc(
                self.client.pin_protocol.get_pin_token, test, *args, **kwargs
            )

        def reboot():
            if self.is_sim:
                print("Sending restart command...")
                self.send_magic_reboot()
                time.sleep(0.25)
            else:
                print("Please reboot authentictor and hit enter")
                input()
                self.find_device()

        testReset()

        print("Get info")
        info = self.ctap.get_info()

        print(info)
        print("Pass")

        print("Check FIDO2 string is in VERSIONS field")
        assert "FIDO_2_0" in info.versions
        print("Pass")

        print("Check pin protocols field")
        if len(info.pin_protocols):
            assert sum(info.pin_protocols) > 0
        print("Pass")

        print("Check options field")
        for x in info.options:
            assert info.options[x] in [True, False]
        print("Pass")

        prev_reg = testMC(
            "Send MC request, expect success",
            cdh,
            rp,
            user,
            key_params,
            expectedError=CtapError.ERR.SUCCESS,
        )

        print("Check attestation format is correct")
        assert prev_reg.fmt in ["packed", "tpm", "android-key", "adroid-safetynet"]
        print("Pass")

        print("Check auth_data is at least 77 bytes")
        assert len(prev_reg.auth_data) >= 77
        print("Pass")

        allow_list = [
            {
                "id": prev_reg.auth_data.credential_data.credential_id,
                "type": "public-key",
            }
        ]

        prev_auth = testGA(
            "Send GA request, expect success",
            rp["id"],
            cdh,
            allow_list,
            expectedError=CtapError.ERR.SUCCESS,
        )

        print("Test auth_data is 37 bytes")
        assert len(prev_auth.auth_data) == 37
        print("pass")

        print("Test that auth_data.rpIdHash is correct")
        assert sha256(rp["id"].encode()) == prev_auth.auth_data.rp_id_hash
        print("Pass")

        print("Check that AT flag is not set")
        assert (prev_auth.auth_data.flags & 0xF8) == 0
        print("Pass")

        print("Test that user, credential and numberOfCredentials are not present")
        assert prev_auth.user == None
        assert prev_auth.number_of_credentials == None
        # assert prev_auth.credential == None # TODO double check this
        print("Pass")

        testGA(
            "Send GA request with empty allow_list, expect NO_CREDENTIALS",
            rp["id"],
            cdh,
            [],
            expectedError=CtapError.ERR.NO_CREDENTIALS,
        )

        # apply bit flip
        badid = list(prev_reg.auth_data.credential_data.credential_id[:])
        badid[len(badid) // 2] = badid[len(badid) // 2] ^ 1
        badid = bytes(badid)

        testGA(
            "Send GA request with corrupt credId in allow_list, expect NO_CREDENTIALS",
            rp["id"],
            cdh,
            [{"id": badid, "type": "public-key"}],
            expectedError=CtapError.ERR.NO_CREDENTIALS,
        )

        testMC(
            "Send MC request with missing clientDataHash, expect error",
            None,
            rp,
            user,
            key_params,
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        testMC(
            "Send MC request with integer for clientDataHash, expect error",
            5,
            rp,
            user,
            key_params,
        )

        testMC(
            "Send MC request with missing user, expect error",
            cdh,
            rp,
            None,
            key_params,
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        testMC(
            "Send MC request with bytearray user, expect error",
            cdh,
            rp,
            b"1234abcd",
            key_params,
        )

        testMC(
            "Send MC request with missing RP, expect error",
            cdh,
            None,
            user,
            key_params,
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        testMC(
            "Send MC request with bytearray RP, expect error",
            cdh,
            b"1234abcd",
            user,
            key_params,
        )

        testMC(
            "Send MC request with missing pubKeyCredParams, expect error",
            cdh,
            rp,
            user,
            None,
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        testMC(
            "Send MC request with incorrect pubKeyCredParams, expect error",
            cdh,
            rp,
            user,
            b"2356",
        )

        testMC(
            "Send MC request with incorrect excludeList, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"exclude_list": 8},
        )

        testMC(
            "Send MC request with incorrect extensions, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"extensions": 8},
        )

        testMC(
            "Send MC request with incorrect options, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"options": 8},
        )

        testMC(
            "Send MC request with bad RP.name",
            cdh,
            {"id": self.host, "name": 8, "icon": "icon"},
            user,
            key_params,
        )

        testMC(
            "Send MC request with bad RP.id",
            cdh,
            {"id": 8, "name": "name", "icon": "icon"},
            user,
            key_params,
        )

        testMC(
            "Send MC request with bad RP.icon",
            cdh,
            {"id": self.host, "name": "name", "icon": 8},
            user,
            key_params,
        )

        testMC(
            "Send MC request with bad user.name",
            cdh,
            rp,
            {"id": b"usee_od", "name": 8},
            key_params,
        )

        testMC(
            "Send MC request with bad user.id",
            cdh,
            rp,
            {"id": "usee_od", "name": "name"},
            key_params,
        )

        testMC(
            "Send MC request with bad user.displayName",
            cdh,
            rp,
            {"id": "usee_od", "name": "name", "displayName": 8},
            key_params,
        )

        testMC(
            "Send MC request with bad user.icon",
            cdh,
            rp,
            {"id": "usee_od", "name": "name", "icon": 8},
            key_params,
        )

        testMC(
            "Send MC request with non-map pubKeyCredParams item",
            cdh,
            rp,
            user,
            ["wrong"],
        )

        testMC(
            "Send MC request with pubKeyCredParams item missing type field",
            cdh,
            rp,
            user,
            [{"alg": ES256.ALGORITHM}],
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        testMC(
            "Send MC request with pubKeyCredParams item with bad type field",
            cdh,
            rp,
            user,
            [{"alg": ES256.ALGORITHM, "type": b"public-key"}],
        )

        testMC(
            "Send MC request with pubKeyCredParams item missing alg",
            cdh,
            rp,
            user,
            [{"type": "public-key"}],
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        testMC(
            "Send MC request with pubKeyCredParams item with bad alg",
            cdh,
            rp,
            user,
            [{"alg": "7", "type": "public-key"}],
        )

        testMC(
            "Send MC request with pubKeyCredParams item with bogus alg, expect UNSUPPORTED_ALGORITHM",
            cdh,
            rp,
            user,
            [{"alg": 1234, "type": "public-key"}],
            expectedError=CtapError.ERR.UNSUPPORTED_ALGORITHM,
        )

        testMC(
            "Send MC request with pubKeyCredParams item with bogus type, expect UNSUPPORTED_ALGORITHM",
            cdh,
            rp,
            user,
            [{"alg": ES256.ALGORITHM, "type": "rot13"}],
            expectedError=CtapError.ERR.UNSUPPORTED_ALGORITHM,
        )

        testMC(
            "Send MC request with excludeList item with bogus type, expect SUCCESS",
            cdh,
            rp,
            user,
            key_params,
            expectedError=CtapError.ERR.SUCCESS,
            other={"exclude_list": [{"id": b"1234", "type": "rot13"}]},
        )

        testMC(
            "Send MC request with excludeList with bad item, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"exclude_list": ["1234"]},
        )

        testMC(
            "Send MC request with excludeList with item missing type field, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"exclude_list": [{"id": b"1234"}]},
        )

        testMC(
            "Send MC request with excludeList with item missing id field, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"exclude_list": [{"type": "public-key"}]},
        )

        testMC(
            "Send MC request with excludeList with item containing bad id field, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"exclude_list": [{"type": "public-key", "id": "1234"}]},
        )

        testMC(
            "Send MC request with excludeList with item containing bad type field, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"exclude_list": [{"type": b"public-key", "id": b"1234"}]},
        )

        testMC(
            "Send MC request with excludeList containing previous registration, expect CREDENTIAL_EXCLUDED",
            cdh,
            rp,
            user,
            key_params,
            other={
                "exclude_list": [
                    {
                        "type": "public-key",
                        "id": prev_reg.auth_data.credential_data.credential_id,
                    }
                ]
            },
            expectedError=CtapError.ERR.CREDENTIAL_EXCLUDED,
        )

        testMC(
            "Send MC request with unknown option, expect SUCCESS",
            cdh,
            rp,
            user,
            key_params,
            other={"options": {"unknown": False}},
            expectedError=CtapError.ERR.SUCCESS,
        )

        if "uv" in info.options:
            if info.options["uv"]:
                testMC(
                    "Send MC request with uv set to true, expect SUCCESS",
                    cdh,
                    rp,
                    user,
                    key_params,
                    other={"options": {"uv": True}},
                    expectedError=CtapError.ERR.SUCCESS,
                )
        if "up" in info.options:
            if info.options["up"]:
                testMC(
                    "Send MC request with up set to true, expect INVALID_OPTION",
                    cdh,
                    rp,
                    user,
                    key_params,
                    other={"options": {"up": True}},
                    expectedError=CtapError.ERR.INVALID_OPTION,
                )

        testGA(
            "Send GA request with missing RPID, expect MISSING_PARAMETER",
            None,
            cdh,
            allow_list,
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        testGA(
            "Send GA request with bad RPID, expect error",
            {"type": "wrong"},
            cdh,
            allow_list,
        )

        testGA(
            "Send GA request with missing clientDataHash, expect MISSING_PARAMETER",
            rp["id"],
            None,
            allow_list,
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        testGA(
            "Send GA request with bad clientDataHash, expect error",
            rp["id"],
            {"type": "wrong"},
            allow_list,
        )

        testGA(
            "Send GA request with bad allow_list, expect error",
            rp["id"],
            cdh,
            {"type": "wrong"},
        )

        testGA(
            "Send GA request with bad item in allow_list, expect error",
            rp["id"],
            cdh,
            allow_list + ["wrong"],
        )

        testGA(
            "Send GA request with unknown option, expect SUCCESS",
            rp["id"],
            cdh,
            allow_list,
            other={"options": {"unknown": True}},
            expectedError=CtapError.ERR.SUCCESS,
        )

        if "uv" in info.options:
            if info.options["uv"]:
                res = testGA(
                    "Send GA request with uv set to true, expect SUCCESS",
                    rp["id"],
                    cdh,
                    allow_list,
                    other={"options": {"uv": True}},
                    expectedError=CtapError.ERR.SUCCESS,
                )
                print("Check that UV flag is set in response")
                assert res.auth_data.flags & (1 << 2)
                print("Pass")
        if "up" in info.options:
            if info.options["up"]:
                res = testGA(
                    "Send GA request with up set to true, expect SUCCESS",
                    rp["id"],
                    cdh,
                    allow_list,
                    other={"options": {"up": True}},
                    expectedError=CtapError.ERR.SUCCESS,
                )
                print("Check that UP flag is set in response")
                assert res.auth_data.flags & 1
                print("Pass")

        testGA(
            "Send GA request with bogus type item in allow_list, expect SUCCESS",
            rp["id"],
            cdh,
            allow_list + [{"type": "rot13", "id": b"1234"}],
            expectedError=CtapError.ERR.SUCCESS,
        )

        testGA(
            "Send GA request with item missing type field in allow_list, expect error",
            rp["id"],
            cdh,
            allow_list + [{"id": b"1234"}],
        )

        testGA(
            "Send GA request with item containing bad type field in allow_list, expect error",
            rp["id"],
            cdh,
            allow_list + [{"type": b"public-key", "id": b"1234"}],
        )

        testGA(
            "Send GA request with item containing bad id in allow_list, expect error",
            rp["id"],
            cdh,
            allow_list + [{"type": b"public-key", "id": 42}],
        )

        testGA(
            "Send GA request with item missing id in allow_list, expect error",
            rp["id"],
            cdh,
            allow_list + [{"type": b"public-key"}],
        )

        testReset()

        def testRk(pin_code=None):
            testGA(
                "Send GA request with reset auth, expect NO_CREDENTIALS",
                rp["id"],
                cdh,
                allow_list,
                expectedError=CtapError.ERR.NO_CREDENTIALS,
            )

            pin_auth = None
            if pin_code:
                print("Setting pin code ...")
                self.client.pin_protocol.set_pin(pin_code)
                pin_token = self.client.pin_protocol.get_pin_token(pin_code)
                pin_auth = hmac_sha256(pin_token, cdh)[:16]
                print("Pass")

            testMC(
                "Send MC request with rk option set to true, expect SUCCESS",
                cdh,
                rp,
                user,
                key_params,
                other={"options": {"rk": True}, "pin_auth": pin_auth},
                expectedError=CtapError.ERR.SUCCESS,
            )

            options = {"rk": True}
            if "uv" in info.options and info.options["uv"]:
                options["uv"] = False

            for i, x in enumerate([user1, user2, user3]):
                testMC(
                    "Send MC request with rk option set to true, expect SUCCESS %d/3"
                    % (i + 1),
                    cdh,
                    rp2,
                    x,
                    key_params,
                    other={"options": options, "pin_auth": pin_auth},
                    expectedError=CtapError.ERR.SUCCESS,
                )

            auth1 = testGA(
                "Send GA request with no allow_list, expect SUCCESS",
                rp2["id"],
                cdh,
                other={"options": options, "pin_auth": pin_auth},
                expectedError=CtapError.ERR.SUCCESS,
            )

            print("Check that there are 3 credentials returned")
            assert auth1.number_of_credentials == 3
            print("Pass")

            print("Get the next 2 assertions")
            auth2 = self.ctap.get_next_assertion()
            auth3 = self.ctap.get_next_assertion()
            print("Pass")

            if not pin_code:
                print("Check only the user ID was returned")
                assert "id" in auth1.user.keys() and len(auth1.user.keys()) == 1
                assert "id" in auth2.user.keys() and len(auth2.user.keys()) == 1
                assert "id" in auth3.user.keys() and len(auth3.user.keys()) == 1
                print("Pass")
            else:
                print("Check that all user info was returned")
                for x in (auth1, auth2, auth3):
                    for y in ("name", "icon", "displayName", "id"):
                        assert y in x.user.keys()
                    assert len(x.user.keys()) == 4
                print("Pass")

            print("Send an extra getNextAssertion request, expect error")
            try:
                auth4 = self.ctap.get_next_assertion()
                assert 0
            except CtapError as e:
                print(e)
            print("Pass")

        testRk(None)
        #
        # print("Assuming authenticator does NOT have a display.")
        pin1 = "1234567890"
        testRk("1234567890")

        # PinProtocolV1
        res = testCP(
            "Test getKeyAgreement, expect SUCCESS",
            pin_protocol,
            PinProtocolV1.CMD.GET_KEY_AGREEMENT,
            expectedError=CtapError.ERR.SUCCESS,
        )

        print("Test getKeyAgreement has appropriate fields")
        key = res[1]
        assert "Is public key" and key[1] == 2
        assert "Is P256" and key[-1] == 1
        assert "Is right alg" and key[3] == -7
        assert "Right key" and len(key[-3]) == 32 and type(key[-3]) == type(bytes())
        print("Pass")

        print("Test setting a new pin")
        pin2 = "qwertyuiop\x11\x22\x33\x00123"
        self.client.pin_protocol.change_pin(pin1, pin2)
        print("Pass")

        print("Test getting new pin_auth")
        pin_token = self.client.pin_protocol.get_pin_token(pin2)
        pin_auth = hmac_sha256(pin_token, cdh)[:16]
        print("Pass")

        res_mc = testMC(
            "Send MC request with new pin auth",
            cdh,
            rp,
            user,
            key_params,
            other={"pin_auth": pin_auth},
            expectedError=CtapError.ERR.SUCCESS,
        )

        print("Check UV flag is set")
        assert res_mc.auth_data.flags & (1 << 2)
        print("Pass")

        res_ga = testGA(
            "Send GA request with no allow_list, expect SUCCESS",
            rp["id"],
            cdh,
            [
                {
                    "type": "public-key",
                    "id": res_mc.auth_data.credential_data.credential_id,
                }
            ],
            other={"pin_auth": pin_auth},
            expectedError=CtapError.ERR.SUCCESS,
        )

        print("Check UV flag is set")
        assert res_ga.auth_data.flags & (1 << 2)
        print("Pass")

        testReset()

        print("Setting pin code, expect SUCCESS")
        self.client.pin_protocol.set_pin(pin1)
        print("Pass")

        testReset()

        # print("Setting pin code <4 bytes, expect POLICY_VIOLATION ")
        # try:
        #     self.client.pin_protocol.set_pin("123")
        # except CtapError as e:
        #     assert e.code == CtapError.ERR.POLICY_VIOLATION
        # print("Pass")

        print("Setting pin code >63 bytes, expect POLICY_VIOLATION ")
        try:
            self.client.pin_protocol.set_pin("A" * 64)
            assert 0
        except CtapError as e:
            assert e.code == CtapError.ERR.PIN_POLICY_VIOLATION
        print("Pass")

        print("Get pin token when no pin is set, expect PIN_NOT_SET")
        try:
            self.client.pin_protocol.get_pin_token(pin1)
            assert 0
        except CtapError as e:
            assert e.code == CtapError.ERR.PIN_NOT_SET

        print("Get change pin when no pin is set, expect PIN_NOT_SET")
        try:
            self.client.pin_protocol.change_pin(pin1, "1234")
            assert 0
        except CtapError as e:
            assert e.code == CtapError.ERR.PIN_NOT_SET
        print("Pass")

        print("Setting pin code and get pin_token, expect SUCCESS")
        self.client.pin_protocol.set_pin(pin1)
        pin_token = self.client.pin_protocol.get_pin_token(pin1)
        pin_auth = hmac_sha256(pin_token, cdh)[:16]
        print("Pass")

        print("Get info and assert that clientPin is set to true")
        info = self.ctap.get_info()
        assert info.options["clientPin"]
        print("Pass")

        print("Test setting pin again fails")
        try:
            self.client.pin_protocol.set_pin(pin1)
            assert 0
        except CtapError as e:
            print(e)
        print("Pass")

        res_mc = testMC(
            "Send MC request with no pin_auth, expect PIN_REQUIRED",
            cdh,
            rp,
            user,
            key_params,
            expectedError=CtapError.ERR.PIN_REQUIRED,
        )

        res_mc = testGA(
            "Send GA request with no pin_auth, expect PIN_REQUIRED",
            rp["id"],
            cdh,
            expectedError=CtapError.ERR.PIN_REQUIRED,
        )

        res = testCP(
            "Test getRetries, expect SUCCESS",
            pin_protocol,
            PinProtocolV1.CMD.GET_RETRIES,
            expectedError=CtapError.ERR.SUCCESS,
        )

        print("Check there is 8 pin attempts left")
        assert res[3] == 8
        print("Pass")

        # Flip 1 bit
        pin_wrong = list(pin1)
        c = pin1[len(pin1) // 2]

        pin_wrong[len(pin1) // 2] = chr(ord(c) ^ 1)
        pin_wrong = "".join(pin_wrong)

        for i in range(1, 3):
            testPP(
                "Get pin_token with wrong pin code, expect PIN_INVALID (%d/2)" % i,
                pin_wrong,
                expectedError=CtapError.ERR.PIN_INVALID,
            )
            print("Check there is %d pin attempts left" % (8 - i))
            res = self.ctap.client_pin(pin_protocol, PinProtocolV1.CMD.GET_RETRIES)
            assert res[3] == (8 - i)
            print("Pass")

        for i in range(1, 3):
            testPP(
                "Get pin_token with wrong pin code, expect PIN_AUTH_BLOCKED %d/2" % i,
                pin_wrong,
                expectedError=CtapError.ERR.PIN_AUTH_BLOCKED,
            )

        reboot()

        print("Get pin_token, expect SUCCESS")
        pin_token = self.client.pin_protocol.get_pin_token(pin1)
        pin_auth = hmac_sha256(pin_token, cdh)[:16]
        print("Pass")

        res_mc = testMC(
            "Send MC request with correct pin_auth",
            cdh,
            rp,
            user,
            key_params,
            other={"pin_auth": pin_auth},
            expectedError=CtapError.ERR.SUCCESS,
        )

        print("Test getRetries resets to 8")
        res = self.ctap.client_pin(pin_protocol, PinProtocolV1.CMD.GET_RETRIES)
        assert res[3] == (8)
        print("Pass")

        for i in range(1, 10):
            err = CtapError.ERR.PIN_INVALID
            if i in (3, 6):
                err = CtapError.ERR.PIN_AUTH_BLOCKED
            elif i >= 9:
                err = CtapError.ERR.PIN_BLOCKED
            testPP(
                "Lock out authentictor and check correct error codes %d/9" % i,
                pin_wrong,
                expectedError=err,
            )

            attempts = 8 - i
            if i > 8:
                attempts = 0

            print("Check there is %d pin attempts left" % attempts)
            res = self.ctap.client_pin(pin_protocol, PinProtocolV1.CMD.GET_RETRIES)
            assert res[3] == attempts

            print("Pass")

            if err == CtapError.ERR.PIN_AUTH_BLOCKED:
                reboot()

        res_mc = testMC(
            "Send MC request with correct pin_auth, expect PIN_BLOCKED",
            cdh,
            rp,
            user,
            key_params,
            other={"pin_auth": pin_auth},
            expectedError=CtapError.ERR.PIN_BLOCKED,
        )

        reboot()

        testPP(
            "Get pin_token with correct pin code, expect PIN_BLOCKED",
            pin1,
            expectedError=CtapError.ERR.PIN_BLOCKED,
        )

        testReset()

        print("Done")

    def test_rk(self,):
        creds = []
        rp = {"id": self.host, "name": "ExaRP"}

        users = [
            {"id": b"user" + os.urandom(16), "name": "Username%d" % i}
            for i in range(0, self.user_count)
        ]
        challenge = "Y2hhbGxlbmdl"
        PIN = None
        print("reset")
        self.ctap.reset()
        # if PIN: self.client.pin_protocol.set_pin(PIN)

        print("registering 1 user with RK")
        t1 = time.time() * 1000
        attest, data = self.client.make_credential(
            rp, users[-1], challenge, pin=PIN, exclude_list=[], rk=True
        )
        t2 = time.time() * 1000
        VerifyAttestation(attest, data)
        creds.append(attest.auth_data.credential_data)
        print("Register valid (%d ms)" % (t2 - t1))

        print("1 assertion")
        t1 = time.time() * 1000
        assertions, client_data = self.client.get_assertion(
            rp["id"], challenge, pin=PIN
        )
        t2 = time.time() * 1000
        assertions[0].verify(client_data.hash, creds[0].public_key)
        print("Assertion valid (%d ms)" % (t2 - t1))

        print(assertions[0], client_data)

        print("registering %d users with RK" % len(users))
        for i in range(0, len(users) - 1):
            t1 = time.time() * 1000
            attest, data = self.client.make_credential(
                rp, users[i], challenge, pin=PIN, exclude_list=[], rk=True
            )
            t2 = time.time() * 1000
            VerifyAttestation(attest, data)
            print("Register valid (%d ms)" % (t2 - t1))

            creds.append(attest.auth_data.credential_data)

        t1 = time.time() * 1000
        assertions, client_data = self.client.get_assertion(
            rp["id"], challenge, pin=PIN
        )
        t2 = time.time() * 1000

        print("Got %d assertions for %d users" % (len(assertions), len(users)))
        assert len(assertions) == len(users)

        for x, y in zip(assertions, creds):
            x.verify(client_data.hash, y.public_key)

        print("Assertion(s) valid (%d ms)" % (t2 - t1))

        print("registering a duplicate user ")

        t1 = time.time() * 1000
        attest, data = self.client.make_credential(
            rp, users[1], challenge, pin=PIN, exclude_list=[], rk=True
        )
        t2 = time.time() * 1000
        VerifyAttestation(attest, data)
        creds = creds[:2] + creds[3:] + [attest.auth_data.credential_data]
        print("Register valid (%d ms)" % (t2 - t1))

        t1 = time.time() * 1000
        assertions, client_data = self.client.get_assertion(
            rp["id"], challenge, pin=PIN
        )
        t2 = time.time() * 1000
        print("Assertions: %d, users: %d" % (len(assertions), len(users)))
        assert len(assertions) == len(users)
        for x, y in zip(assertions, creds):
            x.verify(client_data.hash, y.public_key)

        print("Assertion(s) valid (%d ms)" % (t2 - t1))

    def test_solo(self,):
        """
        Solo specific tests
        """
        # RNG command
        sc = SoloClient()
        sc.find_device(self.dev)
        sc.use_u2f()
        memmap = (0x08005000, 0x08005000 + 198 * 1024 - 8)

        total = 1024 * 16
        print("Gathering %d random bytes..." % total)
        entropy = b""
        while len(entropy) < total:
            entropy += sc.get_rng()
        total = len(entropy)
        print("Pass")

        print("Test entropy is close to perfect")
        sum = 0.0
        for x in range(0, 256):
            freq = entropy.count(x)
            p = freq / total
            sum -= p * math.log2(p)
        assert sum > 7.98
        print("Entropy is %.5f bits per byte. Pass" % sum)

        print("Test Solo version command")
        assert len(sc.solo_version()) == 3
        print("Pass")

        print("Test bootloader is not active")
        try:
            sc.write_flash(memmap[0], b"1234")
        except ApduError:
            pass
        print("Pass")

    def test_bootloader(self,):
        sc = SoloClient()
        sc.find_device(self.dev)
        sc.use_u2f()

        memmap = (0x08005000, 0x08005000 + 198 * 1024 - 8)
        data = b"A" * 64

        print("Test version command")
        assert len(sc.bootloader_version()) == 3
        print("Pass")

        print("Test write command")
        sc.write_flash(memmap[0], data)
        print("Pass")

        for addr in (memmap[0] - 8, memmap[0] - 4, memmap[1], memmap[1] - 8):
            print("Test out of bounds write command at 0x%04x" % addr)
            try:
                sc.write_flash(addr, data)
            except CtapError as e:
                assert e.code == CtapError.ERR.NOT_ALLOWED
            print("Pass")

    def test_responses(self,):
        PIN = "1234"
        RPID = self.host
        for dev in CtapHidDevice.list_devices():
            print("dev", dev)
            client = Fido2Client(dev, RPID)
            ctap = client.ctap2
            # ctap.reset()
            try:
                if PIN:
                    client.pin_protocol.set_pin(PIN)
            except:
                pass

            inf = ctap.get_info()
            # print (inf)
            print("versions: ", inf.versions)
            print("aaguid: ", inf.aaguid)
            print("rk: ", inf.options["rk"])
            print("clientPin: ", inf.options["clientPin"])
            print("max_message_size: ", inf.max_msg_size)

            # rp = {'id': 'SelectDevice', 'name': 'SelectDevice'}
            rp = {"id": RPID, "name": "ExaRP"}
            user = {"id": os.urandom(10), "name": "SelectDevice"}
            user = {"id": b"21first one", "name": "single User"}
            challenge = "Y2hhbGxlbmdl"

            if 1:
                attest, data = client.make_credential(
                    rp, user, challenge, exclude_list=[], pin=PIN, rk=True
                )

                cred = attest.auth_data.credential_data
                creds = [cred]

                allow_list = [{"id": creds[0].credential_id, "type": "public-key"}]
                allow_list = []
                assertions, client_data = client.get_assertion(
                    rp["id"], challenge, pin=PIN
                )
                assertions[0].verify(client_data.hash, creds[0].public_key)

            if 0:
                print("registering 1 user with RK")
                t1 = time.time() * 1000
                attest, data = client.make_credential(
                    rp, user, challenge, pin=PIN, exclude_list=[], rk=True
                )
                t2 = time.time() * 1000
                VerifyAttestation(attest, data)
                creds = [attest.auth_data.credential_data]
                print("Register valid (%d ms)" % (t2 - t1))

                print("1 assertion")
                t1 = time.time() * 1000
                assertions, client_data = client.get_assertion(
                    rp["id"], challenge, pin=PIN
                )
                t2 = time.time() * 1000
                assertions[0].verify(client_data.hash, creds[0].public_key)
                print("Assertion valid (%d ms)" % (t2 - t1))

            # print('fmt:',attest.fmt)
            # print('rp_id_hash',attest.auth_data.rp_id_hash)
            # print('flags:', hex(attest.auth_data.flags))
            # print('count:', hex(attest.auth_data.counter))
            print("flags MC:", attest.auth_data)
            print("flags GA:", assertions[0].auth_data)
            # print('cred_id:',attest.auth_data.credential_data.credential_id)
            # print('pubkey:',attest.auth_data.credential_data.public_key)
            # print('aaguid:',attest.auth_data.credential_data.aaguid)
            # print('cred data:',attest.auth_data.credential_data)
            # print('auth_data:',attest.auth_data)
            # print('auth_data:',attest.auth_data)
            # print('alg:',attest.att_statement['alg'])
            # print('sig:',attest.att_statement['sig'])
            # print('x5c:',attest.att_statement['x5c'])
            # print('data:',data)

            print("assertion:", assertions[0])
            print("clientData:", client_data)

            print()
            # break


def test_find_brute_force():
    i = 0
    while 1:
        t1 = time.time() * 1000
        t = Tester()
        t.find_device()
        t2 = time.time() * 1000
        print("connected %d (%d ms)" % (i, t2 - t1))
        i += 1
        time.sleep(0.01)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: %s [sim] <[u2f]|[fido2]|[rk]|[hid]|[ping]>")
        sys.exit(0)

    t = Tester()
    t.set_user_count(3)

    if "sim" in sys.argv:
        print("Using UDP backend.")
        force_udp_backend()
        t.set_sim(True)
        t.set_user_count(10)

    t.find_device()

    if "solo" in sys.argv:
        t.test_solo()

    if "u2f" in sys.argv:
        t.test_u2f()

    if "fido2" in sys.argv:
        t.test_fido2()
        t.test_fido2_other()

    if "rk" in sys.argv:
        t.test_rk()

    if "ping" in sys.argv:
        t.test_long_ping()

    # hid tests are a bit invasive and should be done last
    if "hid" in sys.argv:
        t.test_hid()

    if "bootloader" in sys.argv:
        if t.is_sim:
            raise RuntimeError("Cannot test bootloader in simulation yet.")
        print("Put device in bootloader mode and then hit enter")
        input()
        t.test_bootloader()

    # t.test_responses()
    # test_find_brute_force()
    # t.test_fido2_brute_force()
