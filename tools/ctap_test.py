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
import sys, os, time
from random import randint
from binascii import hexlify
import array, struct, socket

from fido2.hid import CtapHidDevice, CTAPHID
from fido2.client import Fido2Client, ClientError
from fido2.ctap import CtapError
from fido2.ctap1 import CTAP1, ApduError, APDU
from fido2.ctap2 import *
from fido2.cose import *
from fido2.utils import Timeout, sha256
from fido2.attestation import Attestation

from solo.fido2 import force_udp_backend


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
            if lastc > 0x100000:
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
            for i in range(0, self.user_count):
                attest, data = self.client.make_credential(
                    rp, user, challenge, pin=PIN, exclude_list=[]
                )
                VerifyAttestation(attest, data)
                # verify endian-ness is correct
                assert attest.auth_data.counter < 0x10000
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

    if "sim" in sys.argv:
        print("Using UDP backend.")
        force_udp_backend()

    t = Tester()
    t.find_device()
    t.set_user_count(15)

    if "u2f" in sys.argv:
        t.test_u2f()

    if "fido2" in sys.argv:
        t.test_fido2()
        t.test_fido2_simple()

    if "rk" in sys.argv:
        t.test_rk()

    if "ping" in sys.argv:
        t.test_long_ping()

    # hid tests are a bit invasive and should be done last
    if "hid" in sys.argv:
        t.test_hid()

    # t.test_responses()
    # test_find_brute_force()
    # t.test_fido2_brute_force()
