import sys, struct, os, time
from binascii import hexlify

from fido2.hid import CtapHidDevice, CTAPHID
from fido2.ctap import CtapError

from .tester import Tester, Test


class HIDTests(Tester):
    def __init__(self, tester=None):
        super().__init__(tester)
        self.check_timeouts = False

    def set_check_timeouts(self, en):
        self.check_timeouts = en

    def run(self,):
        self.test_long_ping()
        self.test_hid(self.check_timeouts)

    def test_long_ping(self):
        amt = 1000
        pingdata = os.urandom(amt)
        with Test("Send %d byte ping" % amt):
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
            except CtapError as e:
                raise RuntimeError("ping failed")

        sys.stdout.flush()

    def test_hid(self, check_timeouts=False):
        if check_timeouts:
            with Test("idle"):
                try:
                    cmd, resp = self.recv_raw()
                except socket.timeout:
                    pass

        with Test("init"):
            r = self.send_data(CTAPHID.INIT, "\x11\x11\x11\x11\x11\x11\x11\x11")

        with Test("100 byte ping"):
            pingdata = os.urandom(100)
            try:
                r = self.send_data(CTAPHID.PING, pingdata)
                if r != pingdata:
                    raise ValueError("Ping data not echo'd")
            except CtapError as e:
                print("100 byte Ping failed:", e)
                raise RuntimeError("ping failed")

        self.test_long_ping()

        with Test("Wink"):
            r = self.send_data(CTAPHID.WINK, "")

        with Test("CBOR msg with no data"):
            try:
                r = self.send_data(CTAPHID.CBOR, "")
                if len(r) > 1 or r[0] == 0:
                    raise RuntimeError("Cbor is supposed to have payload")
            except CtapError as e:
                assert e.code == CtapError.ERR.INVALID_LENGTH

        with Test("No data in U2F msg"):
            try:
                r = self.send_data(CTAPHID.MSG, "")
                print(hexlify(r))
                if len(r) > 2:
                    raise RuntimeError("MSG is supposed to have payload")
            except CtapError as e:
                assert e.code == CtapError.ERR.INVALID_LENGTH

        with Test("Use init command to resync"):
            r = self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")

        with Test("Invalid HID command"):
            try:
                r = self.send_data(0x66, "")
                raise RuntimeError("Invalid command did not return error")
            except CtapError as e:
                assert e.code == CtapError.ERR.INVALID_COMMAND

        with Test("Sending packet with too large of a length."):
            self.send_raw("\x81\x1d\xba\x00")
            cmd, resp = self.recv_raw()
            self.check_error(resp, CtapError.ERR.INVALID_LENGTH)

        r = self.send_data(CTAPHID.PING, "\x44" * 200)
        with Test("Sending packets that skip a sequence number."):
            self.send_raw("\x81\x04\x90")
            self.send_raw("\x00")
            self.send_raw("\x01")
            # skip 2
            self.send_raw("\x03")
            cmd, resp = self.recv_raw()
            self.check_error(resp, CtapError.ERR.INVALID_SEQ)

        with Test("Resync and send ping"):
            try:
                r = self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
                pingdata = os.urandom(100)
                r = self.send_data(CTAPHID.PING, pingdata)
                if r != pingdata:
                    raise ValueError("Ping data not echo'd")
            except CtapError as e:
                raise RuntimeError("resync fail: ", e)

        with Test("Send ping and abort it"):
            self.send_raw("\x81\x04\x00")
            self.send_raw("\x00")
            self.send_raw("\x01")
            try:
                r = self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
            except CtapError as e:
                raise RuntimeError("resync fail: ", e)

        with Test("Send ping and abort it with different cid, expect timeout"):
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

        with Test("Test timeout"):
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

        with Test("Test not cont"):
            self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
            self.send_raw("\x81\x04\x00")
            self.send_raw("\x00")
            self.send_raw("\x01")
            self.send_raw("\x81\x10\x00")  # init packet
            cmd, r = self.recv_raw()  # timeout response
            assert cmd == 0xBF
            assert r[0] == CtapError.ERR.INVALID_SEQ

        if check_timeouts:
            with Test("Check random cont ignored"):
                self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
                self.send_raw("\x01\x10\x00")
                try:
                    cmd, r = self.recv_raw()  # timeout response
                except socket.timeout:
                    pass

        with Test("Check busy"):
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

        with Test("Check busy interleaved"):
            cid1 = "\x11\x22\x33\x44"
            cid2 = "\x01\x22\x33\x44"
            self.set_cid(cid2)
            self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
            self.set_cid(cid1)
            self.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
            self.send_raw("\x81\x00\x63")  # echo 99 bytes first channel

            self.set_cid(cid2)  # send ping on 2nd channel
            self.send_raw("\x81\x00\x63")
            self.delay(0.1)
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
            with Test("Test idle, wait for timeout"):
                sys.stdout.flush()
                try:
                    cmd, resp = self.recv_raw()
                except socket.timeout:
                    pass

        with Test("Test cid 0 is invalid"):
            self.set_cid("\x00\x00\x00\x00")
            self.send_raw(
                "\x86\x00\x08\x11\x22\x33\x44\x55\x66\x77\x88", cid="\x00\x00\x00\x00"
            )
            cmd, r = self.recv_raw()  # timeout
            assert cmd == 0xBF
            assert r[0] == CtapError.ERR.INVALID_CHANNEL

        with Test("Test invalid broadcast cid use"):
            self.set_cid("\xff\xff\xff\xff")
            self.send_raw(
                "\x81\x00\x08\x11\x22\x33\x44\x55\x66\x77\x88", cid="\xff\xff\xff\xff"
            )
            cmd, r = self.recv_raw()  # timeout
            assert cmd == 0xBF
            assert r[0] == CtapError.ERR.INVALID_CHANNEL
