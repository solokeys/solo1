from fido2.ctap1 import CTAP1, ApduError, APDU
from fido2.utils import sha256
from fido2.client import _call_polling

from .tester import Tester, Test


class U2FTests(Tester):
    def __init__(self, tester=None):
        super().__init__(tester)

    def run(self,):
        self.test_u2f()

    def register(self, chal, appid):
        reg_data = _call_polling(0.25, None, None, self.ctap1.register, chal, appid)
        return reg_data

    def authenticate(self, chal, appid, key_handle, check_only=False):
        auth_data = _call_polling(
            0.25,
            None,
            None,
            self.ctap1.authenticate,
            chal,
            appid,
            key_handle,
            check_only=check_only,
        )
        return auth_data

    def test_u2f(self,):
        chal = sha256(b"AAA")
        appid = sha256(b"BBB")
        lastc = 0

        regs = []

        with Test("Check version"):
            assert self.ctap1.get_version() == "U2F_V2"

        with Test("Check bad INS"):
            try:
                self.ctap1.send_apdu(0, 0, 0, 0, b"")
            except ApduError as e:
                assert e.code == 0x6D00

        with Test("Check bad CLA"):
            try:
                self.ctap1.send_apdu(1, CTAP1.INS.VERSION, 0, 0, b"abc")
            except ApduError as e:
                assert e.code == 0x6E00

        for i in range(0, self.user_count):
            with Test(
                "U2F reg + auth %d/%d (count: %02x)" % (i + 1, self.user_count, lastc)
            ):
                reg = self.register(chal, appid)
                reg.verify(appid, chal)
                auth = self.authenticate(chal, appid, reg.key_handle)
                auth.verify(appid, chal, reg.public_key)

                regs.append(reg)
                # check endianness
                if lastc:
                    assert (auth.counter - lastc) < 10
                lastc = auth.counter
                if lastc > 0x80000000:
                    print("WARNING: counter is unusually high: %04x" % lastc)
                    assert 0

        for i in range(0, self.user_count):
            with Test(
                "Checking previous registration %d/%d" % (i + 1, self.user_count)
            ):
                auth = self.authenticate(chal, appid, regs[i].key_handle)
                auth.verify(appid, chal, regs[i].public_key)

        print("Check that all previous credentials are registered...")
        for i in range(0, self.user_count):
            with Test("Check that previous credential %d is registered" % i):
                try:
                    auth = self.ctap1.authenticate(
                        chal, appid, regs[i].key_handle, check_only=True
                    )
                except ApduError as e:
                    # Indicates that key handle is registered
                    assert e.code == APDU.USE_NOT_SATISFIED

        with Test("Check an incorrect key handle is not registered"):
            kh = bytearray(regs[0].key_handle)
            kh[0] = kh[0] ^ (0x40)
            try:
                self.ctap1.authenticate(chal, appid, kh, check_only=True)
                assert 0
            except ApduError as e:
                assert e.code == APDU.WRONG_DATA

        with Test("Try to sign with incorrect key handle"):
            try:
                self.ctap1.authenticate(chal, appid, kh)
                assert 0
            except ApduError as e:
                assert e.code == APDU.WRONG_DATA

        with Test("Try to sign using an incorrect keyhandle length"):
            try:
                kh = regs[0].key_handle
                self.ctap1.authenticate(chal, appid, kh[: len(kh) // 2])
                assert 0
            except ApduError as e:
                assert e.code == APDU.WRONG_DATA

        with Test("Try to sign using an incorrect appid"):
            badid = bytearray(appid)
            badid[0] = badid[0] ^ (0x40)
            try:
                auth = self.ctap1.authenticate(chal, badid, regs[0].key_handle)
                assert 0
            except ApduError as e:
                assert e.code == APDU.WRONG_DATA
