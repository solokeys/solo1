from solo.client import SoloClient

from fido2.ctap1 import ApduError

from .util import shannon_entropy
from .tester import Tester, Test


class SoloTests(Tester):
    def __init__(self, tester=None):
        super().__init__(tester)

    def run(self,):
        self.test_solo()

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
        with Test("Gathering %d random bytes..." % total):
            entropy = b""
            while len(entropy) < total:
                entropy += sc.get_rng()

        with Test("Test entropy is close to perfect"):
            s = shannon_entropy(entropy)
            assert s > 7.98
        print("Entropy is %.5f bits per byte." % s)

        with Test("Test Solo version command"):
            assert len(sc.solo_version()) == 3

        with Test("Test bootloader is not active"):
            try:
                sc.write_flash(memmap[0], b"1234")
            except ApduError:
                pass

        sc.exchange = sc.exchange_fido2
        with Test("Test Solo version and random commands with fido2 layer"):
            assert len(sc.solo_version()) == 3
            sc.get_rng()

    def test_bootloader(self,):
        sc = SoloClient()
        sc.find_device(self.dev)
        sc.use_u2f()

        memmap = (0x08005000, 0x08005000 + 198 * 1024 - 8)
        data = b"A" * 64

        with Test("Test version command"):
            assert len(sc.bootloader_version()) == 3

        with Test("Test write command"):
            sc.write_flash(memmap[0], data)

        for addr in (memmap[0] - 8, memmap[0] - 4, memmap[1], memmap[1] - 8):
            with Test("Test out of bounds write command at 0x%04x" % addr):
                try:
                    sc.write_flash(addr, data)
                except CtapError as e:
                    assert e.code == CtapError.ERR.NOT_ALLOWED
