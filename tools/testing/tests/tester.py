import time, struct

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from fido2.ctap1 import CTAP1
from fido2.utils import Timeout

from fido2.ctap import CtapError


def ForceU2F(client, device):
    client.ctap = CTAP1(device)
    client.pin_protocol = None
    client._do_make_credential = client._ctap1_make_credential
    client._do_get_assertion = client._ctap1_get_assertion


class Packet(object):
    def __init__(self, data):
        self.data = data

    def ToWireFormat(self,):
        return self.data

    @staticmethod
    def FromWireFormat(pkt_size, data):
        return Packet(data)


class Test:
    def __init__(self, msg, catch=None):
        self.msg = msg
        self.catch = catch

    def __enter__(self,):
        print(self.msg)

    def __exit__(self, a, b, c):
        if self.catch is None:
            print("Pass")
        elif isinstance(b, self.catch):
            print("Pass")
            return b
        else:
            raise RuntimeError(f"Expected exception {self.catch} did not occur.")


class Tester:
    def __init__(self, tester=None):
        self.origin = "https://examplo.org"
        self.host = "examplo.org"
        self.user_count = 10
        self.is_sim = False
        if tester:
            self.initFromTester(tester)

    def initFromTester(self, tester):
        self.user_count = tester.user_count
        self.is_sim = tester.is_sim
        self.dev = tester.dev
        self.ctap = tester.ctap
        self.ctap1 = tester.ctap1
        self.client = tester.client

    def find_device(self,):
        print("--- HID ---")
        print(list(CtapHidDevice.list_devices()))
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            try:
                from fido2.pcsc import CtapPcscDevice
                print("--- NFC ---")
                print(list(CtapPcscDevice.list_devices()))
                dev = next(CtapPcscDevice.list_devices(), None)
            except (ModuleNotFoundError, ImportError):
                print("One of NFC library is not installed properly.")
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

    def reboot(self,):
        if self.is_sim:
            print("Sending restart command...")
            self.send_magic_reboot()
            Tester.delay(0.25)
        else:
            print("Please reboot authentictor and hit enter")
            input()
            self.find_device()

    def send_data(self, cmd, data):
        if not isinstance(data, bytes):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        with Timeout(1.0) as event:
            return self.dev.call(cmd, data, event)

    def send_raw(self, data, cid=None):
        if cid is None:
            cid = self.dev._dev.cid
        elif not isinstance(cid, bytes):
            cid = struct.pack("%dB" % len(cid), *[ord(x) for x in cid])
        if not isinstance(data, bytes):
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
        if not isinstance(cid, (bytes, bytearray)):
            cid = struct.pack("%dB" % len(cid), *[ord(x) for x in cid])
        self.dev._dev.cid = cid

    def recv_raw(self,):
        with Timeout(1.0):
            cmd, payload = self.dev._dev.InternalRecv()
        return cmd, payload

    def check_error(data, err=None):
        assert len(data) == 1
        if err is None:
            if data[0] != 0:
                raise CtapError(data[0])
        elif data[0] != err:
            raise ValueError("Unexpected error: %02x" % data[0])

    def testFunc(self, func, test, *args, **kwargs):
        with Test(test):
            res = None
            expectedError = kwargs.get("expectedError", None)
            otherArgs = kwargs.get("other", {})
            try:
                res = func(*args, **otherArgs)
                if expectedError != CtapError.ERR.SUCCESS:
                    raise RuntimeError("Expected error to occur for test: %s" % test)
            except CtapError as e:
                if expectedError is not None:
                    cond = e.code != expectedError
                    if isinstance(expectedError, list):
                        cond = e.code not in expectedError
                    else:
                        expectedError = [expectedError]
                    if cond:
                        raise RuntimeError(
                            f"Got error code {hex(e.code)}, expected {[hex(x) for x in expectedError]}"
                        )
                else:
                    print(e)
        return res

    def testReset(self,):
        print("Resetting Authenticator...")
        try:
            self.ctap.reset()
        except CtapError:
            # Some authenticators need a power cycle
            print("You must power cycle authentictor.  Hit enter when done.")
            input()
            time.sleep(0.2)
            self.find_device()
            self.ctap.reset()

    def testMC(self, test, *args, **kwargs):
        return self.testFunc(self.ctap.make_credential, test, *args, **kwargs)

    def testGA(self, test, *args, **kwargs):
        return self.testFunc(self.ctap.get_assertion, test, *args, **kwargs)

    def testCP(self, test, *args, **kwargs):
        return self.testFunc(self.ctap.client_pin, test, *args, **kwargs)

    def testPP(self, test, *args, **kwargs):
        return self.testFunc(
            self.client.pin_protocol.get_pin_token, test, *args, **kwargs
        )

    def delay(secs):
        time.sleep(secs)
