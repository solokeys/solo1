from __future__ import print_function, absolute_import, unicode_literals
import time
from random import randint
import array
from functools import cmp_to_key

from fido2 import cbor
from fido2.ctap import CtapError

from fido2.ctap2 import ES256, PinProtocolV1, AttestedCredentialData
from fido2.utils import sha256, hmac_sha256
from fido2.attestation import Attestation

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .u2f import U2FTests
from .tester import Tester, Test
from .util import shannon_entropy

rp = {"id": "examplo.org", "name": "ExaRP"}
rp2 = {"id": "solokeys.com", "name": "ExaRP"}
user = {"id": b"usee_od", "name": "AB User"}
user1 = {"id": b"1234567890", "name": "Conor Patrick"}
user2 = {"id": b"oiewhfoi", "name": "Han Solo"}
user3 = {"id": b"23ohfpjwo@@", "name": "John Smith"}
challenge = "Y2hhbGxlbmdl"
pin_protocol = 1
key_params = [{"type": "public-key", "alg": ES256.ALGORITHM}]
cdh = b"123456789abcdef0123456789abcdef0"


def VerifyAttestation(attest, data):
    verifier = Attestation.for_type(attest.fmt)
    verifier().verify(attest.att_statement, attest.auth_data, data.hash)


def cbor_key_to_representative(key):
    if isinstance(key, int):
        if key >= 0:
            return (0, key)
        return (1, -key)
    elif isinstance(key, bytes):
        return (2, key)
    elif isinstance(key, str):
        return (3, key)
    else:
        raise ValueError(key)


def cbor_str_cmp(a, b):
    if isinstance(a, str) or isinstance(b, str):
        a = a.encode("utf8")
        b = b.encode("utf8")

    if len(a) == len(b):
        for x, y in zip(a, b):
            if x != y:
                return x - y
        return 0
    else:
        return len(a) - len(b)


def cmp_cbor_keys(a, b):
    a = cbor_key_to_representative(a)
    b = cbor_key_to_representative(b)
    if a[0] != b[0]:
        return a[0] - b[0]
    if a[0] in (2, 3):
        return cbor_str_cmp(a[1], b[1])
    else:
        return (a[1] > b[1]) - (a[1] < b[1])


def TestCborKeysSorted(cbor_obj):
    # Cbor canonical ordering of keys.
    # https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form

    if isinstance(cbor_obj, bytes):
        cbor_obj = cbor.loads(cbor_obj)[0]

    if isinstance(cbor_obj, dict):
        l = [x for x in cbor_obj]
    else:
        l = cbor_obj

    l_sorted = sorted(l[:], key=cmp_to_key(cmp_cbor_keys))

    for i in range(len(l)):

        if not isinstance(l[i], (str, int)):
            raise ValueError(f"Cbor map key {l[i]} must be int or str for CTAP2")

        if l[i] != l_sorted[i]:
            raise ValueError(f"Cbor map item {i}: {l[i]} is out of order")

    return l


# hot patch cbor map parsing to test the order of keys in map
_load_map_old = cbor.load_map


def _load_map_new(ai, data):
    values, data = _load_map_old(ai, data)
    TestCborKeysSorted(values)
    return values, data


cbor.load_map = _load_map_new
cbor._DESERIALIZERS[5] = _load_map_new


class FIDO2Tests(Tester):
    def __init__(self, tester=None):
        super().__init__(tester)
        self.self_test()

    def self_test(self,):
        cbor_key_list_sorted = [
            0,
            1,
            1,
            2,
            3,
            -1,
            -2,
            "b",
            "c",
            "aa",
            "aaa",
            "aab",
            "baa",
            "bbb",
        ]
        with Test("Self test CBOR sorting"):
            TestCborKeysSorted(cbor_key_list_sorted)

        with Test("Self test CBOR sorting integers", catch=ValueError):
            TestCborKeysSorted([1, 0])

        with Test("Self test CBOR sorting major type", catch=ValueError):
            TestCborKeysSorted([-1, 0])

        with Test("Self test CBOR sorting strings", catch=ValueError):
            TestCborKeysSorted(["bb", "a"])

        with Test("Self test CBOR sorting same length strings", catch=ValueError):
            TestCborKeysSorted(["ab", "aa"])

    def run(self,):
        self.test_fido2()

    def test_fido2_simple(self, pin_token=None):
        creds = []
        exclude_list = []
        PIN = pin_token

        fake_id1 = array.array("B", [randint(0, 255) for i in range(0, 150)]).tobytes()
        fake_id2 = array.array("B", [randint(0, 255) for i in range(0, 73)]).tobytes()

        exclude_list.append({"id": fake_id1, "type": "public-key"})
        exclude_list.append({"id": fake_id2, "type": "public-key"})

        t1 = time.time() * 1000
        attest, data = self.client.make_credential(
            rp, user, challenge, pin=PIN, exclude_list=[]
        )
        t2 = time.time() * 1000
        VerifyAttestation(attest, data)
        print("Register time: %d ms" % (t2 - t1))

        cred = attest.auth_data.credential_data
        creds.append(cred)

        allow_list = [{"id": creds[0].credential_id, "type": "public-key"}]
        t1 = time.time() * 1000
        assertions, client_data = self.client.get_assertion(
            rp["id"], challenge, allow_list, pin=PIN
        )
        t2 = time.time() * 1000
        assertions[0].verify(client_data.hash, creds[0].public_key)

        print("Assertion time: %d ms" % (t2 - t1))

    def test_extensions(self,):

        salt1 = b"\x5a" * 32
        salt2 = b"\x96" * 32
        salt3 = b"\x03" * 32

        # self.testReset()

        with Test("Get info has hmac-secret"):
            info = self.ctap.get_info()
            assert "hmac-secret" in info.extensions

        reg = self.testMC(
            "Send MC with hmac-secret ext set to true, expect SUCCESS",
            cdh,
            rp,
            user,
            key_params,
            expectedError=CtapError.ERR.SUCCESS,
            other={"extensions": {"hmac-secret": True}, "options": {"rk": True}},
        )

        with Test("Check 'hmac-secret' is set to true in auth_data extensions"):
            assert reg.auth_data.extensions
            assert "hmac-secret" in reg.auth_data.extensions
            assert reg.auth_data.extensions["hmac-secret"] == True

        reg = self.testMC(
            "Send MC with fake extension set to true, expect SUCCESS",
            cdh,
            rp,
            user,
            key_params,
            expectedError=CtapError.ERR.SUCCESS,
            other={"extensions": {"tetris": True}},
        )

        with Test("Get shared secret"):
            key_agreement, shared_secret = (
                self.client.pin_protocol._init_shared_secret()
            )
            cipher = Cipher(
                algorithms.AES(shared_secret),
                modes.CBC(b"\x00" * 16),
                default_backend(),
            )

        def get_salt_params(salts):
            enc = cipher.encryptor()
            salt_enc = b""
            for salt in salts:
                salt_enc += enc.update(salt)
            salt_enc += enc.finalize()

            salt_auth = hmac_sha256(shared_secret, salt_enc)[:16]
            return salt_enc, salt_auth

        for salt_list in ((salt1,), (salt1, salt2)):
            salt_enc, salt_auth = get_salt_params(salt_list)

            auth = self.testGA(
                "Send GA request with %d salts hmac-secret, expect success"
                % len(salt_list),
                rp["id"],
                cdh,
                other={
                    "extensions": {
                        "hmac-secret": {1: key_agreement, 2: salt_enc, 3: salt_auth}
                    }
                },
                expectedError=CtapError.ERR.SUCCESS,
            )

            with Test(
                "Check that hmac-secret is in auth_data extensions and has %d bytes"
                % (len(salt_list) * 32)
            ):
                ext = auth.auth_data.extensions
                assert ext
                assert "hmac-secret" in ext
                assert isinstance(ext["hmac-secret"], bytes)
                assert len(ext["hmac-secret"]) == len(salt_list) * 32

            with Test("Check that shannon_entropy of hmac-secret is good"):
                ext = auth.auth_data.extensions
                dec = cipher.decryptor()
                key = dec.update(ext["hmac-secret"]) + dec.finalize()

                print(shannon_entropy(ext["hmac-secret"]))
                if len(salt_list) == 1:
                    assert shannon_entropy(ext["hmac-secret"]) > 4.6
                    assert shannon_entropy(key) > 4.6
                if len(salt_list) == 2:
                    assert shannon_entropy(ext["hmac-secret"]) > 5.4
                    assert shannon_entropy(key) > 5.4

        salt_enc, salt_auth = get_salt_params((salt3,))

        auth = self.testGA(
            "Send GA request with hmac-secret missing keyAgreement, expect error",
            rp["id"],
            cdh,
            other={"extensions": {"hmac-secret": {2: salt_enc, 3: salt_auth}}},
        )
        auth = self.testGA(
            "Send GA request with hmac-secret missing saltAuth, expect MISSING_PARAMETER",
            rp["id"],
            cdh,
            other={"extensions": {"hmac-secret": {1: key_agreement, 2: salt_enc}}},
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )
        auth = self.testGA(
            "Send GA request with hmac-secret missing saltEnc, expect MISSING_PARAMETER",
            rp["id"],
            cdh,
            other={"extensions": {"hmac-secret": {1: key_agreement, 3: salt_auth}}},
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        bad_auth = list(salt_auth[:])
        bad_auth[len(bad_auth) // 2] = bad_auth[len(bad_auth) // 2] ^ 1
        bad_auth = bytes(bad_auth)

        auth = self.testGA(
            "Send GA request with hmac-secret containing bad saltAuth, expect EXTENSION_FIRST",
            rp["id"],
            cdh,
            other={
                "extensions": {
                    "hmac-secret": {1: key_agreement, 2: salt_enc, 3: bad_auth}
                }
            },
            expectedError=CtapError.ERR.EXTENSION_FIRST,
        )

        salt4 = b"\x5a" * 16
        salt5 = b"\x96" * 64
        for salt_list in ((salt4,), (salt4, salt5)):
            salt_enc, salt_auth = get_salt_params(salt_list)

            salt_auth = hmac_sha256(shared_secret, salt_enc)[:16]
            auth = self.testGA(
                "Send GA request with incorrect salt length %d, expect INVALID_LENGTH"
                % len(salt_enc),
                rp["id"],
                cdh,
                other={
                    "extensions": {
                        "hmac-secret": {1: key_agreement, 2: salt_enc, 3: salt_auth}
                    }
                },
                expectedError=CtapError.ERR.INVALID_LENGTH,
            )

    def test_get_info(self,):
        with Test("Get info"):
            info = self.ctap.get_info()
            print(bytes(info))
            print(cbor.loads(bytes(info)))

        with Test("Check FIDO2 string is in VERSIONS field"):
            assert "FIDO_2_0" in info.versions

        with Test("Check pin protocols field"):
            if len(info.pin_protocols):
                assert sum(info.pin_protocols) > 0

        with Test("Check options field"):
            for x in info.options:
                assert info.options[x] in [True, False]

        if "uv" in info.options:
            if info.options["uv"]:
                self.testMC(
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
                self.testMC(
                    "Send MC request with up set to true, expect INVALID_OPTION",
                    cdh,
                    rp,
                    user,
                    key_params,
                    other={"options": {"up": True}},
                    expectedError=CtapError.ERR.INVALID_OPTION,
                )

    def test_make_credential(self,):

        prev_reg = self.testMC(
            "Send MC request, expect success",
            cdh,
            rp,
            user,
            key_params,
            expectedError=CtapError.ERR.SUCCESS,
        )

        allow_list = [
            {
                "id": prev_reg.auth_data.credential_data.credential_id,
                "type": "public-key",
            }
        ]
        with Test("Check attestation format is correct"):
            assert prev_reg.fmt in ["packed", "tpm", "android-key", "adroid-safetynet"]

        with Test("Check auth_data is at least 77 bytes"):
            assert len(prev_reg.auth_data) >= 77

        self.testMC(
            "Send MC request with missing clientDataHash, expect error",
            None,
            rp,
            user,
            key_params,
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        self.testMC(
            "Send MC request with integer for clientDataHash, expect error",
            5,
            rp,
            user,
            key_params,
        )

        self.testMC(
            "Send MC request with missing user, expect error",
            cdh,
            rp,
            None,
            key_params,
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        self.testMC(
            "Send MC request with bytearray user, expect error",
            cdh,
            rp,
            b"1234abcd",
            key_params,
        )

        self.testMC(
            "Send MC request with missing RP, expect error",
            cdh,
            None,
            user,
            key_params,
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        self.testMC(
            "Send MC request with bytearray RP, expect error",
            cdh,
            b"1234abcd",
            user,
            key_params,
        )

        self.testMC(
            "Send MC request with missing pubKeyCredParams, expect error",
            cdh,
            rp,
            user,
            None,
        )

        self.testMC(
            "Send MC request with incorrect pubKeyCredParams, expect error",
            cdh,
            rp,
            user,
            b"2356",
        )

        self.testMC(
            "Send MC request with incorrect excludeList, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"exclude_list": 8},
        )

        self.testMC(
            "Send MC request with incorrect extensions, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"extensions": 8},
        )

        self.testMC(
            "Send MC request with incorrect options, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"options": 8},
        )

        self.testMC(
            "Send MC request with bad RP.name",
            cdh,
            {"id": self.host, "name": 8, "icon": "icon"},
            user,
            key_params,
        )

        self.testMC(
            "Send MC request with bad RP.id",
            cdh,
            {"id": 8, "name": "name", "icon": "icon"},
            user,
            key_params,
        )

        self.testMC(
            "Send MC request with bad RP.icon",
            cdh,
            {"id": self.host, "name": "name", "icon": 8},
            user,
            key_params,
        )

        self.testMC(
            "Send MC request with bad user.name",
            cdh,
            rp,
            {"id": b"usee_od", "name": 8},
            key_params,
        )

        self.testMC(
            "Send MC request with bad user.id",
            cdh,
            rp,
            {"id": "usee_od", "name": "name"},
            key_params,
        )

        self.testMC(
            "Send MC request with bad user.displayName",
            cdh,
            rp,
            {"id": "usee_od", "name": "name", "displayName": 8},
            key_params,
        )

        self.testMC(
            "Send MC request with bad user.icon",
            cdh,
            rp,
            {"id": "usee_od", "name": "name", "icon": 8},
            key_params,
        )

        self.testMC(
            "Send MC request with non-map pubKeyCredParams item",
            cdh,
            rp,
            user,
            ["wrong"],
        )

        self.testMC(
            "Send MC request with pubKeyCredParams item missing type field",
            cdh,
            rp,
            user,
            [{"alg": ES256.ALGORITHM}],
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        self.testMC(
            "Send MC request with pubKeyCredParams item with bad type field",
            cdh,
            rp,
            user,
            [{"alg": ES256.ALGORITHM, "type": b"public-key"}],
        )

        self.testMC(
            "Send MC request with pubKeyCredParams item missing alg",
            cdh,
            rp,
            user,
            [{"type": "public-key"}],
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        self.testMC(
            "Send MC request with pubKeyCredParams item with bad alg",
            cdh,
            rp,
            user,
            [{"alg": "7", "type": "public-key"}],
        )

        self.testMC(
            "Send MC request with pubKeyCredParams item with bogus alg, expect UNSUPPORTED_ALGORITHM",
            cdh,
            rp,
            user,
            [{"alg": 1234, "type": "public-key"}],
            expectedError=CtapError.ERR.UNSUPPORTED_ALGORITHM,
        )

        self.testMC(
            "Send MC request with pubKeyCredParams item with bogus type, expect UNSUPPORTED_ALGORITHM",
            cdh,
            rp,
            user,
            [{"alg": ES256.ALGORITHM, "type": "rot13"}],
            expectedError=CtapError.ERR.UNSUPPORTED_ALGORITHM,
        )

        self.testMC(
            "Send MC request with excludeList item with bogus type, expect SUCCESS",
            cdh,
            rp,
            user,
            key_params,
            expectedError=CtapError.ERR.SUCCESS,
            other={"exclude_list": [{"id": b"1234", "type": "rot13"}]},
        )

        self.testMC(
            "Send MC request with excludeList with bad item, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"exclude_list": ["1234"]},
        )

        self.testMC(
            "Send MC request with excludeList with item missing type field, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"exclude_list": [{"id": b"1234"}]},
        )

        self.testMC(
            "Send MC request with excludeList with item missing id field, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"exclude_list": [{"type": "public-key"}]},
        )

        self.testMC(
            "Send MC request with excludeList with item containing bad id field, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"exclude_list": [{"type": "public-key", "id": "1234"}]},
        )

        self.testMC(
            "Send MC request with excludeList with item containing bad type field, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"exclude_list": [{"type": b"public-key", "id": b"1234"}]},
        )

        self.testMC(
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

        self.testMC(
            "Send MC request with unknown option, expect SUCCESS",
            cdh,
            rp,
            user,
            key_params,
            other={"options": {"unknown": False}},
            expectedError=CtapError.ERR.SUCCESS,
        )

        self.testReset()

        self.testGA(
            "Send GA request with reset auth, expect NO_CREDENTIALS",
            rp["id"],
            cdh,
            allow_list,
            expectedError=CtapError.ERR.NO_CREDENTIALS,
        )

    def test_get_assertion(self,):

        self.testReset()

        prev_reg = self.testMC(
            "Send MC request, expect success",
            cdh,
            rp,
            user,
            key_params,
            expectedError=CtapError.ERR.SUCCESS,
        )

        allow_list = [
            {
                "id": prev_reg.auth_data.credential_data.credential_id,
                "type": "public-key",
            }
        ]

        prev_auth = self.testGA(
            "Send GA request, expect success",
            rp["id"],
            cdh,
            allow_list,
            expectedError=CtapError.ERR.SUCCESS,
        )

        with Test("Test auth_data is 37 bytes"):
            assert len(prev_auth.auth_data) == 37

        with Test("Test that auth_data.rpIdHash is correct"):
            assert sha256(rp["id"].encode()) == prev_auth.auth_data.rp_id_hash

        with Test("Check that AT flag is not set"):
            assert (prev_auth.auth_data.flags & 0xF8) == 0

        with Test("Test that user, credential and numberOfCredentials are not present"):
            assert prev_auth.user == None
            assert prev_auth.number_of_credentials == None

        self.testGA(
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

        self.testGA(
            "Send GA request with corrupt credId in allow_list, expect NO_CREDENTIALS",
            rp["id"],
            cdh,
            [{"id": badid, "type": "public-key"}],
            expectedError=CtapError.ERR.NO_CREDENTIALS,
        )

        self.testGA(
            "Send GA request with missing RPID, expect MISSING_PARAMETER",
            None,
            cdh,
            allow_list,
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        self.testGA(
            "Send GA request with bad RPID, expect error",
            {"type": "wrong"},
            cdh,
            allow_list,
        )

        self.testGA(
            "Send GA request with missing clientDataHash, expect MISSING_PARAMETER",
            rp["id"],
            None,
            allow_list,
            expectedError=CtapError.ERR.MISSING_PARAMETER,
        )

        self.testGA(
            "Send GA request with bad clientDataHash, expect error",
            rp["id"],
            {"type": "wrong"},
            allow_list,
        )

        self.testGA(
            "Send GA request with bad allow_list, expect error",
            rp["id"],
            cdh,
            {"type": "wrong"},
        )

        self.testGA(
            "Send GA request with bad item in allow_list, expect error",
            rp["id"],
            cdh,
            allow_list + ["wrong"],
        )

        self.testGA(
            "Send GA request with unknown option, expect SUCCESS",
            rp["id"],
            cdh,
            allow_list,
            other={"options": {"unknown": True}},
            expectedError=CtapError.ERR.SUCCESS,
        )
        with Test("Get info"):
            info = self.ctap.get_info()

        if "uv" in info.options:
            if info.options["uv"]:
                res = self.testGA(
                    "Send GA request with uv set to true, expect SUCCESS",
                    rp["id"],
                    cdh,
                    allow_list,
                    other={"options": {"uv": True}},
                    expectedError=CtapError.ERR.SUCCESS,
                )
                with Test("Check that UV flag is set in response"):
                    assert res.auth_data.flags & (1 << 2)
        if "up" in info.options:
            if info.options["up"]:
                res = self.testGA(
                    "Send GA request with up set to true, expect SUCCESS",
                    rp["id"],
                    cdh,
                    allow_list,
                    other={"options": {"up": True}},
                    expectedError=CtapError.ERR.SUCCESS,
                )
            with Test("Check that UP flag is set in response"):
                assert res.auth_data.flags & 1

        self.testGA(
            "Send GA request with bogus type item in allow_list, expect SUCCESS",
            rp["id"],
            cdh,
            allow_list + [{"type": "rot13", "id": b"1234"}],
            expectedError=CtapError.ERR.SUCCESS,
        )

        self.testGA(
            "Send GA request with item missing type field in allow_list, expect error",
            rp["id"],
            cdh,
            allow_list + [{"id": b"1234"}],
        )

        self.testGA(
            "Send GA request with item containing bad type field in allow_list, expect error",
            rp["id"],
            cdh,
            allow_list + [{"type": b"public-key", "id": b"1234"}],
        )

        self.testGA(
            "Send GA request with item containing bad id in allow_list, expect error",
            rp["id"],
            cdh,
            allow_list + [{"type": b"public-key", "id": 42}],
        )

        self.testGA(
            "Send GA request with item missing id in allow_list, expect error",
            rp["id"],
            cdh,
            allow_list + [{"type": b"public-key"}],
        )

        self.testReset()

        appid = sha256(rp["id"].encode("utf8"))
        chal = sha256(challenge.encode("utf8"))
        with Test("Send CTAP1 register request"):
            u2f = U2FTests(self)
            reg = u2f.register(chal, appid)
            reg.verify(appid, chal)

        with Test("Authenticate CTAP1"):
            auth = u2f.authenticate(chal, appid, reg.key_handle)
            auth.verify(appid, chal, reg.public_key)

        auth = self.testGA(
            "Authenticate CTAP1 registration with CTAP2",
            rp["id"],
            cdh,
            [{"id": reg.key_handle, "type": "public-key"}],
            expectedError=CtapError.ERR.SUCCESS,
        )

        with Test("Check assertion is correct"):
            credential_data = AttestedCredentialData.from_ctap1(
                reg.key_handle, reg.public_key
            )
            auth.verify(cdh, credential_data.public_key)
            assert auth.credential["id"] == reg.key_handle

    def test_rk(self, pin_code=None):

        pin_auth = None
        if pin_code:
            pin_protocol = 1
        else:
            pin_protocol = None
        if pin_code:
            with Test("Set pin code"):
                self.client.pin_protocol.set_pin(pin_code)
                pin_token = self.client.pin_protocol.get_pin_token(pin_code)
                pin_auth = hmac_sha256(pin_token, cdh)[:16]

        self.testMC(
            "Send MC request with rk option set to true, expect SUCCESS",
            cdh,
            rp,
            user,
            key_params,
            other={
                "options": {"rk": True},
                "pin_auth": pin_auth,
                "pin_protocol": pin_protocol,
            },
            expectedError=CtapError.ERR.SUCCESS,
        )

        with Test("Get info"):
            info = self.ctap.get_info()

        options = {"rk": True}
        if "uv" in info.options and info.options["uv"]:
            options["uv"] = False

        for i, x in enumerate([user1, user2, user3]):
            self.testMC(
                "Send MC request with rk option set to true, expect SUCCESS %d/3"
                % (i + 1),
                cdh,
                rp2,
                x,
                key_params,
                other={
                    "options": options,
                    "pin_auth": pin_auth,
                    "pin_protocol": pin_protocol,
                },
                expectedError=CtapError.ERR.SUCCESS,
            )

        auth1 = self.testGA(
            "Send GA request with no allow_list, expect SUCCESS",
            rp2["id"],
            cdh,
            other={"pin_auth": pin_auth, "pin_protocol": pin_protocol},
            expectedError=CtapError.ERR.SUCCESS,
        )

        with Test("Check that there are 3 credentials returned"):
            assert auth1.number_of_credentials == 3

        with Test("Get the next 2 assertions"):
            auth2 = self.ctap.get_next_assertion()
            auth3 = self.ctap.get_next_assertion()

        if not pin_code:
            with Test("Check only the user ID was returned"):
                assert "id" in auth1.user.keys() and len(auth1.user.keys()) == 1
                assert "id" in auth2.user.keys() and len(auth2.user.keys()) == 1
                assert "id" in auth3.user.keys() and len(auth3.user.keys()) == 1
        else:
            with Test("Check that all user info was returned"):
                for x in (auth1, auth2, auth3):
                    for y in ("name", "icon", "displayName", "id"):
                        if y not in x.user.keys():
                            print("FAIL: %s was not in user: " % y, x.user)

        with Test("Send an extra getNextAssertion request, expect error"):
            try:
                self.ctap.get_next_assertion()
                assert 0
            except CtapError as e:
                print(e)

    def test_client_pin(self,):
        pin1 = "1234567890"
        self.test_rk(pin1)

        # PinProtocolV1
        res = self.testCP(
            "Test getKeyAgreement, expect SUCCESS",
            pin_protocol,
            PinProtocolV1.CMD.GET_KEY_AGREEMENT,
            expectedError=CtapError.ERR.SUCCESS,
        )

        with Test("Test getKeyAgreement has appropriate fields"):
            key = res[1]
            assert "Is public key" and key[1] == 2
            assert "Is P256" and key[-1] == 1
            if key[3] != -7:
                print("WARNING: algorithm returned is not for ES256 (-7): ", key[3])
            assert "Right key" and len(key[-3]) == 32 and isinstance(key[-3], bytes)

        with Test("Test setting a new pin"):
            pin2 = "qwertyuiop\x11\x22\x33\x00123"
            self.client.pin_protocol.change_pin(pin1, pin2)

        with Test("Test getting new pin_auth"):
            pin_token = self.client.pin_protocol.get_pin_token(pin2)
            pin_auth = hmac_sha256(pin_token, cdh)[:16]

        res_mc = self.testMC(
            "Send MC request with new pin auth",
            cdh,
            rp,
            user,
            key_params,
            other={"pin_auth": pin_auth, "pin_protocol": pin_protocol},
            expectedError=CtapError.ERR.SUCCESS,
        )

        with Test("Check UV flag is set"):
            assert res_mc.auth_data.flags & (1 << 2)

        res_ga = self.testGA(
            "Send GA request with pinAuth, expect SUCCESS",
            rp["id"],
            cdh,
            [
                {
                    "type": "public-key",
                    "id": res_mc.auth_data.credential_data.credential_id,
                }
            ],
            other={"pin_auth": pin_auth, "pin_protocol": pin_protocol},
            expectedError=CtapError.ERR.SUCCESS,
        )

        with Test("Check UV flag is set"):
            assert res_ga.auth_data.flags & (1 << 2)

        res_ga = self.testGA(
            "Send GA request with no pinAuth, expect SUCCESS",
            rp["id"],
            cdh,
            [
                {
                    "type": "public-key",
                    "id": res_mc.auth_data.credential_data.credential_id,
                }
            ],
            expectedError=CtapError.ERR.SUCCESS,
        )

        with Test("Check UV flag is NOT set"):
            assert not (res_ga.auth_data.flags & (1 << 2))

        self.testReset()

        with Test("Setting pin code, expect SUCCESS"):
            self.client.pin_protocol.set_pin(pin1)

        self.testReset()
        with Test("Setting pin code >63 bytes, expect POLICY_VIOLATION "):
            try:
                self.client.pin_protocol.set_pin("A" * 64)
                assert 0
            except CtapError as e:
                assert e.code == CtapError.ERR.PIN_POLICY_VIOLATION

        with Test("Get pin token when no pin is set, expect PIN_NOT_SET"):
            try:
                self.client.pin_protocol.get_pin_token(pin1)
                assert 0
            except CtapError as e:
                assert e.code == CtapError.ERR.PIN_NOT_SET

        with Test("Get change pin when no pin is set, expect PIN_NOT_SET"):
            try:
                self.client.pin_protocol.change_pin(pin1, "1234")
                assert 0
            except CtapError as e:
                assert e.code == CtapError.ERR.PIN_NOT_SET

        with Test("Setting pin code and get pin_token, expect SUCCESS"):
            self.client.pin_protocol.set_pin(pin1)
            pin_token = self.client.pin_protocol.get_pin_token(pin1)
            pin_auth = hmac_sha256(pin_token, cdh)[:16]

        with Test("Get info and assert that clientPin is set to true"):
            info = self.ctap.get_info()
            assert info.options["clientPin"]

        with Test("Test setting pin again fails"):
            try:
                self.client.pin_protocol.set_pin(pin1)
                assert 0
            except CtapError as e:
                print(e)

        res_mc = self.testMC(
            "Send MC request with no pin_auth, expect PIN_REQUIRED",
            cdh,
            rp,
            user,
            key_params,
            expectedError=CtapError.ERR.PIN_REQUIRED,
        )

        res_mc = self.testGA(
            "Send GA request with no pin_auth, expect NO_CREDENTIALS",
            rp["id"],
            cdh,
            expectedError=CtapError.ERR.NO_CREDENTIALS,
        )

        res = self.testCP(
            "Test getRetries, expect SUCCESS",
            pin_protocol,
            PinProtocolV1.CMD.GET_RETRIES,
            expectedError=CtapError.ERR.SUCCESS,
        )

        with Test("Check there is 8 pin attempts left"):
            assert res[3] == 8

        # Flip 1 bit
        pin_wrong = list(pin1)
        c = pin1[len(pin1) // 2]

        pin_wrong[len(pin1) // 2] = chr(ord(c) ^ 1)
        pin_wrong = "".join(pin_wrong)

        for i in range(1, 3):
            self.testPP(
                "Get pin_token with wrong pin code, expect PIN_INVALID (%d/2)" % i,
                pin_wrong,
                expectedError=CtapError.ERR.PIN_INVALID,
            )
            print("Check there is %d pin attempts left" % (8 - i))
            res = self.ctap.client_pin(pin_protocol, PinProtocolV1.CMD.GET_RETRIES)
            assert res[3] == (8 - i)
            print("Pass")

        for i in range(1, 3):
            self.testPP(
                "Get pin_token with wrong pin code, expect PIN_AUTH_BLOCKED %d/2" % i,
                pin_wrong,
                expectedError=CtapError.ERR.PIN_AUTH_BLOCKED,
            )

        self.reboot()

        with Test("Get pin_token, expect SUCCESS"):
            pin_token = self.client.pin_protocol.get_pin_token(pin1)
            pin_auth = hmac_sha256(pin_token, cdh)[:16]

        res_mc = self.testMC(
            "Send MC request with correct pin_auth",
            cdh,
            rp,
            user,
            key_params,
            other={"pin_auth": pin_auth, "pin_protocol": pin_protocol},
            expectedError=CtapError.ERR.SUCCESS,
        )

        with Test("Test getRetries resets to 8"):
            res = self.ctap.client_pin(pin_protocol, PinProtocolV1.CMD.GET_RETRIES)
            assert res[3] == (8)

        for i in range(1, 10):
            err = CtapError.ERR.PIN_INVALID
            if i in (3, 6):
                err = CtapError.ERR.PIN_AUTH_BLOCKED
            elif i >= 8:
                err = [CtapError.ERR.PIN_BLOCKED, CtapError.ERR.PIN_INVALID]
            self.testPP(
                "Lock out authentictor and check correct error codes %d/9" % i,
                pin_wrong,
                expectedError=err,
            )

            attempts = 8 - i
            if i > 8:
                attempts = 0

            with Test("Check there is %d pin attempts left" % attempts):
                res = self.ctap.client_pin(pin_protocol, PinProtocolV1.CMD.GET_RETRIES)
                assert res[3] == attempts

            if err == CtapError.ERR.PIN_AUTH_BLOCKED:
                self.reboot()

        res_mc = self.testMC(
            "Send MC request with correct pin_auth, expect error",
            cdh,
            rp,
            user,
            key_params,
            other={"pin_auth": pin_auth, "pin_protocol": pin_protocol},
        )

        self.reboot()

        self.testPP(
            "Get pin_token with correct pin code, expect PIN_BLOCKED",
            pin1,
            expectedError=CtapError.ERR.PIN_BLOCKED,
        )

    def test_fido2(self,):

        self.testReset()

        self.test_get_info()

        self.test_get_assertion()

        self.test_make_credential()

        self.test_rk(None)

        self.test_client_pin()

        self.testReset()

        self.test_extensions()

        print("Done")
