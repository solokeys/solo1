from smartcard.scard import *
from fido2.hid import CAPABILITY

def SCGetErrorMsg(hresult):
    return SCardGetErrorMessage(hresult)


class PCSCDevice:
    def __init__(self, hcontext=None, reader=None):
        self.hcontext = hcontext
        self.reader = reader
        self.capabilities = CAPABILITY.WINK + CAPABILITY.CBOR
        return

    def call(self, chid, apdu):
        print("apdu", apdu)
        return b""



def SCGetReader():
    try:
        hresult, hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
        if hresult != SCARD_S_SUCCESS:
            raise error('Failed to establish context: ' + SCGetErrorMsg(hresult))
        print('Context established!')

        hresult, readers = SCardListReaders(hcontext, [])
        if hresult != SCARD_S_SUCCESS:
            print("err", SCardGetErrorMessage(hresult).encode("cp1251"))
            raise error('Failed to list readers: [' + hex(hresult) + '] ' + SCGetErrorMsg(hresult))

        print('PCSC Readers:', readers)

        hresult, readerGroups = SCardListReaderGroups(hcontext)
        if hresult != SCARD_S_SUCCESS:
            raise error('Unable to list reader groups: ' + SCGetErrorMsg(hresult))
        print('PCSC Reader groups:', readerGroups)

        if len(readers) > 0:
            print('Use reader: ' + readers[0])
        else:
            raise error('ERROR: no reader in the system')

        return hcontext, readers[0]

    except error as e:
        print("ERROR:", e)


def SCRelease(hcontext):
    try:
        hresult = SCardReleaseContext(hcontext)
        if hresult != SCARD_S_SUCCESS:
            raise error('Failed to release context: ' + SCGetErrorMsg(hresult))
        print('Released context.')

    except error as e:
        print("ERROR:", e)

