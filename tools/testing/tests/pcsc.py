from smartcard.scard import *
from fido2.hid import CAPABILITY

def SCGetErrorMsg(hresult):
    return SCardGetErrorMessage(hresult)


class PCSCDevice:
    def __init__(self, hcontext=None, reader=None):
        self.hcontext = hcontext
        self.reader = reader
        self.card = None
        self.atr = None
        self.protocol = None
        self.capabilities = CAPABILITY.WINK + CAPABILITY.CBOR
        return


    def call(self, chid, apdu):
        print("apdu", apdu)

        if self.card is None:
            self.card, self.atr, self.protocol = SCGetCard(self.hcontext, self.reader)

        print("card and protocol", self.card, self.protocol)
        hresult, response = SCardTransmit(self.card, self.protocol, list(apdu))
        if hresult != SCARD_S_SUCCESS:
            raise error('Failed to transmit: ' + SCardGetErrorMessage(hresult))

        print("response", response)
        return response



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


def SCGetCard(hcontext, zreader):
    try:
        hresult, hcard, dwActiveProtocol = SCardConnect(
            hcontext,
            zreader,
            SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
        if hresult != SCARD_S_SUCCESS:
            raise error('unable to connect: ' + SCGetErrorMsg(hresult))
        print('Connected with active protocol', dwActiveProtocol)

        hresult = SCardBeginTransaction(hcard)
        if hresult != SCARD_S_SUCCESS:
            raise error('failed to begin transaction: ' + SCGetErrorMsg(hresult))

        hresult, reader, state, protocol, atr = SCardStatus(hcard)
        if hresult != SCARD_S_SUCCESS:
            raise error('failed to get status: ' + SCGetErrorMsg(hresult))
        print('ATR:', end=' ')
        for i in range(len(atr)):
            print("0x%.2X" % atr[i], end=' ')
        print("")

        return hcard, atr, dwActiveProtocol

    except error as e:
        print("ERROR:", e)
        return None, None, None


def SCRelease(hcontext):
    try:
#        if self.card is not None:
        '''
        hresult = SCardEndTransaction(hcard, SCARD_LEAVE_CARD)
        if hresult != SCARD_S_SUCCESS:
            raise error(
                'failed to end transaction: ' + \
                SCardGetErrorMessage(hresult))
        print('Transaction ended')
        
        hresult = SCardDisconnect(hcard, SCARD_UNPOWER_CARD)
        if hresult != SCARD_S_SUCCESS:
            raise error(
                'failed to disconnect: ' + \
                SCardGetErrorMessage(hresult))
        print('Disconnected')
        '''
        hresult = SCardReleaseContext(hcontext)
        if hresult != SCARD_S_SUCCESS:
            raise error('Failed to release context: ' + SCGetErrorMsg(hresult))
        print('Released context.')

    except error as e:
        print("ERROR:", e)

