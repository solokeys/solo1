from smartcard.scard import *
from fido2.hid import CAPABILITY, CTAPHID
import binascii

def SCGetErrorMsg(hresult):
    return SCardGetErrorMessage(hresult)


class PCSCDevice:
    def __init__(self, hcontext=None, reader=None):
        self.hcontext = hcontext
        self.reader = reader
        self.card = None
        self.atr = None
        self.protocol = None
        self.aidats = None
        self.capabilities = CAPABILITY.WINK + CAPABILITY.CBOR
        return

    def exapdu(self, apdu):
        hresult, response = SCardTransmit(self.card, self.protocol, list(apdu))
        if hresult != SCARD_S_SUCCESS:
            raise error('Failed to transmit: [' + hex(hresult) + '] ' + SCardGetErrorMessage(hresult))

        bresponse = bytes(response)
        return bresponse

    def USBApduToNFC(self, chid, apdu):
        if chid == CTAPHID.MSG:
            vapdu = apdu[7:]
            vapdu = vapdu[:-2]
            if apdu.find(b"\x00\x01") == 0:
                vapdu = b"\x00\x01\x03\x00" + bytes([len(vapdu)]) + vapdu
            else:
                vapdu = apdu[0:4] + bytes([len(vapdu)]) + vapdu

            vapdu += b"\x00"
            #print("apdu changed", vapdu.hex())
            return vapdu

        if chid == CTAPHID.CBOR:
            vapdu = apdu
            vapdu = b"\x80\x10\x00\x00" + bytes([len(vapdu)]) + vapdu
            vapdu += b"\x00"
            print("apdu CBOR changed", vapdu.hex())
            return vapdu

        if chid == CTAPHID.PING:
            return apdu

        if chid == CTAPHID.WINK:
            return apdu

        return b""

    def call(self, chid, apdu, event=None, on_keepalive=None):
        print("ch", chid, "apdu", apdu.hex())

        if self.card is None:
            self.card, self.atr, self.protocol = SCGetCard(self.hcontext, self.reader)
            if self.card is None or self.card == 0:
                return b""
            # select
            self.aidats = self.exapdu(binascii.unhexlify("00A4040008A0000006472F000100"))
            print("answer to select application:", self.aidats)

        apdu = self.USBApduToNFC(chid, apdu)

        response = self.exapdu(apdu)

        if len(response) >= 2 and response[-2] == 0x61:
            resp2 = response
            while len(resp2) > 2 and resp2[-2] == 0x61:
                resp2 = self.exapdu(b"\x00\xc0\x00\x00\x00\x00")
                if len(resp2) > 0:
                    response = response[:-2] + resp2
                else:
                    break


        print("apdu response:", response[-2:].hex())
        return response


def SCGetReader(readerCaption = "CL"):
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

        readerNum = 0;
        for indx, x in enumerate(readers, start=0):
            if x.find(readerCaption) >= 0:
                readerNum = indx
                break

        if len(readers) > 0:
            print('Use reader: `' + readers[readerNum] + '`')
        else:
            raise error('ERROR: no reader in the system')

        return hcontext, readers[readerNum]

    except error as e:
        print("ERROR:", e)


def SCGetCard(hcontext, zreader):
    try:
        hresult, hcard, dwActiveProtocol = SCardConnect(
            hcontext,
            zreader,
            SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1) # | SCARD_PROTOCOL_T1
        if hresult != SCARD_S_SUCCESS:
            raise error('unable to connect: ' + SCGetErrorMsg(hresult))
        print('Connected with active protocol', dwActiveProtocol, " t0=", SCARD_PROTOCOL_T0)

        #hresult = SCardBeginTransaction(hcard)
        #if hresult != SCARD_S_SUCCESS:
        #    raise error('failed to begin transaction: ' + SCGetErrorMsg(hresult))

        hresult, reader, state, protocol, atr = SCardStatus(hcard)
        if hresult != SCARD_S_SUCCESS:
            raise error('failed to get status: ' + SCGetErrorMsg(hresult))
        print('ATR:', bytes(atr).hex(), "protocol", protocol)

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

