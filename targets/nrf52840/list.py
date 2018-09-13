from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from fido2.pyu2f import hidtransport
import sys
from random import randint
import array


# Locate a device
for d in CtapHidDevice.list_devices():
    print(d)
#selector = hidtransport.HidUsageSelector
#for d in hidtransport.hid.Enumerate():
    #print('1',d)
    #if selector(d):
        #try:
            #dev = hidtransport.hid.Open(d['path'])
            #print('2',dev)
        #except OSError:
            ## Insufficient permissions to access device
            #pass
