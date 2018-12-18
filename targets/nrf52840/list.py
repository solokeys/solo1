#
# Copyright (C) 2018 SoloKeys, Inc. <https://solokeys.com/>
# 
# This file is part of Solo.
# 
# Solo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# Solo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with Solo.  If not, see <https://www.gnu.org/licenses/>
# 
# This code is available under licenses for commercial use.
# Please contact SoloKeys for more information.
#
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
