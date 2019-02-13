#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
import datetime, sys
from binascii import hexlify

import Chameleon


def verboseLog(text):
    formatString = "[{}] {}"
    timeString = datetime.datetime.utcnow()
    print(formatString.format(timeString, text))


chameleon = Chameleon.Device(verboseLog)

p = None
for p in Chameleon.Device.listDevices():
    break

if p:
    chameleon.connect(p)
else:
    raise RuntimeError("No chameleon mini connected")

chameleon.execCmd("LOGMODE=LIVE")

while 1:
    b = chameleon.read(1, 20)
    h = hexlify(b)
    h = h.decode()
    sys.stdout.write(h)
    sys.stdout.flush()

chameleon.execCmd("LOGMODE=NONE")
