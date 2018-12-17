#!/usr/bin/python
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
import serial, sys
from sys import argv

if len(argv) not in [2,3]:
    print('usage: %s <com-port> [baud-rate]' % argv[0])
    sys.exit(1)

baud = 115200
if len(argv) > 2:
    baud = int(argv[2])

ser = serial.Serial(argv[1],baud)

print('reading..')
sys.stdout.flush()
while True:
    sys.stdout.write(ser.read())
