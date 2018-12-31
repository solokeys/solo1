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

# This is a basic, cross-platfrom serial emulator.
# It will automatically try to reconnect to a serial port that disconnects.
# Ideal for development with Solo.
#
# Requires pySerial
#
import sys,time
import serial

if len(sys.argv) != 2:
    print(
"""
usage: %s <serial-port>
      * <serial-port> will look like COM10 or /dev/ttyACM0 or something.
      * baud is 115200.
""" % sys.argv[0])
    sys.exit(1)

port = sys.argv[1]

ser = serial.Serial(port,115200,timeout=.05)

def reconnect():
    while(1):
        time.sleep(0.02)
        try:
            ser = serial.Serial(port,115200,timeout=.05)
            return ser
        except serial.SerialException:
            pass
while 1:
    try:
        d = ser.read(1)
    except serial.SerialException:
        print('reconnecting...')
        ser = reconnect()
        print('done')
    sys.stdout.buffer.write(d)
    sys.stdout.flush()
