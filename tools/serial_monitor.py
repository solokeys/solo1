#!/usr/bin/python
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
