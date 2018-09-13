#!/usr/bin/python
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
