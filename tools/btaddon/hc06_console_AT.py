#!/usr/bin/env python3

import sys
import time
import serial

if len(sys.argv) < 2:
    print('Usage: %s <baudrate>' % sys.argv[0])
    sys.exit(1)
baudrate = int(sys.argv[1])
ser = serial.Serial(
    port='/dev/ttyUSB0',
    baudrate=baudrate,
    parity=serial.PARITY_NONE,
    stopbits=serial.STOPBITS_ONE,
    bytesize=serial.EIGHTBITS
)

ser.isOpen()
ser.write(b'AT')
out = b''
time.sleep(1)
while ser.inWaiting() > 0:
    out += ser.read(1)
if out != b'OK':
    ser.close()
    print("HC-06 dongle not found. Abort.")
    exit(1)
print('Enter your commands below.\r\nInsert "exit" to leave the application.')

while 1 :
    # get keyboard input
    inp = input(">> ")
    inp = inp.encode('utf8')
    if inp == 'exit':
        ser.close()
        exit()
    else:
        ser.write(inp)
        out = b''
        time.sleep(1)
        while ser.inWaiting() > 0:
            out += ser.read(1)
        if out != b'':
            print("<< " + out.decode('utf8'))
