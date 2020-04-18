#!/usr/bin/env python3

import sys
import time
try:
    import serial
except ModuleNotFoundError:
    print("Please install pyserial module first.")
    sys.exit(1)

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
        wait = 1
        ti = time.perf_counter()
        while True:
            time.sleep(0.05)
            if (ser.in_waiting > 0):
                # When receiving data, reset timer and shorten timeout
                ti = time.perf_counter()
                wait = 0.05
                out += ser.read(1)
                continue
            # We stop either after 1s if no data or 50ms after last data received
            if time.perf_counter() - ti > wait:
                break
        if out != b'':
            print("<< " + out.decode('utf8'))
