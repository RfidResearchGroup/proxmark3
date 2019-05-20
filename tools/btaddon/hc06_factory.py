#!/usr/bin/env python3

import time
import serial

name = b'PM3_RDV4.0'
pin  = b'1234'
role = b'M'
#role = b'S'

ser = None

baud2id = {
       9600:b'4',
      19200:b'5',
      38400:b'6',
      57600:b'7',
     115200:b'8',
     230400:b'9',
     460800:b'A',
     921600:b'B',
    1382400:b'C'
}

p2c={
    serial.PARITY_NONE:b'N',
    serial.PARITY_ODD: b'O',
    serial.PARITY_EVEN:b'E'
}

def send(cmd):
    print("<<" + cmd.decode('utf8'))
    ser.write(cmd)
    out = b''
    time.sleep(1)
    while ser.inWaiting() > 0:
        out += ser.read(1)
    if out != b'':
        print(">>" + out.decode('utf8'))
    return out

def usart_bt_testcomm(baudrate, parity):
    print("Configuring UART: %i 8%s1" % (baudrate, p2c[parity].decode('utf8')))
    global ser
    ser = serial.Serial(
        port='/dev/ttyUSB0',
        baudrate=baudrate,
        parity=parity,
        stopbits=serial.STOPBITS_ONE,
        bytesize=serial.EIGHTBITS
    )
    ser.isOpen()
    resp=send(b'AT')
    if resp != b'OK':
        ser.close()
    return resp == b'OK'

if __name__ == '__main__':
    print("WARNING: process only if strictly needed!")
    print("This requires HC-06 dongle turned ON and NOT connected!")
    if input("Is the HC-06 dingle LED blinking? (Say 'n' if you want to abort) [y/n] ") != 'y':
        print("Aborting.")
        exit(1)

    print("\nTrying to detect current settings... Please be patient.")

    if not usart_bt_testcomm(115200, serial.PARITY_NONE):
        brs = [1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600, 1382400]
        ps = [ serial.PARITY_NONE, serial.PARITY_ODD, serial.PARITY_EVEN ]
        ibr = 0
        ip = 0
        for p, b in [(i, j) for i in ps for j in brs]:
            if usart_bt_testcomm(b, p):
                break
        else:
            print("Sorry, add-on not found. Abort.")
            exit(1)

    print("Reconfiguring add-on to default settings.")

    resp=send(b'AT+VERSION')
# Change name:
    resp=send(b'AT+NAME%s' % name)
# Change BT PIN:
    resp=send(b'AT+PIN%s' % pin)
# Change BT ROLE:
    resp=send(b'AT+ROLE=%s' % role)
# Change BT Parity N:
    resp=send(b'AT+PN')
# Change BT 115200:
    resp=send(b'AT+BAUD%s' % baud2id[115200])
    ser.close()

    time.sleep(1)
    print("Trying to connect add-on with the new settings.")
    ser = serial.Serial(
        port='/dev/ttyUSB0',
        baudrate=115200,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        bytesize=serial.EIGHTBITS
    )
    ser.isOpen()
    if (send(b'AT') == b'OK'):
        print("HC-06 dongle successfully reset")
    else:
        print("Lost contact with add-on, please try again")
    ser.close()
