#ifndef __USART_DEFS_H
#define __USART_DEFS_H

//#define USART_BAUD_RATE 9600
#define USART_BAUD_RATE 115200
// BT HC-06 physical layer runs at 128kbps
// so it's possible to gain a little bit by using 230400
// with some risk to overflow its internal buffers:
//#define USART_BAUD_RATE 230400

#define USART_BUFFLEN 512
#define USART_FIFOLEN (2*USART_BUFFLEN)

// Higher baudrates are pointless, only increasing overflow risk

#define USART_PARITY 'N'

#if defined (_WIN32)
#define SERIAL_PORT_EXAMPLE_H   "com3"
#elif defined(__APPLE__)
#define SERIAL_PORT_EXAMPLE_H   "/dev/tty.usbmodemiceman1"
#else
#define SERIAL_PORT_EXAMPLE_H   "/dev/ttyACM0"
#endif

#endif
