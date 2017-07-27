# uart

This contains functionality for talking to UART/Serial devices on different platforms. The official client will build either `uart_posix.c` and `uart_win32.c`.  Build targets for these files are contained in `client/Makefile`.

If you want to implement support for other platforms, you need to implement the methods provided in `uart.h`.

## Implementing a new driver

Each driver is called with a string, typically containing a path or other reference to a serial port on the host.  The methods outlined in `uart.h` need to be implemented.

The hardware uses `common/usb_cdc.c` to implement a USB CDC endpoint exposed by the Atmel MCU.


