//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Generic uart / rs232/ serial port library
//-----------------------------------------------------------------------------

#ifndef _UART_H_
#define _UART_H_

#include "common.h"

/* serial_port is declared as a void*, which you should cast to whatever type
 * makes sense to your connection method. Both the posix and win32
 * implementations define their own structs in place.
 */
typedef void *serial_port;

/* Returned by uart_open if the serial port specified was invalid.
 */
#define INVALID_SERIAL_PORT (void*)(~1)

/* Returned by uart_open if the serial port specified is in use by another
 * process.
 */
#define CLAIMED_SERIAL_PORT (void*)(~2)

/* Given a user-specified port name, connect to the port and return a structure
 * used for future references to that port.
 *
 * On errors, this method returns INVALID_SERIAL_PORT or CLAIMED_SERIAL_PORT.
 */
serial_port uart_open(const char *pcPortName, uint32_t speed);

/* Closes the given port.
 */
void uart_close(const serial_port sp);

/* Reads from the given serial port for up to 30ms.
 *   pbtRx: A pointer to a buffer for the returned data to be written to.
 *   pszMaxRxLen: The maximum data size we want to be sent.
 *   pszRxLen: The number of bytes that we were actually sent.
 *
 * Returns TRUE if any data was fetched, even if it was less than pszMaxRxLen.
 *
 * Returns FALSE if there was an error reading from the device. Note that a
 * partial read may have completed into the buffer by the corresponding
 * implementation, so pszRxLen should be checked to see if any data was written.
 */
int uart_receive(const serial_port sp, uint8_t *pbtRx, uint32_t pszMaxRxLen, uint32_t *pszRxLen);

/* Sends a buffer to a given serial port.
 *   pbtTx: A pointer to a buffer containing the data to send.
 *   len: The amount of data to be sent.
 */
int uart_send(const serial_port sp, const uint8_t *pbtTx, const uint32_t len);

/* Sets the current speed of the serial port, in baud.
 */
bool uart_set_speed(serial_port sp, const uint32_t uiPortSpeed);

/* Gets the current speed of the serial port, in baud.
 */
uint32_t uart_get_speed(const serial_port sp);

/* Reconfigure timeouts (ms)
 */
int uart_reconfigure_timeouts(uint32_t value);

/* Get timeouts (ms)
 */
uint32_t uart_get_timeouts(void);

#endif // _UART_H_
