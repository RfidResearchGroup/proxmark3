/*
 * Generic uart / rs232/ serial port library
 *
 * Copyright (c) 2013, Roel Verdult
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holders nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @file uart.h
 */

#ifndef _PM3_UART_H_
#define _PM3_UART_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <stdint.h>
#include <stdbool.h>

typedef unsigned char byte_t;

/* serial_port is declared as a void*, which you should cast to whatever type
 * makes sense to your connection method. Both the posix and win32
 * implementations define their own structs in place.
 */
typedef void* serial_port;

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
serial_port uart_open(const char* pcPortName);

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
bool uart_receive(const serial_port sp, byte_t* pbtRx, size_t pszMaxRxLen, size_t* pszRxLen);

/* Sends a buffer to a given serial port.
 *   pbtTx: A pointer to a buffer containing the data to send.
 *   szTxLen: The amount of data to be sent.
 */
bool uart_send(const serial_port sp, const byte_t* pbtTx, const size_t szTxLen);

/* Sets the current speed of the serial port, in baud.
 */
bool uart_set_speed(serial_port sp, const uint32_t uiPortSpeed);

/* Gets the current speed of the serial port, in baud.
 */
uint32_t uart_get_speed(const serial_port sp);

#endif // _PM3_UART_H_

