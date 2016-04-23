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
 * @brief
 *
 */

#ifndef _RS232_H_
#define _RS232_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef unsigned char byte_t;

// Handle platform specific includes
#ifndef _WIN32
  #include <termios.h>
  #include <sys/ioctl.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <limits.h>
  #include <sys/time.h>
  #include <errno.h>
#else
  #include <windows.h>
#endif

typedef enum {
  SP_INVALID = 0x00, // invalid value, error occured
  SP_NONE    = 0x01, // no parity (default)
  SP_EVEN    = 0x02, // even parity
  SP_ODD     = 0x03  // odd parity
} serial_port_parity;

// Define shortcut to types to make code more readable
typedef void* serial_port;
#define INVALID_SERIAL_PORT (void*)(~1)
#define CLAIMED_SERIAL_PORT (void*)(~2)

serial_port uart_open(const char* pcPortName);
void uart_close(const serial_port sp);

bool uart_set_speed(serial_port sp, const uint32_t uiPortSpeed);
uint32_t uart_get_speed(const serial_port sp);

bool uart_set_parity(serial_port sp, serial_port_parity spp);
serial_port_parity uart_get_parity(const serial_port sp);

bool uart_receive(const serial_port sp, byte_t* pbtRx, size_t* pszRxLen);
bool uart_send(const serial_port sp, const byte_t* pbtTx, const size_t szTxLen);

#endif // _PROXMARK3_RS232_H_


