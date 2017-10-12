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
 * @file uart_win32.c
 *
 * Note: the win32 version of this library has also been seen under the GPLv3+
 * license as part of the libnfc project, which appears to have additional
 * contributors.
 *
 * This version of the library has functionality removed which was not used by
 * proxmark3 project.
 */

#include "uart.h"

// The windows serial port implementation
#ifdef _WIN32
#include <windows.h>

typedef struct {
  HANDLE hPort;     // Serial port handle
  DCB dcb;          // Device control settings
  COMMTIMEOUTS ct;  // Serial port time-out configuration
} serial_port_windows;

void upcase(char *p) {
  while(*p != '\0') {
    if(*p >= 97 && *p <= 122) {
      *p -= 32;
    }
    ++p;
  }
}

serial_port uart_open(const char* pcPortName) {
	char acPortName[255];
	serial_port_windows* sp = malloc(sizeof(serial_port_windows));

	if (sp == 0)
		return INVALID_SERIAL_PORT;

	// Copy the input "com?" to "\\.\COM?" format
	sprintf(acPortName,"\\\\.\\%s", pcPortName);
	upcase(acPortName);

	// Try to open the serial port
	sp->hPort = CreateFileA(acPortName, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (sp->hPort == INVALID_HANDLE_VALUE) {
		uart_close(sp);
		return INVALID_SERIAL_PORT;
	}
  
	// Prepare the device control
	memset(&sp->dcb, 0, sizeof(DCB));
	sp->dcb.DCBlength = sizeof(DCB);
	if (!BuildCommDCBA("baud=115200 parity=N data=8 stop=1",&sp->dcb)) {
		uart_close(sp);
		return INVALID_SERIAL_PORT;
	}
  
	// Update the active serial port
	if (!SetCommState(sp->hPort, &sp->dcb)) {
		uart_close(sp);
		return INVALID_SERIAL_PORT;
	}
	// all zero's configure: no timeout for read/write used.
	// took settings from libnfc/buses/uart.c
	sp->ct.ReadIntervalTimeout         = 0;//1;
	sp->ct.ReadTotalTimeoutMultiplier  = 0;//1;
	sp->ct.ReadTotalTimeoutConstant    = 30;
	sp->ct.WriteTotalTimeoutMultiplier = 0;//1;
	sp->ct.WriteTotalTimeoutConstant   = 30;
  
	if (!SetCommTimeouts(sp->hPort, &sp->ct)) {
		uart_close(sp);
		return INVALID_SERIAL_PORT;
	}
  
	PurgeComm(sp->hPort, PURGE_RXABORT | PURGE_RXCLEAR);

	bool success = uart_set_speed(sp, 460800);
	if (!success)
		uart_set_speed(sp, 115200);
  
	return sp;
}

void uart_close(const serial_port sp) {
	if (((serial_port_windows*)sp)->hPort != INVALID_HANDLE_VALUE )
		CloseHandle(((serial_port_windows*)sp)->hPort);
	free(sp);
}

bool uart_receive(const serial_port sp, byte_t* p_rx, size_t pszMaxRxLen, size_t* p_rxlen) {
	ReadFile(((serial_port_windows*)sp)->hPort, p_rx, pszMaxRxLen, (LPDWORD)p_rxlen, NULL);
	return (*p_rxlen != 0);
}

bool uart_send(const serial_port sp, const byte_t* p_tx, const size_t len) {
	DWORD txlen = 0;
	return WriteFile(((serial_port_windows*)sp)->hPort, p_tx, len, &txlen, NULL);
	/*
	bool res = WriteFile(((serial_port_windows*)sp)->hPort, p_tx, len, &txlen, NULL);
	if ( !res )
		return false;
		
	printf("TX %u\n", txlen);
	return (txlen != 0);
	*/
}

bool uart_set_speed(serial_port sp, const uint32_t uiPortSpeed) {
	serial_port_windows* spw;
	spw = (serial_port_windows*)sp;
	spw->dcb.BaudRate = uiPortSpeed;
	bool result = SetCommState(spw->hPort, &spw->dcb);

	PurgeComm(spw->hPort, PURGE_RXABORT | PURGE_RXCLEAR);
	return result;
}

uint32_t uart_get_speed(const serial_port sp) {
	const serial_port_windows* spw = (serial_port_windows*)sp;
	if (!GetCommState(spw->hPort, (serial_port) & spw->dcb))
		return spw->dcb.BaudRate;

	return 0;
}

#endif