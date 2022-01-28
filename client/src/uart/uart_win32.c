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

#include "uart.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "comms.h"
#include "ui.h"

// The windows serial port implementation
#ifdef _WIN32
#include <windows.h>

typedef struct {
    HANDLE hPort;     // Serial port handle
    DCB dcb;          // Device control settings
    COMMTIMEOUTS ct;  // Serial port time-out configuration
} serial_port_windows_t;

uint32_t newtimeout_value = 0;
bool newtimeout_pending = false;

int uart_reconfigure_timeouts(uint32_t value) {
    newtimeout_value = value;
    newtimeout_pending = true;
    return PM3_SUCCESS;
}

static int uart_reconfigure_timeouts_polling(serial_port sp) {
    if (newtimeout_pending == false)
        return PM3_SUCCESS;
    newtimeout_pending = false;

    serial_port_windows_t *spw;
    spw = (serial_port_windows_t *)sp;
    spw->ct.ReadIntervalTimeout         = newtimeout_value;
    spw->ct.ReadTotalTimeoutMultiplier  = 0;
    spw->ct.ReadTotalTimeoutConstant    = newtimeout_value;
    spw->ct.WriteTotalTimeoutMultiplier = newtimeout_value;
    spw->ct.WriteTotalTimeoutConstant   = 0;

    if (!SetCommTimeouts(spw->hPort, &spw->ct)) {
        uart_close(spw);
        return PM3_EIO;
    }

    PurgeComm(spw->hPort, PURGE_RXABORT | PURGE_RXCLEAR);
    return PM3_SUCCESS;
}

serial_port uart_open(const char *pcPortName, uint32_t speed) {
    char acPortName[255] = {0};
    serial_port_windows_t *sp = calloc(sizeof(serial_port_windows_t), sizeof(uint8_t));

    if (sp == 0) {
        PrintAndLogEx(WARNING, "UART failed to allocate memory\n");
        return INVALID_SERIAL_PORT;
    }
    // Copy the input "com?" to "\\.\COM?" format
    sprintf(acPortName, "\\\\.\\%s", pcPortName);
    _strupr(acPortName);

    // Try to open the serial port
    // r/w,  none-share comport, no security, existing, no overlapping, no templates
    sp->hPort = CreateFileA(acPortName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (sp->hPort == INVALID_HANDLE_VALUE) {
        uart_close(sp);
        return INVALID_SERIAL_PORT;
    }

    // Prepare the device control
    // doesn't matter since PM3 device ignores this CDC command:  set_line_coding in usb_cdc.c
    memset(&sp->dcb, 0, sizeof(DCB));
    sp->dcb.DCBlength = sizeof(DCB);
    if (!BuildCommDCBA("baud=115200 parity=N data=8 stop=1", &sp->dcb)) {
        uart_close(sp);
        PrintAndLogEx(WARNING, "UART error cdc setup\n");
        return INVALID_SERIAL_PORT;
    }

    // Update the active serial port
    if (!SetCommState(sp->hPort, &sp->dcb)) {
        uart_close(sp);
        PrintAndLogEx(WARNING, "UART error while setting com state\n");
        return INVALID_SERIAL_PORT;
    }

    uart_reconfigure_timeouts(UART_FPC_CLIENT_RX_TIMEOUT_MS);
    uart_reconfigure_timeouts_polling(sp);

    if (!uart_set_speed(sp, speed)) {
        // try fallback automatically
        speed = 115200;
        if (!uart_set_speed(sp, speed)) {
            uart_close(sp);
            PrintAndLogEx(WARNING, "UART error while setting baudrate\n");
            return INVALID_SERIAL_PORT;
        }
    }
    g_conn.uart_speed = uart_get_speed(sp);
    return sp;
}

void uart_close(const serial_port sp) {
    if (((serial_port_windows_t *)sp)->hPort != INVALID_HANDLE_VALUE)
        CloseHandle(((serial_port_windows_t *)sp)->hPort);
    free(sp);
}

bool uart_set_speed(serial_port sp, const uint32_t uiPortSpeed) {
    serial_port_windows_t *spw;

    // Set port speed (Input and Output)
    switch (uiPortSpeed) {
        case 9600:
        case 19200:
        case 38400:
        case 57600:
        case 115200:
        case 230400:
        case 460800:
        case 921600:
        case 1382400:
            break;
        default:
            return false;
    };

    spw = (serial_port_windows_t *)sp;
    spw->dcb.BaudRate = uiPortSpeed;
    bool result = SetCommState(spw->hPort, &spw->dcb);
    PurgeComm(spw->hPort, PURGE_RXABORT | PURGE_RXCLEAR);
    if (result)
        g_conn.uart_speed = uiPortSpeed;

    return result;
}

uint32_t uart_get_speed(const serial_port sp) {
    const serial_port_windows_t *spw = (serial_port_windows_t *)sp;
    if (!GetCommState(spw->hPort, (serial_port) & spw->dcb))
        return spw->dcb.BaudRate;

    return 0;
}

int uart_receive(const serial_port sp, uint8_t *pbtRx, uint32_t pszMaxRxLen, uint32_t *pszRxLen) {
    uart_reconfigure_timeouts_polling(sp);
    int res = ReadFile(((serial_port_windows_t *)sp)->hPort, pbtRx, pszMaxRxLen, (LPDWORD)pszRxLen, NULL);
    if (res)
        return PM3_SUCCESS;

    int errorcode = GetLastError();

    if (res == 0 && errorcode == 2) {
        return PM3_EIO;
    }

    return PM3_ENOTTY;
}

int uart_send(const serial_port sp, const uint8_t *p_tx, const uint32_t len) {
    DWORD txlen = 0;
    int res = WriteFile(((serial_port_windows_t *)sp)->hPort, p_tx, len, &txlen, NULL);
    if (res)
        return PM3_SUCCESS;

    int errorcode = GetLastError();
    if (res == 0 && errorcode == 2) {
        return PM3_EIO;
    }
    return PM3_ENOTTY;
}

#endif
