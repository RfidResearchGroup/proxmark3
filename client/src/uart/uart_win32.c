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
#include "ringbuffer.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "comms.h"
#include "ui.h"

// The windows serial port implementation
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

typedef struct {
    HANDLE hPort;          // Serial port handle
    DCB dcb;               // Device control settings
    COMMTIMEOUTS ct;       // Serial port time-out configuration
    SOCKET hSocket;        // Socket handle
    RingBuffer *udpBuffer; // Buffer for UDP
} serial_port_windows_t;

// this is for TCP connection
struct timeval timeout = {
    .tv_sec  = 0, // 0 second
    .tv_usec = UART_NET_CLIENT_RX_TIMEOUT_MS * 1000
};

uint32_t newtimeout_value = 0;
bool newtimeout_pending = false;
uint8_t rx_empty_counter = 0;

int uart_reconfigure_timeouts(uint32_t value) {
    newtimeout_value = value;
    newtimeout_pending = true;
    return PM3_SUCCESS;
}

uint32_t uart_get_timeouts(void) {
    return newtimeout_value;
}

static int uart_reconfigure_timeouts_polling(serial_port sp) {
    if (newtimeout_pending == false)
        return PM3_SUCCESS;
    newtimeout_pending = false;

    serial_port_windows_t *spw = (serial_port_windows_t *)sp;
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

serial_port uart_open(const char *pcPortName, uint32_t speed, bool slient) {
    char acPortName[255] = {0};
    serial_port_windows_t *sp = calloc(sizeof(serial_port_windows_t), sizeof(uint8_t));

    if (sp == 0) {
        PrintAndLogEx(WARNING, "UART failed to allocate memory\n");
        return INVALID_SERIAL_PORT;
    }

    sp->hSocket = INVALID_SOCKET; // default: serial port

    sp->udpBuffer = NULL;
    rx_empty_counter = 0;
    g_conn.send_via_local_ip = false;
    g_conn.send_via_ip = PM3_NONE;

    char *prefix = str_dup(pcPortName);
    if (prefix == NULL) {
        PrintAndLogEx(ERR, "error: string duplication");
        free(sp);
        return INVALID_SERIAL_PORT;
    }
    str_lower(prefix);

    bool isTCP = false;
    bool isUDP = false;
    if (strlen(prefix) > 4) {
        isTCP = (memcmp(prefix, "tcp:", 4) == 0);
        isUDP = (memcmp(prefix, "udp:", 4) == 0);
    }

    if (isTCP || isUDP) {

        free(prefix);

        struct addrinfo *addr = NULL, *rp;

        char *addrPortStr = str_dup(pcPortName + 4);
        if (addrPortStr == NULL) {
            PrintAndLogEx(ERR, "error: string duplication");
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        timeout.tv_usec = UART_NET_CLIENT_RX_TIMEOUT_MS * 1000;

        // find the "bind" option
        char *bindAddrPortStr = strstr(addrPortStr, ",bind=");
        const char *bindAddrStr = NULL;
        const char *bindPortStr = NULL;
        bool isBindingIPv6 = false;

        if (bindAddrPortStr != NULL) {
            *bindAddrPortStr = '\0'; // as the end of target address (and port)
            bindAddrPortStr += 6; // strlen(",bind=")

            int result = uart_parse_address_port(bindAddrPortStr, &bindAddrStr, &bindPortStr, &isBindingIPv6);
            if (result != PM3_SUCCESS) {
                if (result == PM3_ESOFT) {
                    PrintAndLogEx(ERR, "error: wrong address: [] unmatched in bind option");
                } else {
                    PrintAndLogEx(ERR, "error: failed to parse address and port in bind option");
                }
                free(addrPortStr);
                free(sp);
                return INVALID_SERIAL_PORT;
            }

            // for bind option, it's possible to only specify address or port
            if (strlen(bindAddrStr) == 0) {
                bindAddrStr = NULL;
            }
            if (bindPortStr != NULL && strlen(bindPortStr) == 0) {
                bindPortStr = NULL;
            }
        }

        const char *addrStr = NULL;
        const char *portStr = NULL;
        bool isIPv6 = false;

        int result = uart_parse_address_port(addrPortStr, &addrStr, &portStr, &isIPv6);
        if (result != PM3_SUCCESS) {
            if (result == PM3_ESOFT) {
                PrintAndLogEx(ERR, "error: wrong address: [] unmatched");
            } else {
                PrintAndLogEx(ERR, "error: failed to parse address and port");
            }
            free(addrPortStr);
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        g_conn.send_via_ip = isIPv6 ? (isTCP ? PM3_TCPv6 : PM3_UDPv6) : (isTCP ? PM3_TCPv4 : PM3_UDPv4);
        portStr = (portStr == NULL) ? "18888" : portStr;

        WSADATA wsaData;
        struct addrinfo info;
        int iResult;

        iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) {
            PrintAndLogEx(ERR, "error: WSAStartup failed with error: %d", iResult);
            free(addrPortStr);
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        memset(&info, 0, sizeof(info));
        info.ai_family = AF_UNSPEC;
        info.ai_socktype = isTCP ? SOCK_STREAM : SOCK_DGRAM;
        info.ai_protocol = isTCP ? IPPROTO_TCP : IPPROTO_UDP;

        if ((strstr(addrStr, "localhost") != NULL) ||
                (strstr(addrStr, "127.0.0.1") != NULL) ||
                (strstr(addrStr, "::1") != NULL)) {
            g_conn.send_via_local_ip = true;
        }

        int s = getaddrinfo(addrStr, portStr, &info, &addr);
        if (s != 0) {
            PrintAndLogEx(ERR, "error: getaddrinfo: %d: %s", s, gai_strerror(s));
            freeaddrinfo(addr);
            free(addrPortStr);
            free(sp);
            WSACleanup();
            return INVALID_SERIAL_PORT;
        }

        SOCKET hSocket = INVALID_SOCKET;
        for (rp = addr; rp != NULL; rp = rp->ai_next) {
            hSocket = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            if (hSocket == INVALID_SOCKET) {
                continue;
            }

            if (!uart_bind(&hSocket, bindAddrStr, bindPortStr, isBindingIPv6)) {
                PrintAndLogEx(ERR, "error: Could not bind. error: %u", WSAGetLastError());
                closesocket(hSocket);
                hSocket = INVALID_SOCKET;
                freeaddrinfo(addr);
                free(addrPortStr);
                free(sp);
                WSACleanup();
                return INVALID_SERIAL_PORT;
            }

            if (connect(hSocket, rp->ai_addr, (int)rp->ai_addrlen) != INVALID_SOCKET) {
                break;
            }

            closesocket(hSocket);
            hSocket = INVALID_SOCKET;
        }

        freeaddrinfo(addr);
        free(addrPortStr);

        if (rp == NULL) {               /* No address succeeded */
            if (slient == false) {
                PrintAndLogEx(ERR, "error: Could not connect");
            }
            WSACleanup();
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        sp->hSocket = hSocket;

        if (isTCP) {
            int one = 1;
            int res = setsockopt(sp->hSocket, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
            if (res != 0) {
                closesocket(hSocket);
                WSACleanup();
                free(sp);
                return INVALID_SERIAL_PORT;
            }
        } else if (isUDP) {
            sp->udpBuffer = RingBuf_create(MAX(sizeof(PacketResponseNGRaw), sizeof(PacketResponseOLD)) * 30);
        }

        return sp;
    }

    // Copy the input "com?" to "\\.\COM?" format
    snprintf(acPortName, sizeof(acPortName), "\\\\.\\%s", pcPortName);
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
    g_conn.send_via_ip = PM3_NONE;
    return sp;
}

void uart_close(const serial_port sp) {
    serial_port_windows_t *spw = (serial_port_windows_t *)sp;
    if (spw->hSocket != INVALID_SOCKET) {
        shutdown(spw->hSocket, SD_BOTH);
        closesocket(spw->hSocket);
        WSACleanup();
    }
    RingBuf_destroy(spw->udpBuffer);
    if (spw->hPort != INVALID_HANDLE_VALUE)
        CloseHandle(spw->hPort);
    free(sp);
}

bool uart_set_speed(serial_port sp, const uint32_t uiPortSpeed) {
    serial_port_windows_t *spw = (serial_port_windows_t *)sp;

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
    const serial_port_windows_t *spw = (serial_port_windows_t *)sp;
    if (spw->hSocket == INVALID_SOCKET) {
        // serial port
        uart_reconfigure_timeouts_polling(sp);

        int res = ReadFile(spw->hPort, pbtRx, pszMaxRxLen, (LPDWORD)pszRxLen, NULL);
        if (res)
            return PM3_SUCCESS;

        int errorcode = GetLastError();

        if (res == 0 && errorcode == 2) {
            return PM3_EIO;
        }

        return PM3_ENOTTY;
    } else {
        // TCP or UDP
        uint32_t byteCount;  // FIONREAD returns size on 32b
        fd_set rfds;
        struct timeval tv;

        if (newtimeout_pending) {
            timeout.tv_usec = newtimeout_value * 1000;
            newtimeout_pending = false;
        }
        // Reset the output count
        *pszRxLen = 0;
        do {
            int res;
            if (spw->udpBuffer != NULL) {
                // for UDP connection, try to use the data from the buffer

                byteCount = RingBuf_getAvailableSize(spw->udpBuffer);
                // Cap the number of bytes, so we don't overrun the buffer
                if (pszMaxRxLen - (*pszRxLen) < byteCount) {
                    // PrintAndLogEx(ERR, "UART:: RX prevent overrun (have %u, need %u)", pszMaxRxLen - (*pszRxLen), byteCount);
                    byteCount = pszMaxRxLen - (*pszRxLen);
                }
                res = RingBuf_dequeueBatch(spw->udpBuffer, pbtRx + (*pszRxLen), byteCount);
                *pszRxLen += res;

                if (*pszRxLen == pszMaxRxLen) {
                    // We have all the data we wanted.
                    return PM3_SUCCESS;
                }
            }

            // Reset file descriptor
            FD_ZERO(&rfds);
            FD_SET(spw->hSocket, &rfds);
            tv = timeout;
            // the first argument nfds is ignored in Windows
            res = select(0, &rfds, NULL, NULL, &tv);

            // Read error
            if (res == SOCKET_ERROR) {
                return PM3_EIO;
            }

            // Read time-out
            if (res == 0) {
                if (*pszRxLen == 0) {
                    // We received no data
                    return PM3_ENODATA;
                } else {
                    // We received some data, but nothing more is available
                    return PM3_SUCCESS;
                }
            }

            // Retrieve the count of the incoming bytes
            res = ioctlsocket(spw->hSocket, FIONREAD, (u_long *)&byteCount);
            // PrintAndLogEx(ERR, "UART:: RX ioctl res %d byteCount %u", res, byteCount);
            if (res == SOCKET_ERROR) {
                // error occurred (maybe disconnected)
                // This happens when USB-CDC connection is lost
                return PM3_ENOTTY;
            } else if (byteCount == 0) {
                // select() > 0 && byteCount > 0 ===> data available
                // select() > 0 && byteCount always equals to 0 ===> maybe disconnected
                // This happens when TCP connection is lost
                rx_empty_counter++;
                if (rx_empty_counter > 3) {
                    return PM3_ENOTTY;
                }
            } else {
                rx_empty_counter = 0;
            }

            // For UDP connection, put the incoming data into the buffer and handle them in the next round
            if (spw->udpBuffer != NULL) {
                if (RingBuf_getContinousAvailableSize(spw->udpBuffer) >= byteCount) {
                    // write to the buffer directly
                    res = recv(spw->hSocket, (char *)RingBuf_getRearPtr(spw->udpBuffer), RingBuf_getAvailableSize(spw->udpBuffer), 0);
                    if (res >= 0) {
                        RingBuf_postEnqueueBatch(spw->udpBuffer, res);
                    }
                } else {
                    // use transit buffer
                    uint8_t transitBuf[MAX(sizeof(PacketResponseNGRaw), sizeof(PacketResponseOLD)) * 30];
                    res = recv(spw->hSocket, (char *)transitBuf, RingBuf_getAvailableSize(spw->udpBuffer), 0);
                    RingBuf_enqueueBatch(spw->udpBuffer, transitBuf, res);
                }
                // Stop if the OS has some troubles reading the data
                if (res < 0) {
                    return PM3_EIO;
                }
                continue;
            }

            // Cap the number of bytes, so we don't overrun the buffer
            if (pszMaxRxLen - (*pszRxLen) < byteCount) {
                //            PrintAndLogEx(ERR, "UART:: RX prevent overrun (have %u, need %u)", pszMaxRxLen - (*pszRxLen), byteCount);
                byteCount = pszMaxRxLen - (*pszRxLen);
            }

            // There is something available, read the data
            res = recv(spw->hSocket, (char *)pbtRx + (*pszRxLen), byteCount, 0);

            // Stop if the OS has some troubles reading the data
            if (res <= 0) { // includes 0(gracefully closed) and -1(SOCKET_ERROR)
                return PM3_EIO;
            }

            *pszRxLen += res;

            if (*pszRxLen == pszMaxRxLen) {
                // We have all the data we wanted.
                return PM3_SUCCESS;
            }
        } while (byteCount);

        return PM3_SUCCESS;
    }
}

int uart_send(const serial_port sp, const uint8_t *p_tx, const uint32_t len) {
    const serial_port_windows_t *spw = (serial_port_windows_t *)sp;
    if (spw->hSocket == INVALID_SOCKET) { // serial port
        DWORD txlen = 0;
        int res = WriteFile(spw->hPort, p_tx, len, &txlen, NULL);
        if (res)
            return PM3_SUCCESS;

        int errorcode = GetLastError();
        if (res == 0 && errorcode == 2) {
            return PM3_EIO;
        }
        return PM3_ENOTTY;
    } else { // TCP
        uint32_t pos = 0;
        fd_set wfds;
        struct timeval tv;

        while (pos < len) {
            // Reset file descriptor
            FD_ZERO(&wfds);
            FD_SET(spw->hSocket, &wfds);
            tv = timeout;
            // the first argument nfds is ignored in Windows
            int res = select(0, NULL, &wfds, NULL, &tv);

            // Write error
            if (res == SOCKET_ERROR) {
                PrintAndLogEx(ERR, "UART:: write error (%d)", res);
                return PM3_ENOTTY;
            }

            // Write time-out
            if (res == 0) {
                PrintAndLogEx(ERR, "UART:: write time-out");
                return PM3_ETIMEOUT;
            }

            // Send away the bytes
            res = send(spw->hSocket, (const char *)p_tx + pos, len - pos, 0);

            // Stop if the OS has some troubles sending the data
            if (res <= 0)
                return PM3_EIO;

            pos += res;
        }
        return PM3_SUCCESS;

    }
}

#endif
