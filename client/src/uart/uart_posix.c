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

// Test if we are dealing with posix operating systems
#ifndef _WIN32
#define _DEFAULT_SOURCE

#include "uart.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifdef HAVE_BLUEZ
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#endif

#include "comms.h"
#include "ui.h"

// Taken from https://github.com/unbit/uwsgi/commit/b608eb1772641d525bfde268fe9d6d8d0d5efde7
#ifndef SOL_TCP
# define SOL_TCP IPPROTO_TCP
#endif

typedef struct termios term_info;
typedef struct {
    int fd;           // Serial port file descriptor
    term_info tiOld;  // Terminal info before using the port
    term_info tiNew;  // Terminal info during the transaction
} serial_port_unix_t_t;

// see pm3_cmd.h
struct timeval timeout = {
    .tv_sec  = 0, // 0 second
    .tv_usec = UART_FPC_CLIENT_RX_TIMEOUT_MS * 1000
};

static uint32_t newtimeout_value = 0;
static bool newtimeout_pending = false;

int uart_reconfigure_timeouts(uint32_t value) {
    newtimeout_value = value;
    newtimeout_pending = true;
    return PM3_SUCCESS;
}

uint32_t uart_get_timeouts(void) {
    return newtimeout_value;
}

serial_port uart_open(const char *pcPortName, uint32_t speed) {
    serial_port_unix_t_t *sp = calloc(sizeof(serial_port_unix_t_t), sizeof(uint8_t));

    if (sp == 0) {
        PrintAndLogEx(ERR, "UART failed to allocate memory");
        return INVALID_SERIAL_PORT;
    }

    // init timeouts
    timeout.tv_usec = UART_FPC_CLIENT_RX_TIMEOUT_MS * 1000;

    char *prefix = strdup(pcPortName);
    if (prefix == NULL) {
        PrintAndLogEx(ERR, "error:  string duplication");
        free(sp);
        return INVALID_SERIAL_PORT;
    }
    str_lower(prefix);

    if (memcmp(prefix, "tcp:", 4) == 0) {
        free(prefix);

        if (strlen(pcPortName) <= 4) {
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        struct addrinfo *addr = NULL, *rp;

        char *addrstr = strdup(pcPortName + 4);
        if (addrstr == NULL) {
            PrintAndLogEx(ERR, "error: string duplication");
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        timeout.tv_usec = UART_TCP_CLIENT_RX_TIMEOUT_MS * 1000;

        char *colon = strrchr(addrstr, ':');
        const char *portstr;
        if (colon) {
            portstr = colon + 1;
            *colon = '\0';
        } else {
            portstr = "18888";
        }

        struct addrinfo info;

        memset(&info, 0, sizeof(info));

        info.ai_socktype = SOCK_STREAM;

        int s = getaddrinfo(addrstr, portstr, &info, &addr);
        if (s != 0) {
            PrintAndLogEx(ERR, "error: getaddrinfo: %s", gai_strerror(s));
            freeaddrinfo(addr);
            free(addrstr);
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        int sfd;
        for (rp = addr; rp != NULL; rp = rp->ai_next) {
            sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            if (sfd == -1)
                continue;

            if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
                break;

            close(sfd);
        }

        freeaddrinfo(addr);
        free(addrstr);

        if (rp == NULL) {               /* No address succeeded */
            PrintAndLogEx(ERR, "error: Could not connect");
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        sp->fd = sfd;

        int one = 1;
        int res = setsockopt(sp->fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one));
        if (res != 0) {
            free(sp);
            return INVALID_SERIAL_PORT;
        }
        return sp;
    }

    if (memcmp(prefix, "bt:", 3) == 0) {
        free(prefix);

#ifdef HAVE_BLUEZ
        if (strlen(pcPortName) != 20) {
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        char *addrstr = strndup(pcPortName + 3, 17);
        if (addrstr == NULL) {
            PrintAndLogEx(ERR, "error: string duplication");
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        struct sockaddr_rc addr = { 0 };
        addr.rc_family = AF_BLUETOOTH;
        addr.rc_channel = (uint8_t) 1;
        if (str2ba(addrstr, &addr.rc_bdaddr) != 0) {
            PrintAndLogEx(ERR, "Invalid Bluetooth MAC address " _RED_("%s"), addrstr);
            free(addrstr);
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        int sfd = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
        if (sfd == -1) {
            PrintAndLogEx(ERR, "Error opening Bluetooth socket");
            free(addrstr);
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            PrintAndLogEx(ERR, "Error: cannot connect device " _YELLOW_("%s") " over Bluetooth", addrstr);
            close(sfd);
            free(addrstr);
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        sp->fd = sfd;
        return sp;
#else // HAVE_BLUEZ
        PrintAndLogEx(ERR, "Sorry, this client doesn't support native Bluetooth addresses");
        free(sp);
        return INVALID_SERIAL_PORT;
#endif // HAVE_BLUEZ
    }
    // The socket for abstract namespace implement.
    // Is local socket buffer, not a TCP or any net connection!
    // so, you can't connect with address like: 127.0.0.1, or any IP
    // see http://man7.org/linux/man-pages/man7/unix.7.html
    if (memcmp(prefix, "socket:", 7) == 0) {
        free(prefix);

        if (strlen(pcPortName) <= 7) {
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        // we must use max timeout!
        timeout.tv_usec = UART_TCP_CLIENT_RX_TIMEOUT_MS * 1000;

        size_t servernameLen = (strlen(pcPortName) - 7) + 1;
        char serverNameBuf[servernameLen];
        memset(serverNameBuf, '\0', servernameLen);
        for (int i = 7, j = 0; j < servernameLen; ++i, ++j) {
            serverNameBuf[j] = pcPortName[i];
        }
        serverNameBuf[servernameLen - 1] = '\0';

        int localsocket, len;
        struct sockaddr_un remote;

        remote.sun_path[0] = '\0';  // abstract namespace
        strcpy(remote.sun_path + 1, serverNameBuf);
        remote.sun_family = AF_LOCAL;
        int nameLen = strlen(serverNameBuf);
        len = 1 + nameLen + offsetof(struct sockaddr_un, sun_path);

        if ((localsocket = socket(PF_LOCAL, SOCK_STREAM, 0)) == -1) {
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        if (connect(localsocket, (struct sockaddr *) &remote, len) == -1) {
            close(localsocket);
            free(sp);
            return INVALID_SERIAL_PORT;
        }

        sp->fd = localsocket;
        return sp;
    }

    free(prefix);

    sp->fd = open(pcPortName, O_RDWR | O_NOCTTY | O_NDELAY | O_NONBLOCK);
    if (sp->fd == -1) {
        uart_close(sp);
        return INVALID_SERIAL_PORT;
    }

    // Finally figured out a way to claim a serial port interface under unix
    // We just try to set a (advisory) lock on the file descriptor
    struct flock fl;
    fl.l_type   = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;
    fl.l_pid    = getpid();

    // Does the system allows us to place a lock on this file descriptor
    if (fcntl(sp->fd, F_SETLK, &fl) == -1) {
        // A conflicting lock is held by another process
        free(sp);
        return CLAIMED_SERIAL_PORT;
    }

    // Try to retrieve the old (current) terminal info struct
    if (tcgetattr(sp->fd, &sp->tiOld) == -1) {
        PrintAndLogEx(ERR, "error: UART get terminal info attribute");
        uart_close(sp);
        return INVALID_SERIAL_PORT;
    }

    // Duplicate the (old) terminal info struct
    sp->tiNew = sp->tiOld;

    // Configure the serial port
    sp->tiNew.c_cflag = CS8 | CLOCAL | CREAD;
    sp->tiNew.c_iflag = IGNPAR;
    sp->tiNew.c_oflag = 0;
    sp->tiNew.c_lflag = 0;

    // Block until n bytes are received
    sp->tiNew.c_cc[VMIN] = 0;
    // Block until a timer expires (n * 100 mSec.)
    sp->tiNew.c_cc[VTIME] = 0;

    // Try to set the new terminal info struct
    if (tcsetattr(sp->fd, TCSANOW, &sp->tiNew) == -1) {
        PrintAndLogEx(ERR, "error: UART set terminal info attribute");
        perror("tcsetattr() error");
        uart_close(sp);
        return INVALID_SERIAL_PORT;
    }

    // Flush all lingering data that may exist
    tcflush(sp->fd, TCIOFLUSH);

    if (!uart_set_speed(sp, speed)) {
        // try fallback automatically
        speed = 115200;
        if (!uart_set_speed(sp, speed)) {
            uart_close(sp);
            PrintAndLogEx(ERR, "UART error while setting baudrate");
            return INVALID_SERIAL_PORT;
        }
    }
    g_conn.uart_speed = uart_get_speed(sp);
    return sp;
}

void uart_close(const serial_port sp) {
    serial_port_unix_t_t *spu = (serial_port_unix_t_t *)sp;
    tcflush(spu->fd, TCIOFLUSH);
    tcsetattr(spu->fd, TCSANOW, &(spu->tiOld));
    struct flock fl;
    fl.l_type   = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;
    fl.l_pid    = getpid();

    // Does the system allows us to place a lock on this file descriptor
    int err = fcntl(spu->fd, F_SETLK, &fl);
    if (err == -1) {
        //silent error message as it can be called from uart_open failing modes, e.g. when waiting for port to appear
        //PrintAndLogEx(ERR, "UART error while closing port");
    }
    close(spu->fd);
    free(sp);
}

int uart_receive(const serial_port sp, uint8_t *pbtRx, uint32_t pszMaxRxLen, uint32_t *pszRxLen) {
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
        // Reset file descriptor
        FD_ZERO(&rfds);
        FD_SET(((serial_port_unix_t_t *)sp)->fd, &rfds);
        tv = timeout;
        int res = select(((serial_port_unix_t_t *)sp)->fd + 1, &rfds, NULL, NULL, &tv);

        // Read error
        if (res < 0) {
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
        res = ioctl(((serial_port_unix_t_t *)sp)->fd, FIONREAD, &byteCount);
//        PrintAndLogEx(ERR, "UART:: RX ioctl res %d byteCount %u", res, byteCount);
        if (res < 0) return PM3_ENOTTY;

        // Cap the number of bytes, so we don't overrun the buffer
        if (pszMaxRxLen - (*pszRxLen) < byteCount) {
//            PrintAndLogEx(ERR, "UART:: RX prevent overrun (have %u, need %u)", pszMaxRxLen - (*pszRxLen), byteCount);
            byteCount = pszMaxRxLen - (*pszRxLen);
        }

        // There is something available, read the data
        res = read(((serial_port_unix_t_t *)sp)->fd, pbtRx + (*pszRxLen), byteCount);

        // Stop if the OS has some troubles reading the data
        if (res <= 0) {
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

int uart_send(const serial_port sp, const uint8_t *pbtTx, const uint32_t len) {
    uint32_t pos = 0;
    fd_set rfds;
    struct timeval tv;

    while (pos < len) {
        // Reset file descriptor
        FD_ZERO(&rfds);
        FD_SET(((serial_port_unix_t_t *)sp)->fd, &rfds);
        tv = timeout;
        int res = select(((serial_port_unix_t_t *)sp)->fd + 1, NULL, &rfds, NULL, &tv);

        // Write error
        if (res < 0) {
            PrintAndLogEx(ERR, "UART:: write error (%d)", res);
            return PM3_ENOTTY;
        }

        // Write time-out
        if (res == 0) {
            PrintAndLogEx(ERR, "UART:: write time-out");
            return PM3_ETIMEOUT;
        }

        // Send away the bytes
        res = write(((serial_port_unix_t_t *)sp)->fd, pbtTx + pos, len - pos);

        // Stop if the OS has some troubles sending the data
        if (res <= 0)
            return PM3_EIO;

        pos += res;
    }
    return PM3_SUCCESS;
}

bool uart_set_speed(serial_port sp, const uint32_t uiPortSpeed) {
    const serial_port_unix_t_t *spu = (serial_port_unix_t_t *)sp;
    speed_t stPortSpeed;
    switch (uiPortSpeed) {
        case 0:
            stPortSpeed = B0;
            break;
        case 50:
            stPortSpeed = B50;
            break;
        case 75:
            stPortSpeed = B75;
            break;
        case 110:
            stPortSpeed = B110;
            break;
        case 134:
            stPortSpeed = B134;
            break;
        case 150:
            stPortSpeed = B150;
            break;
        case 300:
            stPortSpeed = B300;
            break;
        case 600:
            stPortSpeed = B600;
            break;
        case 1200:
            stPortSpeed = B1200;
            break;
        case 1800:
            stPortSpeed = B1800;
            break;
        case 2400:
            stPortSpeed = B2400;
            break;
        case 4800:
            stPortSpeed = B4800;
            break;
        case 9600:
            stPortSpeed = B9600;
            break;
        case 19200:
            stPortSpeed = B19200;
            break;
        case 38400:
            stPortSpeed = B38400;
            break;
#  ifdef B57600
        case 57600:
            stPortSpeed = B57600;
            break;
#  endif
#  ifdef B115200
        case 115200:
            stPortSpeed = B115200;
            break;
#  endif
#  ifdef B230400
        case 230400:
            stPortSpeed = B230400;
            break;
#  endif
#  ifdef B460800
        case 460800:
            stPortSpeed = B460800;
            break;
#  endif
#  ifdef B921600
        case 921600:
            stPortSpeed = B921600;
            break;
#  endif
#  ifdef B1382400
        case 1382400:
            stPortSpeed = B1382400;
            break;
#  endif

        default:
            return false;
    };

    struct termios ti;
    if (tcgetattr(spu->fd, &ti) == -1)
        return false;

    // Set port speed (Input and Output)
    cfsetispeed(&ti, stPortSpeed);
    cfsetospeed(&ti, stPortSpeed);
    bool result = tcsetattr(spu->fd, TCSANOW, &ti) != -1;
    if (result)
        g_conn.uart_speed = uiPortSpeed;
    return result;
}

uint32_t uart_get_speed(const serial_port sp) {
    struct termios ti;
    uint32_t uiPortSpeed;
    const serial_port_unix_t_t *spu = (serial_port_unix_t_t *)sp;

    if (tcgetattr(spu->fd, &ti) == -1)
        return 0;

    // Set port speed (Input)
    speed_t stPortSpeed = cfgetispeed(&ti);
    switch (stPortSpeed) {
        case B0:
            uiPortSpeed = 0;
            break;
        case B50:
            uiPortSpeed = 50;
            break;
        case B75:
            uiPortSpeed = 75;
            break;
        case B110:
            uiPortSpeed = 110;
            break;
        case B134:
            uiPortSpeed = 134;
            break;
        case B150:
            uiPortSpeed = 150;
            break;
        case B300:
            uiPortSpeed = 300;
            break;
        case B600:
            uiPortSpeed = 600;
            break;
        case B1200:
            uiPortSpeed = 1200;
            break;
        case B1800:
            uiPortSpeed = 1800;
            break;
        case B2400:
            uiPortSpeed = 2400;
            break;
        case B4800:
            uiPortSpeed = 4800;
            break;
        case B9600:
            uiPortSpeed = 9600;
            break;
        case B19200:
            uiPortSpeed = 19200;
            break;
        case B38400:
            uiPortSpeed = 38400;
            break;
#  ifdef B57600
        case B57600:
            uiPortSpeed = 57600;
            break;
#  endif
#  ifdef B115200
        case B115200:
            uiPortSpeed = 115200;
            break;
#  endif
#  ifdef B230400
        case B230400:
            uiPortSpeed = 230400;
            break;
#  endif
#  ifdef B460800
        case B460800:
            uiPortSpeed = 460800;
            break;
#  endif
#  ifdef B921600
        case B921600:
            uiPortSpeed = 921600;
            break;
#  endif
        default:
            return 0;
    };
    return uiPortSpeed;
}
#endif
