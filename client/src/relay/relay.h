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
// TCP relay socket abstraction layer
//-----------------------------------------------------------------------------

#ifndef RELAY_H__
#define RELAY_H__

#include "common.h"

#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET relay_socket_t;
#define RELAY_SOCKET_INVALID  INVALID_SOCKET
#else
typedef int relay_socket_t;
#define RELAY_SOCKET_INVALID  (-1)
#endif

// Initialize relay subsystem (call once at startup).
// On Win32 this calls WSAStartup; on POSIX it is a no-op.
int relay_init(void);

// Tear down relay subsystem (call once at shutdown).
// On Win32 this calls WSACleanup; on POSIX it is a no-op.
void relay_cleanup(void);

// Create a TCP server socket bound to INADDR_ANY:<port>, listen, and
// block until one client connects.  Returns the *client* fd/SOCKET.
// On error, returns RELAY_SOCKET_INVALID.  Caller owns both sockets;
// the listening socket is written to *listen_sock so it can be closed.
relay_socket_t relay_listen_accept(uint16_t port, relay_socket_t *listen_sock);

// Connect to a TCP server at ip:port.
// Returns the connected socket or RELAY_SOCKET_INVALID on error.
relay_socket_t relay_connect(const char *ip, uint16_t port);

// Send exactly `len` bytes from `buf`.
// Returns 0 on success, -1 on error.
int relay_send_all(relay_socket_t sock, const void *buf, uint32_t len);

// Receive exactly `len` bytes into `buf`.
// Returns number of bytes received, or -1 on error / disconnect.
int relay_recv_all(relay_socket_t sock, void *buf, uint32_t len);

// Close a relay socket.
void relay_close(relay_socket_t sock);

#endif // RELAY_H__
