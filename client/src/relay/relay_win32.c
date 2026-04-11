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
// TCP relay socket abstraction — Win32 implementation
//-----------------------------------------------------------------------------

#ifdef _WIN32

#include "relay.h"

#include <stdio.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "ui.h"

static bool g_wsa_initialized = false;

int relay_init(void) {
    if (g_wsa_initialized) {
        return PM3_SUCCESS;
    }

    WSADATA wsa;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (ret != 0) {
        PrintAndLogEx(ERR, "WSAStartup failed with error %d", ret);
        return PM3_EFAILED;
    }

    g_wsa_initialized = true;
    return PM3_SUCCESS;
}

void relay_cleanup(void) {
    if (g_wsa_initialized) {
        WSACleanup();
        g_wsa_initialized = false;
    }
}

relay_socket_t relay_listen_accept(uint16_t port, relay_socket_t *listen_sock) {

    if (relay_init() != PM3_SUCCESS) {
        return RELAY_SOCKET_INVALID;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        PrintAndLogEx(ERR, "Failed to create socket (WSA %d)", WSAGetLastError());
        return RELAY_SOCKET_INVALID;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        PrintAndLogEx(ERR, "Failed to bind to port " _RED_("%u") " (WSA %d)", port, WSAGetLastError());
        closesocket(sock);
        return RELAY_SOCKET_INVALID;
    }

    if (listen(sock, 1) == SOCKET_ERROR) {
        PrintAndLogEx(ERR, "Failed to listen on socket (WSA %d)", WSAGetLastError());
        closesocket(sock);
        return RELAY_SOCKET_INVALID;
    }

    PrintAndLogEx(INFO, "Relay listening on port " _YELLOW_("%u") "...", port);

    SOCKET client = accept(sock, NULL, NULL);
    if (client == INVALID_SOCKET) {
        PrintAndLogEx(ERR, "Failed to accept connection (WSA %d)", WSAGetLastError());
        closesocket(sock);
        return RELAY_SOCKET_INVALID;
    }

    if (listen_sock != NULL) {
        *listen_sock = sock;
    }

    return client;
}

relay_socket_t relay_connect(const char *ip, uint16_t port) {

    if (relay_init() != PM3_SUCCESS) {
        return RELAY_SOCKET_INVALID;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        PrintAndLogEx(ERR, "Failed to create socket (WSA %d)", WSAGetLastError());
        return RELAY_SOCKET_INVALID;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        PrintAndLogEx(ERR, "Invalid IP address... %s:%u", ip, port);
        closesocket(sock);
        return RELAY_SOCKET_INVALID;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        PrintAndLogEx(ERR, "Connection error to %s:%u (WSA %d)", ip, port, WSAGetLastError());
        closesocket(sock);
        return RELAY_SOCKET_INVALID;
    }

    return sock;
}

int relay_send_all(relay_socket_t sock, const void *buf, uint32_t len) {
    const char *p = (const char *)buf;
    uint32_t remaining = len;

    while (remaining > 0) {
        int n = send(sock, p, (int)remaining, 0);
        if (n == SOCKET_ERROR || n <= 0) {
            return -1;
        }
        p += n;
        remaining -= (uint32_t)n;
    }
    return 0;
}

int relay_recv_all(relay_socket_t sock, void *buf, uint32_t len) {
    char *p = (char *)buf;
    uint32_t remaining = len;

    while (remaining > 0) {
        int n = recv(sock, p, (int)remaining, 0);
        if (n == SOCKET_ERROR || n <= 0) {
            return -1;
        }
        p += n;
        remaining -= (uint32_t)n;
    }
    return (int)len;
}

void relay_close(relay_socket_t sock) {
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }
}

#endif // _WIN32
