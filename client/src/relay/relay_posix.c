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
// TCP relay socket abstraction — POSIX implementation
//-----------------------------------------------------------------------------

#ifndef _WIN32

#include "relay.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "ui.h"

int relay_init(void) {
    return PM3_SUCCESS;
}

void relay_cleanup(void) {
}

relay_socket_t relay_listen_accept(uint16_t port, relay_socket_t *listen_sock) {

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        PrintAndLogEx(ERR, "Failed to create socket (%s)", strerror(errno));
        return RELAY_SOCKET_INVALID;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        PrintAndLogEx(ERR, "Failed to bind to port " _RED_("%u") " (%s)", port, strerror(errno));
        close(sock);
        return RELAY_SOCKET_INVALID;
    }

    if (listen(sock, 1) < 0) {
        PrintAndLogEx(ERR, "Failed to listen on socket (%s)", strerror(errno));
        close(sock);
        return RELAY_SOCKET_INVALID;
    }

    PrintAndLogEx(INFO, "Relay listening on port " _YELLOW_("%u") "...", port);

    int client = accept(sock, NULL, NULL);
    if (client < 0) {
        PrintAndLogEx(ERR, "Failed to accept connection (%s)", strerror(errno));
        close(sock);
        return RELAY_SOCKET_INVALID;
    }

    if (listen_sock != NULL) {
        *listen_sock = sock;
    }

    return client;
}

relay_socket_t relay_connect(const char *ip, uint16_t port) {

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        PrintAndLogEx(ERR, "Failed to create socket (%s)", strerror(errno));
        return RELAY_SOCKET_INVALID;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        PrintAndLogEx(ERR, "Invalid IP address... %s:%u", ip, port);
        close(sock);
        return RELAY_SOCKET_INVALID;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        PrintAndLogEx(ERR, "Connection error to %s:%u (%s)", ip, port, strerror(errno));
        close(sock);
        return RELAY_SOCKET_INVALID;
    }

    return sock;
}

int relay_send_all(relay_socket_t sock, const void *buf, uint32_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t remaining = len;

    while (remaining > 0) {
        ssize_t n = send(sock, p, remaining, 0);
        if (n <= 0) {
            return -1;
        }
        p += n;
        remaining -= (uint32_t)n;
    }
    return 0;
}

int relay_recv_all(relay_socket_t sock, void *buf, uint32_t len) {
    uint8_t *p = (uint8_t *)buf;
    uint32_t remaining = len;

    while (remaining > 0) {
        ssize_t n = recv(sock, p, remaining, 0);
        if (n <= 0) {
            return -1;
        }
        p += n;
        remaining -= (uint32_t)n;
    }
    return (int)len;
}

void relay_close(relay_socket_t sock) {
    if (sock != RELAY_SOCKET_INVALID) {
        close(sock);
    }
}

#endif // !_WIN32
