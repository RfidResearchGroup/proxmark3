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

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif

bool uart_bind(void *socket, const char *bindAddrStr, const char *bindPortStr, bool isBindingIPv6) {
    if (bindAddrStr == NULL && bindPortStr == NULL)
        return true; // no need to bind

    struct sockaddr_storage bindSockaddr;
    memset(&bindSockaddr, 0, sizeof(bindSockaddr));
    int bindPort = 0; // 0: port unspecified
    if (bindPortStr != NULL)
        bindPort = atoi(bindPortStr);

    if (!isBindingIPv6) {
        struct sockaddr_in *bindSockaddr4 = (struct sockaddr_in *)&bindSockaddr;
        bindSockaddr4->sin_family = AF_INET;
        bindSockaddr4->sin_port = htons(bindPort);
        if (bindAddrStr == NULL)
            bindSockaddr4->sin_addr.s_addr = INADDR_ANY;
        else
            bindSockaddr4->sin_addr.s_addr = inet_addr(bindAddrStr);
    } else {
        struct sockaddr_in6 *bindSockaddr6 = (struct sockaddr_in6 *)&bindSockaddr;
        bindSockaddr6->sin6_family = AF_INET6;
        bindSockaddr6->sin6_port = htons(bindPort);
        if (bindAddrStr == NULL)
            bindSockaddr6->sin6_addr = in6addr_any;
        else
            inet_pton(AF_INET6, bindAddrStr, &(bindSockaddr6->sin6_addr));
    }
#ifdef _WIN32
    int res = bind(*(SOCKET *)socket, (struct sockaddr *)&bindSockaddr, sizeof(bindSockaddr));
#else
    int res = bind(*(int *)socket, (struct sockaddr *)&bindSockaddr, sizeof(bindSockaddr));
#endif
    return (res >= 0);
}

int uart_parse_address_port(char *addrPortStr, const char **addrStr, const char **portStr, bool *isIPv6) {

    if (addrPortStr == NULL || addrStr == NULL || portStr == NULL) {
        return PM3_EINVARG;
    }

    *addrStr = addrPortStr;
    *portStr = NULL;

    // find the start of the address
    char *endBracket = strrchr(addrPortStr, ']');
    if (addrPortStr[0] == '[') {
        *addrStr += 1;
        if (endBracket == NULL) {
            // [] unmatched
            return PM3_ESOFT;
        }
    }

    if (isIPv6 != NULL) {
        // Assume v4
        *isIPv6 = false;
    }

    // find the port
    char *lColon = strchr(addrPortStr, ':');
    char *rColon = strrchr(addrPortStr, ':');
    if (rColon == NULL) {
        // no colon
        // "<ipv4 address>", "[<ipv4 address>]"
        *portStr = NULL;
    } else if (lColon == rColon) {
        // only one colon
        // "<ipv4 address>:<port>", "[<ipv4 address>]:<port>"
        *portStr = rColon + 1;
    } else {
        // two or more colon, IPv6 address
        // "[<ipv6 address>]:<port>"
        // "<ipv6 address>", "[<ipv6 address>]"
        if (endBracket != NULL && rColon == endBracket + 1) {
            *portStr = rColon + 1;
        } else {
            *portStr = NULL;
        }

        if (isIPv6 != NULL) {
            *isIPv6 = true;
        }
    }

    // handle the end of the address
    if (endBracket != NULL) {
        *endBracket = '\0';
    } else if (rColon != NULL && lColon == rColon) {
        *rColon = '\0';
    }

    return PM3_SUCCESS;
}