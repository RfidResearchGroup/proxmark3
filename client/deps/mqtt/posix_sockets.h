#if !defined(__POSIX_SOCKET_TEMPLATE_H__)
#define __POSIX_SOCKET_TEMPLATE_H__

#ifndef _WIN32

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

//  A template for opening a non-blocking POSIX socket.

void close_nb_socket(int sockfd);
int open_nb_socket(const char *addr, const char *port);

int open_nb_socket(const char *addr, const char *port) {

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC; /* IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Must be TCP */

    struct addrinfo *p, *servinfo;

    /* get address information */
    int rv = getaddrinfo(addr, port, &hints, &servinfo);
    if (rv != 0) {
        fprintf(stderr, "Failed to open socket (getaddrinfo): %s\n", gai_strerror(rv));
        return -1;
    }

    /* open the first possible socket */
    int sockfd = -1;
    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            continue;
        }

        /* connect to server */
        rv = connect(sockfd, p->ai_addr, p->ai_addrlen);
        if (rv == -1) {
            close(sockfd);
            sockfd = -1;
            continue;
        }
        break;
    }

    // free servinfo 
    freeaddrinfo(servinfo);

    // make non-blocking
    if (sockfd != -1) {
        fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);
    }

    return sockfd;
}

void close_nb_socket(int sockfd) {
    if (sockfd != -1) {
        close(sockfd);
    }
}
#endif
#endif