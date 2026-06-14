/*
MIT License

Copyright(c) 2018 Liam Bindle

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files(the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions :

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "mqtt.h"

/**
 * @file
 * @brief Implements @ref mqtt_pal_sendall and @ref mqtt_pal_recvall and
 *        any platform-specific helpers you'd like.
 * @cond Doxygen_Suppress
 */

#if defined(MQTT_USE_CUSTOM_SOCKET_HANDLE)

/*
 * In case of MQTT_USE_CUSTOM_SOCKET_HANDLE, a pal implemantation is
 * provided by the user.
 */

/* Note: Some toolchains complain on an object without symbols */

int _mqtt_pal_dummy;

#else /* defined(MQTT_USE_CUSTOM_SOCKET_HANDLE) */

#if defined(MQTT_USE_MBEDTLS)
#include <mbedtls/ssl.h>

ssize_t mqtt_pal_sendall(mqtt_pal_socket_handle fd, const void *buf, size_t len, int flags) {
    enum MQTTErrors error = 0;
    size_t sent = 0;
    while (sent < len) {
        int rv = mbedtls_ssl_write(fd, (const unsigned char *)buf + sent, len - sent);
        if (rv < 0) {
            if (rv == MBEDTLS_ERR_SSL_WANT_READ ||
                    rv == MBEDTLS_ERR_SSL_WANT_WRITE
#if defined(MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS)
                    || rv == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS
#endif
#if defined(MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)
                    || rv == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS
#endif
               ) {
                /* should call mbedtls_ssl_write later again */
                break;
            }
            error = MQTT_ERROR_SOCKET_ERROR;
            break;
        }
        /*
         * Note: rv can be 0 here eg. when mbedtls just flushed
         * the previous incomplete record.
         *
         * Note: we never send an empty TLS record.
         */
        sent += (size_t) rv;
    }
    if (sent == 0) {
        return error;
    }
    return (ssize_t)sent;
}

ssize_t mqtt_pal_recvall(mqtt_pal_socket_handle fd, void *buf, size_t bufsz, int flags) {
    const void *const start = buf;
    enum MQTTErrors error = 0;
    int rv;
    do {
        rv = mbedtls_ssl_read(fd, (unsigned char *)buf, bufsz);
        if (rv == 0) {
            /*
             * Note: mbedtls_ssl_read returns 0 when the underlying
             * transport was closed without CloseNotify.
             *
             * Raise an error to trigger a reconnect.
             */
            error = MQTT_ERROR_SOCKET_ERROR;
            break;
        }
        if (rv < 0) {
            if (rv == MBEDTLS_ERR_SSL_WANT_READ ||
                    rv == MBEDTLS_ERR_SSL_WANT_WRITE
#if defined(MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS)
                    || rv == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS
#endif
#if defined(MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)
                    || rv == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS
#endif
               ) {
                /* should call mbedtls_ssl_read later again */
                break;
            }
            /* Note: MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY is handled here. */
            error = MQTT_ERROR_SOCKET_ERROR;
            break;
        }
        buf = (char *)buf + rv;
        bufsz -= (unsigned long)rv;
    } while (bufsz > 0);
    if (buf == start) {
        return error;
    }
    return (const char *)buf - (const char *)start;
}

#elif defined(__unix__) || defined(__APPLE__) || defined(__NuttX__)

#include <errno.h>

ssize_t mqtt_pal_sendall(mqtt_pal_socket_handle fd, const void *buf, size_t len, int flags) {
    enum MQTTErrors error = 0;
    size_t sent = 0;
    while (sent < len) {
        ssize_t rv = send(fd, (const char *)buf + sent, len - sent, flags);
        if (rv < 0) {
            if (errno == EAGAIN) {
                /* should call send later again */
                break;
            }
            error = MQTT_ERROR_SOCKET_ERROR;
            break;
        }
        if (rv == 0) {
            /* is this possible? maybe OS bug. */
            error = MQTT_ERROR_SOCKET_ERROR;
            break;
        }
        sent += (size_t) rv;
    }
    if (sent == 0) {
        return error;
    }
    return (ssize_t)sent;
}

ssize_t mqtt_pal_recvall(mqtt_pal_socket_handle fd, void *buf, size_t bufsz, int flags) {
    const void *const start = buf;
    enum MQTTErrors error = 0;
    ssize_t rv;
    do {
        rv = recv(fd, buf, bufsz, flags);
        if (rv == 0) {
            /*
             * recv returns 0 when the socket is (half) closed by the peer.
             *
             * Raise an error to trigger a reconnect.
             */
            error = MQTT_ERROR_SOCKET_ERROR;
            break;
        }
        if (rv < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* should call recv later again */
                break;
            }
            /* an error occurred that wasn't "nothing to read". */
            error = MQTT_ERROR_SOCKET_ERROR;
            break;
        }
        buf = (char *)buf + rv;
        bufsz -= (unsigned long)rv;
    } while (bufsz > 0);
    if (buf == start) {
        return error;
    }
    return (char *)buf - (const char *)start;
}

#elif defined(_MSC_VER) || defined(WIN32)

#include <errno.h>

ssize_t mqtt_pal_sendall(mqtt_pal_socket_handle fd, const void *buf, size_t len, int flags) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t tmp = send(fd, (char *)buf + sent, len - sent, flags);
        if (tmp < 1) {
            return MQTT_ERROR_SOCKET_ERROR;
        }
        sent += (size_t) tmp;
    }
    return sent;
}

ssize_t mqtt_pal_recvall(mqtt_pal_socket_handle fd, void *buf, size_t bufsz, int flags) {
    const char *const start = buf;
    ssize_t rv;
    do {
        rv = recv(fd, buf, bufsz, flags);
        if (rv > 0) {
            /* successfully read bytes from the socket */
            buf = (char *)buf + rv;
            bufsz -= rv;
        } else if (rv < 0) {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                /* an error occurred that wasn't "nothing to read". */
                return MQTT_ERROR_SOCKET_ERROR;
            }
        }
    } while (rv > 0 && bufsz > 0);

    return (ssize_t)((char *)buf - start);
}

#else

#error No PAL!

#endif

#endif /* defined(MQTT_USE_CUSTOM_SOCKET_HANDLE) */

/** @endcond */
