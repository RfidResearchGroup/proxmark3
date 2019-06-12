//-----------------------------------------------------------------------------
// platform-independant sleep macros
//-----------------------------------------------------------------------------

#ifndef SLEEP_H__
#define SLEEP_H__

#ifdef _WIN32
    #include <windows.h>
    #define msleep(n) Sleep(n)
#else
    #include <time.h>
    #include <errno.h>
    static void nsleep(uint64_t n) {
        struct timespec timeout;
        timeout.tv_sec = n / 1000000000;
        timeout.tv_nsec = n % 1000000000;
        while (nanosleep(&timeout, &timeout) && errno == EINTR);
    }
    #define msleep(n) nsleep(1000000 * (uint64_t)n)
#endif

#endif
