#ifndef SLEEP_H__
#define SLEEP_H__

#ifdef WIN32
#include <windows.h>
#define sleep(n) Sleep(1000 * n)
#define msleep(n) Sleep(n)
#else
#include <unistd.h>
#define msleep(n) usleep(1000 * n)
#endif

#endif

