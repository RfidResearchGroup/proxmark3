#ifndef LIBPM3PP_H
#define LIBPM3PP_H

#include "pm3.h"
#include "pm3_helper.hpp"
int pm3_console_async_wrapper(pm3 *dev, char *cmd, ConsoleHandler *console_handler);

#endif // LIBPM3PP_H
