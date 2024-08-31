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
// User API
//-----------------------------------------------------------------------------

#include "pm3.h"

#include <stdlib.h>

#include "proxmark3.h"
#include "cmdmain.h"
#include "ui.h"
#include "usart_defs.h"
#include "util_posix.h"
#include "comms.h"

pm3_device_t *pm3_open(const char *port) {
    pm3_init();
    OpenProxmark(&g_session.current_device, port, false, 20, false, USART_BAUD_RATE);
    if (g_session.pm3_present && (TestProxmark(g_session.current_device) != PM3_SUCCESS)) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " cannot communicate with the Proxmark3\n");
        CloseProxmark(g_session.current_device);
    }

    if ((port != NULL) && (!g_session.pm3_present))
        exit(EXIT_FAILURE);

    if (!g_session.pm3_present) {
        PrintAndLogEx(INFO, _RED_("OFFLINE") " mode");
    }
    // For now, there is no real device context:
    return g_session.current_device;
}

void pm3_close(pm3_device_t *dev) {
    // Clean up the port
    if (g_session.pm3_present) {
        clearCommandBuffer();
        SendCommandNG(CMD_QUIT_SESSION, NULL, 0);
        msleep(100); // Make sure command is sent before killing client
        CloseProxmark(dev);
    }
    free_grabber();
}

int pm3_console(pm3_device_t *dev, const char *cmd, bool passthru) {
    // For now, there is no real device context:
    (void) dev;
    uint8_t prev_printAndLog = g_printAndLog;
    if (! passthru) {
        g_printAndLog |= PRINTANDLOG_GRAB;
        g_printAndLog &= ~PRINTANDLOG_PRINT;
    }
    int ret = CommandReceived(cmd);
    g_printAndLog = prev_printAndLog;
    return ret;
}

const char *pm3_name_get(pm3_device_t *dev) {
    return dev->g_conn->serial_port_name;
}

const char *pm3_grabbed_output_get(pm3_device_t *dev) {
    if (g_grabbed_output.ptr != NULL) {
        char *tmp = g_grabbed_output.ptr;
        tmp[g_grabbed_output.size] = 0;
        g_grabbed_output.idx = 0;
        g_grabbed_output.size = 0;
        return tmp;
    } else {
        return "";
    }
}

pm3_device_t *pm3_get_current_dev(void) {
    return g_session.current_device;
}
