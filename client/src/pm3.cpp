//-----------------------------------------------------------------------------
// User API
//-----------------------------------------------------------------------------

#include "pm3.hpp"

#include <stdlib.h>

#include "proxmark3.h"
#include "cmdmain.h"
#include "ui.h"
#include "usart_defs.h"
#include "util_posix.h"
#include "comms.h"

pm3_device *pm3_open(char *port) {
    pm3_init();
    OpenProxmark(&session.current_device, port, false, 20, false, USART_BAUD_RATE);
    if (session.pm3_present && (TestProxmark(session.current_device) != PM3_SUCCESS)) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " cannot communicate with the Proxmark\n");
        CloseProxmark(session.current_device);
    }

    if ((port != NULL) && (!session.pm3_present))
        exit(EXIT_FAILURE);

    if (!session.pm3_present)
        PrintAndLogEx(INFO, "Running in " _YELLOW_("OFFLINE") " mode");
    // For now, there is no real device context:
    return session.current_device;
}

void pm3_close(pm3_device *dev) {
    // Clean up the port
    if (session.pm3_present) {
        clearCommandBuffer();
        SendCommandNG(CMD_QUIT_SESSION, NULL, 0);
        msleep(100); // Make sure command is sent before killing client
        CloseProxmark(dev);
    }
}

int pm3_console(pm3_device *dev, char *Cmd) {
    // For now, there is no real device context:
    (void) dev;
    return CommandReceived(Cmd);
}

static ConsoleHandler *console_handler_ptr = NULL;
static int console_handler_helper(char *string) {
  return console_handler_ptr->handle_output(string);
}
int pm3_console_async_wrapper(pm3_device *dev, char *Cmd, ConsoleHandler *console_handler) {
    console_handler_ptr = console_handler;
    int result = pm3_console_async(dev, Cmd, &console_handler_helper);
    console_handler = NULL; // ?? console_handler_ptr = NULL cf http://www.swig.org/Doc4.0/SWIGPlus.html#SWIGPlus_target_language_callbacks
    return result;
}

int pm3_console_async(pm3_device *dev, char *Cmd, int (*callback)(char*)) {
    // For now, there is no real device context:
    (void) dev;
    return CommandReceivedCB(Cmd, callback);
}

const char *pm3_name_get(pm3_device *dev) {
    return dev->conn->serial_port_name;
}

pm3_device *pm3_get_current_dev(void) {
    return session.current_device;
}
