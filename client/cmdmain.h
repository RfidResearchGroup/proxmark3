//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Main command parser entry point
//-----------------------------------------------------------------------------

#ifndef CMDMAIN_H__
#define CMDMAIN_H__

#include <stdint.h>
#include <stddef.h>
#include "usb_cmd.h"
#include "cmdparser.h"
extern void UsbCommandReceived(UsbCommand *c);
extern int CommandReceived(char *Cmd);
extern bool WaitForResponseTimeoutW(uint32_t cmd, UsbCommand* response, size_t ms_timeout, bool show_warning);
extern bool WaitForResponseTimeout(uint32_t cmd, UsbCommand* response, size_t ms_timeout);
extern bool WaitForResponse(uint32_t cmd, UsbCommand* response);
extern void clearCommandBuffer();
extern command_t* getTopLevelCommandTable();

//For storing command that are received from the device
#define CMD_BUFFER_SIZE 50

#endif
