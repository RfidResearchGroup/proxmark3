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

#include "usb_cmd.h"
#include "cmdparser.h"
void UsbCommandReceived(UsbCommand *UC);
void CommandReceived(char *Cmd);
bool WaitForResponseTimeout(uint32_t cmd, UsbCommand* response, size_t ms_timeout);
bool WaitForResponse(uint32_t cmd, UsbCommand* response);
void clearCommandBuffer();
command_t* getTopLevelCommandTable();
#endif
