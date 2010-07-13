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

void UsbCommandReceived(UsbCommand *UC);
void CommandReceived(char *Cmd);
UsbCommand * WaitForResponseTimeout(uint32_t response_type, uint32_t ms_timeout);
UsbCommand * WaitForResponse(uint32_t response_type);

#endif
