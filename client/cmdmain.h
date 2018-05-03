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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "util_posix.h"
#include "proxmark3.h"
#include "usb_cmd.h"
#include "util.h"
#include "ui.h"
#include "cmdparser.h"
#include "loclass/fileutils.h"
#include "cmdhf.h"
#include "cmddata.h"
#include "cmdhw.h"
#include "cmdlf.h"
#include "cmdtrace.h"
#include "cmdscript.h"
#include "cmdcrc.h"
#include "cmdanalyse.h"
#include "cmdflashmem.h"	// rdv40 flashmem commands

//For storing command that are received from the device
#define CMD_BUFFER_SIZE 50
typedef enum {
	BIG_BUF,
	BIG_BUF_EML,
	FLASH_MEM,
	SIM_MEM,
	} DeviceMemType_t;
	
extern void UsbCommandReceived(UsbCommand *c);
extern int CommandReceived(char *Cmd);
extern bool WaitForResponseTimeoutW(uint32_t cmd, UsbCommand* response, size_t ms_timeout, bool show_warning);
extern bool WaitForResponseTimeout(uint32_t cmd, UsbCommand* response, size_t ms_timeout);
extern bool WaitForResponse(uint32_t cmd, UsbCommand* response);
extern void clearCommandBuffer();
extern command_t* getTopLevelCommandTable();

extern bool GetFromDevice(DeviceMemType_t memtype, uint8_t *dest, uint32_t bytes, uint32_t start_index, UsbCommand *response, size_t ms_timeout, bool show_warning);

#endif
