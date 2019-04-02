//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Code for communicating with the proxmark3 hardware.
//-----------------------------------------------------------------------------

#ifndef COMMS_H_
#define COMMS_H_

#include <stdbool.h>
#include <pthread.h>

#include "usb_cmd.h"
#include "uart.h"
#include "ui.h"
#include "common.h"
#include "util_posix.h"
#include "util.h"
#include "util_darwin.h"

#if defined(__linux__) && !defined(NO_UNLINK)
#include <unistd.h> // for unlink()
#endif

//For storing command that are received from the device
#ifndef CMD_BUFFER_SIZE
#define CMD_BUFFER_SIZE 100
#endif

typedef enum {
    BIG_BUF,
    BIG_BUF_EML,
    FLASH_MEM,
    SIM_MEM,
} DeviceMemType_t;

typedef struct {
    bool run; // If TRUE, continue running the uart_communication thread
    bool block_after_ACK; // if true, block after receiving an ACK package
} communication_arg_t;


bool dl_it(uint8_t *dest, uint32_t bytes, uint32_t start_index, UsbCommand *response, size_t ms_timeout, bool show_warning, uint32_t rec_cmd);

void SetOffline(bool value);
bool IsOffline();

void *uart_receiver(void *targ);
void SendCommand(UsbCommand *c);
void clearCommandBuffer();

#define FLASHMODE_SPEED 460800
bool OpenProxmark(void *port, bool wait_for_port, int timeout, bool flash_mode, uint32_t speed);
void CloseProxmark(void);

bool WaitForResponseTimeoutW(uint32_t cmd, UsbCommand *response, size_t ms_timeout, bool show_warning);
bool WaitForResponseTimeout(uint32_t cmd, UsbCommand *response, size_t ms_timeout);
bool WaitForResponse(uint32_t cmd, UsbCommand *response);

extern bool GetFromDevice(DeviceMemType_t memtype, uint8_t *dest, uint32_t bytes, uint32_t start_index, UsbCommand *response, size_t ms_timeout, bool show_warning);

#endif


