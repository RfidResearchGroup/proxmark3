//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// USB utilities
//-----------------------------------------------------------------------------

#ifndef PROXUSB_H__
#define PROXUSB_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <usb.h>
#include <strings.h>
#include <errno.h>
#include "proxmark3.h"
#include "usb_cmd.h"
#include "util_posix.h"

extern unsigned char return_on_error;
extern unsigned char error_occured;

void SendCommand(UsbCommand *c);
bool ReceiveCommandPoll(UsbCommand *c);
void ReceiveCommand(UsbCommand *c);
struct usb_dev_handle* FindProxmark(int verbose, unsigned int *iface);
struct usb_dev_handle* OpenProxmark(int verbose);
void CloseProxmark(void);

struct prox_unit {
  usb_dev_handle *handle;
  char serial_number[256];
};

#endif
