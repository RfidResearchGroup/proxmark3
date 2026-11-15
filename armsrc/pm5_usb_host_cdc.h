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
// Proxmark5 USB host CDC (ACM) driver - minimal.
//
// Brings up OTGFS1 as a USB full-speed host, enumerates a CDC-ACM device
// (e.g. an ICS/ICSD module that exposes a "Who"/"RD" ASCII command console),
// applies the ACM line coding, and offers blocking bulk IN/OUT wrappers.
//
// The heavy lifting (core init, enumeration, channel/URB handling) lives in
// the Artery host stack under armlib/at32_usb; this file only wires that
// stack to the PM5 OTGFS1 port and layers the CDC class requests on top.
//-----------------------------------------------------------------------------

#ifndef PM5_USB_HOST_CDC_H__
#define PM5_USB_HOST_CDC_H__

#include "common.h"

// Bring up OTGFS1 as USB host and start the attach/enumerate state machine.
// Call once, after the system clock and USB 48 MHz source are available.
void pm5_usb_host_cdc_init(void);

// Tear the host port down (disable IRQ + peripheral clock).
void pm5_usb_host_cdc_deinit(void);

// Pump the host state machine (attach / enumerate / class requests).
// Non-blocking; call from the main loop.
void pm5_usb_host_cdc_poll(void);

// True once a CDC device has been enumerated and class-configured.
bool pm5_icsd_is_connected(void);

// Send a NUL-terminated command line (e.g. "Who\r\n", "RD\r\n") over the
// bulk OUT endpoint. Returns 0 on success, negative on error.
int pm5_icsd_send_cmd(const char *cmd);

// Read a response from the bulk IN endpoint into buf. Returns the number of
// bytes read (>= 0), or a negative value on error / timeout.
int pm5_icsd_read_response(char *buf, size_t max_len, uint32_t timeout_ms);

#endif // PM5_USB_HOST_CDC_H__
