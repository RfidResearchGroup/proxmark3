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
// Proxmark5 USB host on the CEP (Type-C Extended Port), OTGFS1
//-----------------------------------------------------------------------------

#ifndef __PM5_CEP_USB_HOST_H
#define __PM5_CEP_USB_HOST_H

#include "common.h"

// main loop: reads who powers the port, then runs the host
void cep_usb_host_poll(void);
// the host alone, for the loops that wait on it
void cep_usb_host_task(void);
// restarts a host stopped by a transfer error, enumeration follows. false: nothing is plugged in
bool cep_usb_host_restart(void);
bool cep_usb_host_ready(void);
bool cep_usb_host_connected(void);
uint16_t cep_usb_host_vid(void);
uint16_t cep_usb_host_pid(void);
// bcdDevice of the device
uint16_t cep_usb_host_release(void);
// product string of the device, empty when it has none
const char *cep_usb_host_product(void);
bool cep_usb_host_failed(void);
// why the host gave up on the device
const char *cep_usb_host_failure(void);

#endif
