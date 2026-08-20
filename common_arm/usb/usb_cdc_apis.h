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
// 20250814: Abstract definition, without any platform related information.
//-----------------------------------------------------------------------------

#ifndef USB_CDC_H_
#define USB_CDC_H_

#include "common.h"

void usb_disable(void);
void usb_enable(void);
bool usb_check(void);
bool usb_poll(void);
uint16_t usb_available_length(void);
bool usb_poll_validate_length(void);
uint32_t usb_read(uint8_t *data, size_t len);
int usb_write(const uint8_t *data, size_t len);

int async_usb_write_start(void);
void async_usb_write_pushByte(uint8_t data);
bool async_usb_write_requestWrite(void);
int async_usb_write_stop(void);

void usb_update_serial(uint64_t newSerialNumber);
void usb_get_ep_size(uint32_t *epCtl, uint32_t *epIn, uint32_t *epOut);

#endif // USB_CDC_H_
