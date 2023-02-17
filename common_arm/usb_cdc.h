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
// at91sam7s USB CDC device implementation
// based on the "Basic USB Example" from ATMEL (doc6123.pdf)
//-----------------------------------------------------------------------------

#ifndef _USB_CDC_H_
#define _USB_CDC_H_

#include "common.h"
#include "at91sam7s512.h"

void usb_disable(void);
void usb_enable(void);
bool usb_check(void);
bool usb_poll(void);
bool usb_poll_validate_length(void);
uint32_t usb_read(uint8_t *data, size_t len);
int usb_write(const uint8_t *data, const size_t len);
uint32_t usb_read_ng(uint8_t *data, size_t len);
void usb_update_serial(uint64_t newSerialNumber);

void SetUSBreconnect(int value);
int GetUSBreconnect(void);
void SetUSBconfigured(int value);
int GetUSBconfigured(void);

void AT91F_USB_SendData(AT91PS_UDP pudp, const char *pData, uint32_t length);
void AT91F_USB_SendZlp(AT91PS_UDP pudp);
void AT91F_USB_SendStall(AT91PS_UDP pudp);
void AT91F_CDC_Enumerate(void);

#endif // _USB_CDC_H_
