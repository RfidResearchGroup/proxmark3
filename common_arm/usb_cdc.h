/*
 * at91sam7s USB CDC device implementation
 *
 * Copyright (c) 2012, Roel Verdult
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holders nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * based on the "Basic USB Example" from ATMEL (doc6123.pdf)
 *
 * @file usb_cdc.c
 * @brief
 */

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

void SetUSBreconnect(int value);
int GetUSBreconnect(void);
void SetUSBconfigured(int value);
int GetUSBconfigured(void);

void AT91F_USB_SendData(AT91PS_UDP pudp, const char *pData, uint32_t length);
void AT91F_USB_SendZlp(AT91PS_UDP pudp);
void AT91F_USB_SendStall(AT91PS_UDP pudp);
void AT91F_CDC_Enumerate(void);

#endif // _USB_CDC_H_
