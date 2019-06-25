/*
 * Proxmark send and receive commands
 *
 * Copyright (c) 2010, Roel Verdult
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
 * @file cmd.h
 * @brief
 */

#ifndef _PROXMARK_CMD_H_
#define _PROXMARK_CMD_H_

#include "common.h"
#include "pm3_cmd.h"
#include "usb_cdc.h"
#include "usart.h"
#include "proxmark3.h"

int reply_old(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len);
int reply_ng(uint16_t cmd, int16_t status, uint8_t *data, size_t len);
int reply_mix(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len);
int receive_ng(PacketCommandNG *rx);

// Flags to tell where to add CRC on sent replies
extern bool reply_with_crc_on_usb;
extern bool reply_with_crc_on_fpc;
// "Session" flag, to tell via which interface next msgs should be sent: USB and/or FPC USART
extern bool reply_via_fpc;
extern bool reply_via_usb;

extern void Dbprintf(const char *fmt, ...);
#define Dbprintf_usb(...) {\
        bool tmpfpc = reply_via_fpc;\
        bool tmpusb = reply_via_usb;\
        reply_via_fpc = false;\
        reply_via_usb = true;\
        Dbprintf(__VA_ARGS__);\
        reply_via_fpc = tmpfpc;\
        reply_via_usb = tmpusb;}

#define Dbprintf_fpc(...) {\
        bool tmpfpc = reply_via_fpc;\
        bool tmpusb = reply_via_usb;\
        reply_via_fpc = true;\
        reply_via_usb = false;\
        Dbprintf(__VA_ARGS__);\
        reply_via_fpc = tmpfpc;\
        reply_via_usb = tmpusb;}

#define Dbprintf_all(...) {\
        bool tmpfpc = reply_via_fpc;\
        bool tmpusb = reply_via_usb;\
        reply_via_fpc = true;\
        reply_via_usb = true;\
        Dbprintf(__VA_ARGS__);\
        reply_via_fpc = tmpfpc;\
        reply_via_usb = tmpusb;}

#endif // _PROXMARK_CMD_H_

