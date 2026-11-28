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
// USB CCID smart card reader, class driver for the USB host on the CEP port
//-----------------------------------------------------------------------------

#ifndef __CCID_READER_H
#define __CCID_READER_H

#include "common.h"
#ifndef USE_OTG_HOST_MODE
#define USE_OTG_HOST_MODE
#endif
#include "usbh_core.h"

#define CCID_ERROR_NONE        0
#define CCID_ERROR_OUT_STALL   1
#define CCID_ERROR_OUT_URB     2
#define CCID_ERROR_IN_STALL    3
#define CCID_ERROR_IN_URB      4
#define CCID_ERROR_TIMEOUT     5
#define CCID_ERROR_BAD_ANSWER  6
#define CCID_ERROR_DESCRIPTOR  7
#define CCID_ERROR_LEVEL       8
#define CCID_ERROR_FEATURES    9

usb_sts_type ccid_reader_init_handler(void *host);
usb_sts_type ccid_reader_request_handler(void *host);
usb_sts_type ccid_reader_process_handler(void *host);
usb_sts_type ccid_reader_reset_handler(void *host);
bool ccid_reader_ready(void);
bool ccid_reader_busy(void);
uint8_t ccid_reader_error(void);
// the reader itself is not one this driver can use
bool ccid_reader_error_is_final(uint8_t error);
const char *ccid_reader_error_text(uint8_t error);

// Blocking, they run the USB host until the reader answers. PM3_* return codes.
// Cold reset of the card: its ATR.
int ccid_reader_power_on(uint8_t *atr, uint16_t *atr_len, uint16_t atr_max);
// T=0 or T=1 at the Fi/Di of fidi for the card that just answered to reset, the reader runs the PPS.
// PM3_ENOTIMPL: the card does not offer it, T=1 only with LRC.
int ccid_reader_select(uint8_t protocol, uint8_t fidi);
// The protocol the next APDU goes in, -1 when none can go before the next reset.
int ccid_reader_protocol(void);
// Same at the fastest rate up to the card's that the reader declares, only Di lowered. A refused
// or failed try costs a cold reset and the next goes slower, down to the default. fidi: the one in force.
int ccid_reader_select_fastest(uint8_t protocol, uint8_t *fidi);
int ccid_reader_power_off(void);
// One APDU in the protocol the card runs, rx gets the data and SW1 SW2. tx and rx may be the same buffer.
// Without a PPS since the reset the card keeps the protocol it came up in.
int ccid_reader_xfr_apdu(const uint8_t *tx, uint16_t tx_len, uint8_t *rx, uint16_t *rx_len, uint16_t rx_max);

#endif
