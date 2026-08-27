//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Proxmark5 Battery Wireless Module (BWM) transport shim.
// Enabled by -DWITH_BWM_FORWARD (implies WITH_FPC_USART_HOST).
//-----------------------------------------------------------------------------

#ifndef __BWM_FORWARD_H
#define __BWM_FORWARD_H

#include "common.h"

#define BWM_HDR_HOST_CMD_1     0x7C
#define BWM_HDR_HOST_CMD_2     0xC7
#define BWM_HDR_SLAVE_BCAST_1  0xD2
#define BWM_HDR_SLAVE_BCAST_2  0xD3
#define BWM_HDR_SLAVE_RESP_1   0x2D
#define BWM_HDR_SLAVE_RESP_2   0x3D

#define BWM_CMD_SEND_FORWARD_DATA   5000
#define BWM_CMD_DATA_FORWARD        8089
#define BWM_FC_WINDOW               4
#ifndef BWM_FC_ACK_TIMEOUT_SPINS
#define BWM_FC_ACK_TIMEOUT_SPINS    200000
#endif

#define BWM_CRC16_POLY  0x1021
#define BWM_CRC16_INIT  0xFFFF

int bwm_fwd_writebuffer_sync(const uint8_t *data, size_t len);

uint32_t bwm_read_ng(uint8_t *data, size_t len);

uint16_t bwm_fwd_rxdata_available(void);

#endif
