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
#ifndef __MIFAREDESFIRE_H
#define __MIFAREDESFIRE_H

#include "common.h"

bool InitDesfireCard(void);
void MifareSendCommand(uint8_t *datain);
void MifareDesfireGetInformation(void);
void MifareDES_Auth1(uint8_t *datain);
void ReaderMifareDES(uint32_t param, uint32_t param2, uint8_t *datain);
int DesfireAPDU(uint8_t *cmd, size_t cmd_len, uint8_t *dataout);
size_t CreateAPDU(uint8_t *datain, size_t len, uint8_t *dataout);
void OnSuccess(void);
void OnError(uint8_t reason);
void OnErrorNG(uint16_t cmd, uint8_t reason);

#endif
