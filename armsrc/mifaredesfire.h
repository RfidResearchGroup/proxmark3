//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
// Gerhard de Koning Gans, April 2008, May 2011
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Definitions internal to the app source.
//-----------------------------------------------------------------------------
#ifndef __MIFAREDESFIRE_H
#define __MIFAREDESFIRE_H

#include "common.h"

bool InitDesfireCard();
void MifareSendCommand(uint8_t arg0, uint8_t arg1, uint8_t *datain);
void MifareDesfireGetInformation();
void MifareDES_Auth1(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain);
void ReaderMifareDES(uint32_t param, uint32_t param2, uint8_t *datain);
int DesfireAPDU(uint8_t *cmd, size_t cmd_len, uint8_t *dataout);
size_t CreateAPDU(uint8_t *datain, size_t len, uint8_t *dataout);
void OnSuccess();
void OnError(uint8_t reason);

#endif
