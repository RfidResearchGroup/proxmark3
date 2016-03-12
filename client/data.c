//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Data utilities
//-----------------------------------------------------------------------------

#include <string.h>
#include <stdint.h>
#include "data.h"
#include "ui.h"
#include "proxmark3.h"
#include "cmdmain.h"

uint8_t* sample_buf;

void GetFromBigBuf(uint8_t *dest, int bytes, int start_index) {
	sample_buf = dest;
	UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {start_index, bytes, 0}};
	clearCommandBuffer();
	SendCommand(&c);
}
void GetEMLFromBigBuf(uint8_t *dest, int bytes, int start_index) {
	sample_buf = dest;
	UsbCommand c = {CMD_DOWNLOAD_EML_BIGBUF, {start_index, bytes, 0}};
	clearCommandBuffer();
	SendCommand(&c);
}

