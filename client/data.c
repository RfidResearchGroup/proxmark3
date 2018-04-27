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

uint32_t sample_buf_size;
uint8_t* sample_buf;

// this triggers a download sequence from device,  its received inside  cmdmain.c UsbCommandReceived()
void GetFromBigBuf(uint8_t *dest, uint32_t len, uint32_t start_index) {	
	// global
	sample_buf = dest;
	sample_buf_size = len;
	UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {start_index, len, 0}};
	clearCommandBuffer();
	SendCommand(&c);
}
// this will download the EMULATOR memory part from device, 
// inside the BigBuf EML zon.
bool GetEMLFromBigBuf(uint8_t *dest, uint32_t len, uint32_t start_index) {
	sample_buf = dest;
	sample_buf_size = len;	
	UsbCommand c = {CMD_DOWNLOAD_EML_BIGBUF, {start_index, len, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	
	// the download will be done inside cmdmain.c function UsbCommandReceived(UsbCommand *UC)
	
	// we are waiting for the ACK	
	if ( !WaitForResponseTimeout(CMD_ACK, NULL, 2500))
		return false;
	
	return true;
}

// Download data from flashmem,  rdv40
void GetFromFlashMen(uint8_t *dest, uint32_t len, uint32_t start_index) {
	sample_buf = dest;
	sample_buf_size = len;	
	UsbCommand c = {CMD_DOWNLOAND_FLASH_MEM, {start_index, len, 0}};
	clearCommandBuffer();
	SendCommand(&c);
}
