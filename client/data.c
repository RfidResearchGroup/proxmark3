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

// this triggers a download sequence from device,  its received inside  cmdmain.c UsbCommandReceived()
void GetFromBigBuf(uint8_t *dest, uint32_t len, uint32_t start_index) {	
}


// this will download the EMULATOR memory part from device, 
// inside the BigBuf EML zon.
bool GetEMLFromBigBuf(uint8_t *dest, uint32_t len, uint32_t start_index) {
}

// Download data from flashmem,  rdv40
void GetFromFlashMen(uint8_t *dest, uint32_t len, uint32_t start_index) {
}
