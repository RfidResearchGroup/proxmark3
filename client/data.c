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
#include "proxusb.h"
#include "cmdmain.h"

uint8_t sample_buf[SAMPLE_BUFFER_SIZE];

void GetFromBigBuf(uint8_t *dest, int bytes, int start_index)
{
	start_index = ((start_index/12)*12);
    int n = (((bytes/4)/48)*48) + start_index;
    /*
     if (n % 48 != 0) {
     PrintAndLog("bad len in GetFromBigBuf");
     return;
     }
     */
    for (int i = start_index; i < n; i += 12) {
        UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {i, 0, 0}};
        SendCommand(&c);
        WaitForResponse(CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);
        memcpy(dest+(i*4), sample_buf, 48);
    }
}
