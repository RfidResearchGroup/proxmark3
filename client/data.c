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
#include "proxmark3.h"
#include "cmdmain.h"

uint8_t* sample_buf;
size_t sample_buf_len;

void GetFromBigBuf(uint8_t *dest, int bytes, int start_index)
{
  sample_buf_len = 0;
  sample_buf = dest;
//	start_index = ((start_index/12)*12);
//    int n = start_index + bytes;
    /*
     if (n % 48 != 0) {
     PrintAndLog("bad len in GetFromBigBuf");
     return;
     }
     */
  UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {start_index, bytes, 0}};
  SendCommand(&c);
/*
  for (int i = start_index; i < n; i += 48) {
        UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {i, 0, 0}};
        SendCommand(&c);
//        WaitForResponse(CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);
//        memcpy(dest+(i*4), sample_buf, 48);
    }
*/
}
