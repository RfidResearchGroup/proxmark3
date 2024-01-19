//-----------------------------------------------------------------------------
// Copyright (C) lnv42 2024
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
// Main code for standalone HF/iso15693 Simulation
// This code is trying to dump an iso15 tag, then simulate it
// It doesn't support any password protected/authenticated features
//-----------------------------------------------------------------------------

#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "fpgaloader.h"
#include "iso15693.h"
#include "iso15.h"
#include "protocols.h"
#include "iso15693tools.h"
#include "util.h"
#include "spiffs.h"
#include "appmain.h"
#include "dbprint.h"
#include "ticks.h"
#include "BigBuf.h"
#include "crc16.h"

#define AddCrc15(data, len)     compute_crc(CRC_15693, (data), (len), (data)+(len), (data)+(len)+1)
//#define CalculateCrc15(data, len)  Crc16ex(CRC_15693, (data), (len) + 2);
#define CheckCrc15(data, len)   check_crc(CRC_15693, (data), (len))

#define ISO15693_READER_TIMEOUT            330  // 330/212kHz = 1558us
#define HF_15693SIM_LOGFILE "hf_15693sim.trace"

static void DownloadTraceInstructions(void) {
    Dbprintf("");
    Dbprintf("To get the trace from flash and display it:");
    Dbprintf("1. mem spiffs dump -s "HF_15693SIM_LOGFILE" -d hf_15693sim.trace");
    Dbprintf("2. trace load -f hf_15693sim.trace");
    Dbprintf("3. trace list -t 15 -1");
}

void ModInfo(void) {
    DbpString(" HF 15693 SIM,  a ISO15693 simulator - lnv42");
    DownloadTraceInstructions();
}

void RunMod(void) {
    StandAloneMode();

    Dbprintf(_YELLOW_("HF 15693 SIM started"));
#ifdef WITH_FLASH
    rdv40_spiffs_lazy_mount();
#endif

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF_15);

    iso15693_tag *tag = (iso15693_tag*) BigBuf_get_EM_addr();
    if (tag == NULL) return;

    uint8_t cmd[8] = {0};
    int res;
    uint16_t recvLen;
    uint8_t recv[32];
    uint32_t eof_time = 0, start_time;

    cmd[0] = ISO15_REQ_DATARATE_HIGH;
    cmd[1] = ISO15693_GET_SYSTEM_INFO;
    AddCrc15(cmd, 2);
    uint8_t i;

    LED_B_ON();

    Dbprintf("Wait for a dumpable tag");

    while (1) {
        SpinDelay(200);
        LED_B_OFF();
        if (BUTTON_HELD(500) > 0)
        {
            LEDsoff();
            Dbprintf("Quiting");
            return;
        }
        start_time = 0;//eof_time;
        res = SendDataTag(cmd, 4, true, true, recv, sizeof(recv), start_time, ISO15693_READER_TIMEOUT, &eof_time, &recvLen);
        if (res < 0)
            continue;
        if (recvLen<10) // error: recv too short
        {
            Dbprintf("recvLen<10");
            continue;
        }
        if (!CheckCrc15(recv,recvLen)) // error crc not valid
        {
            Dbprintf("crc failed");
            continue;
        }
        if (recv[0] & ISO15_RES_ERROR) // received error from tag
        {
            Dbprintf("error received");
            continue;
        }

        Dbprintf("Start dumping tag");

        memset(tag, 0, sizeof(iso15693_tag));
        memcpy(tag->uid, &recv[2], 8);

        i=10;
        if (recv[1] & 0x01)
            tag->dsfid = recv[i++];
        if (recv[1] & 0x02)
            tag->afi = recv[i++];
        if (recv[1] & 0x04)
        {
            tag->pagesCount = recv[i++]+1;
            tag->bytesPerPage = recv[i++]+1;
        }
        else
        { // Set default tag values (if can't be readed in SYSINFO)
            tag->bytesPerPage = 4;
            tag->pagesCount = 128;
        }
        if (recv[1] & 0x08)
            tag->ic = recv[i++];
        break;
    }

    cmd[0] = ISO15_REQ_DATARATE_HIGH | ISO15_REQ_OPTION;
    cmd[1] = ISO15693_READBLOCK;

	uint8_t blocknum = 0;
    int retry;

    for (retry = 0; retry < 8; retry++) {
        if (blocknum >= tag->pagesCount)
            break;

        cmd[2] = blocknum;
        AddCrc15(cmd, 3);

        start_time = eof_time;
        res = SendDataTag(cmd, 5, false, true, recv, sizeof(recv), start_time, ISO15693_READER_TIMEOUT, &eof_time, &recvLen);

        if (res < 0)
        {
            SpinDelay(100);
            continue;
        }
        if (recvLen < 4 + tag->bytesPerPage) // error: recv too short
        {
            Dbprintf("recvLen < 4 + tag->bytesPerPage");
            continue;
        }
        if (!CheckCrc15(recv,recvLen)) // error crc not valid
        {
            Dbprintf("crc failed");
            continue;
        }
        if (recv[0] & ISO15_RES_ERROR) // received error from tag
        {
            Dbprintf("error received");
            continue;
        }

        tag->locks[blocknum] = recv[1];
        memcpy(&tag->data[blocknum * tag->bytesPerPage], recv + 2, tag->bytesPerPage);
        retry = 0;
        blocknum++;
    }

    LEDsoff();
    if (retry >= 8)
    {
        Dbprintf("Max retry attemps exeeded");
        Dbprintf("-=[ exit ]=-");
        return;
    }

    Dbprintf("Tag dumped");
    Dbprintf("Start simulation");

    SimTagIso15693(0, 0);

    Dbprintf("Simulation stopped");
    SpinDelay(200);

    uint32_t trace_len = BigBuf_get_traceLen();
#ifndef WITH_FLASH
    // Keep stuff in BigBuf for USB/BT dumping
    if (trace_len > 0)
        Dbprintf("[!] Trace length (bytes) = %u", trace_len);
#else
    // Write stuff to spiffs logfile
    if (trace_len > 0) {
        Dbprintf("[!] Trace length (bytes) = %u", trace_len);

        uint8_t *trace_buffer = BigBuf_get_addr();
        if (!exists_in_spiffs(HF_15693SSIM_LOGFILE)) {
            rdv40_spiffs_write(
                HF_15693SIM_LOGFILE, trace_buffer, trace_len, RDV40_SPIFFS_SAFETY_SAFE);
            Dbprintf("[!] Wrote trace to "HF_15693SIM_LOGFILE);
        } else {
            rdv40_spiffs_append(
                HF_15693SIM_LOGFILE, trace_buffer, trace_len, RDV40_SPIFFS_SAFETY_SAFE);
            Dbprintf("[!] Appended trace to "HF_15693SIM_LOGFILE);
        }
    } else {
        Dbprintf("[!] Trace buffer is empty, nothing to write!");
    }

    LED_D_ON();
    rdv40_spiffs_lazy_unmount();
    LED_D_OFF();

    SpinErr(LED_A, 200, 5);
    SpinDelay(100);
#endif

    Dbprintf("-=[ exit ]=-");
    LEDsoff();
    DownloadTraceInstructions();
}
