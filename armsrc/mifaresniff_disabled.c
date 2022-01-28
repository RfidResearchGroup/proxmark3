//-----------------------------------------------------------------------------
// Copyright (C) Gerhard de Koning Gans - May 2008
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
// Routines to support mifare classic sniffer.
//-----------------------------------------------------------------------------

#include "mifaresniff_disabled.h"

#ifndef CheckCrc14A
# define CheckCrc14A(data, len) check_crc(CRC_14443_A, (data), (len))
#endif

//static int sniffState = SNF_INIT;
static uint8_t sniffUIDType = 0;
static uint8_t sniffUID[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static uint8_t sniffATQA[2] = {0, 0};
static uint8_t sniffSAK = 0;
static uint8_t sniffBuf[17];
static uint32_t timerData = 0;

//-----------------------------------------------------------------------------
// MIFARE sniffer.
//
// if no activity for 2sec, it sends the collected data to the client.
//-----------------------------------------------------------------------------
// "hf mf sniff"
void RAMFUNC SniffMifare(uint8_t param) {
    // param:
    // bit 0 - trigger from first card answer
    // bit 1 - trigger from first reader 7-bit request

    // C(red) A(yellow) B(green)
    LEDsoff();
    iso14443a_setup(FPGA_HF_ISO14443A_SNIFFER);

    // Allocate memory from BigBuf for some buffers
    // free all previous allocations first
    BigBuf_free();
    BigBuf_Clear_ext(false);
    clear_trace();
    set_tracing(true);

    // The command (reader -> tag) that we're receiving.
    uint8_t receivedCmd[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedCmdPar[MAX_MIFARE_PARITY_SIZE] = {0x00};

    // The response (tag -> reader) that we're receiving.
    uint8_t receivedResp[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedRespPar[MAX_MIFARE_PARITY_SIZE] = {0x00};

    // allocate the DMA buffer, used to stream samples from the FPGA
    uint8_t *dmaBuf = BigBuf_malloc(DMA_BUFFER_SIZE);
    uint8_t *data = dmaBuf;
    uint8_t previous_data = 0;
    int dataLen, maxDataLen = 0;
    bool ReaderIsActive = false;
    bool TagIsActive = false;

    // We won't start recording the frames that we acquire until we trigger;
    // a good trigger condition to get started is probably when we see a
    // response from the tag.
    // triggered == false -- to wait first for card
    //bool triggered = !(param & 0x03);


    // Set up the demodulator for tag -> reader responses.
    Demod14aInit(receivedResp, receivedRespPar);

    // Set up the demodulator for the reader -> tag commands
    Uart14aInit(receivedCmd, receivedCmdPar);

    // Setup and start DMA.
    // set transfer address and number of bytes. Start transfer.
    if (!FpgaSetupSscDma(dmaBuf, DMA_BUFFER_SIZE)) {
        if (g_dbglevel > 1) Dbprintf("[!] FpgaSetupSscDma failed. Exiting");
        return;
    }

    tUart14a *uart = GetUart14a();
    tDemod14a *demod = GetDemod14a();

    MfSniffInit();

    uint32_t sniffCounter = 0;
    // loop and listen
    while (BUTTON_PRESS() == false) {
        WDT_HIT();
        LED_A_ON();
        /*
                if ((sniffCounter & 0x0000FFFF) == 0) { // from time to time
                    // check if a transaction is completed (timeout after 2000ms).
                    // if yes, stop the DMA transfer and send what we have so far to the client
                    if (BigBuf_get_traceLen()) {
                        MfSniffSend();
                        // Reset everything - we missed some sniffed data anyway while the DMA was stopped
                        sniffCounter = 0;
                        dmaBuf = BigBuf_malloc(DMA_BUFFER_SIZE);
                        data = dmaBuf;
                        maxDataLen = 0;
                        ReaderIsActive = false;
                        TagIsActive = false;
                        FpgaSetupSscDma((uint8_t *)dmaBuf, DMA_BUFFER_SIZE); // set transfer address and number of bytes. Start transfer.
                    }
                }
                */

        // number of bytes we have processed so far
        int register readBufDataP = data - dmaBuf;
        // number of bytes already transferred
        int register dmaBufDataP = DMA_BUFFER_SIZE - AT91C_BASE_PDC_SSC->PDC_RCR;
        if (readBufDataP <= dmaBufDataP)            // we are processing the same block of data which is currently being transferred
            dataLen = dmaBufDataP - readBufDataP;   // number of bytes still to be processed
        else
            dataLen = DMA_BUFFER_SIZE - readBufDataP + dmaBufDataP; // number of bytes still to be processed

        // test for length of buffer
        if (dataLen > maxDataLen) {                 // we are more behind than ever...
            maxDataLen = dataLen;
            if (dataLen > (9 * DMA_BUFFER_SIZE / 10)) {
                Dbprintf("[!] blew circular buffer! | datalen %u", dataLen);
                break;
            }
        }
        if (dataLen < 1) continue;

        // primary buffer was stopped ( <-- we lost data!
        if (!AT91C_BASE_PDC_SSC->PDC_RCR) {
            AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t)dmaBuf;
            AT91C_BASE_PDC_SSC->PDC_RCR = DMA_BUFFER_SIZE;
            Dbprintf("[-] RxEmpty ERROR | data length %d", dataLen); // temporary
        }
        // secondary buffer sets as primary, secondary buffer was stopped
        if (!AT91C_BASE_PDC_SSC->PDC_RNCR) {
            AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t)dmaBuf;
            AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
        }

        LED_A_OFF();

        // Need two samples to feed Miller and Manchester-Decoder
        if (sniffCounter & 0x01) {

            // no need to try decoding tag data if the reader is sending
            if (!TagIsActive) {
                uint8_t readerbyte = (previous_data & 0xF0) | (*data >> 4);
                if (MillerDecoding(readerbyte, (sniffCounter - 1) * 4)) {
                    LogTrace(receivedCmd, uart->len, 0, 0, NULL, true);
                    Demod14aReset();
                    Uart14aReset();
                }
                ReaderIsActive = (uart->state != STATE_14A_UNSYNCD);
            }

            // no need to try decoding tag data if the reader is sending
            if (!ReaderIsActive) {
                uint8_t tagbyte = (previous_data << 4) | (*data & 0x0F);
                if (ManchesterDecoding(tagbyte, 0, (sniffCounter - 1) * 4)) {
                    LogTrace(receivedResp,  demod->len, 0, 0, NULL, false);
                    Demod14aReset();
                    Uart14aReset();
                }
                TagIsActive = (demod->state != DEMOD_14A_UNSYNCD);
            }
        }
        previous_data = *data;
        sniffCounter++;
        data++;

        if (data == dmaBuf + DMA_BUFFER_SIZE)
            data = dmaBuf;

    } // main cycle

    MfSniffEnd();
    switch_off();
}

void MfSniffInit(void) {
    memset(sniffUID, 0x00, sizeof(sniffUID));
    memset(sniffATQA, 0x00, sizeof(sniffATQA));
    memset(sniffBuf, 0x00, sizeof(sniffBuf));
    sniffSAK = 0;
    sniffUIDType = SNF_UID_4;
    timerData = 0;
}

void MfSniffEnd(void) {
    LED_B_ON();
    reply_old(CMD_ACK, 0, 0, 0, 0, 0);
    LED_B_OFF();
}

/*
bool RAMFUNC MfSniffLogic(const uint8_t *data, uint16_t len, uint8_t *parity, uint16_t bitCnt, bool reader) {

    // reset on 7-Bit commands from reader
    if (reader && (len == 1) && (bitCnt == 7)) {
        sniffState = SNF_INIT;
    }



    switch (sniffState) {
        case SNF_INIT:{
            // REQA,WUPA or MAGICWUP from reader
            if ((len == 1) && (reader) && (bitCnt == 7) ) {
                MfSniffInit();
                sniffState = (data[0] == MIFARE_MAGICWUPC1) ? SNF_MAGIC_WUPC2 : SNF_ATQA;
            }
            break;
        }
        case SNF_MAGIC_WUPC2: {
            if ((len == 1) && (reader) && (data[0] == MIFARE_MAGICWUPC2) ) {
                sniffState = SNF_CARD_IDLE;
            }
            break;
        }
        case SNF_ATQA:{
            // ATQA from tag
            if ((!reader) && (len == 2)) {
                sniffATQA[0] = data[0];
                sniffATQA[1] = data[1];
                sniffState = SNF_UID;
            }
            break;
        }
        case SNF_UID: {

            if ( !reader ) break;
            if ( len != 9 ) break;
            if ( !CheckCrc14A(data, 9)) break;
            if ( data[1] != 0x70 ) break;

            Dbprintf("[!] UID | %x", data[0]);

            if ((data[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT)) {
                // UID_4 - select 4 Byte UID from reader
                memcpy(sniffUID, data+2, 4);
                sniffUIDType = SNF_UID_4;
                sniffState = SNF_SAK;
            } else if ((data[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2)) {
                // UID_7 - Select 2nd part of 7 Byte UID

                // get rid of 0x88
                sniffUID[0] = sniffUID[1];
                sniffUID[1] = sniffUID[2];
                sniffUID[2] = sniffUID[3];
                //new uid bytes
                memcpy(sniffUID+3, data+2, 4);
                sniffUIDType = SNF_UID_7;
                sniffState = SNF_SAK;
            } else if ((data[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3)) {
                // UID_10 - Select 3nd part of 10 Byte UID
                // 3+3+4 = 10.
                // get ride of previous 0x88
                sniffUID[3] = sniffUID[4];
                sniffUID[4] = sniffUID[5];
                sniffUID[5] = sniffUID[6];
                // new uid bytes
                memcpy(sniffUID+6, data+2, 4);
                sniffUIDType = SNF_UID_10;
                sniffState = SNF_SAK;
            }
            break;
        }
        case SNF_SAK:{
            // SAK from card?
            if ((!reader) && (len == 3) && (CheckCrc14A(data, 3))) {
                sniffSAK = data[0];
                // CL2 UID part to be expected
                if (( sniffSAK == 0x04) && (sniffUIDType == SNF_UID_4)) {
                    sniffState = SNF_UID;
                // CL3 UID part to be expected
                } else if ((sniffSAK == 0x04) && (sniffUIDType == SNF_UID_7)) {
                    sniffState = SNF_UID;
                } else {
                    // select completed
                    sniffState = SNF_CARD_IDLE;
                }
            }
            break;
        }
        case SNF_CARD_IDLE:{ // trace the card select sequence
            sniffBuf[0] = 0xFF;
            sniffBuf[1] = 0xFF;
            memcpy(sniffBuf + 2, sniffUID, sizeof(sniffUID));
            memcpy(sniffBuf + 12, sniffATQA, sizeof(sniffATQA));
            sniffBuf[14] = sniffSAK;
            sniffBuf[15] = 0xFF;
            sniffBuf[16] = 0xFF;
            LogTrace(sniffBuf, sizeof(sniffBuf), 0, 0, NULL, true);
            sniffState = SNF_CARD_CMD;
        } // intentionally no break;
        case SNF_CARD_CMD:{
            LogTrace(data, len, 0, 0, NULL, reader);
            timerData = GetTickCount();
            break;
        }
        default:
            sniffState = SNF_INIT;
        break;
    }
    return false;
}
*/

void RAMFUNC MfSniffSend(void) {
    uint16_t tracelen = BigBuf_get_traceLen();
    int packlen = tracelen; // total number of bytes to send
    uint8_t *data = BigBuf_get_addr();

    while (packlen > 0) {
        LED_B_ON();
        uint16_t chunksize = MIN(PM3_CMD_DATA_SIZE, packlen); // chunk size 512
        reply_old(CMD_ACK, 1, tracelen, chunksize, data + tracelen - packlen, chunksize);
        packlen -= chunksize;
        LED_B_OFF();
    }

    LED_B_ON();
    reply_old(CMD_ACK, 2, 0, 0, 0, 0);  // 2 == data transfer finished.
    LED_B_OFF();
}
