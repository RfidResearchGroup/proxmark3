//-----------------------------------------------------------------------------
// Copyright (C) Bogiton 2018
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
// main code for standalone HF Sniff (and ULC/NTAG/ULEV1 pwd storing)
//-----------------------------------------------------------------------------

/*
This can actually be used in two separate ways.
It can either be used to just HF 14a sniff on the go and/or grab the
authentication attempts for ULC/NTAG/ULEV1 into the flash mem (RDV4).

The retrieved sniffing session can be acquired by connecting the device
to a client that supports the reconnect capability and issue 'hf 14a list'.

In order to view the grabbed authentication attempts in the flash mem,
you can simply run 'script run mem_readpwd' or just 'mem dump p l 256'
from the client to view the stored quadlets.
*/

#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "iso14443a.h"
#include "protocols.h"
#include "util.h"
#include "spiffs.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "dbprint.h"
#include "ticks.h"
#include "BigBuf.h"
#include "string.h"

#define DELAY_READER_AIR2ARM_AS_SNIFFER (2 + 3 + 8)
#define DELAY_TAG_AIR2ARM_AS_SNIFFER (3 + 14 + 8)

// Maximum number of auth attempts per standalone session
#define MAX_PWDS_PER_SESSION 64

#define HF_BOG_LOGFILE "hf_bog.log"

// This is actually copied from SniffIso14443a
static void RAMFUNC SniffAndStore(uint8_t param) {

    iso14443a_setup(FPGA_HF_ISO14443A_SNIFFER);

    // Allocate memory from BigBuf for some buffers
    // free all previous allocations first
    BigBuf_free();
    BigBuf_Clear_ext(false);
    clear_trace();
    set_tracing(true);

    // Array to store the authpwds
    uint8_t *capturedPwds = BigBuf_malloc(4 * MAX_PWDS_PER_SESSION);

    // The command (reader -> tag) that we're receiving.
    uint8_t *receivedCmd = BigBuf_malloc(MAX_FRAME_SIZE);
    uint8_t *receivedCmdPar = BigBuf_malloc(MAX_PARITY_SIZE);

    // The response (tag -> reader) that we're receiving.
    uint8_t *receivedResp = BigBuf_malloc(MAX_FRAME_SIZE);
    uint8_t *receivedRespPar = BigBuf_malloc(MAX_PARITY_SIZE);

    // The DMA buffer, used to stream samples from the FPGA
    uint8_t *dmaBuf = BigBuf_malloc(DMA_BUFFER_SIZE);
    uint8_t *data = dmaBuf;

    uint8_t previous_data = 0;
    int dataLen;
    bool TagIsActive = false;
    bool ReaderIsActive = false;

    // Set up the demodulator for tag -> reader responses.
    Demod14aInit(receivedResp, receivedRespPar);

    // Set up the demodulator for the reader -> tag commands
    Uart14aInit(receivedCmd, receivedCmdPar);

    // Setup and start DMA.
    if (!FpgaSetupSscDma((uint8_t *)dmaBuf, DMA_BUFFER_SIZE)) {
        if (g_dbglevel > 1)
            Dbprintf("FpgaSetupSscDma failed. Exiting");
        return;
    }

    tUart14a *uart = GetUart14a();
    tDemod14a *demod = GetDemod14a();

    // We won't start recording the frames that we acquire until we trigger;
    // a good trigger condition to get started is probably when we see a
    // response from the tag.
    // triggered == false -- to wait first for card
    bool triggered = !(param & 0x03);

    uint32_t my_rsamples = 0;

    // Current captured passwords counter
    uint8_t auth_attempts = 0;

    SpinDelay(50);

    // loop and listen
    while (BUTTON_PRESS() == false) {
        WDT_HIT();
        LED_A_ON();

        int register readBufDataP = data - dmaBuf;
        int register dmaBufDataP = DMA_BUFFER_SIZE - AT91C_BASE_PDC_SSC->PDC_RCR;
        if (readBufDataP <= dmaBufDataP)
            dataLen = dmaBufDataP - readBufDataP;
        else
            dataLen = DMA_BUFFER_SIZE - readBufDataP + dmaBufDataP;

        // test for length of buffer
        if (dataLen > DMA_BUFFER_SIZE) { // TODO: Check if this works properly
            Dbprintf("[!] blew circular buffer! | datalen %u", dataLen);
            break;
        }
        if (dataLen < 1)
            continue;

        // primary buffer was stopped( <-- we lost data!
        if (!AT91C_BASE_PDC_SSC->PDC_RCR) {
            AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t)dmaBuf;
            AT91C_BASE_PDC_SSC->PDC_RCR = DMA_BUFFER_SIZE;
            // Dbprintf("[-] RxEmpty ERROR | data length %d", dataLen); // temporary
        }
        // secondary buffer sets as primary, secondary buffer was stopped
        if (!AT91C_BASE_PDC_SSC->PDC_RNCR) {
            AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t)dmaBuf;
            AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
        }

        LED_A_OFF();

        // Need two samples to feed Miller and Manchester-Decoder
        if (my_rsamples & 0x01) {

            if (!TagIsActive) { // no need to try decoding reader data if the tag is sending
                uint8_t readerdata = (previous_data & 0xF0) | (*data >> 4);
                if (MillerDecoding(readerdata, (my_rsamples - 1) * 4)) {
                    LED_C_ON();

                    // check - if there is a short 7bit request from reader
                    if ((!triggered) && (param & 0x02) && (uart->len == 1) && (uart->bitCount == 7))
                        triggered = true;

                    if (triggered) {
                        if ((receivedCmd) &&
                                ((receivedCmd[0] == MIFARE_ULEV1_AUTH) || (receivedCmd[0] == MIFARE_ULC_AUTH_1))) {
                            if (g_dbglevel > 1)
                                Dbprintf("PWD-AUTH KEY: 0x%02x%02x%02x%02x", receivedCmd[1], receivedCmd[2],
                                         receivedCmd[3], receivedCmd[4]);

                            // temporarily save the captured pwd in our array
                            memcpy(&capturedPwds[4 * auth_attempts], receivedCmd + 1, 4);
                            auth_attempts++;
                        }

                        if (!LogTrace(receivedCmd, uart->len, uart->startTime * 16 - DELAY_READER_AIR2ARM_AS_SNIFFER,
                                      uart->endTime * 16 - DELAY_READER_AIR2ARM_AS_SNIFFER, uart->parity, true))
                            break;
                    }
                    /* ready to receive another command. */
                    Uart14aReset();
                    /* reset the demod code, which might have been */
                    /* false-triggered by the commands from the reader. */
                    Demod14aReset();
                    LED_B_OFF();
                }
                ReaderIsActive = (uart->state != STATE_14A_UNSYNCD);
            }

            // no need to try decoding tag data if the reader is sending - and we cannot afford the time
            if (!ReaderIsActive) {
                uint8_t tagdata = (previous_data << 4) | (*data & 0x0F);
                if (ManchesterDecoding(tagdata, 0, (my_rsamples - 1) * 4)) {
                    LED_B_ON();

                    if (!LogTrace(receivedResp, demod->len, demod->startTime * 16 - DELAY_TAG_AIR2ARM_AS_SNIFFER,
                                  demod->endTime * 16 - DELAY_TAG_AIR2ARM_AS_SNIFFER, demod->parity, false))
                        break;

                    if ((!triggered) && (param & 0x01))
                        triggered = true;

                    // ready to receive another response.
                    Demod14aReset();
                    // reset the Miller decoder including its (now outdated) input buffer
                    Uart14aReset();
                    // UartInit(receivedCmd, receivedCmdPar);
                    LED_C_OFF();
                }
                TagIsActive = (demod->state != DEMOD_14A_UNSYNCD);
            }
        }

        previous_data = *data;
        my_rsamples++;
        data++;
        if (data == dmaBuf + DMA_BUFFER_SIZE) {
            data = dmaBuf;
        }
    } // end main loop

    FpgaDisableSscDma();
    set_tracing(false);

    Dbprintf("Stopped sniffing");

    SpinDelay(200);

    // Write stuff to spiffs logfile
    if (auth_attempts > 0) {
        if (g_dbglevel > 1)
            Dbprintf("[!] Authentication attempts = %u", auth_attempts);

        if (!exists_in_spiffs((char *)HF_BOG_LOGFILE)) {
            rdv40_spiffs_write((char *)HF_BOG_LOGFILE, capturedPwds, 4 * auth_attempts, RDV40_SPIFFS_SAFETY_SAFE);
        } else {
            rdv40_spiffs_append((char *)HF_BOG_LOGFILE, capturedPwds, 4 * auth_attempts, RDV40_SPIFFS_SAFETY_SAFE);
        }
    }

    if (g_dbglevel > 1)
        Dbprintf("[!] Wrote %u Authentication attempts into logfile", auth_attempts);

    SpinErr(LED_A, 200, 5);
    SpinDelay(100);
}

void ModInfo(void) {
    DbpString("  HF 14a sniff standalone with ULC/ULEV1/NTAG auth storing in flashmem - aka BogitoRun (Bogito)");
}

void RunMod(void) {

    StandAloneMode();

    Dbprintf(">>  Bogiton 14a Sniff UL/UL-EV1/NTAG a.k.a BogitoRun Started  <<");
    Dbprintf("Starting to sniff");

    // param:
    // bit 0 - trigger from first card answer
    // bit 1 - trigger from first reader 7-bit request
    SniffAndStore(0);
    LEDsoff();
    SpinDelay(300);
    Dbprintf("- [ End ] -> You can take shell back ...");
    Dbprintf("- [  !  ] -> use 'script run data_read_pwd_mem_spiffs' to print passwords");
}
