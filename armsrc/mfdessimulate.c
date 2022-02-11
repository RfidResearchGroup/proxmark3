//-----------------------------------------------------------------------------
// Copyright (C) X41 D-Sec GmbH, Yasar Klawohn, Markus Vervier
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
// Routines to support ISO 14443 type A.
//-----------------------------------------------------------------------------
#include "mfdessimulate.h"

#include "string.h"
#include "proxmark3_arm.h"
#include "cmd.h"
#include "appmain.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "ticks.h"
#include "dbprint.h"
#include "util.h"
#include "util.h"
#include "parity.h"
#include "mifareutil.h"
#include "commonutil.h"
#include "crc16.h"
#include "protocols.h"
#include "mbedtls/aes.h"
#include "desfire_crypto.h"

#define MAX_ISO14A_TIMEOUT 524288

bool test_emulate_reader(uint8_t test_counter, uint8_t *receivedCmd, int *len);

void test_verify_tag_response(uint8_t test_counter, uint8_t *sent_test_cmd,
                              uint8_t sent_test_cmd_len);

//=============================================================================
// ISO 14443 Type A - Miller decoder
//=============================================================================
// Basics:
// This decoder is used when the PM3 acts as a tag.
// The reader will generate "pauses" by temporarily switching of the field.
// At the PM3 antenna we will therefore measure a modulated antenna voltage.
// The FPGA does a comparison with a threshold and would deliver e.g.:
// ........  1 1 1 1 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 0 1 1 1 1 1 1 1 1 1 1  .......
// The Miller decoder needs to identify the following sequences:
// 2 (or 3) ticks pause followed by 6 (or 5) ticks unmodulated: pause at beginning - Sequence Z ("start of communication" or a "0")
// 8 ticks without a modulation:                                no pause - Sequence Y (a "0" or "end of communication" or "no information")
// 4 ticks unmodulated followed by 2 (or 3) ticks pause:        pause in second half - Sequence X (a "1")
// Note 1: the bitstream may start at any time. We therefore need to sync.
// Note 2: the interpretation of Sequence Y and Z depends on the preceding sequence.
//-----------------------------------------------------------------------------
static tUart14a Uart;

//-----------------------------------------------------------------------------
// Main loop of simulated tag: receive commands from reader, decide what
// response to send, and send it.
// 'hf mfdesbrute (get_challenge|open_door)'
//-----------------------------------------------------------------------------
void SimulateMfDesfireEv1(uint8_t tagType, uint16_t flags, uint8_t *uid, uint8_t *enc_key, int purpose) {

    tag_response_info_t *responses;
    uint32_t cuid = 0;
    uint32_t counters[3] = { 0x00, 0x00, 0x00 };
    uint8_t tearings[3] = { 0xbd, 0xbd, 0xbd };
    uint8_t pages = 0;

    // command buffers
    uint8_t receivedCmd[MAX_FRAME_SIZE] = { 0x00 };
    uint8_t receivedCmdPar[MAX_PARITY_SIZE] = { 0x00 };

    // free eventually allocated BigBuf memory but keep Emulator Memory
    BigBuf_free_keep_EM();

    if (SimulateIso14443aInit(tagType, flags, uid, &responses, &cuid, counters, tearings, &pages) == false) {
        BigBuf_free_keep_EM();
        reply_ng(CMD_HF_MIFARE_SIMULATE, PM3_EINIT, NULL, 0);
        return;
    }

    // We need to listen to the high-frequency, peak-detected path.
    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    iso14a_set_timeout(201400); // 106 * 19ms default *100?

    int len = 0;

    int retval = PM3_SUCCESS;

    int cmdsRecvd = 0;

    // for some reason the first time the reader tries to start auth it needs to fail
    bool send_auth_fail = false;

    uint8_t RandA[16] = {0x00};
    // tests depend on the value below. they'll fail if it's changed and for the attack it's fine for it to be static.
    uint8_t RandB[] = {0x91, 0xad, 0xb6, 0x6c, 0xe7, 0x27, 0x53, 0xf3, 0x37, 0x5f, 0xe3, 0xa0, 0x23, 0xf7, 0xce, 0xdc};

    uint8_t iv[16] = {0x00};

    mbedtls_aes_context ctx;

    // aes key storage
    struct desfire_key dfire_key = {0};
    desfirekey_t authentication_key = &dfire_key;

    // session key storage
    struct desfire_key dfire_session_key = {0};
    desfirekey_t skey = &dfire_session_key;

    struct desfire_tag dfire_tag = {0};
    desfiretag_t tag = &dfire_tag;
    DESFIRE(tag)->authentication_scheme = AS_NEW;
    DESFIRE(tag)->session_key = skey;
    int communication_settings = CMAC_COMMAND | MDCM_MACED;

    mbedtls_aes_init(&ctx);
    Desfire_aes_key_new(enc_key, authentication_key);

    // run tests with
    // hf mfdesbrute open_door -t 3 -u 043c5cda986380 -k e757178e13516a4f3171bc6ea85e165a
    // set g_dbglevel to DBG_DEBUG in appmain.c to see the debug output
    bool run_tests = false;
    int test_counter = 0;
    uint8_t sent_test_cmd[128] = {0x00};
    int sent_test_cmd_len = 0;

    clear_trace();
    set_tracing(true);
    LED_A_ON();

    // main loop
    bool finished = false;
    while (finished == false) {
        // BUTTON_PRESS check done in GetIso14443aCommandFromReader
        WDT_HIT();

        tag_response_info_t *p_response = NULL;

        if (run_tests) {
            run_tests = test_emulate_reader(test_counter, receivedCmd, &len);
        } else {
            // Clean receive command buffer
            if (GetIso14443aCommandFromReader(receivedCmd, receivedCmdPar, &len) == false) {
                Dbprintf("Emulator stopped. Trace length: %d ", BigBuf_get_traceLen());
                retval = PM3_EOPABORTED;
                break;
            }
        }

        if (receivedCmd[0] == ISO14443A_CMD_WUPA && len == 1) { // Received a WAKEUP
            p_response = &responses[RESP_INDEX_ATQA];
        } else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT &&
                   len == 2) {    // Received request for UID (cascade 1)
            p_response = &responses[RESP_INDEX_UIDC1];
        } else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 &&
                   len == 2) {  // Received request for UID (cascade 2)
            p_response = &responses[RESP_INDEX_UIDC2];
        } else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3 &&
                   len == 2) {  // Received request for UID (cascade 3)
            p_response = &responses[RESP_INDEX_UIDC3];
        } else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT &&
                   len == 9) {    // Received a SELECT (cascade 1)
            p_response = &responses[RESP_INDEX_SAKC1];
        } else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 &&
                   len == 9) {  // Received a SELECT (cascade 2)
            p_response = &responses[RESP_INDEX_SAKC2];
        } else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3 &&
                   len == 9) {  // Received a SELECT (cascade 3)
            p_response = &responses[RESP_INDEX_SAKC3];
        } else if (receivedCmd[0] == ISO14443A_CMD_PPS) {
            p_response = &responses[RESP_INDEX_PPS];
        } else if (receivedCmd[0] == MIFARE_ULEV1_VERSION && len == 3 && (tagType == 2 || tagType == 7)) {
            p_response = &responses[RESP_INDEX_VERSION];
        } else if (receivedCmd[0] == ISO14443A_CMD_RATS && len == 4) {    // Received a RATS request
            p_response = &responses[RESP_INDEX_RATS];
        } else if (receivedCmd[0] == 0x26 && len == 1) {    // REQA
            uint8_t r[] = {0x44, 0x03};
            EmSendCmd(r, sizeof(r));
            if (run_tests) {
                memcpy(sent_test_cmd, r, sizeof(r));
                sent_test_cmd_len = sizeof(r);
            }
        } else if (receivedCmd[0] == 0x02 && receivedCmd[1] == 0x60) { // Get Version details of card
            uint8_t r[] = {0x02, 0xaf, 0x04, 0x01, 0x02, 0x12, 0x00, 0x18, 0x05, 0x28, 0x42};
            EmSendCmd(r, sizeof(r));
            p_response = NULL;
            if (run_tests) {
                memcpy(sent_test_cmd, r, sizeof(r));
                sent_test_cmd_len = sizeof(r);
            }
        } else if (receivedCmd[0] == 0x03 && receivedCmd[1] == 0xaf && receivedCmd[2] == 0x35 &&
                   receivedCmd[3] == 0x69) { // Get Version details of card 2
            uint8_t r[] = {0x03, 0xaf, 0x04, 0x01, 0x01, 0x02, 0x01, 0x18, 0x05, 0x64, 0x8b};
            EmSendCmd(r, sizeof(r));
            p_response = NULL;
            if (run_tests) {
                memcpy(sent_test_cmd, r, sizeof(r));
                sent_test_cmd_len = sizeof(r);
            }
        } else if (receivedCmd[0] == 0x02 && receivedCmd[1] == 0xaf && receivedCmd[2] == 0xed &&
                   receivedCmd[3] == 0x70) { // Get Version details of card 3
            uint8_t r[] = {0x02, 0x00, 0x04, 0x3c, 0x5c, 0xda, 0x98, 0x63, 0x80,
                           0xce, 0xd8, 0x50, 0x59, 0x60, 0x08,
                           0x19, 0xab, 0xa7
                          };
            EmSendCmd(r, sizeof(r));
            p_response = NULL;
            if (run_tests) {
                memcpy(sent_test_cmd, r, sizeof(r));
                sent_test_cmd_len = sizeof(r);
            }
        } else if ((receivedCmd[0] == 0x02 || receivedCmd[0] == 0x03) &&
                   receivedCmd[1] == MIFARE_EV1_SELECT_APP) {
            // the reader will sequentially try AIDs starting with f518f0
            // it seems f518f0 can always be used, even if the real tags use a bigger AID
            if (receivedCmd[2] >= 0xf0 && receivedCmd[3] == 0x18 &&
                    receivedCmd[4] == 0xf5) {
                uint8_t r[4] = {0x00};
                r[0] = receivedCmd[0];
                AddCrc14A(r, sizeof(r) - 2);
                EmSendCmd(r, sizeof(r));
                p_response = NULL;
                if (run_tests) {
                    memcpy(sent_test_cmd, r, sizeof(r));
                    sent_test_cmd_len = sizeof(r);
                }

                send_auth_fail = false;
            } else {
                // unknown AID? not sure. also covers special case of
                // 5a 71 17 05 in the very beginning that always
                // (needs to?) fail(s)
                uint8_t r[4] = {0x00};
                r[0] = receivedCmd[0];
                r[1] = 0xa0;
                AddCrc14A(r, sizeof(r) - 2);
                EmSendCmd(r, sizeof(r));
                p_response = NULL;
                if (run_tests) {
                    memcpy(sent_test_cmd, r, sizeof(r));
                    sent_test_cmd_len = sizeof(r);
                }
            }
        } else if ((receivedCmd[0] == 0x02 || receivedCmd[0] == 0x03) &&
                   receivedCmd[1] == MIFARE_EV1_AUTH_AES) {
            if (receivedCmd[2] == 0x01) {
                // reader sends 03 aa 01 76 09 after selecting application 71 17 05.
                // the tag needs to reply with 0xae (authentication error) after
                // the reader sent its reply to this challenge
                send_auth_fail = true;
                uint8_t r[] = {0x03, 0xaf, 0x78, 0xd2, 0x9d, 0x9f, 0xd0, 0x17,
                               0xe7, 0xca, 0x48, 0x1d, 0x8b, 0xb7, 0xd9,
                               0xcb, 0x6a, 0xdd, 0x7c, 0xe0
                              };
                EmSendCmd(r, sizeof(r));
                if (run_tests) {
                    memcpy(sent_test_cmd, r, sizeof(r));
                    sent_test_cmd_len = sizeof(r);
                }
            } else {
                uint8_t r[20] = {0x00};
                size_t data_len = sizeof(RandB);

                r[0] = receivedCmd[0];
                r[1] = 0xaf;

                memcpy(r + 2, RandB, data_len);

                mifare_cypher_blocks_chained(DESFIRE(tag), authentication_key,
                                             iv, r + 2, data_len, MCD_SEND,
                                             MCO_ENCYPHER);

                memcpy(iv, r + 2, 16);

                AddCrc14A(r, sizeof(r) - 2);
                EmSendCmd(r, sizeof(r));
                p_response = NULL;
                if (run_tests) {
                    memcpy(sent_test_cmd, r, sizeof(r));
                    sent_test_cmd_len = sizeof(r);
                }
            }
        } else if ((receivedCmd[0] == 0x02 || receivedCmd[0] == 0x03) &&
                   receivedCmd[1] == MIFARE_EV1_AUTH_AES_2) {
            if (send_auth_fail) {
                uint8_t r[4] = {0x00};
                r[0] = receivedCmd[0];
                r[1] = 0xae;
                AddCrc14A(r, sizeof(r) - 2);
                EmSendCmd(r, sizeof(r));
                p_response = NULL;
                if (run_tests) {
                    memcpy(sent_test_cmd, r, sizeof(r));
                    sent_test_cmd_len = sizeof(r);
                }
            } else if (purpose == CMD_HF_MIFARE_EV1_GET_LOCK_CHALLENGE) {
                DbpString("Tag challenge: ");
                Dbhexdump(16, iv, false);
                DbpString("Lock challenge: ");
                Dbhexdump(32, receivedCmd + 2, false);
                return;
            } else if (purpose == CMD_HF_MIFARE_EV1_OPEN_DOOR) {
                uint8_t both[32] = {0x00};
                size_t data_len = sizeof(both);

                memcpy(both, receivedCmd + 2, data_len);
                mifare_cypher_blocks_chained(DESFIRE(tag), authentication_key,
                                             iv, both, data_len, MCD_RECEIVE,
                                             MCO_DECYPHER);

                // save rand A for session key construction
                memcpy(RandA, both, 16);

                uint8_t rotRandA[16] = {0x00};
                memcpy(rotRandA, both, 16);
                rol(rotRandA, 16);

                uint8_t r[20] = {0x00};
                r[0] = receivedCmd[0];
                r[1] = 0x00;

                memcpy(r + 2, rotRandA, 16);
                mifare_cypher_blocks_chained(DESFIRE(tag), authentication_key,
                                             iv, r + 2, sizeof(rotRandA),
                                             MCD_SEND, MCO_ENCYPHER);

                AddCrc14A(r, sizeof(r) - 2);
                EmSendCmd(r, sizeof(r));
                p_response = NULL;
                if (run_tests) {
                    memcpy(sent_test_cmd, r, sizeof(r));
                    sent_test_cmd_len = sizeof(r);
                }
            }
        } else if ((receivedCmd[0] == 0x02 || receivedCmd[0] == 0x03) &&
                   receivedCmd[1] == MIFARE_EV1_GET_FILE_INFO &&
                   receivedCmd[2] == 0x00) { // get file info
            Desfire_session_key_new(RandA, RandB, authentication_key,
                                    DESFIRE(tag)->session_key);

            cmac_generate_subkeys(DESFIRE(tag)->session_key);

            uint8_t read_file[16] = {0x00};
            read_file[0] = 0xf5;
            read_file[1] = 0x00;
            read_file[2] = 0xc0;
            read_file[3] = 0x48;
            size_t read_file_len = 2;
            mifare_cryto_postprocess_data(tag, read_file, &read_file_len,
                                          communication_settings);

            // here the status byte (0x00) needs to be appended for the MAC
            // calculation, but shouldn't still be appended when sending
            uint8_t file_info[24] = {0x00};
            file_info[4] = 0x07;
            size_t file_info_len = 8;
            uint8_t *resp = mifare_cryto_preprocess_data(tag, file_info,
                                                         &file_info_len, 0,
                                                         communication_settings);

            uint8_t r[19] = {0x00};
            r[0] = receivedCmd[0];
            r[6] = 0x07;
            memcpy(r + 9, resp + 8, 8);
            AddCrc14A(r, sizeof(r) - 2);
            EmSendCmd(r, sizeof(r));
            p_response = NULL;
            if (run_tests) {
                memcpy(sent_test_cmd, r, sizeof(r));
                sent_test_cmd_len = sizeof(r);
            }
        } else if ((receivedCmd[0] == 0x02 || receivedCmd[0] == 0x03) &&
                   receivedCmd[1] == MIFARE_EV1_READ_DATA &&
                   receivedCmd[6] == 0x07) {
            // read the contents of the file containing the UID
            uint8_t get_uid[] = {0xbd, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00};
            size_t get_uid_len = sizeof(get_uid);
            mifare_cryto_postprocess_data(tag, get_uid, &get_uid_len,
                                          communication_settings);

            uint8_t uid_and_status[] = {0x04, 0x3c, 0x5c, 0xda, 0x98, 0x63, 0x80,
                                        0x00
                                       };
            uint8_t file_contents[24] = {0x00};
            memcpy(file_contents, uid_and_status, 8);
            size_t file_contents_len = 8;
            uint8_t *resp2 = mifare_cryto_preprocess_data(tag, file_contents,
                                                          &file_contents_len, 0,
                                                          communication_settings);

            uint8_t r[19] = {0x00};
            r[0] = receivedCmd[0];

            memcpy(r + 2, uid_and_status, 7); // skip status byte
            memcpy(r + 9, resp2 + 8, 8); // copy mac
            AddCrc14A(r, sizeof(r) - 2);
            EmSendCmd(r, sizeof(r));
            p_response = NULL;
            if (run_tests) {
                sent_test_cmd_len = sizeof(r);
                memcpy(sent_test_cmd, r, sent_test_cmd_len);
            }
        } else {
            // Never seen this command before
            LogTrace(receivedCmd, Uart.len,
                     Uart.startTime * 16 - DELAY_AIR2ARM_AS_TAG,
                     Uart.endTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.parity,
                     true);
            if (g_dbglevel >= DBG_DEBUG) {
                Dbprintf("Received unknown command (len=%d):", len);
                Dbhexdump(len, receivedCmd, false);
            }
        }

        cmdsRecvd++;

        // Send response
        EmSendPrecompiledCmd(p_response);

        if (run_tests) {
            if (p_response == NULL) {
                test_verify_tag_response(test_counter, sent_test_cmd,
                                         sent_test_cmd_len);
            } else {
                test_verify_tag_response(test_counter, p_response->response,
                                         p_response->response_n);
            }
            ++test_counter;
        }
    }

    switch_off();

    set_tracing(false);
    BigBuf_free_keep_EM();

    if (g_dbglevel >= DBG_EXTENDED) {
        Dbprintf("-[ Num of received cmd  [%d]", cmdsRecvd);
    }

    // TODO canceling the simulator is broken
    // after the button is pressed, the client shows "[#] Emulator stopped. Trace length: 850"
    // but it's not possible to send any new commands using the client.
    // the command prompt "[usb] pm3 --> " does not appear
    reply_ng(CMD_HF_MIFARE_SIMULATE, retval, NULL, 0);
}

// returns false if test_counter is too big to stop testing
bool test_emulate_reader(uint8_t test_counter, uint8_t *receivedCmd, int *len) {
    switch (test_counter) {
        // 0-5 and 13-18 can't be tested for from SimulateIso14443aTag

        //  0 REQA
        //  1 ANTICOLL
        //  2 SELECT_UID
        //  3 ANTICOLL -2
        //  4 ANTICOLL -2
        //  5 RATS
        //  6 GET VERSION
        //  7 AF (Additional Frame)
        //  8 AF (Additional Frame)
        //  9 WRONG SELECT UID
        // 10 SELECT AID 71 17 f5
        // 11 AUTH AES
        // 12 READER AES CHALLENGE REPLY (TAG AE)
        // 13 REQA
        // 14 ANTICOLL
        // 15 SELECT_UID
        // 16 ANTICOLL -2
        // 17 ANTICOLL -2
        // 18 RATS
        // 19 SELECT AID f0 18 f5
        // 20 AUTH AES
        // 21 CHALLENGE REPLY
        // 22 GET FILE 0x00 INFO
        // 23 READ FILE CONTENTS
        case  0:
        case 13: {
            // REQA
            uint8_t cmd[] = {0x26};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }
        case  1:
        case 14: {
            //  ANTICOLL
            uint8_t cmd[] = {0x93, 0x20};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case  2:
        case 15: {
            // SELECT_UID
            uint8_t cmd[] = {0x93, 0x70, 0x88, 0x04, 0x3c, 0x5c, 0xec, 0x3d, 0x0f};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case  3:
        case 16: {
            // ANTICOLL -2
            uint8_t cmd[] = {0x95, 0x20};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case  4:
        case 17: {
            // ANTICOLL -2
            uint8_t cmd[] = {0x95, 0x70, 0xda, 0x98, 0x63, 0x80, 0xa1, 0xbf, 0xeb};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case  5:
        case 18: {
            // RATS
            uint8_t cmd[] = {0xe0, 0x50, 0xbc, 0xa5};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case 6: {
            // GET VERSION
            uint8_t cmd[] = {0x02, 0x60, 0x16, 0x4e};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case 7: {
            // AF (Additional Frame)
            uint8_t cmd[] = {0x03, 0xaf, 0x35, 0x69};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case 8: {
            // AF (Additional Frame)
            uint8_t cmd[] = {0x02, 0xaf, 0xed, 0x70};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case 9: {
            // WRONG SELECT UID
            uint8_t cmd[] = {0x03, 0x5a, 0x71, 0x17, 0x05, 0x12, 0x41};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case 10: {
            // SELECT AID 71 17 f5
            uint8_t cmd[] = {0x02, 0x5a, 0x71, 0x17, 0xf5, 0xd9, 0xbd};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case 11: {
            // AUTH AES
            uint8_t cmd[] = {0x03, 0xaa, 0x01, 0x76, 0x09};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case 12: {
            // READER AES CHALLENGE REPLY
            uint8_t cmd[] = {0x02, 0xaf, 0x81, 0x74, 0xfc, 0xdd, 0x94, 0xb7,
                             0x34, 0x17, 0xb8, 0xa9, 0xa4, 0x15, 0xdc, 0x1b,
                             0x80, 0x57, 0x35, 0x20, 0x67, 0x23, 0x7a, 0x4f,
                             0xe2, 0x96, 0x6b, 0x46, 0xfd, 0x24, 0x2b, 0x34,
                             0xf4, 0xe5, 0x80, 0x36
                            };
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case 19: {
            // SELECT AID f0 18 f5
            uint8_t cmd[] = {0x02, 0x5a, 0xf0, 0x18, 0xf5, 0x21, 0x68};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case 20: {
            // request auth challenge
            uint8_t cmd[] = {0x03, 0xaa, 0x00, 0xff, 0x18};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        // reply to tag's auth challenge + reader challenge
        case 21: {
            uint8_t cmd[] = {0x02, 0xaf, 0x97, 0xfe, 0x4b, 0x5d, 0xe2, 0x41,
                             0x88, 0x45, 0x8d, 0x10, 0x29, 0x59, 0xb8, 0x88,
                             0x93, 0x8c, 0x98, 0x8e, 0x96, 0xfb, 0x98, 0x46,
                             0x9c, 0xe7, 0x42, 0x6f, 0x50, 0xf1, 0x08, 0xea,
                             0xa5, 0x83, 0x8a, 0x32
                            };
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case 22: {
            // request file info
            uint8_t cmd[] = {0x03, 0xf5, 0x00, 0xc0, 0x48};
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        case 23: {
            // request file contents (the tag's UID)
            uint8_t cmd[] = {0x02, 0xbd, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00,
                             0x00, 0xc4, 0x15
                            };
            *len = sizeof(cmd);
            memcpy(receivedCmd, cmd, *len);
            break;
        }

        default:
            return false;
    }
    return true;
}

void test_verify_tag_response(uint8_t test_counter, uint8_t *sent_test_cmd,
                              uint8_t sent_test_cmd_len) {
    uint8_t expected_answer[32] = {0x00};
    size_t expected_answer_len = 0;
    bool success = false;

    switch (test_counter) {
        case  0:
        case 13: {
            uint8_t tmp[] = {0x44, 0x03};
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case  1:
        case 14: {
            uint8_t tmp[] = {0x88, 0x04, 0x3c, 0x5c, 0xec};
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case  2:
        case 15: {
            uint8_t tmp[] = {0x24, 0xd8, 0x36};
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case  3:
        case 16: {
            uint8_t tmp[] = {0xda, 0x98, 0x63, 0x80, 0xa1};
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case  4:
        case 17: {
            uint8_t tmp[] = {0x20, 0xfc, 0x70};
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case  5:
        case 18: {
            uint8_t tmp[] = {0x06, 0x75, 0x77, 0x81, 0x02, 0x80, 0x02, 0xf0};
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case 6: {
            uint8_t tmp[] = {0x02, 0xaf, 0x04, 0x01, 0x02, 0x12, 0x00, 0x18,
                             0x05, 0x28, 0x42
                            };
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case 7: {
            uint8_t tmp[] = {0x03, 0xaf, 0x04, 0x01, 0x01, 0x02, 0x01, 0x18,
                             0x05, 0x64, 0x8b
                            };
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case 8: {
            uint8_t tmp[] = {0x02, 0x00, 0x04, 0x3c, 0x5c, 0xda, 0x98, 0x63,
                             0x80, 0xce, 0xd8, 0x50, 0x59, 0x60, 0x08, 0x19,
                             0xab, 0xa7
                            };
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case 9: {
            uint8_t tmp[] = {0x03, 0xa0, 0xc2, 0x91};
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case 10: {
            uint8_t tmp[] = {0x02, 0xa0, 0x1a, 0x88};
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case 11: {
            // the contents don't really matter here, since the reader accepts
            // anything and the tag will return AE next
            // TODO: this test doesn't make sure that the CRC is correct
            uint8_t tmp[] = {0x03, 0xaf}; //, 0xe8, 0x26, 0xfc, 0xe2, 0xbe, 0xdf, 0xef, 0x37, 0x83, 0xda, 0xf9, 0xdf, 0x0d, 0x82, 0x28, 0xd0, 0x18, 0xf7};
            if (memcmp(sent_test_cmd, tmp, sizeof(tmp)) == 0) {
                success = true;
            }
            break;
        }

        case 12: {
            uint8_t tmp[] = {0x02, 0xae, 0x64, 0x61};
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case 19: {
            uint8_t tmp[] = {0x02, 0x00, 0x10, 0x2d};
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case 20: {
            uint8_t tmp[] = {0x03, 0xaf, 0x3f, 0xda, 0x93, 0x3e, 0x29, 0x53,
                             0xca, 0x5e, 0x6c, 0xfb, 0xbf, 0x95, 0xd1, 0xb5,
                             0x1d, 0xdf, 0x95, 0x14
                            };
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case 21: {
            uint8_t tmp[] = {0x02, 0x00, 0xed, 0x93, 0x55, 0xf6, 0x10, 0x97,
                             0xf8, 0x7b, 0x72, 0xe8, 0x37, 0xed, 0x3f, 0xd4,
                             0x8c, 0x4d, 0x40, 0x70
                            };
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case 22: {
            uint8_t tmp[] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00,
                             0x00, 0xa4, 0xf8, 0x4d, 0xb2, 0x60, 0xb0, 0x2e,
                             0x47, 0xcf, 0x14
                            };
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        case 23: {
            uint8_t tmp[] = {0x02, 0x00, 0x04, 0x3c, 0x5c, 0xda, 0x98, 0x63,
                             0x80, 0xe6, 0x9c, 0x0f, 0xfe, 0x76, 0x25, 0x18,
                             0x56, 0xa6, 0xd5
                            };
            expected_answer_len = sizeof(tmp);
            memcpy(expected_answer, tmp, expected_answer_len);
            break;
        }

        default:
            break;
    }

    // this response is different but it still works
    if (test_counter == 2 || test_counter == 15) {
        return;
    }
    if (success ||
            (memcmp(expected_answer, sent_test_cmd, expected_answer_len) == 0
             && sent_test_cmd_len == expected_answer_len)) {
        Dbprintf("test %i successful!", test_counter);
    } else {
        Dbprintf("test %i resulted in an unexpected answer:", test_counter);
        Dbhexdump(sent_test_cmd_len, sent_test_cmd, false);
    }
}
