//-----------------------------------------------------------------------------
// Copyright (C) Aaron Tulino - December 2025
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
// Routines to support Seos.
//-----------------------------------------------------------------------------
#include "seos.h"
#include "iso14443a.h"
#include "BigBuf.h"

#include "fpgaloader.h"
#include "string.h"
#include "dbprint.h"
#include "protocols.h"

#include "proxmark3_arm.h"
#include "cmd.h"
// Needed for CRC in emulation mode;
// same construction as in ISO 14443;
// different initial value (CRC_ICLASS)
#include "crc16.h"

#include <mbedtls/aes.h>
#include <mbedtls/des.h>
#include "cmac_calc.h"
#include "cmac_3des.h"

#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>

const uint8_t SEOS_AID[] = { 0xA0, 0x00, 0x00, 0x04, 0x40, 0x00, 0x01, 0x01, 0x00, 0x01 };

static uint8_t block_size(uint8_t algorithm) {
    if (algorithm == SEOS_ENCRYPTION_AES) {
        return 16;
    } else if (algorithm == SEOS_ENCRYPTION_2K3DES) {
        return 8;
    } else if (algorithm == SEOS_ENCRYPTION_3K3DES) {
        return 8;
    } else {
        Dbprintf(_RED_("Unknown Encryption Algorithm"));
        return 0;
    }
}

static uint8_t round_to_next(uint8_t value, uint8_t step) {
    if (value % step == 0) {
        return value;
    } else {
        return value + step - (value % step);
    }
}

static uint8_t cryptogram_iv[16] = {0x00};
static bool generate_cryptogram(const uint8_t *key, bool use_iv, const uint8_t *input, size_t length, uint8_t *output, uint8_t algorithm) {
    if (!use_iv) {
        memset(cryptogram_iv, 0x00, 16);
    }

    if (algorithm == SEOS_ENCRYPTION_AES) {
        mbedtls_aes_context ctx;
        mbedtls_aes_setkey_enc(&ctx, key, 128);
        mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, length, cryptogram_iv, input, output);
        mbedtls_aes_free(&ctx);
    } else if (algorithm == SEOS_ENCRYPTION_2K3DES) {
        mbedtls_des3_context ctx;
        mbedtls_des3_set2key_enc(&ctx, key);
        mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, length, cryptogram_iv, input, output);
        mbedtls_des3_free(&ctx);
    }

    return true;
}

static bool decrypt_cryptogram(const uint8_t *key, const uint8_t *input, size_t length, uint8_t *output, uint8_t algorithm) {
    memset(cryptogram_iv, 0x00, 16);

    if (algorithm == SEOS_ENCRYPTION_AES) {
        mbedtls_aes_context ctx;
        mbedtls_aes_init(&ctx);
        mbedtls_aes_setkey_dec(&ctx, key, 128);
        mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, length, cryptogram_iv, input, output);
        mbedtls_aes_free(&ctx);
    } else if (algorithm == SEOS_ENCRYPTION_2K3DES) {
        mbedtls_des3_context ctx;
        mbedtls_des3_set2key_dec(&ctx, key);
        mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, length, cryptogram_iv, input, output);
        mbedtls_des3_free(&ctx);
    } else {
        Dbprintf(_RED_("Unknown Encryption Algorithm"));
        return false;
    }

    return true;
}

// Returns length of generated CMAC
static bool generate_cmac(const uint8_t *key, const uint8_t *input, size_t length, uint8_t *output, uint8_t encryption_algorithm) {
    if (encryption_algorithm == SEOS_ENCRYPTION_AES) {
        ulaes_cmac(key, 16, input, length, output);
    } else if (encryption_algorithm == SEOS_ENCRYPTION_2K3DES || encryption_algorithm == SEOS_ENCRYPTION_3K3DES) {
        uint8_t keylen = 16;
        if (encryption_algorithm == SEOS_ENCRYPTION_3K3DES) keylen = 24;
        des3_cmac(key, keylen, input, length, output);
    } else {
        Dbprintf(_RED_("Unknown Encryption Algorithm"));
        return false;
    }

    return true;
}

static void seos_kdf(bool forEncryption, uint8_t *masterKey, uint8_t keyslot, uint8_t *work_buffer,
             uint8_t *adfOid, size_t adfoid_len, uint8_t *diversifier, uint8_t diversifier_len, uint8_t *out, int encryption_algorithm, int hash_algorithm) {

    // Encryption key      = 04
    // KEK Encryption key  = 05
    // MAC key             = 06
    // KEK MAC key         = 07

    uint8_t typeOfKey = 0x06;
    if (forEncryption == true) {
        typeOfKey = 0x04;
    }

    memset(work_buffer, 0x00, 16);
    work_buffer[11] = typeOfKey;
    work_buffer[14] = 0x80;
    work_buffer[15] = 0x01;
    work_buffer[16] = encryption_algorithm;
    work_buffer[17] = hash_algorithm;
    work_buffer[18] = keyslot;
    memcpy(work_buffer+19, adfOid, adfoid_len);
    memcpy(work_buffer+19+adfoid_len, diversifier, diversifier_len);

    // This CMAC always uses AES, regardless of the main encryption algorithm in use.
    generate_cmac(masterKey, work_buffer, 19 + adfoid_len + diversifier_len, out, SEOS_ENCRYPTION_AES);
}

// turn off afterwards
void SimulateSeos(seos_emulate_req_t *msg) {
    tag_response_info_t *responses;
    uint32_t cuid = 0;

    // command buffers
    uint8_t receivedCmd[MAX_FRAME_SIZE] = { 0x00 };
    uint8_t receivedCmdPar[MAX_PARITY_SIZE] = { 0x00 };

    // These values are determined at runtime
    uint8_t RND_ICC[8] = { 0x00 };
    uint8_t RND_IFD[8];
    uint8_t KEY_ICC[16] = { 0x00 };
    uint8_t KEY_IFD[16];
    uint8_t diver_encr_key[16];
    uint8_t diver_cmac_key[16];

    // Calculated block size
    const uint8_t bs = block_size(msg->encr_alg);
    const uint8_t half_bs = bs >> 1;
    if (bs == 0) {
        // Can't continue, invalid encryption algorithm
        reply_ng(CMD_HF_SEOS_SIMULATE, PM3_EINVARG, NULL, 0);
        return;
    }

    // free eventually allocated BigBuf memory but keep Emulator Memory
    BigBuf_free_keep_EM();

    // Allocate 1024 bytes for the dynamic modulation, created when the reader queries for it
    // Such a response is less time critical, so we can prepare them on the fly
#define DYNAMIC_RESPONSE_BUFFER_SIZE 192
#define DYNAMIC_MODULATION_BUFFER_SIZE 1024

    uint8_t *dynamic_response_buffer = BigBuf_calloc(DYNAMIC_RESPONSE_BUFFER_SIZE);
    if (dynamic_response_buffer == NULL) {
        BigBuf_free_keep_EM();
        reply_ng(CMD_HF_MIFARE_SIMULATE, PM3_EMALLOC, NULL, 0);
        return;
    }
    uint8_t *dynamic_modulation_buffer = BigBuf_calloc(DYNAMIC_MODULATION_BUFFER_SIZE);
    if (dynamic_modulation_buffer == NULL) {
        BigBuf_free_keep_EM();
        reply_ng(CMD_HF_MIFARE_SIMULATE, PM3_EMALLOC, NULL, 0);
        return;
    }
    tag_response_info_t dynamic_response_info = {
        .response = dynamic_response_buffer,
        .response_n = 0,
        .modulation = dynamic_modulation_buffer,
        .modulation_n = 0
    };

    // General-purpose shared buffers
#define WORK_BUFFER_SIZE 0x80
    uint8_t *work_buffer_a = BigBuf_calloc(WORK_BUFFER_SIZE);
    if (work_buffer_a == NULL) {
        BigBuf_free_keep_EM();
        reply_ng(CMD_HF_MIFARE_SIMULATE, PM3_EMALLOC, NULL, 0);
        return;
    }
    uint8_t *work_buffer_b = BigBuf_calloc(WORK_BUFFER_SIZE);
    if (work_buffer_b == NULL) {
        BigBuf_free_keep_EM();
        reply_ng(CMD_HF_MIFARE_SIMULATE, PM3_EMALLOC, NULL, 0);
        return;
    }

    // The RND_* counter is exactly one block size
    uint8_t *rndCounter = BigBuf_calloc(bs);
    if (rndCounter == NULL) {
        BigBuf_free_keep_EM();
        reply_ng(CMD_HF_MIFARE_SIMULATE, PM3_EMALLOC, NULL, 0);
        return;
    }

    uint16_t flags = 0;
    uint8_t data[PM3_CMD_DATA_SIZE] = { 0 };
    memcpy(data, msg->uid, msg->uid_len);
    FLAG_SET_UID_IN_DATA(flags, msg->uid_len);

    // 12 = HID Seos 4K card
    if (SimulateIso14443aInit(12, flags, data, NULL, 0, &responses, &cuid, NULL, NULL) == false) {
        BigBuf_free_keep_EM();
        reply_ng(CMD_HF_SEOS_SIMULATE, PM3_EINIT, NULL, 0);
        return;
    }

    // We need to listen to the high-frequency, peak-detected path.
    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    iso14a_set_timeout(201400); // 106 * 19ms default *100?

    int len = 0;

    int retval = PM3_SUCCESS;

    // Just to allow some checks
    int cmdsRecvd = 0;

    bool odd_reply = true;

    clear_trace();
    set_tracing(true);
    LED_A_ON();

    // main loop
    bool finished = false;
    bool got_rats = false;
    while (finished == false) {
        // BUTTON_PRESS check done in GetIso14443aCommandFromReader
        WDT_HIT();

        tag_response_info_t *p_response = NULL;

        // Clean receive command buffer
        if (GetIso14443aCommandFromReader(receivedCmd, sizeof(receivedCmd), receivedCmdPar, &len) == false) {
            Dbprintf("Emulator stopped. Trace length: %d ", BigBuf_get_traceLen());
            retval = PM3_EOPABORTED;
            break;
        }

        if (receivedCmd[0] == ISO14443A_CMD_REQA && len == 1) { // Received a REQUEST, but in HALTED, skip
            odd_reply = !odd_reply;
            if (odd_reply) {
                p_response = &responses[RESP_INDEX_ATQA];
            }
        } else if (receivedCmd[0] == ISO14443A_CMD_WUPA && len == 1) { // Received a WAKEUP
            p_response = &responses[RESP_INDEX_ATQA];
        } else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && len == 2) {    // Received request for UID (cascade 1)
            p_response = &responses[RESP_INDEX_UIDC1];
        } else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && len == 2) {  // Received request for UID (cascade 2)
            p_response = &responses[RESP_INDEX_UIDC2];
        } else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3 && len == 2) {  // Received request for UID (cascade 3)
            p_response = &responses[RESP_INDEX_UIDC3];
        } else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && len == 9) {    // Received a SELECT (cascade 1)
            p_response = &responses[RESP_INDEX_SAKC1];
        } else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && len == 9) {  // Received a SELECT (cascade 2)
            p_response = &responses[RESP_INDEX_SAKC2];
        } else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3 && len == 9) {  // Received a SELECT (cascade 3)
            p_response = &responses[RESP_INDEX_SAKC3];
        } else if (receivedCmd[0] == ISO14443A_CMD_PPS) {
            p_response = &responses[RESP_INDEX_PPS];
        } else if (receivedCmd[0] == ISO14443A_CMD_HALT && len == 4) {    // Received a HALT
            p_response = NULL;
            if (got_rats) {
                finished = true;
            }
        } else if (receivedCmd[0] == ISO14443A_CMD_RATS && len == 4) {    // Received a RATS request
            p_response = &responses[RESP_INDEX_ATS];
            got_rats = true;
        } else {
            // clear old dynamic responses
            dynamic_response_info.response_n = 0;
            dynamic_response_info.modulation_n = 0;

            // Check for ISO 14443A-4 compliant commands, look at left byte (PCB)
            uint8_t offset = 0;
            switch (receivedCmd[0]) {
                case 0x0B: // IBlock with CID
                case 0x0A: {
                    offset = 1;
                }
                case 0x02: // IBlock without CID
                case 0x03: {
                    dynamic_response_info.response[0] = receivedCmd[0];
                    dynamic_response_info.response[1] = 0x00;
                    dynamic_response_info.response_n = 2;

                    uint8_t apdu_status[2] = {0x6A, 0x82}; // Default: Not Found

                    switch (receivedCmd[2 + offset]) { // APDU Class Byte
                        // receivedCmd in this case is expecting to structured with possibly a CID, then the APDU command for SelectFile
                        //    | IBlock (CID)   | CID | APDU Command | CRC |
                        // or | IBlock (noCID) | APDU Command | CRC |
                        case 0xA4: {  // SELECT FILE
                            // Select File AID uses the following format for GlobalPlatform
                            //
                            // | 00 | A4 | 04 | 00 | xx | AID | 00 |
                            // xx in this case is len of the AID value in hex

                            // aid len is found as a hex value in receivedCmd[6] (Index Starts at 0)
                            uint8_t aid_len = receivedCmd[5 + offset];
                            uint8_t *aid = &receivedCmd[6 + offset];

                            if ((aid_len == sizeof(SEOS_AID)) && (memcmp(SEOS_AID, aid, sizeof(SEOS_AID)) == 0)) { // Evaluate the AID sent by the Reader to the AID supplied
                                // Format as TLV and acknowledge
                                /*
                                6F 0C
                                 84 0A
                                  A0000004400001010001
                                90 00
                                */

                                dynamic_response_info.response[1 + offset] = 0x6F; // Tag
                                dynamic_response_info.response[2 + offset] = aid_len + 2; // Length
                                dynamic_response_info.response[3 + offset] = 0x84; // Inner Tag
                                dynamic_response_info.response[4 + offset] = aid_len; // Inner Length
                                memcpy(dynamic_response_info.response + 5 + offset, aid, aid_len);
                                dynamic_response_info.response_n = 5 + aid_len + offset;

                                // Set status code to Success
                                apdu_status[0] = 0x90;
                                apdu_status[1] = 0x00;
                            } // Any other SELECT FILE command will return with a Not Found
                        }
                        break;

                        case 0xA5: {  // SELECT OID
                            // This is specific to Seos
                            // Should be a TLV structure with the OID stored in tag 0x06
                            uint8_t received_tlv_len = receivedCmd[5 + offset];
                            uint8_t *received_tlv = &receivedCmd[6 + offset];

                            bool selected_oid = false;

                            // Check all requested OIDs and see if we support any
                            uint8_t tlv_offset = 0;
                            while (tlv_offset < received_tlv_len) {
                                uint8_t tag = received_tlv[tlv_offset++];
                                uint8_t length = received_tlv[tlv_offset++];
                                uint8_t* value = &received_tlv[tlv_offset];
                                if (tag == 0x06) {
                                    if (length == msg->oid_len && memcmp(value, msg->oid, length) == 0) {
                                        selected_oid = true;
                                        break;
                                    }
                                }
                                tlv_offset += length;
                            }

                            if (selected_oid) {
                                // Synthesized IV: half a block of random data followed by half of the CMAC of that data
                                memset(cryptogram_iv, 0, half_bs); // TODO: Maybe actually use random data?
                                if (!generate_cmac(msg->privmac, cryptogram_iv, half_bs, cryptogram_iv+half_bs, msg->encr_alg)) {
                                    Dbprintf(_RED_("Select ADF failed") ": Failed to create IV CMAC.");
                                    break;
                                }

                                // Always exactly 0x30 bytes in length
                                const uint8_t reply_len = 0x30;
                                uint8_t reply_idx = 0;
                                uint8_t *reply = work_buffer_a;
                                memset(reply, 0, reply_len);

                                reply[reply_idx++] = 0x06; // Tag: selected OID
                                reply[reply_idx++] = msg->oid_len;
                                memcpy(reply+reply_idx, msg->oid, msg->oid_len);
                                reply_idx += msg->oid_len;

                                reply[reply_idx++] = 0xCF; // Tag: diversifier
                                reply[reply_idx++] = msg->diversifier_len;
                                memcpy(reply+reply_idx, msg->diversifier, msg->diversifier_len);
                                reply_idx += msg->diversifier_len;

                                uint8_t tlv_base = 1 + offset;
                                uint8_t tlv_idx = tlv_base;

                                dynamic_response_info.response[tlv_idx++] = 0xCD; // Tag: cryptography type
                                dynamic_response_info.response[tlv_idx++] = 0x02; // Length
                                dynamic_response_info.response[tlv_idx++] = msg->encr_alg;
                                dynamic_response_info.response[tlv_idx++] = msg->hash_alg;

                                dynamic_response_info.response[tlv_idx++] = 0x85; // Tag: cryptogram
                                dynamic_response_info.response[tlv_idx++] = reply_len + bs; // Length
                                memcpy(dynamic_response_info.response+tlv_idx, cryptogram_iv, bs);
                                tlv_idx += bs;

                                // Generate cryptogram directly into response buffer
                                if (!generate_cryptogram(msg->privenc, true, reply, reply_len, dynamic_response_info.response+tlv_idx, msg->encr_alg)) {
                                    Dbprintf(_RED_("Select ADF failed") ": Failed to create reply cryptogram.");
                                    break;
                                }
                                tlv_idx += reply_len;

                                // Always an 8-byte CMAC
                                const uint8_t cmac_size = 8;
                                uint8_t *cmac = work_buffer_a;
                                if (!generate_cmac(msg->privmac, dynamic_response_info.response+tlv_base, tlv_idx-tlv_base, cmac, msg->encr_alg)) {
                                    Dbprintf(_RED_("Select ADF failed") ": Failed to create reply CMAC.");
                                    break;
                                }

                                dynamic_response_info.response[tlv_idx++] = 0x8E; // Tag: CMAC
                                dynamic_response_info.response[tlv_idx++] = cmac_size; // Length
                                memcpy(dynamic_response_info.response+tlv_idx, cmac, cmac_size);
                                tlv_idx += cmac_size;

                                dynamic_response_info.response_n = tlv_idx;

                                // Set status code to Success
                                apdu_status[0] = 0x90;
                                apdu_status[1] = 0x00;
                            } // No error message here because readers may request multiple OIDs before reaching ours
                        }
                        break;

                        case 0x87: {  // MUTUAL AUTH
                            // This is specific to Seos
                            // Should be a TLV structure with the OID stored in tag 0x16
                            uint8_t *received_tlv = &receivedCmd[6 + offset];

                            if (received_tlv[0] != 0x7C) {
                                Dbprintf(_RED_("Mutual auth failed") ": Invalid tag, expected 7C, got %02X", received_tlv[0]);
                                break;
                            }

                            received_tlv += 2;

                            if (received_tlv[0] == 0x81) {
                                // Request for RND.ICC
                                uint8_t tlv_idx = 1 + offset;

                                dynamic_response_info.response[tlv_idx++] = 0x7C; // Tag: mutual auth
                                dynamic_response_info.response[tlv_idx++] = sizeof(RND_ICC)+2; // Length
                                dynamic_response_info.response[tlv_idx++] = 0x81; // Tag: request for RND.ICC
                                dynamic_response_info.response[tlv_idx++] = sizeof(RND_ICC); // Length
                                memcpy(dynamic_response_info.response+tlv_idx, RND_ICC, sizeof(RND_ICC));
                                tlv_idx += sizeof(RND_ICC);

                                dynamic_response_info.response_n = tlv_idx;

                                // Set status code to Success
                                apdu_status[0] = 0x90;
                                apdu_status[1] = 0x00;
                            } else if (received_tlv[0] == 0x82) {
                                // Request for challenge
                                uint8_t received_tlv_len = received_tlv[1];
                                received_tlv += 2;

                                if (received_tlv_len > WORK_BUFFER_SIZE) {
                                    Dbprintf(_RED_("Mutual auth failed") ": Recieved cryptogram too long.");
                                    break;
                                }

                                if (received_tlv_len < 32) {
                                    Dbprintf(_RED_("Mutual auth failed") ": Recieved cryptogram too short.");
                                    break;
                                }

                                uint8_t keyslot = receivedCmd[4 + offset]; // APDU P2 byte

                                seos_kdf(true, msg->authkey, keyslot, work_buffer_a, msg->oid, msg->oid_len, msg->diversifier, msg->diversifier_len, diver_encr_key, msg->encr_alg, msg->hash_alg);
                                seos_kdf(false, msg->authkey, keyslot, work_buffer_a, msg->oid, msg->oid_len, msg->diversifier, msg->diversifier_len, diver_cmac_key, msg->encr_alg, msg->hash_alg);

                                // Verify CMAC (last 8 bytes)
                                uint8_t request_len = received_tlv_len - 8;
                                uint8_t *cmac = work_buffer_a;
                                if (!generate_cmac(diver_cmac_key, received_tlv, request_len, cmac, msg->encr_alg)) {
                                    Dbprintf(_RED_("Mutual auth failed") ": Failed to create CMAC.");
                                    break;
                                }
                                if (memcmp(cmac, received_tlv + request_len, 8) != 0) {
                                    Dbprintf(_RED_("Mutual auth failed") ": Invalid CMAC:");
                                    Dbhexdump(8, received_tlv + request_len, false);
                                    Dbprintf("for data:");
                                    Dbhexdump(request_len, received_tlv, false);
                                    break;
                                }

                                uint8_t *request = work_buffer_a;
                                if (!decrypt_cryptogram(diver_encr_key, received_tlv, request_len, request, msg->encr_alg)) {
                                    Dbprintf(_RED_("Mutual auth failed") ": Failed to decrypt cryptogram.");
                                    break;
                                }

                                // request = RND.IFD | RND.ICC | Key.IFD
                                if (memcmp(RND_ICC, request + 8, 8) != 0) {
                                    Dbprintf(_RED_("Mutual auth failed") ": Incorrect RND.ICC.");
                                    break;
                                }
                                memcpy(RND_IFD, request, 8);
                                memcpy(KEY_IFD, request + 16, 16);

                                // reply = RND_ICC | RND_IFD | KEY_ICC
                                const uint8_t reply_plain_len = 32;
                                uint8_t *reply_plain = work_buffer_a;
                                memcpy(reply_plain + 0, RND_ICC, 8);
                                memcpy(reply_plain + 8, RND_IFD, 8);
                                memcpy(reply_plain + 16, KEY_ICC, 16);

                                // Generate cryptogram + 8-byte CMAC
                                const uint8_t reply_len = reply_plain_len + 8;
                                uint8_t *reply = work_buffer_b;
                                generate_cryptogram(diver_encr_key, false, reply_plain, reply_plain_len, reply, msg->encr_alg);
                                if (!generate_cmac(diver_cmac_key, reply, reply_plain_len, reply+reply_plain_len, msg->encr_alg)) {
                                    Dbprintf(_RED_("Mutual auth failed") ": Failed to create reply CMAC.");
                                    break;
                                }

                                uint8_t tlv_idx = 1 + offset;

                                dynamic_response_info.response[tlv_idx++] = 0x7C; // Tag: mutual auth
                                dynamic_response_info.response[tlv_idx++] = reply_len+2; // Length
                                dynamic_response_info.response[tlv_idx++] = 0x82; // Tag: request for challenge
                                dynamic_response_info.response[tlv_idx++] = reply_len; // Length
                                memcpy(dynamic_response_info.response+tlv_idx, reply, reply_len);
                                tlv_idx += reply_len;

                                dynamic_response_info.response_n = tlv_idx;

                                // Set status code to Success
                                apdu_status[0] = 0x90;
                                apdu_status[1] = 0x00;

                                // IMPORTANT: before sending reply, calculate final diversified keys

                                uint8_t *hash_input = work_buffer_a;
                                uint8_t hash_idx = 0;
                                // Counter
                                hash_input[hash_idx++] = 0x00;
                                hash_input[hash_idx++] = 0x00;
                                hash_input[hash_idx++] = 0x00;
                                hash_input[hash_idx++] = 0x01;
                                // Only copy first 8 bytes of each KEY
                                memcpy(hash_input+hash_idx, KEY_IFD, 8);
                                hash_idx += 8;
                                memcpy(hash_input+hash_idx, KEY_ICC, 8);
                                hash_idx += 8;
                                // Yes, this is supposed to be the same thing twice
                                hash_input[hash_idx++] = msg->encr_alg;
                                hash_input[hash_idx++] = msg->encr_alg;
                                // Copy full RND values
                                memcpy(hash_input+hash_idx, RND_ICC, 8);
                                hash_idx += 8;
                                memcpy(hash_input+hash_idx, RND_IFD, 8);
                                hash_idx += 8;

                                uint8_t *hash_output = work_buffer_b;
                                if (msg->hash_alg == SEOS_HASHING_SHA1) {
                                    mbedtls_sha1(hash_input, hash_idx, hash_output);

                                    // Increment LSB of counter for second hash
                                    hash_input[3]++;

                                    mbedtls_sha1(hash_input, hash_idx, hash_output + 20);
                                } else if (msg->hash_alg == SEOS_HASHING_SHA256) {
                                    mbedtls_sha256(hash_input, hash_idx, hash_output, 0);
                                } else {
                                    Dbprintf(_RED_("Unknown Hashing Algorithm"));
                                    break;
                                }

                                memcpy(diver_encr_key, hash_output, 16);
                                memcpy(diver_cmac_key, hash_output+16, 16);
                            } else {
                                Dbprintf( _RED_("Mutual auth failed") ": Incorrect tag %02X found.", received_tlv[0]);
                            }
                        }
                        break;

                        case 0xDA:   // PUT DATA
                        case 0xCB: { // GET DATA
                            bool is_put = receivedCmd[2 + offset] == 0xDA;

                            uint8_t received_tlv_len = receivedCmd[5 + offset];
                            uint8_t *received_tlv = &receivedCmd[6 + offset];

                            uint8_t *cryptogram = NULL;
                            uint8_t *recvd_cmac = NULL;
                            uint8_t cryptogram_length = 0;
                            uint8_t recvd_cmac_length = 0;
                            uint8_t recvd_cmac_offset = 0;

                            // Check all requested OIDs and see if we support any
                            uint8_t tlv_offset = 0;
                            while (tlv_offset < received_tlv_len) {
                                uint8_t tag = received_tlv[tlv_offset];
                                uint8_t length = received_tlv[tlv_offset+1];
                                uint8_t* value = &received_tlv[tlv_offset+2];

                                if (tag == 0x85) {
                                    cryptogram = value;
                                    cryptogram_length = length;
                                } else if (tag == 0x8e) {
                                    recvd_cmac = value;
                                    recvd_cmac_length = length;
                                    recvd_cmac_offset = tlv_offset;
                                }
                                tlv_offset += 2 + length;
                            }

                            if (cryptogram != NULL && recvd_cmac != NULL) {
                                if (cryptogram_length > WORK_BUFFER_SIZE) {
                                    Dbprintf(_RED_("Get Data failed") ": Recieved cryptogram too long.");
                                    break;
                                }

                                // Combine the first half_bs each of RND_ICC and RND_IFD,
                                //  then increment as a single counter
                                memcpy(rndCounter, RND_ICC, half_bs);
                                memcpy(rndCounter + half_bs, RND_IFD, half_bs);

                                for (int8_t i=bs-1; i>=0; i--) {
                                    rndCounter[i]++;
                                    if (rndCounter[i] != 0x00) break;
                                }

                                uint8_t *mac_input = work_buffer_a;
                                uint8_t mac_input_idx = 0;

                                // Add RND_* counter to mac_input
                                memcpy(mac_input + mac_input_idx, rndCounter, bs);
                                mac_input_idx += bs;

                                // Add padded APDU header to mac_input
                                uint8_t *padded_apdu_header = mac_input + mac_input_idx;
                                memset(padded_apdu_header, 0, bs);
                                memcpy(padded_apdu_header, &receivedCmd[1 + offset], 4);
                                padded_apdu_header[4] = 0x80;
                                mac_input_idx += bs;

                                // Add received TLV data to mac_input
                                memcpy(mac_input + mac_input_idx, received_tlv, recvd_cmac_offset);
                                mac_input_idx += recvd_cmac_offset;

                                // Add padding (if needed) to mac_input
                                if (mac_input_idx % bs) {
                                    memset(mac_input + mac_input_idx, 0, bs - (mac_input_idx % bs));
                                    mac_input[mac_input_idx] = 0x80;
                                    mac_input_idx += bs - (mac_input_idx % bs);
                                }

                                uint8_t *cmac = work_buffer_b;
                                if (!generate_cmac(diver_cmac_key, mac_input, mac_input_idx, cmac, msg->encr_alg)) {
                                    Dbprintf(_RED_("Get Data failed") ": Failed to create CMAC.");
                                    break;
                                }
                                if (memcmp(cmac, recvd_cmac, recvd_cmac_length) != 0) {
                                    Dbprintf( _RED_("Get Data failed") ": Invalid CMAC.");
                                    break;
                                }

                                uint8_t *request = work_buffer_a;
                                decrypt_cryptogram(diver_encr_key, cryptogram, cryptogram_length, request, msg->encr_alg);

                                uint8_t tlv_base = 1 + offset;
                                uint8_t tlv_idx = tlv_base;

                                if (is_put) {
                                    // TODO: Add write support
                                    Dbprintf(_RED_("Put Data failed") ": Not implemented");
                                    break;
                                } else {
                                    //5c 02 ff 00
                                    if (request[0] != 0x5C) {
                                        Dbprintf(_RED_("Get Data failed") ": Invalid request TLV. Expected tag 5C, but got %02X.", request[0]);
                                        break;
                                    }

                                    if (request[1] != msg->data_tag_len || memcmp(request+2, msg->data_tag, msg->data_tag_len) != 0) {
                                        Dbprintf(_RED_("Get Data failed") ": Requested invalid data tag.");
                                        break;
                                    }

                                    uint8_t reply_len = msg->data_tag_len + 1 + msg->data_len;
                                    reply_len = round_to_next(reply_len, bs);
                                    if (reply_len > WORK_BUFFER_SIZE) {
                                        Dbprintf(_RED_("Get Data failed") ": Unable to generate reply: too long.");
                                        break;
                                    }

                                    uint8_t *reply = work_buffer_a;

                                    uint8_t reply_idx = 0;
                                    memcpy(reply+reply_idx, msg->data_tag, msg->data_tag_len); // Tag
                                    reply_idx += msg->data_tag_len;
                                    reply[reply_idx++] = msg->data_len; // Length
                                    memcpy(reply+reply_idx, msg->data, msg->data_len); // Value
                                    reply_idx += msg->data_len;

                                    if (reply_idx != reply_len) {
                                        memset(reply + reply_idx, 0, reply_len - reply_idx);
                                        // Add 0x80 at first byte after data for start of padding
                                        reply[reply_idx] = 0x80;
                                    }

                                    uint8_t *reply_cryptogram = work_buffer_b;
                                    if (!generate_cryptogram(diver_encr_key, false, reply, reply_len, reply_cryptogram, msg->encr_alg)) {
                                        Dbprintf(_RED_("Get Data failed") ": Failed to create reply cryptogram.");
                                        break;
                                    }

                                    // Only include a cryptogram for GET DATA
                                    dynamic_response_info.response[tlv_idx++] = 0x85; // Tag: cryptogram
                                    dynamic_response_info.response[tlv_idx++] = reply_len; // Length
                                    memcpy(dynamic_response_info.response+tlv_idx, reply_cryptogram, reply_len);
                                    tlv_idx += reply_len;
                                }

                                // Whether we GET DATA or PUT DATA, add the response status code and CMAC
                                dynamic_response_info.response[tlv_idx++] = 0x99; // Tag: status code
                                dynamic_response_info.response[tlv_idx++] = 0x02; // Length
                                dynamic_response_info.response[tlv_idx++] = 0x90;
                                dynamic_response_info.response[tlv_idx++] = 0x00;

                                // Unlike every other CMAC, this time we need to prepend
                                //  the same counter from above, but increment it again
                                for (int8_t i=bs-1; i>=0; i--) {
                                    rndCounter[i]++;
                                    if (rndCounter[i] != 0x00) break;
                                }

                                mac_input_idx = 0;

                                memcpy(mac_input + mac_input_idx, rndCounter, sizeof(rndCounter));
                                mac_input_idx += sizeof(rndCounter);
                                memcpy(mac_input + mac_input_idx, dynamic_response_info.response + tlv_base, tlv_idx - tlv_base);
                                mac_input_idx += tlv_idx - tlv_base;

                                // Add padding (if needed) to mac_input
                                if (mac_input_idx % bs) {
                                    memset(mac_input + mac_input_idx, 0, bs - (mac_input_idx % bs));
                                    mac_input[mac_input_idx] = 0x80;
                                    mac_input_idx += bs - (mac_input_idx % bs);
                                }

                                uint8_t cmac_size = recvd_cmac_length;
                                if (!generate_cmac(diver_cmac_key, mac_input, mac_input_idx, cmac, msg->encr_alg)) {
                                    Dbprintf(_RED_("Get Data failed") ": Failed to create reply CMAC.");
                                    break;
                                }

                                dynamic_response_info.response[tlv_idx++] = 0x8E; // Tag: CMAC
                                dynamic_response_info.response[tlv_idx++] = cmac_size; // Length
                                memcpy(dynamic_response_info.response+tlv_idx, cmac, cmac_size);
                                tlv_idx += cmac_size;

                                dynamic_response_info.response_n = tlv_idx;

                                // Set status code to Success
                                apdu_status[0] = 0x90;
                                apdu_status[1] = 0x00;
                            } else {
                                Dbprintf( _RED_("Get Data failed") ": No cryptogram or CMAC found in request.");
                            }
                        }
                        break;
                        default : {
                            // Any other non-listed command
                            // Respond Not Found (default)
                        }
                    }

                    // Add APDU status code to end of response
                    dynamic_response_info.response[dynamic_response_info.response_n + 0] = apdu_status[0];
                    dynamic_response_info.response[dynamic_response_info.response_n + 1] = apdu_status[1];
                    dynamic_response_info.response_n += 2;
                }
                break;

                case 0xCA:   // S-Block Deselect with CID
                case 0xC2: { // S-Block Deselect without CID
                    dynamic_response_info.response[0] = receivedCmd[0];
                    dynamic_response_info.response[1] = 0x00;
                    dynamic_response_info.response_n = 2;
                    finished = true;
                }
                break;

                default: {
                    // Never seen this PCB before
                    if (g_dbglevel >= DBG_DEBUG) {
                        Dbprintf("Received unknown command (len=%d):", len);
                        Dbhexdump(len, receivedCmd, false);
                    }
                    if ((receivedCmd[0] & 0x10) == 0x10) {
                        Dbprintf("Warning, reader sent a chained command but we lack support for it. Ignoring command.");
                    }
                    // Do not respond
                    dynamic_response_info.response_n = 0;
                }
                break;
            }
            if (dynamic_response_info.response_n > 0) {

                // Copy the CID from the reader query
                if (offset > 0) {
                    dynamic_response_info.response[1] = receivedCmd[1];
                }

                // Add CRC bytes, always used in ISO 14443A-4 compliant cards
                AddCrc14A(dynamic_response_info.response, dynamic_response_info.response_n);
                dynamic_response_info.response_n += 2;

                if (prepare_tag_modulation(&dynamic_response_info, DYNAMIC_MODULATION_BUFFER_SIZE) == false) {
                    if (g_dbglevel >= DBG_DEBUG) DbpString("Error preparing tag response");
                    break;
                }
                p_response = &dynamic_response_info;
            }
        }

        cmdsRecvd++;

        // Send response
        EmSendPrecompiledCmd(p_response);
    }


    switch_off();

    set_tracing(false);
    BigBuf_free_keep_EM();

    if (g_dbglevel >= DBG_EXTENDED) {
        Dbprintf("-[ Num of received cmd  [%d]", cmdsRecvd);
    }

    reply_ng(CMD_HF_SEOS_SIMULATE, retval, NULL, 0);
}