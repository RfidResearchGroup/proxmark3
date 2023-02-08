//-----------------------------------------------------------------------------
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
// Proxmark3 RDV40 Smartcard module commands
//-----------------------------------------------------------------------------
#include "cmdsmartcard.h"
#include <ctype.h>
#include <string.h>
#include "cmdparser.h"          // command_t
#include "commonutil.h"         // ARRAYLEN
#include "protocols.h"
#include "cmdtrace.h"
#include "proxmark3.h"
#include "comms.h"              // getfromdevice
#include "emv/emvcore.h"        // decodeTVL
#include "crypto/libpcrypto.h"  // sha512hash
#include "ui.h"
#include "util.h"
#include "fileutils.h"
#include "crc16.h"              // crc
#include "cliparser.h"          // cliparsing
#include "atrs.h"               // ATR lookup

static int CmdHelp(const char *Cmd);

static int smart_loadjson(const char *preferredName, json_t **root) {

    json_error_t error;

    if (preferredName == NULL) return 1;

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, preferredName, ".json", false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    int retval = PM3_SUCCESS;
    *root = json_load_file(path, 0, &error);
    if (!*root) {
        PrintAndLogEx(ERR, "json (%s) error on line %d: %s", path, error.line, error.text);
        retval = PM3_ESOFT;
        goto out;
    }

    if (!json_is_array(*root)) {
        PrintAndLogEx(ERR, "Invalid json (%s) format. root must be an array.", path);
        retval = PM3_ESOFT;
        goto out;
    }

    PrintAndLogEx(SUCCESS, "Loaded file (%s) OK.", path);
out:
    free(path);
    return retval;
}

static uint8_t GetATRTA1(const uint8_t *atr, size_t atrlen) {
    if (atrlen > 2) {
        uint8_t T0 = atr[1];
        if (T0 & 0x10)
            return atr[2];
    }

    return 0x11; // default value is 0x11, corresponding to fmax=5 MHz, Fi=372, Di=1.
}

static int DiArray[] = {
    0,  // b0000 RFU
    1,  // b0001
    2,
    4,
    8,
    16,
    32,  // b0110
    64,  // b0111. This was RFU in ISO/IEC 7816-3:1997 and former. Some card readers or drivers may erroneously reject cards using this value
    12,
    20,
    0,   // b1010 RFU
    0,
    0,   // ...
    0,
    0,
    0    // b1111 RFU
};

static int FiArray[] = {
    372,    // b0000 Historical note: in ISO/IEC 7816-3:1989, this was assigned to cards with internal clock
    372,    // b0001
    558,    // b0010
    744,    // b0011
    1116,   // b0100
    1488,   // b0101
    1860,   // b0110
    0,      // b0111 RFU
    0,      // b1000 RFU
    512,    // b1001
    768,    // b1010
    1024,   // b1011
    1536,   // b1100
    2048,   // b1101
    0,      // b1110 RFU
    0       // b1111 RFU
};

static float FArray[] = {
    4,    // b0000 Historical note: in ISO/IEC 7816-3:1989, this was assigned to cards with internal clock
    5,    // b0001
    6,    // b0010
    8,    // b0011
    12,   // b0100
    16,   // b0101
    20,   // b0110
    0,    // b0111 RFU
    0,    // b1000 RFU
    5,    // b1001
    7.5,  // b1010
    10,   // b1011
    15,   // b1100
    20,   // b1101
    0,    // b1110 RFU
    0     // b1111 RFU
};

static int GetATRDi(uint8_t *atr, size_t atrlen) {
    uint8_t TA1 = GetATRTA1(atr, atrlen);
    return DiArray[TA1 & 0x0F];  // The 4 low-order bits of TA1 (4th MSbit to 1st LSbit) encode Di
}

static int GetATRFi(uint8_t *atr, size_t atrlen) {
    uint8_t TA1 = GetATRTA1(atr, atrlen);
    return FiArray[TA1 >> 4];  // The 4 high-order bits of TA1 (8th MSbit to 5th LSbit) encode fmax and Fi
}

static float GetATRF(uint8_t *atr, size_t atrlen) {
    uint8_t TA1 = GetATRTA1(atr, atrlen);
    return FArray[TA1 >> 4];  // The 4 high-order bits of TA1 (8th MSbit to 5th LSbit) encode fmax and Fi
}

static void PrintATR(uint8_t *atr, size_t atrlen) {

    uint8_t T0 = atr[1];
    uint8_t K = T0 & 0x0F;
    uint8_t T1len = 0, TD1len = 0, TDilen = 0;
    bool protocol_T0_present = true;
    bool protocol_T15_present = false;

    if (T0 & 0x10) {
        PrintAndLogEx(INFO, "    - TA1 (Maximum clock frequency, proposed bit duration) [ 0x%02x ]", atr[2 + T1len]);
        T1len++;
    }

    if (T0 & 0x20) {
        PrintAndLogEx(INFO, "    - TB1 (Deprecated: VPP requirements) [ 0x%02x ]", atr[2 + T1len]);
        T1len++;
    }

    if (T0 & 0x40) {
        PrintAndLogEx(INFO, "    - TC1 (Extra delay between bytes required by card) [ 0x%02x ]", atr[2 + T1len]);
        T1len++;
    }

    if (T0 & 0x80) {
        uint8_t TD1 = atr[2 + T1len];
        PrintAndLogEx(INFO, "    - TD1 (First offered transmission protocol, presence of TA2..TD2) [ 0x%02x ] Protocol T%d", TD1, TD1 & 0x0f);
        protocol_T0_present = false;
        if ((TD1 & 0x0f) == 0) {
            protocol_T0_present = true;
        }
        if ((TD1 & 0x0f) == 15) {
            protocol_T15_present = true;
        }

        T1len++;

        if (TD1 & 0x10) {
            PrintAndLogEx(INFO, "    - TA2 (Specific protocol and parameters to be used after the ATR) [ 0x%02x ]", atr[2 + T1len + TD1len]);
            TD1len++;
        }
        if (TD1 & 0x20) {
            PrintAndLogEx(INFO, "    - TB2 (Deprecated: VPP precise voltage requirement) [ 0x%02x ]", atr[2 + T1len + TD1len]);
            TD1len++;
        }
        if (TD1 & 0x40) {
            PrintAndLogEx(INFO, "    - TC2 (Maximum waiting time for protocol T=0) [ 0x%02x ]", atr[2 + T1len + TD1len]);
            TD1len++;
        }
        if (TD1 & 0x80) {
            uint8_t TDi = atr[2 + T1len + TD1len];
            PrintAndLogEx(INFO, "    - TD2 (A supported protocol or more global parameters, presence of TA3..TD3) [ 0x%02x ] Protocol T%d", TDi, TDi & 0x0f);
            if ((TDi & 0x0f) == 0) {
                protocol_T0_present = true;
            }
            if ((TDi & 0x0f) == 15) {
                protocol_T15_present = true;
            }
            TD1len++;

            bool nextCycle = true;
            uint8_t vi = 3;
            while (nextCycle) {
                nextCycle = false;
                if (TDi & 0x10) {
                    PrintAndLogEx(INFO, "    - TA%d: 0x%02x", vi, atr[2 + T1len + TD1len + TDilen]);
                    TDilen++;
                }
                if (TDi & 0x20) {
                    PrintAndLogEx(INFO, "    - TB%d: 0x%02x", vi, atr[2 + T1len + TD1len + TDilen]);
                    TDilen++;
                }
                if (TDi & 0x40) {
                    PrintAndLogEx(INFO, "    - TC%d: 0x%02x", vi, atr[2 + T1len + TD1len + TDilen]);
                    TDilen++;
                }
                if (TDi & 0x80) {
                    TDi = atr[2 + T1len + TD1len + TDilen];
                    PrintAndLogEx(INFO, "    - TD%d [ 0x%02x ] Protocol T=%d", vi, TDi, TDi & 0x0f);
                    TDilen++;

                    nextCycle = true;
                    vi++;
                }
            }
        }
    }

    if (!protocol_T0_present || protocol_T15_present) { // there is CRC Check Byte TCK
        uint8_t vxor = 0;
        for (int i = 1; i < atrlen; i++)
            vxor ^= atr[i];

        if (vxor)
            PrintAndLogEx(WARNING, "Invalid check sum. Must be 0 got 0x%02X", vxor);
        else
            PrintAndLogEx(INFO, "Check sum OK.");
    }

    if (atr[0] != 0x3b)
        PrintAndLogEx(WARNING, "Not a direct convention [ 0x%02x ]", atr[0]);

    uint8_t calen = 2 + T1len + TD1len + TDilen + K;

    if (atrlen != calen && atrlen != calen + 1)  // may be CRC
        PrintAndLogEx(WARNING, "Invalid ATR length. len: %zu, T1len: %d, TD1len: %d, TDilen: %d, K: %d", atrlen, T1len, TD1len, TDilen, K);

    if (K > 0)
        PrintAndLogEx(DEBUG, "Historical bytes | len %02d | format %02x", K, atr[2 + T1len + TD1len + TDilen]);

    if (K > 1) {
        PrintAndLogEx(INFO, "    Historical bytes ( %u )", K);
        print_buffer(&atr[2 + T1len + TD1len + TDilen], K, 1);
    }
}

static int smart_wait(uint8_t *out, int maxoutlen, bool verbose) {
    int i = 4;
    uint32_t len;
    do {
        clearCommandBuffer();
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_SMART_RAW, &resp, 1000)) {

            if (resp.status != PM3_SUCCESS) {
                if (verbose) PrintAndLogEx(WARNING, "smart card response status failed");
                return -3;
            }

            len = resp.length;
            if (len == 0) {
                if (verbose) PrintAndLogEx(WARNING, "smart card response failed");
                return -2;
            }

            if (len > maxoutlen) {
                if (verbose) PrintAndLogEx(ERR, "Response too large. Got %u, expected %d", len, maxoutlen);
                return -4;
            }

            memcpy(out, resp.data.asBytes, len);
            if (len >= 2) {
                if (verbose) {


                    if (out[len - 2] == 0x90 && out[len - 1] == 0x00)  {
                        PrintAndLogEx(SUCCESS, _GREEN_("%02X%02X") " | %s", out[len - 2], out[len - 1], GetAPDUCodeDescription(out[len - 2], out[len - 1]));
                    } else {
                        PrintAndLogEx(SUCCESS, "%02X%02X | %s", out[len - 2], out[len - 1], GetAPDUCodeDescription(out[len - 2], out[len - 1]));
                    }
                }
            } else {
                if (verbose) {
                    PrintAndLogEx(SUCCESS, " %d | %s", len, sprint_hex_inrow_ex(out,  len, 8));
                }
            }
            return len;
        }
    } while (i--);

    if (verbose) {
        PrintAndLogEx(WARNING, "smart card response timeout");
    }
    return -1;
}

static int smart_responseEx(uint8_t *out, int maxoutlen, bool verbose) {

    int datalen = smart_wait(out, maxoutlen, verbose);
    int totallen = datalen;
    bool needGetData = false;

    if (datalen < 2) {
        goto out;
    }

    if (out[datalen - 2] == 0x61 || out[datalen - 2] == 0x9F) {
        needGetData = true;
    }

    if (needGetData == true) {
        // Don't discard data we already received except the SW code.
        // If we only received 1 byte, this is the echo of INS, we discard it.
        totallen -= 2;
        if (totallen == 1) {
            totallen = 0;
        }
        int ofs = totallen;
        maxoutlen -= totallen;
        PrintAndLogEx(DEBUG, "Keeping data (%d bytes): %s", ofs, sprint_hex(out, ofs));

        int len = out[datalen - 1];
        if (len == 0 || len > MAX_APDU_SIZE) {
            // Cap the data length or the smartcard may send us a buffer we can't handle
            len = MAX_APDU_SIZE;
        }
        if (maxoutlen < len) {
            // We don't have enough buffer to hold the next part
            goto out;
        }

        if (verbose) PrintAndLogEx(INFO, "Requesting " _YELLOW_("0x%02X") " bytes response", len);

        uint8_t cmd_getresp[] = {0x00, ISO7816_GET_RESPONSE, 0x00, 0x00, len};
        smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) + sizeof(cmd_getresp));
        payload->flags = SC_RAW | SC_LOG;
        payload->len = sizeof(cmd_getresp);
        memcpy(payload->data, cmd_getresp, sizeof(cmd_getresp));

        clearCommandBuffer();
        SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + sizeof(cmd_getresp));
        free(payload);

        datalen = smart_wait(&out[ofs], maxoutlen, verbose);

        if (datalen < 2) {
            goto out;
        }

        // data wo ACK
        if (datalen != len + 2) {
            // data with ACK
            if (datalen == len + 2 + 1) { // 2 - response, 1 - ACK
                if (out[ofs] != ISO7816_GET_RESPONSE) {
                    if (verbose) {
                        PrintAndLogEx(ERR, "GetResponse ACK error. len 0x%x | data[0] %02X", len, out[0]);
                    }
                    datalen = 0;
                    goto out;
                }

                datalen--;
                memmove(&out[ofs], &out[ofs + 1], datalen);
                totallen += datalen;
            } else {
                // wrong length
                if (verbose) {
                    PrintAndLogEx(WARNING, "GetResponse wrong length. Must be 0x%02X got 0x%02X", len, datalen - 3);
                }
            }
        }
    }

out:
    return totallen;
}

static int smart_response(uint8_t *out, int maxoutlen) {
    return smart_responseEx(out, maxoutlen, true);
}

static int CmdSmartRaw(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "smart raw",
                  "Sends raw bytes to card",
                  "smart raw -s -0 -d 00a404000e315041592e5359532e4444463031  -> `1PAY.SYS.DDF01` PPSE directory with get ATR\n"
                  "smart raw -0 -d 00a404000e325041592e5359532e4444463031     -> `2PAY.SYS.DDF01` PPSE directory\n"
                  "smart raw -0 -t -d 00a4040007a0000000041010                -> Mastercard\n"
                  "smart raw -0 -t -d 00a4040007a0000000031010                -> Visa"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("r", NULL, "do not read response"),
        arg_lit0("a", NULL, "active smartcard without select (reset sc module)"),
        arg_lit0("s", NULL, "active smartcard with select (get ATR)"),
        arg_lit0("t", "tlv", "executes TLV decoder if it possible"),
        arg_lit0("0", NULL, "use protocol T=0"),
        arg_str1("d", "data", "<hex>", "bytes to send"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool reply = (arg_get_lit(ctx, 1) == false);
    bool active = arg_get_lit(ctx, 2);
    bool active_select = arg_get_lit(ctx, 3);
    bool decode_tlv = arg_get_lit(ctx, 4);
    bool use_t0 = arg_get_lit(ctx, 5);

    int dlen = 0;
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 6), data, sizeof(data), &dlen);
    CLIParserFree(ctx);

    if (res) {
        PrintAndLogEx(FAILED, "Error parsing bytes");
        return PM3_EINVARG;
    }

    smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) + dlen);
    if (payload == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    payload->len = dlen;
    memcpy(payload->data, data, dlen);

    payload->flags = SC_LOG;
    if (active || active_select) {

        payload->flags |= (SC_CONNECT | SC_CLEARLOG);
        if (active_select)
            payload->flags |= SC_SELECT;
    }

    if (dlen > 0) {
        if (use_t0)
            payload->flags |= SC_RAW_T0;
        else
            payload->flags |= SC_RAW;
    }

    uint8_t *buf = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    if (buf == NULL) {
        PrintAndLogEx(DEBUG, "failed to allocate memory");
        free(payload);
        return PM3_EMALLOC;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + dlen);

    if (reply == false) {
        goto out;
    }

    // reading response from smart card
    int len = smart_response(buf, PM3_CMD_DATA_SIZE);
    if (len < 0) {
        free(payload);
        free(buf);
        return PM3_ESOFT;
    }

    if (buf[0] == 0x6C) {

        // request more bytes to download
        data[4] = buf[1];
        memcpy(payload->data, data, dlen);
        clearCommandBuffer();
        SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + dlen);

        len = smart_response(buf, PM3_CMD_DATA_SIZE);

        data[4] = 0;
    }

    if (decode_tlv && len > 4)
        TLVPrintFromBuffer(buf, len - 2);
    else {
        if (len > 2) {
            PrintAndLogEx(INFO, "Response data:");
            PrintAndLogEx(INFO, " # | bytes                                           | ascii");
            PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");
            print_hex_break(buf, len, 16);
        }
    }
    PrintAndLogEx(NORMAL, "");
out:
    free(payload);
    free(buf);
    return PM3_SUCCESS;
}

static int CmdSmartUpgrade(const char *Cmd) {
    PrintAndLogEx(INFO, "-------------------------------------------------------------------");
    PrintAndLogEx(WARNING, _RED_("WARNING") " - sim module firmware upgrade");
    PrintAndLogEx(WARNING, _RED_("A dangerous command, do wrong and you could brick the sim module"));
    PrintAndLogEx(INFO, "-------------------------------------------------------------------");
    PrintAndLogEx(NORMAL, "");

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "smart upgrade",
                  "Upgrade RDV4 sim module firmware",
                  "smart upgrade -f sim013.bin"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify firmware file name"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    char *bin_extension = filename;
    char *dot_position = NULL;
    while ((dot_position = strchr(bin_extension, '.')) != NULL) {
        bin_extension = dot_position + 1;
    }

    // generate filename for the related SHA512 hash file
    char sha512filename[FILE_PATH_SIZE] = {'\0'};
    if (!strcmp(bin_extension, "BIN") || !strcmp(bin_extension, "bin")) {
        memcpy(sha512filename, filename, strlen(filename) - strlen("bin"));
        strcat(sha512filename, "sha512.txt");
    } else {
        PrintAndLogEx(FAILED, "Filename extension of firmware upgrade file must be .BIN");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "firmware file       " _YELLOW_("%s"), filename);
    PrintAndLogEx(INFO, "Checking integrity  " _YELLOW_("%s"), sha512filename);

    // load firmware file
    size_t firmware_size = 0;
    uint8_t *firmware = NULL;
    if (loadFile_safe(filename, "", (void **)&firmware, &firmware_size) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Firmware file " _YELLOW_("%s") " not found or locked.", filename);
        return PM3_EFILE;
    }

    // load sha512 file
    size_t sha512_size = 0;
    char *hashstring = NULL;
    if (loadFile_safe(sha512filename, "", (void **)&hashstring, &sha512_size) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "SHA-512 file not found or locked.");
        free(firmware);
        return PM3_EFILE;
    }

    if (sha512_size < 128) {
        PrintAndLogEx(FAILED, "SHA-512 file wrong size");
        free(hashstring);
        free(firmware);
        return PM3_ESOFT;
    }
    hashstring[128] = '\0';

    uint8_t hash_1[64];
    if (param_gethex(hashstring, 0, hash_1, 128)) {
        PrintAndLogEx(FAILED, "Couldn't read SHA-512 file");
        free(hashstring);
        free(firmware);
        return PM3_ESOFT;
    }

    uint8_t hash_2[64];
    if (sha512hash(firmware, firmware_size, hash_2)) {
        PrintAndLogEx(FAILED, "Couldn't calculate SHA-512 of firmware");
        free(hashstring);
        free(firmware);
        return PM3_ESOFT;
    }

    if (memcmp(hash_1, hash_2, 64)) {
        PrintAndLogEx(FAILED, "Couldn't verify integrity of firmware file " _RED_("(wrong SHA-512 hash)"));
        free(hashstring);
        free(firmware);
        return PM3_ESOFT;
    }
    free(hashstring);

    PrintAndLogEx(INFO, _GREEN_("Don\'t turn off your PM3!"));
    PrintAndLogEx(SUCCESS, "Sim module firmware uploading to PM3...");

    PacketResponseNG resp;

    //Send to device
    uint32_t index = 0;
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining = firmware_size;

    while (bytes_remaining > 0) {

        struct {
            uint32_t idx;
            uint32_t bytes_in_packet;
            uint16_t crc;
            uint8_t data[400];
        } PACKED upload;

        uint32_t bytes_in_packet = MIN(sizeof(upload.data), bytes_remaining);

        upload.idx = index + bytes_sent;
        upload.bytes_in_packet = bytes_in_packet;
        memcpy(upload.data, firmware + bytes_sent, bytes_in_packet);

        uint8_t a = 0, b = 0;
        compute_crc(CRC_14443_A, upload.data, bytes_in_packet, &a, &b);
        upload.crc = (a << 8 | b);

        clearCommandBuffer();
        SendCommandNG(CMD_SMART_UPLOAD, (uint8_t *)&upload, sizeof(upload));
        if (!WaitForResponseTimeout(CMD_SMART_UPLOAD, &resp, 2000)) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            free(firmware);
            return PM3_ETIMEOUT;
        }

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "uploading to device failed");
            free(firmware);
            return resp.status;
        }
        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;
        PrintAndLogEx(INPLACE, "%d bytes sent", bytes_sent);
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Sim module firmware updating...");

    // trigger the firmware upgrade
    clearCommandBuffer();
    struct {
        uint16_t fw_size;
        uint16_t crc;
    } PACKED payload;
    payload.fw_size = firmware_size;

    uint8_t a = 0, b = 0;
    compute_crc(CRC_14443_A, firmware, firmware_size, &a, &b);
    payload.crc = (a << 8 | b);

    free(firmware);
    SendCommandNG(CMD_SMART_UPGRADE, (uint8_t *)&payload, sizeof(payload));
    if (!WaitForResponseTimeout(CMD_SMART_UPGRADE, &resp, 2500)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Sim module firmware upgrade " _GREEN_("successful"));
        PrintAndLogEx(HINT, "run " _YELLOW_("`hw status`") " to validate the fw version ");
    } else {
        PrintAndLogEx(FAILED, "Sim module firmware upgrade " _RED_("failed"));
    }
    return PM3_SUCCESS;
}

static int CmdSmartInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "smart info",
                  "Extract more detailed information from smart card.",
                  "smart info -v"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_ATR, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SMART_ATR, &resp, 2500) == false) {
        if (verbose) {
            PrintAndLogEx(WARNING, "smart card timeout");
        }
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(WARNING, "smart card select failed");
        }
        return PM3_ESOFT;
    }

    smart_card_atr_t card;
    memcpy(&card, (smart_card_atr_t *)resp.data.asBytes, sizeof(smart_card_atr_t));

    // print header
    PrintAndLogEx(INFO, "--- " _CYAN_("Smartcard Information") " ---------");
    PrintAndLogEx(INFO, "ISO7816-3 ATR... %s", sprint_hex(card.atr, card.atr_len));
    // convert bytes to str.
    char *hexstr = calloc((card.atr_len << 1) + 1, sizeof(uint8_t));
    if (hexstr == NULL) {
        PrintAndLogEx(WARNING, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    hex_to_buffer((uint8_t *)hexstr, card.atr, card.atr_len, (card.atr_len << 1), 0, 0, true);
    PrintAndLogEx(INFO, "Fingerprint..... %s", getAtrInfo(hexstr));
    free(hexstr);

    // print ATR
    PrintAndLogEx(INFO, "ATR");
    PrintATR(card.atr, card.atr_len);

    // print D/F (brom byte TA1 or defaults)
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "D/F (TA1)");
    int Di = GetATRDi(card.atr, card.atr_len);
    int Fi = GetATRFi(card.atr, card.atr_len);
    float F = GetATRF(card.atr, card.atr_len);
    if (GetATRTA1(card.atr, card.atr_len) == 0x11)
        PrintAndLogEx(INFO, "Using default values...");

    PrintAndLogEx(INFO, "\t- Di %d", Di);
    PrintAndLogEx(INFO, "\t- Fi %d", Fi);
    PrintAndLogEx(INFO, "\t- F  %.1f MHz", F);

    if (Di && Fi) {
        PrintAndLogEx(INFO, "\t- Cycles/ETU %d", Fi / Di);
        PrintAndLogEx(INFO, "\t- %.1f bits/sec at 4 MHz", (float)4000000 / (Fi / Di));
        PrintAndLogEx(INFO, "\t- %.1f bits/sec at Fmax (%.1fMHz)", (F * 1000000) / (Fi / Di), F);
    } else {
        PrintAndLogEx(WARNING, "\t- Di or Fi is RFU.");
    };

    return PM3_SUCCESS;
}

static int CmdSmartReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "smart reader",
                  "Act as a smart card reader.",
                  "smart reader"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_ATR, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SMART_ATR, &resp, 2500) == false) {
        if (verbose) {
            PrintAndLogEx(WARNING, "smart card select failed");
        }
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(WARNING, "smart card select failed");
        }
        return PM3_ESOFT;
    }
    smart_card_atr_t *card = (smart_card_atr_t *)resp.data.asBytes;
    PrintAndLogEx(INFO, "ISO7816-3 ATR... %s", sprint_hex(card->atr, card->atr_len));

    // convert bytes to str.
    char *hexstr = calloc((card->atr_len << 1) + 1, sizeof(uint8_t));
    if (hexstr == NULL) {
        PrintAndLogEx(WARNING, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    hex_to_buffer((uint8_t *)hexstr, card->atr, card->atr_len, (card->atr_len << 1), 0, 0, true);
    PrintAndLogEx(INFO, "Fingerprint..... %s", getAtrInfo(hexstr));
    free(hexstr);
    return PM3_SUCCESS;
}

static int CmdSmartSetClock(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "smart setclock",
                  "Set clock speed for smart card interface.",
                  "smart setclock --4mhz\n"
                  "smart setclock --16mhz"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "16mhz", "16 MHz clock speed"),
        arg_lit0(NULL, "8mhz", "8 MHz clock speed"),
        arg_lit0(NULL, "4mhz", "4 MHz clock speed"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    bool c16 = arg_get_lit(ctx, 1);
    bool c8 = arg_get_lit(ctx, 2);
    bool c4 = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if ((c16 + c8 + c4) > 1) {
        PrintAndLogEx(WARNING, "Only one clock speed can be used at a time");
        return PM3_EINVARG;
    }

    struct {
        uint32_t new_clk;
    } PACKED payload;

    if (c16)
        payload.new_clk = 0;
    else if (c8)
        payload.new_clk = 1;
    else if (c4)
        payload.new_clk = 2;

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_SETCLOCK, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_SMART_SETCLOCK, &resp, 2500)) {
        PrintAndLogEx(WARNING, "smart card select failed");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "smart card set clock failed");
        return PM3_ESOFT;
    }

    switch (payload.new_clk) {
        case 0:
            PrintAndLogEx(SUCCESS, "Clock changed to " _GREEN_("16") " MHz giving " _GREEN_("10800") " baudrate");
            break;
        case 1:
            PrintAndLogEx(SUCCESS, "Clock changed to " _GREEN_("8") " MHz giving " _GREEN_("21600") " baudrate");
            break;
        case 2:
            PrintAndLogEx(SUCCESS, "Clock changed to " _GREEN_("4") " MHz giving " _GREEN_("86400") " baudrate");
            break;
        default:
            break;
    }
    return PM3_SUCCESS;
}

static int CmdSmartList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "smart", "7816");
}

static void smart_brute_prim(void) {

    uint8_t *buf = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    if (!buf)
        return;

    uint8_t get_card_data[] = {
        0x80, 0xCA, 0x9F, 0x13, 0x00,
        0x80, 0xCA, 0x9F, 0x17, 0x00,
        0x80, 0xCA, 0x9F, 0x36, 0x00,
        0x80, 0xCA, 0x9F, 0x4f, 0x00
    };

    PrintAndLogEx(INFO, "Reading primitives");

    for (int i = 0; i < ARRAYLEN(get_card_data); i += 5) {

        smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) + 5);
        payload->flags = SC_RAW_T0;
        payload->len = 5;
        memcpy(payload->data, get_card_data + i, 5);

        clearCommandBuffer();
        SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + 5);
        free(payload);

        int len = smart_responseEx(buf, PM3_CMD_DATA_SIZE, false);
        if (len > 2) {
            PrintAndLogEx(SUCCESS, "\tHEX  %d |: %s", len, sprint_hex(buf, len));
        }
    }
    free(buf);
}

static int smart_brute_sfi(bool decodeTLV) {

    uint8_t *buf = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    if (buf == NULL)
        return 1;

    int len;
    // READ RECORD
    uint8_t READ_RECORD[] = {0x00, 0xB2, 0x00, 0x00, 0x00};
    PrintAndLogEx(INFO, "Start SFI brute forcing");

    for (uint8_t sfi = 1; sfi <= 31; sfi++) {

        PrintAndLogEx(NORMAL, "." NOLF);

        for (uint16_t rec = 1; rec <= 255; rec++) {

            if (kbd_enter_pressed()) {
                PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
                free(buf);
                return 1;
            }

            READ_RECORD[2] = rec;
            READ_RECORD[3] = (sfi << 3) | 4;

            smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) +  sizeof(READ_RECORD));
            payload->flags = SC_RAW_T0;
            payload->len = sizeof(READ_RECORD);
            memcpy(payload->data, READ_RECORD, sizeof(READ_RECORD));

            clearCommandBuffer();
            SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) +  sizeof(READ_RECORD));

            len = smart_responseEx(buf, PM3_CMD_DATA_SIZE, false);

            if (buf[0] == 0x6C) {
                READ_RECORD[4] = buf[1];

                memcpy(payload->data, READ_RECORD, sizeof(READ_RECORD));
                clearCommandBuffer();
                SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) +  sizeof(READ_RECORD));
                len = smart_responseEx(buf, PM3_CMD_DATA_SIZE, false);

                READ_RECORD[4] = 0;
            }

            free(payload);

            if (len > 4) {

                PrintAndLogEx(SUCCESS, "\n\t file %02d, record %02d found", sfi, rec);

                uint8_t modifier = (buf[0] == 0xC0) ? 1 : 0;

                if (decodeTLV) {
                    if (!TLVPrintFromBuffer(buf + modifier, len - 2 - modifier)) {
                        PrintAndLogEx(SUCCESS, "\tHEX: %s", sprint_hex(buf, len));
                    }
                }
            }
            memset(buf, 0x00, PM3_CMD_DATA_SIZE);
        }
    }
    free(buf);
    return 0;
}

static void smart_brute_options(bool decodeTLV) {

    uint8_t *buf = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    if (!buf)
        return;

    // Get processing options command
    uint8_t GET_PROCESSING_OPTIONS[] = {0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00};

    smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) + sizeof(GET_PROCESSING_OPTIONS));
    payload->flags = SC_RAW_T0;
    payload->len = sizeof(GET_PROCESSING_OPTIONS);
    memcpy(payload->data, GET_PROCESSING_OPTIONS, sizeof(GET_PROCESSING_OPTIONS));

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + sizeof(GET_PROCESSING_OPTIONS));
    free(payload);

    int len = smart_responseEx(buf, PM3_CMD_DATA_SIZE, false);
    if (len > 4) {
        PrintAndLogEx(SUCCESS, "Got processing options");
        if (decodeTLV) {
            TLVPrintFromBuffer(buf, len - 2);
        }
    } else {
        PrintAndLogEx(FAILED, "Getting processing options failed");
    }

    free(buf);
}

static int CmdSmartBruteforceSFI(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "smart brute",
                  "Tries to bruteforce SFI, using a known list of AID's",
                  "smart brute -t"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("t", "tlv", "executes TLV decoder if it possible"),
//        arg_lit0("0", NULL, "use protocol T=0"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool decode_tlv = arg_get_lit(ctx, 1);
//    bool use_t0 = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    const char *SELECT = "00a40400%02zu%s";

//  uint8_t GENERATE_AC[] = {0x80, 0xAE};
//  uint8_t GET_CHALLENGE[] = {0x00, 0x84, 0x00};
//  uint8_t GET_DATA[] = {0x80, 0xCA, 0x00, 0x00, 0x00};
//  uint8_t SELECT[] = {0x00, 0xA4, 0x04, 0x00};
//  uint8_t UNBLOCK_PIN[] = {0x84, 0x24, 0x00, 0x00, 0x00};
//  uint8_t VERIFY[] = {0x00, 0x20, 0x00, 0x80};

    PrintAndLogEx(INFO, "Importing AID list");
    json_t *root = NULL;
    smart_loadjson("aidlist", &root);

    uint8_t *buf = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    if (!buf)
        return PM3_EMALLOC;

    PrintAndLogEx(INFO, "Selecting card");
    if (!smart_select(false, NULL)) {
        free(buf);
        return PM3_ESOFT;
    }

    char *caid = NULL;

    for (int i = 0; i < json_array_size(root); i++) {

        PrintAndLogEx(NORMAL, "+" NOLF);

        if (caid)
            free(caid);

        json_t *data, *jaid;

        data = json_array_get(root, i);
        if (json_is_object(data) == false) {
            PrintAndLogEx(ERR, "\ndata %d is not an object\n", i + 1);
            json_decref(root);
            return PM3_ESOFT;
        }

        jaid = json_object_get(data, "AID");
        if (json_is_string(jaid) == false) {
            PrintAndLogEx(ERR, "\nAID data [%d] is not a string", i + 1);
            json_decref(root);
            return PM3_ESOFT;
        }

        const char *aid = json_string_value(jaid);
        if (aid == false)
            continue;

        size_t aidlen = strlen(aid);
        caid = calloc(8 + 2 + aidlen + 1, sizeof(uint8_t));
        snprintf(caid, 8 + 2 + aidlen + 1, SELECT, aidlen >> 1, aid);

        int hexlen = 0;
        uint8_t cmddata[PM3_CMD_DATA_SIZE];
        int res = param_gethex_to_eol(caid, 0, cmddata, sizeof(cmddata), &hexlen);
        if (res)
            continue;

        smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) + hexlen);
        payload->flags = SC_RAW_T0;
        payload->len = hexlen;

        memcpy(payload->data, cmddata, hexlen);
        clearCommandBuffer();
        SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + hexlen);
        free(payload);

        int len = smart_responseEx(buf, PM3_CMD_DATA_SIZE, false);
        if (len < 3)
            continue;

        json_t *jvendor, *jname;
        jvendor = json_object_get(data, "Vendor");
        if (json_is_string(jvendor) == false) {
            PrintAndLogEx(ERR, "Vendor data [%d] is not a string", i + 1);
            continue;
        }

        const char *vendor = json_string_value(jvendor);
        if (!vendor)
            continue;

        jname = json_object_get(data, "Name");
        if (json_is_string(jname) == false) {
            PrintAndLogEx(ERR, "Name data [%d] is not a string", i + 1);
            continue;
        }
        const char *name = json_string_value(jname);
        if (!name)
            continue;

        PrintAndLogEx(SUCCESS, "\nAID %s | %s | %s", aid, vendor, name);

        smart_brute_options(decode_tlv);

        smart_brute_prim();

        smart_brute_sfi(decode_tlv);

        PrintAndLogEx(SUCCESS, "\nSFI brute force done\n");
    }

    if (caid)
        free(caid);

    free(buf);
    json_decref(root);

    PrintAndLogEx(SUCCESS, "\nSearch completed.");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,               AlwaysAvailable, "This help"},
    {"list",     CmdSmartList,          AlwaysAvailable, "List ISO 7816 history"},
    {"info",     CmdSmartInfo,          IfPm3Smartcard,  "Tag information"},
    {"reader",   CmdSmartReader,        IfPm3Smartcard,  "Act like an IS07816 reader"},
    {"raw",      CmdSmartRaw,           IfPm3Smartcard,  "Send raw hex data to tag"},
    {"upgrade",  CmdSmartUpgrade,       AlwaysAvailable, "Upgrade sim module firmware"},
    {"setclock", CmdSmartSetClock,      IfPm3Smartcard,  "Set clock speed"},
    {"brute",    CmdSmartBruteforceSFI, IfPm3Smartcard,  "Bruteforce SFI"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdSmartcard(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int ExchangeAPDUSC(bool verbose, uint8_t *datain, int datainlen, bool activateCard, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {

    *dataoutlen = 0;

    smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) + datainlen);
    payload->flags = (SC_RAW_T0 | SC_LOG);
    if (activateCard) {
        payload->flags |= (SC_SELECT | SC_CONNECT);
    }
    payload->len = datainlen;
    memcpy(payload->data, datain, datainlen);

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + datainlen);

    int len = smart_responseEx(dataout, maxdataoutlen, verbose);
    if (len < 0) {
        free(payload);
        return 1;
    }

    // retry
    if (len > 1 && dataout[len - 2] == 0x6c && datainlen > 4) {

        payload->flags = SC_RAW_T0;
        payload->len = 5;
        // transfer length via T=0
        datain[4] = dataout[len - 1];
        memcpy(payload->data, datain, 5);
        clearCommandBuffer();
        SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + 5);
        datain[4] = 0;
        len = smart_responseEx(dataout, maxdataoutlen, verbose);
    }

    free(payload);
    *dataoutlen = len;
    return 0;
}

bool smart_select(bool verbose, smart_card_atr_t *atr) {
    if (atr)
        memset(atr, 0, sizeof(smart_card_atr_t));

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_ATR, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SMART_ATR, &resp, 2500) == false) {
        if (verbose) PrintAndLogEx(WARNING, "smart card select timeout");
        return false;
    }

    if (resp.status != PM3_SUCCESS) {
        if (verbose) PrintAndLogEx(WARNING, "smart card select failed");
        return false;
    }

    smart_card_atr_t card;
    memcpy(&card, (smart_card_atr_t *)resp.data.asBytes, sizeof(smart_card_atr_t));

    if (atr)
        memcpy(atr, &card, sizeof(smart_card_atr_t));

    if (verbose)
        PrintAndLogEx(INFO, "ISO7816-3 ATR : %s", sprint_hex(card.atr, card.atr_len));

    return true;
}


