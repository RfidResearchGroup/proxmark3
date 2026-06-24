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
// High frequency Legic commands
//-----------------------------------------------------------------------------
#include "cmdhflegic.h"

#include <ctype.h> // tolower

#include "pm3line.h"      // pm3line_read, pm3line_free
#include "cliparser.h"
#include "cmdparser.h"    // command_t
#include "comms.h"        // clearCommandBuffer
#include "cmdtrace.h"
#include "crc.h"
#include "crc16.h"
#include "fileutils.h"  //saveFile
#include "util_posix.h" // msleep

static int CmdHelp(const char *Cmd);

#define LEGIC_PRIME_MIM22   22
#define LEGIC_PRIME_MIM256  256
#define LEGIC_PRIME_MIM1024 1024
#define LEGIC_BLOCK_SIZE    8
#define LEGIC_PACKET_SIZE   (PM3_CMD_DATA_SIZE - sizeof(legic_packet_t))

static bool legic_xor(uint8_t *data, uint16_t cardsize) {

    if (cardsize <= 22) {
        PrintAndLogEx(INFO, "No obsfuscation such small dump");
        return false;
    }

    uint8_t crc = data[4];
    uint32_t calc_crc = CRC8Legic(data, 4);
    if (crc != calc_crc) {
        PrintAndLogEx(INFO, "CRC mismatch, obsfuscation not possible");
        return false;
    }

    for (uint16_t i = 22; i < cardsize; i++) {
        data[i] ^= crc;
    }
    PrintAndLogEx(SUCCESS, "Applying xoring of data done!");
    return true;
}

static void legic_xor_with_crc(uint8_t *data, uint16_t cardsize, uint8_t crc) {
    for (uint16_t i = 22; i < cardsize; i++) {
        data[i] ^= crc;
    }
}

static bool legic_clone_update_segment_crcs(uint8_t *data, size_t bytes_read, const uint8_t uid[4]) {
    // Decoded segmented payload starts at byte 22.
    size_t start = 22;
    bool found_segment = false;

    while (start + 5 <= bytes_read) {
        uint16_t seg_len = (((uint16_t)data[start + 1] & 0x07) << 8) | data[start];
        if (seg_len < 5 || start + seg_len > bytes_read) {
            break;
        }

        found_segment = true;
        uint8_t cmd[8] = {
            uid[0], uid[1], uid[2], uid[3],
            data[start], data[start + 1], data[start + 2], data[start + 3]
        };
        data[start + 4] = (uint8_t)CRC8Legic(cmd, sizeof(cmd));

        if (data[start + 1] & 0x80) {
            break;
        }

        start += seg_len;
    }

    if (!found_segment) {
        PrintAndLogEx(INFO, "No parseable LEGIC Prime segments found; treating dump as raw data.");
    }

    return true;
}

static int legic_write_bytes_to_tag(uint16_t offset, const uint8_t *data, size_t dlen) {
    uint32_t IV = 0x55;
    legic_chk_iv(&IV);

    legic_packet_t *payload = calloc(1, sizeof(legic_packet_t) + dlen);
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    payload->offset = (offset & 0xFFFF);
    payload->iv = (IV & 0x7F);
    payload->len = dlen;
    memcpy(payload->data, data, dlen);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_LEGIC_WRITER, (uint8_t *)payload, sizeof(legic_packet_t) + dlen);
    free(payload);

    uint8_t timeout = 0;
    while (WaitForResponseTimeout(CMD_HF_LEGIC_WRITER, &resp, 2000) == false) {
        ++timeout;
        PrintAndLogEx(NORMAL, "." NOLF);
        if (timeout > 10) {
            PrintAndLogEx(WARNING, "\ncommand execution time out");
            return PM3_ETIMEOUT;
        }
    }
    PrintAndLogEx(NORMAL, "");

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed writing tag");
        return PM3_ERFTRANS;
    }

    return PM3_SUCCESS;
}

static int legic_write_dump_to_tag(uint8_t *dump, size_t bytes_read) {
    PrintAndLogEx(SUCCESS, "Restoring to card");

    // fast push mode
    g_conn.block_after_ACK = true;

    PacketResponseNG resp;
    for (size_t i = 7; i < bytes_read; i += LEGIC_PACKET_SIZE) {
        size_t len = MIN((bytes_read - i), LEGIC_PACKET_SIZE);
        if (len == bytes_read - i) {
            g_conn.block_after_ACK = false;
        }

        legic_packet_t *payload = calloc(1, sizeof(legic_packet_t) + len);
        if (payload == NULL) {
            PrintAndLogEx(WARNING, "Failed to allocate memory");
            g_conn.block_after_ACK = false;
            return PM3_EMALLOC;
        }
        payload->offset = i;
        payload->iv = 0x55;
        payload->len = len;
        memcpy(payload->data, dump + i, len);

        clearCommandBuffer();
        SendCommandNG(CMD_HF_LEGIC_WRITER, (uint8_t *)payload, sizeof(legic_packet_t) + len);
        free(payload);

        uint8_t timeout = 0;
        while (WaitForResponseTimeout(CMD_HF_LEGIC_WRITER, &resp, 2000) == false) {
            ++timeout;
            PrintAndLogEx(NORMAL, "." NOLF);
            if (timeout > 10) {
                PrintAndLogEx(WARNING, "\ncommand execution time out");
                g_conn.block_after_ACK = false;
                return PM3_ETIMEOUT;
            }
        }
        PrintAndLogEx(NORMAL, "");

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Failed writing tag");
            g_conn.block_after_ACK = false;
            return PM3_ERFTRANS;
        }
        PrintAndLogEx(SUCCESS, "Wrote chunk [offset %zu | len %zu | total %zu", i, len, i + len);
    }

    g_conn.block_after_ACK = false;
    return PM3_SUCCESS;
}

static int CmdLegicMigrate(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic migrate",
                  "Clone a LEGIC Prime dump to the currently attached tag.\n"
                  "Optionally apply a DCF update after cloning, but only when explicitly requested.",
                  "hf legic migrate -f src.bin\n"
                  "hf legic migrate -f src.bin --dcf 60EA --danger");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Source dump file"),
        arg_str0(NULL, "dcf", "<hex>", "Optional DCF bytes to write after clone"),
        arg_lit0(NULL, "danger", "Allow the explicit DCF write"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int dcf_len = 0;
    uint8_t dcf[2] = {0};
    if (arg_get_str(ctx, 2) != NULL) {
        CLIParamHexToBuf(arg_get_str(ctx, 2), dcf, sizeof(dcf), &dcf_len);
        if (dcf_len != 2) {
            PrintAndLogEx(WARNING, "DCF must be exactly two bytes");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    bool allow_dcf = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (fnlen < 1) {
        PrintAndLogEx(WARNING, "Source dump file is required");
        return PM3_EINVARG;
    }

    if (dcf_len > 0 && !allow_dcf) {
        PrintAndLogEx(WARNING, "Use --danger to allow the explicit DCF write");
        return PM3_EINVARG;
    }

    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, LEGIC_PRIME_MIM1024);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (bytes_read <= 22) {
        PrintAndLogEx(WARNING, "Dump is too small to migrate");
        free(dump);
        return PM3_EFILE;
    }

    if (legic_xor(dump, bytes_read) == false) {
        PrintAndLogEx(FAILED, "Failed to decode source dump");
        free(dump);
        return PM3_EFAILED;
    }

    legic_card_select_t card;
    if (legic_get_type(&card) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed to identify tagtype");
        free(dump);
        return PM3_ESOFT;
    }

    legic_print_type(card.cardsize, 0);

    if (card.cardsize != bytes_read) {
        PrintAndLogEx(WARNING, "Fail, filesize and cardsize is not equal. [%u != %zu]", card.cardsize, bytes_read);
        free(dump);
        return PM3_EFILE;
    }

    uint8_t target_uid[4] = {0};
    memcpy(target_uid, card.uid, sizeof(target_uid));
    uint8_t target_mcc = (uint8_t)CRC8Legic(target_uid, sizeof(target_uid));
    legic_clone_update_segment_crcs(dump, bytes_read, target_uid);
    memcpy(dump, target_uid, sizeof(target_uid));
    dump[4] = target_mcc;

    legic_xor_with_crc(dump, bytes_read, dump[4]);

    int write_res = legic_write_dump_to_tag(dump, bytes_read);
    if (write_res != PM3_SUCCESS) {
        free(dump);
        return write_res;
    }

    if (dcf_len > 0) {
        PrintAndLogEx(SUCCESS, "Applying explicit DCF update");
        int dcf_res = legic_write_bytes_to_tag(5, dcf, sizeof(dcf));
        if (dcf_res != PM3_SUCCESS) {
            free(dump);
            return dcf_res;
        }
    }

    free(dump);
    PrintAndLogEx(SUCCESS, "Done!");
    return PM3_SUCCESS;
}

static int decode_and_print_memory(uint16_t card_size, const uint8_t *input_buffer) {

    if (!(card_size == LEGIC_PRIME_MIM22 || card_size == LEGIC_PRIME_MIM256 || card_size == LEGIC_PRIME_MIM1024)) {
        PrintAndLogEx(FAILED, "Bytebuffer is not any known legic card size! (MIM22, MIM256, MIM1024)");
        return PM3_EFAILED;
    }

    // copy input buffer into newly allocated buffer, because the existing code mutates the data inside.
    uint8_t *data = calloc(card_size, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    memcpy(data, input_buffer, card_size);

    int i = 0, k = 0, segmentNum = 0, segment_len = 0, segment_flag = 0;
    int wrp = 0, wrc = 0, dcf = 0;
    uint8_t stamp_len = 0;
    char token_type[6] = {0, 0, 0, 0, 0, 0};
    int bIsSegmented = 0;
    int return_value = PM3_SUCCESS;

    // Output CDF System area (9 bytes) plus remaining header area (12 bytes)
    int crc = data[4];
    uint32_t calc_crc = CRC8Legic(data, 4);

    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ----------------------------------------");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, " " _CYAN_("CDF: System Area"));
    PrintAndLogEx(INFO, "------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "MCD: " _GREEN_("%02X") " MSN: " _GREEN_("%s") " MCC: " _GREEN_("%02X") " ( %s )",
                  data[0],
                  sprint_hex(data + 1, 3),
                  data[4],
                  (calc_crc == crc) ? _GREEN_("ok") : _RED_("fail")
                 );

    // MCD = Manufacturer ID (should be list meaning something?)

    token_type[0] = 0;
    dcf = ((int)data[6] << 8) | (int)data[5];

    // New unwritten media?
    if (dcf == 0xFFFF) {

        PrintAndLogEx(SUCCESS, "DCF: %d (%02x %02x), Token Type=NM (New Media)",
                      dcf,
                      data[5],
                      data[6]
                     );

    } else if (dcf > 60000) { // Master token?

        int fl = 0;

        if (data[6] == 0xEC) {
            strncpy(token_type, "XAM", sizeof(token_type) - 1);
            fl = 1;
            stamp_len = 0x0c - (data[5] >> 4);
        } else {

            uint8_t tmp = data[5] & 0x7F;
            if (tmp <= 0x2F) {
                strncpy(token_type, "IAM", sizeof(token_type) - 1);
                fl = (0x2F - tmp) + 1;
            } else if (tmp >= 0x30 && tmp <= 0x6F) {
                strncpy(token_type, "SAM", sizeof(token_type) - 1);
                fl = (0x6F - tmp) + 1;
            } else if (tmp >= 0x70 && tmp <= 0x7F) {
                strncpy(token_type, "GAM", sizeof(token_type) - 1);
                fl = (0x7F - tmp) + 1;
            }

            stamp_len = 0xFC - data[6];
        }

        PrintAndLogEx(SUCCESS, "DCF: %d (%02x %02x) Token Type=" _YELLOW_("%s") " (OLE=%01u) OL=%02u FL=%02u",
                      dcf,
                      data[5],
                      data[6],
                      token_type,
                      (data[5] & 0x80) >> 7,
                      stamp_len,
                      fl
                     );

    } else { // Is IM(-S) type of card...

        if (data[7] == 0x9F && data[8] == 0xFF) {
            bIsSegmented = 1;
            strncpy(token_type, "IM-S", sizeof(token_type) - 1);
        } else {
            strncpy(token_type, "IM", sizeof(token_type) - 1);
        }

        PrintAndLogEx(SUCCESS, "DCF: %d (%02x %02x) Token Type = %s (OLE = %01u)",
                      dcf,
                      data[5],
                      data[6],
                      token_type,
                      (data[5] & 0x80) >> 7
                     );
    }

    // Makes no sense to show this on blank media...
    if (dcf != 0xFFFF) {

        if (bIsSegmented) {
            PrintAndLogEx(SUCCESS, "WRP = %02u WRC = %01u RD = %01u SSC = %02X",
                          data[7] & 0x0f,
                          (data[7] & 0x70) >> 4,
                          (data[7] & 0x80) >> 7,
                          data[8]
                         );
        }

        // Header area is only available on IM-S cards, on master tokens this data is the master token data itself
        if (bIsSegmented || dcf > 60000) {
            if (dcf > 60000) {
                PrintAndLogEx(SUCCESS, "Master token data");
                PrintAndLogEx(SUCCESS, "%s", sprint_hex(data + 8, 14));
            } else {
                PrintAndLogEx(SUCCESS, "Remaining Header Area");
                PrintAndLogEx(SUCCESS, "%s", sprint_hex(data + 9, 13));
            }
        }
    }
    PrintAndLogEx(INFO, "------------------------------------------------------");

    uint8_t segCrcBytes[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t segCalcCRC = 0;
    uint32_t segCRC = 0;

    // Not a data card by dcf or too small to contain data (MIM22)?
    if (dcf > 60000 || card_size == LEGIC_PRIME_MIM22) {
        goto out;
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(SUCCESS, _CYAN_("ADF: User Area"));
    PrintAndLogEx(INFO, "------------------------------------------------------");

    if (bIsSegmented) {

        // Data start point on segmented cards
        i = 22;

        // decode segments
        for (segmentNum = 1; segmentNum < 128; segmentNum++) {
            // for decoding the segment header we need at least 4 bytes left in buffer
            if ((i + 4) > card_size) {
                PrintAndLogEx(FAILED, "Cannot read segment header, because the input buffer is too small.");
                PrintAndLogEx(FAILED, "Please check that the data is correct and properly aligned");
                return_value = PM3_EOUTOFBOUND;
                goto out;
            }
            segment_len = ((data[i + 1] ^ crc) & 0x0f) * 256 + (data[i] ^ crc);
            segment_flag = ((data[i + 1] ^ crc) & 0xf0) >> 4;
            wrp = (data[i + 2] ^ crc);
            wrc = ((data[i + 3] ^ crc) & 0x70) >> 4;

            bool hasWRC = (wrc > 0);
            bool hasWRP = (wrp > wrc);
            int wrp_len = (wrp - wrc);
            int remain_seg_payload_len = (segment_len - wrp - 5);

            // validate segment-crc
            segCrcBytes[0] = data[0];         //uid0
            segCrcBytes[1] = data[1];         //uid1
            segCrcBytes[2] = data[2];         //uid2
            segCrcBytes[3] = data[3];         //uid3
            segCrcBytes[4] = (data[i] ^ crc); //hdr0
            segCrcBytes[5] = (data[i + 1] ^ crc); //hdr1
            segCrcBytes[6] = (data[i + 2] ^ crc); //hdr2
            segCrcBytes[7] = (data[i + 3] ^ crc); //hdr3

            segCalcCRC = CRC8Legic(segCrcBytes, 8);
            segCRC = data[i + 4] ^ crc;

            PrintAndLogEx(SUCCESS, "Segment....... " _YELLOW_("%02u"), segmentNum);
            PrintAndLogEx(SUCCESS, "Raw header.... 0x%02X 0x%02X 0x%02X 0x%02X",
                          data[i] ^ crc,
                          data[i + 1] ^ crc,
                          data[i + 2] ^ crc,
                          data[i + 3] ^ crc
                         );
            PrintAndLogEx(SUCCESS, "Segment len... %u  Flag: 0x%X (valid:%01u last:%01u)",
                          segment_len,
                          segment_flag,
                          (segment_flag & 0x4) >> 2,
                          (segment_flag & 0x8) >> 3
                         );
            PrintAndLogEx(SUCCESS, "              WRP: %02u WRC: %02u RD: %01u CRC: 0x%02X ( %s )",
                          wrp,
                          wrc,
                          ((data[i + 3] ^ crc) & 0x80) >> 7,
                          segCRC,
                          (segCRC == segCalcCRC) ? _GREEN_("ok") : _RED_("fail")
                         );

            i += 5;

            // for printing the complete segment we need at least wrc + wrp_len + remain_seg_payload_len bytes
            if ((i + wrc + wrp_len + remain_seg_payload_len) > card_size) {
                PrintAndLogEx(FAILED, "Cannot read segment body, because the input buffer is too small. "
                                      "Please check that the data is correct and properly aligned. ");
                return_value = PM3_EOUTOFBOUND;
                goto out;
            }

            if (hasWRC) {
                PrintAndLogEx(INFO, "");
                PrintAndLogEx(SUCCESS, _CYAN_("WRC protected area:") "   (I %d | K %d| WRC %d)", i, k, wrc);
                PrintAndLogEx(INFO, "");
                PrintAndLogEx(INFO, "## | data                                            | ascii");
                PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");

                for (k = i; k < (i + wrc); ++k)
                    data[k] ^= crc;

                print_hex_break(data + i, wrc, 16);
                PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");
                PrintAndLogEx(INFO, "");
                i += wrc;
            }

            if (hasWRP) {
                PrintAndLogEx(SUCCESS, _CYAN_("Remaining write protected area:") "  (I %d | K %d | WRC %d | WRP %d  WRP_LEN %d)", i, k, wrc, wrp, wrp_len);
                PrintAndLogEx(INFO, "");
                PrintAndLogEx(INFO, "## | data                                            | ascii");
                PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");

                for (k = i; k < (i + wrp_len); ++k)
                    data[k] ^= crc;

                print_hex_break(data + i, wrp_len, 16);
                PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");
                PrintAndLogEx(INFO, "");
                i += wrp_len;

                // does this one work? (Answer: Only if KGH/BGH is used with BCD encoded card number! So maybe this will show just garbage...)
                if (wrp_len == 8) {
                    PrintAndLogEx(SUCCESS, "Card ID: " _YELLOW_("%2X%02X%02X"),
                                  data[i - 4],
                                  data[i - 3],
                                  data[i - 2]
                                 );
                }
            }
            if (remain_seg_payload_len > 0) {
                PrintAndLogEx(SUCCESS, _CYAN_("Remaining segment payload:") "  (I %d | K %d | Remain LEN %d)", i, k, remain_seg_payload_len);
                PrintAndLogEx(INFO, "");
                PrintAndLogEx(INFO, "## | data                                            | ascii");
                PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");

                for (k = i; k < (i + remain_seg_payload_len); ++k)
                    data[k] ^= crc;

                print_hex_break(data + i, remain_seg_payload_len, 16);
                PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------\n");
                i += remain_seg_payload_len;
            }
            // end with last segment
            if (segment_flag & 0x8)
                goto out;

        } // end for loop

    } else {
        // Data start point on unsegmented cards
        i = 8;

        wrp = data[7] & 0x0F;
        wrc = (data[7] & 0x70) >> 4;

        bool hasWRC = (wrc > 0);
        bool hasWRP = (wrp > wrc);
        int wrp_len = (wrp - wrc);
        int remain_seg_payload_len = (card_size - 22 - wrp);

        PrintAndLogEx(SUCCESS, "Unsegmented card - WRP: %02u WRC: %02u RD: %01u",
                      wrp,
                      wrc,
                      (data[7] & 0x80) >> 7
                     );

        // for printing the complete segment we need at least wrc + wrp_len + remain_seg_payload_len bytes
        if ((i + wrc + wrp_len + remain_seg_payload_len) > card_size) {
            PrintAndLogEx(FAILED, "Cannot read segment body, because the input buffer is too small. "
                                  "Please check that the data is correct and properly aligned. ");
            return_value = PM3_EOUTOFBOUND;
            goto out;
        }

        if (hasWRC) {
            PrintAndLogEx(SUCCESS, _CYAN_("WRC protected area:") "   (I %d | WRC %d)", i, wrc);
            PrintAndLogEx(INFO, "");
            PrintAndLogEx(INFO, "## | data                                            | ascii");
            PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");
            print_hex_break(data + i, wrc, 16);
            PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");
            PrintAndLogEx(INFO, "");
            i += wrc;
        }

        if (hasWRP) {
            PrintAndLogEx(SUCCESS, _CYAN_("Remaining write protected area:") "  (I %d | WRC %d | WRP %d | WRP_LEN %d)", i, wrc, wrp, wrp_len);
            PrintAndLogEx(INFO, "");
            PrintAndLogEx(INFO, "## | data                                            | ascii");
            PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");
            print_hex_break(data + i, wrp_len, 16);
            PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");
            PrintAndLogEx(INFO, "");
            i += wrp_len;

            // Q: does this one work?
            // A: Only if KGH/BGH is used with BCD encoded card number. Maybe this will show just garbage
            if (wrp_len == 8) {
                PrintAndLogEx(SUCCESS, "Card ID: " _YELLOW_("%2X%02X%02X"),
                              data[i - 4],
                              data[i - 3],
                              data[i - 2]
                             );
            }
        }

        if (remain_seg_payload_len > 0) {
            PrintAndLogEx(SUCCESS, _CYAN_("Remaining segment payload:") "  (I %d | Remain LEN %d)", i, remain_seg_payload_len);
            PrintAndLogEx(INFO, "");
            PrintAndLogEx(INFO, "## | data                                            | ascii");
            PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");
            print_hex_break(data + i, remain_seg_payload_len, 16);
            PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------\n");
        }
    }

out:
    free(data);
    return (return_value);
}

/*
 *  Output BigBuf and deobfuscate LEGIC RF tag data.
 *  This is based on information given in the talk held
 *  by Henryk Ploetz and Karsten Nohl at 26c3
 */
static int CmdLegicInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic info",
                  "Gets information from a LEGIC Prime tag like systemarea, user areas, etc",
                  "hf legic info");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    uint16_t datalen = 0;

    // tagtype
    legic_card_select_t card;
    if (legic_get_type(&card) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed to identify tagtype");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Reading full tag memory of " _YELLOW_("%d") " bytes...", card.cardsize);

    // allocate receiver buffer
    uint8_t *data = calloc(card.cardsize, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    int status = legic_read_mem(0, card.cardsize, 0x55, data, &datalen);
    if (status != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed reading memory");
        free(data);
        return status;
    }

    if (verbose) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "## |  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F | ascii");
        PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");
        print_hex_break(data, datalen, 16);
    }

    PrintAndLogEx(NORMAL, "");
    decode_and_print_memory(card.cardsize, data);
    free(data);
    return PM3_SUCCESS;
}

// params:
// offset in data memory
// number of bytes to read
static int CmdLegicRdbl(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic rdbl",
                  "Read data from a LEGIC Prime tag",
                  "hf legic rdbl -o 0 -l 16           -> read 16 bytes from offset 0 (system header)\n"
                  "hf legic rdbl -o 0 -l 4 --iv 55    -> read 4 bytes from offset 0\n"
                  "hf legic rdbl -o 0 -l 256 --iv 55  -> read 256 bytes from offset 0");

    void *argtable[] = {
        arg_param_begin,
        arg_int0("o", "offset", "<dec>", "offset in data array to start download from"),
        arg_int0("l", "length", "<dec>", "number of bytes to read"),
        arg_str0(NULL, "iv", "<hex>", "Initialization vector to use. Must be odd and 7bits max"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int offset = arg_get_int_def(ctx, 1, 0);
    int len = arg_get_int_def(ctx, 2, 16);

    int iv_len = 0;
    uint8_t iv[1] = {0x01};
    CLIGetHexWithReturn(ctx, 3, iv, &iv_len);
    CLIParserFree(ctx);

    // sanity checks
    if (len + offset >= LEGIC_PRIME_MIM1024) {
        PrintAndLogEx(WARNING, "Out-of-bounds, Cardsize = %d, [offset+len = %d ]", LEGIC_PRIME_MIM1024, len + offset);
        return PM3_EOUTOFBOUND;
    }

    PrintAndLogEx(SUCCESS, "Reading %d bytes, from offset %d", len, offset);

    // allocate receiver buffer
    uint8_t *data = calloc(len, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    uint16_t datalen = 0;
    int status = legic_read_mem(offset, len, iv[0], data, &datalen);
    if (status == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "## |  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F | ascii");
        PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");
        print_hex_break(data, datalen, 16);
    }
    free(data);
    return status;
}

static int CmdLegicSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic sim",
                  "Simulates a LEGIC Prime tag.\n"
                  "If a file is supplied, it is loaded into emulator memory first.",
                  "hf legic sim --22\n"
                  "hf legic sim -f myfile.bin --1024\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "22", "LEGIC Prime MIM22"),
        arg_lit0(NULL, "256", "LEGIC Prime MIM256 (def)"),
        arg_lit0(NULL, "1024", "LEGIC Prime MIM1024"),
        arg_str0("f", "file", "<fn>", "Optional dump file to load into emulator memory"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool m1 = arg_get_lit(ctx, 1);
    bool m2 = arg_get_lit(ctx, 2);
    bool m3 = arg_get_lit(ctx, 3);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    // validations
    if (m1 + m2 + m3 > 1) {
        PrintAndLogEx(WARNING, "Only specify one LEGIC Prime Type");
        return PM3_EINVARG;
    } else if (m1 + m2 + m3 == 0) {
        m2 = true;
    }

    size_t sim_cardsize = LEGIC_PRIME_MIM256;
    if (m1)
        sim_cardsize = LEGIC_PRIME_MIM22;
    else if (m2)
        sim_cardsize = LEGIC_PRIME_MIM256;
    else if (m3)
        sim_cardsize = LEGIC_PRIME_MIM1024;

    if (fnlen > 0) {
        uint8_t *dump = NULL;
        size_t bytes_read = 0;
        int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, LEGIC_PRIME_MIM1024);
        if (res != PM3_SUCCESS) {
            return res;
        }

        if (bytes_read != sim_cardsize) {
            PrintAndLogEx(WARNING, "Dump size [%zu] does not match selected simulator size [%zu]", bytes_read, sim_cardsize);
            free(dump);
            return PM3_EFILE;
        }

        legic_seteml(dump, 0, bytes_read);
        free(dump);
    }

    struct {
        uint8_t tagtype;
        bool send_reply;
    } PACKED payload;

    payload.send_reply = true;
    if (m1)
        payload.tagtype = 0;
    else if (m2)
        payload.tagtype = 1;
    else if (m3)
        payload.tagtype = 2;

    clearCommandBuffer();
    SendCommandNG(CMD_HF_LEGIC_SIMULATE, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;

    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to abort simulation");
    bool abort_by_keyboard = false;
    for (;;) {
        if (abort_by_keyboard == false && kbd_enter_pressed()) {
            PrintAndLogEx(INFO, "Key pressed, please wait about a minute for the pm3 to stop...");
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, "Aborted via keyboard!");
            abort_by_keyboard = true;
        }

        if (WaitForResponseTimeout(CMD_HF_LEGIC_SIMULATE, &resp, 1500)) {
            break;
        }
    }

    PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf legic list") "` to view trace log");
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

static int CmdLegicWrbl(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic wrbl",
                  "Write data to a LEGIC Prime tag. It autodetects tagsize to ensure proper write",
                  "hf legic wrbl -o 0 -d 11223344    -> Write 0x11223344 starting from offset 0)\n"
                  "hf legic wrbl -o 10 -d DEADBEEF   -> Write 0xdeadbeef starting from offset 10");

    void *argtable[] = {
        arg_param_begin,
        arg_int1("o", "offset", "<dec>", "offset in data array to start writing"),
        arg_str1("d", "data", "<hex>", "data to write"),
        arg_lit0(NULL, "danger", "Auto-confirm dangerous operations"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int offset = arg_get_int_def(ctx, 1, 0);

    int dlen = 0;
    uint8_t data[LEGIC_PRIME_MIM1024] = {0};
    CLIGetHexWithReturn(ctx, 2, data, &dlen);

    bool autoconfirm = arg_get_lit(ctx, 3);

    CLIParserFree(ctx);

    // OUT-OF-BOUNDS checks
    // UID 4+1 bytes can't be written to.
    if (offset < 5) {
        PrintAndLogEx(WARNING, "Out-of-bounds, bytes 0-1-2-3-4 can't be written to. Offset = %d", offset);
        return PM3_EOUTOFBOUND;
    }

    // tagtype
    legic_card_select_t card;
    if (legic_get_type(&card) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed to identify tagtype");
        return PM3_ESOFT;
    }

    legic_print_type(card.cardsize, 0);

    if (dlen + offset > card.cardsize) {
        PrintAndLogEx(WARNING, "Out-of-bounds, Cardsize = %d, [offset+len = %d ]", card.cardsize, dlen + offset);
        return PM3_EOUTOFBOUND;
    }

    if ((offset == 5 || offset == 6) && (! autoconfirm)) {
        PrintAndLogEx(INFO, "############# DANGER ################");
        PrintAndLogEx(WARNING, "# changing the DCF is irreversible  #");
        PrintAndLogEx(INFO, "#####################################");
        const char *confirm = "Do you really want to continue? y(es)/n(o) : ";
        bool overwrite = false;
        char *answer = pm3line_read(confirm);
        overwrite = (answer[0] == 'y' || answer[0] == 'Y');
        pm3line_free(answer);
        if (overwrite == false) {
            PrintAndLogEx(WARNING, "command cancelled");
            return PM3_EOPABORTED;
        }
    }

    uint32_t IV = 0x55;
    legic_chk_iv(&IV);

    PrintAndLogEx(SUCCESS, "Writing to tag to offset %i", offset);

    legic_packet_t *payload = calloc(1, sizeof(legic_packet_t) + dlen);
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    payload->offset = (offset & 0xFFFF);
    payload->iv = (IV & 0x7F);
    payload->len = dlen;
    memcpy(payload->data, data, dlen);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_LEGIC_WRITER, (uint8_t *)payload, sizeof(legic_packet_t) + dlen);
    free(payload);

    uint8_t timeout = 0;
    while (WaitForResponseTimeout(CMD_HF_LEGIC_WRITER, &resp, 2000) == false) {
        ++timeout;
        PrintAndLogEx(NORMAL, "." NOLF);
        if (timeout > 10) {
            PrintAndLogEx(WARNING, "\ncommand execution time out");
            return PM3_ETIMEOUT;
        }
    }
    PrintAndLogEx(NORMAL, "");

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed writing tag");
        return PM3_ERFTRANS;
    }

    return PM3_SUCCESS;
}

static int CmdLegicCalcCrc(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic crc",
                  "Calculates the legic crc8/crc16 on the given data",
                  "hf legic crc -d deadbeef1122\n"
                  "hf legic crc -d deadbeef1122 --mcc 9A -t 16    -> CRC Type 16");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "bytes to calculate crc over"),
        arg_str0(NULL, "mcc", "<hex>", "MCC hex byte (UID CRC)"),
        arg_int0("t", "type", "<dec>", "CRC Type (default: 8)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int data_len = 0;
    uint8_t data[4096] = {0};

    CLIGetHexWithReturn(ctx, 1, data, &data_len);

    int mcc_len = 0;
    uint8_t mcc[1] = {0};  // formerly uidcrc

    CLIGetHexWithReturn(ctx, 2, mcc, &mcc_len);

    int type = arg_get_int_def(ctx, 3, 0);

    CLIParserFree(ctx);

    switch (type) {
        case 16:
            init_table(CRC_LEGIC_16);
            PrintAndLogEx(SUCCESS, "Legic crc16: %X", crc16_legic(data, data_len, mcc[0]));
            break;
        default:
            PrintAndLogEx(SUCCESS, "Legic crc8: %X",  CRC8Legic(data, data_len));
            break;
    }

    return PM3_SUCCESS;
}

int legic_read_mem(uint32_t offset, uint32_t len, uint32_t iv, uint8_t *out, uint16_t *outlen) {

    legic_chk_iv(&iv);

    legic_packet_t *payload = calloc(1, sizeof(legic_packet_t));
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    payload->offset = (offset & 0xFFFF);
    payload->iv = iv;
    payload->len = len;

    clearCommandBuffer();
    SendCommandNG(CMD_HF_LEGIC_READER, (uint8_t *)payload, sizeof(legic_packet_t));
    free(payload);
    PacketResponseNG resp;

    uint8_t timeout = 0;
    while (WaitForResponseTimeout(CMD_HF_LEGIC_READER, &resp, 1000) == false) {
        ++timeout;
        PrintAndLogEx(NORMAL,  "." NOLF);
        if (timeout > 14) {
            PrintAndLogEx(WARNING, "\ncommand execution time out");
            return PM3_ETIMEOUT;
        }
    }
    PrintAndLogEx(NORMAL, "");

    *outlen = resp.data.asDwords[0];
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed reading tag");
        return PM3_ESOFT;
    }

    if (*outlen != len)
        PrintAndLogEx(WARNING, "Fail, only managed to read %u bytes", *outlen);

    // copy data from device
    if (GetFromDevice(BIG_BUF_EML, out, *outlen, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

int legic_print_type(uint32_t tagtype, uint8_t spaces) {
    char spc[11] = "          ";
    spc[10] = 0x00;
    char *spacer = spc + (10 - spaces);

    if (tagtype == LEGIC_PRIME_MIM22)
        PrintAndLogEx(SUCCESS, "%sTYPE: " _YELLOW_("MIM%d card (outdated)"), spacer, tagtype);
    else if (tagtype == LEGIC_PRIME_MIM256)
        PrintAndLogEx(SUCCESS, "%sTYPE: " _YELLOW_("MIM%d card (234 bytes)"), spacer, tagtype);
    else if (tagtype == LEGIC_PRIME_MIM1024)
        PrintAndLogEx(SUCCESS, "%sTYPE: " _YELLOW_("MIM%d card (1002 bytes)"), spacer, tagtype);
    else
        PrintAndLogEx(INFO, "%sTYPE: " _YELLOW_("Unknown %06x"), spacer, tagtype);
    return PM3_SUCCESS;
}
int legic_get_type(legic_card_select_t *card) {

    if (card == NULL) {
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_LEGIC_INFO, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_LEGIC_INFO, &resp, 1500) == false) {
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    memcpy(card, resp.data.asBytes, sizeof(legic_card_select_t));
    return PM3_SUCCESS;
}

void legic_chk_iv(uint32_t *iv) {
    if ((*iv & 0x7F) != *iv) {
        *iv &= 0x7F;
        PrintAndLogEx(INFO, "Truncating IV to 7bits, %u", *iv);
    }
    // IV must be odd
    if ((*iv & 1) == 0) {
        *iv |= 0x01;
        PrintAndLogEx(INFO, "LSB of IV must be SET %u", *iv);
    }
}

void legic_seteml(uint8_t *src, uint32_t offset, uint32_t numofbytes) {

    PrintAndLogEx(INFO, "Uploading to emulator memory");
    PrintAndLogEx(INFO, "." NOLF);

    // fast push mode
    g_conn.block_after_ACK = true;
    for (size_t i = offset; i < numofbytes; i += LEGIC_PACKET_SIZE) {

        size_t len = MIN((numofbytes - i), LEGIC_PACKET_SIZE);
        if (len == numofbytes - i) {
            // Disable fast mode on last packet
            g_conn.block_after_ACK = false;
        }

        legic_packet_t *payload = calloc(1, sizeof(legic_packet_t) + len);
        if (payload == NULL) {
            PrintAndLogEx(WARNING, "Failed to allocate memory");
            return;
        }
        payload->offset = i;
        payload->len = len;
        memcpy(payload->data, src + i, len);

        clearCommandBuffer();
        SendCommandNG(CMD_HF_LEGIC_ESET, (uint8_t *)payload, sizeof(legic_packet_t) + len);
        free(payload);
        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "uploaded " _YELLOW_("%d") " bytes to emulator memory", numofbytes);
}

static int CmdLegicReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic reader",
                  "Read UID and type information from a LEGIC Prime tag",
                  "hf legic reader");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    return readLegicUid(cm, true);
}

static int CmdLegicDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic dump",
                  "Read all memory from LEGIC Prime tags and saves to (bin/json) dump file\n"
                  "It autodetects card type (MIM22, MIM256, MIM1024)",
                  "hf legic dump             --> use UID as filename\n"
                  "hf legic dump -f myfile \n"
                  "hf legic dump --de        --> use UID as filename and deobfuscate data");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "Dump filename"),
        arg_lit0(NULL, "de", "deobfuscate dump data (xor with MCC)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool shall_deobsfuscate = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    // tagtype
    legic_card_select_t card;
    if (legic_get_type(&card) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed to identify tagtype");
        return PM3_ESOFT;
    }
    uint16_t dumplen = card.cardsize;

    legic_print_type(dumplen, 0);
    PrintAndLogEx(SUCCESS, "Reading tag memory." NOLF);

    legic_packet_t *payload = calloc(1, sizeof(legic_packet_t));
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    payload->offset = 0;
    payload->iv = 0x55;
    payload->len = dumplen;

    clearCommandBuffer();
    SendCommandNG(CMD_HF_LEGIC_READER, (uint8_t *)payload, sizeof(legic_packet_t));
    free(payload);
    PacketResponseNG resp;

    uint8_t timeout = 0;
    while (WaitForResponseTimeout(CMD_HF_LEGIC_READER, &resp, 2000) == false) {
        ++timeout;
        PrintAndLogEx(NORMAL, "." NOLF);
        if (timeout > 10) {
            PrintAndLogEx(WARNING, "\ncommand execution time out");
            return PM3_ETIMEOUT;
        }
    }
    PrintAndLogEx(NORMAL, "");

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed dumping tag data");
        return PM3_ERFTRANS;
    }

    uint16_t readlen = resp.data.asDwords[0];
    uint8_t *data = calloc(readlen, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    if (readlen != dumplen)
        PrintAndLogEx(WARNING, "Fail, only managed to read 0x%02X bytes of 0x%02X", readlen, dumplen);

    // copy data from device
    if (GetFromDevice(BIG_BUF_EML, data, readlen, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(data);
        return PM3_ETIMEOUT;
    }

    if (shall_deobsfuscate) {
        // Deobfuscate the whole dump. Unused data (after the last sector) will be MCC since
        // 0x00 ^ MCC = MCC. Finding the end of used data is not part of this function.
        if (legic_xor(data, dumplen) == false) {
            PrintAndLogEx(FAILED, "Deobsfuscate failed, exiting...");
            PrintAndLogEx(HINT, "Hint: Try running command without `--de` parameter");
            free(data);
            return PM3_EFAILED;
        }
    }

    // user supplied filename?
    if (fnlen < 1) {
        PrintAndLogEx(INFO, "Using UID as filename");
        strcat(filename, "hf-legic-");
        FillFileNameByUID(filename, data, "-dump", 4);
    }

    pm3_save_dump(filename, data, readlen, jsfLegic_v2);
    free(data);
    return PM3_SUCCESS;
}

static int CmdLegicRestore(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic restore",
                  "Restore an exact LEGIC Prime dump back to the same card family.\n"
                  "This writes the dump bytes back as-is (except the first 7 bytes [UID(4) MCC(1) DCF(2)] are preserved from the target card).",
                  "hf legic restore -f myfile        --> use user specified filename\n"
                  "hf legic restore -f myfile --ob   --> use UID as filename and obfuscate data");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify a filename to restore"),
        arg_lit0(NULL, "ob", "obfuscate dump data (xor with MCC)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool shall_obsfuscate = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    // tagtype
    legic_card_select_t card;
    if (legic_get_type(&card) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed to identify tagtype");
        return PM3_ESOFT;
    }

    legic_print_type(card.cardsize, 0);

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, LEGIC_PRIME_MIM1024);
    if (res != PM3_SUCCESS) {
        return res;
    }

    // validation
    if (card.cardsize != bytes_read) {
        PrintAndLogEx(WARNING, "Fail, filesize and cardsize is not equal. [%u != %zu]", card.cardsize, bytes_read);
        free(dump);
        return PM3_EFILE;
    }

    if (shall_obsfuscate) {
        if (legic_xor(dump, card.cardsize) == false) {
            PrintAndLogEx(FAILED, "Obsfuscate failed, exiting...");
            PrintAndLogEx(HINT, "Hint: Try running command without `--ob` parameter");
            free(dump);
            return PM3_EFAILED;
        }
    }

    int write_res = legic_write_dump_to_tag(dump, bytes_read);
    if (write_res != PM3_SUCCESS) {
        free(dump);
        return write_res;
    }

    free(dump);
    PrintAndLogEx(SUCCESS, "Done!");
    return PM3_SUCCESS;
}

static int CmdLegicClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic clone",
                  "Rewrite a LEGIC dump for a new target tag or MCC.\n"
                  "Use --mcc to rewrite only the dump obfuscation, or --write to clone to the current tag.",
                  "hf legic clone -f src.bin -c 39 -o clone.bin\n"
                  "hf legic clone -f src.bin --write\n"
                  "hf legic clone -f src.bin --write -o clone.bin");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Source dump file"),
        arg_str0(NULL, "mcc", "<hex>", "Target MCC byte for output-only cloning"),
        arg_str0("o", "output", "<fn>", "Output cloned dump file"),
        arg_lit0("w", "write", "Write cloned dump to the currently attached tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool write_to_tag = arg_get_lit(ctx, 4);

    int outlen = 0;
    char outfilename[FILE_PATH_SIZE] = {0};
    if (!write_to_tag && arg_get_str(ctx, 3) != NULL) {
        CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)outfilename, FILE_PATH_SIZE, &outlen);
        if (outlen < 1) {
            PrintAndLogEx(WARNING, "Output filename is invalid");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    int mcc_len = 0;
    uint8_t mcc_buf[1] = {0};
    bool has_mcc = false;
    if (!write_to_tag && arg_get_str(ctx, 2) != NULL) {
        CLIParamStrToBuf(arg_get_str(ctx, 2), mcc_buf, sizeof(mcc_buf), &mcc_len);
        has_mcc = (mcc_len == 1);
        if (!has_mcc) {
            PrintAndLogEx(WARNING, "Target MCC must be exactly one byte");
            return PM3_EINVARG;
        }
    }

    CLIParserFree(ctx);

    if (fnlen < 1) {
        PrintAndLogEx(WARNING, "Source dump file is required");
        return PM3_EINVARG;
    }

    if (write_to_tag && has_mcc) {
        PrintAndLogEx(WARNING, "Use either --mcc or --write, not both");
        return PM3_EINVARG;
    }

    if (!write_to_tag && !has_mcc) {
        PrintAndLogEx(WARNING, "Either --mcc or --write is required");
        return PM3_EINVARG;
    }

    if (!write_to_tag && outlen < 1) {
        PrintAndLogEx(WARNING, "Output file is required when using --mcc");
        return PM3_EINVARG;
    }

    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, LEGIC_PRIME_MIM1024);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (bytes_read <= 22) {
        PrintAndLogEx(WARNING, "Dump is too small to clone");
        free(dump);
        return PM3_EFILE;
    }

    if (legic_xor(dump, bytes_read) == false) {
        PrintAndLogEx(FAILED, "Failed to decode source dump");
        free(dump);
        return PM3_EFAILED;
    }

    uint8_t target_uid[4] = {0};
    uint8_t target_mcc = 0;

    if (write_to_tag) {
        legic_card_select_t card;
        if (legic_get_type(&card) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Failed to identify tagtype");
            free(dump);
            return PM3_ESOFT;
        }

        legic_print_type(card.cardsize, 0);
        if (card.cardsize != bytes_read) {
            PrintAndLogEx(WARNING, "Fail, filesize and cardsize is not equal. [%u != %zu]", card.cardsize, bytes_read);
            free(dump);
            return PM3_EFILE;
        }

        memcpy(target_uid, card.uid, sizeof(target_uid));
        target_mcc = (uint8_t)CRC8Legic(target_uid, sizeof(target_uid));
        legic_clone_update_segment_crcs(dump, bytes_read, target_uid);
        memcpy(dump, target_uid, sizeof(target_uid));
        dump[4] = target_mcc;
    } else {
        target_mcc = mcc_buf[0];
        dump[4] = target_mcc;
    }

    legic_xor_with_crc(dump, bytes_read, dump[4]);

    if (outlen > 0) {
        PrintAndLogEx(SUCCESS, "Saving cloned dump to %s", outfilename);
        pm3_save_dump(outfilename, dump, bytes_read, jsfLegic_v2);
    } else if (write_to_tag) {
        char auto_filename[FILE_PATH_SIZE] = {0};
        strcat(auto_filename, "hf-legic-");
        FillFileNameByUID(auto_filename, dump, "-dump", 4);
        PrintAndLogEx(SUCCESS, "Saving cloned dump to %s", auto_filename);
        pm3_save_dump(auto_filename, dump, bytes_read, jsfLegic_v2);
    }

    if (write_to_tag) {
        int write_res = legic_write_dump_to_tag(dump, bytes_read);
        free(dump);
        if (write_res != PM3_SUCCESS) {
            return write_res;
        }
        PrintAndLogEx(SUCCESS, "Done!");
        return PM3_SUCCESS;
    }

    free(dump);
    PrintAndLogEx(SUCCESS, "Done!");
    return PM3_SUCCESS;
}

static int CmdLegicELoad(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic eload",
                  "Loads a LEGIC Prime dump file into emulator memory",
                  "hf legic eload -f myfile\n"
                  "hf legic eload -f myfile --obfuscate\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Filename to load"),
        arg_lit0(NULL, "obfuscate", "Obfuscate dump data (xor with MCC)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool shall_obsfuscate = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, LEGIC_PRIME_MIM1024);
    if (res != PM3_SUCCESS) {
        return res;
    }

    // validation
    if (bytes_read != LEGIC_PRIME_MIM22 &&
            bytes_read != LEGIC_PRIME_MIM256 &&
            bytes_read != LEGIC_PRIME_MIM1024) {
        PrintAndLogEx(ERR, "File content error. Read %zu bytes", bytes_read);
        free(dump);
        return PM3_EFILE;
    }

    if (shall_obsfuscate) {
        legic_xor(dump, bytes_read);
    }

    legic_seteml(dump, 0, bytes_read);

    free(dump);

    PrintAndLogEx(HINT, "Hint: You are ready to simulate. See `" _YELLOW_("hf legic sim -h") "`");
    PrintAndLogEx(SUCCESS, "Done!");
    return PM3_SUCCESS;
}

static int CmdLegicESave(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic esave",
                  "Saves a (bin/json) dump file of emulator memory",
                  "hf legic esave                    --> uses UID as filename\n"
                  "hf legic esave -f myfile --22\n"
                  "hf legic esave -f myfile --22 --de\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "Filename to save"),
        arg_lit0(NULL, "22", "LEGIC Prime MIM22"),
        arg_lit0(NULL, "256", "LEGIC Prime MIM256 (def)"),
        arg_lit0(NULL, "1024", "LEGIC Prime MIM1024"),
        arg_lit0(NULL, "de", "De-obfuscate dump data (xor with MCC)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool m1 = arg_get_lit(ctx, 2);
    bool m2 = arg_get_lit(ctx, 3);
    bool m3 = arg_get_lit(ctx, 4);
    bool shall_deobsfuscate = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    // validations
    if (m1 + m2 + m3 > 1) {
        PrintAndLogEx(WARNING, "Only specify one LEGIC Prime Type");
        return PM3_EINVARG;
    } else if (m1 + m2 + m3 == 0) {
        m2 = true;
    }

    size_t numofbytes = LEGIC_PRIME_MIM256;
    if (m1)
        numofbytes = LEGIC_PRIME_MIM22;
    else if (m2)
        numofbytes = LEGIC_PRIME_MIM256;
    else if (m3)
        numofbytes = LEGIC_PRIME_MIM1024;

    // set up buffer
    uint8_t *data = calloc(numofbytes, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    // download emulator memory
    PrintAndLogEx(SUCCESS, "Reading emulator memory...");
    if (GetFromDevice(BIG_BUF_EML, data, numofbytes, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(data);
        return PM3_ETIMEOUT;
    }

    // user supplied filename?
    if (fnlen < 1) {
        PrintAndLogEx(INFO, "Using UID as filename");
        strcat(filename, "hf-legic-");
        FillFileNameByUID(filename, data, "-dump", 4);
    }

    if (shall_deobsfuscate) {
        legic_xor(data, numofbytes);
    }

    pm3_save_dump(filename, data, numofbytes, jsfLegic_v2);
    return PM3_SUCCESS;
}

static int CmdLegicEView(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic eview",
                  "It displays emulator memory",
                  "hf legic eview\n"
                  "hf legic eview --22\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "22", "LEGIC Prime MIM22"),
        arg_lit0(NULL, "256", "LEGIC Prime MIM256 (def)"),
        arg_lit0(NULL, "1024", "LEGIC Prime MIM1024"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool m1 = arg_get_lit(ctx, 1);
    bool m2 = arg_get_lit(ctx, 2);
    bool m3 = arg_get_lit(ctx, 3);
    bool verbose = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    // validations
    if (m1 + m2 + m3 > 1) {
        PrintAndLogEx(WARNING, "Only specify one LEGIC Prime Type");
        return PM3_EINVARG;
    } else if (m1 + m2 + m3 == 0) {
        m2 = true;
    }

    size_t bytes = LEGIC_PRIME_MIM256;
    if (m1)
        bytes = LEGIC_PRIME_MIM22;
    else if (m2)
        bytes = LEGIC_PRIME_MIM256;
    else if (m3)
        bytes = LEGIC_PRIME_MIM1024;

    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "downloading emulator memory");
    if (GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return PM3_ETIMEOUT;
    }

    if (verbose) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "## |  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F | ascii");
        PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");
        print_hex_break(dump, bytes, 16);
    }

    PrintAndLogEx(NORMAL, "");
    decode_and_print_memory(bytes, dump);

    free(dump);
    return PM3_SUCCESS;
}

static int CmdLegicEInfo(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic einfo",
                  "It decodes and displays emulator memory",
                  "hf legic einfo\n"
                  "hf legic eview --22\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "22", "LEGIC Prime MIM22"),
        arg_lit0(NULL, "256", "LEGIC Prime MIM256 (def)"),
        arg_lit0(NULL, "1024", "LEGIC Prime MIM1024"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool m1 = arg_get_lit(ctx, 1);
    bool m2 = arg_get_lit(ctx, 2);
    bool m3 = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    // validations
    if (m1 + m2 + m3 > 1) {
        PrintAndLogEx(WARNING, "Only specify one LEGIC Prime Type");
        return PM3_EINVARG;
    } else if (m1 + m2 + m3 == 0) {
        m2 = true;
    }

    size_t card_size = LEGIC_PRIME_MIM256;
    if (m1)
        card_size = LEGIC_PRIME_MIM22;
    else if (m2)
        card_size = LEGIC_PRIME_MIM256;
    else if (m3)
        card_size = LEGIC_PRIME_MIM1024;

    uint8_t *dump = calloc(card_size, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "downloading emulator memory");
    if (GetFromDevice(BIG_BUF_EML, dump, card_size, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return PM3_ETIMEOUT;
    }

    decode_and_print_memory(card_size, dump);

    free(dump);
    return PM3_SUCCESS;
}

static int CmdLegicWipe(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic wipe",
                  "Fills a LEGIC Prime tags memory with zeros. From byte7 and to the end\n"
                  "It autodetects card type",
                  "hf legic wipe");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // tagtype
    legic_card_select_t card;
    if (legic_get_type(&card) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed to identify tagtype");
        return PM3_ESOFT;
    }

    // set up buffer
    uint8_t *data = calloc(card.cardsize, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    legic_print_type(card.cardsize, 0);

    PrintAndLogEx(SUCCESS, "Erasing");
    // fast push mode
    g_conn.block_after_ACK = true;

    // transfer to device
    PacketResponseNG resp;
    for (size_t i = 7; i < card.cardsize; i += LEGIC_PACKET_SIZE) {

        PrintAndLogEx(NORMAL, "." NOLF);

        size_t len = MIN((card.cardsize - i), LEGIC_PACKET_SIZE);
        if (len == card.cardsize - i) {
            // Disable fast mode on last packet
            g_conn.block_after_ACK = false;
        }

        legic_packet_t *payload = calloc(1, sizeof(legic_packet_t) + len);
        if (payload == NULL) {
            PrintAndLogEx(WARNING, "Failed to allocate memory");
            free(data);
            return PM3_EMALLOC;
        }
        payload->offset = i;
        payload->iv = 0x55;
        payload->len = len;
        memcpy(payload->data, data + i, len);

        clearCommandBuffer();
        SendCommandNG(CMD_HF_LEGIC_WRITER, (uint8_t *)payload, sizeof(legic_packet_t) + len);
        free(payload);

        uint8_t timeout = 0;
        while (WaitForResponseTimeout(CMD_HF_LEGIC_WRITER, &resp, 2000) == false) {
            ++timeout;
            PrintAndLogEx(NORMAL, "." NOLF);
            if (timeout > 10) {
                PrintAndLogEx(WARNING, "\ncommand execution time out");
                free(data);
                return PM3_ETIMEOUT;
            }
        }
        PrintAndLogEx(NORMAL, "");

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "failed writing tag");
            free(data);
            return PM3_ERFTRANS;
        }
    }
    PrintAndLogEx(SUCCESS, "Done!\n");
    free(data);
    return PM3_SUCCESS;
}

static int CmdLegicList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf legic", "legic");
}

static int CmdLegicView(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic view",
                  "Print a LEGIC Prime dump file (bin/eml/json)",
                  "hf legic view -f hf-legic-01020304-dump.bin"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, LEGIC_PRIME_MIM1024);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (verbose) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "## |  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F | ascii");
        PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");
        print_hex_break(dump, bytes_read, 16);
    }

    PrintAndLogEx(NORMAL, "");
    decode_and_print_memory(bytes_read, dump);
    free(dump);
    return PM3_SUCCESS;
}

static command_t CommandTable[] =  {
    {"-----------", CmdHelp,      AlwaysAvailable, "--------------------- " _CYAN_("operations") " ---------------------"},
    {"help",    CmdHelp,          AlwaysAvailable, "This help"},
    {"dump",    CmdLegicDump,     IfPm3Legicrf,    "Dump LEGIC Prime tag to binary file"},
    {"info",    CmdLegicInfo,     IfPm3Legicrf,    "Display deobfuscated and decoded LEGIC Prime tag data"},
    {"list",    CmdLegicList,     AlwaysAvailable, "List LEGIC history"},
    {"rdbl",    CmdLegicRdbl,     IfPm3Legicrf,    "Read bytes from a LEGIC Prime tag"},
    {"reader",  CmdLegicReader,   IfPm3Legicrf,    "LEGIC Prime Reader UID and tag info"},
    {"restore", CmdLegicRestore,  IfPm3Legicrf,    "Restore an exact dump back onto the same LEGIC Prime card family"},
    {"clone",   CmdLegicClone,    IfPm3Legicrf,    "Clone a LEGIC Prime dump to a new MCC or different tag"},
    {"migrate", CmdLegicMigrate,  IfPm3Legicrf,    "Clone a LEGIC Prime dump to a tag; DCF stays opt-in"},
    {"wipe",    CmdLegicWipe,     IfPm3Legicrf,    "Wipe a LEGIC Prime tag"},
    {"wrbl",    CmdLegicWrbl,     IfPm3Legicrf,    "Write data to a LEGIC Prime tag"},
    {"-----------", CmdHelp,      AlwaysAvailable, "--------------------- " _CYAN_("simulation") " ---------------------"},
    {"sim",     CmdLegicSim,      IfPm3Legicrf,    "Start tag simulator"},
    {"eload",   CmdLegicELoad,    IfPm3Legicrf,    "Upload file into emulator memory"},
    {"esave",   CmdLegicESave,    IfPm3Legicrf,    "Save emulator memory to file"},
    {"eview",   CmdLegicEView,    IfPm3Legicrf,    "View emulator memory"},
    {"einfo",   CmdLegicEInfo,    IfPm3Legicrf,    "Display deobfuscated and decoded emulator memory"},
    {"-----------", CmdHelp,      AlwaysAvailable, "--------------------- " _CYAN_("utils") " ---------------------"},
    {"crc",     CmdLegicCalcCrc,  AlwaysAvailable, "Calculate Legic CRC over given bytes"},
    {"view",    CmdLegicView,     AlwaysAvailable, "Display deobfuscated and decoded content from tag dump file"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFLegic(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int readLegicUid(bool loop, bool verbose) {

    do {
        legic_card_select_t card;

        int resp = legic_get_type(&card);

        if (loop) {
            if (resp != PM3_SUCCESS) {
                continue;
            }
        } else {
            switch (resp) {
                case PM3_EINVARG:
                    return PM3_EINVARG;
                case PM3_ETIMEOUT:
                    if (verbose) PrintAndLogEx(WARNING, "command execution time out");
                    return PM3_ETIMEOUT;
                case PM3_ESOFT:
                    if (verbose) PrintAndLogEx(WARNING, "legic card select failed");
                    return PM3_ESOFT;
                default:
                    break;
            }
        }

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, " MCD: " _GREEN_("%02X"), card.uid[0]);
        PrintAndLogEx(SUCCESS, " MSN: " _GREEN_("%s"), sprint_hex(card.uid + 1, sizeof(card.uid) - 1));
        legic_print_type(card.cardsize, 0);

    } while (loop && (kbd_enter_pressed() == false));

    return PM3_SUCCESS;
}
