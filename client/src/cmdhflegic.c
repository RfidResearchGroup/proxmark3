//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Legic commands
//-----------------------------------------------------------------------------
#include "cmdhflegic.h"

#include <stdio.h> // for Mingw readline
#include <ctype.h> // tolower

#ifdef HAVE_READLINE
#include <readline/readline.h>
#endif

#include "cliparser.h"
#include "cmdparser.h"    // command_t
#include "comms.h"        // clearCommandBuffer
#include "cmdtrace.h"
#include "crc.h"
#include "crc16.h"
#include "fileutils.h"  //saveFile

static int CmdHelp(const char *Cmd);

#define MAX_LENGTH 1024

static bool legic_xor(uint8_t *data, uint16_t cardsize) {

    if (cardsize <= 22) {
        PrintAndLogEx(INFO, "No obsfuscation such small dump");
        return false;
    }

    uint8_t crc = data[4];
    uint32_t calc_crc = CRC8Legic(data, 4);
    if (crc != calc_crc) {
        PrintAndLogEx(INFO, "Crc mismatch, obsfuscation not possible");
        return false;
    }


    for (uint16_t i = 22; i < cardsize; i++) {
        data[i] ^= crc;
    }
    PrintAndLogEx(SUCCESS, "(De)Obsfuscation done");
    return true;
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
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    int i = 0, k = 0, segmentNum = 0, segment_len = 0, segment_flag = 0;
    int crc = 0, wrp = 0, wrc = 0;
    uint8_t stamp_len = 0;
    uint16_t datalen = 0;
    char token_type[6] = {0, 0, 0, 0, 0, 0};
    int dcf = 0;
    int bIsSegmented = 0;

    // tagtype
    legic_card_select_t card;
    if (legic_get_type(&card) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed to identify tagtype");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Reading full tag memory of " _YELLOW_("%d") " bytes...", card.cardsize);

    // allocate receiver buffer
    uint8_t *data = calloc(card.cardsize, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Cannot allocate memory");
        return PM3_EMALLOC;
    }

    int status = legic_read_mem(0, card.cardsize, 0x55, data, &datalen);
    if (status != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed reading memory");
        free(data);
        return status;
    }

    // Output CDF System area (9 bytes) plus remaining header area (12 bytes)
    crc = data[4];
    uint32_t calc_crc = CRC8Legic(data, 4);

    PrintAndLogEx(SUCCESS, " " _CYAN_("CDF: System Area"));
    PrintAndLogEx(NORMAL, "------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "MCD: " _GREEN_("%02X") " MSN: " _GREEN_("%s") " MCC: " _GREEN_("%02X") " (%s)",
                  data[0],
                  sprint_hex(data + 1, 3),
                  data[4],
                  (calc_crc == crc) ? _GREEN_("OK") : _RED_("Fail")
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

        if (data[6] == 0xec) {
            strncpy(token_type, "XAM", sizeof(token_type) - 1);
            fl = 1;
            stamp_len = 0x0c - (data[5] >> 4);
        } else {
            switch (data[5] & 0x7f) {
                case 0x00 ... 0x2f:
                    strncpy(token_type, "IAM", sizeof(token_type) - 1);
                    fl = (0x2f - (data[5] & 0x7f)) + 1;
                    break;
                case 0x30 ... 0x6f:
                    strncpy(token_type, "SAM", sizeof(token_type) - 1);
                    fl = (0x6f - (data[5] & 0x7f)) + 1;
                    break;
                case 0x70 ... 0x7f:
                    strncpy(token_type, "GAM", sizeof(token_type) - 1);
                    fl = (0x7f - (data[5] & 0x7f)) + 1;
                    break;
            }

            stamp_len = 0xfc - data[6];
        }

        PrintAndLogEx(SUCCESS, "DCF: %d (%02x %02x), Token Type=" _YELLOW_("%s") " (OLE=%01u), OL=%02u, FL=%02u",
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

        PrintAndLogEx(SUCCESS, "DCF: %d (%02x %02x), Token Type = %s (OLE = %01u)",
                      dcf,
                      data[5],
                      data[6],
                      token_type,
                      (data[5] & 0x80) >> 7
                     );
    }

    // Makes no sence to show this on blank media...
    if (dcf != 0xFFFF) {

        if (bIsSegmented) {
            PrintAndLogEx(SUCCESS, "WRP = %02u, WRC = %01u, RD = %01u, SSC = %02X",
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
    PrintAndLogEx(NORMAL, "------------------------------------------------------");

    uint8_t segCrcBytes[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t segCalcCRC = 0;
    uint32_t segCRC = 0;

    // Not Data card?
    if (dcf > 60000)
        goto out;

    PrintAndLogEx(SUCCESS, _CYAN_("ADF: User Area"));
    PrintAndLogEx(NORMAL, "------------------------------------------------------");

    if (bIsSegmented) {

        // Data start point on segmented cards
        i = 22;

        // decode segments
        for (segmentNum = 1; segmentNum < 128; segmentNum++) {
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

            PrintAndLogEx(SUCCESS, "Segment     | " _YELLOW_("%02u"), segmentNum);
            PrintAndLogEx(SUCCESS, "raw header  | 0x%02X 0x%02X 0x%02X 0x%02X",
                          data[i] ^ crc,
                          data[i + 1] ^ crc,
                          data[i + 2] ^ crc,
                          data[i + 3] ^ crc
                         );
            PrintAndLogEx(SUCCESS, "Segment len | %u,  Flag: 0x%X (valid:%01u, last:%01u)",
                          segment_len,
                          segment_flag,
                          (segment_flag & 0x4) >> 2,
                          (segment_flag & 0x8) >> 3
                         );
            PrintAndLogEx(SUCCESS, "            | WRP: %02u, WRC: %02u, RD: %01u, CRC: 0x%02X (%s)",
                          wrp,
                          wrc,
                          ((data[i + 3] ^ crc) & 0x80) >> 7,
                          segCRC,
                          (segCRC == segCalcCRC) ? _GREEN_("OK") : _RED_("Fail")
                         );

            i += 5;

            if (hasWRC) {
                PrintAndLogEx(SUCCESS, "\nWRC protected area:   (I %d | K %d| WRC %d)", i, k, wrc);
                PrintAndLogEx(NORMAL, "\nrow  | data");
                PrintAndLogEx(NORMAL, "-----+------------------------------------------------");

                for (k = i; k < (i + wrc); ++k)
                    data[k] ^= crc;

                print_hex_break(data + i, wrc, 16);
                PrintAndLogEx(NORMAL, "-----+------------------------------------------------\n");
                i += wrc;
            }

            if (hasWRP) {
                PrintAndLogEx(SUCCESS, "Remaining write protected area:  (I %d | K %d | WRC %d | WRP %d  WRP_LEN %d)", i, k, wrc, wrp, wrp_len);
                PrintAndLogEx(NORMAL, "\nrow  | data");
                PrintAndLogEx(NORMAL, "-----+------------------------------------------------");

                for (k = i; k < (i + wrp_len); ++k)
                    data[k] ^= crc;

                print_hex_break(data + i, wrp_len, 16);
                PrintAndLogEx(NORMAL, "-----+------------------------------------------------\n");
                i += wrp_len;

                // does this one work? (Answer: Only if KGH/BGH is used with BCD encoded card number! So maybe this will show just garbage...)
                if (wrp_len == 8) {
                    PrintAndLogEx(SUCCESS, "Card ID: " _YELLOW_("%2X%02X%02X"),
                                  data[i - 4] ^ crc,
                                  data[i - 3] ^ crc,
                                  data[i - 2] ^ crc
                                 );
                }
            }
            if (remain_seg_payload_len > 0) {
                PrintAndLogEx(SUCCESS, "Remaining segment payload:  (I %d | K %d | Remain LEN %d)", i, k, remain_seg_payload_len);
                PrintAndLogEx(NORMAL, "\nrow  | data");
                PrintAndLogEx(NORMAL, "-----+------------------------------------------------");

                for (k = i; k < (i + remain_seg_payload_len); ++k)
                    data[k] ^= crc;

                print_hex_break(data + i, remain_seg_payload_len, 16);
                PrintAndLogEx(NORMAL, "-----+------------------------------------------------\n");
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
        int remain_seg_payload_len = (card.cardsize - 22 - wrp);

        PrintAndLogEx(SUCCESS, "Unsegmented card - WRP: %02u, WRC: %02u, RD: %01u",
                      wrp,
                      wrc,
                      (data[7] & 0x80) >> 7
                     );

        if (hasWRC) {
            PrintAndLogEx(SUCCESS, "WRC protected area:   (I %d | WRC %d)", i, wrc);
            PrintAndLogEx(NORMAL, "\nrow  | data");
            PrintAndLogEx(NORMAL, "-----+------------------------------------------------");
            print_hex_break(data + i, wrc, 16);
            PrintAndLogEx(NORMAL, "-----+------------------------------------------------\n");
            i += wrc;
        }

        if (hasWRP) {
            PrintAndLogEx(SUCCESS, "Remaining write protected area:  (I %d | WRC %d | WRP %d | WRP_LEN %d)", i, wrc, wrp, wrp_len);
            PrintAndLogEx(NORMAL, "\nrow  | data");
            PrintAndLogEx(NORMAL, "-----+------------------------------------------------");
            print_hex_break(data + i, wrp_len, 16);
            PrintAndLogEx(NORMAL, "-----+------------------------------------------------\n");
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
            PrintAndLogEx(SUCCESS, "Remaining segment payload:  (I %d | Remain LEN %d)", i, remain_seg_payload_len);
            PrintAndLogEx(NORMAL, "\nrow  | data");
            PrintAndLogEx(NORMAL, "-----+------------------------------------------------");
            print_hex_break(data + i, remain_seg_payload_len, 16);
            PrintAndLogEx(NORMAL, "-----+------------------------------------------------\n");
        }
    }

out:
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
                  "hf legic rdbl -o 0 -l 16  <- reads from byte[0] 16 bytes(system header)\n"
                  "hf legic rdbl -o 0 -l 4 --iv 55  <- reads from byte[0] 4 bytes with IV 0x55\n"
                  "hf legic rdbl -o 0 -l 256 --iv 55  <- reads from byte[0] 256 bytes with IV 0x55");

    void *argtable[] = {
        arg_param_begin,
        arg_int1("o", "offset", "<dec>", "offset in data array to start download from"),
        arg_int1("l", "length", "<dec>", "number of bytes to read"),
        arg_str0(NULL, "iv", "<hex>", "Initialization vector to use. Must be odd and 7bits max"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int offset = arg_get_int_def(ctx, 1, 0);

    int len = arg_get_int_def(ctx, 2, 0);

    int iv_len = 0;
    uint8_t iv[1] = {0x01};  // formerly uidcrc

    CLIGetHexWithReturn(ctx, 3, iv, &iv_len);

    CLIParserFree(ctx);

    // sanity checks
    if (len + offset >= MAX_LENGTH) {
        PrintAndLogEx(WARNING, "Out-of-bounds, Cardsize = %d, [offset+len = %d ]", MAX_LENGTH, len + offset);
        return PM3_EOUTOFBOUND;
    }

    PrintAndLogEx(SUCCESS, "Reading %d bytes, from offset %d", len, offset);

    // allocate receiver buffer
    uint8_t *data = calloc(len, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Cannot allocate memory");
        return PM3_EMALLOC;
    }

    uint16_t datalen = 0;
    int status = legic_read_mem(offset, len, iv[0], data, &datalen);
    if (status == PM3_SUCCESS) {
        PrintAndLogEx(NORMAL, " ##  |  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F");
        PrintAndLogEx(NORMAL, "-----+------------------------------------------------------------------------------------------------");
        print_hex_break(data, datalen, 32);
    }
    free(data);
    return status;
}

static int CmdLegicSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic sim",
                  "Simulates a LEGIC Prime tag. MIM22, MIM256, MIM1024 types can be emulated",
                  "hf legic sim -t 0  <- Simulate Type MIM22\n"
                  "hf legic sim -t 1  <- Simulate Type MIM256 (default)\n"
                  "hf legic sim -t 2  <- Simulate Type MIM1024");

    void *argtable[] = {
        arg_param_begin,
        arg_int0("t", "type", "<dec>", "Tag type to simulate."),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct {
        uint8_t tagtype;
        bool send_reply;
    } PACKED payload;

    payload.send_reply = true;
    payload.tagtype = arg_get_int_def(ctx, 1, 1);

    CLIParserFree(ctx);

    if (payload.tagtype > 2) {
        PrintAndLogEx(ERR, "Invalid tag type selected.");
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_LEGIC_SIMULATE, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;

    PrintAndLogEx(INFO, "Press pm3-button to abort simulation");
    bool keypress = kbd_enter_pressed();
    while (keypress == false) {
        keypress = kbd_enter_pressed();

        if (WaitForResponseTimeout(CMD_HF_LEGIC_SIMULATE, &resp, 1500)) {
            break;
        }

    }
    if (keypress)
        SendCommandNG(CMD_BREAK_LOOP, NULL, 0);

    PrintAndLogEx(INFO, "Done");
    return PM3_SUCCESS;
}

static int CmdLegicWrbl(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic wrbl",
                  "Write data to a LEGIC Prime tag. It autodetects tagsize to ensure proper write",
                  "hf legic wrbl -o 0 -d 11223344  <- Write 0x11223344 starting from offset 0)\n"
                  "hf legic wrbl -o 10 -d DEADBEEF  <- Write 0xdeadbeef starting from offset 10");

    void *argtable[] = {
        arg_param_begin,
        arg_int1("o", "offset", "<dec>", "offset in data array to start writing"),
        arg_str1("d", "data", "<hex>", "data to write"),
        arg_lit0(NULL, "danger", "Auto-confirm dangerous operations"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int offset = arg_get_int_def(ctx, 1, 0);

    int data_len = 0;
    uint8_t data[MAX_LENGTH] = {0};

    CLIGetHexWithReturn(ctx, 2, data, &data_len);

    bool autoconfirm = arg_get_lit(ctx, 3);

    CLIParserFree(ctx);

    uint32_t IV = 0x55;

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

    if (data_len + offset > card.cardsize) {
        PrintAndLogEx(WARNING, "Out-of-bounds, Cardsize = %d, [offset+len = %d ]", card.cardsize, data_len + offset);
        return PM3_EOUTOFBOUND;
    }

    if ((offset == 5 || offset == 6) && (! autoconfirm)) {
        PrintAndLogEx(NORMAL, "############# DANGER ################");
        PrintAndLogEx(NORMAL, "# changing the DCF is irreversible  #");
        PrintAndLogEx(NORMAL, "#####################################");
        const char *confirm = "Do you really want to continue? y(es)/n(o) : ";
        bool overwrite = false;
#ifdef HAVE_READLINE
        char *answer = readline(confirm);
        overwrite = (answer[0] == 'y' || answer[0] == 'Y');
#else
        PrintAndLogEx(NORMAL, "%s" NOLF, confirm);
        char *answer = NULL;
        size_t anslen = 0;
        if (getline(&answer, &anslen, stdin) > 0) {
            overwrite = (answer[0] == 'y' || answer[0] == 'Y');
        }
        PrintAndLogEx(NORMAL, "");
#endif
        free(answer);
        if (overwrite == false) {
            PrintAndLogEx(WARNING, "command cancelled");
            return PM3_EOPABORTED;
        }
    }

    legic_chk_iv(&IV);

    PrintAndLogEx(SUCCESS, "Writing to tag");

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandOLD(CMD_HF_LEGIC_WRITER, offset, data_len, IV, data, data_len);

    uint8_t timeout = 0;
    while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        ++timeout;
        PrintAndLogEx(NORMAL, "." NOLF);
        if (timeout > 7) {
            PrintAndLogEx(WARNING, "\ncommand execution time out");
            return PM3_ETIMEOUT;
        }
    }
    PrintAndLogEx(NORMAL, "");

    uint8_t isOK = resp.oldarg[0] & 0xFF;
    if (!isOK) {
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
                  "hf legic crc -d deadbeef1122 --mcc 9A -t 16  <- CRC Type 16");

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
            init_table(CRC_LEGIC);
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

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_LEGIC_READER, offset, len, iv, NULL, 0);
    PacketResponseNG resp;

    uint8_t timeout = 0;
    while (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)) {
        ++timeout;
        PrintAndLogEx(NORMAL,  "." NOLF);
        if (timeout > 14) {
            PrintAndLogEx(WARNING, "\ncommand execution time out");
            return PM3_ETIMEOUT;
        }
    }
    PrintAndLogEx(NORMAL, "");

    uint8_t isOK = resp.oldarg[0] & 0xFF;
    *outlen = resp.oldarg[1];
    if (!isOK) {
        PrintAndLogEx(WARNING, "Failed reading tag");
        return PM3_ESOFT;
    }

    if (*outlen != len)
        PrintAndLogEx(WARNING, "Fail, only managed to read %u bytes", *outlen);

    // copy data from device
    if (!GetFromDevice(BIG_BUF_EML, out, *outlen, 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

int legic_print_type(uint32_t tagtype, uint8_t spaces) {
    char spc[11] = "          ";
    spc[10] = 0x00;
    char *spacer = spc + (10 - spaces);

    if (tagtype == 22)
        PrintAndLogEx(SUCCESS, "%sTYPE: " _YELLOW_("MIM%d card (outdated)"), spacer, tagtype);
    else if (tagtype == 256)
        PrintAndLogEx(SUCCESS, "%sTYPE: " _YELLOW_("MIM%d card (234 bytes)"), spacer, tagtype);
    else if (tagtype == 1024)
        PrintAndLogEx(SUCCESS, "%sTYPE: " _YELLOW_("MIM%d card (1002 bytes)"), spacer, tagtype);
    else
        PrintAndLogEx(INFO, "%sTYPE: " _YELLOW_("Unknown %06x"), spacer, tagtype);
    return PM3_SUCCESS;
}
int legic_get_type(legic_card_select_t *card) {

    if (card == NULL) return PM3_EINVARG;

    clearCommandBuffer();
    SendCommandNG(CMD_HF_LEGIC_INFO, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500))
        return PM3_ETIMEOUT;

    uint8_t isOK = resp.oldarg[0] & 0xFF;
    if (!isOK)
        return PM3_ESOFT;

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
    // fast push mode
    conn.block_after_ACK = true;
    for (size_t i = offset; i < numofbytes; i += PM3_CMD_DATA_SIZE) {

        size_t len = MIN((numofbytes - i), PM3_CMD_DATA_SIZE);
        if (len == numofbytes - i) {
            // Disable fast mode on last packet
            conn.block_after_ACK = false;
        }
        clearCommandBuffer();
        SendCommandOLD(CMD_HF_LEGIC_ESET, i, len, 0, src + i, len);
    }
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
                  "Read all memory from LEGIC Prime MIM22, MIM256, MIM1024 and saves bin/eml/json dump file\n"
                  "It autodetects card type.",
                  "hf legic dump                <-- use UID as filename\n"
                  "hf legic dump -f myfile      <-- use user specified filename\n"
                  "hf legic dump --deobfuscate  <-- use UID as filename and deobfuscate data");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<filename>", "specify a filename for dump file"),
        arg_lit0(NULL, "deobfuscate", "deobfuscate dump data (xor with MCC)"),
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
    PrintAndLogEx(SUCCESS, "Reading tag memory %d b...", dumplen);

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_LEGIC_READER, 0x00, dumplen, 0x55, NULL, 0);
    PacketResponseNG resp;

    uint8_t timeout = 0;
    while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        ++timeout;
        PrintAndLogEx(NORMAL, "." NOLF);
        if (timeout > 7) {
            PrintAndLogEx(WARNING, "\ncommand execution time out");
            return PM3_ETIMEOUT;
        }
    }
    PrintAndLogEx(NORMAL, "");

    uint8_t isOK = resp.oldarg[0] & 0xFF;
    if (!isOK) {
        PrintAndLogEx(WARNING, "Failed dumping tag data");
        return PM3_ERFTRANS;
    }

    uint16_t readlen = resp.oldarg[1];
    uint8_t *data = calloc(readlen, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    if (readlen != dumplen)
        PrintAndLogEx(WARNING, "Fail, only managed to read 0x%02X bytes of 0x%02X", readlen, dumplen);

    // copy data from device
    if (!GetFromDevice(BIG_BUF_EML, data, readlen, 0, NULL, 0, NULL, 2500, false)) {
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
        // Deobfuscate the whole dump. Unused data (after the last sector) will be MCC since
        // 0x00 ^ MCC = MCC. Finding the end of used data is not part of this function.
        legic_xor(data, dumplen);
    }

    saveFile(filename, ".bin", data, readlen);
    saveFileEML(filename, data, readlen, 8);
    saveFileJSON(filename, jsfLegic, data, readlen, NULL);
    free(data);
    return PM3_SUCCESS;
}

static int CmdLegicRestore(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic restore",
                  "Reads binary file and it autodetects card type and verifies that the file has the same size\n"
                  "Then write the data back to card. All bytes except the first 7bytes [UID(4) MCC(1) DCF(2)]",
                  "hf legic restore -f myfile              <-- use user specified filename\n"
                  "hf legic restore -f myfile --obfuscate  <-- use UID as filename and deobfuscate data");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<filename>", "specify a filename to restore"),
        arg_lit0(NULL, "obfuscate", "obfuscate dump data (xor with MCC)"),
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

    // set up buffer
    uint8_t *data = calloc(card.cardsize, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    size_t numofbytes;
    if (loadFile_safe(filename, ".bin", (void **)&data, &numofbytes) != PM3_SUCCESS) {
        free(data);
        PrintAndLogEx(WARNING, "Error, reading file");
        return PM3_EFILE;
    }

    if (card.cardsize != numofbytes) {
        PrintAndLogEx(WARNING, "Fail, filesize and cardsize is not equal. [%u != %zu]", card.cardsize, numofbytes);
        free(data);
        return PM3_EFILE;
    }

    if (shall_obsfuscate) {
        legic_xor(data, card.cardsize);
    }

    PrintAndLogEx(SUCCESS, "Restoring to card");

    // fast push mode
    conn.block_after_ACK = true;

    // transfer to device
    PacketResponseNG resp;
    for (size_t i = 7; i < numofbytes; i += PM3_CMD_DATA_SIZE) {

        size_t len = MIN((numofbytes - i), PM3_CMD_DATA_SIZE);
        if (len == numofbytes - i) {
            // Disable fast mode on last packet
            conn.block_after_ACK = false;
        }
        clearCommandBuffer();
        SendCommandOLD(CMD_HF_LEGIC_WRITER, i, len, 0x55, data + i, len);

        uint8_t timeout = 0;
        while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
            ++timeout;
            PrintAndLogEx(NORMAL, "." NOLF);
            if (timeout > 7) {
                PrintAndLogEx(WARNING, "\ncommand execution time out");
                free(data);
                return PM3_ETIMEOUT;
            }
        }
        PrintAndLogEx(NORMAL, "");

        uint8_t isOK = resp.oldarg[0] & 0xFF;
        if (!isOK) {
            PrintAndLogEx(WARNING, "Failed writing tag [msg = %u]", (uint8_t)(resp.oldarg[1] & 0xFF));
            free(data);
            return PM3_ERFTRANS;
        }
        PrintAndLogEx(SUCCESS, "Wrote chunk [offset %zu | len %zu | total %zu", i, len, i + len);
    }

    free(data);
    PrintAndLogEx(SUCCESS, "Done");
    return PM3_SUCCESS;
}

static int CmdLegicELoad(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic eload",
                  "Loads a LEGIC binary dump into emulator memory",
                  "hf legic eload -f myfile -t 0  <- Simulate Type MIM22\n"
                  "hf legic eload -f myfile -t 1  <- Simulate Type MIM256 (default)\n"
                  "hf legic eload -f myfile -t 2  <- Simulate Type MIM1024");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<filename>", "Specify a filename to restore"),
        arg_int0("t", "type", "<dec>", "Tag type to simulate."),
        arg_lit0(NULL, "obfuscate", "Obfuscate dump data (xor with MCC)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    size_t numofbytes = 0;

    switch (arg_get_int_def(ctx, 2, 1)) {
        case 0:
            numofbytes = 22;
            break;
        case 1:
            numofbytes = 256;
            break;
        case 2:
            numofbytes = 1024;
            break;
        default:
            PrintAndLogEx(ERR, "Unknown tag type");
            CLIParserFree(ctx);
            return PM3_EINVARG;
    }

    bool shall_obsfuscate = arg_get_lit(ctx, 3);

    CLIParserFree(ctx);

    // set up buffer
    uint8_t *data = calloc(numofbytes, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    if (loadFile_safe(filename, ".bin", (void **)&data, &numofbytes) != PM3_SUCCESS) {
        free(data);
        PrintAndLogEx(WARNING, "Error, reading file");
        return PM3_EFILE;
    }

    if (shall_obsfuscate) {
        legic_xor(data, numofbytes);
    }

    PrintAndLogEx(SUCCESS, "Uploading to emulator memory");
    legic_seteml(data, 0, numofbytes);

    free(data);
    PrintAndLogEx(SUCCESS, "Done");
    return PM3_SUCCESS;
}

static int CmdLegicESave(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf legic esave",
                  "Saves bin/eml/json dump file of emulator memory",
                  "hf legic esave                 <- uses UID as filename\n"
                  "hf legic esave -f myfile -t 0  <- Type MIM22\n"
                  "hf legic esave -f myfile -t 1  <- Type MIM256 (default)\n"
                  "hf legic esave -f myfile -t 2  <- Type MIM1024");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<filename>", "Specify a filename to save"),
        arg_int0("t", "type", "<dec>", "Tag type"),
        arg_lit0(NULL, "deobfuscate", "De-obfuscate dump data (xor with MCC)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    size_t numofbytes = 0;

    switch (arg_get_int_def(ctx, 2, 1)) {
        case 0:
            numofbytes = 22;
            break;
        case 1:
            numofbytes = 256;
            break;
        case 2:
            numofbytes = 1024;
            break;
        default:
            PrintAndLogEx(ERR, "Unknown tag type");
            CLIParserFree(ctx);
            return PM3_EINVARG;
    }

    bool shall_deobsfuscate = arg_get_lit(ctx, 3);

    CLIParserFree(ctx);

    // set up buffer
    uint8_t *data = calloc(numofbytes, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    // download emulator memory
    PrintAndLogEx(SUCCESS, "Reading emulator memory...");
    if (!GetFromDevice(BIG_BUF_EML, data, numofbytes, 0, NULL, 0, NULL, 2500, false)) {
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

    saveFile(filename, ".bin", data, numofbytes);
    saveFileEML(filename, data, numofbytes, 8);
    saveFileJSON(filename, jsfLegic, data, numofbytes, NULL);
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
    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    legic_print_type(card.cardsize, 0);

    PrintAndLogEx(SUCCESS, "Erasing");
    // fast push mode
    conn.block_after_ACK = true;

    // transfer to device
    PacketResponseNG resp;
    for (size_t i = 7; i < card.cardsize; i += PM3_CMD_DATA_SIZE) {

        PrintAndLogEx(NORMAL, "." NOLF);

        size_t len = MIN((card.cardsize - i), PM3_CMD_DATA_SIZE);
        if (len == card.cardsize - i) {
            // Disable fast mode on last packet
            conn.block_after_ACK = false;
        }
        clearCommandBuffer();
        SendCommandOLD(CMD_HF_LEGIC_WRITER, i, len, 0x55, data + i, len);

        uint8_t timeout = 0;
        while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
            ++timeout;
            PrintAndLogEx(NORMAL, "." NOLF);
            if (timeout > 7) {
                PrintAndLogEx(WARNING, "\ncommand execution time out");
                free(data);
                return PM3_ETIMEOUT;
            }
        }
        PrintAndLogEx(NORMAL, "");

        uint8_t isOK = resp.oldarg[0] & 0xFF;
        if (!isOK) {
            PrintAndLogEx(WARNING, "Failed writing tag [msg = %u]", (uint8_t)(resp.oldarg[1] & 0xFF));
            free(data);
            return PM3_ERFTRANS;
        }
    }
    PrintAndLogEx(SUCCESS, "ok\n");
    free(data);
    return PM3_SUCCESS;
}

static int CmdLegicList(const char *Cmd) {
    char args[128] = {0};
    if (strlen(Cmd) == 0) {
        snprintf(args, sizeof(args), "-t legic");
    } else {
        strncpy(args, Cmd, sizeof(args) - 1);
    }
    return CmdTraceList(args);
}

static command_t CommandTable[] =  {
    {"help",    CmdHelp,          AlwaysAvailable, "This help"},
    {"list",    CmdLegicList,     AlwaysAvailable,    "List LEGIC history"},
    {"reader",  CmdLegicReader,   IfPm3Legicrf,    "LEGIC Prime Reader UID and tag info"},
    {"info",    CmdLegicInfo,     IfPm3Legicrf,    "Display deobfuscated and decoded LEGIC Prime tag data"},
    {"dump",    CmdLegicDump,     IfPm3Legicrf,    "Dump LEGIC Prime tag to binary file"},
    {"restore", CmdLegicRestore,  IfPm3Legicrf,    "Restore a dump file onto a LEGIC Prime tag"},
    {"rdbl",    CmdLegicRdbl,     IfPm3Legicrf,    "Read bytes from a LEGIC Prime tag"},
    {"sim",     CmdLegicSim,      IfPm3Legicrf,    "Start tag simulator"},
    {"wrbl",    CmdLegicWrbl,     IfPm3Legicrf,    "Write data to a LEGIC Prime tag"},
    {"crc",     CmdLegicCalcCrc,  AlwaysAvailable, "Calculate Legic CRC over given bytes"},
    {"eload",   CmdLegicELoad,    AlwaysAvailable,    "Load binary dump to emulator memory"},
    {"esave",   CmdLegicESave,    AlwaysAvailable,    "Save emulator memory to binary file"},
    {"wipe",    CmdLegicWipe,     IfPm3Legicrf,    "Wipe a LEGIC Prime tag"},
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

    } while (loop && kbd_enter_pressed() == false);

    return PM3_SUCCESS;
}
