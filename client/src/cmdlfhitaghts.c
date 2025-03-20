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
// Low frequency Hitag S support
//-----------------------------------------------------------------------------

#include "cmdlfhitaghts.h"
#include <ctype.h>
#include "cmdparser.h"  // command_t
#include "comms.h"
#include "cmdtrace.h"
#include "commonutil.h"
#include "hitag.h"
#include "fileutils.h"  // savefile
#include "protocols.h"  // defines
#include "cliparser.h"
#include "crc.h"
#include "graph.h"      // MAX_GRAPH_TRACE_LEN
#include "lfdemod.h"
#include "cmddata.h"    // setDemodBuff
#include "pm3_cmd.h"    // return codes
#include "hitag2/hitag2_crypto.h"
#include "util_posix.h"             // msclock

static int CmdHelp(const char *Cmd);

void annotateHitagS(char *exp, size_t size, const uint8_t *cmd, uint8_t nbits, bool is_response) {
    size_t exp_len = 0;
    uint8_t command = 0;

    if (is_response) {
        // Handle responses
        if (nbits == 32) {
            exp_len = snprintf(exp, size, "UID: [%02X%02X%02X%02X]", cmd[0], cmd[1], cmd[2], cmd[3]);
        } else if (nbits == 40) {
            exp_len = snprintf(exp, size, "Data");
        }
    } else if (nbits >= 5) {
        concatbits(&command, 0, cmd, 0, 5, false);

        if (nbits == 5) {
            concatbits(&command, 0, cmd, 0, 5, false);

            switch (command) {
                case HITAGS_UID_REQ_STD:
                    exp_len += snprintf(exp + exp_len, size - exp_len, "UID Request (Standard 00110)");
                    break;
                case HITAGS_UID_REQ_ADV1:
                    exp_len += snprintf(exp + exp_len, size - exp_len, "UID Request (Advanced 11000)");
                    break;
                case HITAGS_UID_REQ_ADV2:
                    exp_len += snprintf(exp + exp_len, size - exp_len, "UID Request (Advanced 11001)");
                    break;
                case HITAGS_UID_REQ_FADV:
                    exp_len += snprintf(exp + exp_len, size - exp_len, "UID Request (Fast Advanced 11010)");
                    break;
            }
        } else if (nbits == 4 + 8 + 8) {
            concatbits(&command, 0, cmd, 0, 4, false);

            if (command == HITAGS_READ_PAGE) {
                exp_len += snprintf(exp + exp_len, size - exp_len, "READ");
            } else if (command == HITAGS_WRITE_PAGE) {
                exp_len += snprintf(exp + exp_len, size - exp_len, "WRITE");
            } else if (command == HITAGS_READ_BLOCK) {
                exp_len += snprintf(exp + exp_len, size - exp_len, "READ_BLOCK");
            } else if (command == HITAGS_WRITE_BLOCK) {
                exp_len += snprintf(exp + exp_len, size - exp_len, "WRITE_BLOCK");
            } else if (command == HITAGS_QUIET) {
                exp_len += snprintf(exp + exp_len, size - exp_len, "QUIET");
            }
            // Hitag 1 commands
            else if (command == HITAG1_RDCPAGE) {
                exp_len += snprintf(exp + exp_len, size - exp_len, "RDCPAGE");
            } else if (command == HITAG1_RDCBLK) {
                exp_len += snprintf(exp + exp_len, size - exp_len, "RDCBLK");
            } else if (command == HITAG1_WRCPAGE) {
                exp_len += snprintf(exp + exp_len, size - exp_len, "WRCPAGE");
            } else if (command == HITAG1_WRCBLK) {
                exp_len += snprintf(exp + exp_len, size - exp_len, "WRCBLK");
            } else {
                exp_len += snprintf(exp + exp_len, size - exp_len, "Unknown (%02X)", command);
            }

            uint8_t page = 0;
            concatbits(&page, 0, cmd, 5, 8, false);
            exp_len += snprintf(exp + exp_len, size - exp_len, " Page: %d", page);
        } else if (nbits == 32 + 8) {
            concatbits(&command, 0, cmd, 0, 5, false);
            exp_len += snprintf(exp + exp_len, size - exp_len, "Data");
        } else if (nbits == 5 + 32 + 8 || nbits == 5 + 32 + 1 + 8) {
            concatbits(&command, 0, cmd, 0, 5, false);

            if (command == HITAGS_SELECT) {
                uint8_t uid[4] = {0};
                concatbits(uid, 0, cmd, 5, 32, false);
                exp_len = snprintf(exp, size, "SELECT UID: %02X%02X%02X%02X", uid[0], uid[1], uid[2], uid[3]);
            }
        }
    } else {
        exp_len = snprintf(exp, size, "Invalid command (too short)");
    }
}

static const char *hts_get_type_str(uint32_t uid) {
    // source 1: https://www.scorpio-lk.com/downloads/Tango/HITAG_Classification.pdf
    // IDE Mark
    // Each HITAG chip contains an unique Device Identifier (IDE ) so called a Serial Number.
    // Bit 7 ot 4 of the IDE serve the function of a chip type identification. Example. IDE is 2A 48 E2 16, the IDE mark is "1".

    // source 2: Hitag S product Specification Revision 3.1
    // 6.1.1 Product Identifier (PID)
    // The Product Identifier (PID) for the HITAG S Transponder IC is coded in the UID 3 Byte of the Unique Identifier (UID).
    // This enables to distinguish between different ICs of the HITAG family
    //     |      UID 3    |
    // msb | PID 1 | PID 0 | lsb
    // Condition for HITAG S: PID 1 = 0x7 – 0xF and PID 0 ≠ 0x5 – 0x6

    //uid s/n        ********
    uint8_t pid0 = NIBBLE_LOW(uid);
    uint8_t pid1 = NIBBLE_HIGH(uid);
    if (pid1 >= 0x7 && pid1 <= 0xF && pid0 != 0x5 && pid0 != 0x6) {
        switch (pid1) {
            case 1:
                return "PCF 7936";
            case 2:
                return "PCF 7946";
            case 3:
                return "PCF 7947";
            case 4:
                return "PCF 7942/44";
            case 5:
                return "PCF 7943";
            case 6:
                return "PCF 7941";
            case 7:
                return "PCF 7952";
            case 9:
                return "PCF 7945";
            default:
                return "n/a";
        }
    } else
        return "Probably not NXP Hitag S";
}

static bool hts_get_uid(uint32_t *uid) {
    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAGS_UID, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_HITAGS_UID, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return false;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - failed getting Hitag S UID");
        return false;
    }

    if (uid) {
        *uid = bytes_to_num(resp.data.asBytes, HITAG_UID_SIZE);
    }
    return true;
}

int read_hts_uid(void) {
    uint32_t uid = 0;
    if (hts_get_uid(&uid) == false) {
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "UID.... " _GREEN_("%08X"), uid);
    PrintAndLogEx(SUCCESS, "TYPE... " _GREEN_("%s"), hts_get_type_str(uid));
    return PM3_SUCCESS;
}

static int process_hitags_common_args(CLIParserContext *ctx, lf_hitag_data_t *const packet) {

    bool use_plain = false;
    bool use_82xx  = arg_get_lit(ctx, 1);

    bool use_nrar  = false;
    uint8_t nrar[HITAG_NRAR_SIZE];
    int nrar_len = 0;

    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), nrar, HITAG_NRAR_SIZE, &nrar_len);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    use_nrar = nrar_len > 0;

    bool use_crypto = arg_get_lit(ctx, 3);

    uint8_t key[HITAG_CRYPTOKEY_SIZE];
    int key_len = 0;

    res = CLIParamHexToBuf(arg_get_str(ctx, 4), key, HITAG_CRYPTOKEY_SIZE, &key_len);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (key_len != 0 && key_len != HITAG_PASSWORD_SIZE && key_len != HITAG_CRYPTOKEY_SIZE) {
        PrintAndLogEx(WARNING, "Wrong KEY len expected 0, 4 or 6, got %d", key_len);
        return PM3_EINVARG;
    }

    if (nrar_len && nrar_len != HITAG_NRAR_SIZE) {
        PrintAndLogEx(WARNING, "Wrong NR/AR len expected %d, got %d", HITAG_NRAR_SIZE, nrar_len);
        return PM3_EINVARG;
    }

    uint8_t mode = arg_get_int_def(ctx, 5, 3);

    if (mode > 3) {
        PrintAndLogEx(WARNING, "Wrong response protocol mode, expected 0, 1, 2 or 3, got %d", mode);
        return PM3_EINVARG;
    }

    // complete options
    switch (key_len) {
        case HITAG_PASSWORD_SIZE:
            use_82xx = true;
            break;
        case HITAG_CRYPTOKEY_SIZE:
            use_crypto = true;
            break;
        default:    // key_len == 0
            if (use_82xx) {
                memcpy(key, "\xBB\xDD\x33\x99", 4);
                key_len = 4;
            } else if (use_crypto) {
                memcpy(key, "ONMIKR", 6);
                key_len = 6;
            }
    }

    // check coherence
    uint8_t auth_methods = (use_plain + use_nrar + use_82xx + use_crypto);
    if (auth_methods > 1) {
        PrintAndLogEx(WARNING, "Specify only one authentication mode");
        return PM3_EINVARG;
    }

    if (auth_methods == 0) {
        use_plain = true;
    }

    memset(packet, 0, sizeof(*packet));

    if (use_plain) {
        PrintAndLogEx(INFO, "Access " _YELLOW_("Hitag S") " in Plain mode");
    } else if (use_nrar) {
        packet->cmd = HTSF_CHALLENGE;
        memcpy(packet->NrAr, nrar, sizeof(packet->NrAr));
        PrintAndLogEx(INFO, "Authenticating to " _YELLOW_("Hitag S") " in Challenge mode");
    } else if (use_82xx) {
        packet->cmd = HTSF_82xx;
        memcpy(packet->pwd, key, sizeof(packet->pwd));
        PrintAndLogEx(INFO, "Authenticating to " _YELLOW_("Hitag S") " in 82xx mode");
    } else if (use_crypto) {
        packet->cmd = HTSF_KEY;
        memcpy(packet->key, key, sizeof(packet->key));
        PrintAndLogEx(INFO, "Authenticating to " _YELLOW_("Hitag S") " in Crypto mode");
    }

    switch (mode) {
        case 0:
            packet->mode = HITAGS_UID_REQ_STD;
            break;
        case 1:
            packet->mode = HITAGS_UID_REQ_ADV1;
            break;
        case 2:
            packet->mode = HITAGS_UID_REQ_ADV2;
            break;
        default:
            packet->mode = HITAGS_UID_REQ_FADV;
            break;
    }

    return PM3_SUCCESS;
}

static void print_error(int8_t reason) {
    switch (reason) {
        case -2:
            PrintAndLogEx(FAILED, "UID Request failed!");
            break;
        case -3:
            PrintAndLogEx(FAILED, "Select UID failed!");
            break;
        case -4:
            PrintAndLogEx(FAILED, "No write access on page " _YELLOW_("64") ". not 82xx?");
            break;
        case -5:
            PrintAndLogEx(FAILED, "Write to page " _YELLOW_("64") " failed! wrong password?");
            break;
        case -6:
            PrintAndLogEx(FAILED, "Error, " _YELLOW_("AUT=1") " This tag is configured in Authentication Mode");
            break;
        case -7:
            PrintAndLogEx(FAILED, "Error, unknown function");
            break;
        case -8:
            PrintAndLogEx(FAILED, "Authenticate failed!");
            break;
        case -9:
            PrintAndLogEx(FAILED, "No write access on page");
            break;
        case -10:
            PrintAndLogEx(FAILED, "Write to page failed!");
            break;
        case -11:
            PrintAndLogEx(FAILED, "Read page failed!");
            break;
        default:
            // PM3_REASON_UNKNOWN
            PrintAndLogEx(FAILED, "Error - Hitag S failed");
    }
}

static void hitags_config_print(hitags_config_t config) {
    PrintAndLogEx(INFO, " Memory type...... " _GREEN_("%s"),
    (const char *[]) {"Hitag S 32", "Hitag S 256", "Hitag S 2048", "Unknown Hitag S/8211"}[config.MEMT]);

    PrintAndLogEx(INFO, " Authenticaion.... %s", config.auth ? _YELLOW_("Yes") : "No");

    PrintAndLogEx(INFO, " TTF coding....... %s",
    config.RES3 ? "FSK  0=RF/10 1=RF/8" : (const char *[]) {"Manchester", "Biphase"}[config.TTFC]);

    PrintAndLogEx(INFO, " TTF data rate.... %s",
    (const char *[]) {"4 kBit", "8 kBit", "2 kBit", "2 kBit and Pigeon Race Standard"}[config.TTFDR]);

    PrintAndLogEx(INFO, " TTF mode......... %s",
    (const char *[]) {
        "TTF Mode disabled (= RTF Mode)",
        "Page 4, Page 5",
        "Page 4, Page 5, Page 6, Page 7",
        "Page 4",
        "TTF Mode disabled (= RTF Mode)",
        "Page 4, Page 5, Page 6",
        "Page 4, Page 5, Page 6, Page 7, Page 8",
        "Page 4, Page 5, Page 6, Page 7, Page 8, Page 9, Page 10, Page 11",
    }[config.RES0 << 2 | config.TTFM]);

    PrintAndLogEx(INFO, " Config locked.... %s", config.LCON ? _RED_("Yes") : _GREEN_("No"));
    PrintAndLogEx(INFO, " Key/PWD locked... %s", config.LKP ? _RED_("Yes") : _GREEN_("No"));
}

static int CmdLFHitagSRead(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag hts rdbl",
                  "Read Hitag S memory.\n\n"
                  "  Crypto mode: \n"
                  "    - key format ISK high + ISK low\n"
                  "    - default key 4F4E4D494B52 (ONMIKR)\n\n"
                  "  8268/8310 password mode: \n"
                  "    - default password BBDD3399\n",
                  "  lf hitag hts rdbl -p 1                         -> Hitag S/8211, plain mode\n"
                  "  lf hitag hts rdbl -p 1 --82xx -k BBDD3399      -> 8268/8310, password mode\n"
                  "  lf hitag hts rdbl -p 1 --nrar 0102030411223344 -> Hitag S, challenge mode\n"
                  "  lf hitag hts rdbl -p 1 --crypto                -> Hitag S, crypto mode, def key\n"
                  "  lf hitag hts rdbl -p 1 -k 4F4E4D494B52         -> Hitag S, crypto mode\n\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("8", "82xx", "8268/8310 mode"),
        arg_str0(NULL, "nrar", "<hex>", "nonce / answer writer, 8 hex bytes"),
        arg_lit0(NULL, "crypto", "crypto mode"),
        arg_str0("k", "key", "<hex>", "pwd or key, 4 or 6 hex bytes"),
        arg_int0("m", "mode", "<dec>", "response protocol mode. 0 (Standard 00110), 1 (Advanced 11000), 2 (Advanced 11001), 3 (Fast Advanced 11010) (def: 3)"),
        arg_int0("p", "page", "<dec>", "page address to read from"),
        arg_int0("c", "count", "<dec>", "how many pages to read. '0' reads all pages up to the end page (def: 1)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    lf_hitag_data_t packet;

    if (process_hitags_common_args(ctx, &packet) < 0) return PM3_EINVARG;

    uint32_t page = arg_get_int_def(ctx, 6, 0);

    if (page > 255) {
        PrintAndLogEx(WARNING, "Page address Invalid.");
        return PM3_EINVARG;
    }

    uint32_t count = arg_get_int_def(ctx, 7, 1);

    if (count > HITAGS_MAX_PAGES) {
        PrintAndLogEx(WARNING, "No more than 64 pages can be read at once.");
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    packet.page = page;
    packet.page_count = count;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAGS_READ, (uint8_t *) &packet, sizeof(packet));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_HITAGS_READ, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        print_error(resp.reason);
        return PM3_ESOFT;
    }

    lf_hts_read_response_t *card = (lf_hts_read_response_t *)resp.data.asBytes;

    hitags_config_t config = card->config_page.s;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");

    hitags_config_print(config);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Data") " ---------------------------");
    PrintAndLogEx(INFO, "  # | 00 01 02 03 | ascii | perm | info");
    PrintAndLogEx(INFO, "----+-------------+-------+------+------");

    const int hts_mem_sizes[] = {1, 8, 64, 64};

    if (count == 0) {
        count = hts_mem_sizes[config.MEMT] > page ? hts_mem_sizes[config.MEMT] - page : 64;
    }

    // int page_end = page + count;
    // page_end = MIN(page_end, 255);

    for (int i = 0; i < count; ++i) {
        int page_addr = page + i;
        if (page_addr > 255) {
            break;
        }
        if (card->pages_reason[i] >= 0) {
            PrintAndLogEx(SUCCESS, "% 3u | %s  | " NOLF, page_addr, sprint_hex_ascii(card->pages[i], HITAGS_PAGE_SIZE));

            // access right
            if (page_addr == HITAGS_UID_PADR) {
                PrintAndLogEx(NORMAL, _RED_("RO  ")NOLF);
                \
            } else if (packet.cmd == HTSF_82xx && page_addr > 40) {  // using an 82xx (pages>40 are RO)
                PrintAndLogEx(NORMAL, _RED_("RO  ")NOLF);
            } else if (page_addr == HITAGS_CONFIG_PADR) {
                if (card->config_page.s.LCON)
                    PrintAndLogEx(NORMAL, _YELLOW_("OTP ")NOLF);
                else
                    PrintAndLogEx(NORMAL, _GREEN_("RW  ")NOLF);
            } else if (2 <= page_addr && page_addr <= 3) {
                if (card->config_page.s.LKP)
                    if (card->config_page.s.auth)
                        PrintAndLogEx(NORMAL, _RED_("NO  ")NOLF);
                    else
                        PrintAndLogEx(NORMAL, _RED_("RO  ")NOLF);
                else
                    PrintAndLogEx(NORMAL, _GREEN_("RW  ")NOLF);
            } else if (4 <= page_addr && page_addr <= 5) {
                if (card->config_page.s.LCK7)
                    if (card->config_page.s.TTFDR == 2 && page_addr == 5)
                        PrintAndLogEx(NORMAL, _YELLOW_("RO/W")NOLF);
                    else
                        PrintAndLogEx(NORMAL, _RED_("RO  ")NOLF);
                else
                    PrintAndLogEx(NORMAL, _GREEN_("RW  ")NOLF);
            } else if (6 <= page_addr && page_addr <= 7) {
                if (card->config_page.s.LCK6)
                    PrintAndLogEx(NORMAL, _RED_("RO  ")NOLF);
                else
                    PrintAndLogEx(NORMAL, _GREEN_("RW  ")NOLF);
            } else if (8 <= page_addr && page_addr <= 11) {
                if (card->config_page.s.LCK5)
                    PrintAndLogEx(NORMAL, _RED_("RO  ")NOLF);
                else
                    PrintAndLogEx(NORMAL, _GREEN_("RW  ")NOLF);
            } else if (12 <= page_addr && page_addr <= 15) {
                if (card->config_page.s.LCK4)
                    PrintAndLogEx(NORMAL, _RED_("RO  ")NOLF);
                else
                    PrintAndLogEx(NORMAL, _GREEN_("RW  ")NOLF);
            } else if (16 <= page_addr && page_addr <= 23) {
                if (card->config_page.s.LCK3)
                    PrintAndLogEx(NORMAL, _RED_("RO  ")NOLF);
                else
                    PrintAndLogEx(NORMAL, _GREEN_("RW  ")NOLF);
            } else if (24 <= page_addr && page_addr <= 32) {
                if (card->config_page.s.LCK2)
                    PrintAndLogEx(NORMAL, _RED_("RO  ")NOLF);
                else
                    PrintAndLogEx(NORMAL, _GREEN_("RW  ")NOLF);
            } else if (32 <= page_addr && page_addr <= 47) {
                if (card->config_page.s.LCK1)
                    PrintAndLogEx(NORMAL, _RED_("RO  ")NOLF);
                else
                    PrintAndLogEx(NORMAL, _GREEN_("RW  ")NOLF);
            } else if (48 <= page_addr && page_addr <= 63) {
                if (card->config_page.s.LCK0)
                    PrintAndLogEx(NORMAL, _RED_("RO  ")NOLF);
                else
                    PrintAndLogEx(NORMAL, _GREEN_("RW  ")NOLF);
            } else
                PrintAndLogEx(NORMAL, _YELLOW_("UNK ") NOLF);

            PrintAndLogEx(NORMAL, " | " NOLF);

            // info
            if (page_addr == HITAGS_UID_PADR) {
                PrintAndLogEx(NORMAL, "UID");
            } else if (page_addr == HITAGS_CONFIG_PADR) {
                PrintAndLogEx(NORMAL, "Config");
            } else if (page_addr == 2 && card->config_page.s.auth) {
                PrintAndLogEx(NORMAL, "Pwd/Key");
            } else if (page_addr == 3 && card->config_page.s.auth) {
                PrintAndLogEx(NORMAL, "Key");
            } else
                PrintAndLogEx(NORMAL, "Data");
        } else {
            PrintAndLogEx(INFO, "% 3u | -- -- -- -- | ....  | N/A  | " NOLF, page_addr);
            print_error(card->pages_reason[i]);
        }
    }

    PrintAndLogEx(INFO, "----+-------------+-------+------+------");
    PrintAndLogEx(INFO, " " _RED_("RO") " = Read Only, " _GREEN_("RW") " = Read Write");
    PrintAndLogEx(INFO, " " _YELLOW_("OTP") " = One Time Programmable");
    PrintAndLogEx(INFO, " " _YELLOW_("RO/W") " = Partially Read Write");
    PrintAndLogEx(INFO, "----------------------------------------");
    return PM3_SUCCESS;
}

static int CmdLFHitagSDump(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag hts dump",
                  "Read all Hitag S memory and save to file\n"
                  " Crypto mode: \n"
                  "    - key format ISK high + ISK low\n"
                  "    - default key 4F4E4D494B52 (ONMIKR)\n\n"
                  "  8268/8310 password mode: \n"
                  "    - default password BBDD3399\n",
                  "lf hitag hts dump --82xx                 -> use def pwd\n"
                  "lf hitag hts dump --82xx -k BBDD3399     -> pwd mode\n"
                  "lf hitag hts dump --crypto               -> use def crypto\n"
                  "lf hitag hts dump -k 4F4E4D494B52        -> crypto mode\n"
                  "lf hitag hts dump --nrar 0102030411223344\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("8", "82xx", "8268/8310 mode"),
        arg_str0(NULL, "nrar", "<hex>", "nonce / answer writer, 8 hex bytes"),
        arg_lit0(NULL, "crypto", "crypto mode"),
        arg_str0("k", "key", "<hex>", "pwd or key, 4 or 6 hex bytes"),
        arg_int0("m", "mode", "<dec>", "response protocol mode. 0 (Standard 00110), 1 (Advanced 11000), 2 (Advanced 11001), 3 (Fast Advanced 11010) (def: 3)"),
        arg_str0("f", "file", "<fn>", "specify file name"),
        arg_lit0(NULL, "ns", "no save to file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    lf_hitag_data_t packet;
    memset(&packet, 0, sizeof(packet));

    if (process_hitags_common_args(ctx, &packet) < 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool nosave = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    // read all pages
    packet.page = 0;
    packet.page_count = 0;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAGS_READ, (uint8_t *) &packet, sizeof(packet));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_HITAGS_READ, &resp, 5000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        print_error(resp.reason);
        return PM3_ESOFT;
    }

    lf_hts_read_response_t *card = (lf_hts_read_response_t *)resp.data.asBytes;

    const int hts_mem_sizes[] = {1, 8, 64, 64};
    int mem_size = hts_mem_sizes[card->config_page.s.MEMT] * HITAGS_PAGE_SIZE;

    hitags_config_t config = card->config_page.s;
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    hitags_config_print(config);

    if (nosave) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "Called with no save option");
        PrintAndLogEx(NORMAL, "");
        return PM3_SUCCESS;
    }

    if (fnlen < 1) {
        char *fptr = filename;
        fptr += snprintf(filename, sizeof(filename), "lf-hitags-");
        FillFileNameByUID(fptr, card->pages[HITAGS_UID_PADR], "-dump", HITAGS_PAGE_SIZE);
    }

    pm3_save_dump(filename, (uint8_t *)card->pages, mem_size, jsfHitag);

    return PM3_SUCCESS;
}

static int CmdLFHitagSRestore(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag hts restore",
                  "Restore a dump file onto Hitag S tag\n"
                  " Crypto mode: \n"
                  "    - key format ISK high + ISK low\n"
                  "    - default key 4F4E4D494B52 (ONMIKR)\n\n"
                  "  8268/8310 password mode: \n"
                  "    - default password BBDD3399\n",
                  "lf hitag hts restore -f myfile --82xx                 -> use def pwd\n"
                  "lf hitag hts restore -f myfile --82xx -k BBDD3399     -> pwd mode\n"
                  "lf hitag hts restore -f myfile --crypto               -> use def crypto\n"
                  "lf hitag hts restore -f myfile -k 4F4E4D494B52        -> crypto mode\n"
                  "lf hitag hts restore -f myfile --nrar 0102030411223344\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("8", "82xx", "8268/8310 mode"),
        arg_str0(NULL, "nrar", "<hex>", "nonce / answer writer, 8 hex bytes"),
        arg_lit0(NULL, "crypto", "crypto mode"),
        arg_str0("k", "key", "<hex>", "pwd or key, 4 or 6 hex bytes"),
        arg_int0("m", "mode", "<dec>", "response protocol mode. 0 (Standard 00110), 1 (Advanced 11000), 2 (Advanced 11001), 3 (Fast Advanced 11010) (def: 3)"),
        arg_str0("f", "file", "<fn>", "specify file name"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, false);

    lf_hitag_data_t packet;
    memset(&packet, 0, sizeof(packet));

    if (process_hitags_common_args(ctx, &packet) < 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    if (fnlen == 0) {
        PrintAndLogEx(ERR, "Must specify a file");
        return PM3_EINVARG;
    }

    // read dump file
    uint32_t *dump = NULL;
    size_t bytes_read = 0;
    if (pm3_load_dump(filename, (void **)&dump, &bytes_read, jsfHitag) != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    // read config to determine memory size and other stuff
    packet.page = HITAGS_CONFIG_PADR;
    packet.page_count = 1;


    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAGS_READ, (uint8_t *)&packet, sizeof(packet));

    PacketResponseNG resp;

    if (WaitForResponseTimeout(CMD_LF_HITAGS_READ, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        free(dump);
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        print_error(resp.reason);
        free(dump);
        return PM3_ESOFT;
    }

    lf_hts_read_response_t *config = (lf_hts_read_response_t *)resp.data.asBytes;
    hitags_config_t tag_config = config->config_page.s;

    const int hts_mem_sizes[] = {1, 8, 64, 64};
    int mem_size = hts_mem_sizes[tag_config.MEMT] * HITAGS_PAGE_SIZE;

    if (bytes_read != mem_size) {
        free(dump);
        PrintAndLogEx(FAILED, "Wrong length of dump file. Expected %d bytes, got %zu", mem_size, bytes_read);
        return PM3_EFILE;
    }

    uint8_t *dump_bytes = (uint8_t *)dump;
    bool auth_changed = false;

    for (int page = packet.page_count + 1; page < hts_mem_sizes[tag_config.MEMT]; page++) { // skip config page

        if (packet.cmd == HTSF_82xx && page > 40) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "Using " _YELLOW_("82xx") ", Pages " _YELLOW_("41-63") " will be skipped");
            PrintAndLogEx(NORMAL, "");
            break;
        }

        size_t offset = page * HITAGS_PAGE_SIZE;

        packet.page = page;
        memcpy(packet.data, &dump_bytes[offset], HITAGS_PAGE_SIZE);

        PrintAndLogEx(INPLACE, " Writing page "_YELLOW_("%d")", data: " _GREEN_("%02X %02X %02X %02X"), page,
                      dump_bytes[offset],
                      dump_bytes[offset + 1],
                      dump_bytes[offset + 2],
                      dump_bytes[offset + 3]);


        clearCommandBuffer();
        SendCommandNG(CMD_LF_HITAGS_WRITE, (uint8_t *)&packet, sizeof(packet));

        if (WaitForResponseTimeout(CMD_LF_HITAGS_WRITE, &resp, 2000) == false) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply");
            free(dump);
            return PM3_ETIMEOUT;
        }

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(FAILED, "Write failed for page %d", page);
            print_error(resp.reason);
            free(dump);
            return PM3_ESOFT;
        }

        switch (page) {
            case 2: // auth first page
                if (packet.cmd == HTSF_82xx) {
                    if (memcmp(packet.pwd, &dump_bytes[offset], HITAGS_PAGE_SIZE) == 0) {
                        break;
                    }
                    auth_changed = true;

                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(WARNING, "Password Changed! Old: " _BACK_BLUE_("%02X %02X %02X %02X") ", New: "_BACK_BLUE_("%02X %02X %02X %02X"),
                                  packet.pwd[0], packet.pwd[1], packet.pwd[2], packet.pwd[3],
                                  dump_bytes[offset], dump_bytes[offset + 1],
                                  dump_bytes[offset + 2], dump_bytes[offset + 3]);


                    memcpy(packet.pwd, &dump_bytes[offset], HITAG_PASSWORD_SIZE);


                    PrintAndLogEx(SUCCESS, "Using new password for subsequent writes");
                }
                break;
            case 3:  // crypto mode
                if (packet.cmd == HTSF_KEY) {

                    if (memcmp(packet.key, &dump_bytes[offset - HITAGS_PAGE_SIZE], HITAG_CRYPTOKEY_SIZE) == 0) {
                        break;
                    }
                    auth_changed = true;

                    memcpy(packet.key, &dump_bytes[offset - HITAGS_PAGE_SIZE], HITAG_CRYPTOKEY_SIZE);

                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(WARNING, "New key detected: " _BACK_BLUE_("%02X %02X %02X %02X %02X %02X"),
                                  packet.key[0], packet.key[1], packet.key[2],
                                  packet.key[3], packet.key[4], packet.key[5]);

                    PrintAndLogEx(SUCCESS, "Using new key for subsequent writes");
                }
                break;
        }
    }

    // restore config page at end
    size_t config_offset = HITAGS_PAGE_SIZE * 1; // page 1
    packet.page = HITAGS_CONFIG_PADR;
    memcpy(packet.data, &dump_bytes[HITAGS_PAGE_SIZE], HITAGS_PAGE_SIZE);


    PrintAndLogEx(SUCCESS, "Applying "_YELLOW_("restored config: ")  _GREEN_("%02X %02X %02X %02X"),
                  dump_bytes[config_offset],
                  dump_bytes[config_offset + 1],
                  dump_bytes[config_offset + 2],
                  dump_bytes[config_offset + 3]);


    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAGS_WRITE, (uint8_t *)&packet, sizeof(packet));

    if (WaitForResponseTimeout(CMD_LF_HITAGS_WRITE, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        free(dump);
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(FAILED, "Failed to apply config");
        print_error(resp.reason);
        free(dump);
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Write process completed");

    if (auth_changed) {
        if (packet.cmd == HTSF_82xx) {
            PrintAndLogEx(SUCCESS, "New Password: " _BACK_BLUE_("%02X %02X %02X %02X"),
                          packet.pwd[0], packet.pwd[1], packet.pwd[2], packet.pwd[3]);
        } else if (packet.cmd == HTSF_KEY) {
            PrintAndLogEx(SUCCESS, "New Key: " _BACK_BLUE_("%02X %02X %02X %02X %02X %02X"),
                          packet.key[0], packet.key[1], packet.key[2],
                          packet.key[3], packet.key[4], packet.key[5]);
        }
    }

    return PM3_SUCCESS;
}

static int CmdLFHitagSWrite(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag hts wrbl",
                  "Write a page in Hitag S memory.\n"
                  "  Crypto mode: \n"
                  "    - key format ISK high + ISK low\n"
                  "    - default key 4F4E4D494B52 (ONMIKR)\n\n"
                  "  8268/8310 password mode: \n"
                  "    - default password BBDD3399\n",
                  "  lf hitag hts wrbl -p 6 -d 01020304                         -> Hitag S/8211, plain mode\n"
                  "  lf hitag hts wrbl -p 6 -d 01020304 --82xx                  -> use def pwd\n"
                  "  lf hitag hts wrbl -p 6 -d 01020304 --82xx -k BBDD3399      -> 8268/8310, password mode\n"
                  "  lf hitag hts wrbl -p 6 -d 01020304 --nrar 0102030411223344 -> Hitag S, challenge mode\n"
                  "  lf hitag hts wrbl -p 6 -d 01020304 --crypto                -> Hitag S, crypto mode, default key\n"
                  "  lf hitag hts wrbl -p 6 -d 01020304 -k 4F4E4D494B52         -> Hitag S, crypto mode\n\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("8", "82xx", "8268/8310 mode"),
        arg_str0(NULL, "nrar", "<hex>", "nonce / answer writer, 8 hex bytes"),
        arg_lit0(NULL, "crypto", "crypto mode"),
        arg_str0("k", "key", "<hex>", "pwd or key, 4 or 6 hex bytes"),
        arg_int0("m", "mode", "<dec>", "response protocol mode. 0 (Standard 00110), 1 (Advanced 11000), 2 (Advanced 11001), 3 (Fast Advanced 11010) (def: 3)"),
        arg_int1("p", "page", "<dec>", "page address to write to"),
        arg_str1("d", "data", "<hex>", "data, 4 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    lf_hitag_data_t packet;

    if (process_hitags_common_args(ctx, &packet) < 0) return PM3_EINVARG;

    int page = arg_get_int_def(ctx, 6, 0);

    uint8_t data[HITAGS_PAGE_SIZE];
    int data_len = 0;

    int res = CLIParamHexToBuf(arg_get_str(ctx, 7), data, HITAGS_PAGE_SIZE, &data_len);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    packet.page = page;
    memcpy(packet.data, data, sizeof(packet.data));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAGS_WRITE, (uint8_t *) &packet, sizeof(packet));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_HITAGS_WRITE, &resp, 4000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_ETEAROFF) {
        PrintAndLogEx(INFO, "Writing tear off triggered");
        return PM3_SUCCESS;
    }

    if (resp.status != PM3_SUCCESS) {
        print_error(resp.reason);
        return resp.status;
    }

    PrintAndLogEx(SUCCESS, "Write ( " _GREEN_("ok") " )");
    return PM3_SUCCESS;
}

static int CmdLFHitagSReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag hts reader",
                  "Act as a Hitag S reader.  Look for Hitag S tags until Enter or the pm3 button is pressed\n",
                  "lf hitag hts reader\n"
                  "lf hitag hts reader -@   -> Continuous mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    do {
        // read UID
        uint32_t uid = 0;
        if (hts_get_uid(&uid)) {
            PrintAndLogEx(SUCCESS, "UID.... " _GREEN_("%08X"), uid);
        }
    } while (cm && kbd_enter_pressed() == false);

    return PM3_SUCCESS;
}

static int CmdLFHitagSSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag hts sim",
                  "Simulate Hitag S transponder\n"
                  "You need to `lf hitag hts eload` first",
                  "lf hitag hts sim\n"
                  "lf hitag hts sim --82xx\n"
                  "lf hitag hts sim -t 30    -> set threshold to 30");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("8", "82xx", "simulate 8268/8310"),
        arg_int0("t", "threshold", "<dec>", "set edge detect threshold (def: 127)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    // bool use_82xx = arg_get_lit(ctx, 1);    // not implemented yet
    int threshold = arg_get_int_def(ctx, 2, 127);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandMIX(CMD_LF_HITAGS_SIMULATE, false, threshold, 0, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdLFHitagSList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "lf hitag hts", "hts");
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,           AlwaysAvailable, "This help"},
    {"list",        CmdLFHitagSList,   AlwaysAvailable, "List Hitag S trace history"},
    {"-----------", CmdHelp,           IfPm3Hitag,      "----------------------- " _CYAN_("General") " ------------------------"},
    {"reader",      CmdLFHitagSReader, IfPm3Hitag,      "Act like a Hitag S reader"},
    {"rdbl",        CmdLFHitagSRead,   IfPm3Hitag,      "Read Hitag S page"},
    {"dump",        CmdLFHitagSDump,   IfPm3Hitag,      "Dump Hitag S pages to a file"},
    {"restore",     CmdLFHitagSRestore, IfPm3Hitag,      "Restore Hitag S memory from dump file"},
    {"wrbl",        CmdLFHitagSWrite,  IfPm3Hitag,      "Write Hitag S page"},
    {"-----------", CmdHelp,           IfPm3Hitag,      "----------------------- " _CYAN_("Simulation") " -----------------------"},
    {"sim",         CmdLFHitagSSim,    IfPm3Hitag,      "Simulate Hitag S transponder"},
    {NULL,          NULL,              0,               NULL}
};

static int CmdHelp(const char *Cmd) {
    (void) Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFHitagS(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
