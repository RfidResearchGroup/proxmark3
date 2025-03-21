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
// Low frequency Hitag µ support
//-----------------------------------------------------------------------------
#include "cmdlfhitagu.h"

#include "cliparser.h"
#include "cmddata.h"  // setDemodBuff
#include "cmdparser.h"  // command_t
#include "cmdtrace.h"
#include "commonutil.h"
#include "comms.h"
#include "crc16.h"
#include "fileutils.h"  // savefile
#include "graph.h"      // MAX_GRAPH_TRACE_LEN
#include "hitag.h"
#include "hitag2/hitag2_crypto.h"
#include "lfdemod.h"
#include "pm3_cmd.h"     // return codes
#include "protocols.h"   // defines
#include "util_posix.h"  // msclock
#include <ctype.h>

static int CmdHelp(const char *Cmd);

uint8_t hitagu_CRC_check(uint8_t *d, uint32_t nbit) {
    if (nbit < 9) {
        return 2;
    }

    return (Crc16(d, nbit, 0, CRC16_POLY_CCITT, false, false) == 0);
}

void annotateHitagU(char *exp, size_t size, const uint8_t *cmd, uint8_t cmdsize, bool is_response) {

    if (is_response) {

    } else {
        uint8_t flag = reflect8(cmd[0]) & 0x1F;
        uint8_t command = ((reflect8(cmd[0]) >> 5) & 0x07) | ((reflect8(cmd[1]) & 0x07) << 3);
        bool has_uid = false;

        size_t exp_len = snprintf(exp, size, "Flg:");

        if ((flag & HITAGU_FLAG_PEXT) == HITAGU_FLAG_PEXT) {
            exp_len += snprintf(exp + exp_len, size - exp_len, " PEXT");
        }

        if ((flag & HITAGU_FLAG_INV) == HITAGU_FLAG_INV) {

            exp_len += snprintf(exp + exp_len, size - exp_len, " INV");

            if ((flag & HITAGU_FLAG_RFU) == HITAGU_FLAG_RFU) {
                exp_len += snprintf(exp + exp_len, size - exp_len, " RFU");
            }

            if ((flag & HITAGU_FLAG_NOS) == HITAGU_FLAG_NOS) {
                exp_len += snprintf(exp + exp_len, size - exp_len, " NOS");
            }

        } else {

            if ((flag & HITAGU_FLAG_SEL) == HITAGU_FLAG_SEL) {
                exp_len += snprintf(exp + exp_len, size - exp_len, " SEL");
            }

            if ((flag & HITAGU_FLAG_ADR) == HITAGU_FLAG_ADR) {
                exp_len += snprintf(exp + exp_len, size - exp_len, " ADR");
                has_uid = true;
            }
        }

        if ((flag & HITAGU_FLAG_CRCT) == HITAGU_FLAG_CRCT) {
            exp_len += snprintf(exp + exp_len, size - exp_len, " CRCT");
        }

        exp_len += snprintf(exp + exp_len, size - exp_len, "|Cmd: ");

        switch (command) {
            case HITAGU_CMD_LOGIN: {

                bool has_mfc = false;

                if (cmdsize == (6 + (has_uid * HITAGU_UID_SIZE)) || cmdsize == (8 + (has_uid * HITAGU_UID_SIZE))) {

                    exp_len += snprintf(exp + exp_len, size - exp_len, "8265 LOGIN");

                } else if (cmdsize == (7 + (has_uid * HITAGU_UID_SIZE)) || cmdsize == (9 + (has_uid * HITAGU_UID_SIZE))) {

                    uint8_t mfc = 0;
                    concatbits(&mfc, 0, cmd, 5 + 6 + 8 + 32, 8, false);
                    exp_len += snprintf(exp + exp_len, size - exp_len, "LOGIN mfc:%02x ", mfc);
                    has_mfc = true;
                }

                if (has_uid) {
                    uint8_t uid[HITAGU_UID_SIZE] = {0};
                    concatbits(uid, 0, cmd, 5 + 6 + has_mfc * 8 + 32, HITAGU_UID_SIZE * 8, false);
                    exp_len += snprintf(exp + exp_len, size - exp_len, " uid:%s", sprint_hex_inrow(uid, HITAGU_UID_SIZE));
                }

                uint8_t password[HITAG_PASSWORD_SIZE] = {0};
                concatbits(password, 0, cmd, 5 + 6 + has_mfc * 8 + has_uid * HITAGU_UID_SIZE * 8, HITAG_PASSWORD_SIZE * 8, false);
                exp_len += snprintf(exp + exp_len, size - exp_len, " pwd:%s", sprint_hex_inrow(password, HITAG_PASSWORD_SIZE));
                break;
            }
            case HITAGU_CMD_INVENTORY: {
                exp_len += snprintf(exp + exp_len, size - exp_len, "INVENTORY");
                break;
            }
            case HITAGU_CMD_READ_MULTIPLE_BLOCK: {
                uint8_t block_addr = 0;
                concatbits(&block_addr, 0, cmd, 5 + 6, 8, false);

                uint8_t block_count = 0;
                concatbits(&block_count, 0, cmd, 5 + 6 + 8, 8, false);

                exp_len += snprintf(exp + exp_len, size - exp_len, "READ MULTIPLE BLOCK start:%d num:%d"
                                    , reflect8(block_addr)
                                    , reflect8(block_count)
                                   );
                break;
            }
            case HITAGU_CMD_WRITE_SINGLE_BLOCK: {
                uint8_t block_addr = 0;
                concatbits(&block_addr, 0, cmd, 5 + 6, 8, false);

                uint8_t block_data[4] = {0};
                concatbits(block_data, 0, cmd, 5 + 6 + 8, 32, false);

                exp_len += snprintf(exp + exp_len, size - exp_len, "WRITE SINGLE BLOCK start:%d data:[%s]"
                                    , reflect8(block_addr)
                                    , sprint_hex_inrow(block_data, 4)
                                   );
                break;
            }
            case HITAGU_CMD_SELECT: {
                exp_len += snprintf(exp + exp_len, size - exp_len, "SELECT");
                break;
            }
            case HITAGU_CMD_SYSINFO: {
                exp_len += snprintf(exp + exp_len, size - exp_len, "GET SYSTEM INFORMATION");
                break;
            }
            case HITAGU_CMD_READ_UID: {
                exp_len += snprintf(exp + exp_len, size - exp_len, "READ UID");
                break;
            }
            case HITAGU_CMD_STAY_QUIET: {
                exp_len += snprintf(exp + exp_len, size - exp_len, "STAY QUIET");
                break;
            }
            default: {
                exp_len += snprintf(exp + exp_len, size - exp_len, "Unknown 0x%02X", command);
                break;
            }
        }
    }
}

static bool htu_get_uid(uint64_t *uid) {
    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAGU_UID, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_HITAGU_UID, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return false;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - failed getting Hitag µ UID");
        return false;
    }

    if (uid) {
        *uid = bytes_to_num(resp.data.asBytes, HITAGU_UID_SIZE);
    }
    return true;
}

int read_htu_uid(void) {
    uint64_t uid = 0;
    if (htu_get_uid(&uid) == false) {
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "UID.... " _GREEN_("%012llX"), uid);
    // PrintAndLogEx(SUCCESS, "TYPE... " _GREEN_("%s"), htu_get_type_str(uid));
    return PM3_SUCCESS;
}

static int process_hitagu_common_args(CLIParserContext *ctx, lf_hitag_data_t *const packet) {
    bool use_82xx = arg_get_lit(ctx, 1);
    bool use_password = false;
    uint8_t key[HITAG_PASSWORD_SIZE];
    int key_len = 0;

    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), key, HITAG_PASSWORD_SIZE, &key_len);
    if (res != 0) {
        return PM3_EINVARG;
    }

    if (key_len != 0 && key_len != HITAG_PASSWORD_SIZE) {
        PrintAndLogEx(WARNING, "Wrong KEY len expected 0 or 4, got %d", key_len);
        return PM3_EINVARG;
    }

    // complete options
    if (key_len == 0 && use_82xx) {
        memcpy(key, "\x00\x00\x00\x00", 4);
        key_len = 4;
    } else if (key_len != 0) {
        use_password = true;
    }

    memset(packet, 0, sizeof(*packet));

    if (use_82xx) {
        packet->cmd = HTUF_82xx;
        memcpy(packet->pwd, key, sizeof(packet->pwd));
        PrintAndLogEx(INFO, "Authenticating to " _YELLOW_("Hitag µ") " in 82xx mode");

    } else if (use_password) {
        packet->cmd = HTUF_PASSWORD;
        memcpy(packet->pwd, key, sizeof(packet->pwd));
        PrintAndLogEx(INFO, "Authenticating to " _YELLOW_("Hitag µ") " in password mode");

    } else {
        packet->cmd = HTUF_PLAIN;
        memcpy(packet->pwd, key, sizeof(packet->pwd));
        PrintAndLogEx(INFO, "Access " _YELLOW_("Hitag µ") " in Plain mode");
    }

    return PM3_SUCCESS;
}

static void print_error(int8_t reason) {

    //todo:  USE ENUM OR DEFINES
    switch (reason) {
        case 0: {
            PrintAndLogEx(INFO, "No data");
            break;
        }
        case -2: {
            PrintAndLogEx(FAILED, "READ UID failed!");
            break;
        }
        case -3: {
            PrintAndLogEx(FAILED, "Get System Information / Config failed!");
            break;
        }
        case -4: {
            PrintAndLogEx(FAILED, "Login failed! Wrong password?");
            break;
        }
        case -5: {
            PrintAndLogEx(FAILED, "No write access on block. Not authorized?");
            break;
        }
        case -6: {
            PrintAndLogEx(FAILED, "Response CRC invalid!");
            break;
        }
        case -7: {
            PrintAndLogEx(FAILED, "Read block failed!");
            break;
        }
        default: {
            // PM3_REASON_UNKNOWN
            PrintAndLogEx(FAILED, "Error - Hitag µ failed");
            break;
        }
    }
}

static void hitagu_config_print(hitagu_config_t config) {
    PrintAndLogEx(INFO, " Data Rate......... %s", (const char *[]) {"2 kbit/s", "4 kbit/s", "8 kbit/s", "Reserved"}[config.datarate]);
    PrintAndLogEx(INFO, " Encoding.......... %s", config.encoding ? _YELLOW_("Bi-phase") : _YELLOW_("Manchester"));
    PrintAndLogEx(INFO, " Password Protect W  Bit   0-127(block  0-3)   %s", config.pwdW0_127 ? _RED_("Yes") : _GREEN_("No"));
    PrintAndLogEx(INFO, " Password Protect W  Bit 128-511(block  4-15)  %s", config.pwdW128_511 ? _RED_("Yes") : _GREEN_("No"));
    PrintAndLogEx(INFO, " Password Protect W  Bit 512-Max(block 16-Max) %s", config.pwdW512_max ? _RED_("Yes") : _GREEN_("No"));
    PrintAndLogEx(INFO, " Password Protect RW Bit 512-Max(block 16-Max) %s", config.pwdRW512_max ? _RED_("Yes") : _GREEN_("No"));
}

static void hitagu8265_config_print(hitagu82xx_config_t config) {
    PrintAndLogEx(INFO, " Config Byte0: %s", sprint_hex((uint8_t *)&config, sizeof(config)));  // for debug
    // Check if datarate_override is set
    if (config.datarate_override) {
        PrintAndLogEx(INFO, " Data Rate........ %s", _YELLOW_("2 kbit/s"));
    } else {
        PrintAndLogEx(INFO, " Data Rate........ %s",
        (const char *[]) {"2 kbit/s", "4 kbit/s", "8 kbit/s", "2 kbit/s"}[config.datarate]);
    }
    PrintAndLogEx(INFO, " Rate Override.... %s", config.datarate_override ? _RED_("Yes") : _GREEN_("No"));
    PrintAndLogEx(INFO, " Encoding......... %s", config.encoding ? _YELLOW_("Bi-phase") : _YELLOW_("Manchester"));

    PrintAndLogEx(INFO, " TTF mode ........ %s",
    (const char *[]) {
        "Block 0, Block 1, Block 2, Block 3",
        "Block 0, Block 1",
        "Block 0, Block 1, Block 2, Block 3",
        "Block 0, Block 1, Block 2, Block 3",
    }[config.ttf_mode]);
    PrintAndLogEx(INFO, " TTF.............. %s", config.ttf ? _GREEN_("Enabled") : _RED_("Disabled"));
}

static int CmdLFHitagURead(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag htu rdbl",
                  "Read Hitag µ memory.\n\n"
                  "  82xx password mode: \n"
                  "    - default password 00000000\n",
                  "  lf hitag htu rdbl -p 1                    -> Hitag µ, plain mode\n"
                  "  lf hitag htu rdbl -p 1 --82xx             -> 82xx, password mode, def pass\n"
                  "  lf hitag htu rdbl -p 1 --82xx -k 9AC4999C -> 82xx, password mode\n");

    void *argtable[] = {arg_param_begin,
                        arg_lit0("8", "82xx", "82xx mode"),
                        arg_str0("k", "key", "<hex>", "pwd, 4 hex bytes"),
                        arg_int0("p", "page", "<dec>", "block address to read from (def: 0)"),
                        arg_int0("c", "count", "<dec>", "how many blocks to read. '0' reads all blocks (def: 1)"),
                        arg_param_end
                       };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    lf_hitag_data_t packet;

    if (process_hitagu_common_args(ctx, &packet) < 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t page = arg_get_int_def(ctx, 3, 0);

    if (page >= HITAGU_MAX_BLOCKS) {
        PrintAndLogEx(WARNING, "Block address out-of-range. Max is 255, got %u", page);
        return PM3_EINVARG;
    }

    uint32_t count = arg_get_int_def(ctx, 4, 1);

    if (count > HITAGU_MAX_BLOCKS) {
        PrintAndLogEx(WARNING, "No more than %d blocks can be read at once", HITAGU_MAX_BLOCKS);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    packet.page = page;
    packet.page_count = count;
    // packet.mode = 1;  // for debug

    PrintAndLogEx(INFO, "Read Hitag µ memory block " _YELLOW_("%d") ", count " _YELLOW_("%d"), page, count);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAGU_READ, (uint8_t *)&packet, sizeof(packet));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_HITAGU_READ, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        print_error(resp.reason);
        return PM3_ESOFT;
    }

    lf_htu_read_response_t *card = (lf_htu_read_response_t *)resp.data.asBytes;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");

    int user_blocks;
    uint8_t icr = card->icr;

    if (icr == HITAGU_ICR_STANDARD) {
        user_blocks = HITAGU_MAX_PAGE_STANDARD;
        PrintAndLogEx(INFO, "Hitag µ Standard (ICR=0x%02X), user blocks: 0x%02X", icr, user_blocks);
    } else if (icr == HITAGU_ICR_ADVANCED) {
        user_blocks = HITAGU_MAX_PAGE_ADVANCED;
        PrintAndLogEx(INFO, "Hitag µ Advanced (ICR=0x%02X), user blocks: 0x%02X", icr, user_blocks);
    } else if (icr == HITAGU_ICR_ADVANCED_PLUS) {
        user_blocks = HITAGU_MAX_PAGE_ADVANCED_PLUS;
        PrintAndLogEx(INFO, "Hitag µ Advanced+ (ICR=0x%02X), user blocks: 0x%02X", icr, user_blocks);
    } else if (icr == HITAGU_ICR_8265) {
        user_blocks = HITAGU_MAX_PAGE_8265;
        PrintAndLogEx(INFO, "Hitag µ 8265 (ICR=0x%02X), user blocks: 0x%02X", icr, user_blocks);
    } else {
        user_blocks = HITAGU_MAX_PAGE_STANDARD;
        PrintAndLogEx(INFO, "Unknown ICR (0x%02X)", icr);
    }

    if (packet.cmd == HTUF_82xx || icr == HITAGU_ICR_8265) {
        hitagu8265_config_print(card->config_page.s82xx);
    } else {
        hitagu_config_print(card->config_page.s);
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Data") " ---------------------------");
    PrintAndLogEx(INFO, "  # | 00 01 02 03 | ascii | perm | info");
    PrintAndLogEx(INFO, "----+-------------+-------+------+------");

    if (count == 0) {
        count = (user_blocks > page) ? (user_blocks - page) : HITAGU_MAX_BLOCKS;
    }

    for (int i = 0; i < count; ++i) {

        int page_addr = page + i;
        if (page_addr >= HITAGU_MAX_BLOCKS) {
            break;
        }

        if (card->pages_reason[i] > 0) {
            PrintAndLogEx(SUCCESS, "% 3u | %s  | " NOLF, page_addr, sprint_hex_ascii(card->pages[i], HITAGU_BLOCK_SIZE));

            // access right
            // 82xx
            if ((packet.cmd == HTUF_82xx || icr == HITAGU_ICR_8265) && page_addr != HITAGU_PASSWORD_PADR) {
                PrintAndLogEx(NORMAL, _YELLOW_("RO  ") NOLF);
            } else if ((packet.cmd == HTUF_82xx || icr == HITAGU_ICR_8265) && page_addr == HITAGU_PASSWORD_PADR) {
                PrintAndLogEx(NORMAL, _RED_("R/WP") NOLF);
                // Hitag µ
            } else if (page_addr < HITAGU_MAX_PAGE_STANDARD) {

                if (card->config_page.s.pwdW0_127) {
                    PrintAndLogEx(NORMAL, _RED_("RO  ") NOLF);
                } else {
                    PrintAndLogEx(NORMAL, _GREEN_("RW  ") NOLF);
                }

            } else if (HITAGU_MAX_PAGE_STANDARD <= page_addr && page_addr < HITAGU_MAX_PAGE_ADVANCED) {

                if (card->config_page.s.pwdW128_511) {
                    PrintAndLogEx(NORMAL, _RED_("RO  ") NOLF);
                } else {
                    PrintAndLogEx(NORMAL, _GREEN_("RW  ") NOLF);
                }

            } else if (HITAGU_MAX_PAGE_ADVANCED <= page_addr && page_addr < HITAGU_MAX_PAGE_ADVANCED_PLUS) {

                if (card->config_page.s.pwdRW512_max) {
                    PrintAndLogEx(NORMAL, _RED_("R/WP") NOLF);
                } else {

                    if (card->config_page.s.pwdW512_max) {
                        PrintAndLogEx(NORMAL, _RED_("RO  ") NOLF);
                    } else {
                        PrintAndLogEx(NORMAL, _GREEN_("RW  ") NOLF);
                    }
                }
            } else {
                PrintAndLogEx(NORMAL, _YELLOW_("UNK ") NOLF);
            }

            PrintAndLogEx(NORMAL, " | " NOLF);

            // info
            if (page_addr == HITAGU_PASSWORD_PADR) {
                PrintAndLogEx(NORMAL, "Password");
            } else if (page_addr == HITAGU_CONFIG_PADR) {
                PrintAndLogEx(NORMAL, "Config");
            } else {
                PrintAndLogEx(NORMAL, "Data");
            }
        } else {
            PrintAndLogEx(INFO, "% 3u | -- -- -- -- | ....  | N/A  | " NOLF, page_addr);
            print_error(card->pages_reason[i]);
        }
    }

    PrintAndLogEx(INFO, "----+-------------+-------+------+------");
    PrintAndLogEx(INFO, " " _YELLOW_("RO") " = Read without password, write with password");
    PrintAndLogEx(INFO, " " _GREEN_("R/W") " = Read and write without password");
    PrintAndLogEx(INFO, " " _RED_("R/WP") " = Read and write with password");
    PrintAndLogEx(INFO, "----------------------------------------");
    return PM3_SUCCESS;
}

static int CmdLFHitagUDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag htu dump",
                  "Read all Hitag µ memory and save to file\n"
                  "  82xx password mode: \n"
                  "    - default password 00000000\n",
                  "lf hitag htu dump --82xx              -> use def pwd\n"
                  "lf hitag htu dump --82xx -k 9AC4999C  -> pwd mode\n");

    void *argtable[] = {arg_param_begin,
                        arg_lit0("8", "82xx", "82xx mode"),
                        arg_str0("k", "key", "<hex>", "pwd, 4 hex bytes"),
                        arg_str0("f", "file", "<fn>", "specify file name"),
                        arg_lit0(NULL, "ns", "no save to file"),
                        arg_param_end
                       };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    lf_hitag_data_t packet;
    memset(&packet, 0, sizeof(packet));

    if (process_hitagu_common_args(ctx, &packet) < 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool nosave = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    // read all pages
    packet.page = 0;
    packet.page_count = 0;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAGU_READ, (uint8_t *)&packet, sizeof(packet));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_HITAGU_READ, &resp, 5000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        print_error(resp.reason);
        return PM3_ESOFT;
    }

    lf_htu_read_response_t *card = (lf_htu_read_response_t *)resp.data.asBytes;

    int user_blocks;
    uint8_t icr = card->icr;

    if (icr == HITAGU_ICR_STANDARD) {
        user_blocks = HITAGU_MAX_PAGE_STANDARD;
        PrintAndLogEx(INFO, "Hitag µ Standard (ICR=0x%02X), user blocks: 0x%02X", icr, user_blocks);
    } else if (icr == HITAGU_ICR_ADVANCED) {
        user_blocks = HITAGU_MAX_PAGE_ADVANCED;
        PrintAndLogEx(INFO, "Hitag µ Advanced (ICR=0x%02X), user blocks: 0x%02X", icr, user_blocks);
    } else if (icr == HITAGU_ICR_ADVANCED_PLUS) {
        user_blocks = HITAGU_MAX_PAGE_ADVANCED_PLUS;
        PrintAndLogEx(INFO, "Hitag µ Advanced+ (ICR=0x%02X), user blocks: 0x%02X", icr, user_blocks);
    } else if (icr == HITAGU_ICR_8265) {
        user_blocks = HITAGU_MAX_PAGE_8265;
        PrintAndLogEx(INFO, "Hitag µ 8265 (ICR=0x%02X), user blocks: 0x%02X", icr, user_blocks);
    } else {
        user_blocks = HITAGU_MAX_PAGE_STANDARD;
        PrintAndLogEx(INFO, "Unknown ICR (0x%02X)", icr);
    }

    int mem_size = (user_blocks + 2) * HITAGU_BLOCK_SIZE;

    hitagu_config_t config = card->config_page.s;
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    hitagu_config_print(config);

    if (nosave) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "Called with no save option");
        PrintAndLogEx(NORMAL, "");
        return PM3_SUCCESS;
    }

    if (fnlen < 1) {
        char *fptr = filename;
        fptr += snprintf(filename, sizeof(filename), "lf-htu-");
        FillFileNameByUID(fptr, card->uid, "-dump", HITAGU_UID_SIZE);
    }

    pm3_save_dump(filename, (uint8_t *)card->pages, mem_size, jsfHitag);

    return PM3_SUCCESS;
}

static int CmdLFHitagUWrite(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag htu wrbl",
                  "Write a block in Hitag µ memory.\n"
                  "  82xx password mode: \n"
                  "    - default password 00000000\n",
                  "  lf hitag htu wrbl -p 6 -d 01020304                    -> Hitag µ, plain mode\n"
                  "  lf hitag htu wrbl -p 6 -d 01020304 --82xx             -> use def pwd\n"
                  "  lf hitag htu wrbl -p 6 -d 01020304 --82xx -k 9AC4999C -> 82xx, password mode\n");

    void *argtable[] = {arg_param_begin,
                        arg_lit0("8", "82xx", "82xx mode"),
                        arg_str0("k", "key", "<hex>", "pwd, 4 hex bytes"),
                        arg_int1("p", "page", "<dec>", "block address to write to"),
                        arg_str1("d", "data", "<hex>", "data, 4 hex bytes"),
                        arg_param_end
                       };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    lf_hitag_data_t packet;

    if (process_hitagu_common_args(ctx, &packet) < 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int page = arg_get_int_def(ctx, 3, 0);

    uint8_t data[HITAGU_BLOCK_SIZE];
    int data_len = 0;

    int res = CLIParamHexToBuf(arg_get_str(ctx, 4), data, HITAGU_BLOCK_SIZE, &data_len);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    packet.page = page;
    memcpy(packet.data, data, sizeof(packet.data));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAGU_WRITE, (uint8_t *)&packet, sizeof(packet));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_HITAGU_WRITE, &resp, 4000) == false) {
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

static int CmdLFHitagUReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag htu reader", "Act as a Hitag µ reader. Look for Hitag µ tags until Enter or the pm3 button is pressed\n",
                  "lf hitag htu reader\n"
                  "lf hitag htu reader -@   -> Continuous mode");

    void *argtable[] = {
        arg_param_begin, arg_lit0("@", NULL, "continuous reader mode"), arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    do {
        read_htu_uid();
    } while (cm && kbd_enter_pressed() == false);

    return PM3_SUCCESS;
}

static int CmdLFHitagUSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag htu sim",
                  "Simulate Hitag µ transponder\n"
                  "You need to `lf hitag htu eload` first",
                  "lf hitag htu sim\n"
                  "lf hitag htu sim --82xx\n"
                  "lf hitag htu sim -t 30    -> set threshold to 30");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("8", "82xx", "simulate 82xx"),
        arg_int0("t", "threshold", "<dec>", "set edge detect threshold (def: 127)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    // bool use_82xx = arg_get_lit(ctx, 1);    // not implemented yet
    int threshold = arg_get_int_def(ctx, 2, 127);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandMIX(CMD_LF_HITAGU_SIMULATE, false, threshold, 0, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdLFHitagUList(const char *Cmd) { return CmdTraceListAlias(Cmd, "lf hitag htu", "htu"); }

static command_t CommandTable[] = {
    {"help",        CmdHelp,            AlwaysAvailable, "This help"},
    {"list",        CmdLFHitagUList,    AlwaysAvailable, "List Hitag µ trace history"},
    {"-----------", CmdHelp,            IfPm3Hitag,      "----------- " _CYAN_("General") " -----------"},
    {"reader",      CmdLFHitagUReader,  IfPm3Hitag,      "Act like a Hitag µ reader"},
    {"rdbl",        CmdLFHitagURead,    IfPm3Hitag,      "Read Hitag µ block"},
    {"dump",        CmdLFHitagUDump,    IfPm3Hitag,      "Dump Hitag µ blocks to a file"},
    {"wrbl",        CmdLFHitagUWrite,   IfPm3Hitag,      "Write Hitag µ block"},
    {"-----------", CmdHelp,            IfPm3Hitag,      "----------- " _CYAN_("Simulation") " -----------"},
    {"sim",         CmdLFHitagUSim,     IfPm3Hitag,      "Simulate Hitag µ transponder"},
    {NULL, NULL, 0, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd;  // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFHitagU(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
