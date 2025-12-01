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
// High frequency ISO 18002 / FeliCa commands
//-----------------------------------------------------------------------------
#include "cmdhffelica.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include "cmdparser.h"   // command_t
#include "comms.h"
#include "cmdtrace.h"
#include "crc16.h"
#include "util.h"
#include "ui.h"
#include "iso18.h"       // felica_card_select_t struct
#include "des.h"
#include "platform_util.h"
#include "cliparser.h"   // cliparser
#include "util_posix.h"  // msleep


#define FELICA_BLK_SIZE 16
#define FELICA_BLK_HALF (FELICA_BLK_SIZE/2)

#define FELICA_BLK_NUMBER_RC    0x80
#define FELICA_BLK_NUMBER_ID    0x82
#define FELICA_BLK_NUMBER_WCNT  0x90
#define FELICA_BLK_NUMBER_MACA  0x91
#define FELICA_BLK_NUMBER_STATE 0x92

#define FELICA_SERVICE_ATTRIBUTE_UNAUTH_READ    (0b000001)
#define FELICA_SERVICE_ATTRIBUTE_READ_ONLY      (0b000010)
#define FELICA_SERVICE_ATTRIBUTE_RANDOM_ACCESS  (0b001000)
#define FELICA_SERVICE_ATTRIBUTE_CYCLIC         (0b001100)
#define FELICA_SERVICE_ATTRIBUTE_PURSE          (0b010000)
#define FELICA_SERVICE_ATTRIBUTE_PURSE_SUBFIELD (0b000110)


static int CmdHelp(const char *Cmd);
static felica_card_select_t last_known_card;

static void set_last_known_card(felica_card_select_t card) {
    last_known_card = card;
}

static void print_status_flag1_interpretation(void) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, _CYAN_("Status Flag 1"));
    PrintAndLogEx(INFO, "----+--------------------------------------------------------------------------------------------------------------------");
    PrintAndLogEx(INFO, " 00 | Indicates the successful completion of a command.");
    PrintAndLogEx(INFO, " FF | If an error occurs during the processing of a command that includes no list in the command packet, \n"
                  "    | or if an error occurs independently of any list, the card returns a response by setting FFh to Status Flag1.");
    PrintAndLogEx(INFO, " XX | If an error occurs while processing a command that includes Service Code List or Block List \n"
                  "    | in the command packet, the card returns a response by setting a number in the list to Status Flag1,\n"
                  "    | indicating the location of the error.");
    PrintAndLogEx(INFO, "----+--------------------------------------------------------------------------------------------------------------------");
}

static void print_status_flag2_interpration(void) {
    PrintAndLogEx(INFO, _CYAN_("Status Flag 2"));
    PrintAndLogEx(INFO, "----+--------------------------------------------------------------------------------------------------------------------");
    PrintAndLogEx(INFO, " 00 | Indicates the successful completion of a command.");
    PrintAndLogEx(INFO, " 01 | The calculated result is either less than zero when the purse data is decremented, or exceeds 4\n"
                  "    | Bytes when the purse data is incremented.");
    PrintAndLogEx(INFO, " 02 | The specified data exceeds the value of cashback data at cashback of purse.");
    PrintAndLogEx(INFO, " 70 | Memory error (fatal error).");
    PrintAndLogEx(INFO, " 71 | The number of memory rewrites exceeds the upper limit (this is only a warning; data writing is performed as normal).\n"
                  "    | The maximum number of rewrites can differ, depending on the product being used.\n"
                  "    | In addition, Status Flag1 is either 00h or FFh depending on the product being used.");

    PrintAndLogEx(INFO, " A1 | Illegal Number of Service| Number of Service or Number of Node specified by the command \n"
                  "    | falls outside the range of the prescribed value.");
    PrintAndLogEx(INFO, " A2 | Illegal command packet (specified Number of Block) : Number of Block specified by the \n"
                  "    | command falls outside the range of the prescribed values for the product.");
    PrintAndLogEx(INFO, " A3 | Illegal Block List (specified order of Service) : Service Code List Order specified by \n"
                  "    | Block List Element falls outside the Number of Service specified by the command \n"
                  "    | (or the Number of Service specified at the times of mutual authentication).");
    PrintAndLogEx(INFO, " A4 | Illegal Service type : Area Attribute specified by the command or Service Attribute of Service Code is incorrect.");
    PrintAndLogEx(INFO, " A5 | Access is not allowed : Area or Service specified by the command cannot be accessed.\n"
                  "    | The parameter specified by the command does not satisfy the conditions for success.");
    PrintAndLogEx(INFO, " A6 | Illegal Service Code List : Target to be accessed, identified by Service Code List Order, specified by Block\n"
                  "    | List Element does not exist. Or, Node specified by Node Code List does not exist.");
    PrintAndLogEx(INFO, " A7 | Illegal Block List (Access Mode) : Access Mode specified by Block List Element is incorrect.");
    PrintAndLogEx(INFO, " A8 | Illegal Block Number Block Number (access to the specified data is inhibited) :\n"
                  "    | specified by Block List Element exceeds the number of Blocks assigned to Service.");
    PrintAndLogEx(INFO, " A9 | Data write failure : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, " AA | Key-change failure : Key change failed.");
    PrintAndLogEx(INFO, " AB | Illegal Package Parity or illegal Package MAC : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, " AC | Illegal parameter : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, " AD | Service exists already : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, " AE | Illegal System Code : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, " AF | Too many simultaneous cyclic write operations : Number of simultaneous write Blocks\n"
                  "    | specified by the command to Cyclic Service exceeds the number of Blocks assigned to Service.");
    PrintAndLogEx(INFO, " C0 | Illegal Package Identifier : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, " C1 | Discrepancy of parameters inside and outside Package : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, " C2 | Command is disabled already : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, "----+--------------------------------------------------------------------------------------------------------------------");
    PrintAndLogEx(NORMAL, "");
}

static void print_block_list_element_constraints(void) {
    PrintAndLogEx(INFO, "    - Each Block List Element shall satisfy the following conditions:");
    PrintAndLogEx(INFO, "        - The value of Service Code List Order shall not exceed Number of Service.");
    PrintAndLogEx(INFO, "        - Access Mode shall be 000b.");
    PrintAndLogEx(INFO, "        - The target specified by Service Code shall not be Area or System.");
    PrintAndLogEx(INFO, "        - Service specified in Service Code List shall exist in System.");
    PrintAndLogEx(INFO, "        - Service Attribute of Service specified in Service Code List shall be authentication-not-required Service.");
    PrintAndLogEx(INFO, "        - Block Number shall be in the range of the number of Blocks assigned to the specified Service.");
}

static void print_number_of_service_constraints(void) {
    PrintAndLogEx(INFO, "    - Number of Service: shall be a positive integer in the range of 1 to 16, inclusive.");
}

static void print_number_of_block_constraints(void) {
    PrintAndLogEx(INFO, "    - Number of Block: shall be less than or equal to the maximum number of Blocks that can be read simultaneously.\n"
                  "            The maximum number of Blocks that can be read simultaneously can differ, depending on the product being used.\n"
                  "            Use as default 01");
}

static void print_service_code_list_constraints(void) {
    PrintAndLogEx(INFO, "    - Service Code List: For Service Code List, only Service Code existing in the product shall be specified:");
    PrintAndLogEx(INFO, "        - Even when Service Code exists in the product, Service Code not referenced from Block List shall not \n"
                  "          be specified to Service Code List.");
    PrintAndLogEx(INFO, "        - For existence or nonexistence of Service in a product, please check using the Request Service \n"
                  "          (or Request Service v2) command.");
}

/*
static int usage_hf_felica_sim(void) {
    PrintAndLogEx(INFO, "\n Emulating ISO/18092 FeliCa tag \n");
    PrintAndLogEx(INFO, "Usage: hf felica sim -t <type> [-v]");
    PrintAndLogEx(INFO, "Options:");
    PrintAndLogEx(INFO, "    t     : 1 = FeliCa");
    PrintAndLogEx(INFO, "          : 2 = FeliCaLiteS");
    PrintAndLogEx(INFO, "    v     : (Optional) Verbose");
    PrintAndLogEx(INFO, "Examples:");
    PrintAndLogEx(INFO, "          hf felica sim -t 1");
    return PM3_SUCCESS;
}
*/

static int print_authentication1(void) {
    PrintAndLogEx(INFO, "Initiate mutual authentication. This command must always be executed before Auth2 command");
    PrintAndLogEx(INFO, "and mutual authentication is achieve only after Auth2 command has succeeded.");
    PrintAndLogEx(INFO, "  - Auth1 Parameters:");
    PrintAndLogEx(INFO, "    - Number of Areas n: 1-byte (1 <= n <= 8)");
    PrintAndLogEx(INFO, "    - Area Code List: 2n byte");
    PrintAndLogEx(INFO, "    - Number of Services m: 1-byte (1 <= n <= 8)");
    PrintAndLogEx(INFO, "    - Service Code List: 2n byte");
    PrintAndLogEx(INFO, "    - 3DES-Key: 128-bit master secret used for the encryption");
    PrintAndLogEx(INFO, "    - M1c: Encrypted random number - challenge for tag authentication (8-byte)");
    PrintAndLogEx(INFO, "  - Response:");
    PrintAndLogEx(INFO, "    - Response Code: 11h 1-byte");
    PrintAndLogEx(INFO, "    - Manufacture ID(IDm): 8-byte");
    PrintAndLogEx(INFO, "    - M2c: 8-byte");
    PrintAndLogEx(INFO, "    - M3c: 8-byte");
    PrintAndLogEx(INFO, "  - Success: Card Mode switches to Mode1. You can check this with the request response command.");
    PrintAndLogEx(INFO, "  - Unsuccessful: Card should not respond at all.");
    return PM3_SUCCESS;
}

static int print_authentication2(void) {
    PrintAndLogEx(INFO, "Complete mutual authentication.");
    PrintAndLogEx(INFO, "This command can only be executed subsquent to Auth1 command.");
    PrintAndLogEx(INFO, "  - Auth2 Parameters:");
    PrintAndLogEx(INFO, "    - Manufacturer IDm: (8-byte)");
    PrintAndLogEx(INFO, "    - M3c: card challenge (8-byte)");
    PrintAndLogEx(INFO, "    - 3DES Key: key used for decryption of M3c (16-byte)");
    PrintAndLogEx(INFO, "  - Response (encrypted):");
    PrintAndLogEx(INFO, "    - Response Code: 13h (1-byte)");
    PrintAndLogEx(INFO, "    - IDtc:  (8-byte)");
    PrintAndLogEx(INFO, "    - IDi (encrypted):  (8-byte)");
    PrintAndLogEx(INFO, "    - PMi (encrypted):  (8-byte)");
    PrintAndLogEx(INFO, "  - Success: Card switches to mode2 and sends response frame.");
    PrintAndLogEx(INFO, "  - Unsuccessful: Card should not respond at all.");
    return PM3_SUCCESS;
}

static const char *felica_model_name(uint8_t rom_type, uint8_t ic_type) {
    // source: mainly https://www.sony.net/Products/felica/business/tech-support/list.html
    switch (ic_type) {
        // FeliCa Standard Products:
        case 0x46:
            return "FeliCa Standard RC-SA21/2";
        case 0x45:
            return "FeliCa Standard RC-SA20/2";
        case 0x44:
            return "FeliCa Standard RC-SA20/1";
        case 0x35:
            return "FeliCa Standard RC-SA01/2";
        case 0x32:
            return "FeliCa Standard RC-SA00/1";
        case 0x20:
            return "FeliCa Standard RC-S962";
        case 0x0D:
            return "FeliCa Standard RC-S960";
        case 0x0C:
            return "FeliCa Standard RC-S954";
        case 0x09:
            return "FeliCa Standard RC-S953";
        case 0x08:
            return "FeliCa Standard RC-S952";
        case 0x01:
            return "FeliCa Standard RC-S915";
        // FeliCa Lite Products:
        case 0xF1:
            return "FeliCa Lite-S RC-S966";
        case 0xF0:
            return "FeliCa Lite RC-S965";
        // FeliCa Link Products:
        case 0xF2:
            return "FeliCa Link RC-S967 (Lite-S Mode or Lite-S HT Mode)";
        case 0xE1:
            return "FeliCa Link RC-S967 (Plug Mode)";
        case 0xFF:
            if (rom_type == 0xFF) { // from FeliCa Link User's Manual
                return "FeliCa Link RC-S967 (NFC-DEP Mode)";
            }
            break;
        // NFC Dynamic Tag (FeliCa Plug) Products:
        case 0xE0:
            return "NFC Dynamic Tag (FeliCa Plug) RC-S926";

        // FeliCa Mobile Chip
        case 0x14:
        case 0x15:
        case 0x16:
        case 0x17:
        case 0x18:
        case 0x19:
        case 0x1A:
        case 0x1B:
        case 0x1C:
        case 0x1D:
        case 0x1E:
        case 0x1F:
            return "FeliCa Mobile IC Chip V3.0";
        case 0x10:
        case 0x11:
        case 0x12:
        case 0x13:
            return "Mobile FeliCa IC Chip V2.0";
        case 0x06:
        case 0x07:
            return "Mobile FeliCa IC Chip V1.0";

        // odd findings
        case 0x00:
            return "FeliCa Standard RC-S830";
        case 0x02:
            return "FeliCa Standard RC-S919";
        case 0x0B:
        case 0x31:
        case 0x36:
            return "Suica card (FeliCa Standard RC-S ?)";
        default:
            break;
    }
    return "Unknown IC Type";
}

/**
 * Wait for response from pm3 or timeout.
 * Checks if receveid bytes have a valid CRC.
 * @param verbose prints out the response received.
 */
static bool waitCmdFelica(bool iSelect, PacketResponseNG *resp, bool verbose) {
    if (WaitForResponseTimeout(CMD_ACK, resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return false;
    }

    uint16_t len = (iSelect) ? (resp->oldarg[1] & 0xffff) : (resp->oldarg[0] & 0xffff);

    if (verbose) {

        if (len == 0 || len == 1) {
            PrintAndLogEx(ERR, "Could not receive data correctly!");
            return false;
        }

        PrintAndLogEx(SUCCESS, "(%u) %s", len, sprint_hex(resp->data.asBytes, len));

        if (iSelect == false) {
            if (check_crc(CRC_FELICA, resp->data.asBytes + 2, len - 2) == false) {
                PrintAndLogEx(WARNING, "CRC ( " _RED_("fail") " )");
            }

            if (resp->data.asBytes[0] != 0xB2 && resp->data.asBytes[1] != 0x4D) {
                PrintAndLogEx(ERR, "received incorrect frame format!");
                return false;
            }
        }
    }
    return true;
}


/**
 * Adds the last known IDm (8-Byte) to the data frame.
 * @param position start of where the IDm is added within the frame.
 * @param data frame in where the IDM is added.
 * @return true if IDm was added;
 */
static bool add_last_IDm(uint8_t position, uint8_t *data) {
    if (last_known_card.IDm[0] != 0 && last_known_card.IDm[1] != 0) {
        memcpy(data + position, last_known_card.IDm, sizeof(last_known_card.IDm));
        return true;
    }
    return false;
}

static int CmdHFFelicaList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf felica", "felica");
}

int read_felica_uid(bool loop, bool verbose) {

    int res = PM3_ETIMEOUT;

    do {
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_FELICA_COMMAND, FELICA_CONNECT, 0, 0, NULL, 0);
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {

            uint8_t status = resp.oldarg[0] & 0xFF;

            if (loop) {
                if (status != 0) {
                    continue;
                }
            } else {
                // when not in continuous mode
                if (status != 0) {
                    if (verbose) PrintAndLogEx(WARNING, "FeliCa card select failed");
                    res = PM3_EOPABORTED;
                    break;
                }
            }

            felica_card_select_t card;
            memcpy(&card, (felica_card_select_t *)resp.data.asBytes, sizeof(felica_card_select_t));
            if (loop == false) {
                PrintAndLogEx(NORMAL, "");
            }
            PrintAndLogEx(SUCCESS, "IDm: " _GREEN_("%s"), sprint_hex_inrow(card.IDm, sizeof(card.IDm)));
            set_last_known_card(card);

            res = PM3_SUCCESS;
        }

    } while (loop && (kbd_enter_pressed() == false));

    DropField();
    return res;
}

static int CmdHFFelicaReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica reader",
                  "Act as a ISO 18092 / FeliCa reader. Look for FeliCa tags until Enter or the pm3 button is pressed",
                  "hf felica reader -@    -> Continuous mode");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s", "silent", "silent (no messages)"),
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = (arg_get_lit(ctx, 1) == false);
    bool cm = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    CLIParserFree(ctx);
    return read_felica_uid(cm, verbose);
}

static int info_felica(bool verbose) {

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_FELICA_COMMAND, FELICA_CONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        if (verbose) PrintAndLogEx(WARNING, "FeliCa card select failed");
        return PM3_ESOFT;
    }

    felica_card_select_t card;
    memcpy(&card, (felica_card_select_t *)resp.data.asBytes, sizeof(felica_card_select_t));
    uint64_t status = resp.oldarg[0];

    switch (status) {
        case 1: {
            if (verbose)
                PrintAndLogEx(WARNING, "card timeout");
            return PM3_ETIMEOUT;
        }
        case 2: {
            if (verbose)
                PrintAndLogEx(WARNING, "card answered wrong");
            return PM3_ESOFT;
        }
        case 3: {
            if (verbose)
                PrintAndLogEx(WARNING, "CRC check failed");
            return PM3_ESOFT;
        }
        case 0: {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
            PrintAndLogEx(INFO, "IDm............ " _GREEN_("%s"), sprint_hex_inrow(card.IDm, sizeof(card.IDm)));
            PrintAndLogEx(INFO, "Code........... %s ", sprint_hex_inrow(card.code, sizeof(card.code)));
            PrintAndLogEx(INFO, "NFCID2......... %s", sprint_hex_inrow(card.uid, sizeof(card.uid)));
            PrintAndLogEx(INFO, "Parameter");
            PrintAndLogEx(INFO, "PAD............ " _YELLOW_("%s"), sprint_hex_inrow(card.PMm, sizeof(card.PMm)));
            PrintAndLogEx(INFO, "IC code........ %s ( " _YELLOW_("%s") " )", sprint_hex_inrow(card.iccode, sizeof(card.iccode)), felica_model_name(card.iccode[0], card.iccode[1]));
            PrintAndLogEx(INFO, "MRT............ %s", sprint_hex_inrow(card.mrt, sizeof(card.mrt)));
            PrintAndLogEx(INFO, "Service code... " _YELLOW_("%s"), sprint_hex(card.servicecode, sizeof(card.servicecode)));
            PrintAndLogEx(NORMAL, "");
            set_last_known_card(card);
            break;
        }
    }
    return PM3_SUCCESS;
}

static int CmdHFFelicaInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica info",
                  "Reader for FeliCa based tags",
                  "hf felica info");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return info_felica(false);
}

/**
 * Clears command buffer and sends the given data to pm3 with mix mode.
 */
static void clear_and_send_command(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose) {
    uint16_t numbits = 0;
    uint16_t payload_len = 0;
    uint8_t *payload = data;

    // ARMSRC implementation adds FeliCa preamble and length automatically (felica_sendraw:575-576)
    // A bunch of code in this module adds length byte at data[0] regardless of that, which is wrong
    // This is a workaround to extract the actual payload correctly so that length byte isn't repeated
    // It also strips CRC if present, as ARMSRC adds it too
    if (data && datalen) {
        if (datalen >= data[0] && data[0] > 0) {
            payload_len = data[0] - 1;
            if (payload_len > datalen - 1) {
                payload_len = datalen - 1;
            }
            payload = data + 1;
        } else {
            payload_len = datalen;
        }
    }

    clearCommandBuffer();
    if (verbose) {
        PrintAndLogEx(INFO, "Send raw command - Frame: %s", sprint_hex(payload, payload_len));
    }
    SendCommandMIX(CMD_HF_FELICA_COMMAND, flags, (payload_len & 0xFFFF) | (uint32_t)(numbits << 16), 0, payload, payload_len);
}

/**
 * Prints read-without-encryption response.
 * @param rd_noCry_resp Response frame.
 * @param block_index Optional explicit block index (UINT16_MAX to use tag value)
 */
static void print_rd_plain_response(felica_read_without_encryption_response_t *rd_noCry_resp, uint16_t block_index) {

    uint16_t display_block = block_index;

    if (rd_noCry_resp->status_flags.status_flag1[0] == 00 &&
            rd_noCry_resp->status_flags.status_flag2[0] == 00) {

        char *temp = sprint_hex(rd_noCry_resp->block_data, sizeof(rd_noCry_resp->block_data));

        char bl_data[256];
        strncpy(bl_data, temp, sizeof(bl_data) - 1);


        PrintAndLogEx(INFO, "  %04X | %s  ", display_block, bl_data);
    } else {
        char sf1[8];
        char sf2[8];
        snprintf(sf1, sizeof(sf1), "%02X", rd_noCry_resp->status_flags.status_flag1[0]);
        snprintf(sf2, sizeof(sf2), "%02X", rd_noCry_resp->status_flags.status_flag2[0]);
        PrintAndLogEx(INFO, "  %04X | Status flag 1... %s; Status flag 2... %s", display_block, sf1, sf2);
    }
}

/**
 * Sends a request service frame to the pm3 and prints response.
 */
int send_request_service(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose) {

    clear_and_send_command(flags, datalen, data, verbose);
    if (datalen) {

        PacketResponseNG resp;
        if (waitCmdFelica(false, &resp, true) == false) {
            PrintAndLogEx(ERR, "\nGot no response from card");
            return PM3_ERFTRANS;
        }

        felica_request_service_response_t r;
        memcpy(&r, (felica_request_service_response_t *)resp.data.asBytes, sizeof(felica_request_service_response_t));

        if (r.frame_response.IDm[0] != 0) {
            PrintAndLogEx(SUCCESS, "Service Response:");
            PrintAndLogEx(SUCCESS, "IDm... %s", sprint_hex_inrow(r.frame_response.IDm, sizeof(r.frame_response.IDm)));
            PrintAndLogEx(SUCCESS, "  Node number............. %s", sprint_hex(r.node_number, sizeof(r.node_number)));
            PrintAndLogEx(SUCCESS, "  Node key version list... %s\n", sprint_hex(r.node_key_versions, sizeof(r.node_key_versions)));
        }
        return PM3_SUCCESS;
    }
    return PM3_ERFTRANS;
}

/**
 * Sends a read_without_encryption frame to the pm3 and prints response.
 * @param flags to use for pm3 communication.
 * @param datalen frame length.
 * @param data frame to be send.
 * @param verbose display additional output.
 * @param rd_noCry_resp frame in which the response will be saved.
 * @return success if response was received.
 */
int send_rd_plain(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose, felica_read_without_encryption_response_t *rd_noCry_resp) {
    clear_and_send_command(flags, datalen, data, verbose);
    PacketResponseNG resp;
    if (waitCmdFelica(false, &resp, verbose) == false) {
        PrintAndLogEx(ERR, "No response from card");
        return PM3_ERFTRANS;
    } else {
        memcpy(rd_noCry_resp, (felica_read_without_encryption_response_t *)resp.data.asBytes, sizeof(felica_read_without_encryption_response_t));
          if (rd_noCry_resp->frame_response.cmd_code[0] != 0x07) {
            PrintAndLogEx(FAILED, "Bad response cmd 0x%02X @ 0x%04X.",
                          rd_noCry_resp->frame_response.cmd_code[0], 0x00);
            PrintAndLogEx(INFO, "This is either a normal signal issue, or an issue caused by wrong parameter. Please try again.");
            return PM3_ERFTRANS;
        }
        return PM3_SUCCESS;
    }
}

/**
 * Sends a dump_service frame to the pm3 and prints response.
 * @param flags to use for pm3 communication.
 * @param datalen frame length.
 * @param data frame to be send.
 * @param verbose display additional output.
 * @param dump_sv_resp frame in which the response will be saved.
 * @param is_area true if the service is an area, false if it is a service.
 * @return success if response was received.
 */
int send_dump_sv_plain(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose, felica_service_dump_response_t *dump_sv_resp, bool is_area) {
    clear_and_send_command(flags, datalen, data, verbose);
    PacketResponseNG resp;
    if (waitCmdFelica(false, &resp, verbose) == false) {
        PrintAndLogEx(ERR, "No response from card");
        return PM3_ERFTRANS;
    } else {
        memcpy(dump_sv_resp, (felica_service_dump_response_t *)resp.data.asBytes, sizeof(felica_service_dump_response_t));
        return PM3_SUCCESS;
    }
}

/**
 * Checks if last known card can be added to data and adds it if possible.
 * @param custom_IDm
 * @param data
 * @return
 */
static bool check_last_idm(uint8_t *data, uint16_t datalen) {
    if (add_last_IDm(2, data) == false) {
        PrintAndLogEx(WARNING, "No last known card! Use `" _YELLOW_("hf felica reader") "` first or set a custom IDm");
        return false;
    }

    PrintAndLogEx(INFO, "Using last known IDm... " _GREEN_("%s"), sprint_hex_inrow(data, datalen));
    return true;
}

/**
 * Sends a read_without_encryption frame to the pm3 and prints response.
 * @param flags to use for pm3 communication.
 * @param datalen frame length.
 * @param data frame to be send.
 * @param verbose display additional output.
 * @param wr_noCry_resp frame in which the response will be saved.
 * @return success if response was received.
 */
static int send_wr_plain(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose, felica_status_response_t *wr_noCry_resp) {
    clear_and_send_command(flags, datalen, data, verbose);
    PacketResponseNG resp;
    if (waitCmdFelica(false, &resp, verbose) == false) {
        PrintAndLogEx(ERR, "no response from card");
        return PM3_ERFTRANS;
    }

    memcpy(wr_noCry_resp, (felica_status_response_t *)resp.data.asBytes, sizeof(felica_status_response_t));
    return PM3_SUCCESS;
}

/**
 * Reverses the master secret. Example: AA AA AA AA AA AA AA BB to BB AA AA AA AA AA AA AA
 * @param master_key the secret which order will be reversed.
 * @param length in bytes of the master secret.
 * @param reverse_master_key output in which the reversed secret is stored.
 */
static void reverse_3des_key(const uint8_t *master_key, int length, uint8_t *reverse_master_key) {
    for (int i = 0; i < length; i++) {
        reverse_master_key[i] = master_key[(length - 1) - i];
    }
}

/**
 * Command parser for auth1
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaAuthentication1(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica auth1",
                  "Initiate mutual authentication. This command must always be executed before Auth2 command\n"
                  "and mutual authentication is achieve only after Auth2 command has succeeded.\n"
                  _RED_("INCOMPLETE / EXPERIMENTAL COMMAND!!!"),
                  "hf felica auth1 --an 01 --acl 0000 --sn 01 --scl 8B00 --key AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB\n"
                  "hf felica auth1 --an 01 --acl 0000 --sn 01 --scl 8B00 --key AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBAAAAAAAAAAAAAAAA\n"
                  "hf felica auth1 -i 11100910C11BC407 --an 01 --acl 0000 --sn 01 ..scl 8B00 --key AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "an",  "<hex>", "number of areas, 1 byte"),
        arg_str0(NULL, "acl", "<hex>", "area code list, 2 bytes"),
        arg_str0("i", NULL, "<hex>", "set custom IDm"),
        arg_str0(NULL, "sn",  "<hex>", "number of service, 1 byte"),
        arg_str0(NULL, "scl", "<hex>", "service code list, 2 bytes"),
        arg_str0("k", "key",  "<hex>", "3des key, 16 bytes"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t an[1] = {0};
    int anlen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), an, sizeof(an), &anlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t acl[2] = {0};
    int acllen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), acl, sizeof(acl), &acllen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t idm[8] = {0};
    int ilen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 3), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t sn[1] = {0};
    int snlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 4), sn, sizeof(sn), &snlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t scl[2] = {0};
    int scllen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 5), scl, sizeof(scl), &scllen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t key[24] = {0};
    int keylen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 6), key, sizeof(key), &keylen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool verbose = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);
    if (verbose) {
        print_authentication1();
        return PM3_SUCCESS;
    }

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));
    data[0] = 0x0C; // Static length
    data[1] = 0x3E; // Command ID

    bool custom_IDm = false;

    if (ilen) {
        custom_IDm = true;
        memcpy(data + 2, idm, 8);
    }

    // Length (1),
    // Command ID (1),
    // IDm (8),
    // Number of Area (1),
    // Area Code List (2),
    // Number of Service (1),
    // Service Code List (2),
    // M1c (16)
    uint16_t datalen = 32;
    data[0] = (datalen & 0xFF);
    data[1] = 0x10; // Command ID

    if (custom_IDm == false && check_last_idm(data, datalen) == false) {
        return PM3_EINVARG;
    }

    if (anlen) {
        data[10] = an[0];
    }
    if (acllen) {
        data[11] = acl[0];
        data[12] = acl[1];
    }
    if (snlen) {
        data[13] = sn[0];
    }
    if (scllen) {
        data[14] = scl[0];
        data[15] = scl[1];
    }
    if (keylen) {
        memcpy(data + 16, key, keylen);
    }

    // READER CHALLENGE - (RANDOM To Encrypt = Rac)
    uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    PrintAndLogEx(INFO, "Reader challenge (unencrypted): %s", sprint_hex(nonce, 8));

    // Create M1c Challenge with 3DES (3 Keys = 24, 2 Keys = 16)
    uint8_t master_key[24] = {0};
    mbedtls_des3_context des3_ctx;
    mbedtls_des3_init(&des3_ctx);

    if (keylen == 24) {

        mbedtls_des3_set3key_enc(&des3_ctx, master_key);
        PrintAndLogEx(INFO, "3DES Master Secret: %s", sprint_hex(master_key, keylen));

    } else if (keylen == 16) {

        // Assumption: Master secret split in half for Kac, Kbc
        mbedtls_des3_set2key_enc(&des3_ctx, master_key);
        PrintAndLogEx(INFO, "3DES Master Secret: %s", sprint_hex(master_key, keylen));
    } else {
        PrintAndLogEx(ERR, "Invalid key length");
        mbedtls_des3_free(&des3_ctx);
        return PM3_EINVARG;
    }

    uint8_t output[8];
    mbedtls_des3_crypt_ecb(&des3_ctx, nonce, output);
    mbedtls_des3_free(&des3_ctx);

    PrintAndLogEx(INFO, "3DES ENCRYPTED M1c: %s", sprint_hex(output, sizeof(output)));

    // Add M1c Challenge to frame
    memcpy(data + 16, output, sizeof(output));

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);

    PrintAndLogEx(INFO, "Client send AUTH1 frame: %s", sprint_hex(data, datalen));
    clear_and_send_command(flags, datalen, data, 0);

    PacketResponseNG resp;
    if (waitCmdFelica(false, &resp, true) == false) {
        PrintAndLogEx(ERR, "no response from card");
        return PM3_ERFTRANS;
    }

    felica_auth1_response_t auth1_response;
    memcpy(&auth1_response, (felica_auth1_response_t *)resp.data.asBytes, sizeof(felica_auth1_response_t));

    if (auth1_response.frame_response.IDm[0]) {
        PrintAndLogEx(SUCCESS, "Auth1 response:");
        PrintAndLogEx(SUCCESS, "IDm... %s", sprint_hex(auth1_response.frame_response.IDm, sizeof(auth1_response.frame_response.IDm)));
        PrintAndLogEx(SUCCESS, "M2C... %s", sprint_hex(auth1_response.m2c, sizeof(auth1_response.m2c)));
        PrintAndLogEx(SUCCESS, "M3C... %s", sprint_hex(auth1_response.m3c, sizeof(auth1_response.m3c)));

        // Assumption: Key swap method used
        uint8_t rev_master_key[PM3_CMD_DATA_SIZE];
        reverse_3des_key(master_key, 16, rev_master_key);
        mbedtls_des3_set2key_dec(&des3_ctx, rev_master_key);

        bool is_key_correct = false;
        unsigned char p2c[8];
        mbedtls_des3_crypt_ecb(&des3_ctx, auth1_response.m2c, p2c);

        for (uint8_t i = 0; i < 8; i++) {
            if (p2c[i] != nonce[i]) {
                is_key_correct = false;
                break;
            } else {
                is_key_correct = true;
            }
        }

        if (is_key_correct) {
            PrintAndLogEx(SUCCESS, "Auth1 done with correct key material!");
            PrintAndLogEx(SUCCESS, "Use Auth2 now with M3C and same key");
        } else {
            PrintAndLogEx(INFO, "3DES secret (swapped decryption): %s", sprint_hex(rev_master_key, 16));
            PrintAndLogEx(INFO, "P2c: %s", sprint_hex(p2c, 8));
            PrintAndLogEx(ERR, "Can't decrypt M2C with master secret (P1c != P2c)!");
            PrintAndLogEx(ERR, "Probably wrong keys or wrong decryption method");
        }
    }
    return PM3_SUCCESS;
}

/**
 * Command parser for auth2
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaAuthentication2(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica auth2",
                  "Complete mutual authentication. This command can only be executed subsquent to Auth1\n"
                  _RED_("INCOMPLETE / EXPERIMENTAL COMMAND!!!\n")
                  _RED_("EXPERIMENTAL COMMAND - M2c/P2c will be not checked"),
                  "hf felica auth2 --cc 0102030405060708 --key AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB\n"
                  "hf felica auth2 -i 11100910C11BC407 --cc 0102030405060708 --key AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("i", NULL, "<hex>", "set custom IDm"),
        arg_str0("c", "cc", "<hex>", "M3c card challenge, 8 bytes"),
        arg_str0("k", "key",  "<hex>", "3des M3c decryption key, 16 bytes"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t cc[8] = {0};
    int cclen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), cc, sizeof(cc), &cclen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t key[16] = {0};
    int keylen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 3), key, sizeof(key), &keylen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool verbose = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);
    if (verbose) {
        print_authentication2();
        return PM3_SUCCESS;
    }

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));

    bool custom_IDm = false;

    if (ilen) {
        custom_IDm = true;
        memcpy(data + 2, idm, 8);
    }

    uint16_t datalen = 18; // Length (1), Command ID (1), IDm (8), M4c (8)
    data[0] = (datalen & 0xFF);
    data[1] = 0x12; // Command ID

    if (custom_IDm == false && check_last_idm(data, datalen) == false) {
        return PM3_EINVARG;
    }

    if (cclen) {
        memcpy(data + 16, cc, cclen);
    }

    if (keylen) {
        memcpy(data + 16, key, keylen);
    }


    if (custom_IDm == false && check_last_idm(data, datalen) == false) {
        return PM3_EINVARG;
    }

    // M3c (8) == cc
//    unsigned char m3c[8];  == cc


    mbedtls_des3_context des3_ctx_enc;
    mbedtls_des3_context des3_ctx_dec;

    mbedtls_des3_init(&des3_ctx_enc);
    mbedtls_des3_init(&des3_ctx_dec);

    if (keylen == 16) {

        // set encryption context
        mbedtls_des3_set2key_enc(&des3_ctx_enc, key);

        // Create M4c challenge response with 3DES
        uint8_t rev_key[16];
        reverse_3des_key(key, sizeof(key), rev_key);

        // set decryption context
        mbedtls_des3_set2key_dec(&des3_ctx_dec, rev_key);

        // Assumption: Key swap method used for E2
        PrintAndLogEx(INFO, "3DES Master Secret (encryption)... %s", sprint_hex_inrow(key, sizeof(key)));
        PrintAndLogEx(INFO, "3DES Master Secret (decryption)... %s", sprint_hex_inrow(rev_key, sizeof(rev_key)));
    } else {
        PrintAndLogEx(ERR, "Invalid key length");
        mbedtls_des3_free(&des3_ctx_enc);
        mbedtls_des3_free(&des3_ctx_dec);
        return PM3_EINVARG;
    }

    // Decrypt m3c with reverse_master_key
    unsigned char p3c[8];
    mbedtls_des3_crypt_ecb(&des3_ctx_dec, cc, p3c);
    PrintAndLogEx(INFO, "3DES decrypted M3c = P3c... %s", sprint_hex_inrow(p3c, sizeof(p3c)));

    // Encrypt p3c with master_key
    unsigned char m4c[8];
    mbedtls_des3_crypt_ecb(&des3_ctx_enc, p3c, m4c);
    PrintAndLogEx(INFO, "3DES encrypted M4c......... %s", sprint_hex_inrow(m4c, sizeof(m4c)));

    // free contexts
    mbedtls_des3_free(&des3_ctx_enc);
    mbedtls_des3_free(&des3_ctx_dec);

    // Add M4c Challenge to frame
    memcpy(data + 10, m4c, sizeof(m4c));

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);

    PrintAndLogEx(INFO, "Client Send AUTH2 Frame: %s", sprint_hex(data, datalen));
    clear_and_send_command(flags, datalen, data, 0);

    PacketResponseNG resp;
    if (waitCmdFelica(false, &resp, true) == false) {
        PrintAndLogEx(ERR, "no response from card");
        return PM3_ERFTRANS;
    }

    felica_auth2_response_t auth2_response;
    memcpy(&auth2_response, (felica_auth2_response_t *)resp.data.asBytes, sizeof(felica_auth2_response_t));
    if (auth2_response.code[0] != 0x12) {
        PrintAndLogEx(SUCCESS, "Auth2 response:");
        PrintAndLogEx(SUCCESS, "IDtc.............. %s", sprint_hex(auth2_response.IDtc, sizeof(auth2_response.IDtc)));
        PrintAndLogEx(SUCCESS, "IDi (encrypted)... %s", sprint_hex(auth2_response.IDi, sizeof(auth2_response.IDi)));
        PrintAndLogEx(SUCCESS, "PMi (encrypted)... %s", sprint_hex(auth2_response.PMi, sizeof(auth2_response.PMi)));
    } else {
        PrintAndLogEx(ERR, "Got wrong frame format");
    }
    return PM3_SUCCESS;
}


/**
 * Command parser for wrunencrypted.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaWritePlain(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica wrbl",
                  "Use this command to write block data to authentication-not-required Service.\n\n"
                  " - Mode shall be Mode0.\n"
                  " - Un-/Ssuccessful == Status Flag1 and Flag2",
                  "hf felica wrbl --sn 01 --scl CB10 --bn 01 --ble 8001 -d 0102030405060708090A0B0C0D0E0F10\n"
                  "hf felica wrbl -i 01100910c11bc407 --sn 01 --scl CB10 --bn 01 --ble 8001 -d 0102030405060708090A0B0C0D0E0F10\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("d", "data", "<hex>", "data, 16 hex bytes"),
        arg_str0("i", NULL,   "<hex>", "set custom IDm"),
        arg_str0(NULL, "sn",  "<hex>", "number of service"),
        arg_str0(NULL, "scl", "<hex>", "service code list"),
        arg_str0(NULL, "bn",  "<hex>", "number of block"),
        arg_str0(NULL, "ble", "<hex>", "block list element (def 2|3 bytes)"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t userdata[16] = {0};
    int udlen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), userdata, sizeof(userdata), &udlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t idm[8] = {0};
    int ilen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t sn[1] = {0};
    int snlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 3), sn, sizeof(sn), &snlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t scl[2] = {0};
    int scllen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 4), scl, sizeof(scl), &scllen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t bn[1] = {0};
    int bnlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 5), bn, sizeof(bn), &bnlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t ble[3] = {0};
    int blelen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 6), ble, sizeof(ble), &blelen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool verbose = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    if (verbose) {
        print_number_of_service_constraints();
        print_number_of_block_constraints();
        print_service_code_list_constraints();
        print_block_list_element_constraints();
        print_status_flag1_interpretation();
        print_status_flag2_interpration();
        return PM3_SUCCESS;
    }

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));
    data[0] = 0x20; // Static length
    data[1] = 0x08; // Command ID

    bool custom_IDm = false;
    if (ilen) {
        custom_IDm = true;
        memcpy(data + 2, idm, sizeof(idm));
    }

    // Length (1)
    // Command ID (1)
    // IDm (8)
    // Number of Service (1)
    // Service Code List(2)
    // Number of Block(1)
    // Block List(3)
    // Block Data(16)

    uint16_t datalen = 32; // Length (1), Command ID (1), IDm (8), Number of Service (1), Service Code List(2), Number of Block(1), Block List(3), Block Data(16)
    if (custom_IDm == false && check_last_idm(data, datalen) == false) {
        return PM3_EINVARG;
    }

    if (blelen == 3) {
        datalen++;
    }

    // Number of Service 1, Service Code List 2, Number of Block 1, Block List Element 2, Data 16

    // Service Number 1 byte
    if (snlen) {
        data[10] = sn[0];
    }
    // Service Code List 2 bytes
    if (scllen) {
        data[11] = scl[0];
        data[12] = scl[1];
    }

    // Block number 1 byte
    if (bnlen) {
        data[13] = bn[0];
    }

    // Block List Element 2|3 bytes
    if (blelen) {
        memcpy(data + 14, ble, blelen);
    }

    // data to be written, 16 bytes
    if (udlen) {
        memcpy(data + 14 + blelen, userdata, sizeof(userdata));
    }

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);

    felica_status_response_t wr_noCry_resp;
    if (send_wr_plain(flags, datalen, data, 1, &wr_noCry_resp) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "IDm............ %s", sprint_hex(wr_noCry_resp.frame_response.IDm, sizeof(wr_noCry_resp.frame_response.IDm)));
        PrintAndLogEx(SUCCESS, "Status Flag1... %s", sprint_hex(wr_noCry_resp.status_flags.status_flag1, sizeof(wr_noCry_resp.status_flags.status_flag1)));
        PrintAndLogEx(SUCCESS, "Status Flag2... %s\n", sprint_hex(wr_noCry_resp.status_flags.status_flag2, sizeof(wr_noCry_resp.status_flags.status_flag2)));
        if (wr_noCry_resp.status_flags.status_flag1[0] == 0x00 && wr_noCry_resp.status_flags.status_flag2[0] == 0x00) {
            PrintAndLogEx(SUCCESS, "Writing data successful!");
        } else {
            PrintAndLogEx(FAILED, "Something went wrong! Check status flags.");
        }
    }

    return PM3_SUCCESS;
}

/**
 * Command parser for rdunencrypted.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaReadPlain(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica rdbl",
                  "Use this command to read block data from authentication-not-required Service.\n\n"
                  " - Mode shall be Mode0.\n"
                  " - Successful == block data\n"
                  " - Unsuccessful == Status Flag1 and Flag2",
                  "hf felica rdbl --sn 01 --scl 8B00 --bn 01 --ble 8000\n"
                  "hf felica rdbl --sn 01 --scl 4B18 --bn 01 --ble 8000 -b\n"
                  "hf felica rdbl -i 01100910c11bc407 --sn 01 --scl 8B00 --bn 01 --ble 8000\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("b", NULL, "get all block list elements 00 -> FF"),
        arg_str0("i", NULL, "<hex>", "set custom IDm"),
        arg_lit0("l", "long", "use 3 byte block list element block number"),
        arg_str0(NULL, "sn",  "<hex>", "number of service"),
        arg_str0(NULL, "scl", "<hex>", "service code list"),
        arg_str0(NULL, "bn",  "<hex>", "number of block"),
        arg_str0(NULL, "ble", "<hex>", "block list element (def 2|3 bytes)"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool all_block_list_elements = arg_get_lit(ctx, 1);

    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t long_block_numbers = arg_get_lit(ctx, 3);

    uint8_t sn[1] = {0};
    int snlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 4), sn, sizeof(sn), &snlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t scl[2] = {0};
    int scllen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 5), scl, sizeof(scl), &scllen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t bn[1] = {0};
    int bnlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 6), bn, sizeof(bn), &bnlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t ble[3] = {0};
    int blelen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 7), ble, sizeof(ble), &blelen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool verbose = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);
    if (verbose) {
        print_number_of_service_constraints();
        print_number_of_block_constraints();
        print_service_code_list_constraints();
        print_block_list_element_constraints();
        print_status_flag1_interpretation();
        print_status_flag2_interpration();
        return PM3_SUCCESS;
    }

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));
    data[0] = 0x10; // Static length
    data[1] = 0x06; // Command ID

    bool custom_IDm = false;
    if (ilen) {
        custom_IDm = true;
        memcpy(data + 2, idm, sizeof(idm));
    }

    uint16_t datalen = 16; // Length (1), Command ID (1), IDm (8), Number of Service (1), Service Code List(2), Number of Block(1), Block List(3)
    if (custom_IDm  == false && check_last_idm(data, datalen) == false) {
        return PM3_EINVARG;
    }

    if (long_block_numbers) {
        datalen++;
    }

    // Number of Service 1, Service Code List 2, Number of Block 1, Block List Element 2|3
    if (snlen) {
        data[10] = sn[0];
    }
    if (scllen) {
        data[11] = scl[0];
        data[12] = scl[1];
    }
    if (bnlen) {
        data[13] = bn[0];
    }
    if (blelen)
        memcpy(data + 14, ble, blelen);

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);

    PrintAndLogEx(INFO, "block | data  ");
    PrintAndLogEx(INFO, "------+----------------------------------------");

    // main loop block reads
    if (all_block_list_elements) {

        uint16_t last_blockno = 0xFF;
        if (long_block_numbers) {
            last_blockno = 0xFFFF;
        }

        for (uint16_t i = 0x00; i < last_blockno; i++) {
            data[15] = i;
            felica_read_without_encryption_response_t rd_noCry_resp;
            if ((send_rd_plain(flags, datalen, data, 0, &rd_noCry_resp) == PM3_SUCCESS)) {
                print_rd_plain_response(&rd_noCry_resp, i);
            } else {
                break;
            }
        }
    } else {
        felica_read_without_encryption_response_t rd_noCry_resp;
        if (send_rd_plain(flags, datalen, data, 1, &rd_noCry_resp) == PM3_SUCCESS) {
            print_rd_plain_response(&rd_noCry_resp, bnlen ? bn[0] : 0);
        }
    }
    return PM3_SUCCESS;
}

/**
 * Command parser for rqresponse
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaRequestResponse(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica rqresponse",
                  "Use this command to verify the existence of a card and its Mode.\n"
                  " - current mode of the card is returned",
                  "hf felica rqresponse -i 11100910C11BC407\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("i", NULL, "<hex>", "set custom IDm"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));
    data[0] = 0x0A; // Static length
    data[1] = 0x04; // Command ID

    bool custom_IDm = false;
    if (ilen) {
        custom_IDm = true;
        memcpy(data + 2, idm, sizeof(idm));
    }

    uint8_t datalen = 10; // Length (1), Command ID (1), IDm (8)
    if (!custom_IDm && !check_last_idm(data, datalen)) {
        return PM3_EINVARG;
    }

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);
    clear_and_send_command(flags, datalen, data, 0);

    PacketResponseNG resp;
    if (waitCmdFelica(false, &resp, true) == false) {
        PrintAndLogEx(ERR, "Got no response from card");
        return PM3_ERFTRANS;
    }

    felica_request_request_response_t rq_response;
    memcpy(&rq_response, (felica_request_request_response_t *)resp.data.asBytes, sizeof(felica_request_request_response_t));
    if (rq_response.frame_response.IDm[0] != 0) {
        PrintAndLogEx(SUCCESS, "Request Response");
        PrintAndLogEx(SUCCESS, "IDm...... %s", sprint_hex(rq_response.frame_response.IDm, sizeof(rq_response.frame_response.IDm)));
        PrintAndLogEx(SUCCESS, "  Mode... %s", sprint_hex(rq_response.mode, sizeof(rq_response.mode)));
    }

    return PM3_SUCCESS;
}

/**
 * Command parser for rqspecver
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaRequestSpecificationVersion(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica rqspecver",
                  "Use this command to acquire the version of card OS.\n"
                  "Response:\n"
                  " - Format version: Fixed value 00h. Provided only if Status Flag1 = 00h\n"
                  " - Basic version: Each value of version is expressed in BCD notation. Provided only if Status Flag1 = 00h\n"
                  " - Number of Option: value = 0: AES card, value = 1: AES/DES card. Provided only if Status Flag1 = 00h\n"
                  " - Option version list: Provided only if Status Flag1 = 00h\n"
                  "     - AES card: not added\n"
                  "     - AES/DES card: DES option version is added - BCD notation",

                  "hf felica rqspecver\n"
                  "hf felica rqspecver -r 0001\n"
                  "hf felica rqspecver -i 11100910C11BC407 \n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("i", NULL, "<hex>", "set custom IDm"),
        arg_str0("r", NULL, "<hex>", "set custom reserve"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t reserved[2] = {0, 0};
    int rlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), reserved, sizeof(reserved), &rlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool verbose = arg_get_lit(ctx, 3);
    if (verbose) {
        print_status_flag1_interpretation();
        print_status_flag2_interpration();
    }
    CLIParserFree(ctx);

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));
    data[0] = 0x0C; // Static length
    data[1] = 0x3C; // Command ID

    bool custom_IDm = false;

    // add custom idm
    if (ilen) {
        custom_IDm = true;
        memcpy(data + 2, idm, sizeof(idm));
    }

    // add custom reserved
    if (rlen) {
        memcpy(data + 10, reserved, sizeof(reserved));
    } else {
        data[10] = 0x00; // Reserved Value
        data[11] = 0x00; // Reserved Value
    }

    uint16_t datalen = 12; // Length (1), Command ID (1), IDm (8), Reserved (2)
    if (custom_IDm == false && check_last_idm(data, datalen) == false) {
        return PM3_EINVARG;
    }

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);

    clear_and_send_command(flags, datalen, data, 0);

    PacketResponseNG resp;
    if (waitCmdFelica(false, &resp, true) == false) {
        PrintAndLogEx(FAILED, "Got no response from card");
        return PM3_ERFTRANS;
    }

    felica_request_spec_response_t spec_response;
    memcpy(&spec_response, (felica_request_spec_response_t *)resp.data.asBytes, sizeof(felica_request_spec_response_t));

    if (spec_response.frame_response.IDm[0] != 0) {
        PrintAndLogEx(SUCCESS, "Got Request Response");
        PrintAndLogEx(SUCCESS, "IDm............ %s", sprint_hex(spec_response.frame_response.IDm, sizeof(spec_response.frame_response.IDm)));
        PrintAndLogEx(SUCCESS, "Status Flag1... %s", sprint_hex(spec_response.status_flags.status_flag1, sizeof(spec_response.status_flags.status_flag1)));
        PrintAndLogEx(SUCCESS, "Status Flag2... %s", sprint_hex(spec_response.status_flags.status_flag2, sizeof(spec_response.status_flags.status_flag2)));

        if (spec_response.status_flags.status_flag1[0] == 0) {
            PrintAndLogEx(SUCCESS, "Format Version..... %s", sprint_hex(spec_response.format_version, sizeof(spec_response.format_version)));
            PrintAndLogEx(SUCCESS, "Basic Version...... %s", sprint_hex(spec_response.basic_version, sizeof(spec_response.basic_version)));
            PrintAndLogEx(SUCCESS, "Number of Option... %s", sprint_hex(spec_response.number_of_option, sizeof(spec_response.number_of_option)));
            if (spec_response.number_of_option[0] == 1) {
                PrintAndLogEx(SUCCESS, "Option Version List...");
                for (int i = 0; i < spec_response.number_of_option[0]; i++) {
                    PrintAndLogEx(SUCCESS, "  - %s", sprint_hex(spec_response.option_version_list + i * 2, 2));
                }
            }
        }
    }
    return PM3_SUCCESS;
}

/**
 * Command parser for resetmode
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaResetMode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica resetmode",
                  "Use this command to reset Mode to Mode 0.",
                  "hf felica resetmode\n"
                  "hf felica resetmode -r 0001\n"
                  "hf felica resetmode -i 11100910C11BC407 \n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("i", NULL, "<hex>", "set custom IDm"),
        arg_str0("r", NULL, "<hex>", "set custom reserve"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t reserved[2] = {0, 0};
    int rlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), reserved, sizeof(reserved), &rlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool verbose = arg_get_lit(ctx, 3);
    if (verbose) {
        print_status_flag1_interpretation();
        print_status_flag2_interpration();
    }
    CLIParserFree(ctx);

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));
    data[0] = 0x0C; // Static length
    data[1] = 0x3E; // Command ID

    bool custom_IDm = false;

    if (ilen) {
        custom_IDm = true;
        memcpy(data + 2, idm, 8);
    }
    if (rlen) {
        memcpy(data + 10, reserved, 2);
    } else {
        data[10] = 0x00; // Reserved Value
        data[11] = 0x00; // Reserved Value
    }

    uint16_t datalen = 12; // Length (1), Command ID (1), IDm (8), Reserved (2)
    if (custom_IDm == false && check_last_idm(data, datalen) == false) {
        return PM3_EINVARG;
    }

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);

    clear_and_send_command(flags, datalen, data, 0);

    PacketResponseNG resp;
    if (waitCmdFelica(false, &resp, true) == false) {
        PrintAndLogEx(ERR, "Got no response from card");
        return PM3_ERFTRANS;
    }

    felica_status_response_t reset_mode_response;
    memcpy(&reset_mode_response, (felica_status_response_t *)resp.data.asBytes, sizeof(felica_status_response_t));
    if (reset_mode_response.frame_response.IDm[0] != 0) {
        PrintAndLogEx(SUCCESS, "Request Response");
        PrintAndLogEx(SUCCESS, "IDm............ %s", sprint_hex(reset_mode_response.frame_response.IDm, sizeof(reset_mode_response.frame_response.IDm)));
        PrintAndLogEx(SUCCESS, "Status Flag1... %s", sprint_hex(reset_mode_response.status_flags.status_flag1, sizeof(reset_mode_response.status_flags.status_flag1)));
        PrintAndLogEx(SUCCESS, "Status Flag2... %s", sprint_hex(reset_mode_response.status_flags.status_flag2, sizeof(reset_mode_response.status_flags.status_flag2)));
    }
    return PM3_SUCCESS;
}

/**
 * Command parser for rqsyscode
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaRequestSystemCode(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica rqsyscode",
                  "Use this command to acquire System Code registered to the card."
                  "  - if a card is divided into more than one System, \n"
                  "    this command acquires System Code of each System existing in the card.",
                  "hf felica rqsyscode\n"
                  "hf felica rqsyscode -i 11100910C11BC407 \n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("i", NULL, "<hex>", "set custom IDm"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    CLIParserFree(ctx);


    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));
    data[0] = 0x0A; // Static length
    data[1] = 0x0C; // Command ID

    bool custom_IDm = false;
    if (ilen) {
        custom_IDm = true;
        memcpy(data + 2, idm, sizeof(idm));
    }

    uint16_t datalen = 10; // Length (1), Command ID (1), IDm (8)
    if (custom_IDm == false && check_last_idm(data, datalen) == false) {
        return PM3_EINVARG;
    }

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);

    clear_and_send_command(flags, datalen, data, 0);

    PacketResponseNG resp;
    if (waitCmdFelica(false, &resp, true) == false) {
        PrintAndLogEx(ERR, "Got no response from card");
        return PM3_ERFTRANS;
    }

    felica_syscode_response_t rq_syscode_response;
    memcpy(&rq_syscode_response, (felica_syscode_response_t *)resp.data.asBytes, sizeof(felica_syscode_response_t));

    if (rq_syscode_response.frame_response.IDm[0] != 0) {
        PrintAndLogEx(SUCCESS, "Request Response");
        PrintAndLogEx(SUCCESS, "IDm... %s", sprint_hex(rq_syscode_response.frame_response.IDm, sizeof(rq_syscode_response.frame_response.IDm)));
        PrintAndLogEx(SUCCESS, "  - Number of Systems: %s", sprint_hex(rq_syscode_response.number_of_systems, sizeof(rq_syscode_response.number_of_systems)));
        PrintAndLogEx(SUCCESS, "  - System Codes: enumerated in ascending order starting from System 0.");

        for (int i = 0; i < rq_syscode_response.number_of_systems[0]; i++) {
            PrintAndLogEx(SUCCESS, "    - %s", sprint_hex(rq_syscode_response.system_code_list + i * 2, 2));
        }
    }

    return PM3_SUCCESS;
}

/**
 * Command parser for rqservice.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica dump",
                  "Dump all existing Area Code and Service Code.\n"
                  "Only works on services that do not require authentication yet.\n",
                  "hf felica dump");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "no-auth", "read public services"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // bool no_auth = arg_get_lit(ctx, 1);

    uint8_t data_service_dump[PM3_CMD_DATA_SIZE] = {0};
    data_service_dump[0] = 0x0C;
    data_service_dump[1] = 0x0A;
    uint16_t service_datalen = 12;
    if (!check_last_idm(data_service_dump, service_datalen))
        return PM3_EINVARG;

    uint8_t data_block_dump[PM3_CMD_DATA_SIZE] = {0};
    data_block_dump[0] = 0x10; // Static length
    data_block_dump[1] = 0x06; // unauth read block command
    data_block_dump[10] = 0x01; // read one service at a time
    data_block_dump[13] = 0x01; // read one block at a time
    data_block_dump[14] = 0x80; // block list element first byte
    uint16_t block_datalen = 16; // Length (1), Command ID (1), IDm (8), Number of Service (1), Service Code List(2), Number of Block(1), Block List(3)
    if (!check_last_idm(data_block_dump, block_datalen)) {
        return PM3_EINVARG;
    }

    uint8_t flags = FELICA_APPEND_CRC | FELICA_RAW;

    uint16_t cursor = 0x0000;

    felica_service_dump_response_t resp;

    while (true) {

        data_service_dump[10] = cursor & 0xFF;
        data_service_dump[11] = cursor >> 8;

        if (send_dump_sv_plain(flags, service_datalen, data_service_dump, 0,
                               &resp, false) != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "No response at cursor 0x%04X", cursor);
            return PM3_ERFTRANS;
        }
        if (resp.frame_response.cmd_code[0] != 0x0B) {
            PrintAndLogEx(FAILED, "Bad response cmd 0x%02X @ 0x%04X.",
                          resp.frame_response.cmd_code[0], cursor);
            PrintAndLogEx(INFO, "This is a normal signal issue. Please try again.");
            PrintAndLogEx(INFO, "If the issue persists, move the card around and check signal strength. FeliCa can be hard to keep in field.");
            return PM3_ERFTRANS;
        }
        uint8_t len = resp.frame_response.length[0];
        uint16_t node_code = resp.payload[0] | (resp.payload[1] << 8);
        if (node_code == 0xFFFF) break;
        char attrib_str[64] = "";
        switch (len) {
            case 0x0E:
                break;
            case 0x0C: {
                uint8_t attribute = node_code & 0x3F;
                bool is_public = (attribute & FELICA_SERVICE_ATTRIBUTE_UNAUTH_READ) != 0;
                strcat(attrib_str, is_public ? "| Public  " : "| Private ");

                bool is_purse = (attribute & FELICA_SERVICE_ATTRIBUTE_PURSE) != 0;
                // Subfield bitwise attributes are applicable depending on is PURSE or not

                if (is_purse) {
                    strcat(attrib_str, "| Purse  |");
                    switch ((attribute & FELICA_SERVICE_ATTRIBUTE_PURSE_SUBFIELD) >> 1) {
                        case 0:
                            strcat(attrib_str, " Direct     |");
                            break;
                        case 1:
                            strcat(attrib_str, " Cashback   |");
                            break;
                        case 2:
                            strcat(attrib_str, " Decrement  |");
                            break;
                        case 3:
                            strcat(attrib_str, " Read Only  |");
                            break;
                        default:
                            strcat(attrib_str, " Unknown    |");
                            break;
                    }
                } else {
                    bool is_random = (attribute & FELICA_SERVICE_ATTRIBUTE_RANDOM_ACCESS) != 0;
                    strcat(attrib_str, is_random ? "| Random |" : "| Cyclic |");
                    bool is_readonly = (attribute & FELICA_SERVICE_ATTRIBUTE_READ_ONLY) != 0;
                    strcat(attrib_str, is_readonly ? " Read Only  |" : " Read/Write |");
                }

                PrintAndLogEx(INFO, "Service %04X %s", node_code, attrib_str);

                if (is_public) {
                    // dump blocks here
                    PrintAndLogEx(INFO, " block | data  ");
                    PrintAndLogEx(INFO, "-------+----------------------------------------");

                    data_block_dump[11] = resp.payload[0]; // convert service code to little endian
                    data_block_dump[12] = resp.payload[1];

                    uint16_t last_blockno = 0xFF;
                    for (uint16_t i = 0x00; i < last_blockno; i++) {
                        data_block_dump[15] = i;
                        felica_read_without_encryption_response_t rd_noCry_resp;
                        if ((send_rd_plain(flags, block_datalen, data_block_dump, 0, &rd_noCry_resp) == PM3_SUCCESS)) {
                            if (rd_noCry_resp.status_flags.status_flag1[0] == 0 && rd_noCry_resp.status_flags.status_flag2[0] == 0) {
                                print_rd_plain_response(&rd_noCry_resp, i);
                            } else {
                                break; // no more blocks to read
                            }
                        } else {
                            break;
                        }
                    }
                }
                break;
            }
            default:
                PrintAndLogEx(FAILED, "Unexpected length 0x%02X @ 0x%04X",
                              len, cursor);
                return PM3_ERFTRANS;
        }
        cursor++;
        if (cursor == 0) break;
    }

    PrintAndLogEx(SUCCESS, "Unauth service dump complete.");
    return PM3_SUCCESS;
}


/**
 * Command parser for rqservice.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaRequestService(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica rqservice",
                  "Use this command to verify the existence of Area and Service, and to acquire Key Version:\n"
                  "       - When the specified Area or Service exists, the card returns Key Version.\n"
                  "       - When the specified Area or Service does not exist, the card returns FFFFh as Key Version.\n"
                  "For Node Code List of a command packet, Area Code or Service Code of the target\n"
                  "of acquisition of Key Version shall be enumerated in Little Endian format.\n"
                  "If Key Version of System is the target of acquisition, FFFFh shall be specified\n"
                  "in the command packet.",
                  "hf felcia rqservice --node 01 --code FFFF\n"
                  "hf felcia rqservice -a --code FFFF\n"
                  "hf felica rqservice -i 011204126417E405 --node 01 --code FFFF"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "all", "auto node number mode, iterates through all nodes 1 < n < 32"),
        arg_str0("n", "node", "<hex>", "Number of Node"),
        arg_str0("c", "code", "<hex>", "Node Code List (little endian)"),
        arg_str0("i", "idm", "<hex>", "use custom IDm"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool all_nodes = arg_get_lit(ctx, 1);

    uint8_t node[1] = {0};
    int nlen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), node, sizeof(node), &nlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t code[2] = {0, 0};
    int clen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 3), code, sizeof(code), &clen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t idm[8] = {0};
    int ilen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 4), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    CLIParserFree(ctx);

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));

    bool custom_IDm = false;

    if (ilen) {
        custom_IDm = true;
        memcpy(data + 2, idm, 8);
    }

    if (all_nodes == false) {
        // Node Number
        if (nlen == 1) {
            memcpy(data + 10, node, sizeof(node));
        }

        // code
        if (clen == 2) {
            memcpy(data + 11, code, sizeof(code));
        }
    }

    uint8_t datalen = 13; // length (1) + CMD (1) + IDm(8) + Node Number (1) + Node Code List (2)

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);
    if (custom_IDm) {
        flags |= FELICA_NO_SELECT;
    }

    // Todo activate once datalen isn't hardcoded anymore...
    if (custom_IDm == false && check_last_idm(data, datalen) == false) {
        return PM3_EINVARG;
    }

    data[0] = (datalen & 0xFF);
    data[1] = 0x02; // Service Request Command ID
    if (all_nodes) {

        // send 32 calls
        for (uint8_t i = 1; i < 32; i++) {
            data[10] = i;
            send_request_service(flags, datalen, data, 1);
        }

    } else {
        send_request_service(flags, datalen, data, 1);
    }

    return PM3_SUCCESS;
}

/**
 * Command parser for rqservice.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaDumpServiceArea(const char *Cmd) {
    /* -- CLI boilerplate (unchanged) ------------------------------- */
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica scsvcode",
                  "Dump all existing Area Code and Service Code.\n",
                  "hf felica scsvcode");
    void *argtable[] = { arg_param_begin, arg_param_end };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    /* -- build static part of Search-Service frame ---------------- */
    uint8_t data[PM3_CMD_DATA_SIZE] = {0};
    data[0] = 0x0C;                      /* LEN               */
    data[1] = 0x0A;                      /* CMD = 0x0A         */
    uint16_t datalen = 12;               /* LEN + CMD + IDm + cursor */

    if (!check_last_idm(data, datalen))
        return PM3_EINVARG;

    PrintAndLogEx(HINT, "Area and service codes are printed in network order.");
    PrintAndLogEx(INFO, "┌───────────────────────────────────────────────");

    uint8_t flags = FELICA_APPEND_CRC | FELICA_RAW;

    /* -- traversal state ------------------------------------------ */
    uint16_t cursor = 0x0000;
    uint16_t area_end_stack[8] = {0xFFFF};   /* root “end” = 0xFFFF */
    int      depth = 0;                      /* current stack depth */

    felica_service_dump_response_t resp;

    while (true) {

        /* insert cursor LE */
        data[10] = cursor & 0xFF;
        data[11] = cursor >> 8;

        if (send_dump_sv_plain(flags, datalen, data, 0,
                               &resp, false) != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "No response at cursor 0x%04X", cursor);
            return PM3_ERFTRANS;
        }
        if (resp.frame_response.cmd_code[0] != 0x0B) {
            PrintAndLogEx(FAILED, "Bad response cmd 0x%02X @ 0x%04X.",
                          resp.frame_response.cmd_code[0], cursor);
            PrintAndLogEx(INFO, "This is a normal signal issue. Please try again.");
            PrintAndLogEx(INFO, "If the issue persists, move the card around and check signal strength. FeliCa can be hard to keep in field.");
            return PM3_ERFTRANS;
        }

        uint8_t len = resp.frame_response.length[0];
        uint16_t node_code = resp.payload[0] | (resp.payload[1] << 8);      /* LE for traversal */
        uint16_t node_code_net = (resp.payload[0] << 8) | resp.payload[1];   /* BE for display */
        uint16_t node_number = node_code >> 6;                               /* upper 10 bits in host order */

        if (node_code == 0xFFFF) break;          /* end-marker */

        /* pop finished areas */
        while (depth && node_code > area_end_stack[depth]) depth--;


        /* ----- compose nice prefix ------------------------------------ */
        char prefix[64] = "";
        for (int i = 1; i < depth; i++) {
            bool more_siblings = (cursor < area_end_stack[i]);
            strcat(prefix, more_siblings ? "│   " : "    ");
        }
        /* decide glyph for this line (areas always use └──) */
        const char *line_glyph = "├── ";
        strcat(prefix, line_glyph);

        /* ----- print --------------------------------------------------- */
        if (len == 0x0E) {                          /* AREA node */
            uint16_t end_code = resp.payload[2] | (resp.payload[3] << 8);
            uint16_t end_number = end_code >> 6;
            PrintAndLogEx(INFO, "%sAREA_%02X%02X%02X%02X (%u-%u)", prefix,
                          resp.payload[0], resp.payload[1], resp.payload[2], resp.payload[3],
                          node_number, end_number);

            if (depth < 7) {
                area_end_stack[++depth] = end_code;
            }
        } else if (len == 0x0C) {                                /* SERVICE */
            PrintAndLogEx(INFO, "%sSVC_%04X (%u)", prefix, node_code_net, node_number);
        } else {
            PrintAndLogEx(FAILED, "Unexpected length 0x%02X @ 0x%04X",
                          len, cursor);
            return PM3_ERFTRANS;
        }
        cursor++;
        if (cursor == 0) break; /* overflow safety */
    }

    /* draw closing bar └─┴─... based on final depth */
    char bar[128];                 /* large enough for depth ≤ 7 */
    size_t pos = 0;

    /* leading corner */
    pos += snprintf(bar + pos, sizeof(bar) - pos, "└");

    /* one segment per level-1 */
    for (int i = 0; i < depth - 1 && pos < sizeof(bar); i++)
        pos += snprintf(bar + pos, sizeof(bar) - pos, "───┴");

    /* tail */
    snprintf(bar + pos, sizeof(bar) - pos, "───────────────────────");

    PrintAndLogEx(INFO, "%s", bar);


    PrintAndLogEx(SUCCESS, "Service code and area dump complete.");
    return PM3_SUCCESS;
}

static int CmdHFFelicaSniff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica sniff",
                  "Collect data from the field and save into command buffer.\n"
                  "Buffer accessible from `hf felica list`",
                  "hf felica sniff\n"
                  "hf felica sniff -s 10 -t 19"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("s", "samples", "<dec>", "samples to skip"),
        arg_u64_0("t", "trig", "<dec>", "triggers to skip "),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct p {
        uint32_t samples;
        uint32_t triggers;
    } PACKED payload;

    payload.samples = arg_get_u32_def(ctx, 1, 10);
    payload.triggers = arg_get_u32_def(ctx, 2, 5000);
    CLIParserFree(ctx);

    if (payload.samples > 9999) {
        payload.samples = 9999;
        PrintAndLogEx(INFO, "Too large samples to skip value, using max value 9999");
    }

    if (payload.triggers  > 9999) {
        payload.triggers  = 9999;
        PrintAndLogEx(INFO, "Too large trigger to skip value, using max value 9999");
    }


    PrintAndLogEx(INFO, "Sniff Felica,  getting first %" PRIu32 " frames, skipping after %" PRIu32 " triggers", payload.samples,   payload.triggers);
    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to abort sniffing");
    clearCommandBuffer();
    SendCommandNG(CMD_HF_FELICA_SNIFF, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;

    for (;;) {
        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, "\naborted via keyboard!");
            msleep(300);
            break;
        }

        if (WaitForResponseTimeout(CMD_HF_FELICA_SNIFF, &resp, 1000)) {
            if (resp.status == PM3_EOPABORTED) {
                PrintAndLogEx(DEBUG, "Button pressed, user aborted");
                break;
            }
        }
    }

    PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf felica list") "` to view");
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

// uid  hex
static int CmdHFFelicaSimLite(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica litesim",
                  "Emulating ISO/18092 FeliCa Lite tag",
                  "hf felica litesim -u 1122334455667788"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("u", "uid", "<hex>", "UID/NDEF2 8 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int uid_len = 0;
    struct p {
        uint8_t uid[8];
    } PACKED payload;
    CLIGetHexWithReturn(ctx, 1, payload.uid, &uid_len);
    CLIParserFree(ctx);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to abort simulation");

    clearCommandBuffer();
    SendCommandNG(CMD_HF_FELICALITE_SIMULATE, payload.uid, sizeof(payload));
    PacketResponseNG resp;

    for (;;) {
        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, "\naborted via keyboard!");
            msleep(300);
            break;
        }

        if (WaitForResponseTimeout(CMD_HF_FELICALITE_SIMULATE, &resp, 1000)) {
            if (resp.status == PM3_EOPABORTED) {
                PrintAndLogEx(DEBUG, "Button pressed, user aborted");
                break;
            }
        }
    }

    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

static int felica_make_block_list(uint16_t *out, const uint8_t *blk_numbers, const size_t length) {
    if (length > 4) {
        PrintAndLogEx(ERR, "felica_make_block_list: exceeds max size");
        return PM3_EINVARG;
    }

    uint16_t tmp[4];
    memset(tmp, 0, sizeof(tmp));

    for (size_t i = 0; i < length; i++) {
        tmp[i] = (uint16_t)(blk_numbers[i] << 8) | 0x80;
    }
    memcpy(out, tmp, length * sizeof(uint16_t));

    return PM3_SUCCESS;
}

static int read_without_encryption(
    const uint8_t *idm,
    const uint8_t num,
    const uint8_t *blk_numbers,
    uint8_t *out,
    uint16_t *n) {

    felica_read_request_haeder_t request = {
        .command_code = { 0x06 },
        .number_of_service = { 1 },
        .service_code_list = { 0x00B },
        .number_of_block = { num },
    };
    memcpy(request.IDm, idm, sizeof(request.IDm));

    uint16_t svc[num];
    int ret = felica_make_block_list(svc, blk_numbers, num);
    if (ret) {
        return PM3_EINVARG;
    }

    size_t hdr_size = sizeof(request);
    uint16_t size = hdr_size + sizeof(svc) + 1;
    *n = size;

    memcpy(out, &(uint8_t) { size }, sizeof(uint8_t));
    memcpy(out + 1, &request, hdr_size);
    memcpy(out + hdr_size + 1, &svc, sizeof(svc));

    return PM3_SUCCESS;
}

static bool check_write_req_data(const felica_write_request_haeder_t *hdr, const uint8_t datalen) {
    if (!hdr || !datalen)
        return false;

    uint8_t num = *(hdr->number_of_block);
    if (num != 1 && num != 2)
        return false;

    // Check Block data size
    if (num * 16 != datalen)
        return false;

    return true;
}

static int write_without_encryption(
    const uint8_t *idm,
    uint8_t num,
    uint8_t *blk_numbers,
    const uint8_t *data,
    size_t datalen,
    uint8_t *out,
    uint16_t *n) {

    felica_write_request_haeder_t hdr = {
        .command_code = { 0x08 },
        .number_of_service = { 1 },
        .service_code_list = { 0x009 },
        .number_of_block = { num },
    };
    memcpy(hdr.IDm, idm, sizeof(hdr.IDm));

    uint8_t dl = (uint8_t)(datalen);

    if (check_write_req_data(&hdr, dl) == false) {
        PrintAndLogEx(FAILED, "invalid request");
        return PM3_EINVARG;
    }

    uint16_t blk[num];
    int ret = felica_make_block_list(blk, blk_numbers, num);
    if (ret) {
        return PM3_EINVARG;
    }


    size_t hdr_size = sizeof(hdr);
    size_t offset = hdr_size + (num * 2) + 1;

    uint8_t size = hdr_size + sizeof(blk) + dl + 1;
    *n = size;

    memcpy(out, &(uint8_t) { size }, sizeof(uint8_t));
    memcpy(out + 1, &hdr, hdr_size);
    memcpy(out + hdr_size + 1, &blk, sizeof(blk));
    memcpy(out + offset, data, dl);

    return PM3_SUCCESS;
}

static int parse_multiple_block_data(const uint8_t *data, const size_t datalen, uint8_t *out, uint8_t *outlen) {
    if (datalen < 3) {
        PrintAndLogEx(ERR, "\ndata size must be at least 3 bytes");
        return PM3_EINVARG;
    }

    felica_status_response_t res;
    memcpy(&res, data, sizeof(res));

    uint8_t empty[8] = {0};

    if (!memcmp(res.frame_response.IDm, empty, sizeof(empty))) {
        PrintAndLogEx(ERR, "internal error");
        return PM3_ERFTRANS;
    }


    if (res.status_flags.status_flag1[0] != 0x00 || res.status_flags.status_flag2[0] != 0x00) {
        PrintAndLogEx(ERR, "error status");
        return PM3_ERFTRANS;
    }

    size_t res_size = sizeof(res);

    uint8_t num = 0;
    memcpy(&num, data + res_size, sizeof(uint8_t));
    res_size++;

    memcpy(out, data + res_size, num * FELICA_BLK_SIZE);

    if (outlen) {
        *outlen = num * FELICA_BLK_SIZE;
    }

    return PM3_SUCCESS;
}

static int send_rd_multiple_plain(uint8_t flags, uint16_t datalen, uint8_t *data, uint8_t *out) {
    clear_and_send_command(flags, datalen, data, false);
    PacketResponseNG res;
    if (waitCmdFelica(false, &res, false) == false) {
        PrintAndLogEx(ERR, "\nGot no response from card");
        return PM3_ERFTRANS;
    }

    uint8_t block_data[FELICA_BLK_SIZE * 4];
    memset(block_data, 0, sizeof(block_data));

    uint8_t outlen = 0;

    int ret = parse_multiple_block_data(res.data.asBytes, sizeof(res.data.asBytes), block_data, &outlen);
    if (ret) {
        return PM3_ERFTRANS;
    }

    memcpy(out, block_data, outlen);

    return PM3_SUCCESS;
}

static int felica_auth_context_init(
    mbedtls_des3_context *ctx,
    const uint8_t *rc,
    const size_t rclen,
    const uint8_t *key,
    const size_t keylen,
    felica_auth_context_t *auth_ctx) {

    int ret = PM3_SUCCESS;

    uint8_t rev_rc[16], rev_key[16];
    uint8_t encrypted_sk[16], rev_sk[16];
    uint8_t iv[8] = {0};

    if (!ctx || !auth_ctx || rclen != 16 || keylen != 16) {
        PrintAndLogEx(ERR, "\nfelica_auth_context_init: invalid parameters");
        return PM3_EINVARG;
    }

    SwapEndian64ex(rc, sizeof(rev_rc), 8, rev_rc);
    memcpy(auth_ctx->random_challenge, rev_rc, sizeof(auth_ctx->random_challenge));

    SwapEndian64ex(key, sizeof(rev_key), 8, rev_key);

    if (mbedtls_des3_set2key_enc(ctx, rev_key) != 0) {
        ret = PM3_ECRYPTO;
        goto cleanup;
    }

    if (mbedtls_des3_crypt_cbc(ctx, MBEDTLS_DES_ENCRYPT, 16, iv, rev_rc, encrypted_sk) != 0) {
        ret = PM3_ECRYPTO;
        goto cleanup;
    }

    SwapEndian64ex(encrypted_sk, sizeof(encrypted_sk), 8, rev_sk);

    memcpy(auth_ctx->session_key, rev_sk, sizeof(auth_ctx->session_key));

cleanup:
    mbedtls_platform_zeroize(rev_rc, sizeof(rev_rc));
    mbedtls_platform_zeroize(rev_key, sizeof(rev_key));
    mbedtls_platform_zeroize(iv, sizeof(iv));
    mbedtls_platform_zeroize(encrypted_sk, sizeof(encrypted_sk));
    mbedtls_platform_zeroize(rev_sk, sizeof(rev_sk));

    return ret;
}

static void felica_auth_context_free(felica_auth_context_t *auth_ctx) {
    if (!auth_ctx) {
        return;
    }

    mbedtls_platform_zeroize(auth_ctx->session_key, sizeof(auth_ctx->session_key));
    mbedtls_platform_zeroize(auth_ctx->random_challenge, sizeof(auth_ctx->random_challenge));
}

static int felica_generate_mac(
    mbedtls_des3_context *ctx,
    const felica_auth_context_t *auth_ctx,
    const uint8_t *initialize_block,
    const uint8_t *block_data,
    const size_t length,
    bool use_read_key,
    uint8_t *mac) {

    int ret = PM3_SUCCESS;

    uint8_t rev_sk[FELICA_BLK_SIZE];
    uint8_t iv[8], rev_block[8], out[8];

    if (!ctx || !auth_ctx || !initialize_block || !block_data || !mac) {
        return PM3_EINVARG;
    }

    if (length % FELICA_BLK_HALF != 0) {
        return PM3_EINVARG;
    }

    uint8_t sk[FELICA_BLK_SIZE];

    if (use_read_key == false) {
        memcpy(sk, auth_ctx->session_key + 8, 8);
        memcpy(sk + 8, auth_ctx->session_key, 8);
    } else {
        memcpy(sk, auth_ctx->session_key, sizeof(auth_ctx->session_key));
    }

    SwapEndian64ex(sk, sizeof(sk), 8, rev_sk);

    memcpy(iv, auth_ctx->random_challenge, sizeof(iv));

    SwapEndian64ex(initialize_block, sizeof(rev_block), 8, rev_block);

    if (mbedtls_des3_set2key_enc(ctx, rev_sk) != 0) {
        ret = PM3_ECRYPTO;
        goto cleanup;
    }

    for (int i = 0; i <= length; i += 8) {
        if (mbedtls_des3_crypt_cbc(ctx, MBEDTLS_DES_ENCRYPT, sizeof(rev_block), iv, rev_block, out) != 0) {
            ret = PM3_ECRYPTO;
            goto cleanup;
        }
        memcpy(iv, out, sizeof(iv));
        SwapEndian64ex(block_data + i, 8, 8, rev_block);
    }

    SwapEndian64ex(out, FELICA_BLK_HALF, 8, mac);

cleanup:
    mbedtls_platform_zeroize(sk, sizeof(sk));
    mbedtls_platform_zeroize(rev_sk, sizeof(rev_sk));
    mbedtls_platform_zeroize(iv, sizeof(iv));
    mbedtls_platform_zeroize(out, sizeof(out));
    mbedtls_platform_zeroize(rev_block, sizeof(rev_block));

    return ret;
}

static int write_with_mac(
    mbedtls_des3_context *ctx,
    const felica_auth_context_t *auth_ctx,
    const uint8_t *counter,
    const uint8_t blk_number,
    const uint8_t *block_data,
    uint8_t *out) {

    uint8_t initialize_blk[FELICA_BLK_HALF];
    memset(initialize_blk, 0, sizeof(initialize_blk));

    uint8_t wcnt[3];
    memcpy(wcnt, counter, 3);

    memcpy(initialize_blk, wcnt, sizeof(wcnt));
    initialize_blk[4] = blk_number;
    initialize_blk[6] = 0x91;

    uint8_t mac[FELICA_BLK_HALF];

    int ret = felica_generate_mac(ctx, auth_ctx, initialize_blk, block_data, FELICA_BLK_SIZE, false, mac);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    uint8_t payload[FELICA_BLK_SIZE * 2];
    memset(payload, 0, sizeof(payload));

    memcpy(payload, block_data, FELICA_BLK_SIZE);
    memcpy(payload + FELICA_BLK_SIZE, mac, sizeof(mac));
    memcpy(payload + FELICA_BLK_SIZE + sizeof(mac), wcnt, sizeof(wcnt));

    memcpy(out, payload, sizeof(payload));

    return PM3_SUCCESS;
}

static int felica_internal_authentication(
    const uint8_t *idm,
    const uint8_t *rc,
    const size_t rclen,
    mbedtls_des3_context *ctx,
    const felica_auth_context_t *auth_ctx,
    bool verbose) {

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));

    uint8_t blk_numbers[1] = {FELICA_BLK_NUMBER_RC};

    uint16_t datalen = 0;

    int ret = write_without_encryption(idm, (uint8_t)sizeof(blk_numbers), blk_numbers, rc, rclen, data, &datalen);
    if (ret) {
        return PM3_ERFTRANS;
    }

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW | FELICA_NO_DISCONNECT);

    felica_status_response_t res;
    if (send_wr_plain(flags, datalen, data, false, &res) != PM3_SUCCESS) {
        return PM3_ERFTRANS;
    }

    if (res.status_flags.status_flag1[0] != 0x00 && res.status_flags.status_flag2[0] != 0x00) {
        PrintAndLogEx(ERR, "\nError RC Write");
        return PM3_ERFTRANS;
    }

    memset(data, 0, sizeof(data));

    uint8_t blk_numbers2[2] = {FELICA_BLK_NUMBER_ID, FELICA_BLK_NUMBER_MACA};

    ret = read_without_encryption(idm, (uint8_t)sizeof(blk_numbers2), blk_numbers2, data, &datalen);
    if (ret) {
        return PM3_ERFTRANS;
    }

    uint8_t pd[FELICA_BLK_SIZE * sizeof(blk_numbers2)];
    memset(pd, 0, sizeof(pd));

    ret = send_rd_multiple_plain(flags, datalen, data, pd);
    if (ret) {
        return PM3_ERFTRANS;
    }

    uint8_t id_blk[FELICA_BLK_SIZE];
    memcpy(id_blk, pd, FELICA_BLK_SIZE);

    uint8_t mac_blk[FELICA_BLK_SIZE];
    memcpy(mac_blk, pd + FELICA_BLK_SIZE, FELICA_BLK_SIZE);

    uint8_t initialize_blk[8];
    memset(initialize_blk, 0xFF, sizeof(initialize_blk));

    initialize_blk[0] = FELICA_BLK_NUMBER_ID;
    initialize_blk[1] = 0x00;
    initialize_blk[2] = FELICA_BLK_NUMBER_MACA;
    initialize_blk[3] = 0x00;

    uint8_t mac[FELICA_BLK_HALF];

    ret = felica_generate_mac(ctx, auth_ctx, initialize_blk, id_blk, sizeof(id_blk), true, mac);
    if (ret) {
        return PM3_ERFTRANS;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "MAC_A: %s", sprint_hex(mac, sizeof(mac)));
    }

    if (memcmp(mac_blk, mac, FELICA_BLK_HALF) != 0) {
        PrintAndLogEx(ERR, "\nInternal Authenticate: " _RED_("Failed"));
        return PM3_ERFTRANS;
    }

    PrintAndLogEx(SUCCESS, "Internal Authenticate: " _GREEN_("OK"));

    return PM3_SUCCESS;
}

static int felica_external_authentication(
    const uint8_t *idm,
    mbedtls_des3_context *ctx,
    const felica_auth_context_t *auth_ctx,
    bool keep) {

    uint8_t data[PM3_CMD_DATA_SIZE_MIX];
    memset(data, 0, sizeof(data));

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW | FELICA_NO_DISCONNECT);

    uint16_t datalen = 0;

    uint8_t blk_numbers[1] = {FELICA_BLK_NUMBER_WCNT};

    int ret = read_without_encryption(idm, (uint8_t)sizeof(blk_numbers), blk_numbers, data, &datalen);
    if (ret) {
        return PM3_ERFTRANS;
    }

    uint8_t wcnt_blk[FELICA_BLK_SIZE];
    ret = send_rd_multiple_plain(flags, datalen, data, wcnt_blk);
    if (ret) {
        return PM3_ERFTRANS;
    }

    uint8_t ext_auth[FELICA_BLK_SIZE];
    memset(ext_auth, 0, sizeof(ext_auth));

    ext_auth[0] = 1; // After Authenticate

    uint8_t mac_w[FELICA_BLK_SIZE * 2];

    ret = write_with_mac(ctx, auth_ctx, wcnt_blk, FELICA_BLK_NUMBER_STATE, ext_auth, mac_w);
    if (ret) {
        return PM3_ERFTRANS;
    }

    uint8_t blk_numbers2[2] = {FELICA_BLK_NUMBER_STATE, FELICA_BLK_NUMBER_MACA};

    ret = write_without_encryption(idm, (uint8_t)sizeof(blk_numbers2), blk_numbers2, mac_w, sizeof(mac_w), data, &datalen);
    if (ret) {
        return PM3_ERFTRANS;
    }

    if (keep == false) {
        flags &= ~FELICA_NO_DISCONNECT;
    }

    felica_status_response_t res;
    if (send_wr_plain(flags, datalen, data, false, &res) != PM3_SUCCESS) {
        return PM3_ERFTRANS;
    }

    if (res.status_flags.status_flag1[0] != 0x00 && res.status_flags.status_flag2[0] != 0x00) {
        PrintAndLogEx(ERR, "\nExternal Authenticate: " _RED_("Failed"));
        return PM3_ERFTRANS;
    }

    PrintAndLogEx(SUCCESS, "External Authenticate: " _GREEN_("OK"));

    return PM3_SUCCESS;
}

static int felica_mutual_authentication(
    const uint8_t *idm,
    const uint8_t *rc,
    const size_t rclen,
    const uint8_t *key,
    const size_t keylen,
    bool keep,
    bool verbose) {

    int ret = PM3_SUCCESS;

    mbedtls_des3_context des3_ctx;
    mbedtls_des3_init(&des3_ctx);

    felica_auth_context_t auth_ctx;

    ret = felica_auth_context_init(&des3_ctx, rc, rclen, key, keylen, &auth_ctx);
    if (ret) {
        goto cleanup;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Session Key(SK): %s", sprint_hex(auth_ctx.session_key, sizeof(auth_ctx.session_key)));
    }

    ret = felica_internal_authentication(idm, rc, rclen, &des3_ctx, &auth_ctx, verbose);
    if (ret) {
        goto cleanup;
    }

    ret = felica_external_authentication(idm, &des3_ctx, &auth_ctx, keep);
    if (ret) {
        goto cleanup;
    }

cleanup:
    mbedtls_des3_free(&des3_ctx);
    felica_auth_context_free(&auth_ctx);

    return ret;
}

/**
 * Command parser for liteauth.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaAuthenticationLite(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica liteauth",
                  "Authenticate",
                  "hf felica liteauth -i 11100910C11BC407\n"
                  "hf felica liteauth --key 46656c69436130313233343536616263\n"
                  "hf felica liteauth --key 46656c69436130313233343536616263 -k\n"
                  "hf felica liteauth -c 701185c59f8d30afeab8e4b3a61f5cc4 --key 46656c69436130313233343536616263"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "key", "<hex>", "set card key, 16 bytes"),
        arg_str0("c", "", "<hex>", "set random challenge, 16 bytes"),
        arg_str0("i", "", "<hex>", "set custom IDm"),
        arg_lit0("k", "", "keep signal field ON after receive"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t key[FELICA_BLK_SIZE];
    memset(key, 0, sizeof(key));
    int keylen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), key, sizeof(key), &keylen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t rc[FELICA_BLK_SIZE];
    memset(rc, 0, sizeof(rc));
    int rclen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), rc, sizeof(rc), &rclen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t idm[8];
    memset(idm, 0, sizeof(idm));
    int ilen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 3), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool keep_field_on = arg_get_lit(ctx, 4);

    CLIParserFree(ctx);

    if (!ilen) {
        if (last_known_card.IDm[0] != 0 && last_known_card.IDm[1] != 0) {
            memcpy(idm, last_known_card.IDm, sizeof(idm));
        } else {
            PrintAndLogEx(WARNING, "No last known card! Use `" _YELLOW_("hf felica reader") "` first or set a custom IDm");
            return PM3_EINVARG;
        }
    }

    int ret = PM3_SUCCESS;

    PrintAndLogEx(INFO, "Card Key: %s", sprint_hex(key, sizeof(key)));
    PrintAndLogEx(INFO, "Random Challenge(RC): %s", sprint_hex(rc, sizeof(rc)));

    PrintAndLogEx(SUCCESS, "FeliCa lite - auth started");

    ret = felica_mutual_authentication(idm, rc, sizeof(rc), key, sizeof(key), keep_field_on, true);
    if (ret) {
        return PM3_EINVARG;
    }

    return PM3_SUCCESS;
}

static void printSep(void) {
    PrintAndLogEx(INFO, "------------------------------------------------------------------------------------");
}

static uint16_t PrintFliteBlock(uint16_t tracepos, uint8_t *trace, uint16_t tracelen) {
    if (tracepos + 19 >= tracelen)
        return tracelen;

    trace += tracepos;
    uint8_t blocknum = trace[0];
    uint8_t status1 = trace[1];
    uint8_t status2 = trace[2];

    bool error = (status1 != 0x00 && (status2 == 0xB1 || status2 == 0xB2));

    char line[110] = {0};
    for (int j = 0; j < 16; j++) {
        if (error) {
            snprintf(line + (j * 4), sizeof(line) - 1 - (j * 4), "??  ");
        } else {
            snprintf(line + (j * 4), sizeof(line) - 1 - (j * 4), "%02x  ", trace[j + 3]);
        }
    }

    PrintAndLogEx(NORMAL, "block number %02x, status: %02x %02x", blocknum, status1, status2);
    switch (blocknum) {
        case 0x00:
            PrintAndLogEx(NORMAL,  "S_PAD0: %s", line);
            break;
        case 0x01:
            PrintAndLogEx(NORMAL,  "S_PAD1: %s", line);
            break;
        case 0x02:
            PrintAndLogEx(NORMAL,  "S_PAD2: %s", line);
            break;
        case 0x03:
            PrintAndLogEx(NORMAL,  "S_PAD3: %s", line);
            break;
        case 0x04:
            PrintAndLogEx(NORMAL,  "S_PAD4: %s", line);
            break;
        case 0x05:
            PrintAndLogEx(NORMAL,  "S_PAD5: %s", line);
            break;
        case 0x06:
            PrintAndLogEx(NORMAL,  "S_PAD6: %s", line);
            break;
        case 0x07:
            PrintAndLogEx(NORMAL,  "S_PAD7: %s", line);
            break;
        case 0x08:
            PrintAndLogEx(NORMAL,  "S_PAD8: %s", line);
            break;
        case 0x09:
            PrintAndLogEx(NORMAL,  "S_PAD9: %s", line);
            break;
        case 0x0a:
            PrintAndLogEx(NORMAL,  "S_PAD10: %s", line);
            break;
        case 0x0b:
            PrintAndLogEx(NORMAL,  "S_PAD11: %s", line);
            break;
        case 0x0c:
            PrintAndLogEx(NORMAL,  "S_PAD12: %s", line);
            break;
        case 0x0d:
            PrintAndLogEx(NORMAL,  "S_PAD13: %s", line);
            break;
        case 0x0E: {
            uint32_t regA = trace[3] | trace[4] << 8 | trace[5] << 16 | trace[6] << 24;
            uint32_t regB = trace[7] | trace[8] << 8 | trace[9] << 16 | trace[10] << 24;
            line[0] = 0;
            for (int j = 0; j < 8; j++)
                snprintf(line + (j * 2), sizeof(line) - 1 - (j * 2), "%02x", trace[j + 11]);

            if (error) {
                PrintAndLogEx(NORMAL,  "REG: regA: ???????? regB: ???????? regC: ???????????????? ");
            } else {
                PrintAndLogEx(NORMAL,  "REG: regA: %d regB: %d regC: %s ", regA, regB, line);
            }
        }
        break;
        case 0x80:
            PrintAndLogEx(NORMAL,  "Random Challenge, WO:  %s ", line);
            break;
        case 0x81:
            PrintAndLogEx(NORMAL,  "MAC, only set on dual read:  %s ", line);
            break;
        case 0x82: {
            char idd[20];
            char idm[20];
            for (int j = 0; j < 8; j++)
                snprintf(idd + (j * 2), sizeof(idd) - 1 - (j * 2), "%02x", trace[j + 3]);

            for (int j = 0; j < 6; j++)
                snprintf(idm + (j * 2), sizeof(idm) - 1 - (j * 2), "%02x", trace[j + 13]);

            PrintAndLogEx(NORMAL,  "ID Block, IDd: 0x%s DFC: 0x%02x%02x Arb: %s ", idd, trace[11], trace [12], idm);
        }
        break;
        case 0x83: {
            char idm[20];
            char pmm[20];
            for (int j = 0; j < 8; j++)
                snprintf(idm + (j * 2), sizeof(idm) - 1 - (j * 2), "%02x", trace[j + 3]);

            for (int j = 0; j < 8; j++)
                snprintf(pmm + (j * 2), sizeof(pmm) - 1 - (j * 2), "%02x", trace[j + 11]);

            PrintAndLogEx(NORMAL,  "DeviceId:  IDm: 0x%s PMm: 0x%s ", idm, pmm);
        }
        break;
        case 0x84:
            PrintAndLogEx(NORMAL,  "SER_C: 0x%02x%02x ", trace[3], trace[4]);
            break;
        case 0x85:
            PrintAndLogEx(NORMAL,  "SYS_Cl 0x%02x%02x ", trace[3], trace[4]);
            break;
        case 0x86:
            PrintAndLogEx(NORMAL,  "CKV (key version): 0x%02x%02x ", trace[3], trace[4]);
            break;
        case 0x87:
            PrintAndLogEx(NORMAL,  "CK (card key), WO:   %s ", line);
            break;
        case 0x88: {
            PrintAndLogEx(NORMAL,  "Memory Configuration (MC):");
            PrintAndLogEx(NORMAL,  "MAC needed to write state: %s", trace[3 + 12] ? "on" : "off");
            //order might be off here...
            PrintAndLogEx(NORMAL,  "Write with MAC for S_PAD  : %s ", sprint_bin(trace + 3 + 10, 2));
            PrintAndLogEx(NORMAL,  "Write with AUTH for S_PAD : %s ", sprint_bin(trace + 3 + 8, 2));
            PrintAndLogEx(NORMAL,  "Read after AUTH for S_PAD : %s ", sprint_bin(trace + 3 + 6, 2));
            PrintAndLogEx(NORMAL,  "MAC needed to write CK and CKV: %s", trace[3 + 5] ? "on" : "off");
            PrintAndLogEx(NORMAL,  "RF parameter: %02x", (trace[3 + 4] & 0x7));
            PrintAndLogEx(NORMAL,  "Compatible with NDEF: %s", trace[3 + 3] ? "yes" : "no");
            PrintAndLogEx(NORMAL,  "Memory config writable : %s", (trace[3 + 2] == 0xff) ? "yes" : "no");
            PrintAndLogEx(NORMAL,  "RW access for S_PAD : %s ", sprint_bin(trace + 3, 2));
        }
        break;
        case 0x90: {
            PrintAndLogEx(NORMAL,  "Write counter, RO:   %02x %02x %02x ", trace[3], trace[4], trace[5]);
        }
        break;
        case 0x91: {
            PrintAndLogEx(NORMAL,  "MAC_A, RW (auth):   %s ", line);
        }
        break;
        case 0x92:
            PrintAndLogEx(NORMAL,  "State:");
            PrintAndLogEx(NORMAL,  "Polling disabled: %s", trace[3 + 8] ? "yes" : "no");
            PrintAndLogEx(NORMAL,  "Authenticated: %s", trace[3] ? "yes" : "no");
            break;
        case 0xa0:
            PrintAndLogEx(NORMAL,  "CRC of all blocks match : %s", (trace[3 + 2] == 0xff) ? "no" : "yes");
            break;
        default:
            PrintAndLogEx(WARNING,  "INVALID %d: %s", blocknum, line);
            break;
    }
    return tracepos + 19;
}

static int CmdHFFelicaDumpLite(const char *Cmd) {

    /*
    iceman 2021,
    Why does this command say it dumps a FeliCa lite card
    and then tries to print a trace?!?
    Is this a trace list or a FeliCa dump cmd?
    */


    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica litedump",
                  "Dump ISO/18092 FeliCa Lite tag.  It will timeout after 200sec",
                  "hf felica litedump"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("i", "", "<hex>", "set custom IDm"),
        arg_str0(NULL, "key", "<hex>", "set card key, 16 bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t idm[8];
    memset(idm, 0, sizeof(idm));
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t key[FELICA_BLK_SIZE];
    memset(key, 0, sizeof(key));
    int keylen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), key, sizeof(key), &keylen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    if (keylen != 0) {
        if (!ilen) {
            if (last_known_card.IDm[0] != 0 && last_known_card.IDm[1] != 0) {
                memcpy(idm, last_known_card.IDm, sizeof(idm));
            } else {
                PrintAndLogEx(WARNING, "No last known card! Use `" _YELLOW_("hf felica reader") "` first or set a custom IDm");
                return PM3_EINVARG;
            }
        }

        uint8_t rc[FELICA_BLK_SIZE] = {0};

        int ret = felica_mutual_authentication(idm, rc, sizeof(rc), key, sizeof(key), true, false);
        if (ret) {
            PrintAndLogEx(WARNING, "Authenticate Failed");
        }
    }

    PrintAndLogEx(NORMAL, "");

    PrintAndLogEx(SUCCESS, "FeliCa lite - dump started");

    clearCommandBuffer();
    SendCommandNG(CMD_HF_FELICALITE_DUMP, NULL, 0);
    PacketResponseNG resp;

    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to abort dumping");

    uint8_t timeout = 0;
    while (WaitForResponseTimeout(CMD_ACK, &resp, 2000) == false) {

        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, "\naborted via keyboard!");
            return PM3_EOPABORTED;
        }

        timeout++;
        PrintAndLogEx(INPLACE, "% 3i", timeout);

        fflush(stdout);
        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
            DropField();
            return PM3_EOPABORTED;
        }
        if (timeout > 10) {
            PrintAndLogEx(WARNING, "\ntimeout while waiting for reply");
            DropField();
            return PM3_ETIMEOUT;
        }
    }

    PrintAndLogEx(NORMAL, "");

    if (resp.oldarg[0] == 0) {
        PrintAndLogEx(WARNING, "Button pressed, aborted");
        return PM3_EOPABORTED;
    }

    uint16_t tracelen = resp.oldarg[1];
    if (tracelen == 0) {
        PrintAndLogEx(WARNING, "No trace data! Maybe not a FeliCa Lite card?");
        return PM3_ESOFT;
    }

    uint8_t *trace = calloc(tracelen, sizeof(uint8_t));
    if (trace == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    if (GetFromDevice(BIG_BUF, trace, tracelen, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        free(trace);
        return PM3_ETIMEOUT;
    }


    PrintAndLogEx(SUCCESS, "Recorded Activity (trace len = %"PRIu32" bytes)", tracelen);
    print_hex_break(trace, tracelen, 32);
    printSep();

    uint16_t tracepos = 0;
    while (tracepos < tracelen)
        tracepos = PrintFliteBlock(tracepos, trace, tracelen);

    printSep();

    free(trace);
    return PM3_SUCCESS;
}

static int CmdHFFelicaCmdRaw(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica raw ",
                  "Send raw hex data to tag",
                  "hf felica raw -cs 20\n"
                  "hf felica raw -cs 2008"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  NULL, "active signal field ON without select"),
        arg_lit0("c",  NULL, "calculate and append CRC"),
        arg_lit0("k",  NULL, "keep signal field ON after receive"),
        arg_u64_0("n", NULL, "<dec>", "number of bits"),
        arg_lit0("r",  NULL, "do not read response"),
        arg_lit0("s",  NULL, "active signal field ON with select"),
        arg_str1(NULL, NULL, "<hex>", "raw bytes to send"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool active = arg_get_lit(ctx, 1);
    bool crc = arg_get_lit(ctx, 2);
    bool keep_field_on = arg_get_lit(ctx, 3);
    uint16_t numbits = arg_get_u32_def(ctx, 4, 0) & 0xFFFF;
    bool reply = (arg_get_lit(ctx, 5) == false);
    bool active_select = arg_get_lit(ctx, 6);

    int datalen = 0;
    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));

    CLIGetHexWithReturn(ctx, 7, data, &datalen);
    CLIParserFree(ctx);

    uint8_t flags = 0;

    if (crc) {
        flags |= FELICA_APPEND_CRC;
    }

    if (active || active_select) {
        flags |= FELICA_CONNECT;
        if (active) {
            flags |= FELICA_NO_SELECT;
        }
    }

    if (keep_field_on) {
        flags |= FELICA_NO_DISCONNECT;
    }

    if (datalen > 0) {
        flags |= FELICA_RAW;
    }

    // Max buffer is PM3_CMD_DATA_SIZE
    datalen = (datalen > PM3_CMD_DATA_SIZE) ? PM3_CMD_DATA_SIZE : datalen;

    clearCommandBuffer();
    PrintAndLogEx(SUCCESS, "Data: %s", sprint_hex(data, datalen));

    SendCommandMIX(CMD_HF_FELICA_COMMAND, flags, (datalen & 0xFFFF) | (uint32_t)(numbits << 16), 0, data, datalen);

    if (reply) {

        if (active_select) {
            PrintAndLogEx(SUCCESS, "Active select wait for FeliCa.");
            PacketResponseNG resp_IDm;
            if (waitCmdFelica(true, &resp_IDm, true) == false) {
                return PM3_ERFTRANS;
            }
        }

        if (datalen) {
            PacketResponseNG resp_frame;
            if (waitCmdFelica(false, &resp_frame, true) == false) {
                return PM3_ERFTRANS;
            }
        }
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"-----------",     CmdHelp,                          AlwaysAvailable, "----------------------- " _CYAN_("General") " -----------------------"},
    {"help",            CmdHelp,                          AlwaysAvailable, "This help"},
    {"list",            CmdHFFelicaList,                  AlwaysAvailable, "List ISO 18092/FeliCa history"},
    {"-----------",     CmdHelp,                          AlwaysAvailable, "----------------------- " _CYAN_("Operations") " -----------------------"},
    {"info",            CmdHFFelicaInfo,                  IfPm3Felica,     "Tag information"},
    {"raw",             CmdHFFelicaCmdRaw,                IfPm3Felica,     "Send raw hex data to tag"},
    {"rdbl",            CmdHFFelicaReadPlain,             IfPm3Felica,     "read block data from authentication-not-required Service."},
    {"reader",          CmdHFFelicaReader,                IfPm3Felica,     "Act like an ISO18092/FeliCa reader"},
    {"sniff",           CmdHFFelicaSniff,                 IfPm3Felica,     "Sniff ISO 18092/FeliCa traffic"},
    {"wrbl",            CmdHFFelicaWritePlain,            IfPm3Felica,     "write block data to an authentication-not-required Service."},
    {"-----------",     CmdHelp,                          AlwaysAvailable, "----------------------- " _CYAN_("FeliCa Standard") " -----------------------"},
    {"dump",            CmdHFFelicaDump,                  IfPm3Felica,     "Wait for and try dumping FeliCa"},
    {"rqservice",       CmdHFFelicaRequestService,        IfPm3Felica,     "verify the existence of Area and Service, and to acquire Key Version."},
    {"rqresponse",      CmdHFFelicaRequestResponse,       IfPm3Felica,     "verify the existence of a card and its Mode."},
    {"scsvcode",        CmdHFFelicaDumpServiceArea,       IfPm3Felica,     "acquire Area Code and Service Code."},
    {"rqsyscode",       CmdHFFelicaRequestSystemCode,     IfPm3Felica,     "acquire System Code registered to the card."},
    {"auth1",           CmdHFFelicaAuthentication1,       IfPm3Felica,     "authenticate a card. Start mutual authentication with Auth1"},
    {"auth2",           CmdHFFelicaAuthentication2,       IfPm3Felica,     "allow a card to authenticate a Reader/Writer. Complete mutual authentication"},
    //{"read",          CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "read Block Data from authentication-required Service."},
    //{"write",         CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "write Block Data to an authentication-required Service."},
    //{"scsvcodev2",    CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "verify the existence of Area or Service, and to acquire Key Version."},
    //{"getsysstatus",  CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "acquire the setup information in System."},
    {"rqspecver",       CmdHFFelicaRequestSpecificationVersion, IfPm3Felica,  "acquire the version of card OS."},
    {"resetmode",       CmdHFFelicaResetMode,             IfPm3Felica,     "reset Mode to Mode 0."},
    //{"auth1v2",       CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "authenticate a card."},
    //{"auth2v2",       CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "allow a card to authenticate a Reader/Writer."},
    //{"readv2",        CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "read Block Data from authentication-required Service."},
    //{"writev2",       CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "write Block Data to authentication-required Service."},
    //{"uprandomid",    CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "update Random ID (IDr)."},
    {"-----------",     CmdHelp,                          AlwaysAvailable, "----------------------- " _CYAN_("FeliCa Light") " -----------------------"},
    {"litesim",         CmdHFFelicaSimLite,               IfPm3Felica,     "Emulating ISO/18092 FeliCa Lite tag"},
    {"liteauth",        CmdHFFelicaAuthenticationLite,    IfPm3Felica,     "authenticate a card."},
    {"litedump",        CmdHFFelicaDumpLite,              IfPm3Felica,     "Wait for and try dumping FelicaLite"},
    //    {"sim",       CmdHFFelicaSim,                   IfPm3Felica,     "<UID> -- Simulate ISO 18092/FeliCa tag"}
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFFelica(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
