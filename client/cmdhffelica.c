//-----------------------------------------------------------------------------
// Copyright (C) 2017 October, Satsuoni
// 2017 iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO18092 / FeliCa commands
//-----------------------------------------------------------------------------
#include "cmdhffelica.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include "cmdparser.h"    // command_t
#include "comms.h"
#include "cmdtrace.h"
#include "crc16.h"
#include "util.h"
#include "ui.h"
#include "mifare.h"     // felica_card_select_t struct
#define AddCrc(data, len) compute_crc(CRC_FELICA, (data), (len), (data)+(len)+1, (data)+(len))

static int CmdHelp(const char *Cmd);
static felica_card_select_t last_known_card;

static void set_last_known_card(felica_card_select_t card) {
    last_known_card = card;
}

/*
static int usage_hf_felica_sim(void) {
    PrintAndLogEx(NORMAL, "\n Emulating ISO/18092 FeliCa tag \n");
    PrintAndLogEx(NORMAL, "Usage: hf felica sim [h] t <type> [v]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "    h     : This help");
    PrintAndLogEx(NORMAL, "    t     : 1 = FeliCa");
    PrintAndLogEx(NORMAL, "          : 2 = FeliCaLiteS");
    PrintAndLogEx(NORMAL, "    v     : (Optional) Verbose");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "          hf felica sim t 1 ");
    return PM3_SUCCESS;
}
*/

static int usage_hf_felica_sniff(void) {
    PrintAndLogEx(NORMAL, "It get data from the field and saves it into command buffer.");
    PrintAndLogEx(NORMAL, "Buffer accessible from command 'hf list felica'");
    PrintAndLogEx(NORMAL, "Usage:  hf felica sniff <s> <t>");
    PrintAndLogEx(NORMAL, "      s       samples to skip (decimal)");
    PrintAndLogEx(NORMAL, "      t       triggers to skip (decimal)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "          hf felica sniff s 1000");
    return PM3_SUCCESS;
}
static int usage_hf_felica_simlite(void) {
    PrintAndLogEx(NORMAL, "\n Emulating ISO/18092 FeliCa Lite tag \n");
    PrintAndLogEx(NORMAL, "Usage: hf felica litesim [h] u <uid>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "    h     : This help");
    PrintAndLogEx(NORMAL, "    uid   : UID in hexsymbol");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "          hf felica litesim 11223344556677");
    return PM3_SUCCESS;
}
static int usage_hf_felica_dumplite(void) {
    PrintAndLogEx(NORMAL, "\n Dump ISO/18092 FeliCa Lite tag \n");
    PrintAndLogEx(NORMAL, "press button to abort run, otherwise it will loop for 200sec.");
    PrintAndLogEx(NORMAL, "Usage: hf felica litedump [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "    h     : This help");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "          hf felica litedump");
    return PM3_SUCCESS;
}
static int usage_hf_felica_raw(void) {
    PrintAndLogEx(NORMAL, "Usage: hf felica raw [-h] [-r] [-c] [-p] [-a] <0A 0B 0C ... hex>");
    PrintAndLogEx(NORMAL, "       -h    this help");
    PrintAndLogEx(NORMAL, "       -r    do not read response");
    PrintAndLogEx(NORMAL, "       -c    calculate and append CRC");
    PrintAndLogEx(NORMAL, "       -p    leave the signal field ON after receive");
    PrintAndLogEx(NORMAL, "       -a    active signal field ON without select");
    PrintAndLogEx(NORMAL, "       -s    active signal field ON with select");
    return PM3_SUCCESS;
}

static int usage_hf_felica_request_service(void) {
    PrintAndLogEx(NORMAL, "\nInfo: Use this command to verify the existence of Area and Service, and to acquire Key Version:");
    PrintAndLogEx(NORMAL, "       - When the specified Area or Service exists, the card returns Key Version.");
    PrintAndLogEx(NORMAL, "       - When the specified Area or Service does not exist, the card returns FFFFh as Key Version.");
    PrintAndLogEx(NORMAL, "For Node Code List of a command packet, Area Code or Service Code of the target "
                  "of acquisition of Key Version shall be enumerated in Little Endian format. "
                  "If Key Version of System is the target of acquisition, FFFFh shall be specified "
                  "in the command packet.");
    PrintAndLogEx(NORMAL, "\nUsage: hf felica rqservice [-h] [-i] <01 Number of Node hex> <0A0B Node Code List hex (Little Endian)>");
    PrintAndLogEx(NORMAL, "       -h    this help");
    PrintAndLogEx(NORMAL, "       -i    <0A0B0C ... hex> set custom IDm to use");
    PrintAndLogEx(NORMAL, "       -a    auto node number mode - iterates through all possible nodes 1 < n < 32");
    PrintAndLogEx(NORMAL, "\nExamples: ");
    PrintAndLogEx(NORMAL, "  hf felica rqservice 01 FFFF");
    PrintAndLogEx(NORMAL, "  hf felica rqservice -a FFFF");
    PrintAndLogEx(NORMAL, "  hf felica rqservice -i 01100910c11bc407 01 FFFF \n\n");
    return PM3_SUCCESS;
}

static int usage_hf_felica_request_response(void) {
    PrintAndLogEx(NORMAL, "\nInfo: Use this command to verify the existence of a card and its Mode.");
    PrintAndLogEx(NORMAL, "       - Current Mode of the card is returned.");
    PrintAndLogEx(NORMAL, "\nUsage: hf felica rqresponse [-h]");
    PrintAndLogEx(NORMAL, "       -h    this help");
    PrintAndLogEx(NORMAL, "       -i    <0A0B0C ... hex> set custom IDm to use");
    return PM3_SUCCESS;
}

static void print_status_flag1_interpretation() {
    PrintAndLogEx(NORMAL, "\nStatus Flag1:");
    PrintAndLogEx(NORMAL, "  - 00h : Indicates the successful completion of a command.");
    PrintAndLogEx(NORMAL, "  - FFh : If an error occurs during the processing of a command that includes no list in the command packet, or if "
                  "an error occurs independently of any list, the card returns a response by setting FFh to Status Flag1.");
    PrintAndLogEx(NORMAL, "  - XXh : If an error occurs while processing a command that includes Service Code List or Block List "
                  "in the command packet, the card returns a response by setting a number in the list to Status Flag1, "
                  "indicating the location of the error.");
}

static void print_status_flag2_interpration() {
    PrintAndLogEx(NORMAL, "\nStatus Flag2:");
    PrintAndLogEx(NORMAL, "  - 00h : Indicates the successful completion of a command.");
    PrintAndLogEx(NORMAL, "  - 01h : The calculated result is either less than zero when the purse data is decremented, or exceeds 4"
                  "Bytes when the purse data is incremented.");
    PrintAndLogEx(NORMAL, "  - 02h : The specified data exceeds the value of cashback data at cashback of purse.");
    PrintAndLogEx(NORMAL, "  - 70h : Memory error (fatal error).");
    PrintAndLogEx(NORMAL, "  - 71h : The number of memory rewrites exceeds the upper limit (this is only a warning; data writing is "
                  "performed as normal). The maximum number of rewrites can differ, depending on the product being used.");
    PrintAndLogEx(NORMAL, "          In addition, Status Flag1 is either 00h or FFh depending on the product being used.");
    PrintAndLogEx(NORMAL, "  - A1h : Illegal Number of Service: Number of Service or Number of Node specified by the command falls outside the range of the prescribed value.");
    PrintAndLogEx(NORMAL, "  - A2h : Illegal command packet (specified Number of Block): Number of Block specified by the command falls outside the range of the prescribed values for the product.");
    PrintAndLogEx(NORMAL, "  - A3h : Illegal Block List (specified order of Service): Service Code List Order specified by Block List Element falls outside the Number of Service specified by the "
                  "command (or the Number of Service specified at the times of mutual authentication).");
    PrintAndLogEx(NORMAL, "  - A4h : Illegal Service type: Area Attribute specified by the command or Service Attribute of Service Code is incorrect.");
    PrintAndLogEx(NORMAL, "  - A5h : Access is not allowed: Area or Service specified by the command cannot be accessed. "
                  "The parameter specified by the command does not satisfy the conditions for success.");
    PrintAndLogEx(NORMAL, "  - A6h : Illegal Service Code List: Target to be accessed, identified by Service Code List Order, specified by Block "
                  "List Element does not exist. Or, Node specified by Node Code List does not exist.");
    PrintAndLogEx(NORMAL, "  - A7h : Illegal Block List (Access Mode): Access Mode specified by Block List Element is incorrect.");
    PrintAndLogEx(NORMAL, "  - A8h : Illegal Block Number Block Number (access to the specified data is inhibited): specified by Block List Element exceeds the number of Blocks assigned to Service.");
    PrintAndLogEx(NORMAL, "  - A9h : Data write failure: This is the error that occurs in issuance commands.");
    PrintAndLogEx(NORMAL, "  - AAh : Key-change failure: Key change failed.");
    PrintAndLogEx(NORMAL, "  - ABh : Illegal Package Parity or illegal Package MAC: This is the error that occurs in issuance commands.");
    PrintAndLogEx(NORMAL, "  - ACh : Illegal parameter: This is the error that occurs in issuance commands.");
    PrintAndLogEx(NORMAL, "  - ADh : Service exists already: This is the error that occurs in issuance commands.");
    PrintAndLogEx(NORMAL, "  - AEh : Illegal System Code: This is the error that occurs in issuance commands.");
    PrintAndLogEx(NORMAL, "  - AFh : Too many simultaneous cyclic write operations: Number of simultaneous write Blocks specified by the command to Cyclic Service "
                  "exceeds the number of Blocks assigned to Service.");
    PrintAndLogEx(NORMAL, "  - C0h : Illegal Package Identifier: This is the error that occurs in issuance commands.");
    PrintAndLogEx(NORMAL, "  - C1h : Discrepancy of parameters inside and outside Package: This is the error that occurs in issuance commands.");
    PrintAndLogEx(NORMAL, "  - C2h : Command is disabled already: This is the error that occurs in issuance commands.");
}

static int usage_hf_felica_read_without_encryption() {
    PrintAndLogEx(NORMAL, "\nInfo: Use this command to read Block Data from authentication-not-required Service.");
    PrintAndLogEx(NORMAL, "       - Mode shall be Mode0.");
    PrintAndLogEx(NORMAL, "       - Number of Service: shall be a positive integer in the range of 1 to 16, inclusive.");
    PrintAndLogEx(NORMAL, "       - Number of Block: shall be less than or equal to the maximum number of Blocks that can be read simultaneously. "
                  "The maximum number of Blocks that can be read simultaneously can differ, depending on the product being used. Use as default 01");
    PrintAndLogEx(NORMAL, "       - Service Code List: For Service Code List, only Service Code existing in the product shall be specified:");
    PrintAndLogEx(NORMAL, "              - Even when Service Code exists in the product, Service Code not referenced from Block List shall not be specified to Service Code List.");
    PrintAndLogEx(NORMAL, "              - For existence or nonexistence of Service in a product, please check using the Request Service (or Request Service v2) command.");
    PrintAndLogEx(NORMAL, "       - Each Block List Element shall satisfy the following conditions:");
    PrintAndLogEx(NORMAL, "              - The value of Service Code List Order shall not exceed Number of Service.");
    PrintAndLogEx(NORMAL, "              - Access Mode shall be 000b.");
    PrintAndLogEx(NORMAL, "              - The target specified by Service Code shall not be Area or System.");
    PrintAndLogEx(NORMAL, "              - Service specified in Service Code List shall exist in System.");
    PrintAndLogEx(NORMAL, "              - Service Attribute of Service specified in Service Code List shall be authentication-not-required Service.");
    PrintAndLogEx(NORMAL, "              - Block Number shall be in the range of the number of Blocks assigned to the specified Service.");
    PrintAndLogEx(NORMAL, "       - Successful read: Card responses the block data");
    PrintAndLogEx(NORMAL, "       - Unsuccessful read: Card responses with Status Flag1 and Flag2");
    print_status_flag1_interpretation();
    print_status_flag2_interpration();
    PrintAndLogEx(NORMAL, "\nUsage: hf felica rdunencrypted [-h] <01 Number of Service hex> <0A0B Service Code List (Little Endian) hex> <01 Number of Block hex> <0A0B Block List Element hex>");
    PrintAndLogEx(NORMAL, "       -h    this help");
    PrintAndLogEx(NORMAL, "       -i    <0A0B0C ... hex> set custom IDm to use");
    PrintAndLogEx(NORMAL, "       -b    get all Block List Elements starting from 00 to FF - stops when a block return an error status flags");
    PrintAndLogEx(NORMAL, "       -l    use 3-byte block list element block number");
    PrintAndLogEx(NORMAL, "\nExamples: ");
    PrintAndLogEx(NORMAL, "  hf felica rdunencrypted 01 8B00 01 8000");
    PrintAndLogEx(NORMAL, "  hf felica rdunencrypted -i 01100910c11bc407 01 8B00 01 8000");
    PrintAndLogEx(NORMAL, "  hf felica rdunencrypted -b 01 8B00 01 8000\n\n");
    return PM3_SUCCESS;
}

/**
 * Wait for response from pm3 or timeout.
 * Checks if receveid bytes have a valid CRC.
 * @param verbose prints out the response received.
 */
static bool waitCmdFelica(uint8_t iSelect, PacketResponseNG *resp, bool verbose) {
    if (WaitForResponseTimeout(CMD_ACK, resp, 2000)) {
        uint16_t len = iSelect ? (resp->oldarg[1] & 0xffff) : (resp->oldarg[0] & 0xffff);
        if (verbose) {
            PrintAndLogEx(NORMAL, "Client Received %i octets", len);
            if (!len || len < 2) {
                PrintAndLogEx(ERR, "Could not receive data correctly!");
            }
            PrintAndLogEx(NORMAL, "%s", sprint_hex(resp->data.asBytes, len));
            if (!check_crc(CRC_FELICA, resp->data.asBytes + 2, len - 2)) {
                PrintAndLogEx(WARNING, "Wrong or no CRC bytes");
            }
        }
        return true;
    } else {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
    }
    return false;
}

/*
 * Counts and sets the number of parameters.
 */
static void strip_cmds(const char *Cmd) {
    while (*Cmd == ' ' || *Cmd == '\t') {
        Cmd++;
    }
}

/**
 * Converts integer value to equivalent hex value.
 * Examples: 1 = 1, 11 = B
 * @param number number of hex bytes.
 * @return number as hex value.
 */
static uint8_t int_to_hex(uint16_t *number) {
    uint32_t hex;
    char dataLengthChar[5];
    sprintf(dataLengthChar, "%x", *number);
    sscanf(dataLengthChar, "%x", &hex);
    return (uint8_t)(hex & 0xff);
}

/**
 * Adds the last known IDm (8-Byte) to the data frame.
 * @param position start of where the IDm is added within the frame.
 * @param data frame in where the IDM is added.
 * @return true if IDm was added;
 */
static bool add_last_IDm(uint8_t position, uint8_t *data) {
    if (last_known_card.IDm[0] != 0 && last_known_card.IDm[1] != 0) {
        for (int i = 0; i < 8; i++) {
            uint16_t number = (uint16_t)last_known_card.IDm[i];
            data[position + i] = int_to_hex(&number);
        }
        return true;
    } else {
        return false;
    }
}

static int CmdHFFelicaList(const char *Cmd) {
    (void)Cmd;
    CmdTraceList("felica");
    return PM3_SUCCESS;
}

static int CmdHFFelicaReader(const char *Cmd) {
    bool verbose = !(tolower(Cmd[0]) == 's');
    return readFelicaUid(verbose);
}

/**
 * Clears command buffer and sends the given data to pm3 with mix mode.
 */
static void clear_and_send_command(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose) {
    uint16_t numbits = 0;
    clearCommandBuffer();
    if (verbose) {
        PrintAndLogEx(NORMAL, "Send Service Request Frame: %s", sprint_hex(data, datalen));
    }
    SendCommandMIX(CMD_HF_FELICA_COMMAND, flags, (datalen & 0xFFFF) | (uint32_t)(numbits << 16), 0, data, datalen);
}

/**
 * Adds a parameter to the frame and checks if the parameter has the specific length.
 * @param Cmd User input with the parameter.
 * @param paramCount number of the parameter within the user input.
 * @param data frame in which the data is stored.
 * @param dataPosition position within frame where the data will be stored.
 * @param length which the parameter should have and will be tested against.
 * @return true if parameters was added.
 */
static bool add_param(const char *Cmd, uint8_t paramCount, uint8_t *data, uint8_t dataPosition, uint8_t length) {
    if (param_getlength(Cmd, paramCount) == length) {
        param_gethex(Cmd, paramCount, data + dataPosition, length);
        return true;
    } else {
        PrintAndLogEx(ERR, "Incorrect Parameter length! Param %i", paramCount);
        return false;
    }
}

/**
 * Prints read-without-encryption response.
 * @param rd_noCry_resp Response frame.
 */
static void print_rd_noEncrpytion_response(felica_read_without_encryption_response_t *rd_noCry_resp) {
    if (rd_noCry_resp->status_flag1[0] == 00 && rd_noCry_resp->status_flag2[0] == 00) {
        char *temp = sprint_hex(rd_noCry_resp->block_data, sizeof(rd_noCry_resp->block_data));
        char bl_data[256];
        strcpy(bl_data, temp);

        char bl_element_number[4];
        temp = sprint_hex(rd_noCry_resp->block_element_number, sizeof(rd_noCry_resp->block_element_number));
        strcpy(bl_element_number, temp);
        PrintAndLogEx(NORMAL, "\t%s\t|  %s  ", bl_element_number, bl_data);
    } else {
        PrintAndLogEx(NORMAL, "IDm: %s", sprint_hex(rd_noCry_resp->IDm, sizeof(rd_noCry_resp->IDm)));
        PrintAndLogEx(NORMAL, "Status Flag1: %s", sprint_hex(rd_noCry_resp->status_flag1, sizeof(rd_noCry_resp->status_flag1)));
        PrintAndLogEx(NORMAL, "Status Flag2: %s", sprint_hex(rd_noCry_resp->status_flag1, sizeof(rd_noCry_resp->status_flag1)));
    }
}

/**
 * Sends a request service frame to the pm3 and prints response.
 */
int send_request_service(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose) {
    clear_and_send_command(flags, datalen, data, verbose);
    PacketResponseNG resp;
    if (datalen > 0) {
        if (!waitCmdFelica(0, &resp, 1)) {
            PrintAndLogEx(ERR, "\nGot no Response from card");
            return PM3_ERFTRANS;
        }
        felica_request_service_response_t rqs_response;
        memcpy(&rqs_response, (felica_request_service_response_t *)resp.data.asBytes, sizeof(felica_request_service_response_t));

        if (rqs_response.IDm[0] != 0) {
            PrintAndLogEx(SUCCESS, "\nGot Service Response:");
            PrintAndLogEx(NORMAL, "IDm: %s", sprint_hex(rqs_response.IDm, sizeof(rqs_response.IDm)));
            PrintAndLogEx(NORMAL, "  -Node Number: %s", sprint_hex(rqs_response.node_number, sizeof(rqs_response.node_number)));
            PrintAndLogEx(NORMAL, "  -Node Key Version List: %s\n", sprint_hex(rqs_response.node_key_versions, sizeof(rqs_response.node_key_versions)));
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
 * @param rd_noCry_resp frame in which the response will be saved
 * @return success if response was received.
 */
int send_rd_unencrypted(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose, felica_read_without_encryption_response_t *rd_noCry_resp) {
    clear_and_send_command(flags, datalen, data, verbose);
    PacketResponseNG resp;
    if (!waitCmdFelica(0, &resp, verbose)) {
        PrintAndLogEx(ERR, "\nGot no Response from card");
        return PM3_ERFTRANS;
    } else {
        memcpy(rd_noCry_resp, (felica_read_without_encryption_response_t *)resp.data.asBytes, sizeof(felica_read_without_encryption_response_t));
        rd_noCry_resp->block_element_number[0] = data[15];
        return PM3_SUCCESS;
    }
}

/**
 * Command parser for rdunencrypted.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaReadWithoutEncryption(const char *Cmd) {
    if (strlen(Cmd) < 4)
        return usage_hf_felica_read_without_encryption();
    uint8_t data[PM3_CMD_DATA_SIZE];
    bool custom_IDm = false;
    strip_cmds(Cmd);
    uint16_t datalen = 16; // Length (1), Command ID (1), IDm (8), Number of Service (1), Service Code List(2), Number of Block(1), Block List(3)
    uint8_t paramCount = 0;
    uint8_t flags = 0;
    uint8_t all_block_list_elements = false;
    uint8_t long_block_numbers = false;
    int i = 0;
    while (Cmd[i] != '\0') {
        if (Cmd[i] == '-') {
            switch (Cmd[i + 1]) {
                case 'H':
                case 'h':
                    return usage_hf_felica_request_response();
                case 'i':
                    paramCount++;
                    custom_IDm = true;
                    if (!add_param(Cmd, paramCount, data, 3, 8)) {
                        return PM3_EINVARG;
                    }
                    break;
                case 'b':
                    paramCount++;
                    all_block_list_elements = true;
                    break;
                case 'l':
                    paramCount++;
                    long_block_numbers = true;
                    break;
            }
        }
        i++;
    }
    data[0] = 0x10; // Static length
    data[1] = 0x06; // Command ID
    if (!custom_IDm) {
        if (!add_last_IDm(2, data)) {
            PrintAndLogEx(ERR, "No last known card! Use reader first or set a custom IDm!");
            return PM3_EINVARG;
        } else {
            PrintAndLogEx(INFO, "Used last known IDm.", sprint_hex(data, datalen));
        }
    }
    // Number of Service 2, Service Code List 4, Number of Block 2, Block List Element 4
    uint8_t lengths[] = {2, 4, 2, 4};
    uint8_t dataPositions[] = {10, 11, 13, 14};
    if (long_block_numbers) {
        datalen += 1;
        lengths[3] = 6;
    }
    for (int i = 0; i < 4; i++) {
        if (add_param(Cmd, paramCount, data, dataPositions[i], lengths[i])) {
            paramCount++;
        } else {
            return PM3_EINVARG;
        }
    }

    flags |= FELICA_APPEND_CRC;
    flags |= FELICA_RAW;
    if (all_block_list_elements) {
        uint16_t last_block_number = 0xFF;
        if (long_block_numbers) {
            last_block_number = 0xFFFF;
        }
        PrintAndLogEx(NORMAL, "Block Element\t|  Data  ");
        for (int i = 0x00; i < last_block_number; i++) {
            data[15] = i;
            AddCrc(data, datalen);
            datalen += 2;
            felica_read_without_encryption_response_t rd_noCry_resp;
            if ((send_rd_unencrypted(flags, datalen, data, 0, &rd_noCry_resp) == PM3_SUCCESS)) {
                if (rd_noCry_resp.status_flag1[0] == 00 && rd_noCry_resp.status_flag2[0] == 00) {
                    print_rd_noEncrpytion_response(&rd_noCry_resp);
                } else {
                    break;
                }
            } else {
                break;
            }
            datalen -= 2;
        }
    } else {
        AddCrc(data, datalen);
        datalen += 2;
        felica_read_without_encryption_response_t rd_noCry_resp;
        send_rd_unencrypted(flags, datalen, data, 1, &rd_noCry_resp);
        PrintAndLogEx(NORMAL, "Block Element\t|  Data  ");
        print_rd_noEncrpytion_response(&rd_noCry_resp);
    }
    return PM3_SUCCESS;
}

/**
 * Command parser for rqresponse
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaRequestResponse(const char *Cmd) {
    uint8_t data[PM3_CMD_DATA_SIZE];
    bool custom_IDm = false;
    strip_cmds(Cmd);
    uint16_t datalen = 10; // Length (1), Command ID (1), IDm (8)
    uint8_t paramCount = 0;
    uint8_t flags = 0;
    int i = 0;
    while (Cmd[i] != '\0') {
        if (Cmd[i] == '-') {
            switch (Cmd[i + 1]) {
                case 'H':
                case 'h':
                    return usage_hf_felica_request_response();
                case 'i':
                    paramCount++;
                    custom_IDm = true;
                    if (param_getlength(Cmd, paramCount) == 16) {
                        param_gethex(Cmd, paramCount++, data + 2, 16);
                    } else {
                        PrintAndLogEx(ERR, "Incorrect IDm length! IDm must be 8-Byte.");
                        return PM3_EINVARG;
                    }
                    break;
            }
        }
        i++;
    }
    data[0] = 0x0A; // Static length
    data[1] = 0x04; // Command ID
    if (!custom_IDm) {
        if (!add_last_IDm(2, data)) {
            PrintAndLogEx(ERR, "No last known card! Use reader first or set a custom IDm!");
            return PM3_EINVARG;
        } else {
            PrintAndLogEx(INFO, "Used last known IDm.", sprint_hex(data, datalen));
        }
    }
    AddCrc(data, datalen);
    datalen += 2;
    flags |= FELICA_APPEND_CRC;
    flags |= FELICA_RAW;
    clear_and_send_command(flags, datalen, data, 0);
    PacketResponseNG resp;
    if (!waitCmdFelica(0, &resp, 1)) {
        PrintAndLogEx(ERR, "\nGot no Response from card");
        return PM3_ERFTRANS;
    } else {
        felica_request_request_response_t rq_response;
        memcpy(&rq_response, (felica_request_request_response_t *)resp.data.asBytes, sizeof(felica_request_request_response_t));
        if (rq_response.IDm[0] != 0) {
            PrintAndLogEx(SUCCESS, "\nGot Request Response:");
            PrintAndLogEx(NORMAL, "IDm: %s", sprint_hex(rq_response.IDm, sizeof(rq_response.IDm)));
            PrintAndLogEx(NORMAL, "  -Mode: %s\n\n", sprint_hex(rq_response.mode, sizeof(rq_response.mode)));
        }
    }
    return PM3_SUCCESS;
}


/**
 * Command parser for rqservice.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaRequestService(const char *Cmd) {
    if (strlen(Cmd) < 2) return usage_hf_felica_request_service();
    int i = 0;
    uint8_t data[PM3_CMD_DATA_SIZE];
    bool custom_IDm = false;
    bool all_nodes = false;
    uint16_t datalen = 13; // length (1) + CMD (1) + IDm(8) + Node Number (1) + Node Code List (2)
    uint8_t flags = 0;
    uint8_t paramCount = 0;
    strip_cmds(Cmd);
    while (Cmd[i] != '\0') {
        if (Cmd[i] == '-') {
            switch (Cmd[i + 1]) {
                case 'H':
                case 'h':
                    return usage_hf_felica_request_service();
                case 'i':
                    paramCount++;
                    custom_IDm = true;
                    if (param_getlength(Cmd, paramCount) == 16) {
                        param_gethex(Cmd, paramCount++, data + 2, 16);
                    } else {
                        PrintAndLogEx(ERR, "Incorrect IDm length! IDm must be 8-Byte.");
                        return PM3_EINVARG;
                    }
                    i += 8;
                    break;
                case 'a':
                    paramCount++;
                    all_nodes = true;
                    break;
                default:
                    return usage_hf_felica_request_service();
            }
            i += 2;
        }
        i++;
    }
    if (!all_nodes) {
        // Node Number
        if (param_getlength(Cmd, paramCount) == 2) {
            param_gethex(Cmd, paramCount++, data + 10, 2);
        } else {
            PrintAndLogEx(ERR, "Incorrect Node number length!");
            return PM3_EINVARG;
        }
    }

    // Node Code List
    if (param_getlength(Cmd, paramCount) == 4) {
        param_gethex(Cmd, paramCount++, data + 11, 4);
    } else {
        PrintAndLogEx(ERR, "Incorrect Node Code List length!");
        return PM3_EINVARG;
    }

    flags |= FELICA_APPEND_CRC;
    if (custom_IDm) {
        flags |= FELICA_NO_SELECT;
    }
    if (datalen > 0) {
        flags |= FELICA_RAW;
    }
    datalen = (datalen > PM3_CMD_DATA_SIZE) ? PM3_CMD_DATA_SIZE : datalen;
    if (!custom_IDm) {
        if (!add_last_IDm(2, data)) {
            PrintAndLogEx(ERR, "No last known card! Use reader first or set a custom IDm!");
            return PM3_EINVARG;
        } else {
            PrintAndLogEx(INFO, "Used last known IDm.", sprint_hex(data, datalen));
        }
    }
    data[0] = int_to_hex(&datalen);
    data[1] = 0x02; // Service Request Command ID
    if (all_nodes) {
        for (uint16_t y = 1; y < 32; y++) {
            data[10] = int_to_hex(&y);
            AddCrc(data, datalen);
            datalen += 2;
            send_request_service(flags, datalen, data, 1);
            datalen -= 2; // Remove CRC bytes before adding new ones
        }
    } else {
        AddCrc(data, datalen);
        datalen += 2;
        send_request_service(flags, datalen, data, 1);
    }

    return PM3_SUCCESS;
}

static int CmdHFFelicaNotImplementedYet(const char *Cmd) {
    PrintAndLogEx(NORMAL, "Feature not implemented Yet!");
    return PM3_SUCCESS;
}

// simulate iso18092 / FeliCa tag
// Commented, there is no counterpart in ARM at the moment
/*
static int CmdHFFelicaSim(const char *Cmd) {
    bool errors = false;
    uint8_t flags = 0;
    uint8_t tagtype = 1;
    uint8_t cmdp = 0;
    uint8_t uid[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int uidlen = 0;
    bool verbose =  false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (param_getchar(Cmd, cmdp)) {
            case 'h':
            case 'H':
                return usage_hf_felica_sim();
            case 't':
            case 'T':
                // Retrieve the tag type
                tagtype = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (tagtype == 0)
                    errors = true;
                cmdp += 2;
                break;
            case 'u':
            case 'U':
                // Retrieve the full 4,7,10 byte long uid
                param_gethex_ex(Cmd, cmdp + 1, uid, &uidlen);
                if (!errors) {
                    PrintAndLogEx(NORMAL, "Emulating ISO18092/FeliCa tag with %d byte UID (%s)", uidlen >> 1, sprint_hex(uid, uidlen >> 1));
                }
                cmdp += 2;
                break;
            case 'v':
            case 'V':
                verbose = true;
                cmdp++;
                break;
            case 'e':
            case 'E':
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors || cmdp == 0) return usage_hf_felica_sim();

    clearCommandBuffer();
    SendCommandOLD(CMD_HF_FELICA_SIMULATE,  tagtype, flags, 0, uid, uidlen >> 1);
    PacketResponseNG resp;

    if (verbose)
        PrintAndLogEx(NORMAL, "Press pm3-button to abort simulation");

    while (!kbd_enter_pressed()) {
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) continue;
    }
    return PM3_SUCCESS;
}
*/

static int CmdHFFelicaSniff(const char *Cmd) {
    uint8_t cmdp = 0;
    uint64_t samples2skip = 0;
    uint64_t triggers2skip = 0;
    bool errors = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (param_getchar(Cmd, cmdp)) {
            case 'h':
            case 'H':
                return usage_hf_felica_sniff();
            case 's':
            case 'S':
                samples2skip = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            case 't':
            case 'T':
                triggers2skip = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors || cmdp == 0) return usage_hf_felica_sniff();

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_FELICA_SNIFF, samples2skip, triggers2skip, 0, NULL, 0);
    return PM3_SUCCESS;
}

// uid  hex
static int CmdHFFelicaSimLite(const char *Cmd) {
    uint64_t uid = param_get64ex(Cmd, 0, 0, 16);

    if (!uid)
        return usage_hf_felica_simlite();

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_FELICALITE_SIMULATE, uid, 0, 0, NULL, 0);
    return PM3_SUCCESS;
}

static void printSep() {
    PrintAndLogEx(NORMAL, "------------------------------------------------------------------------------------");
}

static uint16_t PrintFliteBlock(uint16_t tracepos, uint8_t *trace, uint16_t tracelen) {
    if (tracepos + 19 >= tracelen)
        return tracelen;

    trace += tracepos;
    uint8_t blocknum = trace[0];
    uint8_t status1 = trace[1];
    uint8_t status2 = trace[2];

    char line[110] = {0};
    for (int j = 0; j < 16; j++) {
        snprintf(line + (j * 4), sizeof(line) - 1 - (j * 4), "%02x  ", trace[j + 3]);
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
            uint32_t regA = trace[3] | trace[4] << 8 | trace[5] << 16 | trace[ 6] << 24;
            uint32_t regB = trace[7] | trace[8] << 8 | trace[9] << 16 | trace[10] << 24;
            line[0] = 0;
            for (int j = 0; j < 8; j++)
                snprintf(line + (j * 2), sizeof(line) - 1 - (j * 2), "%02x", trace[j + 11]);

            PrintAndLogEx(NORMAL,  "REG: regA: %d regB: %d regC: %s ", regA, regB, line);
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
            PrintAndLogEx(NORMAL,  "Write count, RO:   %02x %02x %02x ", trace[3], trace[4], trace[5]);
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

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return usage_hf_felica_dumplite();

    PrintAndLogEx(SUCCESS, "FeliCa lite - dump started");
    PrintAndLogEx(SUCCESS, "press pm3-button to cancel");
    clearCommandBuffer();
    SendCommandNG(CMD_HF_FELICALITE_DUMP, NULL, 0);
    PacketResponseNG resp;

    uint8_t timeout = 0;
    while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        timeout++;
        printf(".");
        fflush(stdout);
        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\n[!] aborted via keyboard!\n");
            DropField();
            return PM3_EOPABORTED;
        }
        if (timeout > 100) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            DropField();
            return PM3_ETIMEOUT;
        }
    }
    if (resp.oldarg[0] == 0) {
        PrintAndLogEx(WARNING, "\nButton pressed. Aborted.");
        return PM3_EOPABORTED;
    }

    uint32_t tracelen = resp.oldarg[1];
    if (tracelen == 0) {
        PrintAndLogEx(WARNING, "\nNo trace data! Maybe not a FeliCa Lite card?");
        return PM3_ESOFT;
    }

    uint8_t *trace = calloc(tracelen, sizeof(uint8_t));
    if (trace == NULL) {
        PrintAndLogEx(WARNING, "Cannot allocate memory for trace");
        return PM3_EMALLOC;
    }

    if (!GetFromDevice(BIG_BUF, trace, tracelen, 0, NULL, 0, NULL, 2500, false)) {
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
    bool reply = 1;
    bool crc = false;
    bool power = false;
    bool active = false;
    bool active_select = false;
    uint16_t numbits = 0;
    char buf[5] = "";
    int i = 0;
    uint8_t data[PM3_CMD_DATA_SIZE];
    uint16_t datalen = 0;
    uint32_t temp;

    if (strlen(Cmd) < 2) return usage_hf_felica_raw();

    // strip
    while (*Cmd == ' ' || *Cmd == '\t') Cmd++;

    while (Cmd[i] != '\0') {
        if (Cmd[i] == ' ' || Cmd[i] == '\t') { i++; continue; }
        if (Cmd[i] == '-') {
            switch (Cmd[i + 1]) {
                case 'H':
                case 'h':
                    return usage_hf_felica_raw();
                case 'r':
                    reply = false;
                    break;
                case 'c':
                    crc = true;
                    break;
                case 'p':
                    power = true;
                    break;
                case 'a':
                    active = true;
                    break;
                case 's':
                    active_select = true;
                    break;
                case 'b':
                    sscanf(Cmd + i + 2, "%d", &temp);
                    numbits = temp & 0xFFFF;
                    i += 3;
                    while (Cmd[i] != ' ' && Cmd[i] != '\0') { i++; }
                    i -= 2;
                    break;
                default:
                    return usage_hf_felica_raw();
            }
            i += 2;
            continue;
        }
        if ((Cmd[i] >= '0' && Cmd[i] <= '9') ||
                (Cmd[i] >= 'a' && Cmd[i] <= 'f') ||
                (Cmd[i] >= 'A' && Cmd[i] <= 'F')) {
            buf[strlen(buf) + 1] = 0;
            buf[strlen(buf)] = Cmd[i];
            i++;

            if (strlen(buf) >= 2) {
                sscanf(buf, "%x", &temp);
                data[datalen] = (uint8_t)(temp & 0xff);
                *buf = 0;
                if (++datalen >= sizeof(data)) {
                    if (crc)
                        PrintAndLogEx(NORMAL, "Buffer is full, we can't add CRC to your data");
                    break;
                }
            }
            continue;
        }
        PrintAndLogEx(WARNING, "Invalid char on input");
        return PM3_EINVARG;
    }

    if (crc) {
        AddCrc(data, datalen);
        datalen += 2;
    }

    uint8_t flags = 0;
    if (active || active_select) {
        flags |= FELICA_CONNECT;
        if (active)
            flags |= FELICA_NO_SELECT;
    }

    if (power) {
        flags |= FELICA_NO_DISCONNECT;
    }

    if (datalen > 0) {
        flags |= FELICA_RAW;
    }

    // Max buffer is PM3_CMD_DATA_SIZE
    datalen = (datalen > PM3_CMD_DATA_SIZE) ? PM3_CMD_DATA_SIZE : datalen;

    clearCommandBuffer();
    PrintAndLogEx(NORMAL, "Data: %s", sprint_hex(data, datalen));
    SendCommandMIX(CMD_HF_FELICA_COMMAND, flags, (datalen & 0xFFFF) | (uint32_t)(numbits << 16), 0, data, datalen);

    if (reply) {
        if (active_select) {
            PrintAndLogEx(NORMAL, "Active select wait for FeliCa.");
            PacketResponseNG resp_IDm;
            waitCmdFelica(1, &resp_IDm, 1);
        }
        if (datalen > 0) {
            PacketResponseNG resp_frame;
            waitCmdFelica(0, &resp_frame, 1);
        }
    }
    return PM3_SUCCESS;
}

int readFelicaUid(bool verbose) {

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_FELICA_COMMAND, FELICA_CONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
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
            PrintAndLogEx(SUCCESS, "FeliCa tag info");

            PrintAndLogEx(NORMAL, "IDm  %s", sprint_hex(card.IDm, sizeof(card.IDm)));
            PrintAndLogEx(NORMAL, "  - CODE    %s", sprint_hex(card.code, sizeof(card.code)));
            PrintAndLogEx(NORMAL, "  - NFCID2  %s", sprint_hex(card.uid, sizeof(card.uid)));

            PrintAndLogEx(NORMAL, "Parameter (PAD) | %s", sprint_hex(card.PMm, sizeof(card.PMm)));
            PrintAndLogEx(NORMAL, "  - IC CODE %s", sprint_hex(card.iccode, sizeof(card.iccode)));
            PrintAndLogEx(NORMAL, "  - MRT     %s", sprint_hex(card.mrt, sizeof(card.mrt)));

            PrintAndLogEx(NORMAL, "SERVICE CODE %s", sprint_hex(card.servicecode, sizeof(card.servicecode)));
            set_last_known_card(card);
            break;
        }
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"----------- General -----------", CmdHelp,                IfPm3Iso14443a,  ""},
    {"help",                CmdHelp,              AlwaysAvailable, "This help"},
    {"list",                CmdHFFelicaList,      AlwaysAvailable,     "List ISO 18092/FeliCa history"},
    {"reader",              CmdHFFelicaReader,    IfPm3Felica,     "Act like an ISO18092/FeliCa reader"},
    {"sniff",               CmdHFFelicaSniff,     IfPm3Felica,     "Sniff ISO 18092/FeliCa traffic"},
    {"raw",                 CmdHFFelicaCmdRaw,    IfPm3Felica,     "Send raw hex data to tag"},
    {"----------- FeliCa Standard (support in progress) -----------", CmdHelp,                IfPm3Iso14443a,  ""},
    //{"dump",              CmdHFFelicaDump,                 IfPm3Felica,     "Wait for and try dumping FeliCa"},
    {"rqservice",           CmdHFFelicaRequestService,       IfPm3Felica,     "verify the existence of Area and Service, and to acquire Key Version."},
    {"rqresponse",          CmdHFFelicaRequestResponse,      IfPm3Felica,     "verify the existence of a card and its Mode."},
    {"rdunencrypted",      CmdHFFelicaReadWithoutEncryption,    IfPm3Felica,     "read Block Data from authentication-not-required Service."},
    {"wrunencrypted",      CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "write Block Data to an authentication-not-required Service."},
    //{"scsvcode",      CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "acquire Area Code and Service Code."},
    //{"rqsyscode",         CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "acquire System Code registered to the card."},
    //{"auth1",             CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "authenticate a card."},
    //{"auth2",             CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "allow a card to authenticate a Reader/Writer."},
    //{"read",              CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "read Block Data from authentication-required Service."},
    //{"write",             CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "write Block Data to an authentication-required Service."},
    //{"scsvcodev2",    CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "verify the existence of Area or Service, and to acquire Key Version."},
    //{"getsysstatus",      CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "acquire the setup information in System."},
    //{"rqspecver",         CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "acquire the version of card OS."},
    //{"resetmode",         CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "reset Mode to Mode 0."},
    //{"auth1v2",           CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "authenticate a card."},
    //{"auth2v2",           CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "allow a card to authenticate a Reader/Writer."},
    //{"readv2",            CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "read Block Data from authentication-required Service."},
    //{"writev2",           CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "write Block Data to authentication-required Service."},
    //{"uprandomid",        CmdHFFelicaNotImplementedYet,    IfPm3Felica,     "update Random ID (IDr)."},
    {"----------- FeliCa Light -----------", CmdHelp,                IfPm3Iso14443a,  ""},
    {"litesim",             CmdHFFelicaSimLite,   IfPm3Felica,     "<NDEF2> - only reply to poll request"},
    {"litedump",            CmdHFFelicaDumpLite,  IfPm3Felica,     "Wait for and try dumping FelicaLite"},
    //    {"sim",           CmdHFFelicaSim,       IfPm3Felica,     "<UID> -- Simulate ISO 18092/FeliCa tag"}
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
