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
#include "mbedtls/des.h"
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
    PrintAndLogEx(NORMAL, "\nInfo: It get data from the field and saves it into command buffer. ");
    PrintAndLogEx(NORMAL, "        Buffer accessible from command 'hf list felica'");
    PrintAndLogEx(NORMAL, "\nUsage:  hf felica sniff [-h] [-s] [-t]");
    PrintAndLogEx(NORMAL, "       -h    this help");
    PrintAndLogEx(NORMAL, "       -s    samples to skip (decimal) max 9999");
    PrintAndLogEx(NORMAL, "       -t    triggers to skip (decimal) max 9999");

    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "          hf felica sniff");
    PrintAndLogEx(NORMAL, "          hf felica sniff -s 10 -t 10");
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
    PrintAndLogEx(NORMAL, " hf felica rqresponse -i 01100910c11bc407");
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

static void print_block_list_element_constraints() {
    PrintAndLogEx(NORMAL, "       - Each Block List Element shall satisfy the following conditions:");
    PrintAndLogEx(NORMAL, "              - The value of Service Code List Order shall not exceed Number of Service.");
    PrintAndLogEx(NORMAL, "              - Access Mode shall be 000b.");
    PrintAndLogEx(NORMAL, "              - The target specified by Service Code shall not be Area or System.");
    PrintAndLogEx(NORMAL, "              - Service specified in Service Code List shall exist in System.");
    PrintAndLogEx(NORMAL, "              - Service Attribute of Service specified in Service Code List shall be authentication-not-required Service.");
    PrintAndLogEx(NORMAL, "              - Block Number shall be in the range of the number of Blocks assigned to the specified Service.");
}

static void print_number_of_service_constraints() {
    PrintAndLogEx(NORMAL, "       - Number of Service: shall be a positive integer in the range of 1 to 16, inclusive.");
}

static void print_number_of_block_constraints() {
    PrintAndLogEx(NORMAL, "       - Number of Block: shall be less than or equal to the maximum number of Blocks that can be read simultaneously. "
                  "The maximum number of Blocks that can be read simultaneously can differ, depending on the product being used. Use as default 01");
}

static void print_service_code_list_constraints() {
    PrintAndLogEx(NORMAL, "       - Service Code List: For Service Code List, only Service Code existing in the product shall be specified:");
    PrintAndLogEx(NORMAL, "              - Even when Service Code exists in the product, Service Code not referenced from Block List shall not be specified to Service Code List.");
    PrintAndLogEx(NORMAL, "              - For existence or nonexistence of Service in a product, please check using the Request Service (or Request Service v2) command.");
}

static int usage_hf_felica_read_without_encryption() {
    PrintAndLogEx(NORMAL, "\nInfo: Use this command to read Block Data from authentication-not-required Service.");
    PrintAndLogEx(NORMAL, "       - Mode shall be Mode0.");
    print_number_of_service_constraints();
    print_number_of_block_constraints();
    print_service_code_list_constraints();
    print_block_list_element_constraints();
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
    PrintAndLogEx(NORMAL, "  hf felica rdunencrypted -b 01 4B18 01 8000\n\n");
    return PM3_SUCCESS;
}

static int usage_hf_felica_write_without_encryption() {
    PrintAndLogEx(NORMAL, "\nInfo: Use this command to write Block Data to authentication-not-required Service.");
    PrintAndLogEx(NORMAL, "       - Mode shall be Mode0.");
    print_number_of_service_constraints();
    print_number_of_block_constraints();
    print_service_code_list_constraints();
    print_block_list_element_constraints();
    PrintAndLogEx(NORMAL, "       - Un-/Successful read: Card responses with Status Flag1 and Flag2");
    print_status_flag1_interpretation();
    print_status_flag2_interpration();
    PrintAndLogEx(NORMAL, "\nUsage: hf felica wrunencrypted [-h][-i] <01 Number of Service hex> <0A0B Service Code List (Little Endian) hex> <01 Number of Block hex> <0A0B Block List Element hex> <0A0B0C0D0E0F... Data hex (16-Byte)>");
    PrintAndLogEx(NORMAL, "       -h    this help");
    PrintAndLogEx(NORMAL, "       -i    <0A0B0C ... hex> set custom IDm to use\n");
    PrintAndLogEx(NORMAL, "\nExamples: ");
    PrintAndLogEx(NORMAL, "  hf felica wrunencrypted 01 CB10 01 8001 0102030405060708090A0B0C0D0E0F10");
    PrintAndLogEx(NORMAL, "  hf felica wrunencrypted -i 11100910C11BC407 01 CB10 01 8001 0102030405060708090A0B0C0D0E0F10\n\n");
    return PM3_SUCCESS;
}

static int usage_hf_felica_request_system_code() {
    PrintAndLogEx(NORMAL, "\nInfo: Use this command to acquire System Code registered to the card.");
    PrintAndLogEx(NORMAL, "       - If a card is divided into more than one System, this command acquires System Code of each System existing in the card.");
    PrintAndLogEx(NORMAL, "\nUsage: hf felica rqsyscode [-h] [-i]");
    PrintAndLogEx(NORMAL, "       -h    this help");
    PrintAndLogEx(NORMAL, "       -i    <0A0B0C ... hex> set custom IDm to use");
    PrintAndLogEx(NORMAL, "\nExamples: ");
    PrintAndLogEx(NORMAL, "  hf felica rqsyscode ");
    PrintAndLogEx(NORMAL, "  hf felica rqsyscode -i 11100910C11BC407\n\n");
    return PM3_SUCCESS;
}

static int usage_hf_felica_reset_mode() {
    PrintAndLogEx(NORMAL, "\nInfo: Use this command to reset Mode to Mode 0.");
    print_status_flag1_interpretation();
    print_status_flag2_interpration();
    PrintAndLogEx(NORMAL, "\nUsage: hf felica resetmode [-h][-i][-r]");
    PrintAndLogEx(NORMAL, "       -h    this help");
    PrintAndLogEx(NORMAL, "       -i    <0A0B0C ... hex> set custom IDm to use");
    PrintAndLogEx(NORMAL, "       -r    <0A0B hex> set custom reserve to use");
    PrintAndLogEx(NORMAL, "\nExamples: ");
    PrintAndLogEx(NORMAL, "  hf felica resetmode ");
    PrintAndLogEx(NORMAL, "  hf felica resetmode -r 0001");
    PrintAndLogEx(NORMAL, "  hf felica resetmode -i 11100910C11BC407\n\n");
    return PM3_SUCCESS;
}

static int usage_hf_felica_request_specification_version() {
    PrintAndLogEx(NORMAL, "\nInfo: Use this command to acquire the version of card OS.");
    PrintAndLogEx(NORMAL, "  - Response:");
    PrintAndLogEx(NORMAL, "    - Format Version: Fixed value 00h. Provided only if Status Flag1 = 00h.");
    PrintAndLogEx(NORMAL, "    - Basic Version: Each value of version is expressed in BCD notation <Little Endian>. Provided only if Status Flag1 = 00h.");
    PrintAndLogEx(NORMAL, "    - Number of Option: value = 0: AES card, value = 1: AES/DES card. Provided only if Status Flag1 = 00h.");
    PrintAndLogEx(NORMAL, "    - Option Version List: Provided only if Status Flag1 = 00h.");
    PrintAndLogEx(NORMAL, "       - For AES card: not added.");
    PrintAndLogEx(NORMAL, "       - For AES/DES card: DES option version is added - BCD notation <Little Endian>.");
    print_status_flag1_interpretation();
    print_status_flag2_interpration();
    PrintAndLogEx(NORMAL, "\nUsage: hf felica rqspecver [-h][-i][-r]");
    PrintAndLogEx(NORMAL, "       -h    this help");
    PrintAndLogEx(NORMAL, "       -i    <0A0B0C ... hex> set custom IDm to use");
    PrintAndLogEx(NORMAL, "       -r    <0A0B hex> set custom reserve to use");
    PrintAndLogEx(NORMAL, "\nExamples: ");
    PrintAndLogEx(NORMAL, "  hf felica rqspecver ");
    PrintAndLogEx(NORMAL, "  hf felica rqspecver -r 0001");
    PrintAndLogEx(NORMAL, "  hf felica rqspecver -i 11100910C11BC407\n\n");
    return PM3_SUCCESS;
}

static int usage_hf_felica_authentication1() {
    PrintAndLogEx(NORMAL, "\nInfo: Initiate mutual authentication. This command must always be executed before Authentication2 command"
                  ", and mutual authentication is achieve only after Authentication2 command has succeeded.");
    PrintAndLogEx(NORMAL, "  - Auth1 Parameters:");
    PrintAndLogEx(NORMAL, "    - Number of Areas n: 1-byte (1 <= n <= 8)");
    PrintAndLogEx(NORMAL, "    - Area Code List: 2n byte");
    PrintAndLogEx(NORMAL, "    - Number of Services m: 1-byte (1 <= n <= 8)");
    PrintAndLogEx(NORMAL, "    - Service Code List: 2n byte");
    PrintAndLogEx(NORMAL, "    - 3DES-Key: 128-bit master secret used for the encryption");
    PrintAndLogEx(NORMAL, "    - M1c: Encrypted random number - challenge for tag authentication (8-byte)");
    PrintAndLogEx(NORMAL, "  - Response:");
    PrintAndLogEx(NORMAL, "    - Response Code: 11h 1-byte");
    PrintAndLogEx(NORMAL, "    - Manufacture ID(IDm): 8-byte");
    PrintAndLogEx(NORMAL, "    - M2c: 8-byte");
    PrintAndLogEx(NORMAL, "    - M3c: 8-byte");
    PrintAndLogEx(NORMAL, "  - Success: Card Mode switches to Mode1. You can check this with the request response command.");
    PrintAndLogEx(NORMAL, "  - Unsuccessful: Card should not respond at all.");

    PrintAndLogEx(NORMAL, "\nUsage: hf felica auth1 [-h][-i] <01 Number of Areas hex> <0A0B... Area Code List hex> <01 Number of Services hex> <0A0B... Service Code List hex> <0x0102030405060809... 3DES-key hex (16-byte)>");
    PrintAndLogEx(NORMAL, "       -h    this help");
    PrintAndLogEx(NORMAL, "       -i    <0A0B0C ... hex> set custom IDm to use");
    PrintAndLogEx(NORMAL, "\nExamples: ");
    PrintAndLogEx(NORMAL, "  hf felica auth1 01 0000 01 8B00 AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB ");
    PrintAndLogEx(NORMAL, "  hf felica auth1 01 0000 01 8B00 AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBAAAAAAAAAAAAAAAA ");
    PrintAndLogEx(NORMAL, "  hf felica auth1 -i 11100910C11BC407 01 0000 01 8B00 AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB\n\n");
    return PM3_SUCCESS;
}

static int usage_hf_felica_authentication2() {
    PrintAndLogEx(NORMAL, "\nInfo: Complete mutual authentication. This command can only be executed subsquent to Authentication1"
                  " command.");
    PrintAndLogEx(NORMAL, "  - Auth2 Parameters:");
    PrintAndLogEx(NORMAL, "    - Manufacturer IDm: (8-byte)");
    PrintAndLogEx(NORMAL, "    - M3c: card challenge (8-byte)");
    PrintAndLogEx(NORMAL, "    - 3DES Key: key used for decryption of M3c (16-byte)");
    PrintAndLogEx(NORMAL, "  - Response (encrypted):");
    PrintAndLogEx(NORMAL, "    - Response Code: 13h (1-byte)");
    PrintAndLogEx(NORMAL, "    - IDtc:  (8-byte)");
    PrintAndLogEx(NORMAL, "    - IDi (encrypted):  (8-byte)");
    PrintAndLogEx(NORMAL, "    - PMi (encrypted):  (8-byte)");
    PrintAndLogEx(NORMAL, "  - Success: Card switches to mode2 and sends response frame.");
    PrintAndLogEx(NORMAL, "  - Unsuccessful: Card should not respond at all.");
    PrintAndLogEx(NORMAL, "\nUsage: hf felica auth2 [-h][-i] <0102030405060708 M3c hex> <0x0102030405060809... 3DES-key hex (16-byte)>");
    PrintAndLogEx(NORMAL, "       -h    this help");
    PrintAndLogEx(NORMAL, "       -i    <0A0B0C ... hex> set custom IDm to use");
    PrintAndLogEx(NORMAL, "\nExamples: ");
    PrintAndLogEx(NORMAL, "  hf felica auth2 0102030405060708 AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB");
    PrintAndLogEx(NORMAL, "  hf felica auth2 -i 11100910C11BC407 0102030405060708 AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB\n\n");

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
            PrintAndLogEx(SUCCESS, "Client Received %i octets", len);
            if (len == 0 || len == 1) {
                PrintAndLogEx(ERR, "Could not receive data correctly!");
                return false;
            }
            PrintAndLogEx(SUCCESS, "%s", sprint_hex(resp->data.asBytes, len));
            if (!check_crc(CRC_FELICA, resp->data.asBytes + 2, len - 2)) {
                PrintAndLogEx(WARNING, "Wrong or no CRC bytes");
            }
            if (resp->data.asBytes[0] != 0xB2 && resp->data.asBytes[1] != 0x4D) {
                PrintAndLogEx(ERR, "Received incorrect Frame Format!");
                return false;
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
        PrintAndLogEx(INFO, "Send raw command - Frame: %s", sprint_hex(data, datalen));
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
        
        if (param_gethex(Cmd, paramCount, data + dataPosition, length) == 1)
            return false;    
        else 
            return true;

    } else {
        PrintAndLogEx(ERR, "Param %s", Cmd);
        PrintAndLogEx(ERR, "Incorrect Parameter length! Param %i should be %i", paramCount, length);
        return false;
    }
}

/**
 * Prints read-without-encryption response.
 * @param rd_noCry_resp Response frame.
 */
static void print_rd_noEncrpytion_response(felica_read_without_encryption_response_t *rd_noCry_resp) {

    if (rd_noCry_resp->status_flags.status_flag1[0] == 00 &&
        rd_noCry_resp->status_flags.status_flag2[0] == 00) {

        char *temp = sprint_hex(rd_noCry_resp->block_data, sizeof(rd_noCry_resp->block_data));

        char bl_data[256];
        strncpy(bl_data, temp, sizeof(bl_data) - 1);

        char bl_element_number[4];
        temp = sprint_hex(rd_noCry_resp->block_element_number, sizeof(rd_noCry_resp->block_element_number));
        strncpy(bl_element_number, temp, sizeof(bl_element_number) - 1);

        PrintAndLogEx(INFO, "\t%s\t|  %s  ", bl_element_number, bl_data);
    } else {
        PrintAndLogEx(SUCCESS, "IDm: %s", sprint_hex(rd_noCry_resp->frame_response.IDm, sizeof(rd_noCry_resp->frame_response.IDm)));
        PrintAndLogEx(SUCCESS, "Status Flag1: %s", sprint_hex(rd_noCry_resp->status_flags.status_flag1, sizeof(rd_noCry_resp->status_flags.status_flag1)));
        PrintAndLogEx(SUCCESS, "Status Flag2: %s", sprint_hex(rd_noCry_resp->status_flags.status_flag1, sizeof(rd_noCry_resp->status_flags.status_flag1)));
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
            PrintAndLogEx(ERR, "\nGot no response from card");
            return PM3_ERFTRANS;
        }
        felica_request_service_response_t rqs_response;
        memcpy(&rqs_response, (felica_request_service_response_t *)resp.data.asBytes, sizeof(felica_request_service_response_t));

        if (rqs_response.frame_response.IDm[0] != 0) {
            PrintAndLogEx(SUCCESS, "\nGot Service Response:");
            PrintAndLogEx(SUCCESS, "IDm: %s", sprint_hex(rqs_response.frame_response.IDm, sizeof(rqs_response.frame_response.IDm)));
            PrintAndLogEx(SUCCESS, "  -Node Number: %s", sprint_hex(rqs_response.node_number, sizeof(rqs_response.node_number)));
            PrintAndLogEx(SUCCESS, "  -Node Key Version List: %s\n", sprint_hex(rqs_response.node_key_versions, sizeof(rqs_response.node_key_versions)));
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
int send_rd_unencrypted(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose, felica_read_without_encryption_response_t *rd_noCry_resp) {
    clear_and_send_command(flags, datalen, data, verbose);
    PacketResponseNG resp;
    if (!waitCmdFelica(0, &resp, verbose)) {
        PrintAndLogEx(ERR, "\nGot no response from card");
        return PM3_ERFTRANS;
    } else {
        memcpy(rd_noCry_resp, (felica_read_without_encryption_response_t *)resp.data.asBytes, sizeof(felica_read_without_encryption_response_t));
        rd_noCry_resp->block_element_number[0] = data[15];
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
    if (!add_last_IDm(2, data)) {
        PrintAndLogEx(ERR, "No last known card! Use reader first or set a custom IDm!");
        return 0;
    } else {
        PrintAndLogEx(INFO, "Used last known IDm. %s", sprint_hex(data, datalen));
        return 1;
    }
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
int send_wr_unencrypted(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose, felica_status_response_t *wr_noCry_resp) {
    clear_and_send_command(flags, datalen, data, verbose);
    PacketResponseNG resp;
    if (!waitCmdFelica(0, &resp, verbose)) {
        PrintAndLogEx(ERR, "\nGot no response from card");
        return PM3_ERFTRANS;
    } else {
        memcpy(wr_noCry_resp, (felica_status_response_t *)resp.data.asBytes, sizeof(felica_status_response_t));
        return PM3_SUCCESS;
    }
}

/**
 * Reverses the master secret. Example: AA AA AA AA AA AA AA BB to BB AA AA AA AA AA AA AA
 * @param master_key the secret which order will be reversed.
 * @param length in bytes of the master secret.
 * @param reverse_master_key output in which the reversed secret is stored.
 */
static void reverse_3des_key(uint8_t *master_key, int length, uint8_t *reverse_master_key) {
    for (int i = 0; i < length; i++) {
        reverse_master_key[i] = master_key[(length - 1) - i];
    }
};

/**
 * Command parser for auth1
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaAuthentication1(const char *Cmd) {
    if (strlen(Cmd) < 4) {
        return usage_hf_felica_authentication1();
    }

    PrintAndLogEx(INFO, "EXPERIMENTAL COMMAND");
    uint8_t data[PM3_CMD_DATA_SIZE];
    bool custom_IDm = false;
    strip_cmds(Cmd);
    uint16_t datalen = 24; // Length (1), Command ID (1), IDm (8), Number of Area (1), Area Code List (2), Number of Service (1), Service Code List (2), M1c (8)
    uint8_t paramCount = 0;
    uint8_t flags = 0;
    int i = 0;
    while (Cmd[i] != '\0') {
        if (Cmd[i] == '-') {
            switch (tolower(Cmd[i + 1])) {
                case 'h':
                    return usage_hf_felica_authentication1();
                case 'i':
                    paramCount++;
                    custom_IDm = true;
                    if (!add_param(Cmd, paramCount, data, 2, 16)) {
                        return PM3_EINVARG;
                    }
                    paramCount++;
                    i += 16;
                    break;
                default:
                    return usage_hf_felica_authentication1();
            }
        }
        i++;
    }
    data[0] = int_to_hex(&datalen);
    data[1] = 0x10; // Command ID
    if (!custom_IDm && !check_last_idm(data, datalen)) {
        return PM3_EINVARG;
    }
    // Number of Area (1), Area Code List (2), Number of Service (1), Service Code List (2), M1c (8)
    uint8_t lengths[] = {2, 4, 2, 4};
    uint8_t dataPositions[] = {10, 11, 13, 14};
    for (i = 0; i < 4; i++) {
        if (add_param(Cmd, paramCount, data, dataPositions[i], lengths[i])) {
            paramCount++;
        } else {
            return PM3_EINVARG;
        }
    }

    // READER CHALLENGE - (RANDOM To Encrypt = Rac)
    unsigned char input[8];
    input[0] = 0x1;
    input[1] = 0x2;
    input[2] = 0x3;
    input[3] = 0x4;
    input[4] = 0x5;
    input[5] = 0x6;
    input[6] = 0x7;
    input[7] = 0x8;
    PrintAndLogEx(INFO, "Reader challenge (unencrypted): %s", sprint_hex(input, 8));
    unsigned char output[8];
    // Create M1c Challenge with 3DES (3 Keys = 24, 2 Keys = 16)
    uint8_t master_key[PM3_CMD_DATA_SIZE];
    mbedtls_des3_context des3_ctx;
    mbedtls_des3_init(&des3_ctx);
    if (param_getlength(Cmd, paramCount) == 48) {
        if (param_gethex(Cmd, paramCount, master_key, 48) == 1) {
            PrintAndLogEx(ERR, "Failed param key");
            return PM3_EINVARG;
        }
        mbedtls_des3_set3key_enc(&des3_ctx, master_key);
        PrintAndLogEx(INFO, "3DES Master Secret: %s", sprint_hex(master_key, 24));
    } else if (param_getlength(Cmd, paramCount) == 32) {
        
        if (param_gethex(Cmd, paramCount, master_key, 32) == 1) {
            PrintAndLogEx(ERR, "Failed param key");
            return PM3_EINVARG;
        }

        // Assumption: Master secret split in half for Kac, Kbc
        mbedtls_des3_set2key_enc(&des3_ctx, master_key);
        PrintAndLogEx(INFO, "3DES Master Secret: %s", sprint_hex(master_key, 16));
    } else {
        PrintAndLogEx(ERR, "Invalid key length");
        return PM3_EINVARG;
    }

    mbedtls_des3_crypt_ecb(&des3_ctx, input, output);
    PrintAndLogEx(INFO, "3DES ENCRYPTED M1c: %s", sprint_hex(output, 8));
    // Add M1c Challenge to frame
    int frame_position = 16;
    for (i = 0; i < 8; i++) {
        data[frame_position++] = output[i];
    }

    AddCrc(data, datalen);
    datalen += 2;
    flags |= FELICA_APPEND_CRC;
    flags |= FELICA_RAW;

    PrintAndLogEx(INFO, "Client Send AUTH1 Frame: %s", sprint_hex(data, datalen));
    clear_and_send_command(flags, datalen, data, 0);

    PacketResponseNG resp;
    if (!waitCmdFelica(0, &resp, 1)) {
        PrintAndLogEx(ERR, "\nGot no Response from card");
        return PM3_ERFTRANS;
    } else {
        felica_auth1_response_t auth1_response;
        memcpy(&auth1_response, (felica_auth1_response_t *)resp.data.asBytes, sizeof(felica_auth1_response_t));
        if (auth1_response.frame_response.IDm[0] != 0) {
            PrintAndLogEx(SUCCESS, "\nGot auth1 response:");
            PrintAndLogEx(SUCCESS, "IDm: %s", sprint_hex(auth1_response.frame_response.IDm, sizeof(auth1_response.frame_response.IDm)));
            PrintAndLogEx(SUCCESS, "M2C: %s", sprint_hex(auth1_response.m2c, sizeof(auth1_response.m2c)));
            PrintAndLogEx(SUCCESS, "M3C: %s", sprint_hex(auth1_response.m3c, sizeof(auth1_response.m3c)));
            // Assumption: Key swap method used
            uint8_t reverse_master_key[PM3_CMD_DATA_SIZE];
            reverse_3des_key(master_key, 16, reverse_master_key);
            mbedtls_des3_set2key_dec(&des3_ctx, reverse_master_key);
            bool isKeyCorrect = false;
            unsigned char p2c[8];
            mbedtls_des3_crypt_ecb(&des3_ctx, auth1_response.m2c, p2c);
            for (i = 0; i < 8; i++) {
                if (p2c[i] != input[i]) {
                    isKeyCorrect = false;
                    break;
                } else {
                    isKeyCorrect = true;
                }
            }
            if (isKeyCorrect) {
                PrintAndLogEx(SUCCESS, "\nAuth1 done with correct key material! Use Auth2 now with M3C and same key");
            } else {
                PrintAndLogEx(INFO, "3DES secret (swapped decryption): %s", sprint_hex(reverse_master_key, 16));
                PrintAndLogEx(INFO, "P2c: %s", sprint_hex(p2c, 8));
                PrintAndLogEx(ERR, "Can't decrypt M2C with master secret (P1c != P2c)! Probably wrong keys or wrong decryption method");
            }
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
    if (strlen(Cmd) < 2) {
        return usage_hf_felica_authentication2();
    }
    PrintAndLogEx(INFO, "EXPERIMENTAL COMMAND - M2c/P2c will be not checked");
    uint8_t data[PM3_CMD_DATA_SIZE];
    bool custom_IDm = false;
    strip_cmds(Cmd);
    uint16_t datalen = 18; // Length (1), Command ID (1), IDm (8), M4c (8)
    uint8_t paramCount = 0;
    uint8_t flags = 0;
    int i = 0;
    while (Cmd[i] != '\0') {
        if (Cmd[i] == '-') {
            switch (tolower(Cmd[i + 1])) {
                case 'h':
                    return usage_hf_felica_authentication2();
                case 'i':
                    paramCount++;
                    custom_IDm = true;
                    if (!add_param(Cmd, paramCount, data, 2, 16)) {
                        return PM3_EINVARG;
                    }
                    paramCount++;
                    i += 16;
                    break;
                default:
                    return usage_hf_felica_authentication1();
            }
        }
        i++;
    }

    data[0] = int_to_hex(&datalen);
    data[1] = 0x12; // Command ID
    if (!custom_IDm && !check_last_idm(data, datalen)) {
        return PM3_EINVARG;
    }

    // M3c (8)
    unsigned char m3c[8];
    if (add_param(Cmd, paramCount, m3c, 0, 16)) {
        paramCount++;
    } else {
        return PM3_EINVARG;
    }

    // Create M4c challenge response with 3DES
    uint8_t master_key[PM3_CMD_DATA_SIZE];
    uint8_t reverse_master_key[PM3_CMD_DATA_SIZE];
    mbedtls_des3_context des3_ctx;
    mbedtls_des3_init(&des3_ctx);
    unsigned char p3c[8];
    if (param_getlength(Cmd, paramCount) == 32) {
        
        if (param_gethex(Cmd, paramCount, master_key, 32) == 1) {
            PrintAndLogEx(ERR, "Failed param key");
            return PM3_EINVARG;
        }
        reverse_3des_key(master_key, 16, reverse_master_key);
        mbedtls_des3_set2key_dec(&des3_ctx, reverse_master_key);
        mbedtls_des3_set2key_enc(&des3_ctx, master_key);
        // Assumption: Key swap method used for E2
        PrintAndLogEx(INFO, "3DES Master Secret (encryption): %s", sprint_hex(master_key, 16));
        PrintAndLogEx(INFO, "3DES Master Secret (decryption): %s", sprint_hex(reverse_master_key, 16));
    } else {
        PrintAndLogEx(ERR, "Invalid key length");
        return PM3_EINVARG;
    }
    // Decrypt m3c with reverse_master_key
    mbedtls_des3_crypt_ecb(&des3_ctx, m3c, p3c);
    PrintAndLogEx(INFO, "3DES decrypted M3c = P3c: %s", sprint_hex(p3c, 8));
    // Encrypt p3c with master_key
    unsigned char m4c[8];
    mbedtls_des3_crypt_ecb(&des3_ctx, p3c, m4c);
    PrintAndLogEx(INFO, "3DES encrypted M4c: %s", sprint_hex(m4c, 8));

    // Add M4c Challenge to frame
    int frame_position = 10;
    for (i = 0; i < 8; i++) {
        data[frame_position++] = m4c[i];
    }

    AddCrc(data, datalen);
    datalen += 2;
    flags |= FELICA_APPEND_CRC;
    flags |= FELICA_RAW;

    PrintAndLogEx(INFO, "Client Send AUTH2 Frame: %s", sprint_hex(data, datalen));
    clear_and_send_command(flags, datalen, data, 0);

    PacketResponseNG resp;
    if (!waitCmdFelica(0, &resp, 1)) {
        PrintAndLogEx(ERR, "\nGot no Response from card");
        return PM3_ERFTRANS;
    } else {
        felica_auth2_response_t auth2_response;
        memcpy(&auth2_response, (felica_auth2_response_t *)resp.data.asBytes, sizeof(felica_auth2_response_t));
        if (auth2_response.code[0] != 0x12) {
            PrintAndLogEx(SUCCESS, "\nGot auth2 response:");
            PrintAndLogEx(SUCCESS, "IDtc: %s", sprint_hex(auth2_response.IDtc, sizeof(auth2_response.IDtc)));
            PrintAndLogEx(SUCCESS, "IDi (encrypted): %s", sprint_hex(auth2_response.IDi, sizeof(auth2_response.IDi)));
            PrintAndLogEx(SUCCESS, "PMi (encrypted): %s", sprint_hex(auth2_response.PMi, sizeof(auth2_response.PMi)));
        } else {
            PrintAndLogEx(ERR, "\nGot wrong frame format.");
        }
    }
    return PM3_SUCCESS;
}


/**
 * Command parser for wrunencrypted.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaWriteWithoutEncryption(const char *Cmd) {
    if (strlen(Cmd) < 5)
        return usage_hf_felica_write_without_encryption();
    uint8_t data[PM3_CMD_DATA_SIZE];
    bool custom_IDm = false;
    strip_cmds(Cmd);
    uint16_t datalen = 32; // Length (1), Command ID (1), IDm (8), Number of Service (1), Service Code List(2), Number of Block(1), Block List(3), Block Data(16)
    uint8_t paramCount = 0;
    uint8_t flags = 0;
    int i = 0;
    while (Cmd[i] != '\0') {
        if (Cmd[i] == '-') {
            switch (tolower(Cmd[i + 1])) {
                case 'h':
                    return usage_hf_felica_write_without_encryption();
                case 'i':
                    paramCount++;
                    custom_IDm = true;
                    if (!add_param(Cmd, paramCount, data, 2, 16)) {
                        return PM3_EINVARG;
                    }
                    paramCount++;
                    i += 16;
                    break;
                default:
                    return usage_hf_felica_write_without_encryption();
            }
        }
        i++;
    }
    data[0] = 0x20; // Static length
    data[1] = 0x08; // Command ID
    if (!custom_IDm && !check_last_idm(data, datalen)) {
        return PM3_EINVARG;
    }
    // Number of Service 2, Service Code List 4, Number of Block 2, Block List Element 4, Data 16
    uint8_t lengths[] = {2, 4, 2, 4, 32};
    uint8_t dataPositions[] = {10, 11, 13, 14, 16};
    for (i = 0; i < 5; i++) {
        if (add_param(Cmd, paramCount, data, dataPositions[i], lengths[i])) {
            paramCount++;
        } else {
            return PM3_EINVARG;
        }
    }
    flags |= FELICA_APPEND_CRC;
    flags |= FELICA_RAW;
    AddCrc(data, datalen);
    datalen += 2;
    felica_status_response_t wr_noCry_resp;
    if (send_wr_unencrypted(flags, datalen, data, 1, &wr_noCry_resp) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nIDm: %s", sprint_hex(wr_noCry_resp.frame_response.IDm, sizeof(wr_noCry_resp.frame_response.IDm)));
        PrintAndLogEx(SUCCESS, "Status Flag1: %s", sprint_hex(wr_noCry_resp.status_flags.status_flag1, sizeof(wr_noCry_resp.status_flags.status_flag1)));
        PrintAndLogEx(SUCCESS, "Status Flag2: %s\n", sprint_hex(wr_noCry_resp.status_flags.status_flag2, sizeof(wr_noCry_resp.status_flags.status_flag2)));
        if (wr_noCry_resp.status_flags.status_flag1[0] == 0x00 && wr_noCry_resp.status_flags.status_flag2[0] == 0x00) {
            PrintAndLogEx(SUCCESS, "Writing data successful!\n");
        } else {
            PrintAndLogEx(ERR, "Something went wrong! Check status flags.\n");
        }
    }
    return PM3_SUCCESS;
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
            switch (tolower(Cmd[i + 1])) {
                case 'h':
                    return usage_hf_felica_read_without_encryption();
                case 'i':
                    paramCount++;
                    custom_IDm = true;
                    if (!add_param(Cmd, paramCount, data, 2, 16)) {
                        return PM3_EINVARG;
                    }
                    paramCount++;
                    i += 16;
                    break;
                case 'b':
                    paramCount++;
                    all_block_list_elements = true;
                    break;
                case 'l':
                    paramCount++;
                    long_block_numbers = true;
                    break;
                default:
                    return usage_hf_felica_read_without_encryption();
            }
        }
        i++;
    }
    data[0] = 0x10; // Static length
    data[1] = 0x06; // Command ID
    if (!custom_IDm && !check_last_idm(data, datalen)) {
        return PM3_EINVARG;
    }
    // Number of Service 2, Service Code List 4, Number of Block 2, Block List Element 4
    uint8_t lengths[] = {2, 4, 2, 4};
    uint8_t dataPositions[] = {10, 11, 13, 14};
    if (long_block_numbers) {
        datalen += 1;
        lengths[3] = 6;
    }
    for (i = 0; i < 4; i++) {
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
        PrintAndLogEx(INFO, "Block Element\t|  Data  ");
        for (i = 0x00; i < last_block_number; i++) {
            data[15] = i;
            AddCrc(data, datalen);
            datalen += 2;
            felica_read_without_encryption_response_t rd_noCry_resp;
            if ((send_rd_unencrypted(flags, datalen, data, 0, &rd_noCry_resp) == PM3_SUCCESS)) {
                if (rd_noCry_resp.status_flags.status_flag1[0] == 00 && rd_noCry_resp.status_flags.status_flag2[0] == 00) {
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
        if (send_rd_unencrypted(flags, datalen, data, 1, &rd_noCry_resp) == PM3_SUCCESS) {
            PrintAndLogEx(INFO, "Block Element\t|  Data  ");
            print_rd_noEncrpytion_response(&rd_noCry_resp);
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
    uint8_t data[PM3_CMD_DATA_SIZE];
    bool custom_IDm = false;
    strip_cmds(Cmd);
    uint16_t datalen = 10; // Length (1), Command ID (1), IDm (8)
    uint8_t paramCount = 0;
    uint8_t flags = 0;
    int i = 0;
    while (Cmd[i] != '\0') {
        if (Cmd[i] == '-') {
            switch (tolower(Cmd[i + 1])) {
                case 'h':
                    return usage_hf_felica_request_response();
                case 'i':
                    paramCount++;
                    custom_IDm = true;
                    if (!add_param(Cmd, paramCount, data, 2, 16)) {
                        return PM3_EINVARG;
                    }
                    paramCount++;
                    i += 16;
                    break;
                default:
                    return usage_hf_felica_request_response();
            }
        }
        i++;
    }
    data[0] = 0x0A; // Static length
    data[1] = 0x04; // Command ID
    if (!custom_IDm && !check_last_idm(data, datalen)) {
        return PM3_EINVARG;
    }
    AddCrc(data, datalen);
    datalen += 2;
    flags |= FELICA_APPEND_CRC;
    flags |= FELICA_RAW;
    clear_and_send_command(flags, datalen, data, 0);
    PacketResponseNG resp;
    if (!waitCmdFelica(0, &resp, 1)) {
        PrintAndLogEx(ERR, "\nGot no response from card");
        return PM3_ERFTRANS;
    } else {
        felica_request_request_response_t rq_response;
        memcpy(&rq_response, (felica_request_request_response_t *)resp.data.asBytes, sizeof(felica_request_request_response_t));
        if (rq_response.frame_response.IDm[0] != 0) {
            PrintAndLogEx(SUCCESS, "\nGot Request Response:");
            PrintAndLogEx(SUCCESS, "IDm: %s", sprint_hex(rq_response.frame_response.IDm, sizeof(rq_response.frame_response.IDm)));
            PrintAndLogEx(SUCCESS, "  -Mode: %s\n\n", sprint_hex(rq_response.mode, sizeof(rq_response.mode)));
        }
    }
    return PM3_SUCCESS;
}


/**
 * Command parser for rqspecver
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaRequestSpecificationVersion(const char *Cmd) {
    uint8_t data[PM3_CMD_DATA_SIZE];
    bool custom_IDm = false;
    bool custom_reserve = false;
    strip_cmds(Cmd);
    uint16_t datalen = 12; // Length (1), Command ID (1), IDm (8), Reserved (2)
    uint8_t paramCount = 0;
    uint8_t flags = 0;
    int i = 0;
    while (Cmd[i] != '\0') {
        if (Cmd[i] == '-') {
            switch (tolower(Cmd[i + 1])) {
                case 'h':
                    return usage_hf_felica_request_specification_version();
                case 'i':
                    paramCount++;
                    custom_IDm = true;
                    if (!add_param(Cmd, paramCount, data, 2, 16)) {
                        return PM3_EINVARG;
                    }
                    paramCount++;
                    i += 16;
                    break;
                case 'r':
                    paramCount++;
                    custom_reserve = true;
                    if (!add_param(Cmd, paramCount, data, 10, 4)) {
                        return PM3_EINVARG;
                    }
                    paramCount++;
                    i += 4;
                    break;
                default:
                    return usage_hf_felica_request_specification_version();
            }
        }
        i++;
    }
    data[0] = 0x0C; // Static length
    data[1] = 0x3C; // Command ID
    if (!custom_reserve) {
        data[10] = 0x00; // Reserved Value
        data[11] = 0x00; // Reserved Value
    }
    if (!custom_IDm && !check_last_idm(data, datalen)) {
        return PM3_EINVARG;
    }
    AddCrc(data, datalen);
    datalen += 2;
    flags |= FELICA_APPEND_CRC;
    flags |= FELICA_RAW;
    clear_and_send_command(flags, datalen, data, 0);
    PacketResponseNG resp;
    if (!waitCmdFelica(0, &resp, 1)) {
        PrintAndLogEx(ERR, "\nGot no response from card");
        return PM3_ERFTRANS;
    } else {
        felica_request_spec_response_t spec_response;
        memcpy(&spec_response, (felica_request_spec_response_t *)resp.data.asBytes, sizeof(felica_request_spec_response_t));
        
        if (spec_response.frame_response.IDm[0] != 0) {
            PrintAndLogEx(SUCCESS, "\nGot Request Response:");
            PrintAndLogEx(SUCCESS, "\nIDm: %s", sprint_hex(spec_response.frame_response.IDm, sizeof(spec_response.frame_response.IDm)));
            PrintAndLogEx(SUCCESS, "Status Flag1: %s", sprint_hex(spec_response.status_flags.status_flag1, sizeof(spec_response.status_flags.status_flag1)));
            PrintAndLogEx(SUCCESS, "Status Flag2: %s", sprint_hex(spec_response.status_flags.status_flag2, sizeof(spec_response.status_flags.status_flag2)));
            if (spec_response.status_flags.status_flag1[0] == 0x00) {
                PrintAndLogEx(SUCCESS, "Format Version: %s", sprint_hex(spec_response.format_version, sizeof(spec_response.format_version)));
                PrintAndLogEx(SUCCESS, "Basic Version: %s", sprint_hex(spec_response.basic_version, sizeof(spec_response.basic_version)));
                PrintAndLogEx(SUCCESS, "Number of Option: %s", sprint_hex(spec_response.number_of_option, sizeof(spec_response.number_of_option)));
                if (spec_response.number_of_option[0] == 0x01) {
                    PrintAndLogEx(SUCCESS, "Option Version List:");
                    for (i = 0; i < spec_response.number_of_option[0]; i++) {
                        PrintAndLogEx(SUCCESS, "  - %s", sprint_hex(spec_response.option_version_list + i * 2, sizeof(uint8_t) * 2));
                    }
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
    uint8_t data[PM3_CMD_DATA_SIZE];
    bool custom_IDm = false;
    bool custom_reserve = false;
    strip_cmds(Cmd);
    uint16_t datalen = 12; // Length (1), Command ID (1), IDm (8), Reserved (2)
    uint8_t paramCount = 0;
    uint8_t flags = 0;
    int i = 0;
    while (Cmd[i] != '\0') {
        if (Cmd[i] == '-') {
            switch (tolower(Cmd[i + 1])) {
                case 'h':
                    return usage_hf_felica_reset_mode();
                case 'i':
                    paramCount++;
                    custom_IDm = true;
                    if (!add_param(Cmd, paramCount, data, 2, 16)) {
                        return PM3_EINVARG;
                    }
                    paramCount++;
                    i += 16;
                    break;
                case 'r':
                    paramCount++;
                    custom_reserve = true;
                    if (!add_param(Cmd, paramCount, data, 10, 4)) {
                        return PM3_EINVARG;
                    }
                    paramCount++;
                    i += 4;
                    break;
                default:
                    return usage_hf_felica_reset_mode();
            }
        }
        i++;
    }
    data[0] = 0x0C; // Static length
    data[1] = 0x3E; // Command ID
    if (!custom_reserve) {
        data[10] = 0x00; // Reserved Value
        data[11] = 0x00; // Reserved Value
    }
    if (!custom_IDm && !check_last_idm(data, datalen)) {
        return PM3_EINVARG;
    }
    AddCrc(data, datalen);
    datalen += 2;
    flags |= FELICA_APPEND_CRC;
    flags |= FELICA_RAW;
    clear_and_send_command(flags, datalen, data, 0);
    PacketResponseNG resp;
    if (!waitCmdFelica(0, &resp, 1)) {
        PrintAndLogEx(ERR, "\nGot no response from card");
        return PM3_ERFTRANS;
    } else {
        felica_status_response_t reset_mode_response;
        memcpy(&reset_mode_response, (felica_status_response_t *)resp.data.asBytes, sizeof(felica_status_response_t));
        if (reset_mode_response.frame_response.IDm[0] != 0) {
            PrintAndLogEx(SUCCESS, "\nGot Request Response:");
            PrintAndLogEx(SUCCESS, "\nIDm: %s", sprint_hex(reset_mode_response.frame_response.IDm, sizeof(reset_mode_response.frame_response.IDm)));
            PrintAndLogEx(SUCCESS, "Status Flag1: %s", sprint_hex(reset_mode_response.status_flags.status_flag1, sizeof(reset_mode_response.status_flags.status_flag1)));
            PrintAndLogEx(SUCCESS, "Status Flag2: %s\n", sprint_hex(reset_mode_response.status_flags.status_flag2, sizeof(reset_mode_response.status_flags.status_flag2)));
        }
    }
    return PM3_SUCCESS;
}

/**
 * Command parser for rqsyscode
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaRequestSystemCode(const char *Cmd) {
    uint8_t data[PM3_CMD_DATA_SIZE];
    bool custom_IDm = false;
    strip_cmds(Cmd);
    uint16_t datalen = 10; // Length (1), Command ID (1), IDm (8)
    uint8_t paramCount = 0;
    uint8_t flags = 0;
    int i = 0;
    while (Cmd[i] != '\0') {
        if (Cmd[i] == '-') {
            switch (tolower(Cmd[i + 1])) {
                case 'h':
                    return usage_hf_felica_request_system_code();
                case 'i':
                    paramCount++;
                    custom_IDm = true;
                    if (!add_param(Cmd, paramCount, data, 2, 16)) {
                        return PM3_EINVARG;
                    }
                    paramCount++;
                    i += 16;
                    break;
                default:
                    return usage_hf_felica_request_system_code();
            }
        }
        i++;
    }
    data[0] = 0x0A; // Static length
    data[1] = 0x0C; // Command ID
    if (!custom_IDm && !check_last_idm(data, datalen)) {
        return PM3_EINVARG;
    }
    AddCrc(data, datalen);
    datalen += 2;
    flags |= FELICA_APPEND_CRC;
    flags |= FELICA_RAW;
    clear_and_send_command(flags, datalen, data, 0);
    PacketResponseNG resp;
    if (!waitCmdFelica(0, &resp, 1)) {
        PrintAndLogEx(ERR, "\nGot no response from card");
        return PM3_ERFTRANS;
    } else {
        felica_syscode_response_t rq_syscode_response;
        memcpy(&rq_syscode_response, (felica_syscode_response_t *)resp.data.asBytes, sizeof(felica_syscode_response_t));

        if (rq_syscode_response.frame_response.IDm[0] != 0) {
            PrintAndLogEx(SUCCESS, "\nGot Request Response:");
            PrintAndLogEx(SUCCESS, "IDm: %s", sprint_hex(rq_syscode_response.frame_response.IDm, sizeof(rq_syscode_response.frame_response.IDm)));
            PrintAndLogEx(SUCCESS, "  - Number of Systems: %s", sprint_hex(rq_syscode_response.number_of_systems, sizeof(rq_syscode_response.number_of_systems)));
            PrintAndLogEx(SUCCESS, "  - System Codes: enumerated in ascending order starting from System 0.");
            for (i = 0; i < rq_syscode_response.number_of_systems[0]; i++) {
                PrintAndLogEx(SUCCESS, "    - %s", sprint_hex(rq_syscode_response.system_code_list + i * 2, sizeof(uint8_t) * 2));
            }
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
            switch (tolower(Cmd[i + 1])) {
                case 'h':
                    return usage_hf_felica_request_service();
                case 'i':
                    paramCount++;
                    custom_IDm = true;
                    if (!add_param(Cmd, paramCount, data, 2, 16)) {
                        return PM3_EINVARG;
                    }
                    paramCount++;
                    i += 16;
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
            
            if (param_gethex(Cmd, paramCount++, data + 10, 2) == 1) {
                PrintAndLogEx(ERR, "Failed param key");
                return PM3_EINVARG;
            }
            
        } else {
            PrintAndLogEx(ERR, "Incorrect Node number length!");
            return PM3_EINVARG;
        }
    }

    if (param_getlength(Cmd, paramCount) == 4) {
        
        if (param_gethex(Cmd, paramCount++, data + 11, 4) == 1) {
            PrintAndLogEx(ERR, "Failed param key");
            return PM3_EINVARG;
        }
    } else {
        PrintAndLogEx(ERR, "Incorrect parameter length!");
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
    if (!custom_IDm && !check_last_idm(data, datalen)) {
        return PM3_EINVARG;
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
    PrintAndLogEx(INFO, "Feature not implemented yet.");
    PrintAndLogEx(INFO, "Feel free to contribute!");
    return PM3_SUCCESS;
}

static int CmdHFFelicaSniff(const char *Cmd) {
    uint8_t paramCount = 0;
    uint64_t samples2skip = 0;
    uint64_t triggers2skip = 0;
    strip_cmds(Cmd);
    int i = 0;
    while (Cmd[i] != '\0') {
        if (Cmd[i] == '-') {
            switch (tolower(Cmd[i + 1])) {
                case 'H':
                    return usage_hf_felica_sniff();
                case 's':
                    paramCount++;
                    if (param_getlength(Cmd, paramCount) < 5) {
                        samples2skip = param_get32ex(Cmd, paramCount++, 0, 10);
                    } else {
                        PrintAndLogEx(ERR, "Invalid samples number!");
                        return PM3_EINVARG;
                    }
                    break;
                case 't':
                    paramCount++;
                    if (param_getlength(Cmd, paramCount) < 5) {
                        triggers2skip = param_get32ex(Cmd, paramCount++, 0, 10);
                    } else {
                        PrintAndLogEx(ERR, "Invalid triggers number!");
                        return PM3_EINVARG;
                    }
                    break;
                default:
                    PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, paramCount));
                    return usage_hf_felica_sniff();
            }
            i += 2;
        }
        i++;
    }
    
    if (samples2skip == 0) {
        samples2skip = 10;
        PrintAndLogEx(INFO, "Set default samples2skip: %" PRIu64, samples2skip);
    }
    
    if (triggers2skip == 0) {
        triggers2skip = 5000;
        PrintAndLogEx(INFO, "Set default triggers2skip: %" PRIu64, triggers2skip);
    }

    PrintAndLogEx(INFO, "Start Sniffing now. You can stop sniffing with clicking the PM3 Button");
    PrintAndLogEx(INFO, "During sniffing, other pm3 commands may not response.");
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
    PrintAndLogEx(INFO, "------------------------------------------------------------------------------------");
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
            switch (tolower(Cmd[i + 1])) {
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
                if (++datalen >= (sizeof(data) - 2)) {
                    if (crc)
                        PrintAndLogEx(WARNING, "Buffer is full, we can't add CRC to your data");
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
    PrintAndLogEx(SUCCESS, "Data: %s", sprint_hex(data, datalen));
    SendCommandMIX(CMD_HF_FELICA_COMMAND, flags, (datalen & 0xFFFF) | (uint32_t)(numbits << 16), 0, data, datalen);

    if (reply) {
        if (active_select) {
            PrintAndLogEx(SUCCESS, "Active select wait for FeliCa.");
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

            PrintAndLogEx(SUCCESS, "IDm  %s", sprint_hex(card.IDm, sizeof(card.IDm)));
            PrintAndLogEx(SUCCESS, "  - CODE    %s", sprint_hex(card.code, sizeof(card.code)));
            PrintAndLogEx(SUCCESS, "  - NFCID2  %s", sprint_hex(card.uid, sizeof(card.uid)));

            PrintAndLogEx(SUCCESS, "Parameter (PAD) | %s", sprint_hex(card.PMm, sizeof(card.PMm)));
            PrintAndLogEx(SUCCESS, "  - IC CODE %s", sprint_hex(card.iccode, sizeof(card.iccode)));
            PrintAndLogEx(SUCCESS, "  - MRT     %s", sprint_hex(card.mrt, sizeof(card.mrt)));

            PrintAndLogEx(SUCCESS, "SERVICE CODE %s", sprint_hex(card.servicecode, sizeof(card.servicecode)));
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
    {"----------- FeliCa Standard (support in progress) -----------", CmdHelp,       IfPm3Iso14443a,  ""},
    //{"dump",              CmdHFFelicaDump,                        IfPm3Felica,     "Wait for and try dumping FeliCa"},
    {"rqservice",           CmdHFFelicaRequestService,              IfPm3Felica,     "verify the existence of Area and Service, and to acquire Key Version."},
    {"rqresponse",          CmdHFFelicaRequestResponse,             IfPm3Felica,     "verify the existence of a card and its Mode."},
    {"rdunencrypted",       CmdHFFelicaReadWithoutEncryption,       IfPm3Felica,     "read Block Data from authentication-not-required Service."},
    {"wrunencrypted",       CmdHFFelicaWriteWithoutEncryption,      IfPm3Felica,     "write Block Data to an authentication-not-required Service."},
    {"scsvcode",            CmdHFFelicaNotImplementedYet,           IfPm3Felica,     "acquire Area Code and Service Code."},
    {"rqsyscode",           CmdHFFelicaRequestSystemCode,           IfPm3Felica,     "acquire System Code registered to the card."},
    {"auth1",               CmdHFFelicaAuthentication1,             IfPm3Felica,     "authenticate a card. Start mutual authentication with Auth1"},
    {"auth2",               CmdHFFelicaAuthentication2,             IfPm3Felica,     "allow a card to authenticate a Reader/Writer. Complete mutual authentication"},
    {"read",                CmdHFFelicaNotImplementedYet,           IfPm3Felica,     "read Block Data from authentication-required Service."},
    //{"write",             CmdHFFelicaNotImplementedYet,           IfPm3Felica,     "write Block Data to an authentication-required Service."},
    //{"scsvcodev2",        CmdHFFelicaNotImplementedYet,           IfPm3Felica,     "verify the existence of Area or Service, and to acquire Key Version."},
    //{"getsysstatus",      CmdHFFelicaNotImplementedYet,           IfPm3Felica,     "acquire the setup information in System."},
    {"rqspecver",           CmdHFFelicaRequestSpecificationVersion, IfPm3Felica,     "acquire the version of card OS."},
    {"resetmode",           CmdHFFelicaResetMode,                   IfPm3Felica,     "reset Mode to Mode 0."},
    //{"auth1v2",           CmdHFFelicaNotImplementedYet,           IfPm3Felica,     "authenticate a card."},
    //{"auth2v2",           CmdHFFelicaNotImplementedYet,           IfPm3Felica,     "allow a card to authenticate a Reader/Writer."},
    //{"readv2",            CmdHFFelicaNotImplementedYet,           IfPm3Felica,     "read Block Data from authentication-required Service."},
    //{"writev2",           CmdHFFelicaNotImplementedYet,           IfPm3Felica,     "write Block Data to authentication-required Service."},
    //{"uprandomid",        CmdHFFelicaNotImplementedYet,           IfPm3Felica,     "update Random ID (IDr)."},
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
