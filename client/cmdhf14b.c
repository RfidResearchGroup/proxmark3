//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// Modified 2018 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443B commands
//-----------------------------------------------------------------------------

#include "cmdhf14b.h"

#define TIMEOUT 2000
static int CmdHelp(const char *Cmd);

int usage_hf_14b_info(void) {
    PrintAndLogEx(NORMAL, "Usage: hf 14b info [h] [s]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h    this help");
    PrintAndLogEx(NORMAL, "       s    silently");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       hf 14b info");
    return 0;
}
int usage_hf_14b_reader(void) {
    PrintAndLogEx(NORMAL, "Usage: hf 14b reader [h] [s]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h    this help");
    PrintAndLogEx(NORMAL, "       s    silently");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       hf 14b reader");
    return 0;
}
int usage_hf_14b_raw(void) {
    PrintAndLogEx(NORMAL, "Usage: hf 14b raw [-h] [-r] [-c] [-p] [-s / -ss] [-t] <0A 0B 0C ... hex>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       -h    this help");
    PrintAndLogEx(NORMAL, "       -r    do not read response");
    PrintAndLogEx(NORMAL, "       -c    calculate and append CRC");
    PrintAndLogEx(NORMAL, "       -p    leave the field on after receive");
    PrintAndLogEx(NORMAL, "       -s    active signal field ON with select");
    PrintAndLogEx(NORMAL, "       -ss   active signal field ON with select for SRx ST Microelectronics tags");
    PrintAndLogEx(NORMAL, "       -t    timeout in ms");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       hf 14b raw -s -c -p 0200a40400");
    return 0;
}
int usage_hf_14b_sniff(void) {
    PrintAndLogEx(NORMAL, "It get data from the field and saves it into command buffer.");
    PrintAndLogEx(NORMAL, "Buffer accessible from command 'hf list 14b'");
    PrintAndLogEx(NORMAL, "Usage: hf 14b sniff [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h    this help");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       hf 14b sniff");
    return 0;
}
int usage_hf_14b_sim(void) {
    PrintAndLogEx(NORMAL, "Emulating ISO/IEC 14443 type B tag with 4 UID / PUPI");
    PrintAndLogEx(NORMAL, "Usage: hf 14b sim [h] u <uid>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h    this help");
    PrintAndLogEx(NORMAL, "       u    4byte UID/PUPI");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       hf 14b sim");
    PrintAndLogEx(NORMAL, "       hf 14b sim u 11223344");
    return 0;
}
int usage_hf_14b_read_srx(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf 14b sriread [h] <1|2>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h        this help");
    PrintAndLogEx(NORMAL, "       <1|2>    1 = SRIX4K , 2 = SRI512");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       hf 14b sriread 1");
    PrintAndLogEx(NORMAL, "       hf 14b sriread 2");
    return 0;
}
int usage_hf_14b_write_srx(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf 14b [h] sriwrite <1|2> <BLOCK> <DATA>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h        this help");
    PrintAndLogEx(NORMAL, "       <1|2>    1 = SRIX4K , 2 = SRI512");
    PrintAndLogEx(NORMAL, "       <block>  BLOCK number depends on tag, special block == FF");
    PrintAndLogEx(NORMAL, "       <data>   hex bytes of data to be written");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       hf 14b sriwrite 1 7F 11223344");
    PrintAndLogEx(NORMAL, "       hf 14b sriwrite 1 FF 11223344");
    PrintAndLogEx(NORMAL, "       hf 14b sriwrite 2 15 11223344");
    PrintAndLogEx(NORMAL, "       hf 14b sriwrite 2 FF 11223344");
    return 0;
}
int usage_hf_14b_dump(void) {
    PrintAndLogEx(NORMAL, "This command dumps the contents of a ISO-14443-B tag and save it to file\n"
                  "\n"
                  "Usage: hf 14b dump [h] [card memory] <f filname> \n"
                  "Options:\n"
                  "\th             this help\n"
                  "\t[card memory] 1 = SRIX4K (default), 2 = SRI512"
                  "\tf <name>      filename,  if no <name> UID will be used as filename\n"
                  "\n"
                  "Example:\n"
                  "\thf 14b dump f\n"
                  "\thf 14b dump 2 f mydump");
    return 0;
}

/*
static void switch_on_field_14b(void) {
    UsbCommand c = {CMD_ISO_14443B_COMMAND, {ISO14B_CONNECT, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
}
*/

static int switch_off_field_14b(void) {
    UsbCommand c = {CMD_ISO_14443B_COMMAND, {ISO14B_DISCONNECT, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

int CmdHF14BList(const char *Cmd) {
    CmdTraceList("14b");
    return 0;
}

int CmdHF14BSim(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_14b_sim();

    uint32_t pupi = 0;
    if (cmdp == 'u') {
        pupi = param_get32ex(Cmd, 1, 0, 16);
    }

    UsbCommand c = {CMD_SIMULATE_TAG_ISO_14443B, {pupi, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

int CmdHF14BSniff(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_14b_sniff();

    UsbCommand c = {CMD_SNIFF_ISO_14443B, {0, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

int CmdHF14BCmdRaw(const char *Cmd) {
    bool reply = true, power = false, select = false, hasTimeout = false;
    char buf[5] = "";
    int i = 0;
    uint8_t data[USB_CMD_DATA_SIZE] = {0x00};
    uint16_t datalen = 0;
    uint32_t flags = ISO14B_CONNECT;
    uint32_t temp = 0, user_timeout = 0, time_wait = 0;

    if (strlen(Cmd) < 3) return usage_hf_14b_raw();

    // strip
    while (*Cmd == ' ' || *Cmd == '\t') ++Cmd;

    while (Cmd[i] != '\0') {
        if (Cmd[i] == ' ' || Cmd[i] == '\t') { ++i; continue; }
        if (Cmd[i] == '-') {
            switch (tolower(Cmd[i + 1])) {
                case 'h':
                    return usage_hf_14b_raw();
                case 'r':
                    reply = false;
                    break;
                case 'c':
                    flags |= ISO14B_APPEND_CRC;
                    break;
                case 'p':
                    power = true;
                    break;
                case 's':
                    select = true;
                    if (tolower(Cmd[i + 2]) == 's') {
                        flags |= ISO14B_SELECT_SR;
                        ++i;
                    } else {
                        flags |= ISO14B_SELECT_STD;
                    }
                    break;
                case 't':
                    hasTimeout = true;
                    sscanf(Cmd + i + 2, "%d", &user_timeout);
                    i += 3;
                    while (Cmd[i] != ' ' && Cmd[i] != '\0') { i++; }
                    i -= 2;
                    break;
                default:
                    return usage_hf_14b_raw();
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
                data[datalen++] = (uint8_t)(temp & 0xff);
                *buf = 0;
                memset(buf, 0x00, sizeof(buf));
            }
            continue;
        }
        PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, i));
        return 0;
    }

    if (hasTimeout) {
#define MAX_TIMEOUT 40542464 // = (2^32-1) * (8*16) / 13560000Hz * 1000ms/s
        flags |= ISO14B_SET_TIMEOUT;
        if (user_timeout > MAX_TIMEOUT) {
            user_timeout = MAX_TIMEOUT;
            PrintAndLogEx(NORMAL, "Set timeout to 40542 seconds (11.26 hours). The max we can wait for response");
        }
        time_wait = 13560000 / 1000 / (8 * 16) * user_timeout; // timeout in ETUs (time to transfer 1 bit, approx. 9.4 us)
    }

    if (power == 0)
        flags |= ISO14B_DISCONNECT;

    if (datalen > 0)
        flags |= ISO14B_RAW;

    // Max buffer is USB_CMD_DATA_SIZE
    datalen = (datalen > USB_CMD_DATA_SIZE) ? USB_CMD_DATA_SIZE : datalen;

    UsbCommand c = {CMD_ISO_14443B_COMMAND, {flags, datalen, time_wait}};
    memcpy(c.d.asBytes, data, datalen);
    clearCommandBuffer();
    SendCommand(&c);

    if (!reply) return 1;

    bool success = true;
    // get back iso14b_card_select_t, don't print it.
    if (select)
        success = waitCmd14b(false);

    // get back response from the raw bytes you sent.
    if (success && datalen > 0) waitCmd14b(true);

    return 1;
}

static bool get_14b_UID(iso14b_card_select_t *card) {

    if (!card)
        return false;

    int8_t retry = 3;
    UsbCommand resp;
    UsbCommand c = {CMD_ISO_14443B_COMMAND, {ISO14B_CONNECT | ISO14B_SELECT_SR | ISO14B_DISCONNECT, 0, 0}};

    // test for 14b SR
    while (retry--) {

        clearCommandBuffer();
        SendCommand(&c);
        if (WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {

            uint8_t status = resp.arg[0];
            if (status == 0) {
                memcpy(card, (iso14b_card_select_t *)resp.d.asBytes, sizeof(iso14b_card_select_t));
                return true;
            }
        }
    } // retry

    // test 14b standard
    c.arg[0] = ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT;
    retry = 3;
    while (retry--) {


        clearCommandBuffer();
        SendCommand(&c);
        if (WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {

            uint8_t status = resp.arg[0];
            if (status == 0) {
                memcpy(card, (iso14b_card_select_t *)resp.d.asBytes, sizeof(iso14b_card_select_t));
                return true;
            }
        }
    } // retry

    if (retry <= 0)
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");

    return false;
}

// print full atqb info
// bytes
// 0,1,2,3 = application data
// 4       = bit rate capacity
// 5       = max frame size / -4 info
// 6       = FWI / Coding options
static void print_atqb_resp(uint8_t *data, uint8_t cid) {
    //PrintAndLogEx(NORMAL, "           UID: %s", sprint_hex(data+1,4));
    PrintAndLogEx(NORMAL, "      App Data: %s", sprint_hex(data, 4));
    PrintAndLogEx(NORMAL, "      Protocol: %s", sprint_hex(data + 4, 3));
    uint8_t BitRate = data[4];
    if (!BitRate) PrintAndLogEx(NORMAL, "      Bit Rate: 106 kbit/s only PICC <-> PCD");
    if (BitRate & 0x10) PrintAndLogEx(NORMAL, "      Bit Rate: 212 kbit/s PICC -> PCD supported");
    if (BitRate & 0x20) PrintAndLogEx(NORMAL, "      Bit Rate: 424 kbit/s PICC -> PCD supported");
    if (BitRate & 0x40) PrintAndLogEx(NORMAL, "      Bit Rate: 847 kbit/s PICC -> PCD supported");
    if (BitRate & 0x01) PrintAndLogEx(NORMAL, "      Bit Rate: 212 kbit/s PICC <- PCD supported");
    if (BitRate & 0x02) PrintAndLogEx(NORMAL, "      Bit Rate: 424 kbit/s PICC <- PCD supported");
    if (BitRate & 0x04) PrintAndLogEx(NORMAL, "      Bit Rate: 847 kbit/s PICC <- PCD supported");
    if (BitRate & 0x80) PrintAndLogEx(NORMAL, "                Same bit rate <-> required");

    uint16_t maxFrame = data[5] >> 4;
    if (maxFrame < 5)       maxFrame = 8 * maxFrame + 16;
    else if (maxFrame == 5) maxFrame = 64;
    else if (maxFrame == 6) maxFrame = 96;
    else if (maxFrame == 7) maxFrame = 128;
    else if (maxFrame == 8) maxFrame = 256;
    else maxFrame = 257;

    PrintAndLogEx(NORMAL, "Max Frame Size: %u%s bytes", maxFrame, (maxFrame == 257) ? "+ RFU" : "");

    uint8_t protocolT = data[5] & 0xF;
    PrintAndLogEx(NORMAL, " Protocol Type: Protocol is %scompliant with ISO/IEC 14443-4", (protocolT) ? "" : "not ");

    uint8_t fwt = data[6] >> 4;
    if (fwt < 16) {
        uint32_t etus = (32 << fwt);
        uint32_t fwt_time = (302 << fwt);
        PrintAndLogEx(NORMAL, "Frame Wait Integer: %u - %u ETUs | %u us", fwt, etus, fwt_time);
    } else {
        PrintAndLogEx(NORMAL, "Frame Wait Integer: %u - RFU", fwt);
    }

    PrintAndLogEx(NORMAL, " App Data Code: Application is %s", (data[6] & 4) ? "Standard" : "Proprietary");
    PrintAndLogEx(NORMAL, " Frame Options: NAD is %ssupported", (data[6] & 2) ? "" : "not ");
    PrintAndLogEx(NORMAL, " Frame Options: CID is %ssupported", (data[6] & 1) ? "" : "not ");
    PrintAndLogEx(NORMAL, "Tag :");
    PrintAndLogEx(NORMAL, "  Max Buf Length: %u (MBLI) %s", cid >> 4, (cid & 0xF0) ? "" : "chained frames not supported");
    PrintAndLogEx(NORMAL, "  CID : %u", cid & 0x0f);
    return;
}

// get SRx chip model (from UID) // from ST Microelectronics
char *get_ST_Chip_Model(uint8_t data) {
    static char model[20];
    char *retStr = model;
    memset(model, 0, sizeof(model));

    switch (data) {
        case 0x0:
            sprintf(retStr, "SRIX4K (Special)");
            break;
        case 0x2:
            sprintf(retStr, "SR176");
            break;
        case 0x3:
            sprintf(retStr, "SRIX4K");
            break;
        case 0x4:
            sprintf(retStr, "SRIX512");
            break;
        case 0x6:
            sprintf(retStr, "SRI512");
            break;
        case 0x7:
            sprintf(retStr, "SRI4K");
            break;
        case 0xC:
            sprintf(retStr, "SRT512");
            break;
        default :
            sprintf(retStr, "Unknown");
            break;
    }
    return retStr;
}

// REMAKE:
int print_ST_Lock_info(uint8_t model) {

    // PrintAndLogEx(NORMAL, "Chip Write Protection Bits:");
    // // now interpret the data
    // switch (model){
    // case 0x0: //fall through (SRIX4K special)
    // case 0x3: //fall through (SRIx4K)
    // case 0x7: //             (SRI4K)
    // //only need data[3]
    // blk1 = 9;
    // PrintAndLogEx(NORMAL, "   raw: %s", sprint_bin(data+3, 1));
    // PrintAndLogEx(NORMAL, " 07/08:%slocked", (data[3] & 1) ? " not " : " " );
    // for (uint8_t i = 1; i<8; i++){
    // PrintAndLogEx(NORMAL, "    %02u:%slocked", blk1, (data[3] & (1 << i)) ? " not " : " " );
    // blk1++;
    // }
    // break;
    // case 0x4: //fall through (SRIX512)
    // case 0x6: //fall through (SRI512)
    // case 0xC: //             (SRT512)
    // //need data[2] and data[3]
    // blk1 = 0;
    // PrintAndLogEx(NORMAL, "   raw: %s", sprint_bin(data+2, 2));
    // for (uint8_t b=2; b<4; b++){
    // for (uint8_t i=0; i<8; i++){
    // PrintAndLogEx(NORMAL, "    %02u:%slocked", blk1, (data[b] & (1 << i)) ? " not " : " " );
    // blk1++;
    // }
    // }
    // break;
    // case 0x2: //             (SR176)
    // //need data[2]
    // blk1 = 0;
    // PrintAndLogEx(NORMAL, "   raw: %s", sprint_bin(data+2, 1));
    // for (uint8_t i = 0; i<8; i++){
    // PrintAndLogEx(NORMAL, " %02u/%02u:%slocked", blk1, blk1+1, (data[2] & (1 << i)) ? " " : " not " );
    // blk1+=2;
    // }
    // break;
    // default:
    // return rawClose();
    // }
    return 1;
}

// print UID info from SRx chips (ST Microelectronics)
static void print_st_general_info(uint8_t *data, uint8_t len) {
    //uid = first 8 bytes in data
    PrintAndLogEx(NORMAL, " UID: %s", sprint_hex(SwapEndian64(data, 8, 8), len));
    PrintAndLogEx(NORMAL, " MFG: %02X, %s", data[6], getTagInfo(data[6]));
    PrintAndLogEx(NORMAL, "Chip: %02X, %s", data[5] >> 2, get_ST_Chip_Model(data[5] >> 2));
    return;
}

//05 00 00 = find one tag in field
//1d xx xx xx xx 00 08 01 00 = attrib xx=UID (resp 10 [f9 e0])
//a3 = ?  (resp 03 [e2 c2])
//02 = ?  (resp 02 [6a d3])
// 022b (resp 02 67 00 [29  5b])
// 0200a40400 (resp 02 67 00 [29 5b])
// 0200a4040c07a0000002480300 (resp 02 67 00 [29 5b])
// 0200a4040c07a0000002480200 (resp 02 67 00 [29 5b])
// 0200a4040006a0000000010100 (resp 02 6a 82 [4b 4c])
// 0200a4040c09d27600002545500200 (resp 02 67 00 [29 5b])
// 0200a404000cd2760001354b414e4d30310000 (resp 02 6a 82 [4b 4c])
// 0200a404000ca000000063504b43532d313500 (resp 02 6a 82 [4b 4c])
// 0200a4040010a000000018300301000000000000000000 (resp 02 6a 82 [4b 4c])
//03 = ?  (resp 03 [e3 c2])
//c2 = ?  (resp c2 [66 15])
//b2 = ?  (resp a3 [e9 67])
//a2 = ?  (resp 02 [6a d3])

// 14b get and print Full Info (as much as we know)
bool HF14B_Std_Info(bool verbose) {

    bool isSuccess = false;

    // 14b get and print UID only (general info)
    UsbCommand c = {CMD_ISO_14443B_COMMAND, {ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;

    if (!WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {
        if (verbose) PrintAndLogEx(WARNING, "command execution timeout");
        switch_off_field_14b();
        return false;
    }

    iso14b_card_select_t card;
    memcpy(&card, (iso14b_card_select_t *)resp.d.asBytes, sizeof(iso14b_card_select_t));

    uint64_t status = resp.arg[0];

    switch (status) {
        case 0:
            PrintAndLogEx(NORMAL, " UID    : %s", sprint_hex(card.uid, card.uidlen));
            PrintAndLogEx(NORMAL, " ATQB   : %s", sprint_hex(card.atqb, sizeof(card.atqb)));
            PrintAndLogEx(NORMAL, " CHIPID : %02X", card.chipid);
            print_atqb_resp(card.atqb, card.cid);
            isSuccess = true;
            break;
        case 2:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 ATTRIB fail");
            break;
        case 3:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 CRC fail");
            break;
        default:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-b card select failed");
            break;
    }

    return isSuccess;
}

// SRx get and print full info (needs more info...)
bool HF14B_ST_Info(bool verbose) {

    UsbCommand c = {CMD_ISO_14443B_COMMAND, {ISO14B_CONNECT | ISO14B_SELECT_SR | ISO14B_DISCONNECT, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;

    if (!WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {
        if (verbose) PrintAndLogEx(WARNING, "command execution timeout");
        return false;
    }

    iso14b_card_select_t card;
    memcpy(&card, (iso14b_card_select_t *)resp.d.asBytes, sizeof(iso14b_card_select_t));

    uint64_t status = resp.arg[0];
    if (status > 0)
        return false;

    print_st_general_info(card.uid, card.uidlen);

    //add locking bit information here. uint8_t data[16] = {0x00};
    // uint8_t datalen = 2;
    // uint8_t resplen;
    // uint8_t blk1;
    // data[0] = 0x08;

    //
    // if (model == 0x2) { //SR176 has special command:
    // data[1] = 0xf;
    // resplen = 4;
    // } else {
    // data[1] = 0xff;
    // resplen = 6;
    // }

    // //std read cmd
    // if (HF14BCmdRaw(true, true, data, &datalen, false)==0)
    // return rawClose();

    // if (datalen != resplen || !crc) return rawClose();
    //print_ST_Lock_info(data[5]>>2);
    return true;
}

// get and print all info known about any known 14b tag
bool HF14BInfo(bool verbose) {

    // try std 14b (atqb)
    if (HF14B_Std_Info(verbose)) return true;

    // try ST 14b
    if (HF14B_ST_Info(verbose)) return true;

    // try unknown 14b read commands (to be identified later)
    //   could be read of calypso, CEPAS, moneo, or pico pass.
    if (verbose) PrintAndLogEx(FAILED, "no 14443-B tag found");
    return false;
}

// menu command to get and print all info known about any known 14b tag
int CmdHF14Binfo(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_14b_info();

    bool verbose = !(cmdp == 's');
    return HF14BInfo(verbose);
}

bool HF14B_ST_Reader(bool verbose) {

    bool isSuccess = false;

    // SRx get and print general info about SRx chip from UID
    UsbCommand c = {CMD_ISO_14443B_COMMAND, {ISO14B_CONNECT | ISO14B_SELECT_SR | ISO14B_DISCONNECT, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {
        if (verbose) PrintAndLogEx(WARNING, "command execution timeout");
        return false;
    }

    iso14b_card_select_t card;
    memcpy(&card, (iso14b_card_select_t *)resp.d.asBytes, sizeof(iso14b_card_select_t));

    uint64_t status = resp.arg[0];

    switch (status) {
        case 0:
            print_st_general_info(card.uid, card.uidlen);
            isSuccess = true;
            break;
        case 1:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 random chip id fail");
            break;
        case 2:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 ATTRIB fail");
            break;
        case 3:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 CRC fail");
            break;
        default:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-b card select SRx failed");
            break;
    }
    return isSuccess;
}

bool HF14B_Std_Reader(bool verbose) {

    bool isSuccess = false;

    // 14b get and print UID only (general info)
    UsbCommand c = {CMD_ISO_14443B_COMMAND, {ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;

    if (!WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {
        if (verbose) PrintAndLogEx(WARNING, "command execution timeout");
        return false;
    }

    iso14b_card_select_t card;
    memcpy(&card, (iso14b_card_select_t *)resp.d.asBytes, sizeof(iso14b_card_select_t));

    uint64_t status = resp.arg[0];

    switch (status) {
        case 0:
            PrintAndLogEx(NORMAL, " UID    : %s", sprint_hex(card.uid, card.uidlen));
            PrintAndLogEx(NORMAL, " ATQB   : %s", sprint_hex(card.atqb, sizeof(card.atqb)));
            PrintAndLogEx(NORMAL, " CHIPID : %02X", card.chipid);
            print_atqb_resp(card.atqb, card.cid);
            isSuccess = true;
            break;
        case 2:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 ATTRIB fail");
            break;
        case 3:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 CRC fail");
            break;
        default:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-b card select failed");
            break;
    }
    return isSuccess;
}

// test for other 14b type tags (mimic another reader - don't have tags to identify)
bool HF14B_Other_Reader() {

    // uint8_t data[] = {0x00, 0x0b, 0x3f, 0x80};
    // uint8_t datalen = 4;

    // // 14b get and print UID only (general info)
    // uint32_t flags = ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_RAW | ISO14B_APPEND_CRC;

    // UsbCommand c = {CMD_ISO_14443B_COMMAND, {flags, datalen, 0}};
    // memcpy(c.d.asBytes, data, datalen);

    // clearCommandBuffer();
    // SendCommand(&c);
    // UsbCommand resp;
    // WaitForResponse(CMD_ACK,&resp);

    // if (datalen > 2 ) {
    // PrintAndLogEx(NORMAL, "\n14443-3b tag found:");
    // PrintAndLogEx(NORMAL, "unknown tag type answered to a 0x000b3f80 command ans:");
    // //PrintAndLogEx(NORMAL, "%s", sprint_hex(data, datalen));
    // rawclose();
    // return true;
    // }

    // c.arg1 = 1;
    // c.d.asBytes[0] = ISO14443B_AUTHENTICATE;
    // clearCommandBuffer();
    // SendCommand(&c);
    // UsbCommand resp;
    // WaitForResponse(CMD_ACK, &resp);

    // if (datalen > 0) {
    // PrintAndLogEx(NORMAL, "\n14443-3b tag found:");
    // PrintAndLogEx(NORMAL, "Unknown tag type answered to a 0x0A command ans:");
    // // PrintAndLogEx(NORMAL, "%s", sprint_hex(data, datalen));
    // rawClose();
    // return true;
    // }

    // c.arg1 = 1;
    // c.d.asBytes[0] = ISO14443B_RESET;
    // clearCommandBuffer();
    // SendCommand(&c);
    // UsbCommand resp;
    // WaitForResponse(CMD_ACK, &resp);

    // if (datalen > 0) {
    // PrintAndLogEx(NORMAL, "\n14443-3b tag found:");
    // PrintAndLogEx(NORMAL, "Unknown tag type answered to a 0x0C command ans:");
    // PrintAndLogEx(NORMAL, "%s", sprint_hex(data, datalen));
    // rawClose();
    // return true;
    // }

    // rawClose();
    return false;
}

// get and print general info about all known 14b chips
bool HF14BReader(bool verbose) {

    // try std 14b (atqb)
    if (HF14B_Std_Reader(verbose)) return true;

    // try ST Microelectronics 14b
    if (HF14B_ST_Reader(verbose)) return true;

    // try unknown 14b read commands (to be identified later)
    // could be read of calypso, CEPAS, moneo, or pico pass.
    if (HF14B_Other_Reader()) return true;

    if (verbose) PrintAndLogEx(FAILED, "no 14443-B tag found");
    return false;
}

// menu command to get and print general info about all known 14b chips
int CmdHF14BReader(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_14b_reader();

    bool verbose = !(cmdp == 's');
    return HF14BReader(verbose);
}

/* New command to read the contents of a SRI512|SRIX4K tag
 * SRI* tags are ISO14443-B modulated memory tags,
 * this command just dumps the contents of the memory/
 */
int CmdHF14BReadSri(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || cmdp == 'h') return usage_hf_14b_read_srx();

    uint8_t tagtype = param_get8(Cmd, 0);
    uint8_t blocks = (tagtype == 1) ? 0x7F : 0x0F;

    UsbCommand c = {CMD_READ_SRI_TAG, {blocks, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}
// New command to write a SRI512/SRIX4K tag.
int CmdHF14BWriteSri(const char *Cmd) {
    /*
     * For SRIX4K  blocks 00 - 7F
     * hf 14b raw -c -p 09 $srix4kwblock $srix4kwdata
     *
     * For SR512  blocks 00 - 0F
     * hf 14b raw -c -p 09 $sr512wblock $sr512wdata
     *
     * Special block FF =  otp_lock_reg block.
     * Data len 4 bytes-
     */
    char cmdp = tolower(param_getchar(Cmd, 0));
    uint8_t blockno = -1;
    uint8_t data[4] = {0x00};
    bool isSrix4k = true;
    char str[30];
    memset(str, 0x00, sizeof(str));

    if (strlen(Cmd) < 1 || cmdp == 'h') return usage_hf_14b_write_srx();

    if (cmdp == '2')
        isSrix4k = false;

    //blockno = param_get8(Cmd, 1);

    if (param_gethex(Cmd, 1, &blockno, 2)) {
        PrintAndLogEx(WARNING, "block number must include 2 HEX symbols");
        return 0;
    }

    if (isSrix4k) {
        if (blockno > 0x7f && blockno != 0xff) {
            PrintAndLogEx(FAILED, "block number out of range");
            return 0;
        }
    } else {
        if (blockno > 0x0f && blockno != 0xff) {
            PrintAndLogEx(FAILED, "block number out of range");
            return 0;
        }
    }

    if (param_gethex(Cmd, 2, data, 8)) {
        PrintAndLogEx(WARNING, "data must include 8 HEX symbols");
        return 0;
    }

    if (blockno == 0xff) {
        PrintAndLogEx(SUCCESS, "[%s] Write special block %02X [ %s ]",
                      (isSrix4k) ? "SRIX4K" : "SRI512",
                      blockno,
                      sprint_hex(data, 4)
                     );
    } else {
        PrintAndLogEx(SUCCESS, "[%s] Write block %02X [ %s ]",
                      (isSrix4k) ? "SRIX4K" : "SRI512",
                      blockno,
                      sprint_hex(data, 4)
                     );
    }

    sprintf(str, "-ss -c %02x %02x %02x %02x %02x %02x", ISO14443B_WRITE_BLK, blockno, data[0], data[1], data[2], data[3]);
    CmdHF14BCmdRaw(str);
    return 0;
}

// need to write to file
int CmdHF14BDump(const char *Cmd) {

    uint8_t fileNameLen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    char *fptr = filename;
    bool errors = false;
    uint8_t cmdp = 0, cardtype = 1;
    uint16_t cardsize = 0;
    uint8_t blocks = 0;
    iso14b_card_select_t card;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_14b_dump();
            case 'f':
                fileNameLen = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                cmdp += 2;
                break;
            default:
                if (cmdp == 0) {
                    cardtype = param_get8ex(Cmd, cmdp, 1, 10);
                    cmdp++;
                } else {
                    PrintAndLogEx(WARNING, "Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                    errors = true;
                    break;
                }
        }
    }

    //Validations
    if (errors) return usage_hf_14b_dump();

    switch (cardtype) {
        case 2:
            cardsize = (512 / 8) + 4;
            blocks = 0x0F;
            break;
        case 1:
        default:
            cardsize = (4096 / 8) + 4;
            blocks = 0x7F;
            break;
    }

    if (!get_14b_UID(&card)) {
        PrintAndLogEx(WARNING, "No tag found.");
        return 1;
    }

    if (fileNameLen < 1) {
        PrintAndLogEx(INFO, "Using UID as filename");
        fptr += sprintf(fptr, "hf-14b-");
        FillFileNameByUID(fptr, card.uid, "-dump", card.uidlen);
    }

    // detect blocksize from card :)
    PrintAndLogEx(NORMAL, "Reading memory from tag UID %s", sprint_hex(card.uid, card.uidlen));

    uint8_t data[cardsize];
    memset(data, 0, sizeof(data));

    int blocknum = 0;
    uint8_t *recv = NULL;

    UsbCommand resp;
    UsbCommand c = {CMD_ISO_14443B_COMMAND, { ISO14B_CONNECT | ISO14B_SELECT_SR, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);

    //select
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        if (resp.arg[0]) {
            PrintAndLogEx(INFO, "failed to select %d | %d", resp.arg[0], resp.arg[1]);
            goto out;
        }
    }

    c.arg[0] = ISO14B_APPEND_CRC | ISO14B_RAW;
    c.arg[1] = 2;

    uint8_t *req = c.d.asBytes;
    req[0] = ISO14443B_READ_BLK;

    for (int retry = 0; retry < 5; retry++) {

        req[1] = blocknum;

        clearCommandBuffer();
        SendCommand(&c);

        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {

            uint8_t status = resp.arg[0] & 0xFF;
            if (status > 0) {
                continue;
            }

            uint16_t len = (resp.arg[1] & 0xFFFF);
            recv = resp.d.asBytes;

            if (!check_crc(CRC_14443_B, recv, len)) {
                PrintAndLogEx(FAILED, "crc fail, retrying one more time");
                continue;
            }

            memcpy(data + (blocknum * 4), resp.d.asBytes, 4);

            if (blocknum == 0xFF) {
                //last read.
                break;
            }


            retry = 0;
            blocknum++;
            if (blocknum > blocks) {
                // read config block
                blocknum = 0xFF;
            }

            printf(".");
            fflush(stdout);
        }
    }

    if (blocknum != 0xFF) {
        PrintAndLogEx(NORMAL, "\n Dump failed");
        goto out;
    }

    PrintAndLogEx(NORMAL, "\n");
    PrintAndLogEx(NORMAL, "block#   | data         | ascii");
    PrintAndLogEx(NORMAL, "---------+--------------+----------");

    for (int i = 0; i <= blocks; i++) {
        PrintAndLogEx(NORMAL,
                      "%3d/0x%02X | %s | %s",
                      i,
                      i,
                      sprint_hex(data + (i * 4), 4),
                      sprint_ascii(data + (i * 4), 4)
                     );
    }

    PrintAndLogEx(NORMAL, "\n");


    size_t datalen = (blocks + 1) * 4;
    saveFileEML(filename, "eml", data, datalen, 4);
    saveFile(filename, "bin", data, datalen);
out:
    return switch_off_field_14b();
}

uint32_t srix4kEncode(uint32_t value) {
    /*
    // vv = value
    // pp = position
    //                vv vv vv pp
    4 bytes         : 00 1A 20 01
    */
    // only the lower crumbs.
    uint8_t block = (value & 0xFF);
    uint8_t i = 0;
    uint8_t valuebytes[] = {0, 0, 0};

    num_to_bytes(value, 3, valuebytes);

    // Scrambled part
    // Crumb swapping of value.
    uint8_t temp[] = {0, 0};
    temp[0] = (CRUMB(value, 22) << 4 | CRUMB(value, 14) << 2 | CRUMB(value, 6)) << 4;
    temp[0] |= CRUMB(value, 20) << 4 | CRUMB(value, 12) << 2 | CRUMB(value, 4);
    temp[1] = (CRUMB(value, 18) << 4 | CRUMB(value, 10) << 2 | CRUMB(value, 2)) << 4;
    temp[1] |= CRUMB(value, 16) << 4 | CRUMB(value, 8) << 2 | CRUMB(value, 0);

    // chksum part
    uint32_t chksum = 0xFF - block;

    // chksum is reduced by each nibbles of value.
    for (i = 0; i < 3; ++i) {
        chksum -= NIBBLE_HIGH(valuebytes[i]);
        chksum -= NIBBLE_LOW(valuebytes[i]);
    }

    // base4 conversion and left shift twice
    i = 3;
    uint8_t base4[] = {0, 0, 0, 0};
    while (chksum != 0) {
        base4[i--] = (chksum % 4 << 2);
        chksum /= 4;
    }

    // merge scambled and chksum parts
    uint32_t encvalue =
        (NIBBLE_LOW(base4[0]) << 28) |
        (NIBBLE_HIGH(temp[0])  << 24) |

        (NIBBLE_LOW(base4[1]) << 20) |
        (NIBBLE_LOW(temp[0])  << 16) |

        (NIBBLE_LOW(base4[2]) << 12) |
        (NIBBLE_HIGH(temp[1])  << 8) |

        (NIBBLE_LOW(base4[3]) << 4) |
        NIBBLE_LOW(temp[1]);

    PrintAndLogEx(NORMAL, "ICE encoded | %08X -> %08X", value, encvalue);
    return encvalue;
}
uint32_t srix4kDecode(uint32_t value) {
    switch (value) {
        case 0xC04F42C5:
            return 0x003139;
        case 0xC1484807:
            return 0x002943;
        case 0xC0C60848:
            return 0x001A20;
    }
    return 0;
}
uint32_t srix4kDecodeCounter(uint32_t num) {
    uint32_t value = ~num;
    ++value;
    return value;
}

uint32_t srix4kGetMagicbytes(uint64_t uid, uint32_t block6, uint32_t block18, uint32_t block19) {
#define MASK 0xFFFFFFFF;
    uint32_t uid32 = uid & MASK;
    uint32_t counter = srix4kDecodeCounter(block6);
    uint32_t decodedBlock18 = srix4kDecode(block18);
    uint32_t decodedBlock19 = srix4kDecode(block19);
    uint32_t doubleBlock = (decodedBlock18 << 16 | decodedBlock19) + 1;

    uint32_t result = (uid32 * doubleBlock * counter) & MASK;
    PrintAndLogEx(SUCCESS, "Magic bytes | %08X", result);
    return result;
}
int srix4kValid(const char *Cmd) {

    uint64_t uid = 0xD00202501A4532F9;
    uint32_t block6 = 0xFFFFFFFF;
    uint32_t block18 = 0xC04F42C5;
    uint32_t block19 = 0xC1484807;
    uint32_t block21 = 0xD1BCABA4;

    uint32_t test_b18 = 0x00313918;
    uint32_t test_b18_enc = srix4kEncode(test_b18);
    //uint32_t test_b18_dec = srix4kDecode(test_b18_enc);
    PrintAndLogEx(SUCCESS, "ENCODE & CHECKSUM |  %08X -> %08X (%s)", test_b18, test_b18_enc, "");

    uint32_t magic = srix4kGetMagicbytes(uid, block6, block18, block19);
    PrintAndLogEx(SUCCESS, "BLOCK 21 |  %08X -> %08X (no XOR)", block21, magic ^ block21);
    return 0;
}

bool waitCmd14b(bool verbose) {

    bool crc = false;
    uint8_t data[USB_CMD_DATA_SIZE] = {0x00};
    uint8_t status = 0;
    uint16_t len = 0;
    UsbCommand resp;

    if (WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {

        status = (resp.arg[0] & 0xFF);
        if (status > 0) return false;

        len = (resp.arg[1] & 0xFFFF);

        memcpy(data, resp.d.asBytes, len);

        if (verbose) {
            if (len >= 3) {
                crc = check_crc(CRC_14443_B, data, len);

                PrintAndLogEx(NORMAL, "[LEN %u] %s[%02X %02X] %s",
                              len,
                              sprint_hex(data, len - 2),
                              data[len - 2],
                              data[len - 1],
                              (crc) ? "OK" : "FAIL"
                             );
            } else {
                PrintAndLogEx(NORMAL, "[LEN %u] %s", len, sprint_hex(data, len));
            }
        }
        return true;
    } else {
        PrintAndLogEx(WARNING, "command execution timeout");
        return false;
    }
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,        1, "This help"},
    {"dump",        CmdHF14BDump,   0, "Read all memory pages of an ISO14443-B tag, save to file"},
    {"info",        CmdHF14Binfo,   0, "Tag information"},
    {"list",        CmdHF14BList,   0, "[Deprecated] List ISO 14443B history"},
    {"raw",         CmdHF14BCmdRaw, 0, "Send raw hex data to tag"},
    {"reader",      CmdHF14BReader, 0, "Act as a 14443B reader to identify a tag"},
    {"sim",         CmdHF14BSim,    0, "Fake ISO 14443B tag"},
    {"sniff",       CmdHF14BSniff,  0, "Eavesdrop ISO 14443B"},
    {"sriread",     CmdHF14BReadSri,  0, "Read contents of a SRI512 | SRIX4K tag"},
    {"sriwrite",    CmdHF14BWriteSri, 0, "Write data to a SRI512 | SRIX4K tag"},
    //{"valid",     srix4kValid,    1, "srix4k checksum test"},
    {NULL, NULL, 0, NULL}
};

int CmdHF14B(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
