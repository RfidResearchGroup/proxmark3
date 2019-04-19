//-----------------------------------------------------------------------------
// Copyright (C) Merlok - 2017
// iceman 2018
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Command: hf mf list. It shows data from arm buffer.
//-----------------------------------------------------------------------------

#include "cmdhflist.h"

enum MifareAuthSeq {
    masNone,
    masNt,
    masNrAr,
    masAt,
    masAuthComplete,
    masFirstData,
    masData,
    masError,
};
static enum MifareAuthSeq MifareAuthState;
static TAuthData AuthData;

void ClearAuthData() {
    AuthData.uid = 0;
    AuthData.nt = 0;
    AuthData.first_auth = true;
    AuthData.ks2 = 0;
    AuthData.ks3 = 0;
}

/**
 * @brief iso14443A_CRC_check Checks CRC in command or response
 * @param isResponse
 * @param data
 * @param len
 * @return  0 : CRC-command, CRC not ok
 *          1 : CRC-command, CRC ok
 *          2 : Not crc-command
 */

uint8_t iso14443A_CRC_check(bool isResponse, uint8_t *d, uint8_t n) {
    if (n < 3) return 2;
    if (isResponse && (n < 6)) return 2;
    if (n > 2 && d[1] == 0x50 &&
            d[0] >= ISO14443A_CMD_ANTICOLL_OR_SELECT &&
            d[0] <= ISO14443A_CMD_ANTICOLL_OR_SELECT_3)
        return 2;
    return check_crc(CRC_14443_A, d, n);
}

uint8_t mifare_CRC_check(bool isResponse, uint8_t *data, uint8_t len) {
    switch (MifareAuthState) {
        case masNone:
        case masError:
            return iso14443A_CRC_check(isResponse, data, len);
        case masNt:
        case masNrAr:
        case masAt:
        case masAuthComplete:
        case masFirstData:
        case masData:
            break;
    }
    return 2;
}

/**
 * @brief iso14443B_CRC_check Checks CRC
 * @param data
 * @param len
 * @return  0 : CRC-command, CRC not ok
 *          1 : CRC-command, CRC ok
 *          2 : Not crc-command
 */
uint8_t iso14443B_CRC_check(uint8_t *d, uint8_t n) {
    return check_crc(CRC_14443_B, d, n);
}

uint8_t iso15693_CRC_check(uint8_t *d, uint8_t n) {
    return check_crc(CRC_15693, d, n);
}

/**
 * @brief iclass_CRC_Ok Checks CRC in command or response
 * @param isResponse
 * @param data
 * @param len
 * @return  0 : CRC-command, CRC not ok
 *          1 : CRC-command, CRC ok
 *          2 : Not crc-command
 */
uint8_t iclass_CRC_check(bool isResponse, uint8_t *d, uint8_t n) {
    //CRC commands (and responses) are all at least 4 bytes
    if (n < 4) return 2;

    //Commands to tag
    //Don't include the command byte
    if (!isResponse) {
        /**
          These commands should have CRC. Total length leftmost
          4 READ
          4 READ4
          12 UPDATE - unsecured, ends with CRC16
          14 UPDATE - secured, ends with signature instead
          4 PAGESEL
          **/
        //Covers three of them
        if (n == 4 || n == 12) {
            return check_crc(CRC_ICLASS, d + 1, n - 1);
        }
        return 2;
    }
    /**
    These tag responses should have CRC. Total length leftmost

    10  READ      data[8] crc[2]
    34  READ4     data[32]crc[2]
    10  UPDATE    data[8] crc[2]
    10 SELECT     csn[8] crc[2]
    10  IDENTIFY  asnb[8] crc[2]
    10  PAGESEL   block1[8] crc[2]
    10  DETECT    csn[8] crc[2]

    These should not

    4  CHECK      chip_response[4]
    8  READCHECK  data[8]
    1  ACTALL     sof[1]
    1  ACT        sof[1]

    In conclusion, without looking at the command; any response
    of length 10 or 34 should have CRC
      **/
    if (n != 10 && n != 34) return true;

    return check_crc(CRC_ICLASS, d, n);
}

int applyIso14443a(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize) {
    switch (cmd[0]) {
        case ISO14443A_CMD_WUPA:
            snprintf(exp, size, "WUPA");
            break;
        case ISO14443A_CMD_ANTICOLL_OR_SELECT: {
            // 93 20 = Anticollision (usage: 9320 - answer: 4bytes UID+1byte UID-bytes-xor)
            // 93 50 = Bit oriented anti-collision (usage: 9350+ up to 5bytes, 9350 answer - up to 5bytes UID+BCC)
            // 93 70 = Select (usage: 9370+5bytes 9370 answer - answer: 1byte SAK)
            if (cmd[1] == 0x70)
                snprintf(exp, size, "SELECT_UID");
            else if (cmd[1] == 0x20 || cmd[1] == 0x50)
                snprintf(exp, size, "ANTICOLL");
            else
                snprintf(exp, size, "SELECT_XXX");
            break;
        }
        case ISO14443A_CMD_ANTICOLL_OR_SELECT_2: {
            //95 20 = Anticollision of cascade level2
            //95 50 = Bit oriented anti-collision level2
            //95 70 = Select of cascade level2
            if (cmd[1] == 0x70)
                snprintf(exp, size, "SELECT_UID-2");
            else if (cmd[1] == 0x20 || cmd[1] == 0x50)
                snprintf(exp, size, "ANTICOLL-2");
            else
                snprintf(exp, size, "SELECT_XXX-2");
            break;
        }
        case ISO14443A_CMD_ANTICOLL_OR_SELECT_3: {
            //97 20 = Anticollision of cascade level3
            //97 50 = Bit oriented anti-collision level3
            //97 70 = Select of cascade level3
            if (cmd[1] == 0x70)
                snprintf(exp, size, "SELECT_UID-3");
            else if (cmd[1] == 0x20 || cmd[1] == 0x50)
                snprintf(exp, size, "ANTICOLL-3");
            else
                snprintf(exp, size, "SELECT_XXX-3");
            break;
        }
        case ISO14443A_CMD_REQA:
            snprintf(exp, size, "REQA");
            break;
        case ISO14443A_CMD_READBLOCK:
            snprintf(exp, size, "READBLOCK(%d)", cmd[1]);
            break;
        case ISO14443A_CMD_WRITEBLOCK:
            snprintf(exp, size, "WRITEBLOCK(%d)", cmd[1]);
            break;
        case ISO14443A_CMD_HALT:
            snprintf(exp, size, "HALT");
            MifareAuthState = masNone;
            break;
        case ISO14443A_CMD_RATS:
            snprintf(exp, size, "RATS");
            break;
        case ISO14443A_CMD_OPTS:
            snprintf(exp, size, "OPTIONAL TIMESLOT");
            break;
        case MIFARE_CMD_INC:
            snprintf(exp, size, "INC(%d)", cmd[1]);
            break;
        case MIFARE_CMD_DEC:
            snprintf(exp, size, "DEC(%d)", cmd[1]);
            break;
        case MIFARE_CMD_RESTORE:
            snprintf(exp, size, "RESTORE(%d)", cmd[1]);
            break;
        case MIFARE_CMD_TRANSFER:
            snprintf(exp, size, "TRANSFER(%d)", cmd[1]);
            break;
        case MIFARE_AUTH_KEYA: {
            if (cmdsize > 3) {
                snprintf(exp, size, "AUTH-A(%d)", cmd[1]);
                MifareAuthState = masNt;
            } else {
                // case MIFARE_ULEV1_VERSION :  both 0x60.
                snprintf(exp, size, "EV1 VERSION");
            }
            break;
        }
        case MIFARE_AUTH_KEYB: {
            MifareAuthState = masNt;
            snprintf(exp, size, "AUTH-B(%d)", cmd[1]);
            break;
        }
        case MIFARE_MAGICWUPC1:
            snprintf(exp, size, "MAGIC WUPC1");
            break;
        case MIFARE_MAGICWUPC2:
            snprintf(exp, size, "MAGIC WUPC2");
            break;
        case MIFARE_MAGICWIPEC:
            snprintf(exp, size, "MAGIC WIPEC");
            break;
        case MIFARE_ULC_AUTH_1:
            snprintf(exp, size, "AUTH ");
            break;
        case MIFARE_ULC_AUTH_2:
            snprintf(exp, size, "AUTH_ANSW");
            break;
        case MIFARE_ULEV1_AUTH:
            if (cmdsize == 7)
                snprintf(exp, size, "PWD-AUTH KEY: " _YELLOW_("0x%02x%02x%02x%02x"), cmd[1], cmd[2], cmd[3], cmd[4]);
            else
                snprintf(exp, size, "PWD-AUTH");
            break;
        case MIFARE_ULEV1_FASTREAD : {
            if (cmdsize >= 3 && cmd[2] <= 0xE6)
                snprintf(exp, size, "READ RANGE (%d-%d)", cmd[1], cmd[2]);
            else
                // outside limits, useful for some tags...
                snprintf(exp, size, "READ RANGE (%d-%d) (?)", cmd[1], cmd[2]);
            break;
        }
        case MIFARE_ULC_WRITE : {
            if (cmd[1] < 0x21)
                snprintf(exp, size, "WRITEBLOCK(%d)", cmd[1]);
            else
                // outside limits, useful for some tags...
                snprintf(exp, size, "WRITEBLOCK(%d) (?)", cmd[1]);
            break;
        }
        case MIFARE_ULEV1_READ_CNT : {
            if (cmd[1] < 5)
                snprintf(exp, size, "READ CNT(%d)", cmd[1]);
            else
                snprintf(exp, size, "?");
            break;
        }
        case MIFARE_ULEV1_INCR_CNT : {
            if (cmd[1] < 5)
                snprintf(exp, size, "INCR(%d)", cmd[1]);
            else
                snprintf(exp, size, "?");
            break;
        }
        case MIFARE_ULEV1_READSIG:
            snprintf(exp, size, "READ_SIG");
            break;
        case MIFARE_ULEV1_CHECKTEAR:
            snprintf(exp, size, "CHK_TEARING(%d)", cmd[1]);
            break;
        case MIFARE_ULEV1_VCSL:
            snprintf(exp, size, "VCSL");
            break;
        default:
            return 0;
    }
    return 1;
}

void annotateIso14443a(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize) {
    applyIso14443a(exp, size, cmd, cmdsize);
}

void annotateIclass(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize) {
    switch (cmd[0]) {
        case ICLASS_CMD_ACTALL:
            snprintf(exp, size, "ACTALL");
            break;
        case ICLASS_CMD_READ_OR_IDENTIFY: {
            if (cmdsize > 1) {
                snprintf(exp, size, "READ(%d)", cmd[1]);
            } else {
                snprintf(exp, size, "IDENTIFY");
            }
            break;
        }
        case ICLASS_CMD_SELECT:
            snprintf(exp, size, "SELECT");
            break;
        case ICLASS_CMD_PAGESEL:
            snprintf(exp, size, "PAGESEL(%d)", cmd[1]);
            break;
        case ICLASS_CMD_READCHECK_KC:
            snprintf(exp, size, "READCHECK[Kc](%d)", cmd[1]);
            break;
        case ICLASS_CMD_READCHECK_KD:
            snprintf(exp, size, "READCHECK[Kd](%d)", cmd[1]);
            break;
        case ICLASS_CMD_CHECK:
            snprintf(exp, size, "CHECK");
            break;
        case ICLASS_CMD_DETECT:
            snprintf(exp, size, "DETECT");
            break;
        case ICLASS_CMD_HALT:
            snprintf(exp, size, "HALT");
            break;
        case ICLASS_CMD_UPDATE:
            snprintf(exp, size, "UPDATE(%d)", cmd[1]);
            break;
        case ICLASS_CMD_ACT:
            snprintf(exp, size, "ACT");
            break;
        case ICLASS_CMD_READ4:
            snprintf(exp, size, "READ4(%d)", cmd[1]);
            break;
        default:
            snprintf(exp, size, "?");
            break;
    }
    return;
}

void annotateIso15693(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize) {

    switch (cmd[1]) {
        case ISO15693_INVENTORY:
            snprintf(exp, size, "INVENTORY");
            return;
        case ISO15693_STAYQUIET:
            snprintf(exp, size, "STAY_QUIET");
            return;
        case ISO15693_READBLOCK:
            snprintf(exp, size, "READBLOCK");
            return;
        case ISO15693_WRITEBLOCK:
            snprintf(exp, size, "WRITEBLOCK");
            return;
        case ISO15693_LOCKBLOCK:
            snprintf(exp, size, "LOCKBLOCK");
            return;
        case ISO15693_READ_MULTI_BLOCK:
            snprintf(exp, size, "READ_MULTI_BLOCK");
            return;
        case ISO15693_SELECT:
            snprintf(exp, size, "SELECT");
            return;
        case ISO15693_RESET_TO_READY:
            snprintf(exp, size, "RESET_TO_READY");
            return;
        case ISO15693_WRITE_AFI:
            snprintf(exp, size, "WRITE_AFI");
            return;
        case ISO15693_LOCK_AFI:
            snprintf(exp, size, "LOCK_AFI");
            return;
        case ISO15693_WRITE_DSFID:
            snprintf(exp, size, "WRITE_DSFID");
            return;
        case ISO15693_LOCK_DSFID:
            snprintf(exp, size, "LOCK_DSFID");
            return;
        case ISO15693_GET_SYSTEM_INFO:
            snprintf(exp, size, "GET_SYSTEM_INFO");
            return;
        case ISO15693_READ_MULTI_SECSTATUS:
            snprintf(exp, size, "READ_MULTI_SECSTATUS");
            return;
        default:
            break;
    }

    if (cmd[1] >= 0x2D && cmd[1] <= 0x9F) snprintf(exp, size, "Optional RFU");
    else if (cmd[1] >= 0xA0 && cmd[1] <= 0xDF) snprintf(exp, size, "Cust IC MFG dependent");
    else if (cmd[1] >= 0xE0 && cmd[1] <= 0xFF) snprintf(exp, size, "Proprietary IC MFG dependent");
    else
        snprintf(exp, size, "?");
}

void annotateTopaz(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize) {
    switch (cmd[0]) {
        case TOPAZ_REQA:
            snprintf(exp, size, "REQA");
            break;
        case TOPAZ_WUPA:
            snprintf(exp, size, "WUPA");
            break;
        case TOPAZ_RID:
            snprintf(exp, size, "RID");
            break;
        case TOPAZ_RALL:
            snprintf(exp, size, "RALL");
            break;
        case TOPAZ_READ:
            snprintf(exp, size, "READ");
            break;
        case TOPAZ_WRITE_E:
            snprintf(exp, size, "WRITE-E");
            break;
        case TOPAZ_WRITE_NE:
            snprintf(exp, size, "WRITE-NE");
            break;
        case TOPAZ_RSEG:
            snprintf(exp, size, "RSEG");
            break;
        case TOPAZ_READ8:
            snprintf(exp, size, "READ8");
            break;
        case TOPAZ_WRITE_E8:
            snprintf(exp, size, "WRITE-E8");
            break;
        case TOPAZ_WRITE_NE8:
            snprintf(exp, size, "WRITE-NE8");
            break;
        default:
            snprintf(exp, size, "?");
            break;
    }
}

// iso 7816-3
void annotateIso7816(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize) {
    // S-block
    if ((cmd[0] & 0xC0) && (cmdsize == 3)) {
        switch ((cmd[0] & 0x3f)) {
            case 0x00   :
                snprintf(exp, size, "S-block RESYNCH req");
                break;
            case 0x20   :
                snprintf(exp, size, "S-block RESYNCH resp");
                break;
            case 0x01   :
                snprintf(exp, size, "S-block IFS req");
                break;
            case 0x21   :
                snprintf(exp, size, "S-block IFS resp");
                break;
            case 0x02   :
                snprintf(exp, size, "S-block ABORT req");
                break;
            case 0x22   :
                snprintf(exp, size, "S-block ABORT resp");
                break;
            case 0x03   :
                snprintf(exp, size, "S-block WTX reqt");
                break;
            case 0x23   :
                snprintf(exp, size, "S-block WTX resp");
                break;
            default     :
                snprintf(exp, size, "S-block");
                break;
        }
    }
    // R-block (ack)
    else if (((cmd[0] & 0xD0) == 0x80) && (cmdsize > 2)) {
        if ((cmd[0] & 0x10) == 0)
            snprintf(exp, size, "R-block ACK");
        else
            snprintf(exp, size, "R-block NACK");
    }
    // I-block
    else {
        int pos = 0;
        switch (cmd[0]) {
            case 2:
            case 3:
                pos = 2;
                break;
            case 0:
                pos = 1;
                break;
            default:
                pos = 3;
                break;
        }
        switch (cmd[pos]) {
            case ISO7816_READ_BINARY:
                snprintf(exp, size, "READ BIN");
                break;
            case ISO7816_WRITE_BINARY:
                snprintf(exp, size, "WRITE BIN");
                break;
            case ISO7816_UPDATE_BINARY:
                snprintf(exp, size, "UPDATE BIN");
                break;
            case ISO7816_ERASE_BINARY:
                snprintf(exp, size, "ERASE BIN");
                break;
            case ISO7816_READ_RECORDS:
                snprintf(exp, size, "READ RECORDS");
                break;
            case ISO7816_WRITE_RECORDS:
                snprintf(exp, size, "WRITE RECORDS");
                break;
            case ISO7816_APPEND_RECORD:
                snprintf(exp, size, "APPEND RECORD");
                break;
            case ISO7816_UPDATE_RECORD:
                snprintf(exp, size, "UPDATE RECORD");
                break;
            case ISO7816_GET_DATA:
                snprintf(exp, size, "GET DATA");
                break;
            case ISO7816_PUT_DATA:
                snprintf(exp, size, "PUT DATA");
                break;
            case ISO7816_SELECT_FILE:
                snprintf(exp, size, "SELECT FILE");
                break;
            case ISO7816_VERIFY:
                snprintf(exp, size, "VERIFY");
                break;
            case ISO7816_INTERNAL_AUTHENTICATION:
                snprintf(exp, size, "INTERNAL AUTH");
                break;
            case ISO7816_EXTERNAL_AUTHENTICATION:
                snprintf(exp, size, "EXTERNAL AUTH");
                break;
            case ISO7816_GET_CHALLENGE:
                snprintf(exp, size, "GET CHALLENGE");
                break;
            case ISO7816_MANAGE_CHANNEL:
                snprintf(exp, size, "MANAGE CHANNEL");
                break;
            case ISO7816_GET_RESPONSE:
                snprintf(exp, size, "GET RESPONSE");
                break;
            default:
                snprintf(exp, size, "?");
                break;
        }
    }
}

// MIFARE DESFire
void annotateMfDesfire(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize) {

    // it's basically a ISO14443a tag, so try annotation from there
    if (!applyIso14443a(exp, size, cmd, cmdsize)) {
        // S-block 11xxx010
        if ((cmd[0] & 0xC0) && (cmdsize == 3)) {
            switch ((cmd[0] & 0x30)) {
                case 0x30:
                    snprintf(exp, size, "S-block DESELECT");
                    break;
                case 0x00:
                    snprintf(exp, size, "S-block WTX");
                    break;
                default:
                    snprintf(exp, size, "S-block");
                    break;
            }
        }
        // R-block (ack) 101xx01x
        else if (((cmd[0] & 0xB0) == 0xA0) && (cmdsize > 2)) {
            if ((cmd[0] & 0x10) == 0)
                snprintf(exp, size, "R-block ACK(%d)", (cmd[0] & 0x01));
            else
                snprintf(exp, size, "R-block NACK(%d)", (cmd[0] & 0x01));
        }
        // I-block 000xCN1x
        else if ((cmd[0] & 0xC0) == 0x00) {
            // PCB [CID] [NAD] [INF] CRC CRC
            int pos = 1;
            if ((cmd[0] & 0x08) == 0x08)  // cid byte following
                pos = pos + 1;
            if ((cmd[0] & 0x04) == 0x04)  // nad byte following
                pos = pos + 1;
            switch (cmd[pos]) {
                case MFDES_CREATE_APPLICATION:
                    snprintf(exp, size, "CREATE APPLICATION");
                    break;
                case MFDES_DELETE_APPLICATION:
                    snprintf(exp, size, "DELETE APPLICATION");
                    break;
                case MFDES_GET_APPLICATION_IDS:
                    snprintf(exp, size, "GET APPLICATION IDS");
                    break;
                case MFDES_SELECT_APPLICATION:
                    snprintf(exp, size, "SELECT APPLICATION");
                    break;
                case MFDES_FORMAT_PICC:
                    snprintf(exp, size, "FORMAT PICC");
                    break;
                case MFDES_GET_VERSION:
                    snprintf(exp, size, "GET VERSION");
                    break;
                case MFDES_READ_DATA:
                    snprintf(exp, size, "READ DATA");
                    break;
                case MFDES_WRITE_DATA:
                    snprintf(exp, size, "WRITE DATA");
                    break;
                case MFDES_GET_VALUE:
                    snprintf(exp, size, "GET VALUE");
                    break;
                case MFDES_CREDIT:
                    snprintf(exp, size, "CREDIT");
                    break;
                case MFDES_DEBIT:
                    snprintf(exp, size, "DEBIT");
                    break;
                case MFDES_LIMITED_CREDIT:
                    snprintf(exp, size, "LIMITED CREDIT");
                    break;
                case MFDES_WRITE_RECORD:
                    snprintf(exp, size, "WRITE RECORD");
                    break;
                case MFDES_READ_RECORDS:
                    snprintf(exp, size, "READ RECORDS");
                    break;
                case MFDES_CLEAR_RECORD_FILE:
                    snprintf(exp, size, "CLEAR RECORD FILE");
                    break;
                case MFDES_COMMIT_TRANSACTION:
                    snprintf(exp, size, "COMMIT TRANSACTION");
                    break;
                case MFDES_ABORT_TRANSACTION:
                    snprintf(exp, size, "ABORT TRANSACTION");
                    break;
                case MFDES_GET_FREE_MEMORY:
                    snprintf(exp, size, "GET FREE MEMORY");
                    break;
                case MFDES_GET_FILE_IDS:
                    snprintf(exp, size, "GET FILE IDS");
                    break;
                case MFDES_GET_ISOFILE_IDS:
                    snprintf(exp, size, "GET ISOFILE IDS");
                    break;
                case MFDES_GET_FILE_SETTINGS:
                    snprintf(exp, size, "GET FILE SETTINGS");
                    break;
                case MFDES_CHANGE_FILE_SETTINGS:
                    snprintf(exp, size, "CHANGE FILE SETTINGS");
                    break;
                case MFDES_CREATE_STD_DATA_FILE:
                    snprintf(exp, size, "CREATE STD DATA FILE");
                    break;
                case MFDES_CREATE_BACKUP_DATA_FILE:
                    snprintf(exp, size, "CREATE BACKUP DATA FILE");
                    break;
                case MFDES_CREATE_VALUE_FILE:
                    snprintf(exp, size, "CREATE VALUE FILE");
                    break;
                case MFDES_CREATE_LINEAR_RECORD_FILE:
                    snprintf(exp, size, "CREATE LINEAR RECORD FILE");
                    break;
                case MFDES_CREATE_CYCLIC_RECORD_FILE:
                    snprintf(exp, size, "CREATE CYCLIC RECORD FILE");
                    break;
                case MFDES_DELETE_FILE:
                    snprintf(exp, size, "DELETE FILE");
                    break;
                case MFDES_AUTHENTICATE:
                    snprintf(exp, size, "AUTH NATIVE (keyNo %d)", cmd[pos + 1]);
                    break;  // AUTHENTICATE_NATIVE
                case MFDES_AUTHENTICATE_ISO:
                    snprintf(exp, size, "AUTH ISO (keyNo %d)", cmd[pos + 1]);
                    break;  // AUTHENTICATE_STANDARD
                case MFDES_AUTHENTICATE_AES:
                    snprintf(exp, size, "AUTH AES (keyNo %d)", cmd[pos + 1]);
                    break;
                case MFDES_CHANGE_KEY_SETTINGS:
                    snprintf(exp, size, "CHANGE KEY SETTINGS");
                    break;
                case MFDES_GET_KEY_SETTINGS:
                    snprintf(exp, size, "GET KEY SETTINGS");
                    break;
                case MFDES_CHANGE_KEY:
                    snprintf(exp, size, "CHANGE KEY");
                    break;
                case MFDES_GET_KEY_VERSION:
                    snprintf(exp, size, "GET KEY VERSION");
                    break;
                case MFDES_AUTHENTICATION_FRAME:
                    snprintf(exp, size, "AUTH FRAME / NEXT FRAME");
                    break;
                default:
                    break;
            }
        } else {
            // anything else
            snprintf(exp, size, "?");
        }
    }
}

/**
06 00 = INITIATE
0E xx = SELECT ID (xx = Chip-ID)
0B = Get UID
08 yy = Read Block (yy = block number)
09 yy dd dd dd dd = Write Block (yy = block number; dd dd dd dd = data to be written)
0C = Reset to Inventory
0F = Completion
0A 11 22 33 44 55 66 = Authenticate (11 22 33 44 55 66 = data to authenticate)
**/
void annotateIso14443b(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize) {
    switch (cmd[0]) {
        case ISO14443B_REQB           : {

            switch (cmd[2] & 0x07) {
                case 0:
                    snprintf(exp, size, "1 slot ");
                    break;
                case 1:
                    snprintf(exp, size, "2 slots ");
                    break;
                case 2:
                    snprintf(exp, size, "4 slots ");
                    break;
                case 3:
                    snprintf(exp, size, "8 slots ");
                    break;
                default:
                    snprintf(exp, size, "16 slots ");
                    break;
            }
            if ((cmd[2] & 0x8))
                snprintf(exp, size, "WUPB");
            else
                snprintf(exp, size, "REQB");
            break;
        }
        case ISO14443B_ATTRIB:
            snprintf(exp, size, "ATTRIB");
            break;
        case ISO14443B_HALT:
            snprintf(exp, size, "HALT");
            break;
        case ISO14443B_INITIATE:
            snprintf(exp, size, "INITIATE");
            break;
        case ISO14443B_SELECT:
            snprintf(exp, size, "SELECT(%d)", cmd[1]);
            break;
        case ISO14443B_GET_UID:
            snprintf(exp, size, "GET UID");
            break;
        case ISO14443B_READ_BLK:
            snprintf(exp, size, "READ_BLK(%d)", cmd[1]);
            break;
        case ISO14443B_WRITE_BLK:
            snprintf(exp, size, "WRITE_BLK(%d)", cmd[1]);
            break;
        case ISO14443B_RESET:
            snprintf(exp, size, "RESET");
            break;
        case ISO14443B_COMPLETION:
            snprintf(exp, size, "COMPLETION");
            break;
        case ISO14443B_AUTHENTICATE:
            snprintf(exp, size, "AUTHENTICATE");
            break;
        case ISO14443B_PING:
            snprintf(exp, size, "PING");
            break;
        case ISO14443B_PONG:
            snprintf(exp, size, "PONG");
            break;
        default:
            snprintf(exp, size, "?");
            break;
    }
}

// LEGIC
// 1 = read
// 0 = write
// Quite simpel tag
void annotateLegic(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize) {
    uint8_t bitsend = cmd[0];
    uint8_t cmdBit = (cmd[1] & 1);
    switch (bitsend) {
        case 7:
            snprintf(exp, size, "IV 0x%02X", cmd[1]);
            break;
        case 6: {
            switch (cmd[1]) {
                case LEGIC_MIM_22:
                    snprintf(exp, size, "MIM22");
                    break;
                case LEGIC_MIM_256:
                    snprintf(exp, size, "MIM256");
                    break;
                case LEGIC_MIM_1024:
                    snprintf(exp, size, "MIM1024");
                    break;
                case LEGIC_ACK_22:
                    snprintf(exp, size, "ACK 22");
                    break;
                case LEGIC_ACK_256:
                    snprintf(exp, size, "ACK 256/1024");
                    break;
            }
            break;
        }
        case 9:
        case 11: {

            uint16_t address = (cmd[2] << 7) | cmd[1] >> 1;

            if (cmdBit == LEGIC_READ)
                snprintf(exp, size, "READ Byte(%d)", address);

            if (cmdBit == LEGIC_WRITE)
                snprintf(exp, size, "WRITE Byte(%d)", address);
            break;
        }
        case 21: {
            if (cmdBit == LEGIC_WRITE) {
                uint16_t address = ((cmd[2] << 7) | cmd[1] >> 1) & 0xFF;
                uint8_t val = (cmd[3] & 1) << 7 | cmd[2] >> 1;
                snprintf(exp, size, "WRITE Byte(%d) %02X", address, val);
            }
            break;
        }
        case 23: {
            if (cmdBit == LEGIC_WRITE) {
                uint16_t address = ((cmd[2] << 7) | cmd[1] >> 1) & 0x3FF;
                uint8_t val = (cmd[3] & 0x7) << 5 | cmd[2] >> 3;
                snprintf(exp, size, "WRITE Byte(%d) %02X", address, val);
            }
            break;
        }
        case 12:
        default:
            break;
    }
}

void annotateFelica(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize) {

    switch (cmd[0]) {
        case FELICA_POLL_REQ:
            snprintf(exp, size, "POLLING");
            break;
        case FELICA_POLL_ACK:
            snprintf(exp, size, "POLL ACK");
            break;
        case FELICA_REQSRV_REQ:
            snprintf(exp, size, "REQUEST SERVICE");
            break;
        case FELICA_REQSRV_ACK:
            snprintf(exp, size, "REQ SERV ACK");
            break;
        case FELICA_REQRESP_REQ:
            snprintf(exp, size, "REQUEST RESPONSE");
            break;
        case FELICA_REQRESP_ACK:
            snprintf(exp, size, "REQ RESP ACK");
            break;
        case FELICA_RDBLK_REQ:
            snprintf(exp, size, "READ BLK");
            break;
        case FELICA_RDBLK_ACK:
            snprintf(exp, size, "READ BLK ACK");
            break;
        case FELICA_WRTBLK_REQ:
            snprintf(exp, size, "WRITE BLK");
            break;
        case FELICA_WRTBLK_ACK:
            snprintf(exp, size, "WRITE BLK ACK");
            break;
        case FELICA_SRCHSYSCODE_REQ:
            snprintf(exp, size, "SEARCH SERVICE CODE");
            break;
        case FELICA_SRCHSYSCODE_ACK:
            snprintf(exp, size, "SSC ACK");
            break;
        case FELICA_REQSYSCODE_REQ:
            snprintf(exp, size, "REQUEST SYSTEM CODE");
            break;
        case FELICA_REQSYSCODE_ACK:
            snprintf(exp, size, "RSC ACK");
            break;
        case FELICA_AUTH1_REQ:
            snprintf(exp, size, "AUTH 1");
            break;
        case FELICA_AUTH1_ACK:
            snprintf(exp, size, "AUTH 1 ACK");
            break;
        case FELICA_AUTH2_REQ:
            snprintf(exp, size, "AUTH 2");
            break;
        case FELICA_AUTH2_ACK:
            snprintf(exp, size, "AUTH 2 ACK");
            break;
        case FELICA_RDSEC_REQ:
            snprintf(exp, size, "READ");
            break;
        case FELICA_RDSEC_ACK:
            snprintf(exp, size, "READ ACK");
            break;
        case FELICA_WRTSEC_REQ:
            snprintf(exp, size, "WRITE");
            break;
        case FELICA_WRTSEC_ACK:
            snprintf(exp, size, "WRITE ACK");
            break;
        case FELICA_REQSRV2_REQ:
            snprintf(exp, size, "REQUEST SERVICE v2");
            break;
        case FELICA_REQSRV2_ACK:
            snprintf(exp, size, "REQ SERV v2 ACK");
            break;
        case FELICA_GETSTATUS_REQ:
            snprintf(exp, size, "GET STATUS");
            break;
        case FELICA_GETSTATUS_ACK:
            snprintf(exp, size, "GET STATUS ACK");
            break;
        case FELICA_OSVER_REQ:
            snprintf(exp, size, "REQUEST SPECIFIC VERSION");
            break;
        case FELICA_OSVER_ACK:
            snprintf(exp, size, "RSV ACK");
            break;
        case FELICA_RESET_MODE_REQ:
            snprintf(exp, size, "RESET MODE");
            break;
        case FELICA_RESET_MODE_ACK:
            snprintf(exp, size, "RESET MODE ACK");
            break;
        case FELICA_AUTH1V2_REQ:
            snprintf(exp, size, "AUTH 1 v2");
            break;
        case FELICA_AUTH1V2_ACK:
            snprintf(exp, size, "AUTH 1 v2 ACK");
            break;
        case FELICA_AUTH2V2_REQ:
            snprintf(exp, size, "AUTH 2 v2");
            break;
        case FELICA_AUTH2V2_ACK:
            snprintf(exp, size, "AUTH 2 v2 ACK");
            break;
        case FELICA_RDSECV2_REQ:
            snprintf(exp, size, "READ v2");
            break;
        case FELICA_RDSECV2_ACK:
            snprintf(exp, size, "READ v2 ACK");
            break;
        case FELICA_WRTSECV2_REQ:
            snprintf(exp, size, "WRITE v2");
            break;
        case FELICA_WRTSECV2_ACK:
            snprintf(exp, size, "WRITE v2 ACK");
            break;
        case FELICA_UPDATE_RNDID_REQ:
            snprintf(exp, size, "UPDATE RANDOM ID");
            break;
        case FELICA_UPDATE_RNDID_ACK:
            snprintf(exp, size, "URI ACK");
            break;
        default                     :
            snprintf(exp, size, "?");
            break;
    }
}

void annotateMifare(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize, uint8_t *parity, uint8_t paritysize, bool isResponse) {
    if (!isResponse && cmdsize == 1) {
        switch (cmd[0]) {
            case ISO14443A_CMD_WUPA:
            case ISO14443A_CMD_REQA:
                MifareAuthState = masNone;
                break;
            default:
                break;
        }
    }

    // get UID
    if (MifareAuthState == masNone) {
        if (cmdsize == 9 && cmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && cmd[1] == 0x70) {
            ClearAuthData();
            AuthData.uid = bytes_to_num(&cmd[2], 4);
        }
        if (cmdsize == 9 && cmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && cmd[1] == 0x70) {
            ClearAuthData();
            AuthData.uid = bytes_to_num(&cmd[2], 4);
        }
        if (cmdsize == 9 && cmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3 && cmd[1] == 0x70) {
            ClearAuthData();
            AuthData.uid = bytes_to_num(&cmd[2], 4);
        }
    }

    switch (MifareAuthState) {
        case masNt:
            if (cmdsize == 4 && isResponse) {
                snprintf(exp, size, "AUTH: nt %s", (AuthData.first_auth) ? "" : "(enc)");
                MifareAuthState = masNrAr;
                if (AuthData.first_auth) {
                    AuthData.nt = bytes_to_num(cmd, 4);
                } else {
                    AuthData.nt_enc = bytes_to_num(cmd, 4);
                    AuthData.nt_enc_par = parity[0];
                }
                return;
            } else {
                MifareAuthState = masError;
            }
            break;
        case masNrAr:
            if (cmdsize == 8 && !isResponse) {
                snprintf(exp, size, "AUTH: nr ar (enc)");
                MifareAuthState = masAt;
                AuthData.nr_enc = bytes_to_num(cmd, 4);
                AuthData.ar_enc = bytes_to_num(&cmd[4], 4);
                AuthData.ar_enc_par = parity[0] << 4;
                return;
            } else {
                MifareAuthState = masError;
            }
            break;
        case masAt:
            if (cmdsize == 4 && isResponse) {
                snprintf(exp, size, "AUTH: at (enc)");
                MifareAuthState = masAuthComplete;
                AuthData.at_enc = bytes_to_num(cmd, 4);
                AuthData.at_enc_par = parity[0];
                return;
            } else {
                MifareAuthState = masError;
            }
            break;
        case masNone:
        case masError:
        case masAuthComplete:
        case masFirstData:
        case masData:
            break;
    }

    if (!isResponse && ((MifareAuthState == masNone) || (MifareAuthState == masError)))
        annotateIso14443a(exp, size, cmd, cmdsize);

}

bool DecodeMifareData(uint8_t *cmd, uint8_t cmdsize, uint8_t *parity, bool isResponse, uint8_t *mfData, size_t *mfDataLen) {
    static struct Crypto1State *traceCrypto1;
    static uint64_t mfLastKey;

    *mfDataLen = 0;

    if (MifareAuthState == masAuthComplete) {
        if (traceCrypto1) {
            crypto1_destroy(traceCrypto1);
            traceCrypto1 = NULL;
        }

        MifareAuthState = masFirstData;
        return false;
    }

    if (cmdsize > 32)
        return false;

    if (MifareAuthState == masFirstData) {
        if (AuthData.first_auth) {
            AuthData.ks2 = AuthData.ar_enc ^ prng_successor(AuthData.nt, 64);
            AuthData.ks3 = AuthData.at_enc ^ prng_successor(AuthData.nt, 96);

            mfLastKey = GetCrypto1ProbableKey(&AuthData);
            PrintAndLogEx(NORMAL, "            |            |  *  |%49s %012"PRIx64" prng %s |     |",
                          "key",
                          mfLastKey,
                          validate_prng_nonce(AuthData.nt) ? _GREEN_("WEAK") : _YELLOW_("HARD"));

            AuthData.first_auth = false;

            traceCrypto1 = lfsr_recovery64(AuthData.ks2, AuthData.ks3);
        } else {
            if (traceCrypto1) {
                crypto1_destroy(traceCrypto1);
                traceCrypto1 = NULL;
            }

            // check last used key
            if (mfLastKey) {
                if (NestedCheckKey(mfLastKey, &AuthData, cmd, cmdsize, parity)) {
                    PrintAndLogEx(NORMAL, "            |            |  *  |%60s %012"PRIx64"|     |", "last used key", mfLastKey);
                    traceCrypto1 = lfsr_recovery64(AuthData.ks2, AuthData.ks3);
                };
            }

            // check default keys
            if (!traceCrypto1) {
                for (int i = 0; i < MIFARE_DEFAULTKEYS_SIZE; i++) {
                    if (NestedCheckKey(g_mifare_default_keys[i], &AuthData, cmd, cmdsize, parity)) {
                        PrintAndLogEx(NORMAL, "            |            |  *  |%61s %012"PRIx64"|     |", "key", g_mifare_default_keys[i]);

                        mfLastKey = g_mifare_default_keys[i];
                        traceCrypto1 = lfsr_recovery64(AuthData.ks2, AuthData.ks3);
                        break;
                    };
                }
            }

            // nested
            if (!traceCrypto1 && validate_prng_nonce(AuthData.nt)) {
                uint32_t ntx = prng_successor(AuthData.nt, 90);
                for (int i = 0; i < 16383; i++) {
                    ntx = prng_successor(ntx, 1);
                    if (NTParityChk(&AuthData, ntx)) {

                        uint32_t ks2 = AuthData.ar_enc ^ prng_successor(ntx, 64);
                        uint32_t ks3 = AuthData.at_enc ^ prng_successor(ntx, 96);
                        struct Crypto1State *pcs = lfsr_recovery64(ks2, ks3);
                        memcpy(mfData, cmd, cmdsize);
                        mf_crypto1_decrypt(pcs, mfData, cmdsize, 0);
                        crypto1_destroy(pcs);

                        if (CheckCrypto1Parity(cmd, cmdsize, mfData, parity) && check_crc(CRC_14443_A, mfData, cmdsize)) {
                            AuthData.ks2 = ks2;
                            AuthData.ks3 = ks3;
                            AuthData.nt = ntx;
                            mfLastKey = GetCrypto1ProbableKey(&AuthData);
                            PrintAndLogEx(NORMAL, "            |            |  *  | nested probable key:%012"PRIx64"      ks2:%08x ks3:%08x |     |",
                                          mfLastKey,
                                          AuthData.ks2,
                                          AuthData.ks3);

                            traceCrypto1 = lfsr_recovery64(AuthData.ks2, AuthData.ks3);
                            break;
                        }
                    }
                }
            }

            //hardnested
            if (!traceCrypto1) {
                PrintAndLogEx(NORMAL, "hardnested not implemented. uid:%x nt:%x ar_enc:%x at_enc:%x\n", AuthData.uid, AuthData.nt, AuthData.ar_enc, AuthData.at_enc);
                MifareAuthState = masError;

                /* TOO SLOW( needs to have more strong filter. with this filter - aprox 4 mln tests
                uint32_t t = msclock();
                uint32_t t1 = t;
                int n = 0;
                for (uint32_t i = 0; i < 0xFFFFFFFF; i++) {
                    if (NTParityChk(&AuthData, i)){

                        uint32_t ks2 = AuthData.ar_enc ^ prng_successor(i, 64);
                        uint32_t ks3 = AuthData.at_enc ^ prng_successor(i, 96);
                        struct Crypto1State *pcs = lfsr_recovery64(ks2, ks3);

                        n++;

                        if (!(n % 100000)) {
                            PrintAndLogEx(NORMAL, "delta=%d n=%d ks2=%x ks3=%x \n", msclock() - t1 , n, ks2, ks3);
                            t1 = msclock();
                        }

                    }
                }
                PrintAndLogEx(NORMAL, "delta=%d n=%d\n", msclock() - t, n);
                */
            }
        }
        MifareAuthState = masData;
    }

    if (MifareAuthState == masData && traceCrypto1) {
        memcpy(mfData, cmd, cmdsize);
        mf_crypto1_decrypt(traceCrypto1, mfData, cmdsize, 0);
        *mfDataLen = cmdsize;
    }

    return *mfDataLen > 0;
}

bool NTParityChk(TAuthData *ad, uint32_t ntx) {
    if (
        (oddparity8(ntx >> 8 & 0xff) ^ (ntx & 0x01) ^ ((ad->nt_enc_par >> 5) & 0x01) ^ (ad->nt_enc & 0x01)) ||
        (oddparity8(ntx >> 16 & 0xff) ^ (ntx >> 8 & 0x01) ^ ((ad->nt_enc_par >> 6) & 0x01) ^ (ad->nt_enc >> 8 & 0x01)) ||
        (oddparity8(ntx >> 24 & 0xff) ^ (ntx >> 16 & 0x01) ^ ((ad->nt_enc_par >> 7) & 0x01) ^ (ad->nt_enc >> 16 & 0x01))
    )
        return false;

    uint32_t ar = prng_successor(ntx, 64);
    if (
        (oddparity8(ar >> 8 & 0xff) ^ (ar & 0x01) ^ ((ad->ar_enc_par >> 5) & 0x01) ^ (ad->ar_enc & 0x01)) ||
        (oddparity8(ar >> 16 & 0xff) ^ (ar >> 8 & 0x01) ^ ((ad->ar_enc_par >> 6) & 0x01) ^ (ad->ar_enc >> 8 & 0x01)) ||
        (oddparity8(ar >> 24 & 0xff) ^ (ar >> 16 & 0x01) ^ ((ad->ar_enc_par >> 7) & 0x01) ^ (ad->ar_enc >> 16 & 0x01))
    )
        return false;

    uint32_t at = prng_successor(ntx, 96);
    if (
        (oddparity8(ar & 0xff) ^ (at >> 24 & 0x01) ^ ((ad->ar_enc_par >> 4) & 0x01) ^ (ad->at_enc >> 24 & 0x01)) ||
        (oddparity8(at >> 8 & 0xff) ^ (at & 0x01) ^ ((ad->at_enc_par >> 5) & 0x01) ^ (ad->at_enc & 0x01)) ||
        (oddparity8(at >> 16 & 0xff) ^ (at >> 8 & 0x01) ^ ((ad->at_enc_par >> 6) & 0x01) ^ (ad->at_enc >> 8 & 0x01)) ||
        (oddparity8(at >> 24 & 0xff) ^ (at >> 16 & 0x01) ^ ((ad->at_enc_par >> 7) & 0x01) ^ (ad->at_enc >> 16 & 0x01))
    )
        return false;

    return true;
}

bool NestedCheckKey(uint64_t key, TAuthData *ad, uint8_t *cmd, uint8_t cmdsize, uint8_t *parity) {
    uint8_t buf[32] = {0};
    struct Crypto1State *pcs;

    AuthData.ks2 = 0;
    AuthData.ks3 = 0;

    pcs = crypto1_create(key);
    uint32_t nt1 = crypto1_word(pcs, ad->nt_enc ^ ad->uid, 1) ^ ad->nt_enc;
    uint32_t ar = prng_successor(nt1, 64);
    uint32_t at = prng_successor(nt1, 96);

    crypto1_word(pcs, ad->nr_enc, 1);
//   uint32_t nr1 = crypto1_word(pcs, ad->nr_enc, 1) ^ ad->nr_enc;  // if needs deciphered nr
    uint32_t ar1 = crypto1_word(pcs, 0, 0) ^ ad->ar_enc;
    uint32_t at1 = crypto1_word(pcs, 0, 0) ^ ad->at_enc;

    if (!(ar == ar1 && at == at1 && NTParityChk(ad, nt1))) {
        crypto1_destroy(pcs);
        return false;
    }

    memcpy(buf, cmd, cmdsize);
    mf_crypto1_decrypt(pcs, buf, cmdsize, 0);
    crypto1_destroy(pcs);

    if (!CheckCrypto1Parity(cmd, cmdsize, buf, parity))
        return false;

    if (!check_crc(CRC_14443_A, buf, cmdsize))
        return false;

    AuthData.nt = nt1;
    AuthData.ks2 = AuthData.ar_enc ^ ar;
    AuthData.ks3 = AuthData.at_enc ^ at;
    return true;
}

bool CheckCrypto1Parity(uint8_t *cmd_enc, uint8_t cmdsize, uint8_t *cmd, uint8_t *parity_enc) {
    for (int i = 0; i < cmdsize - 1; i++) {
        if (oddparity8(cmd[i]) ^ (cmd[i + 1] & 0x01) ^ ((parity_enc[i / 8] >> (7 - i % 8)) & 0x01) ^ (cmd_enc[i + 1] & 0x01))
            return false;
    }
    return true;
}

// Another implementation of mfkey64 attack,  more "valid" than "probable"
//
uint64_t GetCrypto1ProbableKey(TAuthData *ad) {
    struct Crypto1State *revstate = lfsr_recovery64(ad->ks2, ad->ks3);
    lfsr_rollback_word(revstate, 0, 0);
    lfsr_rollback_word(revstate, 0, 0);
    lfsr_rollback_word(revstate, ad->nr_enc, 1);
    lfsr_rollback_word(revstate, ad->uid ^ ad->nt, 0);
    uint64_t key = 0;
    crypto1_get_lfsr(revstate, &key);
    crypto1_destroy(revstate);
    return key;
}
