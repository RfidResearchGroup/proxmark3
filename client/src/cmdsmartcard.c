//-----------------------------------------------------------------------------
// Copyright (C) 2018 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Proxmark3 RDV40 Smartcard module commands
//-----------------------------------------------------------------------------
#include "cmdsmartcard.h"

#include <ctype.h>
#include <string.h>

#include "cmdparser.h"    // command_t
#include "commonutil.h"  // ARRAYLEN
#include "protocols.h"
#include "cmdtrace.h"
#include "proxmark3.h"
#include "comms.h"              // getfromdevice
#include "emv/emvcore.h"        // decodeTVL
#include "crypto/libpcrypto.h"  // sha512hash
#include "emv/dump.h"
#include "ui.h"
#include "fileutils.h"

static int CmdHelp(const char *Cmd);

static int usage_sm_raw(void) {
    PrintAndLogEx(NORMAL, "Usage: sc raw [h|r|c] d <0A 0B 0C ... hex>");
    PrintAndLogEx(NORMAL, "       h          :  this help");
    PrintAndLogEx(NORMAL, "       r          :  do not read response");
    PrintAndLogEx(NORMAL, "       a          :  active smartcard without select (reset sc module)");
    PrintAndLogEx(NORMAL, "       s          :  active smartcard with select (get ATR)");
    PrintAndLogEx(NORMAL, "       t          :  executes TLV decoder if it possible");
    PrintAndLogEx(NORMAL, "       0          :  use protocol T=0");
    PrintAndLogEx(NORMAL, "       d <bytes>  :  bytes to send");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        sc raw s 0 d 00a404000e315041592e5359532e4444463031  - `1PAY.SYS.DDF01` PPSE directory with get ATR");
    PrintAndLogEx(NORMAL, "        sc raw 0 d 00a404000e325041592e5359532e4444463031    - `2PAY.SYS.DDF01` PPSE directory");
    PrintAndLogEx(NORMAL, "        sc raw 0 t d 00a4040007a0000000041010              - Mastercard");
    PrintAndLogEx(NORMAL, "        sc raw 0 t d 00a4040007a0000000031010                - Visa");
    return PM3_SUCCESS;
}
static int usage_sm_reader(void) {
    PrintAndLogEx(NORMAL, "Usage: sc reader [h|s]");
    PrintAndLogEx(NORMAL, "       h          :  this help");
    PrintAndLogEx(NORMAL, "       s          :  silent (no messages)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        sc reader");
    return PM3_SUCCESS;
}
static int usage_sm_info(void) {
    PrintAndLogEx(NORMAL, "Usage: sc info [h|s]");
    PrintAndLogEx(NORMAL, "       h          :  this help");
    PrintAndLogEx(NORMAL, "       s          :  silent (no messages)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        sc info");
    return PM3_SUCCESS;
}
static int usage_sm_upgrade(void) {
    PrintAndLogEx(NORMAL, "Upgrade RDV4.0 Sim module firmware");
    PrintAndLogEx(NORMAL, "Usage:  sc upgrade f <file name>");
    PrintAndLogEx(NORMAL, "       h               :  this help");
    PrintAndLogEx(NORMAL, "       f <filename>    :  firmware file name");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        sc upgrade f ../tools/simmodule/sim011.bin");
    return PM3_SUCCESS;
}
static int usage_sm_setclock(void) {
    PrintAndLogEx(NORMAL, "Usage: sc setclock [h] c <clockspeed>");
    PrintAndLogEx(NORMAL, "       h          :  this help");
    PrintAndLogEx(NORMAL, "       c <>       :  clockspeed (0 = 16MHz, 1=8MHz, 2=4MHz) ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        sc setclock c 2");
    return PM3_SUCCESS;
}
static int usage_sm_brute(void) {
    PrintAndLogEx(NORMAL, "Tries to bruteforce SFI, using a known list of AID's ");
    PrintAndLogEx(NORMAL, "Usage: sc brute [h]");
    PrintAndLogEx(NORMAL, "       h          :  this help");
    PrintAndLogEx(NORMAL, "       t          :  executes TLV decoder if it possible");
//  PrintAndLogEx(NORMAL, "       0          :  use protocol T=0");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        sc brute t");
    return PM3_SUCCESS;
}

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

static uint8_t GetATRTA1(uint8_t *atr, size_t atrlen) {
    if (atrlen > 2) {
        uint8_t T0 = atr[1];
        if (T0 & 0x10)
            return atr[2];
    }

    return 0x11; // default value is 0x11, corresponding to fmax=5 MHz, Fi=372, Di=1.
}

int DiArray[] = {
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

int FiArray[] = {
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

float FArray[] = {
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
        PrintAndLogEx(INFO, "\t- TA1 (Maximum clock frequency, proposed bit duration) [ 0x%02x ]", atr[2 + T1len]);
        T1len++;
    }

    if (T0 & 0x20) {
        PrintAndLogEx(INFO, "\t- TB1 (Deprecated: VPP requirements) [ 0x%02x ]", atr[2 + T1len]);
        T1len++;
    }

    if (T0 & 0x40) {
        PrintAndLogEx(INFO, "\t- TC1 (Extra delay between bytes required by card) [ 0x%02x ]", atr[2 + T1len]);
        T1len++;
    }

    if (T0 & 0x80) {
        uint8_t TD1 = atr[2 + T1len];
        PrintAndLogEx(INFO, "\t- TD1 (First offered transmission protocol, presence of TA2..TD2) [ 0x%02x ] Protocol T%d", TD1, TD1 & 0x0f);
        protocol_T0_present = false;
        if ((TD1 & 0x0f) == 0) {
            protocol_T0_present = true;
        }
        if ((TD1 & 0x0f) == 15) {
            protocol_T15_present = true;
        }

        T1len++;

        if (TD1 & 0x10) {
            PrintAndLogEx(INFO, "\t- TA2 (Specific protocol and parameters to be used after the ATR) [ 0x%02x ]", atr[2 + T1len + TD1len]);
            TD1len++;
        }
        if (TD1 & 0x20) {
            PrintAndLogEx(INFO, "\t- TB2 (Deprecated: VPP precise voltage requirement) [ 0x%02x ]", atr[2 + T1len + TD1len]);
            TD1len++;
        }
        if (TD1 & 0x40) {
            PrintAndLogEx(INFO, "\t- TC2 (Maximum waiting time for protocol T=0) [ 0x%02x ]", atr[2 + T1len + TD1len]);
            TD1len++;
        }
        if (TD1 & 0x80) {
            uint8_t TDi = atr[2 + T1len + TD1len];
            PrintAndLogEx(INFO, "\t- TD2 (A supported protocol or more global parameters, presence of TA3..TD3) [ 0x%02x ] Protocol T%d", TDi, TDi & 0x0f);
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
                    PrintAndLogEx(INFO, "\t- TA%d: 0x%02x", vi, atr[2 + T1len + TD1len + TDilen]);
                    TDilen++;
                }
                if (TDi & 0x20) {
                    PrintAndLogEx(INFO, "\t- TB%d: 0x%02x", vi, atr[2 + T1len + TD1len + TDilen]);
                    TDilen++;
                }
                if (TDi & 0x40) {
                    PrintAndLogEx(INFO, "\t- TC%d: 0x%02x", vi, atr[2 + T1len + TD1len + TDilen]);
                    TDilen++;
                }
                if (TDi & 0x80) {
                    TDi = atr[2 + T1len + TD1len + TDilen];
                    PrintAndLogEx(INFO, "\t- TD%d [ 0x%02x ] Protocol T%d", vi, TDi, TDi & 0x0f);
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
        PrintAndLogEx(INFO, "Historical bytes | len 0x%02d | format %02x", K, atr[2 + T1len + TD1len + TDilen]);

    if (K > 1) {
        PrintAndLogEx(INFO, "\tHistorical bytes");
        dump_buffer(&atr[2 + T1len + TD1len + TDilen], K, NULL, 1);
    }
}

static int smart_wait(uint8_t *data, bool silent) {
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        if (!silent) PrintAndLogEx(WARNING, "smart card response timeout");
        return -1;
    }

    uint32_t len = resp.oldarg[0];
    if (!len) {
        if (!silent) PrintAndLogEx(WARNING, "smart card response failed");
        return -2;
    }
    memcpy(data, resp.data.asBytes, len);
    if (len >= 2) {
        if (!silent) PrintAndLogEx(SUCCESS, "%02X%02X | %s", data[len - 2], data[len - 1], GetAPDUCodeDescription(data[len - 2], data[len - 1]));
    } else {
        if (!silent) PrintAndLogEx(SUCCESS, " %d | %s", len, sprint_hex_inrow_ex(data,  len, 8));
    }

    return len;
}

static int smart_responseEx(uint8_t *data, bool silent) {

    int datalen = smart_wait(data, silent);
    bool needGetData = false;

    if (datalen < 2) {
        goto out;
    }

    if (data[datalen - 2] == 0x61 || data[datalen - 2] == 0x9F) {
        needGetData = true;
    }

    if (needGetData) {
        int len = data[datalen - 1];

        if (!silent) PrintAndLogEx(INFO, "Requesting 0x%02X bytes response", len);

        uint8_t getstatus[] = {0x00, ISO7816_GET_RESPONSE, 0x00, 0x00, len};
        clearCommandBuffer();
        SendCommandMIX(CMD_SMART_RAW, SC_RAW, sizeof(getstatus), 0, getstatus, sizeof(getstatus));

        datalen = smart_wait(data, silent);

        if (datalen < 2) {
            goto out;
        }

        // data wo ACK
        if (datalen != len + 2) {
            // data with ACK
            if (datalen == len + 2 + 1) { // 2 - response, 1 - ACK
                if (data[0] != ISO7816_GET_RESPONSE) {
                    if (!silent) {
                        PrintAndLogEx(ERR, "GetResponse ACK error. len 0x%x | data[0] %02X", len, data[0]);
                    }
                    datalen = 0;
                    goto out;
                }

                datalen--;
                memmove(data, &data[1], datalen);
            } else {
                // wrong length
                if (!silent) {
                    PrintAndLogEx(WARNING, "GetResponse wrong length. Must be 0x%02X got 0x%02X", len, datalen - 3);
                }
            }
        }
    }

out:
    return datalen;
}

static int smart_response(uint8_t *data) {
    return smart_responseEx(data, false);
}

static int CmdSmartRaw(const char *Cmd) {

    int hexlen = 0;
    bool active = false;
    bool active_select = false;
    bool useT0 = false;
    uint8_t cmdp = 0;
    bool errors = false, reply = true, decodeTLV = false, breakloop = false;
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_sm_raw();
            case 'r':
                reply = false;
                cmdp++;
                break;
            case 'a':
                active = true;
                cmdp++;
                break;
            case 's':
                active_select = true;
                cmdp++;
                break;
            case 't':
                decodeTLV = true;
                cmdp++;
                break;
            case '0':
                useT0 = true;
                cmdp++;
                break;
            case 'd': {
                switch (param_gethex_to_eol(Cmd, cmdp + 1, data, sizeof(data), &hexlen)) {
                    case 1:
                        PrintAndLogEx(WARNING, "Invalid HEX value.");
                        return PM3_EINVARG;
                    case 2:
                        PrintAndLogEx(WARNING, "Too many bytes.  Max %zu bytes", sizeof(data));
                        return PM3_EINVARG;
                    case 3:
                        PrintAndLogEx(WARNING, "Hex must have even number of digits.");
                        return PM3_EINVARG;
                }
                cmdp++;
                breakloop = true;
                break;
            }
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }

        if (breakloop)
            break;
    }

    //Validations
    if (errors || cmdp == 0) return usage_sm_raw();

    uint8_t flags = 0;
    if (active || active_select) {
        flags |= SC_CONNECT;
        if (active_select)
            flags |= SC_SELECT;
    }

    if (hexlen > 0) {
        if (useT0)
            flags |= SC_RAW_T0;
        else
            flags |= SC_RAW;
    }

    clearCommandBuffer();
    SendCommandOLD(CMD_SMART_RAW, flags, hexlen, 0, data, hexlen);

    // reading response from smart card
    if (reply) {

        uint8_t *buf = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
        if (!buf)
            return PM3_EMALLOC;

        int len = smart_response(buf);
        if (len < 0) {
            free(buf);
            return PM3_ESOFT;
        }

        if (buf[0] == 0x6C) {
            data[4] = buf[1];

            clearCommandBuffer();
            SendCommandMIX(CMD_SMART_RAW, 0, hexlen, 0, data, hexlen);
            len = smart_response(buf);

            data[4] = 0;
        }

        if (decodeTLV && len > 4)
            TLVPrintFromBuffer(buf, len - 2);
        else {
            if (len > 16) {
                for (int i=0; i<len; i += 16) {
                    PrintAndLogEx(SUCCESS, "%s", sprint_hex_ascii(buf + i, 16)) ;
                }
            } else {
                    PrintAndLogEx(SUCCESS, "%s", sprint_hex_ascii(buf, len)) ;
            }
        }

        free(buf);
    }
    return PM3_SUCCESS;
}

static int CmdSmartUpgrade(const char *Cmd) {

    PrintAndLogEx(WARNING, "WARNING - Sim module firmware upgrade.");
    PrintAndLogEx(WARNING, "A dangerous command, do wrong and you could brick the sim module");
    PrintAndLogEx(NORMAL, "");

    char filename[FILE_PATH_SIZE] = {0};
    uint8_t cmdp = 0;
    bool errors = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'f':
                if (param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE) >= FILE_PATH_SIZE) {
                    PrintAndLogEx(FAILED, "Filename too long");
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;
            case 'h':
                return usage_sm_upgrade();
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors || cmdp == 0) return usage_sm_upgrade();


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
    if (loadFile_safe(filename, "", (void**)&firmware, &firmware_size) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Firmware file " _YELLOW_("%s") " not found or locked.", filename);
        return PM3_EFILE;
    }

    // load sha512 file
    size_t sha512_size = 0;
    char *hashstring = NULL;
    if (loadFile_safe(sha512filename, "", (void**)&hashstring, &sha512_size) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "SHA-512 file not found or locked.");
        free(firmware);
        return PM3_EFILE;
    }

    if (sha512_size < 128) {
        PrintAndLogEx(FAILED, "SHA-512 file wrong size");
        free(firmware);
        return PM3_ESOFT;
    }
    hashstring[128] = '\0';

    uint8_t hash_1[64];
    if (param_gethex(hashstring, 0, hash_1, 128)) {
        PrintAndLogEx(FAILED, "Couldn't read SHA-512 file");
        free(firmware);
        return PM3_ESOFT;
    }

    uint8_t hash_2[64];
    if (sha512hash(firmware, firmware_size, hash_2)) {
        PrintAndLogEx(FAILED, "Couldn't calculate SHA-512 of firmware");
        free(firmware);
        return PM3_ESOFT;
    }

    if (memcmp(hash_1, hash_2, 64)) {
        PrintAndLogEx(FAILED, "Couldn't verify integrity of firmware file " _RED_("(wrong SHA-512 hash)"));
        free(firmware);
        return PM3_ESOFT;
    }
    
    PrintAndLogEx(SUCCESS, "Sim module firmware uploading to PM3");

    //Send to device
    uint32_t index = 0;
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining = firmware_size;

    // fast push mode
    conn.block_after_ACK = true;

    while (bytes_remaining > 0) {
        uint32_t bytes_in_packet = MIN(PM3_CMD_DATA_SIZE, bytes_remaining);
        if (bytes_in_packet == bytes_remaining) {
            // Disable fast mode on last packet
            conn.block_after_ACK = false;
        }
        clearCommandBuffer();
        SendCommandOLD(CMD_SMART_UPLOAD, index + bytes_sent, bytes_in_packet, 0, firmware + bytes_sent, bytes_in_packet);
        if (!WaitForResponseTimeout(CMD_ACK, NULL, 2000)) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            free(firmware);
            return PM3_ETIMEOUT;
        }

        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;
        PrintAndLogEx(INPLACE, "%d bytes sent", bytes_sent);
    }
    free(firmware);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Sim module firmware updating,  don\'t turn off your PM3!");

    // trigger the firmware upgrade
    clearCommandBuffer();
    SendCommandMIX(CMD_SMART_UPGRADE, firmware_size, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }
    if ((resp.oldarg[0] & 0xFF)) {
        PrintAndLogEx(SUCCESS, "Sim module firmware upgrade " _GREEN_("successful"));
        PrintAndLogEx(HINT, "run " _YELLOW_("`hw status`") " to validate the fw version ");
    } else {
        PrintAndLogEx(FAILED, "Sim module firmware upgrade " _RED_("failed"));
    }
    return PM3_SUCCESS;
}

static int CmdSmartInfo(const char *Cmd) {
    uint8_t cmdp = 0;
    bool errors = false, silent = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_sm_info();
            case 's':
                silent = true;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
        cmdp++;
    }

    //Validations
    if (errors) return usage_sm_info();

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_ATR, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        if (!silent) PrintAndLogEx(WARNING, "smart card select failed");
        return PM3_ETIMEOUT;
    }

    uint8_t isok = resp.oldarg[0] & 0xFF;
    if (!isok) {
        if (!silent) PrintAndLogEx(WARNING, "smart card select failed");
        return PM3_ESOFT;
    }

    smart_card_atr_t card;
    memcpy(&card, (smart_card_atr_t *)resp.data.asBytes, sizeof(smart_card_atr_t));

    // print header
    PrintAndLogEx(INFO, "--- Smartcard Information ---------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(INFO, "ISO7618-3 ATR : %s", sprint_hex(card.atr, card.atr_len));
    PrintAndLogEx(INFO, "http://smartcard-atr.apdu.fr/parse?ATR=%s", sprint_hex_inrow(card.atr, card.atr_len));

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
    uint8_t cmdp = 0;
    bool errors = false, silent = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_sm_reader();
            case 's':
                silent = true;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
        cmdp++;
    }

    //Validations
    if (errors) return usage_sm_reader();

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_ATR, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        if (!silent) PrintAndLogEx(WARNING, "smart card select failed");
        return PM3_ETIMEOUT;
    }

    uint8_t isok = resp.oldarg[0] & 0xFF;
    if (!isok) {
        if (!silent) PrintAndLogEx(WARNING, "smart card select failed");
        return PM3_ESOFT;
    }
    smart_card_atr_t card;
    memcpy(&card, (smart_card_atr_t *)resp.data.asBytes, sizeof(smart_card_atr_t));

    PrintAndLogEx(INFO, "ISO7816-3 ATR : %s", sprint_hex(card.atr, card.atr_len));
    return PM3_SUCCESS;
}

static int CmdSmartSetClock(const char *Cmd) {
    uint8_t cmdp = 0;
    bool errors = false;
    uint8_t clock1 = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_sm_setclock();
            case 'c':
                clock1 = param_get8ex(Cmd, cmdp + 1, 2, 10);
                if (clock1 > 2)
                    errors = true;

                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors || cmdp == 0) return usage_sm_setclock();

    clearCommandBuffer();
    SendCommandMIX(CMD_SMART_SETCLOCK, clock1, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        PrintAndLogEx(WARNING, "smart card select failed");
        return PM3_ETIMEOUT;
    }

    uint8_t isok = resp.oldarg[0] & 0xFF;
    if (!isok) {
        PrintAndLogEx(WARNING, "smart card set clock failed");
        return PM3_ESOFT;
    }

    switch (clock1) {
        case 0:
            PrintAndLogEx(SUCCESS, "Clock changed to 16MHz giving 10800 baudrate");
            break;
        case 1:
            PrintAndLogEx(SUCCESS, "Clock changed to 8MHz giving 21600 baudrate");
            break;
        case 2:
            PrintAndLogEx(SUCCESS, "Clock changed to 4MHz giving 86400 baudrate");
            break;
        default:
            break;
    }
    return PM3_SUCCESS;
}

static int CmdSmartList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdTraceList("7816");
    return PM3_SUCCESS;
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

        clearCommandBuffer();
        SendCommandMIX(CMD_SMART_RAW, SC_RAW_T0, 5, 0, get_card_data + i, 5);

        int len = smart_responseEx(buf, true);

        if (len > 2) {
            // if ( decodeTLV ) {
            // if (!TLVPrintFromBuffer(buf, len-2)) {
            PrintAndLogEx(SUCCESS, "\tHEX  %d |: %s", len, sprint_hex(buf, len));
            // }
            // }
        }
    }
    free(buf);
}

static int smart_brute_sfi(bool decodeTLV) {

    uint8_t *buf = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    if (!buf)
        return 1;

    int len;
    // READ RECORD
    uint8_t READ_RECORD[] = {0x00, 0xB2, 0x00, 0x00, 0x00};
    PrintAndLogEx(INFO, "Start SFI brute forcing");

    for (uint8_t sfi = 1; sfi <= 31; sfi++) {

        printf(".");
        fflush(stdout);

        for (uint16_t rec = 1; rec <= 255; rec++) {

            if (kbd_enter_pressed()) {
                PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
                free(buf);
                return 1;
            }

            READ_RECORD[2] = rec;
            READ_RECORD[3] = (sfi << 3) | 4;

            clearCommandBuffer();
            SendCommandMIX(CMD_SMART_RAW, SC_RAW_T0, sizeof(READ_RECORD), 0, READ_RECORD, sizeof(READ_RECORD));

            len = smart_responseEx(buf, true);

            if (buf[0] == 0x6C) {
                READ_RECORD[4] = buf[1];

                clearCommandBuffer();
                SendCommandMIX(CMD_SMART_RAW, SC_RAW_T0, sizeof(READ_RECORD), 0, READ_RECORD, sizeof(READ_RECORD));
                len = smart_responseEx(buf, true);

                READ_RECORD[4] = 0;
            }

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

    uint8_t GET_PROCESSING_OPTIONS[] = {0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00};

    // Get processing options command
    clearCommandBuffer();
    SendCommandMIX(CMD_SMART_RAW, SC_RAW_T0, sizeof(GET_PROCESSING_OPTIONS), 0, GET_PROCESSING_OPTIONS, sizeof(GET_PROCESSING_OPTIONS));

    int len = smart_responseEx(buf, true);
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

    uint8_t cmdp = 0;
    bool errors = false, decodeTLV = false; //, useT0 = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_sm_brute();
            case 't':
                decodeTLV = true;
                cmdp++;
                break;
            /*
                    case '0':
                        useT0 = true;
                        cmdp++;
                        break;
            */
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors) return usage_sm_brute();

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

        printf("+");
        fflush(stdout);

        if (caid)
            free(caid);

        json_t *data, *jaid;

        data = json_array_get(root, i);
        if (!json_is_object(data)) {
            PrintAndLogEx(ERR, "data %d is not an object\n", i + 1);
            json_decref(root);
            return PM3_ESOFT;
        }

        jaid = json_object_get(data, "AID");
        if (!json_is_string(jaid)) {
            PrintAndLogEx(ERR, "AID data [%d] is not a string", i + 1);
            json_decref(root);
            return PM3_ESOFT;
        }

        const char *aid = json_string_value(jaid);
        if (!aid)
            continue;

        size_t aidlen = strlen(aid);
        caid = calloc(8 + 2 + aidlen + 1, sizeof(uint8_t));
        snprintf(caid, 8 + 2 + aidlen + 1, SELECT, aidlen >> 1, aid);

        int hexlen = 0;
        uint8_t cmddata[PM3_CMD_DATA_SIZE];
        int res = param_gethex_to_eol(caid, 0, cmddata, sizeof(cmddata), &hexlen);
        if (res)
            continue;

        clearCommandBuffer();
        SendCommandOLD(CMD_SMART_RAW, SC_RAW_T0, hexlen, 0, cmddata, hexlen);

        int len = smart_responseEx(buf, true);
        if (len < 3)
            continue;

        json_t *jvendor, *jname;
        jvendor = json_object_get(data, "Vendor");
        if (!json_is_string(jvendor)) {
            PrintAndLogEx(ERR, "Vendor data [%d] is not a string", i + 1);
            continue;
        }

        const char *vendor = json_string_value(jvendor);
        if (!vendor)
            continue;

        jname = json_object_get(data, "Name");
        if (!json_is_string(jname)) {
            PrintAndLogEx(ERR, "Name data [%d] is not a string", i + 1);
            continue;
        }
        const char *name = json_string_value(jname);
        if (!name)
            continue;

        PrintAndLogEx(SUCCESS, "\nAID %s | %s | %s", aid, vendor, name);

        smart_brute_options(decodeTLV);

        smart_brute_prim();

        smart_brute_sfi(decodeTLV);

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
    {"list",     CmdSmartList,          IfPm3Smartcard,  "List ISO 7816 history"},
    {"info",     CmdSmartInfo,          IfPm3Smartcard,  "Tag information"},
    {"reader",   CmdSmartReader,        IfPm3Smartcard,  "Act like an IS07816 reader"},
    {"raw",      CmdSmartRaw,           IfPm3Smartcard,  "Send raw hex data to tag"},
    {"upgrade",  CmdSmartUpgrade,       AlwaysAvailable,  "Upgrade sim module firmware"},
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

int ExchangeAPDUSC(bool silent, uint8_t *datain, int datainlen, bool activateCard, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {

    *dataoutlen = 0;

    if (activateCard)
        smart_select(true, NULL);

    PrintAndLogEx(DEBUG, "APDU SC");

    uint8_t flags = SC_RAW_T0;
    if (activateCard) {
        flags |= SC_SELECT | SC_CONNECT;
    }

    clearCommandBuffer();
    SendCommandOLD(CMD_SMART_RAW, flags, datainlen, 0, datain, datainlen);

    int len = smart_responseEx(dataout, silent);
    if (len < 0) {
        return 1;
    }

    // retry
    if (len > 1 && dataout[len - 2] == 0x6c && datainlen > 4) {
        uint8_t data [5];
        memcpy(data, datain, 5);

        // transfer length via T=0
        data[4] = dataout[len - 1];

        clearCommandBuffer();
        // something fishy: we have only 5 bytes but we put datainlen in arg1?
        SendCommandMIX(CMD_SMART_RAW, SC_RAW_T0, datainlen, 0, data, sizeof(data));

        len = smart_responseEx(dataout, silent);
    }

    *dataoutlen = len;
    return 0;
}

bool smart_select(bool silent, smart_card_atr_t *atr) {
    if (atr)
        memset(atr, 0, sizeof(smart_card_atr_t));

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_ATR, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {

        if (!silent) PrintAndLogEx(WARNING, "smart card select failed");
        return false;
    }

    uint8_t isok = resp.oldarg[0] & 0xFF;
    if (!isok) {
        if (!silent) PrintAndLogEx(WARNING, "smart card select failed");
        return false;
    }

    smart_card_atr_t card;
    memcpy(&card, (smart_card_atr_t *)resp.data.asBytes, sizeof(smart_card_atr_t));

    if (atr)
        memcpy(atr, &card, sizeof(smart_card_atr_t));

    if (!silent)
        PrintAndLogEx(INFO, "ISO7816-3 ATR : %s", sprint_hex(card.atr, card.atr_len));

    return true;
}

