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
#include "../emv/emvjson.h"

static int CmdHelp(const char *Cmd);

int usage_sm_raw(void) {
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

    return 0;
}
int usage_sm_reader(void) {
    PrintAndLogEx(NORMAL, "Usage: sc reader [h|s]");
    PrintAndLogEx(NORMAL, "       h          :  this help");
    PrintAndLogEx(NORMAL, "       s          :  silent (no messages)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        sc reader");
    return 0;
}
int usage_sm_info(void) {
    PrintAndLogEx(NORMAL, "Usage: s info [h|s]");
    PrintAndLogEx(NORMAL, "       h          :  this help");
    PrintAndLogEx(NORMAL, "       s          :  silent (no messages)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        sc info");
    return 0;
}
int usage_sm_upgrade(void) {
    PrintAndLogEx(NORMAL, "Upgrade RDV4.0 Sim module firmware");
    PrintAndLogEx(NORMAL, "Usage:  sc upgrade f <file name>");
    PrintAndLogEx(NORMAL, "       h               :  this help");
    PrintAndLogEx(NORMAL, "       f <filename>    :  firmware file name");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        sc upgrade f ../tools/simmodule/SIM011.BIN");
    return 0;
}
int usage_sm_setclock(void) {
    PrintAndLogEx(NORMAL, "Usage: sc setclock [h] c <clockspeed>");
    PrintAndLogEx(NORMAL, "       h          :  this help");
    PrintAndLogEx(NORMAL, "       c <>       :  clockspeed (0 = 16mhz, 1=8mhz, 2=4mhz) ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        sc setclock c 2");
    return 0;
}
int usage_sm_brute(void) {
    PrintAndLogEx(NORMAL, "Tries to bruteforce SFI, using a known list of AID's ");
    PrintAndLogEx(NORMAL, "Usage: sc brute [h]");
    PrintAndLogEx(NORMAL, "       h          :  this help");
    PrintAndLogEx(NORMAL, "       t          :  executes TLV decoder if it possible");
//  PrintAndLogEx(NORMAL, "       0          :  use protocol T=0");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        sc brute t");
    return 0;
}

static int smart_loadjson(const char *preferredName, const char *suffix, json_t **root) {

    json_error_t error;

    if (preferredName == NULL) return 1;
    if (suffix == NULL) return 1;

    int retval = 0;
    int size = sizeof(char) * (strlen(get_my_executable_directory()) + strlen(preferredName) + strlen(suffix) + 10);
    char *fileName = calloc(size, sizeof(char));
    sprintf(fileName, "%s%s.%s", get_my_executable_directory(), preferredName, suffix);
    *root = json_load_file(fileName, 0, &error);
    if (!*root) {
        PrintAndLogEx(ERR, "json (%s) error on line %d: %s", fileName, error.line, error.text);
        retval = 2;
        goto out;
    }

    if (!json_is_array(*root)) {
        PrintAndLogEx(ERR, "Invalid json (%s) format. root must be an array.", fileName);
        retval = 3;
        goto out;
    }

    PrintAndLogEx(SUCCESS, "Loaded file (%s) OK.", fileName);
out:
    free(fileName);
    return retval;
}

uint8_t GetATRTA1(uint8_t *atr, size_t atrlen) {
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

int GetATRDi(uint8_t *atr, size_t atrlen) {
    uint8_t TA1 = GetATRTA1(atr, atrlen);
    return DiArray[TA1 & 0x0F];  // The 4 low-order bits of TA1 (4th MSbit to 1st LSbit) encode Di
}

int GetATRFi(uint8_t *atr, size_t atrlen) {
    uint8_t TA1 = GetATRTA1(atr, atrlen);
    return FiArray[TA1 >> 4];  // The 4 high-order bits of TA1 (8th MSbit to 5th LSbit) encode fmax and Fi
}

float GetATRF(uint8_t *atr, size_t atrlen) {
    uint8_t TA1 = GetATRTA1(atr, atrlen);
    return FArray[TA1 >> 4];  // The 4 high-order bits of TA1 (8th MSbit to 5th LSbit) encode fmax and Fi
}

static int PrintATR(uint8_t *atr, size_t atrlen) {

    uint8_t T0 = atr[1];
    uint8_t K = T0 & 0x0F;
    uint8_t TD1 = 0, T1len = 0, TD1len = 0, TDilen = 0;
    bool protocol_T0_present = true;
    bool protocol_T15_present = false;

    if (T0 & 0x10) {
        PrintAndLog("\t- TA1 (Maximum clock frequency, proposed bit duration) [ 0x%02x ]", atr[2 + T1len]);
        T1len++;
    }

    if (T0 & 0x20) {
        PrintAndLog("\t- TB1 (Deprecated: VPP requirements) [ 0x%02x ]", atr[2 + T1len]);
        T1len++;
    }

    if (T0 & 0x40) {
        PrintAndLog("\t- TC1 (Extra delay between bytes required by card) [ 0x%02x ]", atr[2 + T1len]);
        T1len++;
    }

    if (T0 & 0x80) {
        TD1 = atr[2 + T1len];
        PrintAndLog("\t- TD1 (First offered transmission protocol, presence of TA2..TD2) [ 0x%02x ] Protocol T%d", TD1, TD1 & 0x0f);
        protocol_T0_present = false;
        if ((TD1 & 0x0f) == 0) {
            protocol_T0_present = true;
        }
        if ((TD1 & 0x0f) == 15) {
            protocol_T15_present = true;
        }

        T1len++;

        if (TD1 & 0x10) {
            PrintAndLog("\t- TA2 (Specific protocol and parameters to be used after the ATR) [ 0x%02x ]", atr[2 + T1len + TD1len]);
            TD1len++;
        }
        if (TD1 & 0x20) {
            PrintAndLog("\t- TB2 (Deprecated: VPP precise voltage requirement) [ 0x%02x ]", atr[2 + T1len + TD1len]);
            TD1len++;
        }
        if (TD1 & 0x40) {
            PrintAndLog("\t- TC2 (Maximum waiting time for protocol T=0) [ 0x%02x ]", atr[2 + T1len + TD1len]);
            TD1len++;
        }
        if (TD1 & 0x80) {
            uint8_t TDi = atr[2 + T1len + TD1len];
            PrintAndLog("\t- TD2 (A supported protocol or more global parameters, presence of TA3..TD3) [ 0x%02x ] Protocol T%d", TDi, TDi & 0x0f);
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
                    PrintAndLog("\t- TA%d: 0x%02x", vi, atr[2 + T1len + TD1len + TDilen]);
                    TDilen++;
                }
                if (TDi & 0x20) {
                    PrintAndLog("\t- TB%d: 0x%02x", vi, atr[2 + T1len + TD1len + TDilen]);
                    TDilen++;
                }
                if (TDi & 0x40) {
                    PrintAndLog("\t- TC%d: 0x%02x", vi, atr[2 + T1len + TD1len + TDilen]);
                    TDilen++;
                }
                if (TDi & 0x80) {
                    TDi = atr[2 + T1len + TD1len + TDilen];
                    PrintAndLog("\t- TD%d [ 0x%02x ] Protocol T%d", vi, TDi, TDi & 0x0f);
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
            PrintAndLogEx(WARNING, "Check sum error. Must be 0 got 0x%02X", vxor);
        else
            PrintAndLogEx(INFO, "Check sum OK.");
    }

    if (atr[0] != 0x3b)
        PrintAndLogEx(WARNING, "Not a direct convention [ 0x%02x ]", atr[0]);

    uint8_t calen = 2 + T1len + TD1len + TDilen + K;

    if (atrlen != calen && atrlen != calen + 1)  // may be CRC
        PrintAndLogEx(ERR, "ATR length error. len: %d, T1len: %d, TD1len: %d, TDilen: %d, K: %d", atrlen, T1len, TD1len, TDilen, K);

    if (K > 0)
        PrintAndLogEx(INFO, "\nHistorical bytes | len 0x%02d | format %02x", K, atr[2 + T1len + TD1len + TDilen]);

    if (K > 1) {
        PrintAndLogEx(INFO, "\tHistorical bytes");
        dump_buffer(&atr[2 + T1len + TD1len + TDilen], K, NULL, 1);
    }

    return 0;
}

bool smart_select(bool silent, smart_card_atr_t *atr) {
    if (atr)
        memset(atr, 0, sizeof(smart_card_atr_t));

    UsbCommand c = {CMD_SMART_ATR, {0, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        if (!silent) PrintAndLogEx(WARNING, "smart card select failed");
        return false;
    }

    uint8_t isok = resp.arg[0] & 0xFF;
    if (!isok) {
        if (!silent) PrintAndLogEx(WARNING, "smart card select failed");
        return false;
    }

    smart_card_atr_t card;
    memcpy(&card, (smart_card_atr_t *)resp.d.asBytes, sizeof(smart_card_atr_t));

    if (atr)
        memcpy(atr, &card, sizeof(smart_card_atr_t));

    if (!silent)
        PrintAndLogEx(INFO, "ISO7816-3 ATR : %s", sprint_hex(card.atr, card.atr_len));

    return true;
}

static int smart_wait(uint8_t *data, bool silent) {
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        if (!silent) PrintAndLogEx(WARNING, "smart card response timeout");
        return -1;
    }

    uint32_t len = resp.arg[0];
    if (!len) {
        if (!silent) PrintAndLogEx(WARNING, "smart card response failed");
        return -2;
    }
    memcpy(data, resp.d.asBytes, len);
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
        UsbCommand cStatus = {CMD_SMART_RAW, {SC_RAW, sizeof(getstatus), 0}};
        memcpy(cStatus.d.asBytes, getstatus, sizeof(getstatus));
        clearCommandBuffer();
        SendCommand(&cStatus);

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

int CmdSmartRaw(const char *Cmd) {

    int hexlen = 0;
    bool active = false;
    bool active_select = false;
    bool useT0 = false;
    uint8_t cmdp = 0;
    bool errors = false, reply = true, decodeTLV = false, breakloop = false;
    uint8_t data[USB_CMD_DATA_SIZE] = {0x00};

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
                        return 1;
                    case 2:
                        PrintAndLogEx(WARNING, "Too many bytes.  Max %d bytes", sizeof(data));
                        return 1;
                    case 3:
                        PrintAndLogEx(WARNING, "Hex must have even number of digits.");
                        return 1;
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

    // arg0 = RFU flags
    // arg1 = length
    UsbCommand c = {CMD_SMART_RAW, {0, hexlen, 0}};

    if (active || active_select) {
        c.arg[0] |= SC_CONNECT;
        if (active_select)
            c.arg[0] |= SC_SELECT;
    }

    if (hexlen > 0) {
        if (useT0)
            c.arg[0] |= SC_RAW_T0;
        else
            c.arg[0] |= SC_RAW;
    }

    memcpy(c.d.asBytes, data, hexlen);
    clearCommandBuffer();
    SendCommand(&c);

    // reading response from smart card
    if (reply) {

        uint8_t *buf = calloc(USB_CMD_DATA_SIZE, sizeof(uint8_t));
        if (!buf)
            return 1;

        int len = smart_response(buf);
        if (len < 0) {
            free(buf);
            return 2;
        }

        if (buf[0] == 0x6C) {
            data[4] = buf[1];

            memcpy(c.d.asBytes, data, sizeof(data));
            clearCommandBuffer();
            SendCommand(&c);
            len = smart_response(buf);

            data[4] = 0;
        }

        if (decodeTLV && len > 4)
            TLVPrintFromBuffer(buf, len - 2);

        free(buf);
    }
    return 0;
}

int ExchangeAPDUSC(uint8_t *datain, int datainlen, bool activateCard, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    *dataoutlen = 0;

    if (activateCard)
        smart_select(false, NULL);

    PrintAndLogEx(DEBUG, "APDU SC");

    UsbCommand c = {CMD_SMART_RAW, {SC_RAW_T0, datainlen, 0}};
    if (activateCard) {
        c.arg[0] |= SC_SELECT | SC_CONNECT;
    }
    memcpy(c.d.asBytes, datain, datainlen);
    clearCommandBuffer();
    SendCommand(&c);

    int len = smart_responseEx(dataout, true);

    if (len < 0) {
        return 1;
    }

    // retry
    if (len > 1 && dataout[len - 2] == 0x6c && datainlen > 4) {
        UsbCommand c2 = {CMD_SMART_RAW, {SC_RAW_T0, datainlen, 0}};
        memcpy(c2.d.asBytes, datain, 5);

        // transfer length via T=0
        c2.d.asBytes[4] = dataout[len - 1];

        clearCommandBuffer();
        SendCommand(&c2);

        len = smart_responseEx(dataout, true);
    }

    *dataoutlen = len;
    return 0;
}

int CmdSmartUpgrade(const char *Cmd) {

    PrintAndLogEx(WARNING, "WARNING - Sim module firmware upgrade.");
    PrintAndLogEx(WARNING, "A dangerous command, do wrong and you could brick the sim module");
    PrintAndLogEx(NORMAL, "");

    FILE *f;
    char filename[FILE_PATH_SIZE] = {0};
    uint8_t cmdp = 0;
    bool errors = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'f':
                //File handling and reading
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


    char sha512filename[FILE_PATH_SIZE] = {'\0'};
    char *bin_extension = filename;
    char *dot_position = NULL;
    while ((dot_position = strchr(bin_extension, '.')) != NULL) {
        bin_extension = dot_position + 1;
    }

    if (!strcmp(bin_extension, "BIN")
#ifdef _WIN32
            || !strcmp(bin_extension, "bin")
#endif
       ) {
        memcpy(sha512filename, filename, strlen(filename) - strlen("bin"));
        strcat(sha512filename, "sha512.txt");
    } else {
        PrintAndLogEx(FAILED, "Filename extension of firmware upgrade file must be .BIN");
        return 1;
    }

    PrintAndLogEx(INFO, "firmware file      : " _YELLOW_("%s"), filename);
    PrintAndLogEx(INFO, "Checking integrity : " _YELLOW_("%s"), sha512filename);

    // load firmware file
    f = fopen(filename, "rb");
    if (!f) {
        PrintAndLogEx(FAILED, "Firmware file " _YELLOW_("%s") " not found or locked.", filename);
        return 1;
    }

    // get filesize in order to malloc memory
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 0) {
        PrintAndLogEx(WARNING, "error, when getting filesize");
        fclose(f);
        return 1;
    }

    uint8_t *dump = calloc(fsize, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(WARNING, "error, cannot allocate memory ");
        fclose(f);
        return 1;
    }

    size_t firmware_size = fread(dump, 1, fsize, f);
    if (f) {
        fclose(f);
    }

    // load sha512 file
    f = fopen(sha512filename, "rb");
    if (!f) {
        PrintAndLogEx(FAILED, "SHA-512 file not found or locked.");
        free(dump);
        return 1;
    }

    // get filesize in order to malloc memory
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 0)  {
        PrintAndLogEx(FAILED, "Could not determine size of SHA-512 file");
        fclose(f);
        free(dump);
        return 1;
    }

    if (fsize < 128) {
        PrintAndLogEx(FAILED, "SHA-512 file too short");
        fclose(f);
        free(dump);
        return 1;
    }

    char hashstring[129];
    size_t bytes_read = fread(hashstring, 1, 128, f);
    hashstring[128] = '\0';

    if (f)
        fclose(f);

    uint8_t hash1[64];
    if (bytes_read != 128 || param_gethex(hashstring, 0, hash1, 128)) {
        PrintAndLogEx(FAILED, "Couldn't read SHA-512 file");
        free(dump);
        return 1;
    }

    uint8_t hash2[64];
    if (sha512hash(dump, firmware_size, hash2)) {
        PrintAndLogEx(FAILED, "Couldn't calculate SHA-512 of firmware");
        free(dump);
        return 1;
    }

    if (memcmp(hash1, hash2, 64)) {
        PrintAndLogEx(FAILED, "Couldn't verify integrity of firmware file " _RED_("(wrong SHA-512 hash)"));
        free(dump);
        return 1;
    }

    PrintAndLogEx(SUCCESS, "Sim module firmware uploading to PM3");

    //Send to device
    uint32_t index = 0;
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining = firmware_size;

    while (bytes_remaining > 0) {
        uint32_t bytes_in_packet = MIN(USB_CMD_DATA_SIZE, bytes_remaining);
        UsbCommand c = {CMD_SMART_UPLOAD, {index + bytes_sent, bytes_in_packet, 0}};

        // Fill usb bytes with 0xFF
        memset(c.d.asBytes, 0xFF, USB_CMD_DATA_SIZE);
        memcpy(c.d.asBytes, dump + bytes_sent, bytes_in_packet);
        clearCommandBuffer();
        SendCommand(&c);
        if (!WaitForResponseTimeout(CMD_ACK, NULL, 2000)) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            free(dump);
            return 1;
        }

        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;
        printf(".");
        fflush(stdout);
    }
    free(dump);
    printf("\n");
    PrintAndLogEx(SUCCESS, "Sim module firmware updating,  don\'t turn off your PM3!");

    // trigger the firmware upgrade
    UsbCommand c = {CMD_SMART_UPGRADE, {firmware_size, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return 1;
    }
    if ((resp.arg[0] & 0xFF)) {
        PrintAndLogEx(SUCCESS, "Sim module firmware upgrade " _GREEN_("successful"));
        PrintAndLogEx(SUCCESS, "\n run " _YELLOW_("`hw status`") " to validate the fw version ");
    } else {
        PrintAndLogEx(FAILED, "Sim module firmware upgrade " _RED_("failed"));
    }
    return 0;
}

int CmdSmartInfo(const char *Cmd) {
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

    UsbCommand c = {CMD_SMART_ATR, {0, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        if (!silent) PrintAndLogEx(WARNING, "smart card select failed");
        return 1;
    }

    uint8_t isok = resp.arg[0] & 0xFF;
    if (!isok) {
        if (!silent) PrintAndLogEx(WARNING, "smart card select failed");
        return 1;
    }

    smart_card_atr_t card;
    memcpy(&card, (smart_card_atr_t *)resp.d.asBytes, sizeof(smart_card_atr_t));

    // print header
    PrintAndLogEx(INFO, "--- Smartcard Information ---------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(INFO, "ISO7618-3 ATR : %s", sprint_hex(card.atr, card.atr_len));
    PrintAndLogEx(INFO, "\nhttp://smartcard-atr.appspot.com/parse?ATR=%s", sprint_hex_inrow(card.atr, card.atr_len));

    // print ATR
    PrintAndLogEx(NORMAL, "");
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

    PrintAndLogEx(NORMAL, "\t- Di %d", Di);
    PrintAndLogEx(NORMAL, "\t- Fi %d", Fi);
    PrintAndLogEx(NORMAL, "\t- F  %.1f MHz", F);

    if (Di && Fi) {
        PrintAndLogEx(NORMAL, "\t- Cycles/ETU %d", Fi / Di);
        PrintAndLogEx(NORMAL, "\t- %.1f bits/sec at 4MHz", (float)4000000 / (Fi / Di));
        PrintAndLogEx(NORMAL, "\t- %.1f bits/sec at Fmax (%.1fMHz)", (F * 1000000) / (Fi / Di), F);
    } else {
        PrintAndLogEx(WARNING, "\t- Di or Fi is RFU.");
    };

    return 0;
}

int CmdSmartReader(const char *Cmd) {
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

    UsbCommand c = {CMD_SMART_ATR, {0, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        if (!silent) PrintAndLogEx(WARNING, "smart card select failed");
        return 1;
    }

    uint8_t isok = resp.arg[0] & 0xFF;
    if (!isok) {
        if (!silent) PrintAndLogEx(WARNING, "smart card select failed");
        return 1;
    }
    smart_card_atr_t card;
    memcpy(&card, (smart_card_atr_t *)resp.d.asBytes, sizeof(smart_card_atr_t));

    PrintAndLogEx(INFO, "ISO7816-3 ATR : %s", sprint_hex(card.atr, card.atr_len));
    return 0;
}

int CmdSmartSetClock(const char *Cmd) {
    uint8_t cmdp = 0;
    bool errors = false;
    uint8_t clock = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_sm_setclock();
            case 'c':
                clock = param_get8ex(Cmd, cmdp + 1, 2, 10);
                if (clock > 2)
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

    UsbCommand c = {CMD_SMART_SETCLOCK, {clock, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        PrintAndLogEx(WARNING, "smart card select failed");
        return 1;
    }

    uint8_t isok = resp.arg[0] & 0xFF;
    if (!isok) {
        PrintAndLogEx(WARNING, "smart card set clock failed");
        return 1;
    }

    switch (clock) {
        case 0:
            PrintAndLogEx(SUCCESS, "Clock changed to 16mhz giving 10800 baudrate");
            break;
        case 1:
            PrintAndLogEx(SUCCESS, "Clock changed to 8mhz giving 21600 baudrate");
            break;
        case 2:
            PrintAndLogEx(SUCCESS, "Clock changed to 4mhz giving 86400 baudrate");
            break;
        default:
            break;
    }
    return 0;
}

int CmdSmartList(const char *Cmd) {
    CmdTraceList("7816");
    return 0;
}

static void smart_brute_prim() {

    uint8_t *buf = calloc(USB_CMD_DATA_SIZE, sizeof(uint8_t));
    if (!buf)
        return;

    int len = 0;
    uint8_t get_card_data[] = {
        0x80, 0xCA, 0x9F, 0x13, 0x00,
        0x80, 0xCA, 0x9F, 0x17, 0x00,
        0x80, 0xCA, 0x9F, 0x36, 0x00,
        0x80, 0xCA, 0x9F, 0x4f, 0x00
    };

    UsbCommand c = {CMD_SMART_RAW, {SC_RAW_T0, 5, 0}};

    PrintAndLogEx(INFO, "Reading primitives");

    for (int i = 0; i < sizeof(get_card_data); i += 5) {

        memcpy(c.d.asBytes, get_card_data + i, 5);
        clearCommandBuffer();
        SendCommand(&c);

        len = smart_responseEx(buf, true);

        if (len > 2) {

            // if ( decodeTLV ) {
            // if (!TLVPrintFromBuffer(buf, len-2)) {
            PrintAndLogEx(SUCCESS, "\tHEX  %d |: %s", len, sprint_hex(buf, len));
            // }
            // }
        }
        len = 0;
    }
    free(buf);
}

static int smart_brute_sfi(bool decodeTLV) {

    uint8_t *buf = calloc(USB_CMD_DATA_SIZE, sizeof(uint8_t));
    if (!buf)
        return 1;

    int len = 0;
    // READ RECORD
    uint8_t READ_RECORD[] = {0x00, 0xB2, 0x00, 0x00, 0x00};
    UsbCommand c = {CMD_SMART_RAW, {SC_RAW_T0, sizeof(READ_RECORD), 0}};

    PrintAndLogEx(INFO, "Start SFI brute forcing");

    for (uint8_t sfi = 1; sfi <= 31; sfi++) {

        printf(".");
        fflush(stdout);

        for (uint16_t rec = 1; rec <= 255; rec++) {

            if (ukbhit()) {
                int gc = getchar();
                (void)gc;
                PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
                free(buf);
                return 1;
            }

            READ_RECORD[2] = rec;
            READ_RECORD[3] = (sfi << 3) | 4;

            memcpy(c.d.asBytes, READ_RECORD, sizeof(READ_RECORD));
            clearCommandBuffer();
            SendCommand(&c);

            len = smart_responseEx(buf, true);

            if (buf[0] == 0x6C) {
                READ_RECORD[4] = buf[1];

                memcpy(c.d.asBytes, READ_RECORD, sizeof(READ_RECORD));
                clearCommandBuffer();
                SendCommand(&c);
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
            memset(buf, 0x00, USB_CMD_DATA_SIZE);
        }
    }
    free(buf);
    return 0;
}

static void smart_brute_options(bool decodeTLV) {

    uint8_t *buf = calloc(USB_CMD_DATA_SIZE, sizeof(uint8_t));
    if (!buf)
        return;

    uint8_t GET_PROCESSING_OPTIONS[] = {0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00};

    // Get processing options command
    UsbCommand c = {CMD_SMART_RAW, {SC_RAW_T0, sizeof(GET_PROCESSING_OPTIONS), 0}};
    memcpy(c.d.asBytes, GET_PROCESSING_OPTIONS, sizeof(GET_PROCESSING_OPTIONS));
    clearCommandBuffer();
    SendCommand(&c);

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

int CmdSmartBruteforceSFI(const char *Cmd) {

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

    const char *SELECT = "00a40400%02x%s";

//  uint8_t GENERATE_AC[] = {0x80, 0xAE};
//  uint8_t GET_CHALLENGE[] = {0x00, 0x84, 0x00};
//  uint8_t GET_DATA[] = {0x80, 0xCA, 0x00, 0x00, 0x00};
//  uint8_t SELECT[] = {0x00, 0xA4, 0x04, 0x00};
//  uint8_t UNBLOCK_PIN[] = {0x84, 0x24, 0x00, 0x00, 0x00};
//  uint8_t VERIFY[] = {0x00, 0x20, 0x00, 0x80};

    // Select AID command
    UsbCommand cAid = {CMD_SMART_RAW, {SC_RAW_T0, 0, 0}};

    PrintAndLogEx(INFO, "Importing AID list");
    json_t *root = NULL;
    smart_loadjson("aidlist", "json", &root);

    uint8_t *buf = calloc(USB_CMD_DATA_SIZE, sizeof(uint8_t));
    if (!buf)
        return 1;

    PrintAndLogEx(INFO, "Selecting card");
    if (!smart_select(false, NULL)) {
        free(buf);
        return 1;
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
            return 1;
        }

        jaid = json_object_get(data, "AID");
        if (!json_is_string(jaid)) {
            PrintAndLogEx(ERR, "AID data [%d] is not a string", i + 1);
            json_decref(root);
            return 1;
        }

        const char *aid = json_string_value(jaid);
        if (!aid)
            continue;

        size_t aidlen = strlen(aid);
        caid = calloc(8 + 2 + aidlen + 1, sizeof(uint8_t));
        snprintf(caid, 8 + 2 + aidlen + 1, SELECT, aidlen >> 1, aid);

        int hexlen = 0;
        int res = param_gethex_to_eol(caid, 0, cAid.d.asBytes, sizeof(cAid.d.asBytes), &hexlen);
        if (res)
            continue;

        cAid.arg[1] = hexlen;

        clearCommandBuffer();
        SendCommand(&cAid);

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
    return 0;
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,               1, "This help"},
    {"list",     CmdSmartList,          0, "List ISO 7816 history"},
    {"info",     CmdSmartInfo,          1, "Tag information"},
    {"reader",   CmdSmartReader,        1, "Act like an IS07816 reader"},
    {"raw",      CmdSmartRaw,           1, "Send raw hex data to tag"},
    {"upgrade",  CmdSmartUpgrade,       1, "Upgrade sim module firmware"},
    {"setclock", CmdSmartSetClock,      1, "Set clock speed"},
    {"brute",    CmdSmartBruteforceSFI, 1, "Bruteforce SFI"},
    {NULL, NULL, 0, NULL}
};

int CmdSmartcard(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
