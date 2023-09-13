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
// High frequency MIFARE  Plus commands
//-----------------------------------------------------------------------------

#include "cmdhfmfp.h"
#include <string.h>
#include "cmdparser.h"    // command_t
#include "commonutil.h"  // ARRAYLEN
#include "comms.h"
#include "ui.h"
#include "util.h"
#include "cmdhf14a.h"
#include "mifare/mifare4.h"
#include "mifare/mad.h"
#include "nfc/ndef.h"
#include "cliparser.h"
#include "mifare/mifaredefault.h"
#include "util_posix.h"
#include "fileutils.h"
#include "protocols.h"
#include "crypto/libpcrypto.h"
#include "cmdhfmf.h"    // printblock, header
#include "cmdtrace.h"

static const uint8_t mfp_default_key[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint16_t mfp_card_adresses[] = {0x9000, 0x9001, 0x9002, 0x9003, 0x9004, 0xA000, 0xA001, 0xA080, 0xA081, 0xC000, 0xC001};

#define MFP_KEY_FILE_SIZE  14 + (2 * 64 * (AES_KEY_LEN + 1))

static int CmdHelp(const char *Cmd);

/*
  The 7 MSBits (= n) code the storage size itself based on 2^n,
  the LSBit is set to '0' if the size is exactly 2^n
    and set to '1' if the storage size is between 2^n and 2^(n+1).
    For this version of DESFire the 7 MSBits are set to 0x0C (2^12 = 4096) and the LSBit is '0'.
*/
static char *getCardSizeStr(uint8_t fsize) {

    static char buf[40] = {0x00};
    char *retStr = buf;

    uint16_t usize = 1 << ((fsize >> 1) + 1);
    uint16_t lsize = 1 << (fsize >> 1);

    // is  LSB set?
    if (fsize & 1)
        snprintf(retStr, sizeof(buf), "0x%02X ( " _GREEN_("%d - %d bytes") " )", fsize, usize, lsize);
    else
        snprintf(retStr, sizeof(buf), "0x%02X ( " _GREEN_("%d bytes") " )", fsize, lsize);
    return buf;
}

static char *getProtocolStr(uint8_t id, bool hw) {

    static char buf[50] = {0x00};
    char *retStr = buf;

    if (id == 0x04) {
        snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("ISO 14443-3 MIFARE, 14443-4") " )", id);
    } else if (id == 0x05) {
        if (hw)
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("ISO 14443-2, 14443-3") " )", id);
        else
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("ISO 14443-3, 14443-4") " )", id);
    } else {
        snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("Unknown") " )", id);
    }
    return buf;
}

static char *getVersionStr(uint8_t major, uint8_t minor) {

    static char buf[40] = {0x00};
    char *retStr = buf;

    if (major == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire MF3ICD40") " )", major, minor);
    else if (major == 0x01 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV1") " )", major, minor);
    else if (major == 0x12 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV2") " )", major, minor);
    else if (major == 0x33 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV3") " )", major, minor);
    else if (major == 0x30 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire Light") " )", major, minor);
    else if (major == 0x11 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("Plus EV1") " )", major, minor);
    else
        snprintf(retStr, sizeof(buf), "%x.%x ( " _YELLOW_("Unknown") " )", major, minor);
    return buf;
}

static char *getTypeStr(uint8_t type) {

    static char buf[40] = {0x00};
    char *retStr = buf;

    switch (type) {
        case 1:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("DESFire") " )", type);
            break;
        case 2:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("Plus") " )", type);
            break;
        case 3:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("Ultralight") " )", type);
            break;
        case 4:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("NTAG") " )", type);
            break;
        default:
            break;
    }
    return buf;
}

static nxp_cardtype_t getCardType(uint8_t major, uint8_t minor) {

    // DESFire MF3ICD40
    if (major == 0x00 &&  minor == 0x00)
        return DESFIRE_MF3ICD40;

    // DESFire EV1
    if (major == 0x01 &&  minor == 0x00)
        return DESFIRE_EV1;

    // DESFire EV2
    if (major == 0x12 &&  minor == 0x00)
        return DESFIRE_EV2;

    // DESFire EV3
    if (major == 0x33 &&  minor == 0x00)
        return DESFIRE_EV3;

    // DESFire Light
    if (major == 0x30 &&  minor == 0x00)
        return DESFIRE_LIGHT;

    // Plus EV1
    if (major == 0x11 &&  minor == 0x00)
        return PLUS_EV1;

    return MFP_UNKNOWN;
}

// --- GET SIGNATURE
static int plus_print_signature(uint8_t *uid, uint8_t uidlen, uint8_t *signature, int signature_len) {

    // ref:  MIFARE Plus EV1 Originality Signature Validation
#define PUBLIC_PLUS_ECDA_KEYLEN 57
    const ecdsa_publickey_t nxp_plus_public_keys[] = {
        {"MIFARE Plus EV1",  "044409ADC42F91A8394066BA83D872FB1D16803734E911170412DDF8BAD1A4DADFD0416291AFE1C748253925DA39A5F39A1C557FFACD34C62E"},
        {"MIFARE Plus Ev_x", "04BB49AE4447E6B1B6D21C098C1538B594A11A4A1DBF3D5E673DEACDEB3CC512D1C08AFA1A2768CE20A200BACD2DC7804CD7523A0131ABF607"},
        {"MIFARE Plus Troika", "040F732E0EA7DF2B38F791BF89425BF7DCDF3EE4D976669E3831F324FF15751BD52AFF1782F72FF2731EEAD5F63ABE7D126E03C856FFB942AF"}
    };

    uint8_t i;
    bool is_valid = false;

    for (i = 0; i < ARRAYLEN(nxp_plus_public_keys); i++) {

        int dl = 0;
        uint8_t key[PUBLIC_PLUS_ECDA_KEYLEN];
        param_gethex_to_eol(nxp_plus_public_keys[i].value, 0, key, PUBLIC_PLUS_ECDA_KEYLEN, &dl);

        int res = ecdsa_signature_r_s_verify(MBEDTLS_ECP_DP_SECP224R1, key, uid, uidlen, signature, signature_len, false);
        is_valid = (res == 0);
        if (is_valid)
            break;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Signature"));

    if (is_valid == false || i == ARRAYLEN(nxp_plus_public_keys)) {
        PrintAndLogEx(INFO, "    Elliptic curve parameters: NID_secp224r1");
        PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, 16));
        PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 16, 16));
        PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 32, 16));
        PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 48, signature_len - 48));
        PrintAndLogEx(SUCCESS, "       Signature verification: " _RED_("failed"));
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, " IC signature public key name: " _GREEN_("%s"), nxp_plus_public_keys[i].desc);
    PrintAndLogEx(INFO, "IC signature public key value: %.32s", nxp_plus_public_keys[i].value);
    PrintAndLogEx(INFO, "                             : %.32s", nxp_plus_public_keys[i].value + 32);
    PrintAndLogEx(INFO, "                             : %.32s", nxp_plus_public_keys[i].value + 64);
    PrintAndLogEx(INFO, "                             : %.32s", nxp_plus_public_keys[i].value + 96);
    PrintAndLogEx(INFO, "    Elliptic curve parameters: NID_secp224r1");
    PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, 16));
    PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 16, 16));
    PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 32, 16));
    PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 48, signature_len - 48));
    PrintAndLogEx(SUCCESS, "       Signature verification: " _GREEN_("successful"));
    return PM3_SUCCESS;
}

static int get_plus_signature(uint8_t *signature, int *signature_len) {

    mfpSetVerboseMode(false);

    uint8_t data[59] = {0};
    int resplen = 0, retval = PM3_SUCCESS;
    MFPGetSignature(true, false, data, sizeof(data), &resplen);

    if (resplen == 59) {
        memcpy(signature, data + 1, 56);
        *signature_len = 56;
    } else {
        *signature_len = 0;
        retval = PM3_ESOFT;
    }

    return retval;
}

// GET VERSION
static int plus_print_version(uint8_t *version) {
    PrintAndLogEx(SUCCESS, "              UID: " _GREEN_("%s"), sprint_hex(version + 14, 7));
    PrintAndLogEx(SUCCESS, "     Batch number: " _GREEN_("%s"), sprint_hex(version + 21, 5));
    PrintAndLogEx(SUCCESS, "  Production date: week " _GREEN_("%02x") " / " _GREEN_("20%02x"), version[7 + 7 + 7 + 5], version[7 + 7 + 7 + 5 + 1]);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Hardware Information"));
    PrintAndLogEx(INFO, "          Raw : %s", sprint_hex(version, 7));
    PrintAndLogEx(INFO, "     Vendor Id: " _YELLOW_("%s"), getTagInfo(version[0]));
    PrintAndLogEx(INFO, "          Type: %s", getTypeStr(version[1]));
    PrintAndLogEx(INFO, "       Subtype: " _YELLOW_("0x%02X"), version[2]);
    PrintAndLogEx(INFO, "       Version: %s", getVersionStr(version[3], version[4]));
    PrintAndLogEx(INFO, "  Storage size: %s", getCardSizeStr(version[5]));
    PrintAndLogEx(INFO, "      Protocol: %s", getProtocolStr(version[6], true));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Software Information"));
    PrintAndLogEx(INFO, "          Raw : %s", sprint_hex(version + 7, 6));
    PrintAndLogEx(INFO, "     Vendor Id: " _YELLOW_("%s"), getTagInfo(version[7]));
    PrintAndLogEx(INFO, "          Type: %s", getTypeStr(version[8]));
    PrintAndLogEx(INFO, "       Subtype: " _YELLOW_("0x%02X"), version[9]);
    PrintAndLogEx(INFO, "       Version: " _YELLOW_("%d.%d"),  version[10], version[11]);
    PrintAndLogEx(INFO, "  Storage size: %s", getCardSizeStr(version[12]));
    PrintAndLogEx(INFO, "      Protocol: %s", getProtocolStr(version[13], false));
    return PM3_SUCCESS;
}

static int get_plus_version(uint8_t *version, int *version_len) {

    int resplen = 0, retval = PM3_SUCCESS;
    mfpSetVerboseMode(false);
    MFPGetVersion(true, false, version, *version_len, &resplen);

    *version_len = resplen;
    if (resplen != 28) {
        retval = PM3_ESOFT;
    }
    return retval;
}

static int CmdHFMFPInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp info",
                  "Get info from MIFARE Plus tags",
                  "hf mfp info");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");

    // Mifare Plus info
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    WaitForResponse(CMD_ACK, &resp);

    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    uint64_t select_status = resp.oldarg[0]; // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision


    bool supportVersion = false;
    bool supportSignature = false;

    // version check
    uint8_t version[30] = {0};
    int version_len = sizeof(version);
    if (get_plus_version(version, &version_len) == PM3_SUCCESS) {
        plus_print_version(version);
        supportVersion = true;
    } else {
        // info about 14a part
        infoHF14A(false, false, false);

        // Historical bytes.

    }


    // Signature originality check
    uint8_t signature[56] = {0};
    int signature_len = sizeof(signature);
    if (get_plus_signature(signature, &signature_len) == PM3_SUCCESS) {
        plus_print_signature(card.uid, card.uidlen, signature, signature_len);
        supportSignature = true;
    }

    if (select_status == 1 || select_status == 2) {

        PrintAndLogEx(INFO, "--- " _CYAN_("Fingerprint"));

        bool isPlus = false;

        if (supportVersion) {

            int cardtype = getCardType(version[3], version[4]);

            if (cardtype == 6) {
                if (supportSignature) {
                    PrintAndLogEx(INFO, "          Tech: " _GREEN_("MIFARE Plus EV1"));
                } else {
                    PrintAndLogEx(INFO, "          Tech: " _YELLOW_("MIFARE Plus SE/X"));
                }
                isPlus = true;
            } else {

            }
        }

        // MIFARE Type Identification Procedure
        // https://www.nxp.com/docs/en/application-note/AN10833.pdf
        uint16_t ATQA = card.atqa[0] + (card.atqa[1] << 8);

        if (ATQA & 0x0004) {
            PrintAndLogEx(INFO, "          SIZE: " _GREEN_("2K") " (%s UID)", (ATQA & 0x0040) ? "7" : "4");
            isPlus = true;
        }
        if (ATQA & 0x0002) {
            PrintAndLogEx(INFO, "          SIZE: " _GREEN_("4K") " (%s UID)", (ATQA & 0x0040) ? "7" : "4");
            isPlus = true;
        }

        uint8_t SLmode = 0xFF;
        if (isPlus) {
            if (card.sak == 0x08) {
                PrintAndLogEx(INFO, "            SAK: " _GREEN_("2K 7b UID"));
                if (select_status == 2) SLmode = 1;
            }
            if (card.sak == 0x18) {
                PrintAndLogEx(INFO, "            SAK: " _GREEN_("4K 7b UID"));
                if (select_status == 2) SLmode = 1;
            }
            if (card.sak == 0x10) {
                PrintAndLogEx(INFO, "            SAK: " _GREEN_("2K"));
                if (select_status == 2) SLmode = 2;
            }
            if (card.sak == 0x11) {
                PrintAndLogEx(INFO, "            SAK: " _GREEN_("4K"));
                if (select_status == 2) SLmode = 2;
            }
        }

        if (card.sak == 0x20) {
            if (card.ats_len > 0) {
                PrintAndLogEx(INFO, "           SAK: " _GREEN_("MIFARE Plus SL0/SL3") " or " _GREEN_("MIFARE DESFire"));
                SLmode = 3;
                // check SL0
                uint8_t data[250] = {0};
                int datalen = 0;
                // https://github.com/Proxmark/proxmark3/blob/master/client/luascripts/mifarePlus.lua#L161
                uint8_t cmd[3 + 16] = {0xa8, 0x90, 0x90, 0x00};
                int res = ExchangeRAW14a(cmd, sizeof(cmd), true, false, data, sizeof(data), &datalen, false);

                // DESFire answers 0x1C or 67 00
                // Plus answers 0x0B, 0x09, 0x06
                // Which tag answers 6D 00 ??
                if (data[0] != 0x0b && data[0] != 0x09 && data[0] != 0x1C && data[0] != 0x67 && data[0] != 0x6d) {
                    PrintAndLogEx(INFO, _RED_("Send copy to iceman of this command output!"));
                    PrintAndLogEx(INFO, "data: %s", sprint_hex(data, datalen));
                }

                if ((memcmp(data, "\x67\x00", 2) == 0) ||
                        (memcmp(data, "\x1C\x83\x0C", 3) == 0)
                   ) {
                    PrintAndLogEx(INFO, "        result: " _RED_("MIFARE DESFire"));
                    PrintAndLogEx(HINT, "Hint:  Try " _YELLOW_("`hf mfdes info`"));
                    DropField();
                    return PM3_SUCCESS;
                } else if (memcmp(data, "\x6D\x00", 2) == 0) {
                    isPlus = false;
                } else {
                    PrintAndLogEx(INFO, "        result: " _GREEN_("MIFARE Plus SL0/SL3"));
                }

                if (!res && datalen > 1 && data[0] == 0x09) {
                    SLmode = 0;
                }
            }
        }

        if (isPlus) {
            // How do we detect SL0 / SL1 / SL2 / SL3 modes?!?
            PrintAndLogEx(INFO, "--- " _CYAN_("Security Level (SL)"));

            if (SLmode != 0xFF)
                PrintAndLogEx(SUCCESS, "       SL mode: " _YELLOW_("SL%d"), SLmode);
            else
                PrintAndLogEx(WARNING, "       SL mode: " _YELLOW_("unknown"));
            switch (SLmode) {
                case 0:
                    PrintAndLogEx(INFO, "  SL 0: initial delivery configuration, used for card personalization");
                    break;
                case 1:
                    PrintAndLogEx(INFO, "  SL 1: backwards functional compatibility mode (with MIFARE Classic 1K / 4K) with an optional AES authentication");
                    break;
                case 2:
                    PrintAndLogEx(INFO, "  SL 2: 3-Pass Authentication based on AES followed by MIFARE CRYPTO1 authentication, communication secured by MIFARE CRYPTO1");
                    break;
                case 3:
                    PrintAndLogEx(INFO, "  SL 3: 3-Pass authentication based on AES, data manipulation commands secured by AES encryption and an AES based MACing method.");
                    break;
                default:
                    break;
            }
        }
    } else {
        PrintAndLogEx(INFO, "\tMifare Plus info not available.");
    }
    PrintAndLogEx(NORMAL, "");
    DropField();
    return PM3_SUCCESS;
}

static int CmdHFMFPWritePerso(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp wrp",
                  "Executes Write Perso command. Can be used in SL0 mode only.",
                  "hf mfp wrp --ki 4000 --key 000102030405060708090a0b0c0d0e0f  -> write key (00..0f) to key number 4000 \n"
                  "hf mfp wrp --ki 4000                                         -> write default key(0xff..0xff) to key number 4000");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "Verbose output"),
        arg_str1(NULL, "ki",  "<hex>", " Key number, 2 hex bytes"),
        arg_str0(NULL, "key", "<hex>", " Key, 16 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);

    uint8_t keyNum[64] = {0};
    int keyNumLen = 0;
    CLIGetHexWithReturn(ctx, 2, keyNum, &keyNumLen);

    uint8_t key[64] = {0};
    int keyLen = 0;
    CLIGetHexWithReturn(ctx, 3, key, &keyLen);
    CLIParserFree(ctx);

    mfpSetVerboseMode(verbose);

    if (!keyLen) {
        memmove(key, mfp_default_key, 16);
        keyLen = 16;
    }

    if (keyNumLen != 2) {
        PrintAndLogEx(ERR, "Key number length must be 2 bytes. Got %d", keyNumLen);
        return PM3_EINVARG;
    }
    if (keyLen != 16) {
        PrintAndLogEx(ERR, "Key length must be 16 bytes. Got %d", keyLen);
        return PM3_EINVARG;
    }

    uint8_t data[250] = {0};
    int datalen = 0;

    int res = MFPWritePerso(keyNum, key, true, false, data, sizeof(data), &datalen);
    if (res) {
        PrintAndLogEx(ERR, "Exchange error: %d", res);
        return res;
    }

    if (datalen != 3) {
        PrintAndLogEx(ERR, "Command must return 3 bytes. Got %d", datalen);
        return PM3_ESOFT;
    }

    if (data[0] != 0x90) {
        PrintAndLogEx(ERR, "Command error: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Write ( " _GREEN_("ok") " )");
    return PM3_SUCCESS;
}

static int CmdHFMFPInitPerso(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp initp",
                  "Executes Write Perso command for all card's keys. Can be used in SL0 mode only.",
                  "hf mfp initp --key 000102030405060708090a0b0c0d0e0f  -> fill all the keys with key (00..0f)\n"
                  "hf mfp initp -vv                                     -> fill all the keys with default key(0xff..0xff) and show all the data exchange");

    void *argtable[] = {
        arg_param_begin,
        arg_litn("v",  "verbose", 0, 2, "Verbose mode"),
        arg_str0("k", "key", "<hex>", "Key, 16 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    bool verbose2 = arg_get_lit(ctx, 1) > 1;

    uint8_t key[256] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 2, key, &keylen);
    CLIParserFree(ctx);

    if (keylen && keylen != 16) {
        PrintAndLogEx(FAILED, "Key length must be 16 bytes. Got %d", keylen);
        return PM3_EINVARG;
    }

    if (keylen == 0) {
        memmove(key, mfp_default_key, sizeof(mfp_default_key));
    }

    uint8_t keyNum[2] = {0};
    uint8_t data[250] = {0};
    int datalen = 0;
    int res;

    mfpSetVerboseMode(verbose2);
    for (uint16_t sn = 0x4000; sn < 0x4050; sn++) {
        keyNum[0] = sn >> 8;
        keyNum[1] = sn & 0xff;
        res = MFPWritePerso(keyNum, key, (sn == 0x4000), true, data, sizeof(data), &datalen);
        if (!res && (datalen == 3) && data[0] == 0x09) {
            PrintAndLogEx(INFO, "2K card detected.");
            break;
        }
        if (res || (datalen != 3) || data[0] != 0x90) {
            PrintAndLogEx(ERR, "Write error on address %04x", sn);
            break;
        }
    }

    mfpSetVerboseMode(verbose);
    for (int i = 0; i < ARRAYLEN(mfp_card_adresses); i++) {
        keyNum[0] = mfp_card_adresses[i] >> 8;
        keyNum[1] = mfp_card_adresses[i] & 0xff;
        res = MFPWritePerso(keyNum, key, false, true, data, sizeof(data), &datalen);
        if (!res && (datalen == 3) && data[0] == 0x09) {
            PrintAndLogEx(WARNING, "Skipped[%04x]...", mfp_card_adresses[i]);
        } else {
            if (res || (datalen != 3) || data[0] != 0x90) {
                PrintAndLogEx(ERR, "Write error on address %04x", mfp_card_adresses[i]);
                break;
            }
        }
    }
    DropField();

    if (res)
        return res;

    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

static int CmdHFMFPCommitPerso(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp commitp",
                  "Executes Commit Perso command. Can be used in SL0 mode only.\n"
                  "OBS! This command will not be executed if \n"
                  "CardConfigKey, CardMasterKey and L3SwitchKey AES keys are not written.",
                  "hf mfp commitp\n"
                  //                "hf mfp commitp --sl 1"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose", "Verbose mode"),
//        arg_int0(NULL,  "sl", "<dec>", "SL mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
//    int slmode = arg_get_int(ctx, 2);
    CLIParserFree(ctx);

    mfpSetVerboseMode(verbose);

    uint8_t data[250] = {0};
    int datalen = 0;

    int res = MFPCommitPerso(true, false, data, sizeof(data), &datalen);
    if (res) {
        PrintAndLogEx(ERR, "Exchange error: %d", res);
        return res;
    }

    if (datalen != 3) {
        PrintAndLogEx(ERR, "Command must return 3 bytes. Got %d", datalen);
        return PM3_EINVARG;
    }

    if (data[0] != 0x90) {
        PrintAndLogEx(ERR, "Command error: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        return PM3_EINVARG;
    }
    PrintAndLogEx(INFO, "Switched security level ( " _GREEN_("ok") " )");
    return PM3_SUCCESS;
}

static int CmdHFMFPAuth(const char *Cmd) {
    uint8_t keyn[250] = {0};
    int keynlen = 0;
    uint8_t key[250] = {0};
    int keylen = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp auth",
                  "Executes AES authentication command for MIFARE Plus card",
                  "hf mfp auth --ki 4000 --key 000102030405060708090a0b0c0d0e0f      -> executes authentication\n"
                  "hf mfp auth --ki 9003 --key FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF -v   -> executes authentication and shows all the system data");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose", "Verbose mode"),
        arg_str1(NULL, "ki", "<hex>", "Key number, 2 hex bytes"),
        arg_str1(NULL, "key", "<hex>", "Key, 16 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    CLIGetHexWithReturn(ctx, 2, keyn, &keynlen);
    CLIGetHexWithReturn(ctx, 3, key, &keylen);
    CLIParserFree(ctx);

    if (keynlen != 2) {
        PrintAndLogEx(ERR, "ERROR: <key number> must be 2 bytes. Got %d", keynlen);
        return PM3_EINVARG;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "ERROR: <key> must be 16 bytes. Got %d", keylen);
        return PM3_EINVARG;
    }

    return MifareAuth4(NULL, keyn, key, true, false, true, verbose, false);
}

static int CmdHFMFPRdbl(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp rdbl",
                  "Reads blocks from MIFARE Plus card",
                  "hf mfp rdbl --blk 0 --key 000102030405060708090a0b0c0d0e0f   -> executes authentication and read block 0 data\n"
                  "hf mfp rdbl --blk 1 -v                                       -> executes authentication and shows sector 1 data with default key 0xFF..0xFF");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose", "Verbose mode"),
        arg_int0("n",  "count", "<dec>", "Blocks count (def: 1)"),
        arg_lit0("b",  "keyb", "Use key B (def: keyA)"),
        arg_lit0("p",  "plain", "Plain communication mode between reader and card"),
        arg_int1(NULL, "blk", "<0..255>", "Block number"),
        arg_str0("k", "key", "<hex>", "Key, 16 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool verbose = arg_get_lit(ctx, 1);
    int blocksCount = arg_get_int_def(ctx, 2, 1);
    bool keyB = arg_get_lit(ctx, 3);
    int plain = arg_get_lit(ctx, 4);
    uint32_t blockn = arg_get_int(ctx, 5);

    uint8_t keyn[2] = {0};
    uint8_t key[250] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 6, key, &keylen);
    CLIParserFree(ctx);

    mfpSetVerboseMode(verbose);

    if (!keylen) {
        memmove(key, mfp_default_key, 16);
        keylen = 16;
    }

    if (blockn > 255) {
        PrintAndLogEx(ERR, "<block number> must be in range [0..255]. got %d", blockn);
        return PM3_EINVARG;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "<key> must be 16 bytes. Got %d", keylen);
        return PM3_EINVARG;
    }

    // 3 blocks - wo iso14443-4 chaining
    if (blocksCount > 3) {
        PrintAndLogEx(ERR, "blocks count must be less than 3. Got %d", blocksCount);
        return PM3_EINVARG;
    }

    if (blocksCount > 1 && mfIsSectorTrailer(blockn)) {
        PrintAndLogEx(WARNING, "WARNING: trailer!");
    }

    uint8_t sectorNum = mfSectorNum(blockn & 0xff);
    uint16_t uKeyNum = 0x4000 + sectorNum * 2 + (keyB ? 1 : 0);
    keyn[0] = uKeyNum >> 8;
    keyn[1] = uKeyNum & 0xff;
    if (verbose)
        PrintAndLogEx(INFO, "--block:%d sector[%u]:%02x key:%04x", blockn, mfNumBlocksPerSector(sectorNum), sectorNum, uKeyNum);

    mf4Session_t mf4session;
    int res = MifareAuth4(&mf4session, keyn, key, true, true, true, verbose, false);
    if (res) {
        PrintAndLogEx(ERR, "Authentication error: %d", res);
        return res;
    }

    uint8_t data[250] = {0};
    int datalen = 0;
    uint8_t mac[8] = {0};
    res = MFPReadBlock(&mf4session, plain, blockn & 0xff, blocksCount, false, false, data, sizeof(data), &datalen, mac);
    if (res) {
        PrintAndLogEx(ERR, "Read error: %d", res);
        return res;
    }

    if (datalen && data[0] != 0x90) {
        PrintAndLogEx(ERR, "Card read error: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        return PM3_ESOFT;
    }

    if (datalen != 1 + blocksCount * 16 + 8 + 2) {
        PrintAndLogEx(ERR, "Error return length: %d", datalen);
        return PM3_ESOFT;
    }

    uint8_t sector = mfSectorNum(blockn);
    mf_print_sector_hdr(sector);

    int indx = blockn;
    for (int i = 0; i < blocksCount; i++)  {
        mf_print_block_one(indx, data + 1 + (i * MFBLOCK_SIZE), verbose);
        indx++;
    }

    if (memcmp(&data[(blocksCount * 16) + 1], mac, 8)) {
        PrintAndLogEx(WARNING, "WARNING: mac not equal...");
        PrintAndLogEx(WARNING, "MAC   card... " _YELLOW_("%s"), sprint_hex_inrow(&data[1 + (blocksCount * MFBLOCK_SIZE)], 8));
        PrintAndLogEx(WARNING, "MAC reader... " _YELLOW_("%s"), sprint_hex_inrow(mac, sizeof(mac)));
    } else {
        if (verbose) {
            PrintAndLogEx(INFO, "MAC... " _YELLOW_("%s"), sprint_hex_inrow(&data[1 + (blocksCount * MFBLOCK_SIZE)], 8));
        }
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHFMFPRdsc(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp rdsc",
                  "Reads one sector from MIFARE Plus card",
                  "hf mfp rdsc -s 0 --key 000102030405060708090a0b0c0d0e0f   -> executes authentication and read sector 0 data\n"
                  "hf mfp rdsc -s 1 -v                                       -> executes authentication and shows sector 1 data with default key");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose", "Verbose mode"),
        arg_lit0("b",  "keyb",    "Use key B (def: keyA)"),
        arg_lit0("p",  "plain",   "Plain communication mode between reader and card"),
        arg_int1("s",  "sn",      "<0..255>", "Sector number"),
        arg_str0("k",  "key",     "<hex>", "Key, 16 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool verbose = arg_get_lit(ctx, 1);
    bool keyB = arg_get_lit(ctx, 2);
    bool plain = arg_get_lit(ctx, 3);
    uint32_t sectorNum = arg_get_int(ctx, 4);
    uint8_t keyn[2] = {0};
    uint8_t key[250] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 5, key, &keylen);
    CLIParserFree(ctx);

    mfpSetVerboseMode(verbose);

    if (!keylen) {
        memmove(key, mfp_default_key, 16);
        keylen = 16;
    }

    if (sectorNum > 39) {
        PrintAndLogEx(ERR, "<sector number> must be in range [0..39]. Got %d", sectorNum);
        return PM3_EINVARG;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "<key> must be 16 bytes. Got %d", keylen);
        return PM3_EINVARG;
    }

    uint16_t uKeyNum = 0x4000 + sectorNum * 2 + (keyB ? 1 : 0);
    keyn[0] = uKeyNum >> 8;
    keyn[1] = uKeyNum & 0xff;
    if (verbose)
        PrintAndLogEx(INFO, "--sector[%u]:%02x key:%04x", mfNumBlocksPerSector(sectorNum), sectorNum, uKeyNum);

    mf4Session_t mf4session;
    int res = MifareAuth4(&mf4session, keyn, key, true, true, true, verbose, false);
    if (res) {
        PrintAndLogEx(ERR, "Authentication error: %d", res);
        return res;
    }

    uint8_t data[250] = {0};
    int datalen = 0;
    uint8_t mac[8] = {0};

    mf_print_sector_hdr(sectorNum);

    for (int blockno = mfFirstBlockOfSector(sectorNum); blockno < mfFirstBlockOfSector(sectorNum) + mfNumBlocksPerSector(sectorNum); blockno++) {

        res = MFPReadBlock(&mf4session, plain, blockno & 0xff, 1, false, true, data, sizeof(data), &datalen, mac);
        if (res) {
            PrintAndLogEx(ERR, "Read error: %d", res);
            DropField();
            return res;
        }

        if (datalen && data[0] != 0x90) {
            PrintAndLogEx(ERR, "Card read error: %02x %s", data[0], mfpGetErrorDescription(data[0]));
            DropField();
            return PM3_ESOFT;
        }

        if (datalen != 1 + MFBLOCK_SIZE + 8 + 2) {
            PrintAndLogEx(ERR, "Error return length:%d", datalen);
            DropField();
            return PM3_ESOFT;
        }

        mf_print_block_one(blockno, data + 1, verbose);

        if (memcmp(&data[1 + 16], mac, 8)) {
            PrintAndLogEx(WARNING, "WARNING: mac on block %d not equal...", blockno);
            PrintAndLogEx(WARNING, "MAC   card... " _YELLOW_("%s"), sprint_hex_inrow(&data[1 + MFBLOCK_SIZE], 8));
            PrintAndLogEx(WARNING, "MAC reader... " _YELLOW_("%s"), sprint_hex_inrow(mac, sizeof(mac)));
        } else {
            if (verbose) {
                PrintAndLogEx(INFO, "MAC... " _YELLOW_("%s"), sprint_hex_inrow(&data[1 + MFBLOCK_SIZE], 8));
            }
        }
    }
    PrintAndLogEx(NORMAL, "");
    DropField();
    return PM3_SUCCESS;
}

static int CmdHFMFPWrbl(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp wrbl",
                  "Writes one block to MIFARE Plus card",
                  "hf mfp wrbl --blk 1 -d ff0000000000000000000000000000ff --key 000102030405060708090a0b0c0d0e0f -> write block 1 data\n"
                  "hf mfp wrbl --blk 2 -d ff0000000000000000000000000000ff -v                                     -> write block 2 data with default key 0xFF..0xFF"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose", "Verbose mode"),
        arg_lit0("b",  "keyb",    "Use key B (def: keyA)"),
        arg_int1(NULL, "blk",     "<0..255>", "Block number"),
        arg_str1("d",  "data",    "<hex>", "Data, 16 hex bytes"),
        arg_str0("k",  "key",     "<hex>", "Key, 16 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool verbose = arg_get_lit(ctx, 1);
    bool keyB = arg_get_lit(ctx, 2);
    uint32_t blockNum = arg_get_int(ctx, 3);

    uint8_t datain[250] = {0};
    int datainlen = 0;
    CLIGetHexWithReturn(ctx, 4, datain, &datainlen);

    uint8_t key[250] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 5, key, &keylen);
    CLIParserFree(ctx);

    uint8_t keyn[2] = {0};

    mfpSetVerboseMode(verbose);

    if (!keylen) {
        memmove(key, mfp_default_key, 16);
        keylen = 16;
    }

    if (blockNum > 255) {
        PrintAndLogEx(ERR, "<block number> must be in range [0..255]. Got %d", blockNum);
        return PM3_EINVARG;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "<key> must be 16 bytes. Got %d", keylen);
        return PM3_EINVARG;
    }

    if (datainlen != 16) {
        PrintAndLogEx(ERR, "<data> must be 16 bytes. Got %d", datainlen);
        return PM3_EINVARG;
    }

    uint8_t sectorNum = mfSectorNum(blockNum & 0xff);
    uint16_t uKeyNum = 0x4000 + sectorNum * 2 + (keyB ? 1 : 0);
    keyn[0] = uKeyNum >> 8;
    keyn[1] = uKeyNum & 0xff;
    if (verbose)
        PrintAndLogEx(INFO, "--block:%d sector[%u]:%02x key:%04x", blockNum & 0xff, mfNumBlocksPerSector(sectorNum), sectorNum, uKeyNum);

    mf4Session_t mf4session;
    int res = MifareAuth4(&mf4session, keyn, key, true, true, true, verbose, false);
    if (res) {
        PrintAndLogEx(ERR, "Authentication error: %d", res);
        return res;
    }

    uint8_t data[250] = {0};
    int datalen = 0;
    uint8_t mac[8] = {0};
    res = MFPWriteBlock(&mf4session, blockNum & 0xff, datain, false, false, data, sizeof(data), &datalen, mac);
    if (res) {
        PrintAndLogEx(ERR, "Write error: %d", res);
        DropField();
        return res;
    }

    if (datalen != 3 && (datalen != 3 + 8)) {
        PrintAndLogEx(ERR, "Error return length:%d", datalen);
        DropField();
        return PM3_ESOFT;
    }

    if (datalen && data[0] != 0x90) {
        PrintAndLogEx(ERR, "Card write error: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        DropField();
        return PM3_ESOFT;
    }

    if (memcmp(&data[1], mac, 8)) {
        PrintAndLogEx(WARNING, "WARNING: mac not equal...");
        PrintAndLogEx(WARNING, "MAC   card: %s", sprint_hex(&data[1], 8));
        PrintAndLogEx(WARNING, "MAC reader: %s", sprint_hex(mac, 8));
    } else {
        if (verbose)
            PrintAndLogEx(INFO, "MAC: %s", sprint_hex(&data[1], 8));
    }

    DropField();
    PrintAndLogEx(INFO, "Write ( " _GREEN_("ok") " )");
    return PM3_SUCCESS;
}

static int plus_key_check(uint8_t startSector, uint8_t endSector, uint8_t startKeyAB, uint8_t endKeyAB,
                          uint8_t keyList[MAX_AES_KEYS_LIST_LEN][AES_KEY_LEN], size_t keyListLen, uint8_t foundKeys[2][64][AES_KEY_LEN + 1],
                          bool verbose) {
    int res;
    bool selectCard = true;
    uint8_t keyn[2] = {0};

    // sector number from 0
    for (uint8_t sector = startSector; sector <= endSector; sector++) {
        // 0-keyA 1-keyB
        for (uint8_t keyAB = startKeyAB; keyAB <= endKeyAB; keyAB++) {
            // main cycle with key check
            for (int i = 0; i < keyListLen; i++) {

                // allow client abort every iteration
                if (kbd_enter_pressed()) {
                    PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
                    DropField();
                    return PM3_EOPABORTED;
                }

                if (i % 10 == 0) {
                    if (verbose == false) {
                        PrintAndLogEx(NORMAL, "." NOLF);
                    }
                }

                uint16_t uKeyNum = 0x4000 + sector * 2 + keyAB;
                keyn[0] = uKeyNum >> 8;
                keyn[1] = uKeyNum & 0xff;

                for (int retry = 0; retry < 4; retry++) {
                    res = MifareAuth4(NULL, keyn, keyList[i], selectCard, true, false, false, true);
                    if (res == PM3_SUCCESS || res == PM3_EWRONGANSWER)
                        break;

                    if (verbose)
                        PrintAndLogEx(WARNING, "\nretried[%d]...", retry);
                    else
                        PrintAndLogEx(NORMAL, "R" NOLF);

                    DropField();
                    selectCard = true;
                    msleep(100);
                }

                // key for [sector,keyAB] found
                if (res == PM3_SUCCESS) {
                    if (verbose)
                        PrintAndLogEx(INFO, "\nFound key for sector %d key %s [%s]", sector, keyAB == 0 ? "A" : "B", sprint_hex_inrow(keyList[i], 16));
                    else
                        PrintAndLogEx(NORMAL, "+" NOLF);

                    foundKeys[keyAB][sector][0] = 0x01;
                    memcpy(&foundKeys[keyAB][sector][1], keyList[i], AES_KEY_LEN);
                    DropField();
                    selectCard = true;
                    msleep(50);

                    // break out from keylist check loop,
                    break;
                }

                if (verbose)
                    PrintAndLogEx(WARNING, "\nsector %02d key %d [%s] res: %d", sector, keyAB, sprint_hex_inrow(keyList[i], 16), res);

                // RES can be:
                // PM3_ERFTRANS     -7
                // PM3_EWRONGANSWER -16
                if (res == PM3_ERFTRANS) {
                    if (verbose)
                        PrintAndLogEx(ERR, "\nExchange error. Aborted.");
                    else
                        PrintAndLogEx(NORMAL, "E" NOLF);

                    DropField();
                    return PM3_ECARDEXCHANGE;
                }

                selectCard = false;
            }
        }
    }

    DropField();
    return PM3_SUCCESS;
}

static void Fill2bPattern(uint8_t keyList[MAX_AES_KEYS_LIST_LEN][AES_KEY_LEN], uint32_t *keyListLen, uint32_t *startPattern) {
    for (uint32_t pt = *startPattern; pt < 0x10000; pt++) {
        keyList[*keyListLen][0] = (pt >> 8) & 0xff;
        keyList[*keyListLen][1] = pt & 0xff;
        memcpy(&keyList[*keyListLen][2], &keyList[*keyListLen][0], 2);
        memcpy(&keyList[*keyListLen][4], &keyList[*keyListLen][0], 4);
        memcpy(&keyList[*keyListLen][8], &keyList[*keyListLen][0], 8);
        (*keyListLen)++;
        *startPattern = pt;
        if (*keyListLen == MAX_AES_KEYS_LIST_LEN)
            break;
    }
    (*startPattern)++;
}

static int CmdHFMFPChk(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp chk",
                  "Checks keys on MIFARE Plus card",
                  "hf mfp chk -k 000102030405060708090a0b0c0d0e0f  -> check key on sector 0 as key A and B\n"
                  "hf mfp chk -s 2 -a                              -> check default key list on sector 2, only key A\n"
                  "hf mfp chk -d mfp_default_keys -s0 -e6          -> check keys from dictionary against sectors 0-6\n"
                  "hf mfp chk --pattern1b --dump                   -> check all 1-byte keys pattern and save found keys to file\n"
                  "hf mfp chk --pattern2b --startp2b FA00          -> check all 2-byte keys pattern. Start from key FA00FA00...FA00");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "keya",      "Check only key A (def: check all keys)"),
        arg_lit0("b",  "keyb",      "Check only key B (def: check all keys)"),
        arg_int0("s",  "startsec",  "<0..255>", "Start sector number"),
        arg_int0("e",  "endsec",    "<0..255>", "End sector number"),
        arg_str0("k",  "key",       "<hex>", "Key for checking (HEX 16 bytes)"),
        arg_str0("d",  "dict",      "<fn>", "Dictionary file with keys"),
        arg_lit0(NULL, "pattern1b", "Check all 1-byte combinations of key (0000...0000, 0101...0101, 0202...0202, ...)"),
        arg_lit0(NULL, "pattern2b", "Check all 2-byte combinations of key (0000...0000, 0001...0001, 0002...0002, ...)"),
        arg_str0(NULL, "startp2b",  "<pattern>", "Start key (2-byte HEX) for 2-byte search (use with `--pattern2b`)"),
        arg_lit0(NULL, "dump",      "Dump found keys to JSON file"),
        arg_lit0("v",  "verbose",   "Verbose mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool keyA = arg_get_lit(ctx, 1);
    bool keyB = arg_get_lit(ctx, 2);
    uint8_t startSector = arg_get_int_def(ctx, 3, 0);
    uint8_t endSector = arg_get_int_def(ctx, 4, 0);

    uint8_t keyList[MAX_AES_KEYS_LIST_LEN][AES_KEY_LEN] = {{0}};
    uint32_t keyListLen = 0;
    uint8_t foundKeys[2][64][AES_KEY_LEN + 1] = {{{0}}};

    uint8_t vkey[16] = {0};
    int vkeylen = 0;
    CLIGetHexWithReturn(ctx, 5, vkey, &vkeylen);
    if (vkeylen > 0) {
        if (vkeylen == 16) {
            memcpy(&keyList[keyListLen], vkey, 16);
            keyListLen++;
        } else {
            PrintAndLogEx(ERR, "Specified key must have 16 bytes. Got %d", vkeylen);
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    uint8_t dict_filename[FILE_PATH_SIZE + 2] = {0};
    int dict_filenamelen = 0;
    if (CLIParamStrToBuf(arg_get_str(ctx, 6), dict_filename, FILE_PATH_SIZE, &dict_filenamelen)) {
        PrintAndLogEx(FAILED, "File name too long or invalid.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool pattern1b = arg_get_lit(ctx, 7);
    bool pattern2b = arg_get_lit(ctx, 8);

    if (pattern1b && pattern2b) {
        PrintAndLogEx(ERR, "Pattern search mode must be 2-byte or 1-byte only.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (dict_filenamelen && (pattern1b || pattern2b)) {
        PrintAndLogEx(ERR, "Pattern search mode and dictionary mode can't be used in one command.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t startPattern = 0x0000;
    uint8_t vpattern[2];
    int vpatternlen = 0;
    CLIGetHexWithReturn(ctx, 9, vpattern, &vpatternlen);
    if (vpatternlen > 0) {
        if (vpatternlen <= 2) {
            startPattern = (vpattern[0] << 8) + vpattern[1];
        } else {
            PrintAndLogEx(ERR, "Pattern must be 2-bytes. Got %d", vpatternlen);
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
        if (!pattern2b)
            PrintAndLogEx(WARNING, "Pattern entered, but search mode not is 2-byte search.");
    }

    bool create_dumpfile = arg_get_lit(ctx, 10);
    bool verbose = arg_get_lit(ctx, 11);
    CLIParserFree(ctx);

    uint8_t startKeyAB = 0;
    uint8_t endKeyAB = 1;
    if (keyA && (keyB == false))
        endKeyAB = 0;

    if ((keyA == false) && keyB)
        startKeyAB = 1;

    if (endSector < startSector)
        endSector = startSector;

    // 1-byte pattern search mode
    if (pattern1b) {
        for (int i = 0; i < 0x100; i++) {
            memset(keyList[i], i, 16);
        }

        keyListLen = 0x100;
    }

    // 2-byte pattern search mode
    if (pattern2b) {
        Fill2bPattern(keyList, &keyListLen, &startPattern);
    }

    int res = PM3_SUCCESS;

    // dictionary mode
    size_t endFilePosition = 0;
    if (dict_filenamelen) {
        uint32_t keycnt = 0;
        res = loadFileDICTIONARYEx((char *)dict_filename, keyList, sizeof(keyList), NULL, 16, &keycnt, 0, &endFilePosition, true);

        if (res == PM3_SUCCESS && endFilePosition) {
            keyListLen = keycnt;
            PrintAndLogEx(SUCCESS, "First part of dictionary successfully loaded.");
        }
    }

    if (keyListLen == 0) {
        for (int i = 0; i < g_mifare_plus_default_keys_len; i++) {
            if (hex_to_bytes(g_mifare_plus_default_keys[i], keyList[keyListLen], 16) != 16) {
                break;
            }

            keyListLen++;
        }
    }

    if (keyListLen == 0) {
        PrintAndLogEx(ERR, "Key list is empty. Nothing to check.");
        return PM3_EINVARG;
    } else {
        PrintAndLogEx(INFO, "Loaded " _YELLOW_("%"PRIu32) " keys", keyListLen);
    }

    if (verbose == false) {
        PrintAndLogEx(INFO, "Search keys");
    }

    while (true) {
        res = plus_key_check(startSector, endSector, startKeyAB, endKeyAB, keyList, keyListLen, foundKeys, verbose);
        if (res == PM3_EOPABORTED) {
            break;
        }

        if (pattern2b && startPattern < 0x10000) {
            if (verbose == false) {
                PrintAndLogEx(NORMAL, "p" NOLF);
            }

            keyListLen = 0;
            Fill2bPattern(keyList, &keyListLen, &startPattern);
            continue;
        }

        if (dict_filenamelen && endFilePosition) {
            if (verbose == false)
                PrintAndLogEx(NORMAL, "d" NOLF);

            uint32_t keycnt = 0;
            res = loadFileDICTIONARYEx((char *)dict_filename, keyList, sizeof(keyList), NULL, 16, &keycnt, endFilePosition, &endFilePosition, false);
            if (res == PM3_SUCCESS && endFilePosition) {
                keyListLen = keycnt;
            }

            continue;
        }
        break;
    }

    if (verbose == false) {
        PrintAndLogEx(NORMAL, "");
    }

    // print result
    char strA[46 + 1] = {0};
    char strB[46 + 1] = {0};

    uint8_t ndef_key[] = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};
    bool has_ndef_key = false;
    bool printedHeader = false;
    for (uint8_t s = startSector; s <= endSector; s++) {

        if ((memcmp(&foundKeys[0][s][1], ndef_key, AES_KEY_LEN) == 0) ||
                (memcmp(&foundKeys[1][s][1], ndef_key, AES_KEY_LEN) == 0)) {
            has_ndef_key = true;
        }

        if (printedHeader == false) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "-----+----------------------------------+----------------------------------");
            PrintAndLogEx(INFO, " Sec | key A                            | key B");
            PrintAndLogEx(INFO, "-----+----------------------------------+----------------------------------");
            printedHeader = true;
        }

        if (foundKeys[0][s][0]) {
            snprintf(strA, sizeof(strA), _GREEN_("%s"), sprint_hex_inrow(&foundKeys[0][s][1], AES_KEY_LEN));
        } else {
            snprintf(strA, sizeof(strA), _RED_("%s"), "--------------------------------");
        }

        if (foundKeys[1][s][0]) {
            snprintf(strB, sizeof(strB), _GREEN_("%s"), sprint_hex_inrow(&foundKeys[1][s][1], AES_KEY_LEN));
        } else {
            snprintf(strB, sizeof(strB), _RED_("%s"), "--------------------------------");
        }

        PrintAndLogEx(INFO, " " _YELLOW_("%03d") " | %s | %s", s, strA, strB);
    }

    if (printedHeader == false)
        PrintAndLogEx(INFO, "No keys found(");
    else
        PrintAndLogEx(INFO, "-----+----------------------------------+----------------------------------\n");

    // save keys to json
    if (create_dumpfile && printedHeader) {

        size_t keys_len = (2 * 64 * (AES_KEY_LEN + 1));

        uint8_t data[10 + 1 + 2 + 1 + 256 + keys_len];
        memset(data, 0, sizeof(data));

        // Mifare Plus info
        SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);

        PacketResponseNG resp;
        WaitForResponse(CMD_ACK, &resp);

        iso14a_card_select_t card;
        memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

        uint64_t select_status = resp.oldarg[0]; // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision
        uint8_t atslen = 0;
        if (select_status == 1 || select_status == 2) {
            memcpy(data, card.uid, card.uidlen);
            data[10] = card.sak;
            data[11] = card.atqa[1];
            data[12] = card.atqa[0];
            atslen = card.ats_len;
            data[13] = atslen;
            memcpy(&data[14], card.ats, atslen);
        }

        char *fptr = calloc(sizeof(char) * (strlen("hf-mfp-") + strlen("-key")) + card.uidlen * 2 + 1,  sizeof(uint8_t));
        strcpy(fptr, "hf-mfp-");

        FillFileNameByUID(fptr, card.uid, "-key", card.uidlen);

        // length: UID(10b)+SAK(1b)+ATQA(2b)+ATSlen(1b)+ATS(atslen)+foundKeys[2][64][AES_KEY_LEN + 1]
        memcpy(&data[14 + atslen], foundKeys, keys_len);
        // 64 here is for how many "rows" there is in the data array.  A bit confusing
        saveFileJSON(fptr, jsfMfPlusKeys, data, 64, NULL);
        free(fptr);
    }

    // MAD detection
    if ((memcmp(&foundKeys[0][0][1], "\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7", AES_KEY_LEN) == 0)) {
        PrintAndLogEx(HINT, "MAD key detected. Try " _YELLOW_("`hf mfp mad`") " for more details");
    }

    // NDEF detection
    if (has_ndef_key) {
        PrintAndLogEx(HINT, "NDEF key detected. Try " _YELLOW_("`hf mfp ndefread -h`") " for more details");
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHFMFPDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp dump",
                  "Dump MIFARE Plus tag to binary file\n"
                  "If no <name> given, UID will be used as filename",
                  "hf mfp dump\n"
                  "hf mfp dump --keys hf-mf-066C8B78-key.bin --> MIFARE Plus with keys from specified file\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f",  "file", "<fn>", "filename of dump"),
        arg_str0("k",  "keys", "<fn>", "filename of keys"),
        arg_lit0(NULL, "ns", "no save to file"),
        arg_lit0("v",  "verbose",   "Verbose mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int datafnlen = 0;
    char data_fn[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)data_fn, FILE_PATH_SIZE, &datafnlen);

    int keyfnlen = 0;
    char key_fn[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)key_fn, FILE_PATH_SIZE, &keyfnlen);

    bool nosave = arg_get_lit(ctx, 3);
    bool verbose = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    mfpSetVerboseMode(verbose);

    // read card
    uint8_t *mem = calloc(MIFARE_4K_MAXBLOCK * MFBLOCK_SIZE, sizeof(uint8_t));
    if (mem == NULL) {
        PrintAndLogEx(ERR, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    /*
        iso14a_card_select_t card ;
        int res = mfp_read_tag(&card, mem, key_fn);
        if (res != PM3_SUCCESS) {
            free(mem);
            return res;
        }
    */

    // Skip saving card data to file
    if (nosave) {
        PrintAndLogEx(INFO, "Called with no save option");
        free(mem);
        return PM3_SUCCESS;
    }
    /*
        // Save to file
        if (strlen(data_fn) < 1) {

            char *fptr = calloc(sizeof(char) * (strlen("hf-mfp-") + strlen("-dump")) + card.uidlen * 2 + 1,  sizeof(uint8_t));
            strcpy(fptr, "hf-mfp-");

            FillFileNameByUID(fptr, card.uid, "-dump", card.uidlen);

            strcpy(data_fn, fptr);
            free(fptr);
        }

        saveFile(data_fn, ".bin", mem, MIFARE_4K_MAX_BYTES);
        saveFileEML(data_fn, mem, MIFARE_4K_MAX_BYTES, MFBLOCK_SIZE);

        iso14a_mf_extdump_t xdump;
        xdump.card_info = card;
        xdump.dump = mem;
        xdump.dumplen = MIFARE_4K_MAX_BYTES;
        saveFileJSON(data_fn, jsfCardMemory, (uint8_t *)&xdump, sizeof(xdump), NULL);
    */
    free(mem);
    return PM3_SUCCESS;
}


static int CmdHFMFPMAD(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp mad",
                  "Checks and prints MIFARE Application Directory (MAD)",
                  "hf mfp mad\n"
                  "hf mfp mad --aid e103 -k d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7  -> read and print NDEF data from MAD aid");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose",  "Show technical data"),
        arg_str0(NULL, "aid",      "<hex>", "Print all sectors with aid"),
        arg_str0("k",  "key",      "<hex>", "Key for printing sectors"),
        arg_lit0("b",  "keyb",     "Use key B for access printing sectors (def: key A)"),
        arg_lit0(NULL, "be",       "(optional: BigEndian)"),
        arg_lit0(NULL, "dch",      "Decode Card Holder information"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    uint8_t aid[2] = {0};
    int aidlen;
    CLIGetHexWithReturn(ctx, 2, aid, &aidlen);
    uint8_t key[16] = {0};
    int keylen;
    CLIGetHexWithReturn(ctx, 3, key, &keylen);
    bool keyB = arg_get_lit(ctx, 4);
    bool swapmad = arg_get_lit(ctx, 5);
    bool decodeholder = arg_get_lit(ctx, 6);

    CLIParserFree(ctx);

    if (aidlen != 2 && !decodeholder && keylen > 0) {
        PrintAndLogEx(WARNING, "Using default MAD keys instead");
    }

    uint8_t sector0[16 * 4] = {0};
    uint8_t sector10[16 * 4] = {0};

    if (mfpReadSector(MF_MAD1_SECTOR, MF_KEY_A, (uint8_t *)g_mifarep_mad_key, sector0, verbose)) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(ERR, "error, read sector 0. card doesn't have MAD or doesn't have MAD on default keys");
        return PM3_ESOFT;
    }

    MADPrintHeader();

    if (verbose) {
        PrintAndLogEx(SUCCESS, "Raw:");
        for (int i = 0; i < 4; i ++)
            PrintAndLogEx(INFO, "[%d] %s", i, sprint_hex(&sector0[i * 16], 16));
    }

    bool haveMAD2 = false;
    MAD1DecodeAndPrint(sector0, swapmad, verbose, &haveMAD2);

    if (haveMAD2) {
        if (mfpReadSector(MF_MAD2_SECTOR, MF_KEY_A, (uint8_t *)g_mifarep_mad_key, sector10, verbose)) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(ERR, "error, read sector " _YELLOW_("0x10") ". Card doesn't have MAD or doesn't have MAD on default keys");
            return PM3_ESOFT;
        }

        MAD2DecodeAndPrint(sector10, swapmad, verbose);
    }

    if (aidlen == 2 || decodeholder) {
        uint16_t mad[7 + 8 + 8 + 8 + 8] = {0};
        size_t madlen = 0;
        if (MADDecode(sector0, sector10, mad, &madlen, swapmad)) {
            PrintAndLogEx(ERR, "can't decode MAD");
            return PM3_EWRONGANSWER;
        }

        // copy default NDEF key
        uint8_t akey[16] = {0};
        memcpy(akey, g_mifarep_ndef_key, 16);

        // user specified key
        if (keylen == 16) {
            memcpy(akey, key, 16);
        }

        uint16_t aaid = 0x0004;
        if (aidlen == 2) {
            aaid = (aid[0] << 8) + aid[1];
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "-------------- " _CYAN_("AID 0x%04x") " ---------------", aaid);

            for (int i = 0; i < madlen; i++) {
                if (aaid == mad[i]) {
                    uint8_t vsector[16 * 4] = {0};
                    if (mfpReadSector(i + 1, keyB ? MF_KEY_B : MF_KEY_A, akey, vsector, false)) {
                        PrintAndLogEx(NORMAL, "");
                        PrintAndLogEx(ERR, "error, read sector %d error", i + 1);
                        return PM3_ESOFT;
                    }

                    for (int j = 0; j < (verbose ? 4 : 3); j ++)
                        PrintAndLogEx(NORMAL, " [%03d] %s", (i + 1) * 4 + j, sprint_hex(&vsector[j * 16], 16));
                }
            }
        }

        if (decodeholder) {

            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "-------- " _CYAN_("Card Holder Info 0x%04x") " --------", aaid);

            uint8_t data[4096] = {0};
            int datalen = 0;

            for (int i = 0; i < madlen; i++) {
                if (aaid == mad[i]) {

                    uint8_t vsector[16 * 4] = {0};
                    if (mfReadSector(i + 1, keyB ? MF_KEY_B : MF_KEY_A, akey, vsector)) {
                        PrintAndLogEx(NORMAL, "");
                        PrintAndLogEx(ERR, "error, read sector %d", i + 1);
                        return PM3_ESOFT;
                    }

                    memcpy(&data[datalen], vsector, 16 * 3);
                    datalen += 16 * 3;
                }
            }

            if (!datalen) {
                PrintAndLogEx(WARNING, "no Card Holder Info data");
                return PM3_SUCCESS;
            }
            MADCardHolderInfoDecode(data, datalen, verbose);
        }
    }
    return PM3_SUCCESS;
}

static int CmdHFMFPNDEFFormat(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp ndefformat",
                  "format MIFARE Plus Tag as a NFC tag with Data Exchange Format (NDEF)\n"
                  "If no <name> given, UID will be used as filename. \n"
                  "It will try default keys and MAD keys to detect if tag is already formatted in order to write.\n"
                  "\n"
                  "If not, it will try finding a key file based on your UID.  ie, if you ran autopwn before",
                  "hf mfp ndefformat\n"
                  "hf mfp ndefformat --keys hf-mf-01020304-key.bin -->  with keys from specified file\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "keys", "<fn>", "filename of keys"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int keyfnlen = 0;
    char keyFilename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)keyFilename, FILE_PATH_SIZE, &keyfnlen);

    CLIParserFree(ctx);

    PrintAndLogEx(SUCCESS, "Not implemented yet. Feel free to contribute!");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

int CmdHFMFPNDEFRead(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp ndefread",
                  "Prints NFC Data Exchange Format (NDEF)",
                  "hf mfp ndefread \n"
                  "hf mfp ndefread -vv                                            -> shows NDEF parsed and raw data\n"
                  "hf mfp ndefread --aid e103 -k d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7 -> shows NDEF data with custom AID and key\n"
                  "hf mfp ndefread -f myfilename -> save raw NDEF to file"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_litn("v",  "verbose",  0, 2, "show technical data"),
        arg_str0(NULL, "aid",      "<aid>", "replace default aid for NDEF"),
        arg_str0("k",  "key",      "<key>", "replace default key for NDEF"),
        arg_lit0("b",  "keyb",     "use key B for access sectors (by default: key A)"),
        arg_str0("f",  "file", "<fn>", "save raw NDEF to file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    bool verbose2 = arg_get_lit(ctx, 1) > 1;
    uint8_t aid[2] = {0};
    int aidlen;
    CLIGetHexWithReturn(ctx, 2, aid, &aidlen);
    uint8_t key[16] = {0};
    int keylen;
    CLIGetHexWithReturn(ctx, 3, key, &keylen);
    bool keyB = arg_get_lit(ctx, 4);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    uint16_t ndefAID = 0xe103;
    if (aidlen == 2)
        ndefAID = (aid[0] << 8) + aid[1];

    uint8_t ndefkey[16] = {0};
    memcpy(ndefkey, g_mifarep_ndef_key, 16);
    if (keylen == 16) {
        memcpy(ndefkey, key, 16);
    }

    uint8_t sector0[16 * 4] = {0};
    uint8_t sector10[16 * 4] = {0};
    uint8_t data[4096] = {0};
    int datalen = 0;

    if (verbose)
        PrintAndLogEx(INFO, "reading MAD v1 sector");

    if (mfpReadSector(MF_MAD1_SECTOR, MF_KEY_A, (uint8_t *)g_mifarep_mad_key, sector0, verbose)) {
        PrintAndLogEx(ERR, "error, read sector 0. card doesn't have MAD or doesn't have MAD on default keys");
        PrintAndLogEx(HINT, "Try " _YELLOW_("`hf mfp ndefread -k `") " with your custom key");
        return PM3_ESOFT;
    }

    bool haveMAD2 = false;
    int res = MADCheck(sector0, NULL, verbose, &haveMAD2);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "MAD error %d", res);
        return res;
    }

    if (haveMAD2) {

        if (verbose)
            PrintAndLogEx(INFO, "reading MAD v2 sector");

        if (mfpReadSector(MF_MAD2_SECTOR, MF_KEY_A, (uint8_t *)g_mifarep_mad_key, sector10, verbose)) {
            PrintAndLogEx(ERR, "error, read sector 0x10. card doesn't have MAD or doesn't have MAD on default keys");
            PrintAndLogEx(HINT, "Try " _YELLOW_("`hf mfp ndefread -k `") " with your custom key");
            return PM3_ESOFT;
        }
    }

    uint16_t mad[7 + 8 + 8 + 8 + 8] = {0};
    size_t madlen = 0;
    res = MADDecode(sector0, (haveMAD2 ? sector10 : NULL), mad, &madlen, false);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "can't decode MAD");
        return res;
    }

    PrintAndLogEx(INFO, "reading data from tag");
    for (int i = 0; i < madlen; i++) {
        if (ndefAID == mad[i]) {
            uint8_t vsector[16 * 4] = {0};
            if (mfpReadSector(i + 1, keyB ? MF_KEY_B : MF_KEY_A, ndefkey, vsector, false)) {
                PrintAndLogEx(ERR, "error, reading sector %d", i + 1);
                return PM3_ESOFT;
            }

            memcpy(&data[datalen], vsector, 16 * 3);
            datalen += 16 * 3;

            PrintAndLogEx(INPLACE, "%d", i);
        }
    }
    PrintAndLogEx(NORMAL, "");

    if (datalen == 0) {
        PrintAndLogEx(ERR, "no NDEF data");
        return PM3_SUCCESS;
    }

    if (verbose2) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("MF Plus NDEF raw") " ----------------");
        print_buffer(data, datalen, 1);
    }

    if (fnlen != 0) {
        saveFile(filename, ".bin", data, datalen);
    }

    res = NDEFDecodeAndPrint(data, datalen, verbose);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(INFO, "Trying to parse NDEF records w/o NDEF header");
        res = NDEFRecordsDecodeAndPrint(data, datalen, verbose);
    }

    if (verbose == false) {
        PrintAndLogEx(HINT, "Try " _YELLOW_("`hf mfp ndefread -v`") " for more details");
    } else {
        if (verbose2 == false) {
            PrintAndLogEx(HINT, "Try " _YELLOW_("`hf mfp ndefread -vv`") " for more details");
        }
    }
    return PM3_SUCCESS;
}

static int CmdHFMFPNDEFWrite(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp ndefwrite",
                  "Write raw NDEF hex bytes to tag. This commands assumes tag already been NFC/NDEF formatted.\n",
                  "hf mfp ndefwrite -d 0300FE      -> write empty record to tag\n"
                  "hf mfp ndefwrite -f myfilename\n"
                  "hf mfp ndefwrite -d 033fd1023a53709101195405656e2d55534963656d616e2054776974746572206c696e6b5101195502747769747465722e636f6d2f686572726d616e6e31303031\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("d", NULL, "<hex>", "raw NDEF hex bytes"),
        arg_str0("f", "file", "<fn>", "write raw NDEF file to tag"),
        arg_lit0("p", NULL, "fix NDEF record headers / terminator block if missing"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t raw[4096] = {0};
    int rawlen;
    CLIGetHexWithReturn(ctx, 1, raw, &rawlen);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool fix_msg = arg_get_lit(ctx, 3);
    bool verbose = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (fix_msg) {
        PrintAndLogEx(NORMAL, "called with fix NDEF message param");
    }

    if (verbose) {
        PrintAndLogEx(NORMAL, "");
    }
    PrintAndLogEx(SUCCESS, "Not implemented yet. Feel free to contribute!");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHFMFPList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf mfp", "mfp -c");
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,                 AlwaysAvailable, "This help"},
    {"list",        CmdHFMFPList,            AlwaysAvailable, "List MIFARE Plus history"},
    {"-----------", CmdHelp,                 IfPm3Iso14443a,  "------------------- " _CYAN_("operations") " ---------------------"},
    {"auth",        CmdHFMFPAuth,            IfPm3Iso14443a,  "Authentication"},
    {"chk",         CmdHFMFPChk,             IfPm3Iso14443a,  "Check keys"},
    {"dump",        CmdHFMFPDump,            IfPm3Iso14443a,  "Dump MIFARE Plus tag to binary file"},
    {"info",        CmdHFMFPInfo,            IfPm3Iso14443a,  "Info about MIFARE Plus tag"},
    {"mad",         CmdHFMFPMAD,             IfPm3Iso14443a,  "Check and print MAD"},
    {"rdbl",        CmdHFMFPRdbl,            IfPm3Iso14443a,  "Read blocks from card"},
    {"rdsc",        CmdHFMFPRdsc,            IfPm3Iso14443a,  "Read sectors from card"},
    {"wrbl",        CmdHFMFPWrbl,            IfPm3Iso14443a,  "Write block to card"},
    {"-----------", CmdHelp,                 IfPm3Iso14443a,  "---------------- " _CYAN_("personalization") " -------------------"},
    {"commitp",     CmdHFMFPCommitPerso,     IfPm3Iso14443a,  "Configure security layer (SL1/SL3 mode)"},
    {"initp",       CmdHFMFPInitPerso,       IfPm3Iso14443a,  "Fill all the card's keys in SL0 mode"},
    {"wrp",         CmdHFMFPWritePerso,      IfPm3Iso14443a,  "Write Perso command"},
    {"-----------", CmdHelp,                 IfPm3Iso14443a,  "---------------------- " _CYAN_("ndef") " ------------------------"},
    {"ndefformat",  CmdHFMFPNDEFFormat,      IfPm3Iso14443a,  "Format MIFARE Plus Tag as NFC Tag"},
    {"ndefread",    CmdHFMFPNDEFRead,        IfPm3Iso14443a,  "Read and print NDEF records from card"},
    {"ndefwrite",   CmdHFMFPNDEFWrite,       IfPm3Iso14443a,  "Write NDEF records to card"},
    {NULL, NULL, 0, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFMFP(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

