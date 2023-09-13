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
// Support functions for smart card
//-----------------------------------------------------------------------------
#include "cardhelper.h"
#include <string.h>
#include <stdio.h>
#include "cmdparser.h"
#include "cmdsmartcard.h"
#include "ui.h"
#include "util.h"

#define CARD_INS_DECRYPT    0x01
#define CARD_INS_ENCRYPT    0x02
#define CARD_INS_VERIFY_RRG 0x05
#define CARD_INS_DECODE     0x06
#define CARD_INS_NUMBLOCKS  0x07
#define CARD_INS_PINSIZE    0x08
#define CARD_INS_CC         0x81
#define CARD_INS_CC_DESC    0x82

// look for CardHelper
bool IsCardHelperPresent(bool verbose) {

    if (IfPm3Smartcard() == false) {
        return false;
    }

    int resp_len = 0;
    uint8_t version[] = {0x96, 0x69, 0x00, 0x00, 0x00};
    uint8_t resp[30] = {0};
    ExchangeAPDUSC(verbose, version, sizeof(version), true, true, resp, sizeof(resp), &resp_len);

    if (resp_len < 8) {
        return false;
    }

    if (strstr("CryptoHelper", (char *)resp) == 0) {
        if (verbose) {
            PrintAndLogEx(INFO, "Found smart card helper");
        }
        return true;
    }
    return false;
}

bool IsHIDSamPresent(bool verbose) {

    if (IfPm3Smartcard() == false) {
        return false;
    }

    // detect SAM
    smart_card_atr_t card;
    smart_select(verbose, &card);
    if (!card.atr_len) {
        PrintAndLogEx(ERR, "Can't get ATR from a smart card");
        return false;
    }

    // SAM identification
    uint8_t sam_atr[] = {0x3B, 0x95, 0x96, 0x80, 0xB1, 0xFE, 0x55, 0x1F, 0xC7, 0x47, 0x72, 0x61, 0x63, 0x65, 0x13};
    if (memcmp(card.atr, sam_atr, card.atr_len) < 0) {

        uint8_t sam_atr2[] = {0x3b, 0x90, 0x96, 0x91, 0x81, 0xb1, 0xfe, 0x55, 0x1f, 0xc7, 0xd4};
        if (memcmp(card.atr, sam_atr2, card.atr_len) < 0) {
            if (verbose) {
                PrintAndLogEx(SUCCESS, "Not detecting a SAM");
            }
            return false;
        }
    }

    // Suspect some SAMs has version name in their ATR
    uint8_t T0 = card.atr[1];
    uint8_t K = T0 & 0x0F;
    if (K > 4 && verbose) {
        if (byte_strstr(card.atr, card.atr_len, (const uint8_t *)"Grace", 5) > -1) {
            PrintAndLogEx(SUCCESS, "SAM (Grace) detected");
        } else if (byte_strstr(card.atr, card.atr_len, (const uint8_t *)"Hopper", 6) > -1) {
            PrintAndLogEx(SUCCESS, "SAM (Hopper) detected");
        }
    }
    return true;
}

static bool executeCrypto(uint8_t ins, uint8_t *src, uint8_t *dest) {
    uint8_t cmd[] = {0x96, ins, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(cmd + 5, src, 8);

    int resp_len = 0;
    uint8_t dec[11] = {0};
    ExchangeAPDUSC(false, cmd, sizeof(cmd), true, true, dec, sizeof(dec), &resp_len);
    if (resp_len == 10) {
        memcpy(dest, dec, 8);
        return true;
    }
    return false;
}

bool Decrypt(uint8_t *src, uint8_t *dest) {
    return executeCrypto(CARD_INS_DECRYPT, src, dest);
}

bool Encrypt(uint8_t *src, uint8_t *dest) {
    return executeCrypto(CARD_INS_ENCRYPT, src, dest);
}

// Call with block6
void DecodeBlock6(uint8_t *src) {
    int resp_len = 0;
    uint8_t resp[254] = {0};

    uint8_t c[] = {0x96, CARD_INS_DECODE, 0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(c + 6, src, 8);

    // first part
    ExchangeAPDUSC(false, c, sizeof(c), false, true, resp, sizeof(resp), &resp_len);


    if (resp_len < 11) {
        return;
    }

    PrintAndLogEx(SUCCESS, "%.*s", resp_len - 11, resp + 9);

    // second part
    c[5] = 0x02;
    ExchangeAPDUSC(false, c, sizeof(c), false, false, resp, sizeof(resp), &resp_len);


    if (resp_len < 11) {
        return;
    }
    PrintAndLogEx(SUCCESS, "%.*s", resp_len - 11, resp + 9);
}

// Call with block6
uint8_t GetNumberBlocksForUserId(uint8_t *src) {
    int resp_len = 0;
    uint8_t resp[254] = {0};
    uint8_t c[] = {0x96, CARD_INS_NUMBLOCKS, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(c + 5, src, 8);
    ExchangeAPDUSC(false, c, sizeof(c), false, false, resp, sizeof(resp), &resp_len);


    if (resp_len < 8) {
        return 0;
    }

    return resp[8];
}

// Call with block6
uint8_t GetPinSize(uint8_t *src) {
    int resp_len = 0;
    uint8_t resp[254] = {0};
    uint8_t c[] = {0x96, CARD_INS_PINSIZE, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(c + 5, src, 8);
    ExchangeAPDUSC(false, c, sizeof(c), false, false, resp, sizeof(resp), &resp_len);
    if (resp_len < 2) {
        return 0;
    }

    if (resp[resp_len - 2] == 0x90 && resp[resp_len - 1] == 0x00) {
        return resp[8];
    }
    return 0;
}

int GetConfigCardByIdx(uint8_t typ, uint8_t *blocks) {
    if (blocks == NULL)
        return PM3_EINVARG;

    int resp_len = 0;
    uint8_t resp[254] = {0};
    uint8_t c[] = {0x96, CARD_INS_CC, 0x00, 0x00, 17, typ, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ExchangeAPDUSC(false, c, sizeof(c), false, true, resp, sizeof(resp), &resp_len);

    if (resp_len < 2) {
        return PM3_ESOFT;
    }

    if (resp[resp_len - 2] == 0x90 && resp[resp_len - 1] == 0x00) {
        memcpy(blocks, resp + 1, 16);
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}

int GetConfigCardStrByIdx(uint8_t typ, uint8_t *out) {
    if (out == NULL)
        return PM3_EINVARG;

    int resp_len = 0;
    uint8_t resp[254] = {0};
    uint8_t c[] = {0x96, CARD_INS_CC_DESC, 0x00, 0x00, 1, typ};
    ExchangeAPDUSC(false, c, sizeof(c), false, true, resp, sizeof(resp), &resp_len);

    if (resp_len < 2) {
        return PM3_ESOFT;
    }

    if (resp[resp_len - 2] == 0x90 && resp[resp_len - 1] == 0x00) {
        memcpy(out, resp + 1, resp_len - 2 - 1);
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}

int VerifyRdv4Signature(uint8_t *memid, uint8_t *signature) {
    if (memid == NULL || signature == NULL)
        return PM3_EINVARG;

    int resp_len = 0;
    uint8_t resp[254] = {0};
    uint8_t c[5 + 8 + 128] = {0x96, CARD_INS_VERIFY_RRG, 0x00, 0x00, 8 + 128};

    memcpy(c + 5, memid, 8);
    memcpy(c + 5 + 8, signature, 128);

    ExchangeAPDUSC(false, c, sizeof(c), true, false, resp, sizeof(resp), &resp_len);
    if (resp_len < 2) {
        return PM3_ESOFT;
    }

    if (memcmp(resp + resp_len - 4, "\x6f\x6b\x90\x00", 4) == 0) {
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}
