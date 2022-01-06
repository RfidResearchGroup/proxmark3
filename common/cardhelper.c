//-----------------------------------------------------------------------------
// Iceman, February 2020
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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

    if (IfPm3Smartcard()) {
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
    }
    return false;
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
