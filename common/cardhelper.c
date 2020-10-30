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
#define CARD_INS_DECODE     0x06
#define CARD_INS_NUMBLOCKS  0x07
#define CARD_INS_PINSIZE    0x08
static uint8_t cmd[] = {0x96, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// look for CryptoHelper
bool IsCryptoHelperPresent(bool verbose) {

    if (IfPm3Smartcard()) {
        int resp_len = 0;
        uint8_t version[] = {0x96, 0x69, 0x00, 0x00, 0x00};
        uint8_t resp[20] = {0};
        ExchangeAPDUSC(true, version, sizeof(version), true, true, resp, sizeof(resp), &resp_len);

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
    int resp_len = 0;
    uint8_t dec[11] = {0};

    cmd[1] = ins;
    memcpy(cmd + 5, src, 8);

    ExchangeAPDUSC(true, cmd, sizeof(cmd), false, true, dec, sizeof(dec), &resp_len);

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
    ExchangeAPDUSC(true, c, sizeof(c), false, true, resp, sizeof(resp), &resp_len);
    PrintAndLogEx(SUCCESS, "%.*s", resp_len - 11, resp + 9);

    // second part
    c[5] = 0x02;
    ExchangeAPDUSC(true, c, sizeof(c), false, true, resp, sizeof(resp), &resp_len);
    PrintAndLogEx(SUCCESS, "%.*s", resp_len - 11, resp + 9);
}

// Call with block6
uint8_t GetNumberBlocksForUserId(uint8_t *src) {
    int resp_len = 0;
    uint8_t resp[254] = {0};
    uint8_t c[] = {0x96, CARD_INS_NUMBLOCKS, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(c + 5, src, 8);
    ExchangeAPDUSC(true, c, sizeof(c), false, true, resp, sizeof(resp), &resp_len);
    return resp[8];
}

// Call with block6
uint8_t GetPinSize(uint8_t *src) {
    int resp_len = 0;
    uint8_t resp[254] = {0};
    uint8_t c[] = {0x96, CARD_INS_PINSIZE, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(c + 5, src, 8);
    ExchangeAPDUSC(true, c, sizeof(c), false, true, resp, sizeof(resp), &resp_len);

    if (resp[resp_len - 2] == 0x90 && resp[resp_len - 1] == 0x00) {
        return resp[8];
    }
    return 0;
}
