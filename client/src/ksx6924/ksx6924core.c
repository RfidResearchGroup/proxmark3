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
// KS X 6924 (T-Money, Snapper+) protocol implementation
//-----------------------------------------------------------------------------
// This is used in T-Money (South Korea) and Snapper plus (Wellington, New
// Zealand).
//
// References:
// - https://github.com/micolous/metrodroid/wiki/T-Money (in English)
// - https://github.com/micolous/metrodroid/wiki/Snapper (in English)
// - https://kssn.net/en/search/stddetail.do?itemNo=K001010104929
//   (KS X 6924, only available in Korean)
// - http://www.tta.or.kr/include/Download.jsp?filename=stnfile/TTAK.KO-12.0240_%5B2%5D.pdf
//   (TTAK.KO 12.0240, only available in Korean)
//-----------------------------------------------------------------------------

#include "ksx6924core.h"

#include <string.h>
#include "emv/emvcore.h"
#include "iso7816/apduinfo.h"
#include "fido/fidocore.h" // FIDOExchange
#include "protocols.h"
#include "ui.h"
#include "util.h"
#include "comms.h"         // clearCommandBuffer
#include "commonutil.h"    // ntohl (pm3 version)
#include "protocols.h"     // ISO7816 APDU return codes

// Date type. This is the actual on-card format.
typedef struct {
    uint8_t year[2];  // bcd
    uint8_t month[1]; // bcd
    uint8_t day[1];   // bcd
} PACKED _ksx6924_internal_date_t;

// Purse information (FCI tag b0). This is the actual on-card format.
typedef struct {
    uint8_t cardType;
    uint8_t alg;
    uint8_t vk;
    uint8_t idCenter;
    uint8_t csn[8];    // bcd
    uint8_t idtr[5];   // bcd
    _ksx6924_internal_date_t issueDate;
    _ksx6924_internal_date_t expiryDate;
    uint8_t userCode;
    uint8_t disRate;
    uint8_t balMax[4]; // uint32_t big-endian
    uint8_t bra[2];    // bcd
    uint8_t mmax[4];   // uint32_t big-endian
    uint8_t tcode;
    uint8_t ccode;
    uint8_t rfu[8];
} PACKED _ksx6924_internal_purse_info_t;

typedef struct {
    uint8_t ALGep;
    uint8_t VKep;
    uint8_t BALep[4];   // uint32_t big-endian
    uint8_t IDcenter;
    uint8_t IDep[8];    // bcd
    uint8_t NTep[4];
    uint8_t Sign1[4];
} PACKED _ksx6924_initialize_card_response_t;

// Declares a structure for simple enums.
#define MAKE_ENUM_TYPE(KEY_TYPE) \
   struct _ksx6924_enum_ ## KEY_TYPE { \
      KEY_TYPE key; \
      const char *value; \
   }; \
   static int _ksx6924_ ## KEY_TYPE ## _enum_compare( \
         const void *a, const void *b) { \
      const KEY_TYPE *needle = a; \
      const struct _ksx6924_enum_ ## KEY_TYPE *candidate = b; \
      return (*needle) - (candidate->key); \
   }

// Declares a enum, and builds a KSX6924Lookup* function to point to it.
#define MAKE_ENUM_CONST(NAME, KEY_TYPE, VALS...) \
   static const struct _ksx6924_enum_ ## KEY_TYPE KSX6924_ENUM_ ## NAME [] = { \
      VALS \
   }; \
   const char* KSX6924Lookup ## NAME ( \
         KEY_TYPE key, const char* defaultValue) { \
      struct _ksx6924_enum_ ## KEY_TYPE *r = bsearch( \
         &key, KSX6924_ENUM_ ## NAME, \
         ARRAYLEN(KSX6924_ENUM_ ## NAME), \
         sizeof(KSX6924_ENUM_ ## NAME [0]), \
         _ksx6924_ ## KEY_TYPE ## _enum_compare); \
      if (r == NULL) { \
         return defaultValue; \
      } \
      return r->value; \
   }

MAKE_ENUM_TYPE(uint8_t);

// KSX6924LookupCardType
MAKE_ENUM_CONST(CardType, uint8_t,
{ 0x00, "Pre-paid" },
{ 0x10, "Post-pay" },
{ 0x20, "Mobile post-pay" },
               );

// KSX6924LookupAlg
MAKE_ENUM_CONST(Alg, uint8_t,
{ 0x00, "SEED" },
{ 0x10, "3DES" },
               );

// KSX6924LookupTMoneyIDCenter
MAKE_ENUM_CONST(TMoneyIDCenter, uint8_t,
{ 0x00, "Reserved" },
{ 0x01, "Korea Financial Telecommunications and Clearings Institute" },
{ 0x02, "A-Cash" },
{ 0x03, "Mybi" },
{ 0x04, "Reserved" },
{ 0x05, "V-Cash" },
{ 0x06, "Mondex Korea" },
{ 0x07, "Korea Expressway Corporation" },
{ 0x08, "Tmoney Co., Ltd." },
{ 0x09, "KORAIL Networks" },
{ 0x0a, "Reserved" },
{ 0x0b, "EB Card Corporation" },
{ 0x0c, "Seoul Bus Transport Association" },
{ 0x0d, "Cardnet" },
               );

// KSX6924LookupTMoneyUserCode
MAKE_ENUM_CONST(TMoneyUserCode, uint8_t,
{ 0x01, "Regular/normal" },
{ 0x02, "Child" },

{ 0x04, "Youth" },

{ 0x06, "elderly" },

{ 0x0f, "Test" },
{ 0xff, "Inactive" },
               );

// KSX6924LookupTMoneyDisRate
MAKE_ENUM_CONST(TMoneyDisRate, uint8_t,
{ 0x00, "No discount" },

{ 0x10, "Disabled, basic" },
{ 0x11, "Disabled, companion" },

{ 0x20, "Merit, basic" },
{ 0x21, "Merit, companion" },
               );

// KSX6924LookupTMoneyTCode
MAKE_ENUM_CONST(TMoneyTCode, uint8_t,
{ 0x00, "None" },
{ 0x01, "SK Telecom" },
{ 0x02, "Korea Telecom" },
{ 0x03, "LG Uplus" },
               );

// KSX6924LookupTMoneyCCode
MAKE_ENUM_CONST(TMoneyCCode, uint8_t,
{ 0x00, "None" },
{ 0x01, "KB Card" },
{ 0x02, "NH Card" },
{ 0x03, "Lotte Card" },
{ 0x04, "BC Card" },
{ 0x05, "Samsung Card" },
{ 0x06, "Shinhan Card" },
{ 0x07, "Citibank Korea" },
{ 0x08, "Korea Exchange Bank" },
{ 0x09, "Woori Card" },
{ 0x0a, "Hana SK Card" },
{ 0x0b, "Hyundai Card" },
               );

static const char *KSX6924_UNKNOWN = "Unknown";

/**
 * Converts a single byte in binary-coded decimal format to an integer.
 *
 * Expected return values are between 0-99 inclusive.
 *
 * Returns -1 on invalid input.
 *
 * Examples:
 *   bcdToInteger(0x35) = 35 (decimal)
 *   bcdToInteger(0x58) = 58 (decimal)
 *   bcdToInteger(0xf4) = -1 (invalid)
 */
static int16_t bcdToInteger(const uint8_t i) {
    uint16_t high = ((i & 0xf0) >> 4) * 10;
    uint16_t low = (i & 0xf);

    if (high >= 100 || low >= 10) {
        // Invalid
        return -1;
    }

    return high + low;
}


/**
 * Converts multiple bytes in binary-coded decimal format to an integer.
 *
 * Expected return values are 0-(100^len).
 *
 * Returns -1 on invalid input.
 *
 * Example:
 *   bcdToLong({0x12, 0x34}, 2) = 1234 (decimal)
 */
static int64_t bcdToLong(const uint8_t *buf, size_t len) {
    int64_t o = 0;
    for (int i = 0; i < len; i++) {
        int16_t t = bcdToInteger(buf[i]);
        if (t < 0) {
            // invalid
            return -1;
        }

        o = (o * 100) + t;
    }

    return o;
}


/**
 * Converts a date from on-card format to ksx6924_date format.
 */
static bool convert_internal_date(const _ksx6924_internal_date_t i, struct ksx6924_date *ret) {

    int64_t year = bcdToLong(i.year, 2);
    int16_t month = bcdToInteger(i.month[0]);
    int16_t day = bcdToInteger(i.day[0]);

    if (year < 0 || year > 0xFFFF || month < 0 || day < 0) {
        memset(ret, 0, sizeof(struct ksx6924_date));
        return false;
    }

    ret->year = year & 0xFFFF;
    ret->month = month;
    ret->day = day;
    return true;
}


/**
 * Parses purse info in FCI tag b0
 */
bool KSX6924ParsePurseInfo(const uint8_t *purseInfo, size_t purseLen, struct ksx6924_purse_info *ret) {

    memset(ret, 0, sizeof(struct ksx6924_purse_info));

    if (purseLen != sizeof(_ksx6924_internal_purse_info_t)) {
        // Invalid size!
        PrintAndLogEx(FAILED, "Expected %ld bytes, got %ld\n", sizeof(_ksx6924_internal_purse_info_t), purseLen);
        return false;
    }

    const _ksx6924_internal_purse_info_t *internalPurseInfo = (const _ksx6924_internal_purse_info_t *)purseInfo;

    // Simple copies
    ret->cardType = internalPurseInfo->cardType;
    ret->alg = internalPurseInfo->alg;
    ret->vk = internalPurseInfo->vk;
    ret->idCenter = internalPurseInfo->idCenter;
    ret->userCode = internalPurseInfo->userCode;
    ret->disRate = internalPurseInfo->disRate;
    ret->tcode = internalPurseInfo->tcode;
    ret->ccode = internalPurseInfo->ccode;

    // Fields that need rewriting
    hex_to_buffer(ret->csn, internalPurseInfo->csn,
                  sizeof(internalPurseInfo->csn),
                  sizeof(ret->csn) - 1,
                  0,    // min_str_len
                  0,    // spaces_between
                  false // uppercase
                 );

    int64_t idtr = bcdToLong(internalPurseInfo->idtr, 5);
    if (idtr < 0) {
        idtr = 0; // fail
    }
    ret->idtr = idtr;

    int64_t bra = bcdToLong(internalPurseInfo->bra, 2);
    if (bra < 0) {
        bra = 0; // fail
    }

    ret->bra = bra & 0xFFFF;

    convert_internal_date(internalPurseInfo->issueDate, &(ret->issueDate));
    convert_internal_date(internalPurseInfo->expiryDate, &(ret->expiryDate));

    ret->balMax = MemBeToUint4byte((uint8_t *)internalPurseInfo->balMax);
    ret->mmax = MemBeToUint4byte((uint8_t *)internalPurseInfo->mmax);

    memcpy(&ret->rfu, &internalPurseInfo->rfu, 8);

    // TODO
    return true;
};

/**
 * Prints out a ksx6924_purse_info
 */
void KSX6924PrintPurseInfo(const struct ksx6924_purse_info *purseInfo) {

    if (purseInfo == NULL) {
        return;
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("KS X 6924 Purse Info") " ---------------------------");
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "  cardType .............................. %02x ( %s )", purseInfo->cardType,
                  KSX6924LookupCardType(purseInfo->cardType, KSX6924_UNKNOWN));
    PrintAndLogEx(INFO, "  alg (encryption algorithm) ............ %02x ( %s )", purseInfo->alg,
                  KSX6924LookupAlg(purseInfo->alg, KSX6924_UNKNOWN));
    PrintAndLogEx(INFO, "  vk (keyset version) ................... %02x", purseInfo->vk);
    PrintAndLogEx(INFO, "  idCenter (issuer ID) .................. %02x ( %s )", purseInfo->idCenter,
                  KSX6924LookupTMoneyIDCenter(purseInfo->idCenter, KSX6924_UNKNOWN));
    PrintAndLogEx(INFO, "  CSN (card number) ..................... %s", purseInfo->csn);
    PrintAndLogEx(INFO, "  idtr (card usage authentication ID) ... %" PRIu64, purseInfo->idtr);
    PrintAndLogEx(INFO, "  issue date ............................ %04i-%02i-%02i",
                  purseInfo->issueDate.year,
                  purseInfo->issueDate.month,
                  purseInfo->issueDate.day);
    PrintAndLogEx(INFO, "  expiry date ........................... %04i-%02i-%02i",
                  purseInfo->expiryDate.year,
                  purseInfo->expiryDate.month,
                  purseInfo->expiryDate.day);
    PrintAndLogEx(INFO, "  user code (ticket type) ............... %02x ( %s )", purseInfo->userCode,
                  KSX6924LookupTMoneyUserCode(purseInfo->userCode, KSX6924_UNKNOWN));
    PrintAndLogEx(INFO, "  disRate (discount type) ............... %02x ( %s )", purseInfo->disRate,
                  KSX6924LookupTMoneyDisRate(purseInfo->disRate, KSX6924_UNKNOWN));
    PrintAndLogEx(INFO, "  balMax (in won/cents) ................. %" PRIu32, purseInfo->balMax);
    PrintAndLogEx(INFO, "  bra (branch code) ..................... %04x", purseInfo->bra);
    PrintAndLogEx(INFO, "  mmax (one-time transaction limit) ..... %" PRIu32, purseInfo->mmax);
    PrintAndLogEx(INFO, "  tcode (telecom carrier ID) ............ %02x ( %s )", purseInfo->tcode,
                  KSX6924LookupTMoneyTCode(purseInfo->tcode, KSX6924_UNKNOWN));
    PrintAndLogEx(INFO, "  ccode (credit card company ID) ........ %02x ( %s )", purseInfo->ccode,
                  KSX6924LookupTMoneyCCode(purseInfo->ccode, KSX6924_UNKNOWN));
    PrintAndLogEx(INFO, "  rfu (reserved) ........................ %s", sprint_hex(purseInfo->rfu, sizeof(purseInfo->rfu)));
    PrintAndLogEx(INFO, "");
}

/**
 * Selects the KS X 6924 Application, D4100000030001, and returns the response
 * data.
 */
int KSX6924Select(bool ActivateField, bool LeaveFieldON, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {

    // T-Money + Snapper
    uint8_t aid[] = {0xD4, 0x10, 0x00, 0x00, 0x03, 0x00, 0x01};

    // Cashbee
    //uint8_t aid[] = {0xD4, 0x10, 0x00, 0x00, 0x14, 0x00, 0x01};
    return EMVSelect(CC_CONTACTLESS,
                     ActivateField,
                     LeaveFieldON,
                     aid,
                     sizeof(aid),
                     Result,
                     MaxResultLen,
                     ResultLen,
                     sw,
                     NULL
                    );
}

/**
 * Selects the KS X 6924 Application. Returns true if selected successfully.
 */
bool KSX6924TrySelect(void) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = KSX6924Select(true, true, buf, sizeof(buf), &len, &sw);

    if (res) {
        DropField();
        return false;
    }

    if (sw != ISO7816_OK) {
        if (sw) {
            PrintAndLogEx(FAILED,
                          "Not a KS X 6924 card! APDU response: %04x - %s",
                          sw,
                          GetAPDUCodeDescription(sw >> 8, sw & 0xff)
                         );
        } else {
            PrintAndLogEx(FAILED, "APDU exchange error. Card returns 0x0000.");
        }
        return false;
    }

    return true;
}


/**
 * Gets the balance from a KS X 6924 card.
 */
bool KSX6924GetBalance(uint32_t *result) {
    if (result == NULL) {
        return false;
    }

    *result = 0;

    uint8_t arr[4 + 2]; // message , sw
    //uint8_t apdu[] = {0x90, 0x4c, 0x00, 0x00, 4, arr};
    memset(arr, 0, sizeof(arr));

    uint8_t data[] = {0x00, 0x00, 0x00, 0x00};

    uint16_t sw = 0;
    size_t rlen = 0;

    int res = FIDOExchange((sAPDU_t) {0x90, 0x4c, 0x00, 0x00, 4, data}, arr, sizeof(arr), &rlen, &sw);

    if (res) {
        return false;
    }

    if (sw != ISO7816_OK) {
        return false;
    }

    *result =  MemBeToUint4byte((uint8_t *)arr);
    return true;
}


/**
 * Perform transaction initialization.
 */
bool KSX6924InitializeCard(uint8_t mpda1, uint8_t mpda2, uint8_t mpda3, uint8_t mpda4, uint8_t *result, size_t *result_len) {

    if (result == NULL) {
        return false;
    }

    *result = 0;
    uint16_t sw = 0;
    size_t rlen = 0;

    //  ALGep +  VKep + BALep + IDcenter + IDep + NTep + Sign1 +  sw
    uint8_t arr[1 + 1 + 4 + 1 + 8 + 4 + 4 + 2];
    memset(arr, 0, sizeof(arr));

    uint8_t data[] = {mpda1, mpda2, mpda3, mpda4};
    int res = FIDOExchange((sAPDU_t) {0x90, 0x02, 0x00, 0x00, 0x04, data}, arr, sizeof(arr), &rlen, &sw);
    if (res) {
        return false;
    }

    if (sw != ISO7816_OK) {
        return false;
    }

    //*result = ntohl(*(uint32_t*)(arr));
    memcpy(result, arr, rlen + 2); // skip 2 sw bytes
    memcpy(result_len, &rlen, sizeof(size_t));
    return true;
}

/**
 * Parses Initialize Card response
 */
bool KSX6924ParseInitializeCardResponse(const uint8_t *initCardResponse, size_t resp_len, struct ksx6924_initialize_card_response *ret) {

    memset(ret, 0, sizeof(struct ksx6924_initialize_card_response));

    if (resp_len != sizeof(_ksx6924_initialize_card_response_t)) {
        // Invalid size!
        PrintAndLogEx(FAILED, "Expected %ld bytes, got %ld\n", sizeof(_ksx6924_initialize_card_response_t), resp_len);
        return false;
    }

    const _ksx6924_initialize_card_response_t *internalInitCardResponse = (const _ksx6924_initialize_card_response_t *)initCardResponse;

    // Simple copies
    ret->ALGep = internalInitCardResponse->ALGep;
    ret->VKep = internalInitCardResponse->VKep;
    ret->IDcenter = internalInitCardResponse->IDcenter;

    // Fields that need rewriting
    hex_to_buffer(ret->IDep, internalInitCardResponse->IDep,
                  sizeof(internalInitCardResponse->IDep),
                  sizeof(ret->IDep) - 1,
                  0,    // min_str_len
                  0,    // spaces_between
                  false // uppercase
                 );

    ret->BALep = MemBeToUint4byte((uint8_t *)internalInitCardResponse->BALep);
    ret->NTep = MemBeToUint4byte((uint8_t *)internalInitCardResponse->NTep);

    memcpy(&ret->Sign1, &internalInitCardResponse->Sign1, 4);

    // TODO
    return true;
};

/**
 * Prints out a Initialize Card response
 */
void KSX6924PrintInitializeCardResponse(const struct ksx6924_initialize_card_response *response) {

    if (response == NULL) {
        return;
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("KS X 6924 Initialize Card Response") " ---------------------------");
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "  ALGep (Algorithm Identifier)........ %02x ( %s )", response->ALGep, KSX6924LookupAlg(response->ALGep, KSX6924_UNKNOWN));
    PrintAndLogEx(INFO, "  VKep (Version of Key) .............. %02x", response->VKep);
    PrintAndLogEx(INFO, "  BALep (Balance...................... %" PRIu32, response->BALep);
    PrintAndLogEx(INFO, "  IDcenter (Issuer ID) ............... %02x ( %s )", response->IDcenter, KSX6924LookupTMoneyIDCenter(response->IDcenter, KSX6924_UNKNOWN));
    PrintAndLogEx(INFO, "  IDep (Card number) ................. %s", response->IDep);
    PrintAndLogEx(INFO, "  NTep (Number of Transaction + 1) ... %" PRIu32, response->NTep);
    PrintAndLogEx(INFO, "  Sign1 .............................. %s", sprint_hex(response->Sign1, sizeof(response->Sign1)));
    PrintAndLogEx(INFO, "");
}

/**
 * Issues a proprietary "get record" command (CLA=90, INS=4C).
 *
 * The function of these records is not known, but they are present on KS X
 * 6924 cards and used by the official mobile apps.
 *
 * result must be a buffer of 16 bytes. The card will only respond to 16 byte
 * requests.
 *
 * Returns false on error.
 */
bool KSX6924ProprietaryGetRecord(uint8_t id, uint8_t *result, size_t result_len) {
    if (result == NULL) {
        return false;
    }
    memset(result, 0, result_len);

    uint8_t arr[result_len + 2]; // message + sw
    memset(arr, 0, sizeof(arr));

    uint16_t sw = 0;
    size_t rlen = 0;

    //uint8_t apdu[] = {0x90, 0x78, id, 0x00, resultLen, arr};
    int res = FIDOExchange((sAPDU_t) {0x90, 0x78, id, 0x00, result_len, arr}, arr, sizeof(arr), &rlen, &sw);
    if (res) {
        return false;
    }

    if (sw != ISO7816_OK) {
        return false;
    }

    memcpy(result, arr, result_len);
    return true;
}

