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
// EMV core functionality
//-----------------------------------------------------------------------------

#ifndef EMVCORE_H__
#define EMVCORE_H__

#include "common.h"

#include <inttypes.h>
#include <jansson.h>

#include "iso7816/apduinfo.h"
#include "iso7816/iso7816core.h"
#include "emv_pki.h"

typedef enum TransactionType {
    TT_MSD,
    TT_VSDC,        // contact only. not standard for contactless
    TT_QVSDCMCHIP,
    TT_CDA,
    TT_END,
} TransactionType_t;
extern const char *TransactionTypeStr[];

enum CardPSVendor {
    CV_NA,
    CV_VISA,
    CV_MASTERCARD,
    CV_AMERICANEXPRESS,
    CV_JCB,
    CV_CB,
    CV_SWITCH,
    CV_DINERS,
    CV_OTHER,
};
enum CardPSVendor GetCardPSVendor(uint8_t *AID, size_t AIDlen);

bool TLVPrintFromBuffer(uint8_t *data, int datalen);
void TLVPrintFromTLV(struct tlvdb *tlv);
void TLVPrintFromTLVLev(struct tlvdb *tlv, int level);
void TLVPrintAIDlistFromSelectTLV(struct tlvdb *tlv);

struct tlvdb *GetPANFromTrack2(const struct tlv *track2);
struct tlvdb *GetdCVVRawFromTrack2(const struct tlv *track2);

// exchange
int EMVExchange(Iso7816CommandChannel channel, bool LeaveFieldON, sAPDU_t apdu, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);

// search application
int EMVSearchPSE(Iso7816CommandChannel channel, bool ActivateField, bool LeaveFieldON, uint8_t PSENum, bool decodeTLV, struct tlvdb *tlv);
int EMVSearch(Iso7816CommandChannel channel, bool ActivateField, bool LeaveFieldON, bool decodeTLV, struct tlvdb *tlv, bool verbose);
int EMVSelectPSE(Iso7816CommandChannel channel, bool ActivateField, bool LeaveFieldON, uint8_t PSENum, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
int EMVSelect(Iso7816CommandChannel channel, bool ActivateField, bool LeaveFieldON, uint8_t *AID, size_t AIDLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);
// select application
int EMVSelectApplication(struct tlvdb *tlv, uint8_t *AID, size_t *AIDlen);
// Get Processing Options
int EMVGPO(Iso7816CommandChannel channel, bool LeaveFieldON, uint8_t *PDOL, size_t PDOLLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);
int EMVReadRecord(Iso7816CommandChannel channel, bool LeaveFieldON, uint8_t SFI, uint8_t SFIrec, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);

// Emv override get data
int EMVGetData(Iso7816CommandChannel channel, bool LeaveFieldON, uint16_t foo, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);
// AC
int EMVGenerateChallenge(Iso7816CommandChannel channel, bool LeaveFieldON, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);
int EMVAC(Iso7816CommandChannel channel, bool LeaveFieldON, uint8_t RefControl, uint8_t *CDOL, size_t CDOLLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);
// DDA
int EMVInternalAuthenticate(Iso7816CommandChannel channel, bool LeaveFieldON, uint8_t *DDOL, size_t DDOLLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);
// Mastercard
int MSCComputeCryptoChecksum(Iso7816CommandChannel channel, bool LeaveFieldON, uint8_t *UDOL, uint8_t UDOLlen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);
// Auth
int trSDA(struct tlvdb *tlv);
int trDDA(Iso7816CommandChannel channel, bool decodeTLV, struct tlvdb *tlv);
int trCDA(struct tlvdb *tlv, struct tlvdb *ac_tlv, struct tlv *pdol_data_tlv, struct tlv *ac_data_tlv);

int RecoveryCertificates(struct tlvdb *tlvRoot, json_t *root);

struct emv_pk *get_ca_pk(struct tlvdb *db);
#endif
