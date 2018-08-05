//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// EMV core functionality
//-----------------------------------------------------------------------------

#ifndef EMVCORE_H__
#define EMVCORE_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include "util.h"
#include "common.h"
#include "ui.h"
#include "cmdhf14a.h"
#include "apduinfo.h"
#include "tlv.h"
#include "dol.h"
#include "dump.h"
#include "emv_tags.h"
#include "emv_pk.h"
#include "emv_pki.h"

#define APDU_RES_LEN 260
#define APDU_AID_LEN 50

enum TransactionType {
	TT_MSD,
	TT_VSDC,        // not standart for contactless!!!!
	TT_QVSDCMCHIP,
	TT_CDA,
};

typedef struct {
	uint8_t CLA;
	uint8_t INS;
	uint8_t P1;
	uint8_t P2;
	uint8_t Lc;
	uint8_t *data;
} sAPDU;

enum CardPSVendor {
	CV_NA,
	CV_VISA,
	CV_MASTERCARD,
	CV_AMERICANEXPRESS,
	CV_JCB,
	CV_CB,
	CV_OTHER,
};
extern enum CardPSVendor GetCardPSVendor(uint8_t * AID, size_t AIDlen);

extern void TLVPrintFromBuffer(uint8_t *data, int datalen);
extern void TLVPrintFromTLV(struct tlvdb *tlv);
extern void TLVPrintFromTLVLev(struct tlvdb *tlv, int level);
extern void TLVPrintAIDlistFromSelectTLV(struct tlvdb *tlv);

extern struct tlvdb *GetPANFromTrack2(const struct tlv *track2);
extern struct tlvdb *GetdCVVRawFromTrack2(const struct tlv *track2);

extern void SetAPDULogging(bool logging);

// search application
extern int EMVSearchPSE(bool ActivateField, bool LeaveFieldON, bool decodeTLV, struct tlvdb *tlv);
extern int EMVSearch(bool ActivateField, bool LeaveFieldON, bool decodeTLV, struct tlvdb *tlv);
extern int EMVSelectPSE(bool ActivateField, bool LeaveFieldON, uint8_t PSENum, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
extern int EMVSelect(bool ActivateField, bool LeaveFieldON, uint8_t *AID, size_t AIDLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);
// select application
extern int EMVSelectApplication(struct tlvdb *tlv, uint8_t *AID, size_t *AIDlen);
// Get Processing Options
extern int EMVGPO(bool LeaveFieldON, uint8_t *PDOL, size_t PDOLLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);
extern int EMVReadRecord(bool LeaveFieldON, uint8_t SFI, uint8_t SFIrec, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);
// AC
extern int EMVGenerateChallenge(bool LeaveFieldON, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);
extern int EMVAC(bool LeaveFieldON, uint8_t RefControl, uint8_t *CDOL, size_t CDOLLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);
// DDA
extern int EMVInternalAuthenticate(bool LeaveFieldON, uint8_t *DDOL, size_t DDOLLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);
// Mastercard
int MSCComputeCryptoChecksum(bool LeaveFieldON, uint8_t *UDOL, uint8_t UDOLlen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv);
// Auth
extern int trSDA(struct tlvdb *tlv);
extern int trDDA(bool decodeTLV, struct tlvdb *tlv);
extern int trCDA(struct tlvdb *tlv, struct tlvdb *ac_tlv, struct tlv *pdol_data_tlv, struct tlv *ac_data_tlv);

#endif




