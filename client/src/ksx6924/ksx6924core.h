// -*- mode: c; indent-tabs-mode: nil; tab-width: 3 -*-
//-----------------------------------------------------------------------------
// Copyright (C) 2019 micolous+git@gmail.com
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// KS X 6924 (T-Money, Snapper+) protocol implementation
//-----------------------------------------------------------------------------

#ifndef __KSX6924CORE_H__
#define __KSX6924CORE_H__

#include <stddef.h>
#include <stdint.h>
#include "cmdhf14a.h"
#include "emv/emvcore.h"

// Convenience structure for representing a date. Actual on-card format is in
// _ksx6924_internal_date_t.
struct ksx6924_date {
    uint16_t year;
    uint8_t month;
    uint8_t day;
};

// Convenience structure for representing purse information.  Actual on-card
// format is in _ksx6924_internal_purse_info_t.
struct ksx6924_purse_info {
    uint8_t cardType;
    uint8_t alg;
    uint8_t vk;
    uint8_t idCenter;
    uint8_t csn[17]; // hex digits + null terminator
    uint64_t idtr;
    struct ksx6924_date issueDate;
    struct ksx6924_date expiryDate;
    uint8_t userCode;
    uint8_t disRate;
    uint32_t balMax;
    uint16_t bra;
    uint32_t mmax;
    uint8_t tcode;
    uint8_t ccode;
    uint8_t rfu[8];
};

// Get card type description
const char *KSX6924LookupCardType(uint8_t key, const char *defaultValue);

// Get encryption algorithm description
const char *KSX6924LookupAlg(uint8_t key, const char *defaultValue);

// Get IDCenter (issuer ID) description
const char *KSX6924LookupTMoneyIDCenter(uint8_t key, const char *defaultValue);

// Get UserCode (ticket type) description
const char *KSX6924LookupTMoneyUserCode(uint8_t key, const char *defaultValue);

// Get DisRate (discount type) description
const char *KSX6924LookupTMoneyDisRate(uint8_t key, const char *defaultValue);

// Get TCode (telecom carrier ID) description
const char *KSX6924LookupTMoneyTCode(uint8_t key, const char *defaultValue);

// Get CCode (credit card company ID) description
const char *KSX6924LookupTMoneyCCode(uint8_t key, const char *defaultValue);

// Parses purse info in FCI tag b0
bool KSX6924ParsePurseInfo(
    const uint8_t *purseInfo, size_t purseLen, struct ksx6924_purse_info *ret);

// Prints out a ksx6924_purse_info
void KSX6924PrintPurseInfo(const struct ksx6924_purse_info *purseInfo);

// Selects the KS X 6924 application, returns all information
int KSX6924Select(
    bool ActivateField, bool LeaveFieldON,
    uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);

// Selects the KS X 6924 application, returns true on success
bool KSX6924TrySelect(void);

// Gets the balance from a KS X 6924 card. Application must be already
// selected.
bool KSX6924GetBalance(uint32_t *result);

// Proprietary get record command. Function unknown.
// result must be 10 bytes long.
bool KSX6924ProprietaryGetRecord(
    uint8_t id, uint8_t *result, size_t resultLen);

#endif /* __KSX6924CORE_H__ */

