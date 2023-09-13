//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/lumag/emv-tools/
// Copyright (C) 2012, 2015 Dmitry Eremin-Solenikov
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
// libopenemv - a library to work with EMV family of smart cards
//-----------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "emv_tags.h"
#include <stdlib.h>
#include <string.h>
#include "commonutil.h"
#include "ui.h"

enum emv_tag_t {
    EMV_TAG_GENERIC,
    EMV_TAG_BITMASK,
    EMV_TAG_DOL,
    EMV_TAG_CVM_LIST,
    EMV_TAG_AFL,
    EMV_TAG_STRING,
    EMV_TAG_NUMERIC,
    EMV_TAG_YYMMDD,
    EMV_TAG_CVR,
    EMV_TAG_CID,
};

struct emv_tag {
    tlv_tag_t tag;
    const char *name;
    enum emv_tag_t type;
    const void *data;
};

struct emv_tag_bit {
    unsigned bit;
    const char *name;
};

#define EMV_BIT(byte, bit) ((byte - 1) * 8 + (8 - bit))
#define EMV_BIT_FINISH { (~0), NULL }

static const struct emv_tag_bit EMV_AIP[] = {
    { EMV_BIT(1, 7), "SDA supported" },
    { EMV_BIT(1, 6), "DDA supported" },
    { EMV_BIT(1, 5), "Cardholder verification is supported" },
    { EMV_BIT(1, 4), "Terminal risk management is to be performed" },
    { EMV_BIT(1, 3), "Issuer authentication is supported" },
    { EMV_BIT(1, 2), "Reserved for use by the EMV Contactless Specifications" },
    { EMV_BIT(1, 1), "CDA supported (Combined Dynamic Data Authentication / Application Cryptogram Generation)" },
    { EMV_BIT(2, 8), "MSD is supported (Magnetic Stripe Data)" },
    { EMV_BIT(2, 7), "Reserved for use by the EMV Contactless Specifications" },
    { EMV_BIT(2, 6), "Reserved for use by the EMV Contactless Specifications" },
    { EMV_BIT(2, 1), "Reserved for use by the EMV Contactless Specifications" },
    EMV_BIT_FINISH,
};

static const struct emv_tag_bit EMV_AUC[] = {
    { EMV_BIT(1, 8), "Valid for domestic cash transactions" },
    { EMV_BIT(1, 7), "Valid for international cash transactions" },
    { EMV_BIT(1, 6), "Valid for domestic goods" },
    { EMV_BIT(1, 5), "Valid for international goods" },
    { EMV_BIT(1, 4), "Valid for domestic services" },
    { EMV_BIT(1, 3), "Valid for international services" },
    { EMV_BIT(1, 2), "Valid for ATMs" },
    { EMV_BIT(1, 1), "Valid at terminals other than ATMs" },
    { EMV_BIT(2, 8), "Domestic cashback allowed" },
    { EMV_BIT(2, 7), "International cashback allowed" },
    EMV_BIT_FINISH,
};

static const struct emv_tag_bit EMV_TVR[] = {
    { EMV_BIT(1, 8), "Offline data authentication was not performed" },
    { EMV_BIT(1, 7), "SDA failed" },
    { EMV_BIT(1, 6), "ICC data missing" },
    { EMV_BIT(1, 5), "Card appears on terminal exception file" },
    { EMV_BIT(1, 4), "DDA failed" },
    { EMV_BIT(1, 3), "CDA failed" },
    { EMV_BIT(1, 2), "SDA selected" },
    { EMV_BIT(2, 8), "ICC and terminal have different application versions" },
    { EMV_BIT(2, 7), "Expired application" },
    { EMV_BIT(2, 6), "Application not yet effective" },
    { EMV_BIT(2, 5), "Requested service not allowed for card product" },
    { EMV_BIT(2, 4), "New card" },
    { EMV_BIT(3, 8), "Cardholder verification was not successful" },
    { EMV_BIT(3, 7), "Unrecognised CVM" },
    { EMV_BIT(3, 6), "PIN Try Limit exceeded" },
    { EMV_BIT(3, 5), "PIN entry required and PIN pad not present or not working" },
    { EMV_BIT(3, 4), "PIN entry required, PIN pad present, but PIN was not entered" },
    { EMV_BIT(3, 3), "Online PIN entered" },
    { EMV_BIT(4, 8), "Transaction exceeds floor limit" },
    { EMV_BIT(4, 7), "Lower consecutive offline limit exceeded" },
    { EMV_BIT(4, 6), "Upper consecutive offline limit exceeded" },
    { EMV_BIT(4, 5), "Transaction selected randomly for online processing" },
    { EMV_BIT(4, 4), "Merchant forced transaction online" },
    { EMV_BIT(5, 8), "Default TDOL used" },
    { EMV_BIT(5, 7), "Issuer authentication failed" },
    { EMV_BIT(5, 6), "Script processing failed before final GENERATE AC" },
    { EMV_BIT(5, 5), "Script processing failed after final GENERATE AC" },
    { EMV_BIT(5, 4), "Reserved for use by the EMV Contactless Specifications" },
    { EMV_BIT(5, 3), "Reserved for use by the EMV Contactless Specifications" },
    { EMV_BIT(5, 2), "Reserved for use by the EMV Contactless Specifications" },
    { EMV_BIT(5, 1), "Reserved for use by the EMV Contactless Specifications" },
    EMV_BIT_FINISH,
};

static const struct emv_tag_bit EMV_CTQ[] = {
    { EMV_BIT(1, 8), "Online PIN Required" },
    { EMV_BIT(1, 7), "Signature Required" },
    { EMV_BIT(1, 6), "Go Online if Offline Data Authentication Fails and Reader is online capable" },
    { EMV_BIT(1, 5), "Switch Interface if Offline Data Authentication fails and Reader supports VIS" },
    { EMV_BIT(1, 4), "Go Online if Application Expired" },
    { EMV_BIT(1, 3), "Switch Interface for Cash Transactions" },
    { EMV_BIT(1, 2), "Switch Interface for Cashback Transactions" },
    { EMV_BIT(2, 8), "Consumer Device CVM Performed" },
    { EMV_BIT(2, 7), "Card supports Issuer Update Processing at the POS" },
    EMV_BIT_FINISH,
};

static const struct emv_tag_bit EMV_TTQ[] = {
    { EMV_BIT(1, 8), "MSD supported" },
    { EMV_BIT(1, 7), "VSDC supported" },
    { EMV_BIT(1, 6), "qVSDC supported" },
    { EMV_BIT(1, 5), "EMV contact chip supported" },
    { EMV_BIT(1, 4), "Offline-only reader" },
    { EMV_BIT(1, 3), "Online PIN supported" },
    { EMV_BIT(1, 2), "Signature supported" },
    { EMV_BIT(1, 1), "Offline Data Authentication (ODA) for Online Authorizations supported\nWarning!!!! Readers compliant to this specification set TTQ byte 1 bit 1 (this field) to 0b" },
    { EMV_BIT(2, 8), "Online cryptogram required" },
    { EMV_BIT(2, 7), "CVM required" },
    { EMV_BIT(2, 6), "(Contact Chip) Offline PIN supported" },
    { EMV_BIT(3, 8), "Issuer Update Processing supported" },
    { EMV_BIT(3, 7), "Mobile functionality supported (Consumer Device CVM)" },
    EMV_BIT_FINISH,
};

static const struct emv_tag_bit EMV_CVR[] = {
    // mask 0F 0F F0 0F
    { EMV_BIT(1, 4), "CDA Performed" },
    { EMV_BIT(1, 3), "Offline DDA Performed" },
    { EMV_BIT(1, 2), "Issuer Authentication Not Performed" },
    { EMV_BIT(1, 1), "Issuer Authentication performed and Failed" },
    { EMV_BIT(2, 4), "Offline PIN Verification Performed" },
    { EMV_BIT(2, 3), "Offline PIN Verification Performed and PIN Not Successfully Verified" },
    { EMV_BIT(2, 2), "PIN Try Limit Exceeded" },
    { EMV_BIT(2, 1), "Last Online Transaction Not Completed" },
    { EMV_BIT(3, 8), "Lower Offline Transaction Count Limit Exceeded" },
    { EMV_BIT(3, 7), "Upper Offline Transaction Count Limit Exceeded" },
    { EMV_BIT(3, 6), "Lower Cumulative Offline Amount Limit Exceeded" },
    { EMV_BIT(3, 5), "Upper Cumulative Offline Amount Limit Exceeded" },
    { EMV_BIT(4, 4), "Issuer script processing failed on last transaction" },
    { EMV_BIT(4, 3), "Offline data authentication failed on previous transaction and transaction declined offline" },
    { EMV_BIT(4, 2), "Go Online on Next Transaction Was Set" },
    { EMV_BIT(4, 1), "Unable to go Online" },
    EMV_BIT_FINISH,
};

// All Data Elements by Tags used in TLV structure (according to the EMV 4.2 Standard )
// https://www.eftlab.co.uk/index.php/site-map/knowledge-base/145-emv-nfc-tags
// http://dexterous-programmer.blogspot.in/2012/05/emv-tags.html
static const struct emv_tag emv_tags[] = {
    // internal
    { 0x00,     "Unknown ???",                                                 EMV_TAG_GENERIC,  NULL },
    { 0x01,     "",                                                            EMV_TAG_STRING,   NULL }, // string for headers
    { 0x02,     "Raw data",                                                    EMV_TAG_GENERIC,  NULL }, // data
    { 0x06,     "Object Identifier (OID)",                                     EMV_TAG_GENERIC,  NULL },
    { 0x20,     "Cardholder Verification Results (CVR)",                       EMV_TAG_CVR,      NULL }, // not standard!
    { 0x21,     "Input list for Offline Data Authentication",                  EMV_TAG_GENERIC,  NULL }, // not standard! data for "Offline Data Authentication" come from "read records" command. (EMV book3 10.3)

    // EMV
    { 0x41,     "Country code and national data",                              EMV_TAG_GENERIC,  NULL },
    { 0x42,     "Issuer Identification Number (IIN)",                          EMV_TAG_GENERIC,  NULL },
    { 0x4f,     "Application Dedicated File (ADF) Name",                       EMV_TAG_GENERIC,  NULL },
    { 0x50,     "Application Label",                                           EMV_TAG_STRING,   NULL },
    { 0x51,     "File reference data element",                                 EMV_TAG_GENERIC,  NULL },
    { 0x52,     "Command APDU",                                                EMV_TAG_GENERIC,  NULL },
    { 0x53,     "Discretionary data (or template)",                            EMV_TAG_GENERIC,  NULL },
    { 0x56,     "Track 1 Data",                                                EMV_TAG_GENERIC,  NULL },
    { 0x57,     "Track 2 Equivalent Data",                                     EMV_TAG_GENERIC,  NULL },
    { 0x5a,     "Application Primary Account Number (PAN)",                    EMV_TAG_GENERIC,  NULL },
    { 0x5f20,   "Cardholder Name",                                             EMV_TAG_STRING,   NULL },
    { 0x5f24,   "Application Expiration Date",                                 EMV_TAG_YYMMDD,   NULL },
    { 0x5f25,   "Application Effective Date",                                  EMV_TAG_YYMMDD,   NULL },
    { 0x5f28,   "Issuer Country Code",                                         EMV_TAG_NUMERIC,  NULL },
    { 0x5f2a,   "Transaction Currency Code",                                   EMV_TAG_NUMERIC,  NULL },
    { 0x5f2d,   "Language Preference",                                         EMV_TAG_STRING,   NULL },
    { 0x5f30,   "Service Code",                                                EMV_TAG_NUMERIC,  NULL },
    { 0x5f34,   "Application Primary Account Number (PAN) Sequence Number",    EMV_TAG_NUMERIC,  NULL },
    { 0x5f36,   "Transaction Currency Exponent",                               EMV_TAG_NUMERIC,  NULL },
    { 0x5f50,   "Issuer URL",                                                  EMV_TAG_STRING,   NULL },
    { 0x5f53,   "International Bank Account Number (IBAN)",                    EMV_TAG_GENERIC,  NULL },
    { 0x5f54,   "Bank Identifier Code (BIC)",                                  EMV_TAG_GENERIC,  NULL },
    { 0x5f55,   "Issuer Country Code (alpha2 format)",                         EMV_TAG_STRING,   NULL },
    { 0x5f56,   "Issuer Country Code (alpha3 format)",                         EMV_TAG_STRING,   NULL },

    { 0x61,     "Application Template",                                        EMV_TAG_GENERIC,  NULL },
    { 0x6f,     "File Control Information (FCI) Template",                     EMV_TAG_GENERIC,  NULL },
    { 0x70,     "READ RECORD Response Message Template",                       EMV_TAG_GENERIC,  NULL },
    { 0x71,     "Issues Script Template 1",                                    EMV_TAG_GENERIC,  NULL },
    { 0x72,     "Issues Script Template 2",                                    EMV_TAG_GENERIC,  NULL },
    { 0x73,     "Directory Discretionary Template",                            EMV_TAG_GENERIC,  NULL },
    { 0x77,     "Response Message Template Format 2",                          EMV_TAG_GENERIC,  NULL },
    { 0x80,     "Response Message Template Format 1",                          EMV_TAG_GENERIC,  NULL },
    { 0x81,     "Amount, Authorised (Binary)",                                 EMV_TAG_GENERIC,  NULL },
    { 0x82,     "Application Interchange Profile",                             EMV_TAG_BITMASK,  &EMV_AIP },
    { 0x83,     "Command Template",                                            EMV_TAG_GENERIC,  NULL },
    { 0x84,     "Dedicated File (DF) Name",                                    EMV_TAG_GENERIC,  NULL },
    { 0x86,     "Issuer Script Command",                                       EMV_TAG_GENERIC,  NULL },
    { 0x87,     "Application Priority Indicator",                              EMV_TAG_GENERIC,  NULL },
    { 0x88,     "Short File Identifier (SFI)",                                 EMV_TAG_GENERIC,  NULL },
    { 0x89,     "Authorisation Code",                                          EMV_TAG_GENERIC,  NULL },
    { 0x8a,     "Authorisation Response Code",                                 EMV_TAG_GENERIC,  NULL },
    { 0x8c,     "Card Risk Management Data Object List 1 (CDOL1)",             EMV_TAG_DOL,      NULL },
    { 0x8d,     "Card Risk Management Data Object List 2 (CDOL2)",             EMV_TAG_DOL,      NULL },
    { 0x8e,     "Cardholder Verification Method (CVM) List",                   EMV_TAG_CVM_LIST, NULL },
    { 0x8f,     "Certification Authority Public Key Index",                    EMV_TAG_GENERIC,  NULL },
    { 0x90,     "Issuer Public Key Certificate",                               EMV_TAG_GENERIC,  NULL },
    { 0x91,     "Issuer Authentication Data",                                  EMV_TAG_GENERIC,  NULL },
    { 0x92,     "Issuer Public Key Remainder",                                 EMV_TAG_GENERIC,  NULL },
    { 0x93,     "Signed Static Application Data",                              EMV_TAG_GENERIC,  NULL },
    { 0x94,     "Application File Locator (AFL)",                              EMV_TAG_AFL,      NULL },
    { 0x95,     "Terminal Verification Results",                               EMV_TAG_GENERIC,  NULL },
    { 0x97,     "Transaction Certificate Data Object List (TDOL)",             EMV_TAG_GENERIC,  NULL },
    { 0x98,     "Transaction Certificate (TC) Hash Value",                     EMV_TAG_GENERIC,  NULL },
    { 0x99,     "Transaction Personal Identification Number (PIN) Data",       EMV_TAG_GENERIC,  NULL },
    { 0x9a,     "Transaction Date",                                            EMV_TAG_YYMMDD,   NULL },
    { 0x9b,     "Transaction Status Information",                              EMV_TAG_GENERIC,  NULL },
    { 0x9c,     "Transaction Type",                                            EMV_TAG_NUMERIC,  NULL },
    { 0x9d,     "Directory Definition File (DDF) Name",                        EMV_TAG_GENERIC,  NULL },

    { 0x9f01,   "Acquirer Identifier",                                         EMV_TAG_NUMERIC,  NULL },
    { 0x9f02,   "Amount, Authorised (Numeric)",                                EMV_TAG_NUMERIC,  NULL },
    { 0x9f03,   "Amount, Other (Numeric)",                                     EMV_TAG_NUMERIC,  NULL },
    { 0x9f04,   "Amount, Other (Binary)",                                      EMV_TAG_NUMERIC,  NULL },
    { 0x9f05,   "Application Discretionary Data",                              EMV_TAG_GENERIC,  NULL },
    { 0x9f07,   "Application Usage Control",                                   EMV_TAG_BITMASK,  &EMV_AUC },
    { 0x9f08,   "Application Version Number",                                  EMV_TAG_GENERIC,  NULL },
    { 0x9f09,   "Application Version Number - terminal",                       EMV_TAG_GENERIC,  NULL },
    { 0x9f0a,   "Application Selection Registered Proprietary Data",           EMV_TAG_GENERIC,  NULL }, // https://blog.ul-ts.com/posts/electronic-card-identifier-one-more-step-for-mif-compliance/
    { 0x9f0b,   "Cardholder Name Extended",                                    EMV_TAG_STRING,   NULL },
    { 0x9f0d,   "Issuer Action Code - Default",                                EMV_TAG_BITMASK,  &EMV_TVR },
    { 0x9f0e,   "Issuer Action Code - Denial",                                 EMV_TAG_BITMASK,  &EMV_TVR },
    { 0x9f0f,   "Issuer Action Code - Online",                                 EMV_TAG_BITMASK,  &EMV_TVR },
    { 0x9f10,   "Issuer Application Data",                                     EMV_TAG_GENERIC,  NULL },
    { 0x9f11,   "Issuer Code Table Index",                                     EMV_TAG_NUMERIC,  NULL },
    { 0x9f12,   "Application Preferred Name",                                  EMV_TAG_STRING,   NULL },
    { 0x9f13,   "Last Online Application Transaction Counter (ATC) Register",  EMV_TAG_GENERIC,  NULL },
    { 0x9f14,   "Lower Consecutive Offline Limit",                             EMV_TAG_GENERIC,  NULL },
    { 0x9f15,   "Merchant Category Code",                                      EMV_TAG_NUMERIC,  NULL },
    { 0x9f16,   "Merchant Identifier",                                         EMV_TAG_STRING,   NULL },
    { 0x9f17,   "Personal Identification Number (PIN) Try Counter",            EMV_TAG_GENERIC,  NULL },
    { 0x9f18,   "Issuer Script Identifier",                                    EMV_TAG_GENERIC,  NULL },
    { 0x9f19,   "Token Requestor ID",                                          EMV_TAG_GENERIC,  NULL },
    { 0x9f1a,   "Terminal Country Code",                                       EMV_TAG_GENERIC,  NULL },
    { 0x9f1b,   "Terminal Floor Limit",                                        EMV_TAG_GENERIC,  NULL },
    { 0x9f1c,   "Terminal Identification",                                     EMV_TAG_STRING,   NULL },
    { 0x9f1d,   "Terminal Risk Management Data",                               EMV_TAG_GENERIC,  NULL },
    { 0x9f1e,   "Interface Device (IFD) Serial Number",                        EMV_TAG_STRING,   NULL },
    { 0x9f1f,   "Track 1 Discretionary Data",                                  EMV_TAG_STRING,   NULL },
    { 0x9f20,   "Track 2 Discretionary Data",                                  EMV_TAG_STRING,   NULL },
    { 0x9f21,   "Transaction Time",                                            EMV_TAG_GENERIC,  NULL },
    { 0x9f22,   "Certification Authority Public Key Index - Terminal",         EMV_TAG_GENERIC,  NULL },
    { 0x9f23,   "Upper Consecutive Offline Limit",                             EMV_TAG_GENERIC,  NULL },
    { 0x9f24,   "Payment Account Reference (PAR)",                             EMV_TAG_GENERIC,  NULL },
    { 0x9f25,   "Last 4 Digits of PAN",                                        EMV_TAG_GENERIC,  NULL },
    { 0x9f26,   "Application Cryptogram",                                      EMV_TAG_GENERIC,  NULL },
    { 0x9f27,   "Cryptogram Information Data",                                 EMV_TAG_CID,      NULL },
    { 0x9f2a,   "Kernel Identifier",                                           EMV_TAG_GENERIC,  NULL },
    { 0x9f2d,   "ICC PIN Encipherment Public Key Certificate",                 EMV_TAG_GENERIC,  NULL },
    { 0x9f2e,   "ICC PIN Encipherment Public Key Exponent",                    EMV_TAG_GENERIC,  NULL },
    { 0x9f2f,   "ICC PIN Encipherment Public Key Remainder",                   EMV_TAG_GENERIC,  NULL },
    { 0x9f32,   "Issuer Public Key Exponent",                                  EMV_TAG_GENERIC,  NULL },
    { 0x9f33,   "Terminal Capabilities",                                       EMV_TAG_GENERIC,  NULL },
    { 0x9f34,   "Cardholder Verification Method (CVM) Results",                EMV_TAG_GENERIC,  NULL },
    { 0x9f35,   "Terminal Type",                                               EMV_TAG_GENERIC,  NULL },
    { 0x9f36,   "Application Transaction Counter (ATC)",                       EMV_TAG_GENERIC,  NULL },
    { 0x9f37,   "Unpredictable Number",                                        EMV_TAG_GENERIC,  NULL },
    { 0x9f38,   "Processing Options Data Object List (PDOL)",                  EMV_TAG_DOL,      NULL },
    { 0x9f39,   "Point-of-Service (POS) Entry Mode",                           EMV_TAG_NUMERIC,  NULL },
    { 0x9f3a,   "Amount, Reference Currency",                                  EMV_TAG_GENERIC,  NULL },
    { 0x9f3b,   "Application Reference Currency",                              EMV_TAG_NUMERIC,  NULL },
    { 0x9f3c,   "Transaction Reference Currency Code",                         EMV_TAG_NUMERIC,  NULL },
    { 0x9f3d,   "Transaction Reference Currency Exponent",                     EMV_TAG_NUMERIC,  NULL },
    { 0x9f40,   "Additional Terminal Capabilities",                            EMV_TAG_GENERIC,  NULL },
    { 0x9f41,   "Transaction Sequence Counter",                                EMV_TAG_NUMERIC,  NULL },
    { 0x9f42,   "Application Currency Code",                                   EMV_TAG_NUMERIC,  NULL },
    { 0x9f43,   "Application Reference Currency Exponent",                     EMV_TAG_NUMERIC,  NULL },
    { 0x9f44,   "Application Currency Exponent",                               EMV_TAG_NUMERIC,  NULL },
    { 0x9f45,   "Data Authentication Code",                                    EMV_TAG_GENERIC,  NULL },
    { 0x9f46,   "ICC Public Key Certificate",                                  EMV_TAG_GENERIC,  NULL },
    { 0x9f47,   "ICC Public Key Exponent",                                     EMV_TAG_GENERIC,  NULL },
    { 0x9f48,   "ICC Public Key Remainder",                                    EMV_TAG_GENERIC,  NULL },
    { 0x9f49,   "Dynamic Data Authentication Data Object List (DDOL)",         EMV_TAG_DOL,      NULL },
    { 0x9f4a,   "Static Data Authentication Tag List",                         EMV_TAG_GENERIC,  NULL },
    { 0x9f4b,   "Signed Dynamic Application Data",                             EMV_TAG_GENERIC,  NULL },
    { 0x9f4c,   "ICC Dynamic Number",                                          EMV_TAG_GENERIC,  NULL },
    { 0x9f4d,   "Log Entry",                                                   EMV_TAG_GENERIC,  NULL },
    { 0x9f4e,   "Merchant Name and Location",                                  EMV_TAG_STRING,   NULL },
    { 0x9f4f,   "Log Format",                                                  EMV_TAG_DOL,      NULL },

    { 0x9f50,   "Offline Accumulator Balance",                                 EMV_TAG_GENERIC,  NULL },
    { 0x9f51,   "Application Currency Code",                                   EMV_TAG_GENERIC,  NULL },
    { 0x9f51,   "DRDOL",                                                       EMV_TAG_GENERIC,  NULL },

    { 0x9f52,   "Application Default Action (ADA)",                            EMV_TAG_GENERIC,  NULL },
    { 0x9f52,   "Terminal Compatibility Indicator",                            EMV_TAG_GENERIC,  NULL },

    { 0x9f53,   "Transaction Category Code",                                   EMV_TAG_GENERIC,  NULL },
    { 0x9f54,   "DS ODS Card",                                                 EMV_TAG_GENERIC,  NULL },

    { 0x9f55,   "Mobile Support Indicator",                                    EMV_TAG_GENERIC,  NULL },
    { 0x9f55,   "Issuer Authentication Flags",                                 EMV_TAG_GENERIC,  NULL },

    { 0x9f56,   "Issuer Authentication Indicator",                             EMV_TAG_GENERIC,  NULL },
    { 0x9f57,   "Issuer Country Code",                                         EMV_TAG_GENERIC,  NULL },
    { 0x9f58,   "Consecutive Transaction Counter Limit (CTCL)",                EMV_TAG_GENERIC,  NULL },
    { 0x9f59,   "Consecutive Transaction Counter Upper Limit (CTCUL)",         EMV_TAG_GENERIC,  NULL },
    { 0x9f5A,   "Application Program Identifier",                              EMV_TAG_GENERIC,  NULL },
    { 0x9f5b,   "Issuer Script Results",                                       EMV_TAG_GENERIC,  NULL },
    { 0x9f5c,   "Cumulative Total Transaction Amount Upper Limit (CTTAUL)",    EMV_TAG_GENERIC,  NULL },
    { 0x9f5d,   "Application Capabilities Information",                        EMV_TAG_GENERIC,  NULL },
    { 0x9f5e,   "Data Storage Identifier",                                     EMV_TAG_GENERIC,  NULL },
    { 0x9f5f,   "DS Slot Availability",                                        EMV_TAG_GENERIC,  NULL },

    { 0x9f60,   "CVC3 (Track1)",                                               EMV_TAG_GENERIC,  NULL },
    { 0x9f61,   "CVC3 (Track2)",                                               EMV_TAG_GENERIC,  NULL },
    { 0x9f62,   "PCVC3 (Track1)",                                              EMV_TAG_GENERIC,  NULL },
    { 0x9f63,   "PUNATC (Track1)",                                             EMV_TAG_GENERIC,  NULL },
    { 0x9f64,   "NATC (Track1)",                                               EMV_TAG_GENERIC,  NULL },
    { 0x9f65,   "PCVC3 (Track2)",                                              EMV_TAG_GENERIC,  NULL },
    { 0x9f66,   "PUNATC (Track2) / Terminal Transaction Qualifiers (TTQ)",     EMV_TAG_BITMASK,  &EMV_TTQ },
    { 0x9f67,   "NATC (Track2) / MSD Offset",                                  EMV_TAG_GENERIC,  NULL },
    { 0x9f68,   "Cardholder verification method list (PayPass)",               EMV_TAG_GENERIC,  NULL },
    { 0x9f69,   "Card Authentication Related Data (UDOL)",                     EMV_TAG_DOL,      NULL },
    { 0x9f6a,   "Unpredictable Number",                                        EMV_TAG_NUMERIC,  NULL },
    { 0x9f6b,   "Track 2 Data",                                                EMV_TAG_GENERIC,  NULL },
    { 0x9f6c,   "Card Transaction Qualifiers (CTQ)",                           EMV_TAG_BITMASK,  &EMV_CTQ },
    { 0x9f6d,   "Mag-stripe Application Version Number (Reader)",              EMV_TAG_GENERIC,  NULL },
    { 0x9f6e,   "Form Factor Indicator",                                       EMV_TAG_GENERIC,  NULL },
    { 0x9f6f,   "DS Slot Management Control",                                  EMV_TAG_GENERIC,  NULL },

    { 0x9f70,   "Protected Data Envelope 1",                                   EMV_TAG_GENERIC,  NULL },
    { 0x9f71,   "Protected Data Envelope 2",                                   EMV_TAG_GENERIC,  NULL },
    { 0x9f72,   "Protected Data Envelope 3",                                   EMV_TAG_GENERIC,  NULL },
    { 0x9f73,   "Protected Data Envelope 4",                                   EMV_TAG_GENERIC,  NULL },
    { 0x9f74,   "Protected Data Envelope 5",                                   EMV_TAG_GENERIC,  NULL },
    { 0x9f75,   "Unprotected Data Envelope 1",                                 EMV_TAG_GENERIC,  NULL },
    { 0x9f76,   "Unprotected Data Envelope 2",                                 EMV_TAG_GENERIC,  NULL },
    { 0x9f77,   "Unprotected Data Envelope 3",                                 EMV_TAG_GENERIC,  NULL },
    { 0x9f78,   "Unprotected Data Envelope 4",                                 EMV_TAG_GENERIC,  NULL },
    { 0x9f79,   "Unprotected Data Envelope 5",                                 EMV_TAG_GENERIC,  NULL },
    { 0x9f7c,   "Merchant Custom Data / Customer Exclusive Data (CED)",        EMV_TAG_GENERIC,  NULL },
    { 0x9f7d,   "DS Summary 1",                                                EMV_TAG_GENERIC,  NULL },
    { 0x9f7e,   "Application Life Cycle Data",                                 EMV_TAG_GENERIC,  NULL },
    { 0x9f7f,   "DS Unpredictable Number",                                     EMV_TAG_GENERIC,  NULL },

    { 0xa5,     "File Control Information (FCI) Proprietary Template",         EMV_TAG_GENERIC,  NULL },
    { 0xbf0c,   "File Control Information (FCI) Issuer Discretionary Data",    EMV_TAG_GENERIC,  NULL },
    { 0xdf20,   "Issuer Proprietary Bitmap (IPB)",                             EMV_TAG_GENERIC,  NULL },
    { 0xdf3e,   "?",                                                           EMV_TAG_BITMASK,  NULL },
    { 0xdf4b,   "POS Cardholder Interaction Information",                      EMV_TAG_GENERIC,  NULL },
    { 0xdf60,   "VISA Log Entry",                                              EMV_TAG_GENERIC,  NULL },
    { 0xdf61,   "DS Digest H",                                                 EMV_TAG_GENERIC,  NULL },
    { 0xdf62,   "DS ODS Info",                                                 EMV_TAG_GENERIC,  NULL },
    { 0xdf63,   "DS ODS Term",                                                 EMV_TAG_GENERIC,  NULL },

    { 0xdf8104, "Balance Read Before Gen AC",                                  EMV_TAG_GENERIC,  NULL },
    { 0xdf8105, "Balance Read After Gen AC",                                   EMV_TAG_GENERIC,  NULL },
    { 0xdf8106, "Data Needed",                                                 EMV_TAG_GENERIC,  NULL },
    { 0xdf8107, "CDOL1 Related Data",                                          EMV_TAG_GENERIC,  NULL },
    { 0xdf8108, "DS AC Type",                                                  EMV_TAG_GENERIC,  NULL },
    { 0xdf8109, "DS Input (Term)",                                             EMV_TAG_GENERIC,  NULL },
    { 0xdf810a, "DS ODS Info For Reader",                                      EMV_TAG_GENERIC,  NULL },
    { 0xdf810b, "DS Summary Status",                                           EMV_TAG_GENERIC,  NULL },
    { 0xdf810c, "Kernel ID",                                                   EMV_TAG_GENERIC,  NULL },
    { 0xdf810d, "DSVN Term",                                                   EMV_TAG_GENERIC,  NULL },
    { 0xdf810e, "Post-Gen AC Put Data Status",                                 EMV_TAG_GENERIC,  NULL },
    { 0xdf810f, "Pre-Gen AC Put Data Status",                                  EMV_TAG_GENERIC,  NULL },
    { 0xdf8110, "Proceed To First Write Flag",                                 EMV_TAG_GENERIC,  NULL },
    { 0xdf8111, "PDOL Related Data",                                           EMV_TAG_GENERIC,  NULL },
    { 0xdf8112, "Tags To Read",                                                EMV_TAG_GENERIC,  NULL },
    { 0xdf8113, "DRDOL Related Data",                                          EMV_TAG_GENERIC,  NULL },
    { 0xdf8114, "Reference Control Parameter",                                 EMV_TAG_GENERIC,  NULL },
    { 0xdf8115, "Error Indication",                                            EMV_TAG_GENERIC,  NULL },
    { 0xdf8116, "User Interface Request Data",                                 EMV_TAG_GENERIC,  NULL },
    { 0xdf8117, "Card Data Input Capability",                                  EMV_TAG_GENERIC,  NULL },
    { 0xdf8118, "CVM Capability - CVM Required",                               EMV_TAG_GENERIC,  NULL },
    { 0xdf8119, "CVM Capability - No CVM Required",                            EMV_TAG_GENERIC,  NULL },
    { 0xdf811a, "Default UDOL",                                                EMV_TAG_DOL,      NULL },
    { 0xdf811b, "Kernel Configuration",                                        EMV_TAG_GENERIC,  NULL },
    { 0xdf811c, "Max Lifetime of Torn Transaction Log Record",                 EMV_TAG_GENERIC,  NULL },
    { 0xdf811d, "Max Number of Torn Transaction Log Records",                  EMV_TAG_GENERIC,  NULL },
    { 0xdf811e, "Mag-stripe CVM Capability - CVM Required",                    EMV_TAG_GENERIC,  NULL },
    { 0xdf811f, "Security Capability",                                         EMV_TAG_GENERIC,  NULL },
    { 0xdf8120, "Terminal Action Code - Default",                              EMV_TAG_GENERIC,  NULL },
    { 0xdf8121, "Terminal Action Code - Denial",                               EMV_TAG_GENERIC,  NULL },
    { 0xdf8122, "Terminal Action Code - Online",                               EMV_TAG_GENERIC,  NULL },
    { 0xdf8123, "Reader Contactless Floor Limit",                              EMV_TAG_GENERIC,  NULL },
    { 0xdf8124, "Reader Contactless Transaction Limit (No On-device CVM)",     EMV_TAG_GENERIC,  NULL },
    { 0xdf8125, "Reader Contactless Transaction Limit (On-device CVM)",        EMV_TAG_GENERIC,  NULL },
    { 0xdf8126, "Reader CVM Required Limit",                                   EMV_TAG_GENERIC,  NULL },
    { 0xdf8127, "TIME_OUT_VALUE",                                              EMV_TAG_GENERIC,  NULL },
    { 0xdf8128, "IDS Status",                                                  EMV_TAG_GENERIC,  NULL },
    { 0xdf8129, "Outcome Parameter Set",                                       EMV_TAG_GENERIC,  NULL },
    { 0xdf812a, "DD Card (Track1)",                                            EMV_TAG_GENERIC,  NULL },
    { 0xdf812b, "DD Card (Track2)",                                            EMV_TAG_GENERIC,  NULL },
    { 0xdf812c, "Mag-stripe CVM Capability - No CVM Required",                 EMV_TAG_GENERIC,  NULL },
    { 0xdf812d, "Message Hold Time",                                           EMV_TAG_GENERIC,  NULL },

    { 0xff8101, "Torn Record",                                                 EMV_TAG_GENERIC,  NULL },
    { 0xff8102, "Tags To Write Before Gen AC",                                 EMV_TAG_GENERIC,  NULL },
    { 0xff8103, "Tags To Write After Gen AC",                                  EMV_TAG_GENERIC,  NULL },
    { 0xff8104, "Data To Send",                                                EMV_TAG_GENERIC,  NULL },
    { 0xff8105, "Data Record",                                                 EMV_TAG_GENERIC,  NULL },
    { 0xff8106, "Discretionary Data",                                          EMV_TAG_GENERIC,  NULL },
};

static int emv_sort_tag(tlv_tag_t tag) {
    return (int)(tag >= 0x100 ? tag : tag << 8);
}

static int emv_tlv_compare(const void *a, const void *b) {
    const struct tlv *tlv = a;
    const struct emv_tag *tag = b;

    return emv_sort_tag(tlv->tag) - (emv_sort_tag(tag->tag));
}

static const struct emv_tag *emv_get_tag(const struct tlv *tlv) {
    struct emv_tag *tag = bsearch(tlv, emv_tags, ARRAYLEN(emv_tags),
                                  sizeof(emv_tags[0]), emv_tlv_compare);

    return tag ? tag : &emv_tags[0];
}

static const char *bitstrings[] = {
    ".......1",
    "......1.",
    ".....1..",
    "....1...",
    "...1....",
    "..1.....",
    ".1......",
    "1.......",
};

static void emv_tag_dump_bitmask(const struct tlv *tlv, const struct emv_tag *tag, int level) {
    const struct emv_tag_bit *bits = tag->data;
    unsigned bit, byte;

    for (byte = 1; byte <= tlv->len; byte ++) {
        unsigned char val = tlv->value[byte - 1];
        PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
        PrintAndLogEx(NORMAL, "    Byte %u (%02x)", byte, val);

        for (bit = 8; bit > 0; bit--, val <<= 1) {
            if (val & 0x80) {
                PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
                PrintAndLogEx(NORMAL, "        %s - '%s'",
                              bitstrings[bit - 1],
                              (bits->bit == EMV_BIT(byte, bit)) ? bits->name : "Unknown"
                             );
            }
            if (bits->bit == EMV_BIT(byte, bit))
                bits ++;
        }
    }
}

static void emv_tag_dump_dol(const struct tlv *tlv, const struct emv_tag *tag, int level) {
    const unsigned char *buf = tlv->value;
    size_t left = tlv->len;

    while (left) {
        struct tlv doltlv;
        const struct emv_tag *doltag;

        if (!tlv_parse_tl(&buf, &left, &doltlv)) {
            PrintAndLogEx(INFO, "%*sInvalid Tag-Len", (level * 4), " ");
            continue;
        }

        doltag = emv_get_tag(&doltlv);

        PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
        PrintAndLogEx(NORMAL, "    Tag %4x len %02zx ('%s')", doltlv.tag, doltlv.len, doltag->name);
    }
}

static void emv_tag_dump_string(const struct tlv *tlv, const struct emv_tag *tag, int level) {
    PrintAndLogEx(NORMAL, "    String value '" _YELLOW_("%s")"'", sprint_hex_inrow(tlv->value, tlv->len));
}

static unsigned long emv_value_numeric(const struct tlv *tlv, unsigned start, unsigned end) {
    unsigned long ret = 0;
    int i;

    if (end > tlv->len * 2)
        return ret;
    if (start >= end)
        return ret;

    if (start & 1) {
        ret += tlv->value[start / 2] & 0xf;
        i = start + 1;
    } else
        i = start;

    for (; i < end - 1; i += 2) {
        ret *= 10;
        ret += tlv->value[i / 2] >> 4;
        ret *= 10;
        ret += tlv->value[i / 2] & 0xf;
    }

    if (end & 1) {
        ret *= 10;
        ret += tlv->value[end / 2] >> 4;
    }

    return ret;
}

static void emv_tag_dump_numeric(const struct tlv *tlv, const struct emv_tag *tag, int level) {
    PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
    PrintAndLogEx(NORMAL, "    Numeric value " _YELLOW_("%lu"), emv_value_numeric(tlv, 0, tlv->len * 2));
}

static void emv_tag_dump_yymmdd(const struct tlv *tlv, const struct emv_tag *tag, int level) {
    PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
    PrintAndLogEx(NORMAL, "    Date: " _YELLOW_("20%02lu.%lu.%lu"),
                  emv_value_numeric(tlv, 0, 2),
                  emv_value_numeric(tlv, 2, 4),
                  emv_value_numeric(tlv, 4, 6)
                 );
}

static uint32_t emv_get_binary(const unsigned char *S) {
    return (S[0] << 24) | (S[1] << 16) | (S[2] << 8) | (S[3] << 0);
}

// https://github.com/binaryfoo/emv-bertlv/blob/master/src/main/resources/fields/visa-cvr.txt
static void emv_tag_dump_cvr(const struct tlv *tlv, const struct emv_tag *tag, int level) {
    if (tlv == NULL || tlv->len < 1) {
        PrintAndLogEx(INFO, "%*s    INVALID length!", (level * 4), " ");
        return;
    }

    if (tlv->len != 5 && tlv->len != tlv->value[0] + 1) {
        PrintAndLogEx(INFO, "%*s    INVALID length!", (level * 4), " ");
        return;
    }

    if (tlv->len >= 2) {
        // AC1
        PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
        if ((tlv->value[1] & 0xC0) == 0x00) PrintAndLogEx(NORMAL, "    AC1: AAC (Transaction declined)");
        if ((tlv->value[1] & 0xC0) == 0x40) PrintAndLogEx(NORMAL, "    AC1: TC (Transaction approved)");
        if ((tlv->value[1] & 0xC0) == 0x80) PrintAndLogEx(NORMAL, "    AC1: ARQC (Online authorisation requested)");
        if ((tlv->value[1] & 0xC0) == 0xC0) PrintAndLogEx(NORMAL, "    AC1: RFU");
        // AC2
        PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
        if ((tlv->value[1] & 0x30) == 0x00) PrintAndLogEx(NORMAL, "    AC2: AAC (Transaction declined)");
        if ((tlv->value[1] & 0x30) == 0x10) PrintAndLogEx(NORMAL, "    AC2: TC (Transaction approved)");
        if ((tlv->value[1] & 0x30) == 0x20) PrintAndLogEx(NORMAL, "    AC2: not requested (ARQC)");
        if ((tlv->value[1] & 0x30) == 0x30) PrintAndLogEx(NORMAL, "    AC2: RFU");
    }
    if (tlv->len >= 3 && (tlv->value[2] >> 4)) {
        PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
        PrintAndLogEx(NORMAL, "    PIN try: %x", tlv->value[2] >> 4);
    }
    if (tlv->len >= 3 && (tlv->value[2] & 0x40)) {
        PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
        PrintAndLogEx(NORMAL, "    PIN try exceeded");
    }
    if (tlv->len >= 4 && (tlv->value[3] >> 4)) {
        PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
        PrintAndLogEx(NORMAL, "    Issuer script counter: %x", tlv->value[3] >> 4);
    }
    if (tlv->len >= 4 && (tlv->value[3] & 0x0F)) {
        PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
        PrintAndLogEx(NORMAL, "    Issuer discretionary bits: %x", tlv->value[3] & 0x0F);
    }
    if (tlv->len >= 5 && (tlv->value[4] >> 4)) {
        PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
        PrintAndLogEx(NORMAL, "    Successfully processed issuer script commands: %x", tlv->value[4] >> 4);
    }
    if (tlv->len >= 5 && (tlv->value[4] & 0x02)) {
        PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
        PrintAndLogEx(NORMAL, "    CDCVM OK");
    }

    // mask 0F 0F F0 0F
    uint8_t data[20] = {0};
    memcpy(data, &tlv->value[1], tlv->len - 1);
    data[0] &= 0x0F;
    data[1] &= 0x0F;
    data[2] &= 0xF0;
    data[3] &= 0x0F;
    const struct tlv bit_tlv = {
        .tag = tlv->tag,
        .len = tlv->len - 1,
        .value = data,
    };
    const struct emv_tag bit_tag = {
        .tag = tag->tag,
        .name = tag->name,
        .type = EMV_TAG_BITMASK,
        .data = EMV_CVR,
    };

    if (data[0] || data[1] || data[2] || data[3])
        emv_tag_dump_bitmask(&bit_tlv, &bit_tag, level);
}

// EMV Book 3
static void emv_tag_dump_cid(const struct tlv *tlv, const struct emv_tag *tag, int level) {
    if (tlv == NULL || tlv->len < 1) {
        PrintAndLogEx(INFO, "%*s    INVALID!", (level * 4), " ");
        return;
    }

    PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");

    if ((tlv->value[0] & EMVAC_AC_MASK) == EMVAC_AAC)
        PrintAndLogEx(NORMAL, "    AC1: AAC (Transaction declined)");
    if ((tlv->value[0] & EMVAC_AC_MASK) == EMVAC_TC)
        PrintAndLogEx(NORMAL, "    AC1: TC (Transaction approved)");
    if ((tlv->value[0] & EMVAC_AC_MASK) == EMVAC_ARQC)
        PrintAndLogEx(NORMAL, "    AC1: ARQC (Online authorisation requested)");
    if ((tlv->value[0] & EMVAC_AC_MASK) == EMVAC_AC_MASK)
        PrintAndLogEx(NORMAL, "    AC1: RFU");

    if (tlv->value[0] & EMVCID_ADVICE) {
        PrintAndLogEx(NORMAL, "%*s" NOLF, (level * 4), " ");
        PrintAndLogEx(NORMAL, "    Advice required!");
    }

    if (tlv->value[0] & EMVCID_REASON_MASK) {
        PrintAndLogEx(NORMAL, "%*s" NOLF, (level * 4), " ");
        PrintAndLogEx(NORMAL, "    Reason/advice/referral code: " NOLF);
        switch ((tlv->value[0] & EMVCID_REASON_MASK)) {
            case 0:
                PrintAndLogEx(NORMAL, "No information given");
                break;
            case 1:
                PrintAndLogEx(NORMAL, "Service not allowed");
                break;
            case 2:
                PrintAndLogEx(NORMAL, "PIN Try Limit exceeded");
                break;
            case 3:
                PrintAndLogEx(NORMAL, "Issuer authentication failed");
                break;
            default:
                PrintAndLogEx(NORMAL, "    RFU: %2x", (tlv->value[0] & EMVCID_REASON_MASK));
                break;
        }
    }
}

static void emv_tag_dump_cvm_list(const struct tlv *tlv, const struct emv_tag *tag, int level) {
    uint32_t X, Y;
    int i;

    if (tlv->len < 10 || tlv->len % 2) {
        PrintAndLogEx(INFO, "%*s    INVALID!", (level * 4), " ");
        return;
    }

    X = emv_get_binary(tlv->value);
    Y = emv_get_binary(tlv->value + 4);

    PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
    PrintAndLogEx(NORMAL, "    X: %u", X);
    PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
    PrintAndLogEx(NORMAL, "    Y: %u", Y);

    for (i = 8; i < tlv->len; i += 2) {
        const char *method;
        const char *condition;

        switch (tlv->value[i] & 0x3f) {
            case 0x0:
                method = "Fail CVM processing";
                break;
            case 0x1:
                method = "Plaintext PIN verification performed by ICC";
                break;
            case 0x2:
                method = "Enciphered PIN verified online";
                break;
            case 0x3:
                method = "Plaintext PIN verification performed by ICC and signature (paper)";
                break;
            case 0x4:
                method = "Enciphered PIN verification performed by ICC";
                break;
            case 0x5:
                method = "Enciphered PIN verification performed by ICC and signature (paper)";
                break;
            case 0x1e:
                method = "Signature (paper)";
                break;
            case 0x1f:
                method = "No CVM required";
                break;
            case 0x3f:
                method = "NOT AVAILABLE!";
                break;
            default:
                method = "Unknown";
                break;
        }

        switch (tlv->value[i + 1]) {
            case 0x00:
                condition = "Always";
                break;
            case 0x01:
                condition = "If unattended cash";
                break;
            case 0x02:
                condition = "If not unattended cash and not manual cash and not purchase with cashback";
                break;
            case 0x03:
                condition = "If terminal supports the CVM";
                break;
            case 0x04:
                condition = "If manual cash";
                break;
            case 0x05:
                condition = "If purchase with cashback";
                break;
            case 0x06:
                condition = "If transaction is in the application currency and is under X value";
                break;
            case 0x07:
                condition = "If transaction is in the application currency and is over X value";
                break;
            case 0x08:
                condition = "If transaction is in the application currency and is under Y value";
                break;
            case 0x09:
                condition = "If transaction is in the application currency and is over Y value";
                break;
            default:
                condition = "Unknown";
                break;
        }

        PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
        PrintAndLogEx(NORMAL, "    %02x %02x: '%s' '%s' and '%s' if this CVM is unsuccessful",
                      tlv->value[i],
                      tlv->value[i + 1],
                      method,
                      condition,
                      (tlv->value[i] & 0x40) ? "continue" : "fail"
                     );
    }
}

static void emv_tag_dump_afl(const struct tlv *tlv, const struct emv_tag *tag, int level) {
    if (tlv->len < 4 || tlv->len % 4) {
        PrintAndLogEx(INFO, "%*s    INVALID!", (level * 4), " ");
        return;
    }

    for (int i = 0; i < tlv->len / 4; i++) {
        PrintAndLogEx(INFO, "%*s" NOLF, (level * 4), " ");
        PrintAndLogEx(NORMAL, "SFI[%02x] start:%02x end:%02x offline:%02x", tlv->value[i * 4 + 0] >> 3, tlv->value[i * 4 + 1], tlv->value[i * 4 + 2], tlv->value[i * 4 + 3]);
    }
}

bool emv_tag_dump(const struct tlv *tlv, int level) {
    if (tlv == NULL) {
        PrintAndLogEx(FAILED, "NULL");
        return false;
    }

    const struct emv_tag *tag = emv_get_tag(tlv);

    PrintAndLogEx(INFO, "%*s--%2x[%02zx] '%s':" NOLF, (level * 4), " ", tlv->tag, tlv->len, tag->name);

    switch (tag->type) {
        case EMV_TAG_GENERIC:
            PrintAndLogEx(NORMAL, "");
            break;
        case EMV_TAG_BITMASK:
            PrintAndLogEx(NORMAL, "");
            emv_tag_dump_bitmask(tlv, tag, level);
            break;
        case EMV_TAG_DOL:
            PrintAndLogEx(NORMAL, "");
            emv_tag_dump_dol(tlv, tag, level);
            break;
        case EMV_TAG_CVM_LIST:
            PrintAndLogEx(NORMAL, "");
            emv_tag_dump_cvm_list(tlv, tag, level);
            break;
        case EMV_TAG_AFL:
            PrintAndLogEx(NORMAL, "");
            emv_tag_dump_afl(tlv, tag, level);
            break;
        case EMV_TAG_STRING:
            emv_tag_dump_string(tlv, tag, level);
            break;
        case EMV_TAG_NUMERIC:
            emv_tag_dump_numeric(tlv, tag, level);
            break;
        case EMV_TAG_YYMMDD:
            emv_tag_dump_yymmdd(tlv, tag, level);
            break;
        case EMV_TAG_CVR:
            PrintAndLogEx(NORMAL, "");
            emv_tag_dump_cvr(tlv, tag, level);
            break;
        case EMV_TAG_CID:
            PrintAndLogEx(NORMAL, "");
            emv_tag_dump_cid(tlv, tag, level);
            break;
    };

    return true;
}

const char *emv_get_tag_name(const struct tlv *tlv) {
    static const char *defstr = "";

    if (!tlv)
        return defstr;

    const struct emv_tag *tag = emv_get_tag(tlv);
    if (tag)
        return tag->name;

    return defstr;
}
