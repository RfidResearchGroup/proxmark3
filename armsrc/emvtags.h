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
// structure to hold EMV card and terminal parameters
//-----------------------------------------------------------------------------
#ifndef __EMVCARD_H
#define __EMVCARD_H

#include "common.h"

//structure to hold received/set tag values
//variable data inputs have length specifiers
typedef struct {
    //ISO14443-A card stuff
    uint8_t ATQA[2]; //Answer to Request
    uint8_t UID_len;
    uint8_t UID[10];
    uint8_t SAK1; //SAK for UID 1
    uint8_t SAK2; //SAK for UID 2
    uint8_t ATS_len; //Answer to select
    uint8_t ATS[256];
    //ATS
    uint8_t TL;
    uint8_t T0;
    uint8_t TA1;
    uint8_t TB1;
    uint8_t TC1;
    uint8_t *historicalbytes;
    //PPS response
    uint8_t PPSS;
    //SFI 2 record 1
    uint8_t tag_4F_len; //length of AID
    uint8_t tag_4F[16]; //Application Identifier (AID)
    uint8_t tag_50_len; //length of application label
    uint8_t tag_50[16]; //Application Label
    uint8_t tag_56_len; //track1 length
    uint8_t tag_56[76]; //Track 1 Data
    uint8_t tag_57_len; //track2 equiv len
    uint8_t tag_57[19]; //Track 2 Equivalent Data
    uint8_t tag_5A_len; //PAN length
    uint8_t tag_5A[10]; //Application Primary Account Number (PAN)
    //uint8_t tag_6F[]; //File Control Information (FCI) Template
    //uint8_t tag_70[255]; //Record Template
    //uint8_t tag_77[]; //Response Message Template Format 2
    //uint8_t tag_80[]; //Response Message Template Format 1
    uint8_t tag_82[2]; //Application Interchange Profile AIP
    //uint8_t tag_83[]; //Command Template
    uint8_t tag_84_len;
    uint8_t tag_84[16]; //DF Name
    uint8_t tag_86_len;
    uint8_t tag_86[261]; //Issuer Script Command
    uint8_t tag_87[1]; //Application Priority Indicator
    uint8_t tag_88[1]; //Short File Identifier
    uint8_t tag_8A[2]; //Authorisation Response Code
    uint8_t tag_8C_len;
    uint8_t tag_8C[252]; //CDOL1
    uint8_t tag_8D_len;
    uint8_t tag_8D[252]; //CDOL2
    uint8_t tag_8E_len;
    uint8_t tag_8E[252]; //Cardholder Verification Method (CVM) List
    uint8_t tag_8F[1];  //Certification Authority Public Key Index
    uint8_t tag_90_len;
    uint8_t tag_90[255]; //ssuer Public Key Certificate
    uint8_t tag_92_len;
    uint8_t tag_92[255]; //Issuer Public Key Remainder
    uint8_t tag_93_len;
    uint8_t tag_93[255]; //Signed Static Application Data
    uint8_t tag_94_len;
    uint8_t tag_94[252]; //Application File Locator AFL
    uint8_t tag_95[5]; //Terminal Verification Results
    uint8_t tag_97_len;
    uint8_t tag_97[252]; //Transaction Certificate Data Object List (TDOL)
    uint8_t tag_98[20]; //Transaction Certificate (TC) Hash Value
    //assume 20 bytes, change after testing
    uint8_t tag_99_len;
    uint8_t tag_99[20]; //Transaction Personal Identification Number (PIN) Data
    uint8_t tag_9A[3]; //Transaction Date
    uint8_t tag_9B[2]; //Transaction Status Information
    uint8_t tag_9C[1]; //Transaction Type
    uint8_t tag_9D_len;
    uint8_t tag_9D[16]; //Directory Definition File

    uint8_t tag_CD[3]; //Card Issuer Action Codes Paypass
    uint8_t tag_CE[3];
    uint8_t tag_CF[3];

    uint8_t tag_D7[3]; //Application Control (PayPass)
    uint8_t tag_D8[2]; //Application Interchange Profile (PayPass)
    uint8_t tag_D9_len; //Application File Locator (PayPass)
    uint8_t tag_D9[16];
    uint8_t tag_DA[2]; //Static CVC3track1
    uint8_t tag_DB[2]; //Static CVC3track2
    uint8_t tag_DC[2]; //IVCVC3 CVC3track1
    uint8_t tag_DD[2]; //IVCVC3 CVC3track2

    uint8_t tag_AF_len;
    uint8_t tag_AF[255]; //Proprietary Information

    uint8_t tag_5F20_len;
    uint8_t tag_5F20[26]; //Cardholder Name
    uint8_t tag_5F24[3]; //Application Expiry Date
    uint8_t tag_5F25[3]; //Application Effective Date YYMMDD
    uint8_t tag_5F28[2]; //Issuer Country Code
    uint8_t tag_5F2A[2]; //Transaction Currency Code
    uint8_t tag_5F2D_len;
    uint8_t tag_5F2D[8]; //Language Preference
    uint8_t tag_5F30[2]; //Service Code
    uint8_t tag_5F34[1]; //Application Primary Account Number (PAN) Sequence Number
    uint8_t tag_5F36[2]; //ATC
    uint8_t tag_5F50_len;
    uint8_t tag_5F50[255]; //Issuer URL
    uint8_t tag_5F54_len;
    uint8_t tag_5F54[11]; //Bank Identifier Code (BIC)
    uint8_t tag_9F01[6]; //Acquirer Identifier
    uint8_t tag_9F02[6]; // Amount, Authorised (Numeric)
    uint8_t tag_9F03[6]; //Amount, Other (Numeric)
    uint8_t tag_9F04[4]; //Amount, Other (Binary)
    uint8_t tag_9F05_len;
    uint8_t tag_9F05[32]; //Application Discretionary Data
    uint8_t tag_9F06_len;
    uint8_t tag_9F06[16]; //AID terminal
    uint8_t tag_9F07[2]; //Application Usage Control
    uint8_t tag_9F08[2]; //Application Version Number
    uint8_t tag_9F09[2]; //Application Version Number
    //uint8_t tag_9F0A[2]
    uint8_t tag_9F0B_len;
    uint8_t tag_9F0B[45]; //Cardholder Name Extended
    uint8_t tag_9F0D[5]; //Issuer Action Code - Default
    uint8_t tag_9F0E[5]; //Issuer Action Code - Denial
    uint8_t tag_9F0F[5]; //Issuer Action Code - Online
    uint8_t tag_9F10_len; //Issuer Application Data
    uint8_t tag_9F10[32];
    uint8_t tag_9F11[1]; //Issuer Code Table Index
    uint8_t tag_9F12_len;
    uint8_t tag_9F12[255]; //Application Preferred Name
    uint8_t tag_9F13[2]; //Last Online Application Transaction Counter (ATC) Registerjk
    uint8_t tag_9F14[1]; //Lower Consecutive Offline Limit
    uint8_t tag_9F15[2]; //Merchant Category Code
    uint8_t tag_9F16[15]; //Merchant Identifier
    uint8_t tag_9F17[1]; //Personal Identification Number (PIN) Try Counter
    uint8_t tag_9F18[4]; //Issuer Script Identifier
    //uint8_t tag_9F19[]
    uint8_t tag_9F1A[2]; //Terminal Country Code
    uint8_t tag_9F1B[4]; //Terminal Floor Limit
    uint8_t tag_9F1C[8]; //Terminal Identification
    uint8_t tag_9F1D_len;
    uint8_t tag_9F1D[8]; //Terminal Risk Management Data
    uint8_t tag_9F1E[8]; //Interface Device (IFD) Serial Number
    uint8_t tag_9F1F_len;
    uint8_t tag_9F1F[255]; //Track 1 Discretionary Data
    uint8_t tag_9F20_len;
    uint8_t tag_9F20[255]; //Track 2 DD
    uint8_t tag_9F21[3]; //Transaction Time
    uint8_t tag_9F22[1]; //Certification Authority Public Key Index
    uint8_t tag_9F23[1]; //Upper Consecutive Offline Limit
    //uint8_t tag_9F24
    //uint8_t tag_9F25
    uint8_t tag_9F26[8]; //Application Cryptogram
    uint8_t tag_9F27[1]; //Cryptogram Information Data
    //uint8_t tag_9F28
    //uint8_t tag_9F29
    //uint8_t tag_9F2A
    //uint8_t tag_9F2B
    //uint8_t tag_9F2C
    uint8_t tag_9F2D_len;
    uint8_t tag_9F2D[255]; //Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate
    uint8_t tag_9F2E[3]; //Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent
    uint8_t tag_9F2F_len;
    uint8_t tag_9F2F[255]; //Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder
    //uint8_t tag_9F30
    //uint8_t tag_9F31
    uint8_t tag_9F32_len;
    uint8_t tag_9F32[3]; //Issuer Public Key Exponent
    uint8_t tag_9F33[3]; //Terminal Capabilities
    uint8_t tag_9F34[3]; //Cardholder Verification Method (CVM) Results
    uint8_t tag_9F35[1]; //Terminal Type
    uint8_t tag_9F36[2]; //Application Transaction Counter (ATC)
    uint8_t tag_9F37[8]; //Unpredictable Number
    uint8_t tag_9F38_len;
    uint8_t tag_9F38[255]; //PDOL
    uint8_t tag_9F39[1]; //Point-of-Service (POS) Entry Mode
    uint8_t tag_9F40[5]; //Additional Terminal Capabilities
    uint8_t tag_9F41[4]; //Transaction Sequence Counter
    uint8_t tag_9F42[2]; //Application Currency Code
    uint8_t tag_9F43[4]; //Application Reference Currency Exponent
    uint8_t tag_9F44[1]; //Application Currency Exponent
    uint8_t tag_9F45[2]; //Data Authentication Code
    uint8_t tag_9F46_len;
    uint8_t tag_9F46[255]; //ICC Public Key Certificate
    uint8_t tag_9F47_len;
    uint8_t tag_9F47[3]; //ICC Public Key Exponent
    uint8_t tag_9F48_len;
    uint8_t tag_9F48[255]; //ICC Public Key Remainder
    uint8_t tag_9F49_len;
    uint8_t tag_9F49[252];
    uint8_t tag_9F4A[1]; //SDA Tag list
    uint8_t tag_9F4B_len;
    uint8_t tag_9F4B[255]; //Signed Dynamic Application Data
    uint8_t tag_9F4C[8]; //ICC Dynamic Number
    uint8_t tag_9F4D[2]; //Log Entry
    uint8_t tag_9F4E[255]; //Merchant Name and Location
    //9F50-9F7F are payment system specific
    uint8_t tag_9F60[2]; //CVC3 track1
    uint8_t tag_9F61[2]; //CVC3 track2
    uint8_t tag_9F62[6]; //Track 1 Bit Map for CVC3 (PCVC3TRACK1)
    uint8_t tag_9F63[6]; //Track 1 Bit Map for UN and ATC (PUNATCTRACK1)
    uint8_t tag_9F64[1]; //Track 1 Number of ATC Digits (NATCTRACK1)
    uint8_t tag_9F65[2]; //rack 2 Bit Map for CVC3 (PCVC3TRACK2)
    uint8_t tag_9F66[4];   //Track 2 Bit Map for UN and ATC (PUNATCTRACK2), or VISA card type
    uint8_t tag_9F67[1];   //Track 2 Number of ATC Digits (NATCTRACK2)
    uint8_t tag_9F68_len;
    uint8_t tag_9F68[252]; //Mag Stripe CVM List
    uint8_t tag_9F69_len;
    uint8_t tag_9F69[255]; //Unpredictable Number Data Object List (UDOL)
    uint8_t tag_9F6A[8]; //Unpredictable Number (Numeric)
    uint8_t tag_9F6B_len;
    uint8_t tag_9F6B[19]; //track 2 data
    uint8_t tag_9F6C[2]; //Mag Stripe Application Version  Number(Card)
    //template holders
    uint8_t tag_61_len;
    uint8_t tag_61[255]; //Application template
    uint8_t tag_6F_len;
    uint8_t tag_6F[255]; //6F template
    uint8_t tag_A5_len;
    uint8_t tag_A5[255]; //A5 template
    uint8_t tag_DFNAME_len;
    uint8_t tag_DFNAME[255]; //A5 template
    uint8_t tag_70_len;
    uint8_t tag_70[255]; //70 template
    uint8_t tag_77_len;
    uint8_t tag_77[255]; //77 template
    uint8_t tag_80_len;
    uint8_t tag_80[255]; //80 template
    uint8_t tag_91_len; //Issuer Authentication Data
    uint8_t tag_91[16];
    uint8_t tag_BF0C_len;
    uint8_t tag_BF0C[222]; //File Control Information (FCI) Issuer Discretionary Data
    uint8_t tag_DFName[16];
    uint8_t tag_DFName_len;
} emvtags_t;

#endif //__EMVCARD_H
