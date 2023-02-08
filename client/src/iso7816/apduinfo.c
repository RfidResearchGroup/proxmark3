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
// APDU status bytes information
//-----------------------------------------------------------------------------

#include "apduinfo.h"

#include <string.h> // memmove
#include <stdio.h>

#include "ui.h"  // Print...
#include "util.h"
#include "commonutil.h"  // ARRAYLEN

const APDUCode_t APDUCodeTable[] = {
    //  ID             Type                  Description
    {"XXXX",     APDUCODE_TYPE_NONE,         ""}, // blank string
    {"6---",     APDUCODE_TYPE_ERROR,        "Class not supported."},
    {"61--",     APDUCODE_TYPE_INFO,         "Response bytes still available"},
    {"61XX",     APDUCODE_TYPE_INFO,         "Command successfully executed; 'XX' bytes of data are available and can be requested using GET RESPONSE."},
    {"62--",     APDUCODE_TYPE_WARNING,      "State of non-volatile memory unchanged"},
    {"6200",     APDUCODE_TYPE_WARNING,      "No information given (NV-Ram not changed)"},
    {"6201",     APDUCODE_TYPE_WARNING,      "NV-Ram not changed 1."},
    {"6281",     APDUCODE_TYPE_WARNING,      "Part of returned data may be corrupted"},
    {"6282",     APDUCODE_TYPE_WARNING,      "End of file/record reached before reading Le bytes"},
    {"6283",     APDUCODE_TYPE_WARNING,      "Selected file invalidated"},
    {"6284",     APDUCODE_TYPE_WARNING,      "Selected file is not valid. FCI not formatted according to ISO"},
    {"6285",     APDUCODE_TYPE_WARNING,      "No input data available from a sensor on the card. No Purse Engine enslaved for R3bc"},
    {"62A2",     APDUCODE_TYPE_WARNING,      "Wrong R-MAC"},
    {"62A4",     APDUCODE_TYPE_WARNING,      "Card locked (during reset( ))"},
    {"62CX",     APDUCODE_TYPE_WARNING,      "Counter with value x (command dependent)"},
    {"62F1",     APDUCODE_TYPE_WARNING,      "Wrong C-MAC"},
    {"62F3",     APDUCODE_TYPE_WARNING,      "Internal reset"},
    {"62F5",     APDUCODE_TYPE_WARNING,      "Default agent locked"},
    {"62F7",     APDUCODE_TYPE_WARNING,      "Cardholder locked"},
    {"62F8",     APDUCODE_TYPE_WARNING,      "Basement is current agent"},
    {"62F9",     APDUCODE_TYPE_WARNING,      "CALC Key Set not unblocked"},
    {"62FX",     APDUCODE_TYPE_WARNING,      "-"},
    {"62XX",     APDUCODE_TYPE_WARNING,      "RFU"},
    {"63--",     APDUCODE_TYPE_WARNING,      "State of non-volatile memory changed"},
    {"6300",     APDUCODE_TYPE_WARNING,      "No information given (NV-Ram changed)"},
    {"6381",     APDUCODE_TYPE_WARNING,      "File filled up by the last write. Loading/updating is not allowed."},
    {"6382",     APDUCODE_TYPE_WARNING,      "Card key not supported."},
    {"6383",     APDUCODE_TYPE_WARNING,      "Reader key not supported."},
    {"6384",     APDUCODE_TYPE_WARNING,      "Plaintext transmission not supported."},
    {"6385",     APDUCODE_TYPE_WARNING,      "Secured transmission not supported."},
    {"6386",     APDUCODE_TYPE_WARNING,      "Volatile memory is not available."},
    {"6387",     APDUCODE_TYPE_WARNING,      "Non-volatile memory is not available."},
    {"6388",     APDUCODE_TYPE_WARNING,      "Key number not valid."},
    {"6389",     APDUCODE_TYPE_WARNING,      "Key length is not correct."},
    {"63C0",     APDUCODE_TYPE_WARNING,      "Verify fail, no try left."},
    {"63C1",     APDUCODE_TYPE_WARNING,      "Verify fail, 1 try left."},
    {"63C2",     APDUCODE_TYPE_WARNING,      "Verify fail, 2 tries left."},
    {"63C3",     APDUCODE_TYPE_WARNING,      "Verify fail, 3 tries left."},
    {"63CX",     APDUCODE_TYPE_WARNING,      "The counter has reached the value 'x' (0 = x = 15) (command dependent)."},
    {"63F1",     APDUCODE_TYPE_WARNING,      "More data expected."},
    {"63F2",     APDUCODE_TYPE_WARNING,      "More data expected and proactive command pending."},
    {"63FX",     APDUCODE_TYPE_WARNING,      "-"},
    {"63XX",     APDUCODE_TYPE_WARNING,      "RFU"},
    {"64--",     APDUCODE_TYPE_ERROR,        "State of non-volatile memory unchanged"},
    {"6400",     APDUCODE_TYPE_ERROR,        "No information given (NV-Ram not changed)"},
    {"6401",     APDUCODE_TYPE_ERROR,        "Command timeout. Immediate response required by the card."},
    {"64XX",     APDUCODE_TYPE_ERROR,        "RFU"},
    {"65--",     APDUCODE_TYPE_ERROR,        "State of non-volatile memory changed"},
    {"6500",     APDUCODE_TYPE_ERROR,        "No information given"},
    {"6501",     APDUCODE_TYPE_ERROR,        "Write error. Memory failure. There have been problems in writing or reading the EEPROM. Other hardware problems may also bring this error."},
    {"6581",     APDUCODE_TYPE_ERROR,        "Memory failure"},
    {"65FX",     APDUCODE_TYPE_ERROR,        "-"},
    {"65XX",     APDUCODE_TYPE_ERROR,        "RFU"},
    {"66--",     APDUCODE_TYPE_SECURITY,     " "},
    {"6600",     APDUCODE_TYPE_SECURITY,     "Error while receiving (timeout)"},
    {"6601",     APDUCODE_TYPE_SECURITY,     "Error while receiving (character parity error)"},
    {"6602",     APDUCODE_TYPE_SECURITY,     "Wrong checksum"},
    {"6603",     APDUCODE_TYPE_SECURITY,     "The current DF file without FCI"},
    {"6604",     APDUCODE_TYPE_SECURITY,     "No SF or KF under the current DF"},
    {"6669",     APDUCODE_TYPE_SECURITY,     "Incorrect Encryption/Decryption Padding"},
    {"66XX",     APDUCODE_TYPE_SECURITY,     "-"},
    {"67--",     APDUCODE_TYPE_ERROR,        " "},
    {"6700",     APDUCODE_TYPE_ERROR,        "Wrong length"},
    {"67XX",     APDUCODE_TYPE_ERROR,        "length incorrect (procedure)(ISO 7816-3)"},
    {"68--",     APDUCODE_TYPE_ERROR,        "Functions in CLA not supported"},
    {"6800",     APDUCODE_TYPE_ERROR,        "No information given (The request function is not supported by the card)"},
    {"6881",     APDUCODE_TYPE_ERROR,        "Logical channel not supported"},
    {"6882",     APDUCODE_TYPE_ERROR,        "Secure messaging not supported"},
    {"6883",     APDUCODE_TYPE_ERROR,        "Last command of the chain expected"},
    {"6884",     APDUCODE_TYPE_ERROR,        "Command chaining not supported"},
    {"68FX",     APDUCODE_TYPE_ERROR,        "-"},
    {"68XX",     APDUCODE_TYPE_ERROR,        "RFU"},
    {"69--",     APDUCODE_TYPE_ERROR,        "Command not allowed"},
    {"6900",     APDUCODE_TYPE_ERROR,        "No information given (Command not allowed)"},
    {"6901",     APDUCODE_TYPE_ERROR,        "Command not accepted (inactive state)"},
    {"6981",     APDUCODE_TYPE_ERROR,        "Command incompatible with file structure"},
    {"6982",     APDUCODE_TYPE_ERROR,        "Security condition not satisfied."},
    {"6983",     APDUCODE_TYPE_ERROR,        "Authentication method blocked"},
    {"6984",     APDUCODE_TYPE_ERROR,        "Referenced data reversibly blocked (invalidated)"},
    {"6985",     APDUCODE_TYPE_ERROR,        "Conditions of use not satisfied."},
    {"6986",     APDUCODE_TYPE_ERROR,        "Command not allowed (no current EF)"},
    {"6987",     APDUCODE_TYPE_ERROR,        "Expected secure messaging (SM) object missing"},
    {"6988",     APDUCODE_TYPE_ERROR,        "Incorrect secure messaging (SM) data object"},
    {"698D",     APDUCODE_TYPE_NONE,         "Reserved"},
    {"6996",     APDUCODE_TYPE_ERROR,        "Data must be updated again"},
    {"69E1",     APDUCODE_TYPE_ERROR,        "POL1 of the currently Enabled Profile prevents this action."},
    {"69F0",     APDUCODE_TYPE_ERROR,        "Permission Denied"},
    {"69F1",     APDUCODE_TYPE_ERROR,        "Permission Denied - Missing Privilege"},
    {"69FX",     APDUCODE_TYPE_ERROR,        "-"},
    {"69XX",     APDUCODE_TYPE_ERROR,        "RFU"},
    {"6A--",     APDUCODE_TYPE_ERROR,        "Wrong parameter(s) P1-P2"},
    {"6A00",     APDUCODE_TYPE_ERROR,        "No information given (Bytes P1 and/or P2 are incorrect)"},
    {"6A80",     APDUCODE_TYPE_ERROR,        "The parameters in the data field are incorrect."},
    {"6A81",     APDUCODE_TYPE_ERROR,        "Function not supported"},
    {"6A82",     APDUCODE_TYPE_ERROR,        "File not found"},
    {"6A83",     APDUCODE_TYPE_ERROR,        "Record not found"},
    {"6A84",     APDUCODE_TYPE_ERROR,        "There is insufficient memory space in record or file"},
    {"6A85",     APDUCODE_TYPE_ERROR,        "Lc inconsistent with TLV structure"},
    {"6A86",     APDUCODE_TYPE_ERROR,        "Incorrect P1 or P2 parameter."},
    {"6A87",     APDUCODE_TYPE_ERROR,        "Lc inconsistent with P1-P2"},
    {"6A88",     APDUCODE_TYPE_ERROR,        "Referenced data not found"},
    {"6A89",     APDUCODE_TYPE_ERROR,        "File already exists"},
    {"6A8A",     APDUCODE_TYPE_ERROR,        "DF name already exists."},
    {"6AF0",     APDUCODE_TYPE_ERROR,        "Wrong parameter value"},
    {"6AFX",     APDUCODE_TYPE_ERROR,        "-"},
    {"6AXX",     APDUCODE_TYPE_ERROR,        "RFU"},
    {"6B--",     APDUCODE_TYPE_ERROR,        " "},
    {"6B00",     APDUCODE_TYPE_ERROR,        "Wrong parameter(s) P1-P2"},
    {"6BXX",     APDUCODE_TYPE_ERROR,        "Reference incorrect (procedure byte), (ISO 7816-3)"},
    {"6C--",     APDUCODE_TYPE_ERROR,        "Wrong length Le"},
    {"6C00",     APDUCODE_TYPE_ERROR,        "Incorrect P3 length."},
    {"6CXX",     APDUCODE_TYPE_ERROR,        "Bad length value in Le; 'xx' is the correct exact Le"},
    {"6D--",     APDUCODE_TYPE_ERROR,        " "},
    {"6D00",     APDUCODE_TYPE_ERROR,        "Instruction code not supported or invalid"},
    {"6DXX",     APDUCODE_TYPE_ERROR,        "Instruction code not programmed or invalid (procedure byte), (ISO 7816-3)"},
    {"6E--",     APDUCODE_TYPE_ERROR,        " "},
    {"6E00",     APDUCODE_TYPE_ERROR,        "Class not supported"},
    {"6EXX",     APDUCODE_TYPE_ERROR,        "Instruction class not supported (procedure byte), (ISO 7816-3)"},
    {"6F--",     APDUCODE_TYPE_ERROR,        "Internal exception"},
    {"6F00",     APDUCODE_TYPE_ERROR,        "Command aborted - more exact diagnosis not possible (e.g., operating system error)."},
    {"6FFF",     APDUCODE_TYPE_ERROR,        "Card dead (overuse)"},
    {"6FXX",     APDUCODE_TYPE_ERROR,        "No precise diagnosis (procedure byte), (ISO 7816-3)"},
    {"9---",     APDUCODE_TYPE_NONE,         ""},
    {"9000",     APDUCODE_TYPE_INFO,         "Command successfully executed (OK)."},
    {"9004",     APDUCODE_TYPE_WARNING,      "PIN not successfully verified, 3 or more PIN tries left"},
    {"9008",     APDUCODE_TYPE_NONE,         "Key/file not found"},
    {"9080",     APDUCODE_TYPE_WARNING,      "Unblock Try Counter has reached zero"},
    {"9100",     APDUCODE_TYPE_NONE,         "OK"},
    {"9101",     APDUCODE_TYPE_NONE,         "States.activity, States.lock Status or States.lockable has wrong value"},
    {"9102",     APDUCODE_TYPE_NONE,         "Transaction number reached its limit"},
    {"910C",     APDUCODE_TYPE_NONE,         "No changes"},
    {"910E",     APDUCODE_TYPE_NONE,         "Insufficient NV-Memory to complete command"},
    {"911C",     APDUCODE_TYPE_NONE,         "Command code not supported"},
    {"911E",     APDUCODE_TYPE_NONE,         "CRC or MAC does not match data"},
    {"9140",     APDUCODE_TYPE_NONE,         "Invalid key number specified"},
    {"917E",     APDUCODE_TYPE_NONE,         "Length of command string invalid"},
    {"919D",     APDUCODE_TYPE_NONE,         "Not allow the requested command"},
    {"919E",     APDUCODE_TYPE_NONE,         "Value of the parameter invalid"},
    {"91A0",     APDUCODE_TYPE_NONE,         "Requested AID not present on PICC"},
    {"91A1",     APDUCODE_TYPE_NONE,         "Unrecoverable error within application"},
    {"91AE",     APDUCODE_TYPE_NONE,         "Authentication status does not allow the requested command"},
    {"91AF",     APDUCODE_TYPE_NONE,         "Additional data frame is expected to be sent"},
    {"91BE",     APDUCODE_TYPE_NONE,         "Out of boundary"},
    {"91C1",     APDUCODE_TYPE_NONE,         "Unrecoverable error within PICC"},
    {"91CA",     APDUCODE_TYPE_NONE,         "Previous Command was not fully completed"},
    {"91CD",     APDUCODE_TYPE_NONE,         "PICC was disabled by an unrecoverable error"},
    {"91CE",     APDUCODE_TYPE_NONE,         "Number of Applications limited to 28"},
    {"91DE",     APDUCODE_TYPE_NONE,         "File or application already exists"},
    {"91EE",     APDUCODE_TYPE_NONE,         "Could not complete NV-write operation due to loss of power"},
    {"91F0",     APDUCODE_TYPE_NONE,         "Specified file number does not exist"},
    {"91F1",     APDUCODE_TYPE_NONE,         "Unrecoverable error within file"},
    {"920x",     APDUCODE_TYPE_INFO,         "Writing to EEPROM successful after 'x' attempts."},
    {"9210",     APDUCODE_TYPE_ERROR,        "Insufficient memory. No more storage available."},
    {"9240",     APDUCODE_TYPE_ERROR,        "Writing to EEPROM not successful."},
    {"9301",     APDUCODE_TYPE_NONE,         "Integrity error"},
    {"9302",     APDUCODE_TYPE_NONE,         "Candidate S2 invalid"},
    {"9303",     APDUCODE_TYPE_ERROR,        "Application is permanently locked"},
    {"9400",     APDUCODE_TYPE_ERROR,        "No EF selected."},
    {"9401",     APDUCODE_TYPE_NONE,         "Candidate currency code does not match purse currency"},
    {"9402",     APDUCODE_TYPE_NONE,         "Candidate amount too high"},
    {"9402",     APDUCODE_TYPE_ERROR,        "Address range exceeded."},
    {"9403",     APDUCODE_TYPE_NONE,         "Candidate amount too low"},
    {"9404",     APDUCODE_TYPE_ERROR,        "FID not found, record not found or comparison pattern not found."},
    {"9405",     APDUCODE_TYPE_NONE,         "Problems in the data field"},
    {"9406",     APDUCODE_TYPE_ERROR,        "Required MAC unavailable"},
    {"9407",     APDUCODE_TYPE_NONE,         "Bad currency : purse engine has no slot with R3bc currency"},
    {"9408",     APDUCODE_TYPE_NONE,         "R3bc currency not supported in purse engine"},
    {"9408",     APDUCODE_TYPE_ERROR,        "Selected file type does not match command."},
    {"9580",     APDUCODE_TYPE_NONE,         "Bad sequence"},
    {"9681",     APDUCODE_TYPE_NONE,         "Slave not found"},
    {"9700",     APDUCODE_TYPE_NONE,         "PIN blocked and Unblock Try Counter is 1 or 2"},
    {"9702",     APDUCODE_TYPE_NONE,         "Main keys are blocked"},
    {"9704",     APDUCODE_TYPE_NONE,         "PIN not successfully verified, 3 or more PIN tries left"},
    {"9784",     APDUCODE_TYPE_NONE,         "Base key"},
    {"9785",     APDUCODE_TYPE_NONE,         "Limit exceeded - C-MAC key"},
    {"9786",     APDUCODE_TYPE_NONE,         "SM error - Limit exceeded - R-MAC key"},
    {"9787",     APDUCODE_TYPE_NONE,         "Limit exceeded - sequence counter"},
    {"9788",     APDUCODE_TYPE_NONE,         "Limit exceeded - R-MAC length"},
    {"9789",     APDUCODE_TYPE_NONE,         "Service not available"},
    {"9802",     APDUCODE_TYPE_ERROR,        "No PIN defined."},
    {"9804",     APDUCODE_TYPE_ERROR,        "Access conditions not satisfied, authentication failed."},
    {"9835",     APDUCODE_TYPE_ERROR,        "ASK RANDOM or GIVE RANDOM not executed."},
    {"9840",     APDUCODE_TYPE_ERROR,        "PIN verification not successful."},
    {"9850",     APDUCODE_TYPE_ERROR,        "INCREASE or DECREASE could not be executed because a limit has been reached."},
    {"9862",     APDUCODE_TYPE_ERROR,        "Authentication Error, application specific (incorrect MAC)"},
    {"9900",     APDUCODE_TYPE_NONE,         "1 PIN try left"},
    {"9904",     APDUCODE_TYPE_NONE,         "PIN not successfully verified, 1 PIN try left"},
    {"9985",     APDUCODE_TYPE_NONE,         "Wrong status - Cardholder lock"},
    {"9986",     APDUCODE_TYPE_ERROR,        "Missing privilege"},
    {"9987",     APDUCODE_TYPE_NONE,         "PIN is not installed"},
    {"9988",     APDUCODE_TYPE_NONE,         "Wrong status - R-MAC state"},
    {"9A00",     APDUCODE_TYPE_NONE,         "2 PIN try left"},
    {"9A04",     APDUCODE_TYPE_NONE,         "PIN not successfully verified, 2 PIN try left"},
    {"9A71",     APDUCODE_TYPE_NONE,         "Wrong parameter value - Double agent AID"},
    {"9A72",     APDUCODE_TYPE_NONE,         "Wrong parameter value - Double agent Type"},
    {"9D05",     APDUCODE_TYPE_ERROR,        "Incorrect certificate type"},
    {"9D07",     APDUCODE_TYPE_ERROR,        "Incorrect session data size"},
    {"9D08",     APDUCODE_TYPE_ERROR,        "Incorrect DIR file record size"},
    {"9D09",     APDUCODE_TYPE_ERROR,        "Incorrect FCI record size"},
    {"9D0A",     APDUCODE_TYPE_ERROR,        "Incorrect code size"},
    {"9D10",     APDUCODE_TYPE_ERROR,        "Insufficient memory to load application"},
    {"9D11",     APDUCODE_TYPE_ERROR,        "Invalid AID"},
    {"9D12",     APDUCODE_TYPE_ERROR,        "Duplicate AID"},
    {"9D13",     APDUCODE_TYPE_ERROR,        "Application previously loaded"},
    {"9D14",     APDUCODE_TYPE_ERROR,        "Application history list full"},
    {"9D15",     APDUCODE_TYPE_ERROR,        "Application not open"},
    {"9D17",     APDUCODE_TYPE_ERROR,        "Invalid offset"},
    {"9D18",     APDUCODE_TYPE_ERROR,        "Application already loaded"},
    {"9D19",     APDUCODE_TYPE_ERROR,        "Invalid certificate"},
    {"9D1A",     APDUCODE_TYPE_ERROR,        "Invalid signature"},
    {"9D1B",     APDUCODE_TYPE_ERROR,        "Invalid KTU"},
    {"9D1D",     APDUCODE_TYPE_ERROR,        "MSM controls not set"},
    {"9D1E",     APDUCODE_TYPE_ERROR,        "Application signature does not exist"},
    {"9D1F",     APDUCODE_TYPE_ERROR,        "KTU does not exist"},
    {"9D20",     APDUCODE_TYPE_ERROR,        "Application not loaded"},
    {"9D21",     APDUCODE_TYPE_ERROR,        "Invalid Open command data length"},
    {"9D30",     APDUCODE_TYPE_ERROR,        "Check data parameter is incorrect (invalid start address)"},
    {"9D31",     APDUCODE_TYPE_ERROR,        "Check data parameter is incorrect (invalid length)"},
    {"9D32",     APDUCODE_TYPE_ERROR,        "Check data parameter is incorrect (illegal memory check area)"},
    {"9D40",     APDUCODE_TYPE_ERROR,        "Invalid MSM Controls ciphertext"},
    {"9D41",     APDUCODE_TYPE_ERROR,        "MSM controls already set"},
    {"9D42",     APDUCODE_TYPE_ERROR,        "Set MSM Controls data length less than 2 bytes"},
    {"9D43",     APDUCODE_TYPE_ERROR,        "Invalid MSM Controls data length"},
    {"9D44",     APDUCODE_TYPE_ERROR,        "Excess MSM Controls ciphertext"},
    {"9D45",     APDUCODE_TYPE_ERROR,        "Verification of MSM Controls data failed"},
    {"9D50",     APDUCODE_TYPE_ERROR,        "Invalid MCD Issuer production ID"},
    {"9D51",     APDUCODE_TYPE_ERROR,        "Invalid MCD Issuer ID"},
    {"9D52",     APDUCODE_TYPE_ERROR,        "Invalid set MSM controls data date"},
    {"9D53",     APDUCODE_TYPE_ERROR,        "Invalid MCD number"},
    {"9D54",     APDUCODE_TYPE_ERROR,        "Reserved field error"},
    {"9D55",     APDUCODE_TYPE_ERROR,        "Reserved field error"},
    {"9D56",     APDUCODE_TYPE_ERROR,        "Reserved field error"},
    {"9D57",     APDUCODE_TYPE_ERROR,        "Reserved field error"},
    {"9D60",     APDUCODE_TYPE_ERROR,        "MAC verification failed"},
    {"9D61",     APDUCODE_TYPE_ERROR,        "Maximum number of unblocks reached"},
    {"9D62",     APDUCODE_TYPE_ERROR,        "Card was not blocked"},
    {"9D63",     APDUCODE_TYPE_ERROR,        "Crypto functions not available"},
    {"9D64",     APDUCODE_TYPE_ERROR,        "No application loaded"},
    {"9E00",     APDUCODE_TYPE_NONE,         "PIN not installed"},
    {"9E04",     APDUCODE_TYPE_NONE,         "PIN not successfully verified, PIN not installed"},
    {"9F00",     APDUCODE_TYPE_NONE,         "PIN blocked and Unblock Try Counter is 3"},
    {"9F04",     APDUCODE_TYPE_NONE,         "PIN not successfully verified, PIN blocked and Unblock Try Counter is 3"},
    {"9FXX",     APDUCODE_TYPE_NONE,         "Command successfully executed; 'xx' bytes of data are available and can be requested using GET RESPONSE."},
    {"9XXX",     APDUCODE_TYPE_NONE,         "Application related status, (ISO 7816-3)"}
};

static int CodeCmp(const char *code1, const char *code2) {
    int xsymb = 0;
    int cmp = 0;
    for (int i = 0; i < 4; i++) {
        if (code1[i] == code2[i])
            cmp++;
        if (code1[i] == 'X' || code2[i] == 'X')
            xsymb++;
    }
    if (cmp == 4)
        return 0;

    if (cmp + xsymb == 4)
        return xsymb;

    return -1;
}

const APDUCode_t *GetAPDUCode(uint8_t sw1, uint8_t sw2) {
    char buf[6] = {0};
    int mineq = ARRAYLEN(APDUCodeTable);
    int mineqindx = 0;

    snprintf(buf, sizeof(buf), "%02X%02X", sw1, sw2);

    for (int i = 0; i < ARRAYLEN(APDUCodeTable); i++) {
        int res = CodeCmp(APDUCodeTable[i].ID, buf);

        // equal
        if (res == 0) {
            return &APDUCodeTable[i];
        }

        // with some  'X'
        if (res > 0 && mineq > res) {
            mineq = res;
            mineqindx = i;
        }
    }

    // if we have not equal, but with some 'X'
    if (mineqindx < ARRAYLEN(APDUCodeTable)) {
        return &APDUCodeTable[mineqindx];
    }

    return NULL;
}

const char *GetAPDUCodeDescription(uint8_t sw1, uint8_t sw2) {
    const APDUCode_t *cd = GetAPDUCode(sw1, sw2);
    if (cd)
        return cd->Description;
    else
        return APDUCodeTable[0].Description; //empty string
}

const char *GetSpecificAPDUCodeDesc(const APDUSpcCodeDescription_t *desc, const size_t desclen, uint16_t code) {
    for (int i = 0; i < desclen; i++) {
        if (desc[i].Code == code)
            return desc[i].Description;
    }
    return GetAPDUCodeDescription(code >> 8, code & 0xff);
}

int APDUDecode(uint8_t *data, int len, APDU_t *apdu) {
    ExtAPDUHeader_t *hapdu = (ExtAPDUHeader_t *)data;

    apdu->cla = hapdu->cla;
    apdu->ins = hapdu->ins;
    apdu->p1 = hapdu->p1;
    apdu->p2 = hapdu->p2;

    apdu->lc = 0;
    apdu->data = NULL;
    apdu->le = 0;
    apdu->extended_apdu = false;
    apdu->case_type = 0x00;

    uint8_t b0 = hapdu->lc[0];

    // case 1
    if (len == 4) {
        apdu->case_type = 0x01;
    }

    // case 2S (Le)
    if (len == 5) {
        apdu->case_type = 0x02;
        apdu->le = b0;
        if (!apdu->le)
            apdu->le = 0x100;
    }

    // case 3S (Lc + data)
    if (len == 5U + b0 && b0 != 0) {
        apdu->case_type = 0x03;
        apdu->lc = b0;
    }

    // case 4S (Lc + data + Le)
    if (len == 5U + b0 + 1U && b0 != 0) {
        apdu->case_type = 0x04;
        apdu->lc = b0;
        apdu->le = data[len - 1];
        if (!apdu->le)
            apdu->le = 0x100;
    }

    // extended length apdu
    if (len >= 7 && b0 == 0) {
        uint16_t extlen = (hapdu->lc[1] << 8) + hapdu->lc[2];

        // case 2E (Le) - extended
        if (len == 7) {
            apdu->case_type = 0x12;
            apdu->extended_apdu = true;
            apdu->le = extlen;
            if (!apdu->le)
                apdu->le = 0x10000;
        }

        // case 3E (Lc + data) - extended
        if (len == 7U + extlen) {
            apdu->case_type = 0x13;
            apdu->extended_apdu = true;
            apdu->lc = extlen;
        }

        // case 4E (Lc + data + Le) - extended 2-byte Le
        if (len == 7U + extlen + 2U) {
            apdu->case_type = 0x14;
            apdu->extended_apdu = true;
            apdu->lc = extlen;
            apdu->le = (data[len - 2] << 8) + data[len - 1];
            if (!apdu->le)
                apdu->le = 0x10000;
        }

        // case 4E (Lc + data + Le) - extended 3-byte Le
        if (len == 7U + extlen + 3U && data[len - 3] == 0) {
            apdu->case_type = 0x24;
            apdu->extended_apdu = true;
            apdu->lc = extlen;
            apdu->le = (data[len - 2] << 8) + data[len - 1];
            if (!apdu->le)
                apdu->le = 0x10000;
        }
    }

    if (!apdu->case_type)
        return 1;

    if (apdu->lc) {
        if (apdu->extended_apdu) {
            apdu->data = data + 7;
        } else {
            apdu->data = data + 5;
        }

    }

    return 0;
}

int APDUEncode(APDU_t *apdu, uint8_t *data, int *len) {
    if (len)
        *len = 0;
    if (apdu == NULL)
        return 1;
    if (apdu->le > 0x10000)
        return 1;

    size_t dptr = 0;
    data[dptr++] = apdu->cla;
    data[dptr++] = apdu->ins;
    data[dptr++] = apdu->p1;
    data[dptr++] = apdu->p2;

    if (apdu->lc) { // apdu->lc is uint16_t so max 0xffff
        if (apdu->extended_apdu || apdu->lc > 0xff || apdu->le > 0x100) {
            data[dptr++] = 0x00;
            data[dptr++] = (apdu->lc >> 8) & 0xff;
            data[dptr++] = (apdu->lc) & 0xff;
            memmove(&data[dptr], apdu->data, apdu->lc);
            dptr += apdu->lc;
            apdu->extended_apdu = true;
        } else {
            data[dptr++] = apdu->lc;
            memmove(&data[dptr], apdu->data, apdu->lc);
            dptr += apdu->lc;
        }
    }

    if (apdu->le) {
        if (apdu->extended_apdu) {
            if (apdu->le != 0x10000) {
                data[dptr++] = 0x00;
                data[dptr++] = (apdu->le >> 8) & 0xff;
                data[dptr++] = (apdu->le) & 0xff;
            } else {
                data[dptr++] = 0x00;
                data[dptr++] = 0x00;
                data[dptr++] = 0x00;
            }
        } else {
            if (apdu->le != 0x100)
                data[dptr++] = apdu->le;
            else
                data[dptr++] = 0x00;
        }
    }

    if (len)
        *len = dptr;
    return 0;
}

int APDUEncodeS(sAPDU_t *sapdu, bool extended, uint16_t le, uint8_t *data, int *len) {
    if (extended && le > 0x100)
        return 10;

    APDU_t apdu;

    apdu.cla = sapdu->CLA;
    apdu.ins = sapdu->INS;
    apdu.p1 = sapdu->P1;
    apdu.p2 = sapdu->P2;

    apdu.lc = sapdu->Lc;
    if (sapdu->Lc)
        apdu.data = sapdu->data;
    else
        apdu.data = NULL;
    apdu.le = le;

    apdu.extended_apdu = extended;
    apdu.case_type = 0x00;

    return APDUEncode(&apdu, data, len);
}

void APDUPrint(APDU_t apdu) {
    APDUPrintEx(apdu, 0);
}

void APDUPrintEx(APDU_t apdu, size_t maxdatalen) {
    PrintAndLogEx(INFO, "APDU: %scase=0x%02x cla=0x%02x ins=0x%02x p1=0x%02x p2=0x%02x Lc=0x%02x(%d) Le=0x%02x(%d)",
                  apdu.extended_apdu ? "[e]" : "",
                  apdu.case_type,
                  apdu.cla,
                  apdu.ins,
                  apdu.p1,
                  apdu.p2,
                  apdu.lc,
                  apdu.lc,
                  apdu.le,
                  apdu.le
                 );
    if (maxdatalen > 0)
        PrintAndLogEx(INFO, "data: %s%s", sprint_hex(apdu.data, MIN(apdu.lc, maxdatalen)), apdu.lc > maxdatalen ? "..." : "");
}

void SAPDUPrint(sAPDU_t apdu, size_t maxdatalen) {
    PrintAndLogEx(INFO, "APDU: CLA 0x%02x, INS 0x%02x, P1 0x%02x, P2 0x%02x, Lc 0x%02x(%d)",
                  apdu.CLA,
                  apdu.INS,
                  apdu.P1,
                  apdu.P2,
                  apdu.Lc,
                  apdu.Lc
                 );

    size_t len = apdu.Lc;
    if (maxdatalen > 0)
        len = MIN(apdu.Lc, maxdatalen);

    PrintAndLogEx(INFO, "data { %s%s }", sprint_hex(apdu.data, len), apdu.Lc > len ? "..." : "");
}

