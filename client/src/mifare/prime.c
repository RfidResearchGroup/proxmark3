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
// Shared MIFARE Prime helpers for ISO-DEP based MIFARE protocols
//-----------------------------------------------------------------------------

#include "mifare/prime.h"

#include <stdio.h>
#include "ui.h"

/*
  The 7 MSBits (= n) code the storage size itself based on 2^n,
  the LSBit is set to '0' if the size is exactly 2^n
    and set to '1' if the storage size is between 2^n and 2^(n+1).
    For this version of DESFire the 7 MSBits are set to 0x0C (2^12 = 4096) and the LSBit is '0'.
*/
const char *mifare_prime_get_card_size_str(uint8_t fsize) {

    static char buf[40] = {0x00};
    char *retStr = buf;

    uint16_t usize = 1U << (((uint16_t)fsize >> 1U) + 1U);
    uint16_t lsize = 1U << ((uint16_t)fsize >> 1U);

    // is LSB set?
    if (fsize & 1U) {
        snprintf(retStr, sizeof(buf), "0x%02X ( " _GREEN_("%d - %d bytes") " )", fsize, usize, lsize);
    } else {
        snprintf(retStr, sizeof(buf), "0x%02X ( " _GREEN_("%d bytes") " )", fsize, lsize);
    }
    return buf;
}

const char *mifare_prime_get_protocol_str(uint8_t id, bool hw) {

    static char buf[64] = {0x00};
    char *retStr = buf;

    if (id == 0x04) {
        snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("ISO 14443-3 MIFARE, 14443-4") " )", id);
    } else if (id == 0x05) {
        if (hw) {
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("ISO 14443-2, 14443-3") " )", id);
        } else {
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("ISO 14443-3, 14443-4") " )", id);
        }
    } else if (id == 0x20) {
        snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("I2C") " )", id);
    } else if (id == 0x25) {
        snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("I2C and ISO/IEC 14443-4") " )", id);
    } else {
        snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("Unknown") " )", id);
    }
    return buf;
}

const char *mifare_prime_get_version_str(uint8_t type, uint8_t major, uint8_t minor) {

    static char buf[60] = {0x00};
    char *retStr = buf;

    if (type == 0x01 && major == 0x00) {
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire MF3ICD40") " )", major, minor);
    } else if (major == 0x10 && minor == 0x00) {
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("NTAG413DNA") " )", major, minor);
    } else if (type == 0x01 && major == 0x01 && minor == 0x00) {
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV1") " )", major, minor);
    } else if (type == 0x01 && major == 0x12 && minor == 0x00) {
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV2") " )", major, minor);
    } else if (type == 0x01 && major == 0x22 && minor == 0x00) {
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV2 XL") " )", major, minor);
    } else if (type == 0x01 && major == 0x42 && minor == 0x00) {
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV2") " )", major, minor);
    } else if (type == 0x01 && major == 0x33 && minor == 0x00) {
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV3") " )", major, minor);
    } else if (type == 0x81 && major == 0x43 && minor == 0x01) {
        // Swisskey iShield Key
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV3C implementation on P71D600") " )", major, minor);
    } else if (type == 0x01 && major == 0x30 && minor == 0x00) {
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire Light") " )", major, minor);
    } else if (type == 0x02 && major == 0x11 && minor == 0x00) {
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("Plus EV1") " )", major, minor);
    } else if (type == 0x02 && major == 0x22 && minor == 0x00) {
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("Plus EV2") " )", major, minor);
    } else if (type == 0x01 && major == 0xA0 && minor == 0x00) {
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DUOX") " )", major, minor);
    } else if ((type & 0x08) == 0x08) {
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire Light") " )", major, minor);
    } else {
        snprintf(retStr, sizeof(buf), "%x.%x ( " _YELLOW_("Unknown") " )", major, minor);
    }
    return buf;
}

const char *mifare_prime_get_type_str(uint8_t type) {

    static char buf[40] = {0x00};
    char *retStr = buf;

    switch (type) {
        case 0x01:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("DESFire") " )", type);
            break;
        case 0x02:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("Plus") " )", type);
            break;
        case 0x03:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("Ultralight") " )", type);
            break;
        case 0x04:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("NTAG") " )", type);
            break;
        case 0x81:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("Smartcard") " )", type);
            break;
        case 0x91:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("Applet") " )", type);
            break;
        default:
            snprintf(retStr, sizeof(buf), "0x%02X", type);
            break;
    }
    return buf;
}
