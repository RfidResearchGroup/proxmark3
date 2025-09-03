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
// Wiegand format packing/unpacking routines
//-----------------------------------------------------------------------------
#include "wiegand_formats.h"
#include <stdlib.h>
#include "commonutil.h"

static bool step_parity_check(wiegand_message_t *packed, int start, int length, bool even_parity) {
    bool parity = even_parity;
    for (int i = start; i < start + length; i += 2) {
        // Extract 2 bits
        bool bit1 = get_bit_by_position(packed, i);
        bool bit2 = get_bit_by_position(packed, i + 1);

        // Calculate parity for these 2 bits
        parity ^= (bit1 ^ bit2);
    }
    return parity;
}

static bool Pack_Defcon32(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 42;
    /*
        By implementing this format I hope to make the CTF easier for people to get into next year
        //~~The wiegand data consists of 3 32 bit units that we need to split the data between Bottom and Mid since we have a 42 bit format~~
        We can use the set linear field function instead this seems to be easier.
        |Mid part|   | Bot part of the packed data  |
        PFFFFFFFFF   FFFFFFFIIIICCCCCCCCCCCCCCCCCCCCP
        1111111111   11111111111000000000000000001000
    FC       111111111   1111111 =                         FF FF
    //FC Mid   111111111   0000000 =                         FF 80  These where used to split data between bot/mid
    //FC Bot   000000000   1111111 =                         00 7F
    Issuance                    1111 =                     0F
    Card Number                     11111111111111111111 = 0FFFFF

    */

    // Referenced from MSB
    set_linear_field(packed, card->CardNumber, 21, 20); // 20 bit
    set_linear_field(packed, card->IssueLevel, 17, 4); // 4 bit
    set_linear_field(packed, card->FacilityCode, 1, 16); // 16 bits

    // Parity calc
    //0123456789|0123456789|0123456789|0123456789|01
    //E E E E E |E E E E E |EO O O O O| O O O O O| O
    set_bit_by_position(packed,
                        evenparity32(
    get_nonlinear_field(packed, 10, (uint8_t[]) {2, 4, 6, 8, 10, 12, 14, 16, 18, 20}))
    , 0);

    set_bit_by_position(packed,
                        oddparity32(
    get_nonlinear_field(packed, 10, (uint8_t[]) {21, 23, 25, 27, 29, 31, 33, 35, 37, 39}))
    , 41);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_Defcon32(wiegand_message_t *packed, wiegand_card_t *card) {
    if (packed->Length != 42) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 16);
    card->IssueLevel = get_linear_field(packed, 17, 4);
    card->CardNumber = get_linear_field(packed, 21, 20);

    card->ParityValid =
        (get_bit_by_position(packed, 41) == oddparity32(
    get_nonlinear_field(packed, 10, (uint8_t[]) {21, 23, 25, 27, 29, 31, 33, 35, 37, 39}))) &&
    (get_bit_by_position(packed, 0) ==
    evenparity32(get_nonlinear_field(packed, 10, (uint8_t[]) {2, 4, 6, 8, 10, 12, 14, 16, 18, 20})));
    return true;
}

static bool Pack_H10301(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 26; // Set number of bits
    packed->Bot |= (card->CardNumber & 0xFFFF) << 1;
    packed->Bot |= (card->FacilityCode & 0xFF) << 17;
    packed->Bot |= oddparity32((packed->Bot >> 1) & 0xFFF);
    packed->Bot |= (evenparity32((packed->Bot >> 13) & 0xFFF)) << 25;
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_H10301(wiegand_message_t *packed, wiegand_card_t *card) {
    if (packed->Length != 26) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->CardNumber = (packed->Bot >> 1) & 0xFFFF;
    card->FacilityCode = (packed->Bot >> 17) & 0xFF;
    card->ParityValid =
        (oddparity32((packed->Bot >> 1) & 0xFFF) == (packed->Bot & 1)) &&
        ((evenparity32((packed->Bot >> 13) & 0xFFF)) == ((packed->Bot >> 25) & 1));
    return true;
}

static bool Pack_ind26(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 26; // Set number of bits

    set_linear_field(packed, card->FacilityCode, 1, 12);
    set_linear_field(packed, card->CardNumber, 13, 12);

    set_bit_by_position(packed,
                        evenparity32(get_linear_field(packed, 1, 12))
                        , 0);
    set_bit_by_position(packed,
                        oddparity32(get_linear_field(packed, 13, 12))
                        , 25);

    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_ind26(wiegand_message_t *packed, wiegand_card_t *card) {
    if (packed->Length != 26) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 12);
    card->CardNumber = get_linear_field(packed, 13, 12);

    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 12))) &&
        (get_bit_by_position(packed, 25) == oddparity32(get_linear_field(packed, 13, 12)));
    return true;
}

static bool Pack_Tecom27(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 27;
    set_nonlinear_field(packed, card->FacilityCode, 11, (uint8_t[]) {15, 19, 24, 23, 22, 18, 6, 10, 14, 3, 2});
    set_nonlinear_field(packed, card->CardNumber, 16, (uint8_t[]) {0, 1, 13, 12, 9, 26, 20, 16, 17, 21, 25, 7, 8, 11, 4, 5});
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_Tecom27(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 27) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->CardNumber = get_nonlinear_field(packed, 16, (uint8_t[]) {0, 1, 13, 12, 9, 26, 20, 16, 17, 21, 25, 7, 8, 11, 4, 5});
    card->FacilityCode = get_nonlinear_field(packed, 11, (uint8_t[]) {15, 19, 24, 23, 22, 18, 6, 10, 14, 3, 2});
    return true;
}

static bool Pack_ind27(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 27; // Set number of bits

    set_linear_field(packed, card->FacilityCode, 0, 13);
    set_linear_field(packed, card->CardNumber, 13, 14);

    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_ind27(wiegand_message_t *packed, wiegand_card_t *card) {
    if (packed->Length != 27) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 0, 13);
    card->CardNumber = get_linear_field(packed, 13, 14);
    return true;
}

static bool Pack_indasc27(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 27;
    set_nonlinear_field(packed, card->FacilityCode, 13, (uint8_t[]) {9, 4, 6, 5, 0, 7, 19, 8, 10, 16, 24, 12, 22});
    set_nonlinear_field(packed, card->CardNumber, 14, (uint8_t[]) {26, 1, 3, 15, 14, 17, 20, 13, 25, 2, 18, 21, 11, 23});
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_indasc27(wiegand_message_t *packed, wiegand_card_t *card) {
    if (packed->Length != 27) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_nonlinear_field(packed, 13, (uint8_t[]) {9, 4, 6, 5, 0, 7, 19, 8, 10, 16, 24, 12, 22});
    card->CardNumber = get_nonlinear_field(packed, 14, (uint8_t[]) {26, 1, 3, 15, 14, 17, 20, 13, 25, 2, 18, 21, 11, 23});
    return true;
}

static bool Pack_2804W(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 28;
    set_linear_field(packed, card->FacilityCode, 4, 8);
    set_linear_field(packed, card->CardNumber, 12, 15);
    set_bit_by_position(packed,
    oddparity32(get_nonlinear_field(packed, 16, (uint8_t[]) {4, 5, 7, 8, 10, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25, 26}))
    , 2);
    set_bit_by_position(packed,
                        evenparity32(get_linear_field(packed, 1, 13))
                        , 0);
    set_bit_by_position(packed,
                        oddparity32(get_linear_field(packed, 0, 27))
                        , 27);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_2804W(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 28) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 4, 8);
    card->CardNumber = get_linear_field(packed, 12, 15);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 13))) &&
    (get_bit_by_position(packed, 2) == oddparity32(get_nonlinear_field(packed, 16, (uint8_t[]) {4, 5, 7, 8, 10, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25, 26}))) &&
    (get_bit_by_position(packed, 27) == oddparity32(get_linear_field(packed, 0, 27)));
    return true;
}

static bool Pack_ind29(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 29; // Set number of bits

    set_linear_field(packed, card->FacilityCode, 0, 13);
    set_linear_field(packed, card->CardNumber, 13, 16);

    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_ind29(wiegand_message_t *packed, wiegand_card_t *card) {
    if (packed->Length != 29) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 0, 13);
    card->CardNumber = get_linear_field(packed, 13, 16);
    return true;
}

static bool Pack_ATSW30(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 30;
    set_linear_field(packed, card->FacilityCode, 1, 12);
    set_linear_field(packed, card->CardNumber, 13, 16);
    set_bit_by_position(packed,
                        evenparity32(get_linear_field(packed, 1, 12))
                        , 0);
    set_bit_by_position(packed,
                        oddparity32(get_linear_field(packed, 13, 16))
                        , 29);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_ATSW30(wiegand_message_t *packed, wiegand_card_t *card) {
    if (packed->Length != 30) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 12);
    card->CardNumber = get_linear_field(packed, 13, 16);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 12))) &&
        (get_bit_by_position(packed, 29) == oddparity32(get_linear_field(packed, 13, 16)));
    return true;
}

static bool Pack_ADT31(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 31;
    set_linear_field(packed, card->FacilityCode, 1, 4);
    set_linear_field(packed, card->CardNumber, 5, 23);
    // Parity not known, but 4 bits are unused.
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_ADT31(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 31) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 4);
    card->CardNumber = get_linear_field(packed, 5, 23);
    return true;
}

static bool Pack_hcp32(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 32; // Set number of bits

    set_linear_field(packed, card->CardNumber, 1, 24);

    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_hcp32(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 32) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->CardNumber = get_linear_field(packed, 1, 24);
    return true;
}

static bool Pack_hpp32(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 32; // Set number of bits

    set_linear_field(packed, card->FacilityCode, 1, 12);
    set_linear_field(packed, card->CardNumber, 13, 29);

    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_hpp32(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 32) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 12);
    card->CardNumber = get_linear_field(packed, 13, 29);
    return true;
}

static bool Pack_wie32(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 32; // Set number of bits

    set_linear_field(packed, card->FacilityCode, 4, 12);
    set_linear_field(packed, card->CardNumber, 16, 16);

    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_wie32(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 32) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 4, 12);
    card->CardNumber = get_linear_field(packed, 16, 16);
    return true;
}

static bool Pack_Kastle(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 32; // Set number of bits
    set_bit_by_position(packed, 1, 1); // Always 1
    set_linear_field(packed, card->IssueLevel, 2, 5);
    set_linear_field(packed, card->FacilityCode, 7, 8);
    set_linear_field(packed, card->CardNumber, 15, 16);
    set_bit_by_position(packed, evenparity32(get_linear_field(packed, 1, 16)), 0);
    set_bit_by_position(packed, oddparity32(get_linear_field(packed, 14, 17)), 31);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_Kastle(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 32) return false; // Wrong length? Stop here.
    if (get_bit_by_position(packed, 1) != 1) return false; // Always 1 in this format

    memset(card, 0, sizeof(wiegand_card_t));

    card->IssueLevel = get_linear_field(packed, 2, 5);
    card->FacilityCode = get_linear_field(packed, 7, 8);
    card->CardNumber = get_linear_field(packed, 15, 16);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 16))) &&
        (get_bit_by_position(packed, 31) == oddparity32(get_linear_field(packed, 14, 17)));
    return true;
}

static bool Pack_Kantech(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 32;
    set_linear_field(packed, card->FacilityCode, 7, 8);
    set_linear_field(packed, card->CardNumber, 15, 16);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_Kantech(wiegand_message_t *packed, wiegand_card_t *card) {
    if (packed->Length != 32) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 7, 8);
    card->CardNumber = get_linear_field(packed, 15, 16);
    return true;
}

static bool Pack_D10202(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 33; // Set number of bits
    set_linear_field(packed, card->FacilityCode, 1, 7);
    set_linear_field(packed, card->CardNumber, 8, 24);
    set_bit_by_position(packed, evenparity32(get_linear_field(packed, 1, 16)), 0);
    set_bit_by_position(packed, oddparity32(get_linear_field(packed, 16, 16)), 32);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_D10202(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 33) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->CardNumber = get_linear_field(packed, 8, 24);
    card->FacilityCode = get_linear_field(packed, 1, 7);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 16))) &&
        (get_bit_by_position(packed, 32) == oddparity32(get_linear_field(packed, 16, 16)));
    return true;
}

static bool Pack_H10306(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 34; // Set number of bits
    packed->Bot |= (card->CardNumber & 0xFFFF) << 1;
    packed->Bot |= (card->FacilityCode & 0x7FFF) << 17;
    packed->Mid |= (card->FacilityCode & 0x8000) >> 15;
    packed->Mid |= (evenparity32((packed->Mid & 0x00000001) ^ (packed->Bot & 0xFFFE0000))) << 1;
    packed->Bot |= (oddparity32(packed->Bot & 0x0001FFFE));
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_H10306(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 34) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 16);
    card->CardNumber = get_linear_field(packed, 17, 16);

    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 16))) &&
        (get_bit_by_position(packed, 33) == oddparity32(get_linear_field(packed, 17, 16)));

    return true;
}

static bool Pack_N10002(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 34; // Set number of bits
    set_linear_field(packed, card->FacilityCode, 1, 16);
    set_linear_field(packed, card->CardNumber, 17, 16);

    set_bit_by_position(packed,
                        evenparity32(get_linear_field(packed, 1, 16))
                        , 0);
    set_bit_by_position(packed,
                        oddparity32(get_linear_field(packed, 17, 16))
                        , 33);

    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_N10002(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 34) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 16);
    card->CardNumber = get_linear_field(packed, 17, 16);

    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 16))) &&
        (get_bit_by_position(packed, 33) == oddparity32(get_linear_field(packed, 17, 16)));

    return true;
}

static bool Pack_C1k35s(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 35; // Set number of bits
    packed->Bot |= (card->CardNumber & 0x000FFFFF) << 1;
    packed->Bot |= (card->FacilityCode & 0x000007FF) << 21;
    packed->Mid |= (card->FacilityCode & 0x00000800) >> 11;
    packed->Mid |= (evenparity32((packed->Mid & 0x1) ^ (packed->Bot & 0xB6DB6DB6))) << 1;
    packed->Bot |= (oddparity32((packed->Mid & 0x3) ^ (packed->Bot & 0x6DB6DB6C)));
    packed->Mid |= (oddparity32((packed->Mid & 0x3) ^ (packed->Bot & 0xFFFFFFFF))) << 2;
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_C1k35s(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 35) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->CardNumber = (packed->Bot >> 1) & 0x000FFFFF;
    card->FacilityCode = ((packed->Mid & 1) << 11) | ((packed->Bot >> 21));
    card->ParityValid =
        (evenparity32((packed->Mid & 0x1) ^ (packed->Bot & 0xB6DB6DB6)) == ((packed->Mid >> 1) & 1)) &&
        (oddparity32((packed->Mid & 0x3) ^ (packed->Bot & 0x6DB6DB6C)) == ((packed->Bot >> 0) & 1)) &&
        (oddparity32((packed->Mid & 0x3) ^ (packed->Bot & 0xFFFFFFFF)) == ((packed->Mid >> 2) & 1));
    return true;
}

static bool Pack_H10320(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 37; // Set number of bits

    // first bit is ONE.
    set_bit_by_position(packed, 1, 0);

    // This card is BCD-encoded rather than binary. Set the 4-bit groups independently.
    for (uint32_t idx = 0; idx < 8; idx++) {
        set_linear_field(packed, (uint64_t)(card->CardNumber / pow(10, 7 - idx)) % 10, idx * 4, 4);
    }
    set_bit_by_position(packed, evenparity32(
    get_nonlinear_field(packed, 8, (uint8_t[]) {0, 4, 8, 12, 16, 20, 24, 28})
                        ), 32);
    set_bit_by_position(packed, oddparity32(
    get_nonlinear_field(packed, 8, (uint8_t[]) {1, 5, 9, 13, 17, 21, 25, 29})
                        ), 33);
    set_bit_by_position(packed, evenparity32(
    get_nonlinear_field(packed, 8, (uint8_t[]) {2, 6, 10, 14, 18, 22, 28, 30})
                        ), 34);
    set_bit_by_position(packed, evenparity32(
    get_nonlinear_field(packed, 8, (uint8_t[]) {3, 7, 11, 15, 19, 23, 29, 31})
                        ), 35);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_H10320(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 37) return false; // Wrong length? Stop here.
    if (get_bit_by_position(packed, 0) != 1) {
        return false;
    }

    memset(card, 0, sizeof(wiegand_card_t));

    // This card is BCD-encoded rather than binary. Get the 4-bit groups independently.
    for (uint32_t idx = 0; idx < 8; idx++) {
        uint64_t val = get_linear_field(packed, idx * 4, 4);
        if (val > 9) {
            // Violation of BCD; Zero and exit.
            card->CardNumber = 0;
            return false;
        } else {
            card->CardNumber += val * pow(10, 7 - idx);
        }
    }
    card->ParityValid =
    (get_bit_by_position(packed, 32) == evenparity32(get_nonlinear_field(packed, 8, (uint8_t[]) {0, 4, 8, 12, 16, 20, 24, 28}))) &&
    (get_bit_by_position(packed, 33) ==  oddparity32(get_nonlinear_field(packed, 8, (uint8_t[]) {1, 5, 9, 13, 17, 21, 25, 29}))) &&
    (get_bit_by_position(packed, 34) == evenparity32(get_nonlinear_field(packed, 8, (uint8_t[]) {2, 6, 10, 14, 18, 22, 28, 30}))) &&
    (get_bit_by_position(packed, 35) == evenparity32(get_nonlinear_field(packed, 8, (uint8_t[]) {3, 7, 11, 15, 19, 23, 29, 31})));
    return true;
}

static bool Pack_S12906(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 36; // Set number of bits
    set_linear_field(packed, card->FacilityCode, 1, 8);
    set_linear_field(packed, card->IssueLevel, 9, 2);
    set_linear_field(packed, card->CardNumber, 11, 24);
    set_bit_by_position(packed, oddparity32(get_linear_field(packed, 1, 17)), 0);
    set_bit_by_position(packed, oddparity32(get_linear_field(packed, 17, 18)), 35);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_S12906(wiegand_message_t *packed, wiegand_card_t *card) {
    if (packed->Length != 36) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 8);
    card->IssueLevel = get_linear_field(packed, 9, 2);
    card->CardNumber = get_linear_field(packed, 11, 24);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == oddparity32(get_linear_field(packed, 1, 17))) &&
        (get_bit_by_position(packed, 35) == oddparity32(get_linear_field(packed, 17, 18)));
    return true;
}


// if (card->FacilityCode != 217) return false; // Must be 0b11011001 aka 217 for Grinnell?
// card->IssueLevel = get_linear_field(packed, 9, 2); // These are actually the two even parity bits...
// using 1-based indexing (as shown in screenshots posted by digitalfx):
// Bit  1 ==  odd parity over bits                     2,  3,  5,  6,   8,  9, 13, 14,   16, 17, 19, 20,   22, 23, 25, 26,   28, 29, 31, 32,   34, 35
// Bit 10 == even parity over bits                     3,  4,  6,  7,   9, 12, 14, 15,   17, 18, 20, 21,   23, 24, 26, 27,   29, 30, 32, 33,   35, 36
// Bit 11 == even parity over bits                     2,  4,  5,  7,   8, 12, 13, 15,   16, 18, 19, 21,   22, 24, 25, 27,   28, 30, 31, 33,   34, 36
// Each of these parity cover 22 bits
// Converting the above to 0-based indexing, as required by C:
static const uint8_t S12906b_odd_parity_bit_0[]   = {  1,  2,  4,  5,   7,  8, 12, 13,   15, 16, 18, 19,   21, 22, 24, 25,   27, 28, 30, 31,   33, 34 };
static const uint8_t S12906b_even_parity_bit_9[]  = {  2,  3,  5,  6,   8, 11, 13, 14,   16, 17, 19, 20,   22, 23, 25, 26,   28, 29, 31, 32,   34, 35 };
static const uint8_t S12906b_even_parity_bit_10[] = {  1,  3,  4,  6,   7, 11, 12, 14,   15, 17, 18, 20,   21, 23, 24, 26,   27, 29, 30, 32,   33, 35 };
#define S12906b_BITS_USED_BY_PARITY (22u)
_Static_assert((sizeof( S12906b_odd_parity_bit_0 ) / sizeof( S12906b_odd_parity_bit_0 [0])) == S12906b_BITS_USED_BY_PARITY, "Wrong array length");
_Static_assert((sizeof(S12906b_even_parity_bit_9 ) / sizeof(S12906b_even_parity_bit_9 [0])) == S12906b_BITS_USED_BY_PARITY, "Wrong array length");
_Static_assert((sizeof(S12906b_even_parity_bit_10) / sizeof(S12906b_even_parity_bit_10[0])) == S12906b_BITS_USED_BY_PARITY, "Wrong array length");

static bool Pack_S12906b(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;
    // if (card->FacilityCode != 217) return false; // Must be 0b11011001 aka 217 for Grinnell?
    if (card->IssueLevel != 0u) return false; // This card does not support issue levels
    if (!card->ParityValid) return false; // Cannot intentionally guess which parity caller wants to invalidate
    if (card->OEM != 0u) return false; // Card does not support OEM values

    packed->Length = 36; // Set number of bits
    set_linear_field(packed, card->FacilityCode, 1, 8);
    set_linear_field(packed, card->CardNumber, 11, 24);
    set_bit_by_position(packed, oddparity32 (get_nonlinear_field(packed, S12906b_BITS_USED_BY_PARITY, S12906b_odd_parity_bit_0)),    0);
    set_bit_by_position(packed, evenparity32(get_nonlinear_field(packed, S12906b_BITS_USED_BY_PARITY, S12906b_even_parity_bit_9)),   9);
    set_bit_by_position(packed, evenparity32(get_nonlinear_field(packed, S12906b_BITS_USED_BY_PARITY, S12906b_even_parity_bit_10)), 10);
    if (preamble) {
        return add_HID_header(packed);
    }
    return true;
}

static bool Unpack_S12906b(wiegand_message_t *packed, wiegand_card_t *card) {
    if (packed->Length != 36) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 8);
    card->CardNumber = get_linear_field(packed, 11, 24);
    // if (card->FacilityCode != 217) return false; // Must be 0b11011001 aka 217 for Grinnell?
    bool odd_1 = get_bit_by_position(packed,  0) == oddparity32( get_nonlinear_field(packed, S12906b_BITS_USED_BY_PARITY, S12906b_odd_parity_bit_0));
    bool even1 = get_bit_by_position(packed,  9) == evenparity32(get_nonlinear_field(packed, S12906b_BITS_USED_BY_PARITY, S12906b_even_parity_bit_9));
    bool even2 = get_bit_by_position(packed, 10) == evenparity32(get_nonlinear_field(packed, S12906b_BITS_USED_BY_PARITY, S12906b_even_parity_bit_10));
    card->ParityValid = odd_1 && even1 && even2;
    return true;
}

static bool Pack_Sie36(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 36; // Set number of bits
    set_linear_field(packed, card->FacilityCode, 1, 18);
    set_linear_field(packed, card->CardNumber, 19, 16);
    set_bit_by_position(packed,
    oddparity32(get_nonlinear_field(packed, 23, (uint8_t[]) {1, 3, 4, 6, 7, 9, 10, 12, 13, 15, 16, 18, 19, 21, 22, 24, 25, 27, 28, 30, 31, 33, 34}))
    , 0);
    set_bit_by_position(packed,
    evenparity32(get_nonlinear_field(packed, 23, (uint8_t[]) {1, 2, 4, 5, 7, 8, 10, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25, 26, 28, 29, 31, 32, 34}))
    , 35);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_Sie36(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 36) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 18);
    card->CardNumber = get_linear_field(packed, 19, 16);
    card->ParityValid =
    (get_bit_by_position(packed, 0) == oddparity32(get_nonlinear_field(packed, 23, (uint8_t[]) {1, 3, 4, 6, 7, 9, 10, 12, 13, 15, 16, 18, 19, 21, 22, 24, 25, 27, 28, 30, 31, 33, 34}))) &&
    (get_bit_by_position(packed, 35) == evenparity32(get_nonlinear_field(packed, 23, (uint8_t[]) {1, 2, 4, 5, 7, 8, 10, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25, 26, 28, 29, 31, 32, 34})));
    return true;
}

static bool Pack_C15001(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    if (card->OEM == 0)
        card->OEM = 900;

    packed->Length = 36; // Set number of bits
    set_linear_field(packed, card->OEM, 1, 10);
    set_linear_field(packed, card->FacilityCode, 11, 8);
    set_linear_field(packed, card->CardNumber, 19, 16);
    set_bit_by_position(packed, evenparity32(get_linear_field(packed, 1, 17)), 0);
    set_bit_by_position(packed, oddparity32(get_linear_field(packed, 18, 17)), 35);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_C15001(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 36) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->OEM = get_linear_field(packed, 1, 10);
    card->FacilityCode = get_linear_field(packed, 11, 8);
    card->CardNumber = get_linear_field(packed, 19, 16);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 17))) &&
        (get_bit_by_position(packed, 35) == oddparity32(get_linear_field(packed, 18, 17)));
    return true;
}

static bool Pack_H10302(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 37; // Set number of bits
    set_linear_field(packed, card->CardNumber, 1, 35);
    set_bit_by_position(packed, evenparity32(get_linear_field(packed, 1, 18)), 0);
    set_bit_by_position(packed, oddparity32(get_linear_field(packed, 18, 18)), 36);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_H10302(wiegand_message_t *packed, wiegand_card_t *card) {
    if (packed->Length != 37) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->CardNumber = get_linear_field(packed, 1, 35);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 18))) &&
        (get_bit_by_position(packed, 36) == oddparity32(get_linear_field(packed, 18, 18)));
    return true;
}

static bool Pack_P10004(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 37; // Set number of bits

    set_linear_field(packed, card->FacilityCode, 1, 13);
    set_linear_field(packed, card->CardNumber, 14, 18);
    // unknown parity scheme
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_P10004(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 37) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 13);
    card->CardNumber = get_linear_field(packed, 14, 18);
    // unknown parity scheme
    return true;
}

static bool Pack_H10304(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 37; // Set number of bits

    set_linear_field(packed, card->FacilityCode, 1, 16);
    set_linear_field(packed, card->CardNumber, 17, 19);

    set_bit_by_position(packed, evenparity32(get_linear_field(packed, 1, 18)), 0);
    set_bit_by_position(packed, oddparity32(get_linear_field(packed, 18, 18)), 36);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_H10304(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 37) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 16);
    card->CardNumber = get_linear_field(packed, 17, 19);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 18))) &&
        (get_bit_by_position(packed, 36) == oddparity32(get_linear_field(packed, 18, 18)));
    return true;
}

static bool Pack_HGeneric37(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 37; // Set number of bits

    set_linear_field(packed, card->CardNumber, 4, 32);

    set_bit_by_position(packed, 1, 36); // Always 1

    // even1
    set_bit_by_position(packed,
                        evenparity32(
    get_nonlinear_field(packed, 8, (uint8_t[]) {4, 8, 12, 16, 20, 24, 28, 32}))
    , 0
                       );
    // odd1
    set_bit_by_position(packed,
                        oddparity32(
    get_nonlinear_field(packed, 8, (uint8_t[]) {6, 10, 14, 18, 22, 26, 30, 34}))
    , 2
                       );
    // even2
    set_bit_by_position(packed,
                        evenparity32(
    get_nonlinear_field(packed, 8, (uint8_t[]) {7, 11, 15, 19, 23, 27, 31, 35}))
    , 3
                       );
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_HGeneric37(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 37) return false; // Wrong length? Stop here.
    if (get_bit_by_position(packed, 36) != 1) return false; // Always 1 in this format

    memset(card, 0, sizeof(wiegand_card_t));

    card->CardNumber = get_linear_field(packed, 4, 32);
    card->ParityValid =
    (get_bit_by_position(packed, 0) == evenparity32(get_nonlinear_field(packed, 8, (uint8_t[]) {4, 8, 12, 16, 20, 24, 28, 32}))) &&
    (get_bit_by_position(packed, 2) ==  oddparity32(get_nonlinear_field(packed, 8, (uint8_t[]) {6, 10, 14, 18, 22, 28, 30, 34}))) &&
    (get_bit_by_position(packed, 3) == evenparity32(get_nonlinear_field(packed, 8, (uint8_t[]) {7, 11, 15, 19, 23, 27, 31, 35})))
    ;
    return true;
}

static bool Pack_H800002(int format_idx, wiegand_card_t *card,
                         wiegand_message_t *packed, bool preamble) {
    int even_parity = 0;
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) {
        return false;
    }

    packed->Length = 46;
    set_linear_field(packed, card->FacilityCode, 1, 14);
    set_linear_field(packed, card->CardNumber, 15, 30);

    // Parity over 44 bits
    even_parity = evenparity32((packed->Bot >> 1) ^ (packed->Mid & 0x1fff));
    set_bit_by_position(packed, even_parity, 0);
    // Invert parity for setting odd parity
    set_bit_by_position(packed, even_parity ^ 1, 45);
    if (preamble) {
        return add_HID_header(packed);
    }
    return true;
}

static bool Unpack_H800002(wiegand_message_t *packed, wiegand_card_t *card) {
    if (packed->Length != 46) {
        return false; // Wrong length? Stop here.
    }

    int even_parity = 0;
    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 14);
    card->CardNumber = get_linear_field(packed, 15, 30);
    even_parity = evenparity32((packed->Bot >> 1) ^ (packed->Mid & 0x1fff));
    card->ParityValid = get_bit_by_position(packed, 0) == even_parity;
    // Invert logic to compare against oddparity
    card->ParityValid &= get_bit_by_position(packed, 45) != even_parity;
    return true;
}

static bool Pack_MDI37(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 37; // Set number of bits

    set_linear_field(packed, card->FacilityCode, 3, 4);
    set_linear_field(packed, card->CardNumber, 7, 29);

    set_bit_by_position(packed, evenparity32(get_linear_field(packed, 1, 18)), 0);
    set_bit_by_position(packed, oddparity32(get_linear_field(packed, 18, 18)), 36);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_MDI37(wiegand_message_t *packed, wiegand_card_t *card) {
    if (packed->Length != 37) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 3, 4);;
    card->CardNumber = get_linear_field(packed, 7, 29);

    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 18))) &&
        (get_bit_by_position(packed, 36) == oddparity32(get_linear_field(packed, 18, 18)))
        ;
    return true;
}

static bool Pack_P10001(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 40; // Set number of bits
    set_linear_field(packed, 0xF, 0, 4);
    set_linear_field(packed, card->FacilityCode, 4, 12);
    set_linear_field(packed, card->CardNumber, 16, 16);
    set_linear_field(packed,
                     get_linear_field(packed, 0, 8) ^
                     get_linear_field(packed, 8, 8) ^
                     get_linear_field(packed, 16, 8) ^
                     get_linear_field(packed, 24, 8)
                     , 32, 8);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_P10001(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 40) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->CardNumber = get_linear_field(packed, 16, 16);
    card->FacilityCode = get_linear_field(packed, 4, 12);
    card->ParityValid = (
                            get_linear_field(packed, 0, 8) ^
                            get_linear_field(packed, 8, 8) ^
                            get_linear_field(packed, 16, 8) ^
                            get_linear_field(packed, 24, 8)
                        ) == get_linear_field(packed, 32, 8);
    return true;
}

static bool Pack_C1k48s(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 48; // Set number of bits
    packed->Bot |= (card->CardNumber & 0x007FFFFF) << 1;
    packed->Bot |= (card->FacilityCode & 0x000000FF) << 24;
    packed->Mid |= (card->FacilityCode & 0x003FFF00) >> 8;
    packed->Mid |= (evenparity32((packed->Mid & 0x00001B6D) ^ (packed->Bot & 0xB6DB6DB6))) << 14;
    packed->Bot |= (oddparity32((packed->Mid & 0x000036DB) ^ (packed->Bot & 0x6DB6DB6C)));
    packed->Mid |= (oddparity32((packed->Mid & 0x00007FFF) ^ (packed->Bot & 0xFFFFFFFF))) << 15;

    if (preamble)
        return add_HID_header(packed);

    return true;
}

static bool Unpack_C1k48s(wiegand_message_t *packed, wiegand_card_t *card) {
    if (packed->Length != 48) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->CardNumber = (packed->Bot >> 1) & 0x007FFFFF;
    card->FacilityCode = ((packed->Mid & 0x00003FFF) << 8) | ((packed->Bot >> 24));
    card->ParityValid =
        (evenparity32((packed->Mid & 0x00001B6D) ^ (packed->Bot & 0xB6DB6DB6)) == ((packed->Mid >> 14) & 1)) &&
        (oddparity32((packed->Mid & 0x000036DB) ^ (packed->Bot & 0x6DB6DB6C)) == ((packed->Bot >> 0) & 1)) &&
        (oddparity32((packed->Mid & 0x00007FFF) ^ (packed->Bot & 0xFFFFFFFF)) == ((packed->Mid >> 15) & 1));
    return true;
}

static bool Pack_CasiRusco40(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 40; // Set number of bits
    set_linear_field(packed, card->CardNumber, 1, 38);

    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_CasiRusco40(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 40) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->CardNumber = get_linear_field(packed, 1, 38);
    return true;
}

static bool Pack_Optus(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    if (!validate_card_limit(format_idx, card)) return false;

    memset(packed, 0, sizeof(wiegand_message_t));

    packed->Length = 34; // Set number of bits
    set_linear_field(packed, card->CardNumber, 1, 16);
    set_linear_field(packed, card->FacilityCode, 22, 11);

    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_Optus(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 34) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->CardNumber = get_linear_field(packed, 1, 16);
    card->FacilityCode = get_linear_field(packed, 22, 11);
    return true;
}

static bool Pack_Smartpass(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 34; // Set number of bits

    set_linear_field(packed, card->FacilityCode, 1, 13);
    set_linear_field(packed, card->IssueLevel, 14, 3);
    set_linear_field(packed, card->CardNumber, 17, 16);
    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_Smartpass(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 34) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 13);
    card->IssueLevel = get_linear_field(packed, 14, 3);
    card->CardNumber = get_linear_field(packed, 17, 16);
    return true;
}

static bool Pack_bqt34(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 34; // Set number of bits

    set_linear_field(packed, card->FacilityCode, 1, 8);
    set_linear_field(packed, card->CardNumber, 9, 24);

    set_bit_by_position(packed,
                        evenparity32(get_linear_field(packed, 1, 16))
                        , 0);
    set_bit_by_position(packed,
                        oddparity32(get_linear_field(packed, 17, 16))
                        , 33);

    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_bqt34(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 34) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 8);
    card->CardNumber = get_linear_field(packed, 9, 24);

    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 16))) &&
        (get_bit_by_position(packed, 33) == oddparity32(get_linear_field(packed, 17, 16)));
    return true;
}

static bool Pack_bqt38(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 38; // Set number of bits

    set_linear_field(packed, card->FacilityCode, 24, 13);
    set_linear_field(packed, card->CardNumber, 1, 19);
    set_linear_field(packed, card->IssueLevel, 20, 4);

    set_bit_by_position(packed,
                        evenparity32(get_linear_field(packed, 1, 18))
                        , 0);
    set_bit_by_position(packed,
                        oddparity32(get_linear_field(packed, 19, 18))
                        , 37);

    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_bqt38(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 38) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 24, 13);
    card->CardNumber = get_linear_field(packed, 1, 19);
    card->IssueLevel = get_linear_field(packed, 20, 4);

    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 18))) &&
        (get_bit_by_position(packed, 37) == oddparity32(get_linear_field(packed, 19, 18)));
    return true;
}

static bool Pack_iscs38(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 38; // Set number of bits

    set_linear_field(packed, card->FacilityCode, 5, 10);
    set_linear_field(packed, card->CardNumber, 15, 22);
    set_linear_field(packed, card->OEM, 1, 4);

    set_bit_by_position(packed,
                        evenparity32(get_linear_field(packed, 1, 18))
                        , 0);
    set_bit_by_position(packed,
                        oddparity32(get_linear_field(packed, 19, 18))
                        , 37);

    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_iscs38(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 38) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 5, 10);
    card->CardNumber = get_linear_field(packed, 15, 22);
    card->OEM = get_linear_field(packed, 1, 4);

    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 18))) &&
        (get_bit_by_position(packed, 37) == oddparity32(get_linear_field(packed, 19, 18)));
    return true;
}

static bool Pack_pw39(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 39; // Set number of bits

    set_linear_field(packed, card->FacilityCode, 1, 17);
    set_linear_field(packed, card->CardNumber, 18, 20);

    set_bit_by_position(packed,
                        evenparity32(get_linear_field(packed, 1, 18))
                        , 0);
    set_bit_by_position(packed,
                        oddparity32(get_linear_field(packed, 19, 19))
                        , 38);

    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_pw39(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 39) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 17);
    card->CardNumber = get_linear_field(packed, 18, 20);

    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 18))) &&
        (get_bit_by_position(packed, 38) == oddparity32(get_linear_field(packed, 19, 19)));
    return true;
}

static bool Pack_bc40(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Length = 40; // Set number of bits

    set_linear_field(packed, card->OEM, 0, 7);

    // cost center 12
    set_linear_field(packed, card->FacilityCode, 7, 12);
    set_linear_field(packed, card->CardNumber, 19, 19);

    set_bit_by_position(packed,
                        oddparity32(get_linear_field(packed, 19, 19))
                        , 39);

    if (preamble)
        return add_HID_header(packed);
    return true;
}

static bool Unpack_bc40(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 40) return false; // Wrong length? Stop here.

    memset(card, 0, sizeof(wiegand_card_t));


    card->OEM = get_linear_field(packed, 0, 7);
    card->FacilityCode = get_linear_field(packed, 7, 12);
    card->CardNumber = get_linear_field(packed, 19, 19);

    card->ParityValid =
        (get_bit_by_position(packed, 39) == oddparity32(get_linear_field(packed, 19, 19)));
    return true;
}

static bool Pack_Avig56(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));
    packed->Length = 56;

    if (!validate_card_limit(format_idx, card)) return false;

    set_linear_field(packed, card->FacilityCode, 1, 20);
    set_linear_field(packed, card->CardNumber, 21, 34);

    bool even_parity_valid = step_parity_check(packed, 0, 28, true);
    set_bit_by_position(packed, !even_parity_valid, 0);

    bool odd_parity_valid = step_parity_check(packed, 28, 28, false);
    set_bit_by_position(packed, !odd_parity_valid, 55);

    if (preamble)
        return add_HID_header(packed);

    return true;
}

static bool Unpack_Avig56(wiegand_message_t *packed, wiegand_card_t *card) {

    if (packed->Length != 56) return false;

    memset(card, 0, sizeof(wiegand_card_t));

    card->FacilityCode = get_linear_field(packed, 1, 20);
    card->CardNumber = get_linear_field(packed, 21, 34);

    // Check step parity for every 2 bits
    bool even_parity_valid = step_parity_check(packed, 0, 28, true);
    bool odd_parity_valid = step_parity_check(packed, 28, 28, false);

    card->ParityValid = even_parity_valid && odd_parity_valid;
    return true;
}

static bool Pack_IR56(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));
    packed->Length = 56;

    if (!validate_card_limit(format_idx, card)) return false;

    packed->Bot = card->CardNumber;
    packed->Mid = card->FacilityCode;

    if (preamble)
        return add_HID_header(packed);

    return true;
}

static bool Unpack_IR56(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 56) return false;

    card->FacilityCode = packed->Mid;
    card->CardNumber = packed->Bot;
    return true;
}
// ---------------------------------------------------------------------------------------------------

void print_desc_wiegand(cardformat_t *fmt, wiegand_message_t *packed) {

    // return if invalid card format
    if (fmt->Name == NULL) {
        return;
    }

    size_t s_len = 128;
    char *s = calloc(s_len, sizeof(uint8_t));
    snprintf(s, s_len * sizeof(uint8_t), _YELLOW_("%-10s")" %-32s",  fmt->Name, fmt->Description);

    if (packed->Top != 0) {
        PrintAndLogEx(SUCCESS, "%s -> " _GREEN_("%X%08X%08X"),
                      s,
                      (uint32_t)packed->Top,
                      (uint32_t)packed->Mid,
                      (uint32_t)packed->Bot
                     );
    } else {
        PrintAndLogEx(SUCCESS, "%s -> " _YELLOW_("%X%08X"),
                      s,
                      (uint32_t)packed->Mid,
                      (uint32_t)packed->Bot
                     );
    }
    free(s);
}

void print_wiegand_code(wiegand_message_t *packed) {
    const char *s = "Wiegand: ";
    if (packed->Top != 0) {
        PrintAndLogEx(SUCCESS, "%s" _GREEN_("%X%08X%08X"),
                      s,
                      (uint32_t)packed->Top,
                      (uint32_t)packed->Mid,
                      (uint32_t)packed->Bot
                     );
    } else {
        PrintAndLogEx(SUCCESS, "%s" _YELLOW_("%X%08X"),
                      s,
                      (uint32_t)packed->Mid,
                      (uint32_t)packed->Bot
                     );
    }
}

static void hid_print_card(wiegand_card_t *card, const cardformat_t format) {

    char s[110] = {0};
    if (format.Fields.hasFacilityCode)
        snprintf(s, sizeof(s), "FC: " _GREEN_("%u"), card->FacilityCode);

    if (format.Fields.hasCardNumber)
        snprintf(s + strlen(s), sizeof(s) - strlen(s), "  CN: " _GREEN_("%"PRIu64), card->CardNumber);

    if (format.Fields.hasIssueLevel)
        snprintf(s + strlen(s), sizeof(s) - strlen(s), "  Issue: " _GREEN_("%u"), card->IssueLevel);

    if (format.Fields.hasOEMCode)
        snprintf(s + strlen(s), sizeof(s) - strlen(s), "  OEM: " _GREEN_("%u"), card->OEM);

    if (format.Fields.hasParity)
        snprintf(s + strlen(s), sizeof(s) - strlen(s), "  parity ( %s )", card->ParityValid ? _GREEN_("ok") : _RED_("fail"));

    PrintAndLogEx(SUCCESS, "[%-8s] %-32s %s", format.Name, format.Description, s);
}

static const cardformat_t FormatTable[] = {                                              // bits  CN FC IL OEM Parity  MaxFC (32u), MaxCN (64u),         MaxIL (32u)  MaxOEM (32u)
    {"H10301",    Pack_H10301,      Unpack_H10301,      "HID H10301 26-bit",                 26,  {1, 1, 0,  0,     1, 0x000000FFu, 0x000000000000FFFFu, 0x00000000u, 0x00000000u}}, // imported from old pack/unpack
    {"ind26",     Pack_ind26,       Unpack_ind26,       "Indala 26-bit",                     26,  {1, 1, 0,  0,     1, 0x00000FFFu, 0x0000000000000FFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"ind27",     Pack_ind27,       Unpack_ind27,       "Indala 27-bit",                     27,  {1, 1, 0,  0,     0, 0x00001FFFu, 0x0000000000003FFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"indasc27",  Pack_indasc27,    Unpack_indasc27,    "Indala ASC 27-bit",                 27,  {1, 1, 0,  0,     0, 0x00001FFFu, 0x0000000000003FFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"Tecom27",   Pack_Tecom27,     Unpack_Tecom27,     "Tecom 27-bit",                      27,  {1, 1, 0,  0,     0, 0x000007FFu, 0x000000000000FFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"2804W",     Pack_2804W,       Unpack_2804W,       "2804 Wiegand 28-bit",               28,  {1, 1, 0,  0,     1, 0x000000FFu, 0x0000000000007FFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"ind29",     Pack_ind29,       Unpack_ind29,       "Indala 29-bit",                     29,  {1, 1, 0,  0,     0, 0x00001FFFu, 0x000000000000FFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"ATSW30",    Pack_ATSW30,      Unpack_ATSW30,      "ATS Wiegand 30-bit",                30,  {1, 1, 0,  0,     1, 0x00000FFFu, 0x000000000000FFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"ADT31",     Pack_ADT31,       Unpack_ADT31,       "HID ADT 31-bit",                    31,  {1, 1, 0,  0,     0, 0x0000000Fu, 0x00000000007FFFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"HCP32",     Pack_hcp32,       Unpack_hcp32,       "HID Check Point 32-bit",            32,  {1, 0, 0,  0,     0, 0x00000000u, 0x0000000000003FFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"HPP32",     Pack_hpp32,       Unpack_hpp32,       "HID Hewlett-Packard 32-bit",        32,  {1, 1, 0,  0,     0, 0x00000FFFu, 0x000000001FFFFFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"Kastle",    Pack_Kastle,      Unpack_Kastle,      "Kastle 32-bit",                     32,  {1, 1, 1,  0,     1, 0x000000FFu, 0x000000000000FFFFu, 0x0000001Fu, 0x00000000u}}, // from @xilni; PR #23 on RfidResearchGroup/proxmark3
    {"Kantech",   Pack_Kantech,     Unpack_Kantech,     "Indala/Kantech KFS 32-bit",         32,  {1, 1, 0,  0,     0, 0x000000FFu, 0x000000000000FFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"WIE32",     Pack_wie32,       Unpack_wie32,       "Wiegand 32-bit",                    32,  {1, 1, 0,  0,     0, 0x00000FFFu, 0x000000000000FFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"D10202",    Pack_D10202,      Unpack_D10202,      "HID D10202 33-bit",                 33,  {1, 1, 0,  0,     1, 0x0000007Fu, 0x0000000000FFFFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"H10306",    Pack_H10306,      Unpack_H10306,      "HID H10306 34-bit",                 34,  {1, 1, 0,  0,     1, 0x0000FFFFu, 0x000000000000FFFFu, 0x00000000u, 0x00000000u}}, // imported from old pack/unpack
    {"N10002",    Pack_N10002,      Unpack_N10002,      "Honeywell/Northern N10002 34-bit",  34,  {1, 1, 0,  0,     1, 0x0000FFFFu, 0x000000000000FFFFu, 0x00000000u, 0x00000000u}}, // from proxclone.com
    {"Optus34",   Pack_Optus,       Unpack_Optus,       "Indala Optus 34-bit",               34,  {1, 1, 0,  0,     0, 0x000003FFu, 0x000000000000FFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"SMP34",     Pack_Smartpass,   Unpack_Smartpass,   "Cardkey Smartpass 34-bit",          34,  {1, 1, 1,  0,     0, 0x000003FFu, 0x000000000000FFFFu, 0x00000007u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"BQT34",     Pack_bqt34,       Unpack_bqt34,       "BQT 34-bit",                        34,  {1, 1, 0,  0,     1, 0x000000FFu, 0x0000000000FFFFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"C1k35s",    Pack_C1k35s,      Unpack_C1k35s,      "HID Corporate 1000 35-bit std",     35,  {1, 1, 0,  0,     1, 0x00000FFFu, 0x00000000000FFFFFu, 0x00000000u, 0x00000000u}}, // imported from old pack/unpack
    {"C15001",    Pack_C15001,      Unpack_C15001,      "HID KeyScan 36-bit",                36,  {1, 1, 0,  1,     1, 0x000000FFu, 0x000000000000FFFFu, 0x00000000u, 0x000003FFu}}, // from Proxmark forums
    {"S12906",    Pack_S12906,      Unpack_S12906,      "HID Simplex 36-bit",                36,  {1, 1, 1,  0,     1, 0x000000FFu, 0x0000000000FFFFFFu, 0x00000003u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"S12906b",   Pack_S12906b,     Unpack_S12906b,     "HID Simplex Grinnell 36-bit",       36,  {1, 1, 0,  0,     1, 0x000000FFu, 0x0000000000FFFFFFu, 0x00000000u, 0x00000000u}}, // from digitalfx screenshots on discord
    {"Sie36",     Pack_Sie36,       Unpack_Sie36,       "HID 36-bit Siemens",                36,  {1, 1, 0,  0,     1, 0x0003FFFFu, 0x000000000000FFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"H10320",    Pack_H10320,      Unpack_H10320,      "HID H10320 37-bit BCD",             37,  {1, 0, 0,  0,     1, 0x00000000u,           99999999u, 0x00000000u, 0x00000000u}}, // from Proxmark forums
    {"H10302",    Pack_H10302,      Unpack_H10302,      "HID H10302 37-bit huge ID",         37,  {1, 0, 0,  0,     1, 0x00000000u, 0x00000007FFFFFFFFu, 0x00000000u, 0x00000000u}}, // from Proxmark forums
    {"H10304",    Pack_H10304,      Unpack_H10304,      "HID H10304 37-bit",                 37,  {1, 1, 0,  0,     1, 0x0000FFFFu, 0x000000000007FFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"P10004",    Pack_P10004,      Unpack_P10004,      "HID P10004 37-bit PCSC",            37,  {1, 1, 0,  0,     0, 0x00001FFFu, 0x000000000003FFFFu, 0x00000000u, 0x00000000u}}, // from @bthedorff; PR #1559
    {"HGen37",    Pack_HGeneric37,  Unpack_HGeneric37,  "HID Generic 37-bit",                37,  {1, 0, 0,  0,     1, 0x00000000u, 0x000000000007FFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"MDI37",     Pack_MDI37,       Unpack_MDI37,       "PointGuard MDI 37-bit",             37,  {1, 1, 0,  0,     1, 0x0000000Fu, 0x000000001FFFFFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"BQT38",     Pack_bqt38,       Unpack_bqt38,       "BQT 38-bit",                        38,  {1, 1, 1,  0,     1, 0x00000FFFu, 0x000000000003FFFFu, 0x00000007u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"ISCS",      Pack_iscs38,      Unpack_iscs38,      "ISCS 38-bit",                       38,  {1, 1, 0,  1,     1, 0x000003FFu, 0x0000000000FFFFFFu, 0x00000000u, 0x00000007u}}, // from cardinfo.barkweb.com.au
    {"PW39",      Pack_pw39,        Unpack_pw39,        "Pyramid 39-bit wiegand format",     39,  {1, 1, 0,  0,     1, 0x0000FFFFu, 0x00000000000FFFFFu, 0x00000000u, 0x00000000u}},  // from cardinfo.barkweb.com.au
    {"P10001",    Pack_P10001,      Unpack_P10001,      "HID P10001 Honeywell 40-bit",       40,  {1, 1, 0,  0,     0, 0x00000FFFu, 0x000000000000FFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"Casi40",    Pack_CasiRusco40, Unpack_CasiRusco40, "Casi-Rusco 40-bit",                 40,  {1, 0, 0,  0,     0, 0x00000000u, 0x000000FFFFFFFFFFu, 0x00000000u, 0x00000000u}}, // from cardinfo.barkweb.com.au
    {"BC40",      Pack_bc40,        Unpack_bc40,        "Bundy TimeClock 40-bit",            40,  {1, 1, 0,  1,     1, 0x00000FFFu, 0x00000000000FFFFFu, 0x00000000u, 0x0000007Fu}}, // from
    {"Defcon32",  Pack_Defcon32,    Unpack_Defcon32,    "Custom Defcon RFCTF 42-bit",        42,  {1, 1, 1,  0,     1, 0x0000FFFFu, 0x00000000000FFFFFu, 0x0000000Fu, 0x00000000u}}, // Created by (@micsen) for the CTF
    {"H800002",   Pack_H800002,     Unpack_H800002,     "HID H800002 46-bit",                46,  {1, 1, 0,  0,     1, 0x00003FFFu, 0x000000003FFFFFFFu, 0x00000000u, 0x00000000u}},
    {"C1k48s",    Pack_C1k48s,      Unpack_C1k48s,      "HID Corporate 1000 48-bit std",     48,  {1, 1, 0,  0,     1, 0x003FFFFFu, 0x00000000007FFFFFu, 0x00000000u, 0x00000000u}}, // imported from old pack/unpack
    {"Avig56",    Pack_Avig56,      Unpack_Avig56,      "Avigilon 56-bit",                   56,  {1, 1, 0,  0,     1, 0x000FFFFFu, 0x00000003FFFFFFFFu, 0x00000000u, 0x00000000u}},
    {"IR56",      Pack_IR56,        Unpack_IR56,        "Inner Range 56-bit",                56,  {1, 1, 0,  0,     0, 0x00FFFFFFu, 0x00000000FFFFFFFFu, 0x00000000u, 0x00000000u}},
    {NULL, NULL, NULL, NULL, 0, {0, 0, 0, 0, 0, 0, 0, 0, 0}} // Must null terminate array 
}; 

void HIDListFormats(void) {
    if (FormatTable[0].Name == NULL)
        return;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "%-10s %s", "Name", "Description");
    PrintAndLogEx(INFO, "------------------------------------------------------------");

    int i = 0;
    while (FormatTable[i].Name) {
        PrintAndLogEx(INFO, _YELLOW_("%-10s")" %-30s", FormatTable[i].Name, FormatTable[i].Description);
        ++i;
    }
    PrintAndLogEx(INFO, "------------------------------------------------------------");
    PrintAndLogEx(INFO, "Available card formats: " _YELLOW_("%" PRIu64), ARRAYLEN(FormatTable) - 1);
    PrintAndLogEx(NORMAL, "");
    return;
}

cardformat_t HIDGetCardFormat(int idx) {

    // if idx is out-of-bounds, return the last item
    if ((idx < 0) || (idx > ARRAYLEN(FormatTable) - 2)) {
        return FormatTable[ARRAYLEN(FormatTable) - 1];
    }
    return FormatTable[idx];
}

int HIDFindCardFormat(const char *format) {

    char *s = str_dup(format);
    str_lower(s);

    int i = 0;
    while (FormatTable[i].Name) {

        char *a = str_dup(FormatTable[i].Name);
        str_lower(a);

        if (strcmp(a, s) == 0) {
            free(a);
            free(s);
            return i;
        }

        free(a);
        ++i;
    }

    free(s);
    return -1;
}

// validate if the card's FC, CN, IL, OEM are within the limit of its format
// return true if the card is valid
bool validate_card_limit(int format_idx, wiegand_card_t *card) {
    cardformatdescriptor_t card_descriptor = FormatTable[format_idx].Fields;

    // If a field is not supported, it's implicitly required to be zero
    if ((!card_descriptor.hasCardNumber  ) && (card->CardNumber   != 0u)) {
        return false; // Format does not support card number, but non-zero card number provided
    }
    if ((!card_descriptor.hasFacilityCode) && (card->FacilityCode != 0u)) {
        return false; // Format does not support facility code, but non-zero facility code provided
    }
    if ((!card_descriptor.hasIssueLevel  ) && (card->IssueLevel   != 0u)) {
        return false; // Format does not support issue levels, but non-zero issue level provided
    }
    if ((!card_descriptor.hasOEMCode     ) && (card->OEM          != 0u)) {
        return false; // Format does not support OEM codes, but non-zero OEM code provided
    }
    return !((card->FacilityCode > card_descriptor.MaxFC) ||
             (card->CardNumber > card_descriptor.MaxCN) ||
             (card->IssueLevel > card_descriptor.MaxIL) ||
             (card->OEM > card_descriptor.MaxOEM));
}

bool HIDPack(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if ((format_idx < 0) || (format_idx > ARRAYLEN(FormatTable) - 2))
        return false;

    return FormatTable[format_idx].Pack(format_idx, card, packed, preamble);
}

void HIDPackTryAll(wiegand_card_t *card, bool preamble) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "%-10s %-30s -> wiegand", "Name", "Description");
    PrintAndLogEx(INFO, "----------------------------------------------------------------------");

    wiegand_message_t packed;
    int i = 0;
    while (FormatTable[i].Name) {
        memset(&packed, 0, sizeof(wiegand_message_t));
        bool res = FormatTable[i].Pack(i, card, &packed, preamble);
        if (res) {
            cardformat_t fmt = HIDGetCardFormat(i);
            print_desc_wiegand(&fmt, &packed);
        }
        i++;
    }
    PrintAndLogEx(NORMAL, "");
}

bool HIDTryUnpack(wiegand_message_t *packed) {
    if (FormatTable[0].Name == NULL) {
        return false;
    }

    wiegand_card_t card;
    memset(&card, 0, sizeof(wiegand_card_t));
    uint8_t found_cnt = 0, found_invalid_par = 0;

    int i = 0;
    while (FormatTable[i].Name) {
        if (FormatTable[i].Unpack(packed, &card)) {

            found_cnt++;
            hid_print_card(&card, FormatTable[i]);
            // if fields has parity AND card parity is false
            if (FormatTable[i].Fields.hasParity && (card.ParityValid == false)) {
                found_invalid_par++;
            }
        }
        ++i;
    }

    if (found_cnt) {
        PrintAndLogEx(INFO, "found " _YELLOW_("%u") " matching " _YELLOW_("%d-bit") " format%s"
                      , found_cnt
                      , packed->Length
                      , (found_cnt > 1) ? "s" : ""
                     );
    }

    if (packed->Length && ((found_cnt - found_invalid_par) == 0)) { // if length > 0 and no valid parity matches
        PrintAndLogEx(FAILED, "Parity tests failed");
    }
    PrintAndLogEx(NORMAL, "");

    return ((found_cnt - found_invalid_par) > 0);
}

void HIDUnpack(int idx, wiegand_message_t *packed) {
    wiegand_card_t card;
    memset(&card, 0, sizeof(wiegand_card_t));
    if (FormatTable[idx].Unpack(packed, &card)) {
        hid_print_card(&card, FormatTable[idx]);
    }
}

// decode wiegand format using HIDTryUnpack
// return true if at least one valid matching formats found
bool decode_wiegand(uint32_t top, uint32_t mid, uint32_t bot, int n) {

    bool res = false;
    if (top == 0 && mid == 0 && bot == 0) {
        return res;
    }

    if (n > 0) {
        wiegand_message_t packed = initialize_message_object(top, mid, bot, n);
        res = HIDTryUnpack(&packed);
    } else {
        wiegand_message_t packed = initialize_message_object(top, mid, bot, n); // 26-37 bits
        res = HIDTryUnpack(&packed);

        PrintAndLogEx(INFO, "Trying with a preamble bit...");
        packed.Length += 1;
        res |= HIDTryUnpack(&packed);
    }

    if (res == false) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID no values found"));
    }

    return res;
}

int HIDDumpPACSBits(const uint8_t *const data, const uint8_t length, bool verbose) {
    uint8_t n = length - 1;
    uint8_t pad = data[0];
    char *binstr = (char *)calloc((length * 8) + 1, sizeof(uint8_t));
    if (binstr == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    bytes_2_binstr(binstr, data + 1, n);

//    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------------------- " _CYAN_("Wiegand") " ---------------------------");
    PrintAndLogEx(SUCCESS, "PACS............. " _GREEN_("%s"), sprint_hex_inrow(data, length));
    PrintAndLogEx(DEBUG, "padded bin....... " _GREEN_("%s") " ( %zu )", binstr, strlen(binstr));

    binstr[strlen(binstr) - pad] = '\0';
    PrintAndLogEx(DEBUG, "bin.............. " _GREEN_("%s") " ( %zu )", binstr, strlen(binstr));

    size_t hexlen = 0;
    uint8_t hex[16] = {0};
    binstr_2_bytes(hex, &hexlen, binstr);
    PrintAndLogEx(SUCCESS, "hex.............. " _GREEN_("%s"), sprint_hex_inrow(hex, hexlen));

    uint32_t top = 0, mid = 0, bot = 0;
    if (binstring_to_u96(&top, &mid, &bot, binstr) != strlen(binstr)) {
        PrintAndLogEx(ERR, "Binary string contains none <0|1> chars");
        free(binstr);
        return PM3_EINVARG;
    }

    PrintAndLogEx(NORMAL, "");
    wiegand_message_t packed = initialize_message_object(top, mid, bot, strlen(binstr));
    HIDTryUnpack(&packed);

    if (strlen(binstr) >= 26 && verbose) {


        // SEOS
        // iCLASS Legacy SE
        // iCLASS Legacy SR

        // iCLASS Legacy
        PrintAndLogEx(INFO, "Clone to " _YELLOW_("iCLASS Legacy"));
        PrintAndLogEx(SUCCESS, "    hf iclass encode --ki 0 --bin %s", binstr);
        PrintAndLogEx(NORMAL, "");

        // HID Prox II
        PrintAndLogEx(INFO, "Downgrade to " _YELLOW_("HID Prox II"));
        PrintAndLogEx(SUCCESS, "    lf hid clone -w H10301 --bin %s", binstr);
        PrintAndLogEx(NORMAL, "");

        // MIFARE DESFire

        // MIFARE Classic
        char mfcbin[28] = {0};
        mfcbin[0] = '1';
        memcpy(mfcbin + 1, binstr, strlen(binstr));
        binstr_2_bytes(hex, &hexlen, mfcbin);

        PrintAndLogEx(INFO, "Downgrade to " _YELLOW_("MIFARE Classic") " (Pm3 simulation)");
        PrintAndLogEx(SUCCESS, "    hf mf eclr;");
        PrintAndLogEx(SUCCESS, "    hf mf esetblk --blk 0 -d 049DBA42A23E80884400C82000000000;");
        PrintAndLogEx(SUCCESS, "    hf mf esetblk --blk 1 -d 1B014D48000000000000000000000000;");
        PrintAndLogEx(SUCCESS, "    hf mf esetblk --blk 3 -d A0A1A2A3A4A5787788C189ECA97F8C2A;");
        PrintAndLogEx(SUCCESS, "    hf mf esetblk --blk 5 -d 020000000000000000000000%s;", sprint_hex_inrow(hex, hexlen));
        PrintAndLogEx(SUCCESS, "    hf mf esetblk --blk 7 -d 484944204953787788AA204752454154;");
        PrintAndLogEx(SUCCESS, "    hf mf sim --1k -i;");
        PrintAndLogEx(NORMAL, "");

        PrintAndLogEx(INFO, "Downgrade to " _YELLOW_("MIFARE Classic 1K"));
        PrintAndLogEx(SUCCESS, "    hf mf encodehid --bin %s", binstr);
        PrintAndLogEx(NORMAL, "");
    }
    free(binstr);
    return PM3_SUCCESS;
}
