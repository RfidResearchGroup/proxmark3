//-----------------------------------------------------------------------------
// Copyright (C) 2018 grauerfuchs
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// HID card format packing/unpacking routines
//-----------------------------------------------------------------------------
#include "wiegand_formats.h"
#include "commonutil.h"

bool Pack_H10301(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0xFF) return false; // Can't encode FC.
    if (card->CardNumber > 0xFFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 26; // Set number of bits
    packed->Bot |= (card->CardNumber & 0xFFFF) << 1;
    packed->Bot |= (card->FacilityCode & 0xFF) << 17;
    packed->Bot |= oddparity32((packed->Bot >> 1) & 0xFFF) & 1;
    packed->Bot |= (evenparity32((packed->Bot >> 13) & 0xFFF) & 1) << 25;
    return add_HID_header(packed);
}

bool Unpack_H10301(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));
    if (packed->Length != 26) return false; // Wrong length? Stop here.

    card->CardNumber = (packed->Bot >> 1) & 0xFFFF;
    card->FacilityCode = (packed->Bot >> 17) & 0xFF;
    card->ParityValid =
        (oddparity32((packed->Bot >> 1) & 0xFFF) == (packed->Bot & 1)) &&
        ((evenparity32((packed->Bot >> 13) & 0xFFF) & 1) == ((packed->Bot >> 25) & 1));
    return true;
}

bool Pack_Tecom27(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0x7FF) return false; // Can't encode FC.
    if (card->CardNumber > 0xFFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 27;
    set_nonlinear_field(packed, card->FacilityCode, 10, (uint8_t[]) {15, 19, 24, 23, 22, 18, 6, 10, 14, 3, 2});
    set_nonlinear_field(packed, card->CardNumber, 16, (uint8_t[]) {0, 1, 13, 12, 9, 26, 20, 16, 17, 21, 25, 7, 8, 11, 4, 5});
    return add_HID_header(packed);
}

bool Unpack_Tecom27(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 27) return false; // Wrong length? Stop here.

    card->CardNumber = get_nonlinear_field(packed, 16, (uint8_t[]) {0, 1, 13, 12, 9, 26, 20, 16, 17, 21, 25, 7, 8, 11, 4, 5});
    card->FacilityCode = get_nonlinear_field(packed, 10, (uint8_t[]) {15, 19, 24, 23, 22, 18, 6, 10, 14, 3, 2});
    return true;
}

bool Pack_2804W(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0x0FF) return false; // Can't encode FC.
    if (card->CardNumber > 0x7FFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

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
    return add_HID_header(packed);
}

bool Unpack_2804W(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 28) return false; // Wrong length? Stop here.

    card->FacilityCode = get_linear_field(packed, 4, 8);
    card->CardNumber = get_linear_field(packed, 12, 15);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 13))) &&
    (get_bit_by_position(packed, 2) == oddparity32(get_nonlinear_field(packed, 16, (uint8_t[]) {4, 5, 7, 8, 10, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25, 26}))) &&
    (get_bit_by_position(packed, 27) == oddparity32(get_linear_field(packed, 0, 27)));
    return true;
}

bool Pack_ATSW30(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0xFFF) return false; // Can't encode FC.
    if (card->CardNumber > 0xFFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 30;
    set_linear_field(packed, card->FacilityCode, 1, 12);
    set_linear_field(packed, card->CardNumber, 13, 16);
    set_bit_by_position(packed,
                        evenparity32(get_linear_field(packed, 1, 12))
                        , 0);
    set_bit_by_position(packed,
                        oddparity32(get_linear_field(packed, 13, 16))
                        , 29);
    return add_HID_header(packed);
}

bool Unpack_ATSW30(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 30) return false; // Wrong length? Stop here.

    card->FacilityCode = get_linear_field(packed, 1, 12);
    card->CardNumber = get_linear_field(packed, 13, 16);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 12))) &&
        (get_bit_by_position(packed, 29) == oddparity32(get_linear_field(packed, 13, 16)));
    return true;
}

bool Pack_ADT31(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0x0F) return false; // Can't encode FC.
    if (card->CardNumber > 0x7FFFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 31;
    set_linear_field(packed, card->FacilityCode, 1, 4);
    set_linear_field(packed, card->CardNumber, 5, 23);
    // Parity not known, but 4 bits are unused.
    return add_HID_header(packed);
}

bool Unpack_ADT31(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 31) return false; // Wrong length? Stop here.
    card->FacilityCode = get_linear_field(packed, 1, 4);
    card->CardNumber = get_linear_field(packed, 5, 23);
    return true;
}

bool Pack_Kastle(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0x00FF) return false; // Can't encode FC.
    if (card->CardNumber > 0x0000FFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0x001F) return false; // IL is only 5 bits.
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 32; // Set number of bits
    set_bit_by_position(packed, 1, 1); // Always 1
    set_linear_field(packed, card->IssueLevel, 2, 5);
    set_linear_field(packed, card->FacilityCode, 7, 8);
    set_linear_field(packed, card->CardNumber, 15, 16);
    set_bit_by_position(packed, evenparity32(get_linear_field(packed, 1, 16)), 0);
    set_bit_by_position(packed, oddparity32(get_linear_field(packed, 14, 17)), 31);
    return add_HID_header(packed);
}

bool Unpack_Kastle(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 32) return false; // Wrong length? Stop here.
    if (get_bit_by_position(packed, 1) != 1) return false; // Always 1 in this format

    card->IssueLevel = get_linear_field(packed, 2, 5);
    card->FacilityCode = get_linear_field(packed, 7, 8);
    card->CardNumber = get_linear_field(packed, 15, 16);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 16))) &&
        (get_bit_by_position(packed, 31) == oddparity32(get_linear_field(packed, 14, 17)));
    return true;
}

bool Pack_D10202(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0x007F) return false; // Can't encode FC.
    if (card->CardNumber > 0x00FFFFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 33; // Set number of bits
    set_linear_field(packed, card->FacilityCode, 1, 7);
    set_linear_field(packed, card->CardNumber, 8, 24);
    set_bit_by_position(packed, evenparity32(get_linear_field(packed, 1, 16)), 0);
    set_bit_by_position(packed, oddparity32(get_linear_field(packed, 16, 16)), 32);
    return add_HID_header(packed);
}

bool Unpack_D10202(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 33) return false; // Wrong length? Stop here.

    card->CardNumber = get_linear_field(packed, 8, 24);
    card->FacilityCode = get_linear_field(packed, 1, 7);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 16))) &&
        (get_bit_by_position(packed, 32) == oddparity32(get_linear_field(packed, 16, 16)));
    return true;
}

bool Pack_H10306(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0xFFFF) return false; // Can't encode FC.
    if (card->CardNumber > 0xFFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 34; // Set number of bits
    packed->Bot |= (card->CardNumber & 0xFFFF) << 1;
    packed->Bot |= (card->FacilityCode & 0x7FFF) << 17;
    packed->Mid |= (card->FacilityCode & 0x8000) >> 15;
    packed->Mid |= (evenparity32((packed->Mid & 0x00000001) ^ (packed->Bot & 0xFFFE0000)) & 1) << 1;
    packed->Bot |= (oddparity32(packed->Bot & 0x0001FFFE) & 1);
    return add_HID_header(packed);
}

bool Unpack_H10306(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 34) return false; // Wrong length? Stop here.

    card->CardNumber = (packed->Bot >> 1) & 0xFFFF;
    card->FacilityCode = ((packed->Mid & 1) << 15) | ((packed->Bot >> 17) & 0xFF);
    card->ParityValid =
        ((evenparity32((packed->Mid & 0x00000001) ^ (packed->Bot & 0xFFFE0000)) & 1) == ((packed->Mid >> 1) & 1)) &&
        ((oddparity32(packed->Bot & 0x0001FFFE) & 1) == ((packed->Bot & 1)));
    return true;
}

bool Pack_N10002(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0xFF) return false; // Can't encode FC.
    if (card->CardNumber > 0xFFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 34; // Set number of bits
    set_linear_field(packed, card->FacilityCode, 9, 8);
    set_linear_field(packed, card->CardNumber, 17, 16);
    return add_HID_header(packed);
}

bool Unpack_N10002(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 34) return false; // Wrong length? Stop here.

    card->CardNumber = get_linear_field(packed, 17, 16);
    card->FacilityCode = get_linear_field(packed, 9, 8);
    return true;
}

bool Pack_C1k35s(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0xFFF) return false; // Can't encode FC.
    if (card->CardNumber > 0xFFFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 35; // Set number of bits
    packed->Bot |= (card->CardNumber & 0x000FFFFF) << 1;
    packed->Bot |= (card->FacilityCode & 0x000007FF) << 21;
    packed->Mid |= (card->FacilityCode & 0x00000800) >> 11;
    packed->Mid |= (evenparity32((packed->Mid & 0x00000001) ^ (packed->Bot & 0xB6DB6DB6)) & 1) << 1;
    packed->Bot |= (oddparity32((packed->Mid & 0x00000003) ^ (packed->Bot & 0x6DB6DB6C)) & 1);
    packed->Mid |= (oddparity32((packed->Mid & 0x00000003) ^ (packed->Bot & 0xFFFFFFFF)) & 1) << 2;
    return add_HID_header(packed);
}

bool Unpack_C1k35s(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 35) return false; // Wrong length? Stop here.

    card->CardNumber = (packed->Bot >> 1) & 0x000FFFFF;
    card->FacilityCode = ((packed->Mid & 1) << 11) | ((packed->Bot >> 21));
    card->ParityValid =
        (evenparity32((packed->Mid & 0x00000001) ^ (packed->Bot & 0xB6DB6DB6)) == ((packed->Mid >> 1) & 1)) &&
        (oddparity32((packed->Mid & 0x00000003) ^ (packed->Bot & 0x6DB6DB6C)) == ((packed->Bot >> 0) & 1)) &&
        (oddparity32((packed->Mid & 0x00000003) ^ (packed->Bot & 0xFFFFFFFF)) == ((packed->Mid >> 2) & 1));
    return true;
}

bool Pack_H10320(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0) return false; // Can't encode FC. (none in this format)
    if (card->CardNumber > 99999999) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 36; // Set number of bits
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
    return add_HID_header(packed);
}

bool Unpack_H10320(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 36) return false; // Wrong length? Stop here.

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

bool Pack_S12906(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0xFF) return false; // Can't encode FC.
    if (card->IssueLevel > 0x03) return false; // Can't encode IL.
    if (card->CardNumber > 0x00FFFFFF) return false; // Can't encode CN.
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 36; // Set number of bits
    set_linear_field(packed, card->FacilityCode, 1, 8);
    set_linear_field(packed, card->IssueLevel, 9, 2);
    set_linear_field(packed, card->CardNumber, 11, 24);
    set_bit_by_position(packed, oddparity32(get_linear_field(packed, 1, 17)), 0);
    set_bit_by_position(packed, oddparity32(get_linear_field(packed, 17, 18)), 35);
    return add_HID_header(packed);
}

bool Unpack_S12906(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 36) return false; // Wrong length? Stop here.

    card->FacilityCode = get_linear_field(packed, 1, 8);
    card->IssueLevel = get_linear_field(packed, 9, 2);
    card->CardNumber = get_linear_field(packed, 11, 24);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == oddparity32(get_linear_field(packed, 1, 17))) &&
        (get_bit_by_position(packed, 35) == oddparity32(get_linear_field(packed, 17, 18)));
    return true;
}

bool Pack_Sie36(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0x0003FFFF) return false; // Can't encode FC.
    if (card->CardNumber > 0x0000FFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 36; // Set number of bits
    set_linear_field(packed, card->FacilityCode, 1, 18);
    set_linear_field(packed, card->CardNumber, 19, 16);
    set_bit_by_position(packed,
    oddparity32(get_nonlinear_field(packed, 23, (uint8_t[]) {1, 3, 4, 6, 7, 9, 10, 12, 13, 15, 16, 18, 19, 21, 22, 24, 25, 27, 28, 30, 31, 33, 34}))
    , 0);
    set_bit_by_position(packed,
    evenparity32(get_nonlinear_field(packed, 23, (uint8_t[]) {1, 2, 4, 5, 7, 8, 10, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25, 26, 28, 29, 31, 32, 34}))
    , 35);
    return add_HID_header(packed);
}

bool Unpack_Sie36(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 36) return false; // Wrong length? Stop here.

    card->FacilityCode = get_linear_field(packed, 1, 18);
    card->CardNumber = get_linear_field(packed, 19, 16);
    card->ParityValid =
    (get_bit_by_position(packed, 0) == oddparity32(get_nonlinear_field(packed, 23, (uint8_t[]) {1, 3, 4, 6, 7, 9, 10, 12, 13, 15, 16, 18, 19, 21, 22, 24, 25, 27, 28, 30, 31, 33, 34}))) &&
    (get_bit_by_position(packed, 35) == oddparity32(get_nonlinear_field(packed, 23, (uint8_t[]) {1, 2, 4, 5, 7, 8, 10, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25, 26, 28, 29, 31, 32, 34})));
    return true;
}

bool Pack_C15001(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0x000000FF) return false; // Can't encode FC.
    if (card->CardNumber > 0x0000FFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0x000003FF) return false; // Can't encode OEM.

    packed->Length = 36; // Set number of bits
    set_linear_field(packed, card->OEM, 1, 10);
    set_linear_field(packed, card->FacilityCode, 11, 8);
    set_linear_field(packed, card->CardNumber, 19, 16);
    set_bit_by_position(packed, evenparity32(get_linear_field(packed, 1, 17)), 0);
    set_bit_by_position(packed, oddparity32(get_linear_field(packed, 18, 17)), 35);
    return add_HID_header(packed);
}

bool Unpack_C15001(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 36) return false; // Wrong length? Stop here.

    card->OEM = get_linear_field(packed, 1, 10);
    card->FacilityCode = get_linear_field(packed, 11, 8);
    card->CardNumber = get_linear_field(packed, 19, 16);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 17))) &&
        (get_bit_by_position(packed, 35) == oddparity32(get_linear_field(packed, 18, 17)));
    return true;
}

bool Pack_H10302(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0) return false; // Can't encode FC. (none in this format)
    if (card->CardNumber > 0x00000007FFFFFFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 37; // Set number of bits
    set_linear_field(packed, card->CardNumber, 1, 35);
    set_bit_by_position(packed, evenparity32(get_linear_field(packed, 1, 18)), 0);
    set_bit_by_position(packed, oddparity32(get_linear_field(packed, 18, 18)), 36);
    return add_HID_header(packed);
}

bool Unpack_H10302(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 37) return false; // Wrong length? Stop here.

    card->CardNumber = get_linear_field(packed, 1, 35);
    card->ParityValid =
        (get_bit_by_position(packed, 0) == evenparity32(get_linear_field(packed, 1, 18))) &&
        (get_bit_by_position(packed, 36) == oddparity32(get_linear_field(packed, 18, 18)));
    return true;
}

bool Pack_H10304(wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0x0000FFFF) return false; // Can't encode FC.
    if (card->CardNumber > 0x0007FFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 37; // Set number of bits
    packed->Bot |= (card->CardNumber & 0x0007FFFF) << 1;
    packed->Bot |= (card->FacilityCode & 0x00000FFF) << 20;
    packed->Mid |= (card->FacilityCode & 0x0000F000) >> 12;
    packed->Mid |= (evenparity32((packed->Mid & 0x0000000F) ^ (packed->Bot & 0xFFFC0000)) & 1) << 4;
    packed->Bot |= (oddparity32(packed->Bot & 0x0007FFFE) & 1);
    return add_HID_header(packed);
}

bool Unpack_H10304(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 37) return false; // Wrong length? Stop here.

    card->CardNumber = (packed->Bot >> 1) & 0x0007FFFF;
    card->FacilityCode = ((packed->Mid & 0xF) << 12) | ((packed->Bot >> 20));
    card->ParityValid =
        (evenparity32((packed->Mid & 0x0000000F) ^ (packed->Bot & 0xFFFC0000)) == ((packed->Mid >> 4) & 1)) &&
        (oddparity32(packed->Bot & 0x0007FFFE) == (packed->Bot & 1));
    return true;
}

bool Pack_P10001(wiegand_card_t *card, wiegand_message_t *packed) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0xFFF) return false; // Can't encode FC.
    if (card->CardNumber > 0xFFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

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
    return add_HID_header(packed);
}

bool Unpack_P10001(wiegand_message_t *packed, wiegand_card_t *card) {

    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 40) return false; // Wrong length? Stop here.

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

bool Pack_C1k48s(wiegand_card_t *card, wiegand_message_t *packed) {

    memset(packed, 0, sizeof(wiegand_message_t));

    if (card->FacilityCode > 0x003FFFFF) return false; // Can't encode FC.
    if (card->CardNumber > 0x007FFFFF) return false; // Can't encode CN.
    if (card->IssueLevel > 0) return false; // Not used in this format
    if (card->OEM > 0) return false; // Not used in this format

    packed->Length = 48; // Set number of bits
    packed->Bot |= (card->CardNumber & 0x007FFFFF) << 1;
    packed->Bot |= (card->FacilityCode & 0x000000FF) << 24;
    packed->Mid |= (card->FacilityCode & 0x003FFF00) >> 8;
    packed->Mid |= (evenparity32((packed->Mid & 0x00001B6D) ^ (packed->Bot & 0xB6DB6DB6)) & 1) << 14;
    packed->Bot |= (oddparity32((packed->Mid & 0x000036DB) ^ (packed->Bot & 0x6DB6DB6C)) & 1);
    packed->Mid |= (oddparity32((packed->Mid & 0x00007FFF) ^ (packed->Bot & 0xFFFFFFFF)) & 1) << 15;
    return add_HID_header(packed);
}

bool Unpack_C1k48s(wiegand_message_t *packed, wiegand_card_t *card) {
    memset(card, 0, sizeof(wiegand_card_t));

    if (packed->Length != 48) return false; // Wrong length? Stop here.

    card->CardNumber = (packed->Bot >> 1) & 0x007FFFFF;
    card->FacilityCode = ((packed->Mid & 0x00003FFF) << 8) | ((packed->Bot >> 24));
    card->ParityValid =
        (evenparity32((packed->Mid & 0x00001B6D) ^ (packed->Bot & 0xB6DB6DB6)) == ((packed->Mid >> 14) & 1)) &&
        (oddparity32((packed->Mid & 0x000036DB) ^ (packed->Bot & 0x6DB6DB6C)) == ((packed->Bot >> 0) & 1)) &&
        (oddparity32((packed->Mid & 0x00007FFF) ^ (packed->Bot & 0xFFFFFFFF)) == ((packed->Mid >> 15) & 1));
    return true;
}

static const cardformat_t FormatTable[] = {
    {"H10301",  Pack_H10301,  Unpack_H10301,  "HID H10301 26-bit",          {1, 1, 0, 0, 1}}, // imported from old pack/unpack
    {"Tecom27", Pack_Tecom27, Unpack_Tecom27, "Tecom 27-bit",               {1, 1, 0, 0, 1}}, // from cardinfo.barkweb.com.au
    {"2804W",   Pack_2804W,   Unpack_2804W,   "2804 Wiegand",               {1, 1, 0, 0, 1}}, // from cardinfo.barkweb.com.au
    {"ATSW30",  Pack_ATSW30,  Unpack_ATSW30,  "ATS Wiegand 30-bit",         {1, 1, 0, 0, 1}}, // from cardinfo.barkweb.com.au
    {"ADT31",   Pack_ADT31,   Unpack_ADT31,   "HID ADT 31-bit",             {1, 1, 0, 0, 1}}, // from cardinfo.barkweb.com.au
    {"Kastle",  Pack_Kastle,  Unpack_Kastle,  "Kastle 32-bit",              {1, 1, 1, 0, 1}}, // from @xilni; PR #23 on RfidResearchGroup/proxmark3
    {"D10202",  Pack_D10202,  Unpack_D10202,  "HID D10202 33-bit",          {1, 1, 0, 0, 1}}, // from cardinfo.barkweb.com.au
    {"H10306",  Pack_H10306,  Unpack_H10306,  "HID H10306 34-bit",          {1, 1, 0, 0, 1}}, // imported from old pack/unpack
    {"N10002",  Pack_N10002,  Unpack_N10002,  "HID N10002 34-bit",          {1, 1, 0, 0, 1}}, // from cardinfo.barkweb.com.au
    {"C1k35s",  Pack_C1k35s,  Unpack_C1k35s,  "HID Corporate 1000 35-bit standard layout", {1, 1, 0, 0, 1}}, // imported from old pack/unpack
    {"C15001",  Pack_C15001,  Unpack_C15001,  "HID KeySpan 36-bit",         {1, 1, 0, 1, 1}}, // from Proxmark forums
    {"S12906",  Pack_S12906,  Unpack_S12906,  "HID Simplex 36-bit",         {1, 1, 1, 0, 1}}, // from cardinfo.barkweb.com.au
    {"Sie36",   Pack_Sie36,   Unpack_Sie36,   "HID 36-bit Siemens",         {1, 1, 0, 0, 1}}, // from cardinfo.barkweb.com.au
    {"H10320",  Pack_H10320,  Unpack_H10320,  "HID H10320 36-bit BCD",      {1, 0, 0, 0, 1}}, // from Proxmark forums
    {"H10302",  Pack_H10302,  Unpack_H10302,  "HID H10302 37-bit huge ID",  {1, 0, 0, 0, 1}}, // from Proxmark forums
    {"H10304",  Pack_H10304,  Unpack_H10304,  "HID H10304 37-bit",          {1, 1, 0, 0, 1}}, // imported from old pack/unpack
    {"P10001",  Pack_P10001,  Unpack_P10001,  "HID P10001 Honeywell 40-bit" }, // from cardinfo.barkweb.com.au
    {"C1k48s",  Pack_C1k48s,  Unpack_C1k48s,  "HID Corporate 1000 48-bit standard layout", {1, 1, 0, 0, 1}}, // imported from old pack/unpack
    {NULL, NULL, NULL, NULL, {0, 0, 0, 0, 0}} // Must null terminate array
};

void HIDListFormats() {
    if (FormatTable[0].Name == NULL)
        return;

    PrintAndLogEx(NORMAL, "%-10s %s", "Name", "Description");
    PrintAndLogEx(NORMAL, "------------------------------------------------------------");

    int i = 0;
    while (FormatTable[i].Name) {
        PrintAndLogEx(NORMAL, _YELLOW_("%-10s")" %-30s", FormatTable[i].Name, FormatTable[i].Descrp);
        ++i;
    }
    PrintAndLogEx(NORMAL, "");
    return;
}

cardformat_t HIDGetCardFormat(int idx) {
    return FormatTable[idx];
}

int HIDFindCardFormat(const char *format) {

    if (FormatTable[0].Name == NULL)
        return -1;

    int i = 0;

// str_lower

    while (FormatTable[i].Name && strcmp(FormatTable[i].Name, format)) {
        ++i;
    }

    if (FormatTable[i].Name)
        return i;

    return -1;
}

bool HIDPack(int format_idx, wiegand_card_t *card, wiegand_message_t *packed) {
    memset(packed, 0, sizeof(wiegand_message_t));

    if (format_idx < 0 || format_idx >= ARRAYLEN(FormatTable))
        return false;

    return FormatTable[format_idx].Pack(card, packed);
}

static void HIDDisplayUnpackedCard(wiegand_card_t *card, const cardformat_t format) {

    /*
        PrintAndLogEx(SUCCESS, "       Format: %s (%s)", format.Name, format.Descrp);

        if (format.Fields.hasFacilityCode)
            PrintAndLogEx(SUCCESS, "Facility Code: %d",card->FacilityCode);

        if (format.Fields.hasCardNumber)
            PrintAndLogEx(SUCCESS, "  Card Number: %d",card->CardNumber);

        if (format.Fields.hasIssueLevel)
            PrintAndLogEx(SUCCESS, "  Issue Level: %d",card->IssueLevel);

        if (format.Fields.hasOEMCode)
            PrintAndLogEx(SUCCESS, "     OEM Code: %d",card->OEM);

        if (format.Fields.hasParity)
            PrintAndLogEx(SUCCESS, "       Parity: %s",card->ParityValid ? "Valid" : "Invalid");
    */

    char s[80] = {0};
    if (format.Fields.hasFacilityCode)
        snprintf(s, sizeof(s), "FC: %u", card->FacilityCode);

    if (format.Fields.hasCardNumber)
        snprintf(s + strlen(s), sizeof(s) - strlen(s), "  CN: %" PRIu64, card->CardNumber);

    if (format.Fields.hasIssueLevel)
        snprintf(s + strlen(s), sizeof(s) - strlen(s), "  Issue %u", card->IssueLevel);

    if (format.Fields.hasOEMCode)
        snprintf(s + strlen(s), sizeof(s) - strlen(s), "  OEM: %u", card->OEM);

    if (format.Fields.hasParity)
        snprintf(s + strlen(s), sizeof(s) - strlen(s), "    parity: %s", card->ParityValid ? "valid" : "invalid");

    PrintAndLogEx(SUCCESS, "%s [%s - %s]", s, format.Name, format.Descrp);
}

bool HIDTryUnpack(wiegand_message_t *packed, bool ignore_parity) {
    if (FormatTable[0].Name == NULL)
        return false;

    bool result = false;
    int i = 0;
    wiegand_card_t card;
    memset(&card, 0, sizeof(wiegand_card_t));

    while (FormatTable[i].Name) {
        if (FormatTable[i].Unpack(packed, &card)) {
            if (ignore_parity || !FormatTable[i].Fields.hasParity || card.ParityValid) {
                result = true;
                HIDDisplayUnpackedCard(&card, FormatTable[i]);
            }
        }
        ++i;
    }
    if (result == false) {
        PrintAndLogEx(SUCCESS, "Unknown. Bit len %d", packed->Length);
    }

    return result;
}
