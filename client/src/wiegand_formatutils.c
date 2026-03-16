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
// Wiegand card format packing/unpacking support functions
//-----------------------------------------------------------------------------

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "commonutil.h"
#include "wiegand_formatutils.h"
#include "loclass/cipherutils.h"
#include "wiegand_formats.h"
#include "util.h"
#include "ui.h"

uint8_t get_bit_by_position(const wiegand_message_t *data, uint8_t pos) {
    if (pos >= data->Length) return false;
    pos = (data->Length - pos) - 1; // invert ordering; Indexing goes from 0 to 1. Subtract 1 for weight of bit.
    uint8_t result = 0;
    if (pos > 95)
        result = 0;
    else if (pos > 63)
        result = (data->Top >> (pos - 64)) & 1;
    else if (pos > 31)
        result = (data->Mid >> (pos - 32)) & 1;
    else
        result = (data->Bot >> pos) & 1;
    return result;
}
bool set_bit_by_position(wiegand_message_t *data, bool value, uint8_t pos) {
    if (pos >= data->Length) return false;
    pos = (data->Length - pos) - 1; // invert ordering; Indexing goes from 0 to 1. Subtract 1 for weight of bit.
    if (pos > 95) {
        return false;
    } else if (pos > 63) {
        if (value)
            data->Top |= (1UL << (pos - 64));
        else
            data->Top &= ~(1UL << (pos - 64));
        return true;
    } else if (pos > 31) {
        if (value)
            data->Mid |= (1UL << (pos - 32));
        else
            data->Mid &= ~(1UL << (pos - 32));
        return true;
    } else {
        if (value)
            data->Bot |= (1UL << pos);
        else
            data->Bot &= ~(1UL << pos);
        return true;
    }
}
/**
 * Safeguard the data by doing a manual deep copy
 *
 * At the time of the initial writing, the struct does not contain pointers. That doesn't
 * mean it won't eventually contain one, however. To prevent memory leaks and erroneous
 * aliasing, perform the copy function manually instead. Hence, this function.
 *
 * If the definition of the wiegand_message struct changes, this function must also
 * be updated to match.
 */
static void message_datacopy(const wiegand_message_t *src, wiegand_message_t *dest) {
    dest->Bot = src->Bot;
    dest->Mid = src->Mid;
    dest->Top = src->Top;
    dest->Length = src->Length;
}
/**
 *
 * Yes, this is horribly inefficient for linear data.
 * The current code is a temporary measure to have a working function in place
 * until all the bugs shaken from the block/chunk version of the code.
 *
 */
uint64_t get_linear_field(const wiegand_message_t *data, uint8_t firstBit, uint8_t length) {
    uint64_t result = 0;
    for (uint8_t i = 0; i < length; i++) {
        result = (result << 1) | get_bit_by_position(data, firstBit + i);
    }
    return result;
}
bool set_linear_field(wiegand_message_t *data, uint64_t value, uint8_t firstBit, uint8_t length) {
    wiegand_message_t tmpdata;
    message_datacopy(data, &tmpdata);
    bool result = true;
    for (int i = 0; i < length; i++) {
        result &= set_bit_by_position(&tmpdata, (value >> ((length - i) - 1)) & 1, firstBit + i);
    }
    if (result)
        message_datacopy(&tmpdata, data);

    return result;
}

uint64_t get_nonlinear_field(const wiegand_message_t *data, uint8_t numBits, const uint8_t *bits) {
    uint64_t result = 0;
    for (int i = 0; i < numBits; i++) {
        result = (result << 1) | get_bit_by_position(data, *(bits + i));
    }
    return result;
}
bool set_nonlinear_field(wiegand_message_t *data, uint64_t value, uint8_t numBits, const uint8_t *bits) {

    wiegand_message_t tmpdata;
    message_datacopy(data, &tmpdata);

    bool result = true;
    for (int i = 0; i < numBits; i++) {
        result &= set_bit_by_position(&tmpdata, (value >> ((numBits - i) - 1)) & 1, *(bits + i));
    }

    if (result)
        message_datacopy(&tmpdata, data);

    return result;
}

uint8_t get_length_from_header(const wiegand_message_t *data) {
    /**
     * detect if message has "preamble" / "sentinel bit"
     * Right now we just calculate the highest bit set
     *
     * (from http://www.proxmark.org/forum/viewtopic.php?pid=5368#p5368)
     * 0000 0010 0000 0000 01xx xxxx xxxx xxxx xxxx xxxx xxxx  26-bit
     * 0000 0010 0000 0000 1xxx xxxx xxxx xxxx xxxx xxxx xxxx  27-bit
     * 0000 0010 0000 0001 xxxx xxxx xxxx xxxx xxxx xxxx xxxx  28-bit
     * 0000 0010 0000 001x xxxx xxxx xxxx xxxx xxxx xxxx xxxx  29-bit
     * 0000 0010 0000 01xx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  30-bit
     * 0000 0010 0000 1xxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  31-bit
     * 0000 0010 0001 xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  32-bit
     * 0000 0010 001x xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  33-bit
     * 0000 0010 01xx xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  34-bit
     * 0000 0010 1xxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  35-bit
     * 0000 0011 xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  36-bit
     * 0000 000x xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  37-bit
     * 0000 00xx xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  38-bit
     */
    uint8_t len = 0;
    uint32_t hfmt = 0; // for calculating card length

    if ((data->Top & 0x000FFFFF) > 0) { // > 64 bits
        hfmt = data->Top & 0x000FFFFF;
        len = 64;
    } else if (data->Mid & 0xFFFFFFC0) { // handle 38bit and above format
        hfmt = data->Mid;
        len = 31; // remove leading 1 (preamble) in 38-64 bits format
    } else if (((data->Mid >> 5) & 1) == 1) { // bit 38 is set => 26-36bit format
        hfmt = (((data->Mid & 31) << 6) | (data->Bot >> 26)); // get bits 27-37 to check for format len bit
        len = 25;
    } else { // if bit 38 is not set => 37bit format
        hfmt = 0;
        len = 37;
    }

    while (hfmt > 0) {
        hfmt >>= 1;
        len++;
    }

    return len;
}

wiegand_message_t initialize_message_object(uint32_t top, uint32_t mid, uint32_t bot, int n) {
    wiegand_message_t result;
    memset(&result, 0, sizeof(wiegand_message_t));

    result.Top = top;
    result.Mid = mid;
    result.Bot = bot;
    if (n > 0)
        result.Length = n;
    else
        result.Length = get_length_from_header(&result);
    return result;
}

bool add_HID_header(wiegand_message_t *data) {
    // Invalid value
    if (data->Length > 84 || data->Length == 0) {
        return false;
    }

    if (data->Length == 48) {
        data->Mid |= 1U << (data->Length - 32); // Example leading 1: start bit
        return true;
    }

    if (data->Length >= 64) {
        data->Top |= 0x09e00000; // Extended-length header
        data->Top |= 1U << (data->Length - 64); // leading 1: start bit
    } else if (data->Length > 37) {
        data->Top |= 0x09e00000; // Extended-length header
        data->Mid |= 1U << (data->Length - 32); // leading 1: start bit
    } else if (data->Length == 37) {
        // No header bits added to 37-bit cards
    } else if (data->Length >= 32) {
        data->Mid |= 0x20; // Bit 37; standard header
        data->Mid |= 1U << (data->Length - 32); // leading 1: start bit
    } else {
        data->Mid |= 0x20; // Bit 37; standard header
        data->Bot |= 1U << data->Length; // leading 1: start bit
    }
    return true;
}

bool wiegand_message_to_binstr(const wiegand_message_t *packed, char *binstr, size_t binstr_size) {
    if (packed == NULL || binstr == NULL || binstr_size <= packed->Length) {
        return false;
    }

    for (uint8_t i = 0; i < packed->Length; i++) {
        binstr[i] = get_bit_by_position(packed, i) ? '1' : '0';
    }
    binstr[packed->Length] = '\0';
    return true;
}

bool wiegand_raw_to_binstr(const uint8_t *raw, size_t raw_len, char *binstr, size_t binstr_size) {
    if (raw == NULL || binstr == NULL || raw_len == 0 || binstr_size == 0) {
        return false;
    }

    size_t raw_bit_len = raw_len * 8;
    if (binstr_size <= raw_bit_len) {
        return false;
    }

    bytes_2_binstr(binstr, raw, raw_len);

    char *sentinel = strchr(binstr, '1');
    if (sentinel == NULL || sentinel[1] == '\0') {
        return false;
    }

    size_t payload_len = strlen(sentinel + 1);
    if (binstr_size <= payload_len) {
        return false;
    }

    memmove(binstr, sentinel + 1, payload_len + 1);
    return true;
}

bool wiegand_new_pacs_to_binstr(const uint8_t *pacs, size_t pacs_len, char *binstr, size_t binstr_size) {
    if (pacs == NULL || binstr == NULL || pacs_len < 2 || pacs[0] > 0x07) {
        return false;
    }

    size_t payload_len = pacs_len - 1;
    size_t padded_bits = payload_len * 8;
    if (binstr_size <= padded_bits) {
        return false;
    }

    bytes_2_binstr(binstr, pacs + 1, payload_len);

    size_t trimmed_len = strlen(binstr);
    if (pacs[0] > trimmed_len) {
        return false;
    }

    binstr[trimmed_len - pacs[0]] = '\0';
    return true;
}

int wiegand_pack_bin_with_hid_header(const char *binstr, wiegand_message_t *packed) {
    size_t bin_len = strlen(binstr);
    if (packed == NULL || bin_len == 0 || bin_len > 84) {
        return PM3_EINVARG;
    }

    uint8_t hex[12] = {0};
    BitstreamOut_t bout = {hex, 0, 0};

    for (size_t i = 0; i < (96 - bin_len - 1); i++) {
        pushBit(&bout, 0);
    }

    pushBit(&bout, 1);

    for (size_t i = 0; i < bin_len; i++) {
        char c = binstr[i];
        if (c == '1') {
            pushBit(&bout, 1);
        } else if (c == '0') {
            pushBit(&bout, 0);
        } else {
            return PM3_EINVARG;
        }
    }

    packed->Length = (uint8_t)bin_len;
    packed->Top = bytes_to_num(hex, 4);
    packed->Mid = bytes_to_num(hex + 4, 4);
    packed->Bot = bytes_to_num(hex + 8, 4);

    return add_HID_header(packed) ? PM3_SUCCESS : PM3_EINVARG;
}

int wiegand_set_plain_binstr(const char *binstr, wiegand_input_t *input) {
    size_t bin_len = strlen(binstr);
    if (input == NULL || bin_len == 0 || bin_len >= sizeof(input->binstr)) {
        return PM3_EINVARG;
    }

    memset(input, 0, sizeof(*input));
    for (size_t i = 0; i < bin_len; i++) {
        if (binstr[i] != '0' && binstr[i] != '1') {
            return PM3_EINVARG;
        }
    }

    memcpy(input->binstr, binstr, bin_len + 1);
    input->bin_len = bin_len;
    return PM3_SUCCESS;
}

int wiegand_set_new_pacs_binstr(const uint8_t *pacs, size_t pacs_len, wiegand_input_t *input) {
    if (input == NULL) {
        return PM3_EINVARG;
    }

    memset(input, 0, sizeof(*input));
    if (wiegand_new_pacs_to_binstr(pacs, pacs_len, input->binstr, sizeof(input->binstr)) == false) {
        return PM3_EINVARG;
    }

    input->bin_len = strlen(input->binstr);
    return PM3_SUCCESS;
}

int wiegand_pack_formatted(int format_idx, wiegand_card_t *card, bool preamble, wiegand_message_t *packed) {
    if (HIDPack(format_idx, card, packed, preamble) == false) {
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

int wiegand_pack_from_plain_bin(const char *binstr, wiegand_input_t *input) {
    int res = wiegand_set_plain_binstr(binstr, input);
    if (res != PM3_SUCCESS) {
        return res;
    }

    res = wiegand_pack_bin_with_hid_header(input->binstr, &input->packed);
    input->packed_valid = (res == PM3_SUCCESS);
    return res;
}

int wiegand_pack_from_new_pacs(const uint8_t *pacs, size_t pacs_len, wiegand_input_t *input) {
    int res = wiegand_set_new_pacs_binstr(pacs, pacs_len, input);
    if (res != PM3_SUCCESS) {
        return res;
    }

    res = wiegand_pack_bin_with_hid_header(input->binstr, &input->packed);
    input->packed_valid = (res == PM3_SUCCESS);
    return res;
}

int wiegand_pack_from_formatted(int format_idx, wiegand_card_t *card, bool preamble, wiegand_input_t *input) {
    memset(input, 0, sizeof(*input));
    int res = wiegand_pack_formatted(format_idx, card, preamble, &input->packed);
    if (res != PM3_SUCCESS) {
        return res;
    }
    input->packed_valid = true;
    if (wiegand_message_to_binstr(&input->packed, input->binstr, sizeof(input->binstr)) == false) {
        return PM3_EINVARG;
    }
    input->bin_len = strlen(input->binstr);
    return PM3_SUCCESS;
}

int wiegand_pack_from_raw_hid(const uint8_t *raw, size_t raw_len, wiegand_input_t *input) {
    uint32_t top = 0, mid = 0, bot = 0;
    memset(input, 0, sizeof(*input));

    char hexstr[40] = {0};
    if ((raw_len * 2) >= sizeof(hexstr)) {
        return PM3_EINVARG;
    }
    memcpy(hexstr, sprint_hex_inrow(raw, raw_len), raw_len * 2);

    if (hexstring_to_u96(&top, &mid, &bot, hexstr) != (int)(raw_len * 2)) {
        return PM3_EINVARG;
    }

    input->packed = initialize_message_object(top, mid, bot, 0);
    input->packed_valid = true;
    if (wiegand_raw_to_binstr(raw, raw_len, input->binstr, sizeof(input->binstr))) {
        input->bin_len = strlen(input->binstr);
    }
    return PM3_SUCCESS;
}
