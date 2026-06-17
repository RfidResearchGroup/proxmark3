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
// Parse Helsinki Region Transport (HRT) travel cards
//-----------------------------------------------------------------------------

// Parser built based on com.bonwal.omamatkakortti mobile application

#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200112L
#endif

#include "cmdparser.h"
#include "cmdparsehrt.h"
#include "comms.h"
#include "common.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

static const int64_t EN1545_ZERO_DATE_MS = 852076800000LL;
static const int64_t DAY_IN_MS           = 86400000LL;
static const int64_t MINUTE_IN_MS        = 60000LL;

// Helper Functions
static bytearray_t bytearray_alloc(size_t length) {
    bytearray_t arr;
    arr.data = calloc(length, 1);
    arr.length = length;
    return arr;
}

static void bytearray_free(bytearray_t *arr) {
    if (!arr) return;

    SAFE_FREE(arr->data);
    arr->length = 0;
}

int hrt_price_to_string(int cents, char *out, size_t out_len) {
    if (!out || out_len == 0) return 0;
    int euros = cents / 100;
    int rem = cents % 100;
    if (rem < 0) rem = -rem;

    return snprintf(out, out_len, "%d.%02d EUR", euros, rem);
}

char *convert_get_hex_string(const uint8_t *data, size_t length) {
    if (!data || length == 0) return NULL;

    size_t out_len = (length * 2) + 1;
    char *hex = malloc(out_len);
    if (!hex) return NULL;

    char *result_ptr = hex;

    for (size_t i = 0; i < length; ++i) {
        snprintf(result_ptr, 3, "%02x", data[i]);
        result_ptr += 2;
    }

    hex[out_len - 1] = '\0';
    return hex;
}

int convert_get_byte_value(
    const uint8_t *data,
    size_t data_len,
    int bit_offset,
    int bit_length
) {
    if (!data || bit_length <= 0) return 0;
    if (bit_length > 8) bit_length = 8;

    int byte_idx = bit_offset / 8;
    int bit_idx  = bit_offset % 8;

    if ((size_t)(byte_idx + 1) >= data_len) return 0;

    uint16_t value =
        ((uint16_t)data[byte_idx] << 8) |
        ((uint16_t)data[byte_idx + 1]);

    uint16_t mask = (uint16_t)((1U << bit_length) - 1U);

    int shift = (16 - bit_idx) - bit_length;

    return (int)((value >> shift) & mask);
}

int convert_get_short_value(
    const uint8_t *data,
    size_t data_len,
    int bit_offset,
    int bit_length
) {
    if (!data || bit_length <= 0) return 0;

    if (bit_length > 16) bit_length = 16;

    int byte_idx = bit_offset / 8;
    int bit_idx  = bit_offset % 8;

    if ((size_t)(byte_idx + 3) >= data_len) return 0;

    uint32_t value =
        ((uint32_t)data[byte_idx]     << 24) |
        ((uint32_t)data[byte_idx + 1] << 16) |
        ((uint32_t)data[byte_idx + 2] <<  8) |
        ((uint32_t)data[byte_idx + 3]);

    uint32_t mask = (1U << bit_length) - 1U;
    int shift = (32 - bit_idx) - bit_length;

    return (int)((value >> shift) & mask);
}

static time_t hrt_apply_local_offset(time_t time) {
    struct tm local_time = {0};
    struct tm utc_time = {0};

#if defined(_WIN32)
    if (localtime_s(&local_time, &time) != 0) return time;
    if (gmtime_s(&utc_time, &time) != 0) return time;
#else
    if (localtime_r(&time, &local_time) == NULL) return time;
    if (gmtime_r(&time, &utc_time) == NULL) return time;
#endif

    time_t local_as_time = mktime(&local_time);
    time_t utc_as_local = mktime(&utc_time);

    if (local_as_time == (time_t) - 1 || utc_as_local == (time_t) - 1) return time;

    time_t offset = local_as_time - utc_as_local;
    return time - offset;
}

time_t en5145_date_to_time(int days) {
    int64_t ms = (int64_t)days * DAY_IN_MS + EN1545_ZERO_DATE_MS;
    time_t time = (time_t)(ms / 1000);
    return hrt_apply_local_offset(time);
}

time_t en5145_datetime_to_time(int days, int minutes) {
    int64_t ms =
        (int64_t)days * DAY_IN_MS +
        (int64_t)minutes * MINUTE_IN_MS +
        EN1545_ZERO_DATE_MS;

    time_t time = (time_t)(ms / 1000);
    return hrt_apply_local_offset(time);
}

void hrt_travelcard_free(hrt_travel_card_t *card) {
    if (!card) return;

    bytearray_free(&card->application_information_data);
    bytearray_free(&card->control_information_data);
    bytearray_free(&card->period_pass_data);
    bytearray_free(&card->stored_value_data);
    bytearray_free(&card->eticket_data);
    bytearray_free(&card->history_data);

    bytearray_free(&card->application_information_data_v2);
    bytearray_free(&card->control_information_data_v2);
    bytearray_free(&card->period_pass_data_v2);
    bytearray_free(&card->stored_value_data_v2);
    bytearray_free(&card->eticket_data_v2);
    bytearray_free(&card->history_data_v2);

    SAFE_FREE(card->application_instance_id);
    SAFE_FREE(card->history_fields);

    // TODO: Implement value tickets
    // if (card->valueticket) {
    //     eticket_free(card->value_ticket);
    //     card->value_ticket = NULL;
    // }

    memset(card, 0, sizeof(*card));
}

void hrt_travelcard_init_empty(hrt_travel_card_t *card, int version) {
    if (!card) return;

    memset(card, 0, sizeof(*card));

    card->application_information_data = bytearray_alloc(11);
    card->control_information_data     = bytearray_alloc(6);
    card->period_pass_data             = bytearray_alloc(32);
    card->stored_value_data            = bytearray_alloc(12);
    card->eticket_data                 = bytearray_alloc(26);
    card->history_data                 = bytearray_alloc(96);

    card->history_fields = calloc(8, sizeof(hrt_history_t));

    card->application_information_data_v2 = bytearray_alloc(11);
    card->control_information_data_v2     = bytearray_alloc(10);
    card->period_pass_data_v2             = bytearray_alloc(35);
    card->stored_value_data_v2            = bytearray_alloc(13);
    card->eticket_data_v2                 = bytearray_alloc(45);
    card->history_data_v2                 = bytearray_alloc(96);

    card->version = version;
    card->error_status = 0;
}

void hrt_travelcard_init_from_buffers(
    hrt_travel_card_t *card,
    const uint8_t *bArr,
    const uint8_t *bArr2,
    const uint8_t *bArr3,
    const uint8_t *bArr4,
    const uint8_t *bArr5,
    const uint8_t *bArr6,
    size_t         history_len,
    int            version
) {

    hrt_travelcard_init_empty(card, version);

    if (version == 2) {
        hrt_travelcard_set_application_info(card, bArr, 11);
        hrt_travelcard_set_control_info(card, bArr2, 10);
        hrt_travelcard_set_period_pass(card, bArr3, 35);
        hrt_travelcard_set_stored_value(card, bArr4, 13);
        hrt_travelcard_set_eticket(card, bArr5, 45);
        hrt_travelcard_set_history(card, bArr6, history_len);
        return;
    }
    hrt_travelcard_set_application_info(card, bArr, 11);
    hrt_travelcard_set_control_info(card, bArr2, 6);
    hrt_travelcard_set_period_pass(card, bArr3, 32);
    hrt_travelcard_set_stored_value(card, bArr4, 12);
    hrt_travelcard_set_eticket(card, bArr5, 26);
    hrt_travelcard_set_history(card, bArr6, history_len);
}


void hrt_travelcard_init_with_error(hrt_travel_card_t *card, int error_status) {
    hrt_travelcard_init_empty(card, 0);
    card->error_status = error_status;
}

static bool hrt_copy_and_parse(bytearray_t *dst,
                               const uint8_t *src,
                               size_t src_len,
                               size_t expected_len,
                               void (*parse_fn)(hrt_travel_card_t *, bytearray_t),
                               hrt_travel_card_t *card) {
    if (!card || !dst || !dst->data || !src) return false;
    if (expected_len == 0 || src_len < expected_len || dst->length < expected_len) return false;

    memcpy(dst->data, src, expected_len);
    if (parse_fn) {
        parse_fn(card, *dst);
    }
    return true;
}

// Parsing Functions
void hrt_read_application_info(hrt_travel_card_t *card, bytearray_t data) {
    if (!card || !data.data || data.length != 11) return;

    uint8_t first_byte = data.data[0];
    card->application_version     = first_byte & 0xF0;
    card->application_key_version = first_byte & 0x0F;

    uint8_t tmp[9];
    memcpy(tmp, &data.data[1], sizeof(tmp));

    // Free previous value if exists
    if (card->application_instance_id) {
        free(card->application_instance_id);
        card->application_instance_id = NULL;
    }

    card->application_instance_id = convert_get_hex_string(tmp, sizeof(tmp));

    uint8_t last_byte = data.data[10];
    card->platform_type  = last_byte & 0xE0;
    card->security_level = last_byte & 0x10;
}

void hrt_read_control_info(hrt_travel_card_t *card, bytearray_t data) {
    if (!card || !data.data) return;
    card->app_status = convert_get_byte_value(data.data, data.length, 14, 1);
}

void hrt_read_period_pass(hrt_travel_card_t *card, bytearray_t data) {
    // TODO: This function contains lots of magic numbers
    // and bad variable names. Refactoring is recommended.
    if (!card || !data.data || data.length < 32) return;

    const uint8_t *bytes = data.data;

    // ---- Product 1 ----
    // TODO: Better var name for i
    uint16_t i = ((uint16_t)bytes[0]) << 6;
    uint8_t byte1 = bytes[1];

    card->product_code1 = (int16_t)(i | ((byte1 & 0xFC) >> 2));
    card->validity_area_type1 = (byte1 & 0x02) >> 1;

    uint8_t byte2 = bytes[2];
    card->validity_area1 =
        (uint8_t)(((byte1 & 0x01) << 3) | ((byte2 & 0xE0) >> 5));

    // TODO: Better var name for s
    int16_t s =
        (int16_t)(((byte2 & 0x1F) << 9) |
                  ((uint16_t)bytes[3] << 1) |
                  (MSB(bytes[4]) >> 7));

    card->period_start_date1 = en5145_date_to_time(s);

    // TODO: Better var name for s2
    int16_t s2 =
        (int16_t)((LSB7(bytes[4]) << 7) |
                  ((bytes[5] & 0xFE) >> 1));

    card->period_end_date1 = en5145_date_to_time(s2);
    card->period_end_date1 += 86399;  // + 23:59:59
    card->period_length1 = (s2 - s) + 1;

    // ---- Product 2 ----
    uint16_t i2 = ((uint16_t)bytes[6]) << 8;
    uint8_t b3 = bytes[7];

    card->product_code2 = (int16_t)((i2 | (b3 & 0xFC)) >> 2);
    card->validity_area_type2 = b3 & 0x02;

    uint8_t b4 = bytes[8];
    card->validity_area2 =
        (uint8_t)(((b3 & 0x01) << 3) | ((b4 & 0xE0) >> 5));

    int16_t s3 =
        (int16_t)(((b4 & 0x1F) << 9) |
                  ((uint16_t)bytes[9] << 1) |
                  ((bytes[10] & 0x80) >> 7));

    card->period_start_date2 = en5145_date_to_time(s3);

    int16_t s4 =
        (int16_t)((LSB7(bytes[10]) << 7) |
                  ((bytes[11] & 0xFE) >> 1));

    card->period_end_date2 = en5145_date_to_time(s4);
    card->period_end_date2 += 86399;  // + 23:59:59
    card->period_length2 = (s4 - s3) + 1;

    // ---- Loaded period ----
    uint16_t i4 = ((uint16_t)bytes[12]) << 6;
    uint8_t b5 = bytes[13];

    card->loaded_period_product = (int16_t)(i4 | ((b5 & 0xFC) >> 2));

    uint16_t i5 =
        ((b5 & 0x03) << 12) |
        ((uint16_t)bytes[14] << 4);

    uint8_t b6 = bytes[15];

    card->period_loading_date = en5145_datetime_to_time(
                                    (int16_t)(i5 | ((b6 & 0xF0) >> 4)),
                                    (int16_t)(((bytes[16] & 0xFE) >> 1) |
                                              ((b6 & 0x0F) << 7))
                                );

    card->loaded_period_length =
        (int16_t)(((bytes[16] & 0x01) << 8) | bytes[17]);

    uint32_t i6 =
        ((uint32_t)bytes[18] << 12) |
        ((uint32_t)bytes[19] << 4);

    uint8_t b7 = bytes[20];
    card->loaded_period_price = i6 | ((b7 & 0xF0) >> 4);

    uint8_t i7 =
        ((b7 & 0x0F) << 10) |
        ((uint16_t)bytes[21] << 2);

    uint8_t b8 = bytes[22];

    card->period_loading_organization =
        (int16_t)(i7 | ((b8 & 0xC0) >> 6));

    card->period_loading_device_number =
        (int16_t)(((b8 & 0x3F) << 8) | bytes[23]);

    // ---- Boarding ----
    uint16_t i8 = ((uint16_t)bytes[24]) << 6;
    uint8_t b9 = bytes[25];

    card->boarding_date =
        en5145_datetime_to_time(
            (int16_t)(i8 | ((b9 & 0xFC) >> 2)),
            (int16_t)(((b9 & 0x03) << 9) |
                      ((uint16_t)bytes[26] << 1) |
                      ((bytes[27] & 0x80) >> 7))
        );

    uint16_t i9 = LSB7(bytes[27]) << 7;
    uint8_t b10 = bytes[28];

    card->boarding_vehicle =
        (int16_t)(i9 | ((b10 & 0xFE) >> 1));

    uint8_t b11 = bytes[29];
    card->boarding_location_num_type =
        (uint8_t)(((b10 & 0x01) << 1) | ((b11 & 0x80) >> 7));

    uint16_t i11 = LSB7(b11) << 7;
    uint8_t b12 = bytes[30];

    card->boarding_location_num =
        (int16_t)(i11 | ((b12 & 0xFE) >> 1));

    card->boarding_direction = b12 & 0x01;
    card->boarding_area = (bytes[31] & 0xF0) >> 4;
}

void hrt_read_period_pass_v2(hrt_travel_card_t *card, bytearray_t data) {
    if (!card || !data.data) return;

    const uint8_t *bytes = data.data;

    // ---- Product 1 ----
    card->product_code_type1 = convert_get_byte_value(bytes, data.length, 0, 1);
    card->product_code1 = convert_get_short_value(bytes, data.length, 1, 14);
    card->validity_area_type1 = convert_get_byte_value(bytes, data.length, 15, 2);
    card->validity_area1 = convert_get_short_value(bytes, data.length, 17, 6);

    int start1 = convert_get_short_value(bytes, data.length, 23, 14);
    int end1 = convert_get_short_value(bytes, data.length, 37, 14);

    card->period_start_date1 = en5145_date_to_time(start1);
    card->period_end_date1 = en5145_date_to_time(end1);
    card->period_length1 = (end1 - start1) + 1;

    // ---- Product 2 ----
    // In the original decompiled code, product_code_type1 is reassigned from bit offset 56.
    // This should probably be product_code_type2 instead as below
    card->product_code_type2 = convert_get_byte_value(bytes, data.length, 56, 1);
    card->product_code2 = convert_get_short_value(bytes, data.length, 57, 14);
    card->validity_area_type2 = convert_get_byte_value(bytes, data.length, 71, 2);
    card->validity_area2 = convert_get_short_value(bytes, data.length, 73, 6);

    int start2 = convert_get_short_value(bytes, data.length, 79, 14);
    int end2 = convert_get_short_value(bytes, data.length, 93, 14);

    card->period_start_date2 = en5145_date_to_time(start2);
    card->period_end_date2 = en5145_date_to_time(end2);
    card->period_length2 = (end2 - start2) + 1;

    // ---- Loaded period ----
    card->loaded_period_product_type = convert_get_byte_value(bytes, data.length, 112, 1);
    card->loaded_period_product = convert_get_short_value(bytes, data.length, 113, 14);
    card->period_loading_date =
        en5145_datetime_to_time(
            convert_get_short_value(bytes, data.length, 127, 14),
            convert_get_short_value(bytes, data.length, 141, 11)
        );
    card->loaded_period_length = convert_get_short_value(bytes, data.length, 152, 9);
    card->loaded_period_price = convert_get_short_value(bytes, data.length, 161, 20);
    card->period_loading_organization = convert_get_short_value(bytes, data.length, 181, 14);
    card->period_loading_device_number = convert_get_short_value(bytes, data.length, 195, 13);

    // ---- Boarding ----
    card->boarding_date =
        en5145_datetime_to_time(
            convert_get_short_value(bytes, data.length, 208, 14),
            convert_get_short_value(bytes, data.length, 222, 11)
        );
    card->boarding_vehicle = convert_get_short_value(bytes, data.length, 233, 14);
    card->boarding_location_num_type = convert_get_short_value(bytes, data.length, 247, 2);
    card->boarding_location_num = convert_get_short_value(bytes, data.length, 249, 14);
    card->boarding_direction = convert_get_byte_value(bytes, data.length, 263, 1);
    card->boarding_area_type = convert_get_byte_value(bytes, data.length, 264, 2);
    card->boarding_area = convert_get_byte_value(bytes, data.length, 266, 6);
}

void hrt_read_stored_value(hrt_travel_card_t *card, bytearray_t data) {
    if (!card || !data.data || data.length < 3) return;

    const uint8_t *bytes = data.data;

    card->stored_value_counter =
        ((uint32_t)(bytes[2] & 0xF0) >> 4) |
        ((uint32_t)bytes[0] << 12) |
        ((uint32_t)bytes[1] << 4);
}

// void readHistory(bytearray_t data, size_t length);
// void readHistory_v2(bytearray_t data, size_t length);

void hrt_history_init(hrt_history_t *history) {
    if (!history) return;

    history->group_size = 0;
    history->price = 0;
    history->transaction_d_time = (time_t)0;
    history->transaction_type = 0;
    history->transfer_end_date = (time_t)0;
}

void hrt_history_set_transaction_datetime(hrt_history_t *history, time_t datetime) {
    if (history) history->transaction_d_time = datetime;
}

void hrt_history_set_transaction_type(hrt_history_t *history, int type) {
    if (history) history->transaction_type = type;
}

void hrt_history_set_group_size(hrt_history_t *history, int group_size) {
    if (history) history->group_size = group_size;
}

void hrt_history_set_price(hrt_history_t *history, int price) {
    if (history) history->price = price;
}

void hrt_history_set_transfer_end_date(hrt_history_t *history, time_t datetime) {
    if (history) history->transfer_end_date = datetime;
}

// TODO: Implement value tickets
// HRT_eTicket *eticket_create(bytearray_t data, int is_encrypted, int version);

// Getter methods for API simplicity
int hrt_travelcard_get_application_version(const hrt_travel_card_t *card) {
    return card ? card->application_version : 0;
}

int hrt_travelcard_get_application_key_version(const hrt_travel_card_t *card) {
    return card ? card->application_key_version : 0;
}

const char *hrt_travelcard_get_application_instance_id(const hrt_travel_card_t *card) {
    return card ? card->application_instance_id : NULL;
}

int hrt_travelcard_get_platform_type(const hrt_travel_card_t *card) {
    return card ? card->platform_type : 0;
}

int hrt_travelcard_get_security_level(const hrt_travel_card_t *card) {
    return card ? card->security_level : 0;
}

int hrt_travelcard_get_product_code_type1(const hrt_travel_card_t *card) {
    return card ? card->product_code_type1 : 0;
}

int hrt_travelcard_get_product_code1(const hrt_travel_card_t *card) {
    return card ? card->product_code1 : 0;
}

int hrt_travelcard_get_validity_area_type1(const hrt_travel_card_t *card) {
    return card ? card->validity_area_type1 : 0;
}

int hrt_travelcard_get_validity_area1(const hrt_travel_card_t *card) {
    return card ? card->validity_area1 : 0;
}

time_t hrt_travelcard_get_period_start_date1(const hrt_travel_card_t *card) {
    return card ? card->period_start_date1 : (time_t)0;
}

time_t hrt_travelcard_get_period_end_date1(const hrt_travel_card_t *card) {
    return card ? card->period_end_date1 : (time_t)0;
}

int hrt_travelcard_get_period_length1(const hrt_travel_card_t *card) {
    return card ? card->period_length1 : 0;
}

int hrt_travelcard_get_product_code_type2(const hrt_travel_card_t *card) {
    return card ? card->product_code_type2 : 0;
}

int hrt_travelcard_get_product_code2(const hrt_travel_card_t *card) {
    return card ? card->product_code2 : 0;
}

int hrt_travelcard_get_validity_area_type2(const hrt_travel_card_t *card) {
    return card ? card->validity_area_type2 : 0;
}

int hrt_travelcard_get_validity_area2(const hrt_travel_card_t *card) {
    return card ? card->validity_area2 : 0;
}

time_t hrt_travelcard_get_period_start_date2(const hrt_travel_card_t *card) {
    return card ? card->period_start_date2 : (time_t)0;
}

time_t hrt_travelcard_get_period_end_date2(const hrt_travel_card_t *card) {
    return card ? card->period_end_date2 : (time_t)0;
}

int hrt_travelcard_get_period_length2(const hrt_travel_card_t *card) {
    return card ? card->period_length2 : 0;
}

int hrt_travelcard_get_stored_value_counter(const hrt_travel_card_t *card) {
    return card ? card->stored_value_counter : 0;
}

const hrt_eticket_t *hrt_travelcard_get_value_ticket(const hrt_travel_card_t *card) {
    return card ? card->value_ticket : NULL;
}

const hrt_history_t *hrt_travelcard_get_history(const hrt_travel_card_t *card) {
    return card ? card->history_fields : NULL;
}

int hrt_travelcard_get_history_len(const hrt_travel_card_t *card) {
    return card ? card->history_len : 0;
}

int hrt_travelcard_get_boarding_area(const hrt_travel_card_t *card) {
    return card ? card->boarding_area : 0;
}

int hrt_travelcard_get_boarding_area_type(const hrt_travel_card_t *card) {
    return card ? card->boarding_area_type : 0;
}

time_t hrt_travelcard_get_boarding_date(const hrt_travel_card_t *card) {
    return card ? card->boarding_date : (time_t)0;
}

int hrt_travelcard_get_boarding_vehicle(const hrt_travel_card_t *card) {
    return card ? card->boarding_vehicle : 0;
}

int hrt_travelcard_get_boarding_location_num_type(const hrt_travel_card_t *card) {
    return card ? card->boarding_location_num_type : 0;
}

int hrt_travelcard_get_boarding_location_num(const hrt_travel_card_t *card) {
    return card ? card->boarding_location_num : 0;
}

int hrt_travelcard_get_boarding_direction(const hrt_travel_card_t *card) {
    return card ? card->boarding_direction : 0;
}

int hrt_travelcard_get_loaded_period_product_type(const hrt_travel_card_t *card) {
    return card ? card->loaded_period_product_type : 0;
}

int hrt_travelcard_get_loaded_period_product(const hrt_travel_card_t *card) {
    return card ? card->loaded_period_product : 0;
}

time_t hrt_travelcard_get_period_loading_date(const hrt_travel_card_t *card) {
    return card ? card->period_loading_date : (time_t)0;
}

int hrt_travelcard_get_loaded_period_length(const hrt_travel_card_t *card) {
    return card ? card->loaded_period_length : 0;
}

int hrt_travelcard_get_loaded_period_price(const hrt_travel_card_t *card) {
    return card ? card->loaded_period_price : 0;
}

int hrt_travelcard_get_period_loading_organization(const hrt_travel_card_t *card) {
    return card ? card->period_loading_organization : 0;
}

int hrt_travelcard_get_period_loading_device_number(const hrt_travel_card_t *card) {
    return card ? card->period_loading_device_number : 0;
}

int hrt_travelcard_get_app_status(const hrt_travel_card_t *card) {
    return card ? card->app_status : 0;
}

int hrt_travelcard_get_version(const hrt_travel_card_t *card) {
    return card ? card->version : 0;
}

bool hrt_travelcard_set_application_info(hrt_travel_card_t *card, const uint8_t *buf, size_t len) {
    if (!card || !buf || len == 0) return false;

    if (card->version == 2) {
        return hrt_copy_and_parse(&card->application_information_data_v2, buf, len, 11,
                                  hrt_read_application_info, card);
    }
    return hrt_copy_and_parse(&card->application_information_data, buf, len, 11,
                              hrt_read_application_info, card);
}

bool hrt_travelcard_set_control_info(hrt_travel_card_t *card, const uint8_t *buf, size_t len) {
    if (!card || !buf || len == 0) return false;

    if (card->version == 2) {
        return hrt_copy_and_parse(&card->control_information_data_v2, buf, len, 10,
                                  hrt_read_control_info, card);
    }
    return hrt_copy_and_parse(&card->control_information_data, buf, len, 6,
                              hrt_read_control_info, card);
}

bool hrt_travelcard_set_period_pass(hrt_travel_card_t *card, const uint8_t *buf, size_t len) {
    if (!card || !buf || len == 0) return false;

    if (card->version == 2) {
        return hrt_copy_and_parse(&card->period_pass_data_v2, buf, len, 35,
                                  hrt_read_period_pass_v2, card);
    }
    return hrt_copy_and_parse(&card->period_pass_data, buf, len, 32,
                              hrt_read_period_pass, card);
}

bool hrt_travelcard_set_stored_value(hrt_travel_card_t *card, const uint8_t *buf, size_t len) {
    if (!card || !buf || len == 0) return false;

    if (card->version == 2) {
        return hrt_copy_and_parse(&card->stored_value_data_v2, buf, len, 13,
                                  hrt_read_stored_value, card);
    }
    return hrt_copy_and_parse(&card->stored_value_data, buf, len, 12,
                              hrt_read_stored_value, card);
}

bool hrt_travelcard_set_eticket(hrt_travel_card_t *card, const uint8_t *buf, size_t len) {
    if (!card || !buf || len == 0) return false;

    if (card->version == 2) {
        if (len < 45 || card->eticket_data_v2.length < 45) return false;
        memcpy(card->eticket_data_v2.data, buf, 45);
        return true;
    }

    if (len < 26 || card->eticket_data.length < 26) return false;
    memcpy(card->eticket_data.data, buf, 26);
    return true;
}

bool hrt_travelcard_set_history(hrt_travel_card_t *card, const uint8_t *buf, size_t len) {
    if (!card || !buf || len == 0) return false;

    if (card->version == 2) {
        if (len > card->history_data_v2.length) len = card->history_data_v2.length;
        memcpy(card->history_data_v2.data, buf, len);
        // TODO: readHistory_v2(card->historyData_v2, len);
        return true;
    }

    if (len > card->history_data.length) len = card->history_data.length;
    memcpy(card->history_data.data, buf, len);
    // TODO: readHistory(card->historyData, len);
    return true;
}

static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {
    {"help", CmdHelp, AlwaysAvailable, "This help"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdParseHRT(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
