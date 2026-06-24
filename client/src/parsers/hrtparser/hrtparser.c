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
#include "comms.h"
#include "hrtparser.h"
#include "common.h"
#include "ui.h"
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

#define HRT_APPLICATION_INFORMATION_LEN     11
#define HRT_CONTROL_INFORMATION_LEN          6
#define HRT_CONTROL_INFORMATION_V2_LEN      10
#define HRT_PERIOD_PASS_LEN                 32
#define HRT_PERIOD_PASS_V2_LEN              35
#define HRT_STORED_VALUE_LEN                12
#define HRT_STORED_VALUE_V2_LEN             13
#define HRT_ETICKET_LEN                     26
#define HRT_ETICKET_V2_LEN                  45
#define HRT_HISTORY_LEN                     96
#define HRT_HISTORY_RECORD_LEN              12
#define HRT_HISTORY_RECORDS                  8

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
    char *hex = calloc(out_len, sizeof(char));
    if (!hex) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return NULL;
    }

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

int convert_get_int_value(
    const uint8_t *data,
    size_t data_len,
    int bit_offset,
    int bit_length
) {
    if (!data || bit_length <= 0) return 0;

    if (bit_length > 25) bit_length = 25;

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

    // EN1545 stores local wall-clock date/time. Match Java TimeZone.getOffset()
    // by using the DST state that applies at the represented timestamp.
    utc_time.tm_isdst = local_time.tm_isdst;

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

static void hrt_eticket_parse_v1(hrt_eticket_t *ticket, const uint8_t *data, size_t data_len, bool encrypted) {
    if (!ticket || !data || data_len < (encrypted ? HRT_ETICKET_LEN + 6 : HRT_ETICKET_LEN)) return;

    ticket->product_code = ((uint16_t)data[0] << 6) | ((data[1] & 0xFC) >> 2);
    ticket->child = (data[1] & 0x02) >> 1;
    ticket->language_code = ((data[1] & 0x01) << 1) | ((data[2] & 0x80) >> 7);
    ticket->validity_length_type = (data[2] & 0x60) >> 5;
    ticket->validity_length = ((data[2] & 0x1F) << 3) | ((data[3] & 0xE0) >> 5);
    ticket->validity_area_type = (data[3] & 0x10) >> 4;
    ticket->validity_area = data[3] & 0x0F;
    ticket->sale_date = en5145_date_to_time(((uint16_t)data[4] << 6) | ((data[5] & 0xFC) >> 2));
    ticket->sale_time = ((data[5] & 0x03) << 3) | ((data[6] & 0xE0) >> 5);
    ticket->ticket_fare = convert_get_short_value(data, data_len, 68, 14);
    ticket->group_size = (data[10] & 0x3E) >> 1;
    ticket->sale_status = data[10] & 0x01;

    size_t offset = encrypted ? 6 : 0;

    ticket->validity_start_date = en5145_datetime_to_time(
                                      ((uint16_t)data[offset + 11] << 6) | ((data[offset + 12] & 0xFC) >> 2),
                                      ((data[offset + 12] & 0x03) << 9) |
                                      ((uint16_t)data[offset + 13] << 1) |
                                      ((data[offset + 14] & 0x80) >> 7)
                                  );

    ticket->validity_end_date = en5145_datetime_to_time(
                                    ((data[offset + 14] & 0x7F) << 7) | ((data[offset + 15] & 0xFF) >> 1),
                                    ((data[offset + 15] & 0x01) << 10) |
                                    ((uint16_t)data[offset + 16] << 2) |
                                    ((data[offset + 17] & 0xC0) >> 6)
                                );

    ticket->validity_status = data[offset + 17] & 0x01;

    ticket->boarding_date = en5145_datetime_to_time(
                                ((uint16_t)data[offset + 18] << 6) | ((data[offset + 19] & 0xFC) >> 2),
                                ((data[offset + 19] & 0x03) << 9) |
                                ((uint16_t)data[offset + 20] << 1) |
                                ((data[offset + 21] & 0x80) >> 7)
                            );

    ticket->boarding_vehicle = ((data[offset + 21] & 0x7F) << 7) | ((data[offset + 22] & 0xFE) >> 1);
    ticket->boarding_location_num_type = ((data[offset + 22] & 0x01) << 1) | ((data[offset + 23] & 0x80) >> 7);
    ticket->boarding_location_num = ((data[offset + 23] & 0x7F) << 7) | ((data[offset + 24] & 0xFE) >> 1);
    ticket->boarding_direction = data[offset + 24] & 0x01;
    ticket->boarding_area = (data[offset + 25] & 0xF0) >> 4;
}

static void hrt_eticket_parse_v2(hrt_eticket_t *ticket, const uint8_t *data, size_t data_len) {
    if (!ticket || !data || data_len < HRT_ETICKET_V2_LEN) return;

    ticket->product_code = convert_get_short_value(data, data_len, 1, 14);
    ticket->product_code_group = convert_get_short_value(data, data_len, 15, 14);
    ticket->language_code = convert_get_byte_value(data, data_len, 39, 2);
    ticket->validity_length_type = convert_get_byte_value(data, data_len, 41, 2);
    ticket->validity_length = convert_get_short_value(data, data_len, 43, 8);
    ticket->validity_length_type_group = convert_get_byte_value(data, data_len, 51, 2);
    ticket->validity_length_group = convert_get_short_value(data, data_len, 53, 8);
    ticket->validity_area_type = convert_get_byte_value(data, data_len, 61, 2);
    ticket->validity_area = convert_get_byte_value(data, data_len, 63, 6);
    ticket->sale_date = en5145_date_to_time(convert_get_short_value(data, data_len, 69, 14));
    ticket->sale_time = convert_get_byte_value(data, data_len, 83, 5);
    ticket->ticket_fare = convert_get_short_value(data, data_len, 105, 14);
    ticket->ticket_fare_group = convert_get_short_value(data, data_len, 119, 14);
    ticket->group_size = convert_get_byte_value(data, data_len, 133, 6);
    ticket->extra_zone = convert_get_byte_value(data, data_len, 139, 1);
    ticket->ext_period_pass_validity_area = convert_get_byte_value(data, data_len, 140, 6);
    ticket->ext_product_code = convert_get_short_value(data, data_len, 146, 14);
    ticket->ext1_validity_area = convert_get_byte_value(data, data_len, 160, 6);
    ticket->ext1_fare = convert_get_short_value(data, data_len, 166, 14);
    ticket->ext2_validity_area = convert_get_byte_value(data, data_len, 180, 6);
    ticket->ext2_fare = convert_get_short_value(data, data_len, 186, 14);
    ticket->sale_status = convert_get_byte_value(data, data_len, 200, 1);
    ticket->validity_start_date = en5145_datetime_to_time(
                                      convert_get_short_value(data, data_len, 205, 14),
                                      convert_get_short_value(data, data_len, 219, 11)
                                  );
    ticket->validity_end_date = en5145_datetime_to_time(
                                    convert_get_short_value(data, data_len, 230, 14),
                                    convert_get_short_value(data, data_len, 244, 11)
                                );

    int group_end_days = convert_get_short_value(data, data_len, 255, 14);
    int group_end_minutes = convert_get_short_value(data, data_len, 269, 11);
    if (group_end_days > 0 && group_end_minutes > 0) {
        ticket->validity_end_date_group = en5145_datetime_to_time(group_end_days, group_end_minutes);
        ticket->has_validity_end_date_group = true;
    }

    ticket->validity_status = convert_get_byte_value(data, data_len, 285, 1);
    ticket->boarding_date = en5145_datetime_to_time(
                                convert_get_short_value(data, data_len, 286, 14),
                                convert_get_short_value(data, data_len, 300, 11)
                            );
    ticket->boarding_vehicle = convert_get_short_value(data, data_len, 311, 14);
    ticket->boarding_location_num_type = convert_get_byte_value(data, data_len, 325, 2);
    ticket->boarding_location_num = convert_get_short_value(data, data_len, 327, 14);
    ticket->boarding_direction = convert_get_byte_value(data, data_len, 341, 1);
    ticket->boarding_area = convert_get_byte_value(data, data_len, 344, 6);
}

static hrt_eticket_t *hrt_eticket_create(const uint8_t *data, size_t data_len, bool encrypted, int version) {
    if (!data) return NULL;

    hrt_eticket_t *ticket = calloc(1, sizeof(hrt_eticket_t));
    if (!ticket) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return NULL;
    }

    if (version == 2) {
        hrt_eticket_parse_v2(ticket, data, data_len);
    } else {
        hrt_eticket_parse_v1(ticket, data, data_len, encrypted);
    }

    return ticket;
}

void hrt_travelcard_free(hrt_travel_card_t *card) {
    if (!card) return;

    free(card->application_information_data);
    free(card->control_information_data);
    free(card->period_pass_data);
    free(card->stored_value_data);
    free(card->eticket_data);
    free(card->history_data);

    free(card->application_information_data_v2);
    free(card->control_information_data_v2);
    free(card->period_pass_data_v2);
    free(card->stored_value_data_v2);
    free(card->eticket_data_v2);
    free(card->history_data_v2);

    free(card->application_instance_id);
    free(card->history_fields);

    free(card->value_ticket);
    memset(card, 0, sizeof(*card));
}

void hrt_travelcard_init_empty(hrt_travel_card_t *card, int version) {
    if (!card) return;

    memset(card, 0, sizeof(*card));

    card->application_information_data = calloc(HRT_APPLICATION_INFORMATION_LEN, sizeof(uint8_t));
    card->control_information_data     = calloc(HRT_CONTROL_INFORMATION_LEN, sizeof(uint8_t));
    card->period_pass_data             = calloc(HRT_PERIOD_PASS_LEN, sizeof(uint8_t));
    card->stored_value_data            = calloc(HRT_STORED_VALUE_LEN, sizeof(uint8_t));
    card->eticket_data                 = calloc(HRT_ETICKET_LEN, sizeof(uint8_t));
    card->history_data                 = calloc(HRT_HISTORY_LEN, sizeof(uint8_t));

    card->history_fields = calloc(HRT_HISTORY_RECORDS, sizeof(hrt_history_t));

    card->application_information_data_v2 = calloc(HRT_APPLICATION_INFORMATION_LEN, sizeof(uint8_t));
    card->control_information_data_v2     = calloc(HRT_CONTROL_INFORMATION_V2_LEN, sizeof(uint8_t));
    card->period_pass_data_v2             = calloc(HRT_PERIOD_PASS_V2_LEN, sizeof(uint8_t));
    card->stored_value_data_v2            = calloc(HRT_STORED_VALUE_V2_LEN, sizeof(uint8_t));
    card->eticket_data_v2                 = calloc(HRT_ETICKET_V2_LEN, sizeof(uint8_t));
    card->history_data_v2                 = calloc(HRT_HISTORY_LEN, sizeof(uint8_t));

    if (
        !card->application_information_data ||
        !card->control_information_data ||
        !card->period_pass_data ||
        !card->stored_value_data ||
        !card->eticket_data ||
        !card->history_data ||
        !card->history_fields ||
        !card->application_information_data_v2 ||
        !card->control_information_data_v2 ||
        !card->period_pass_data_v2 ||
        !card->stored_value_data_v2 ||
        !card->eticket_data_v2 ||
        !card->history_data_v2
    ) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        hrt_travelcard_free(card);
        card->error_status = HRT_TRAVELCARD_HSL_CARD_DATA_FAILURE;
        return;
    }

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
    if (!card || card->error_status != HRT_TRAVELCARD_OK_STATUS) return;

    if (version == 2) {
        hrt_travelcard_set_application_info(card, bArr, HRT_APPLICATION_INFORMATION_LEN);
        hrt_travelcard_set_control_info(card, bArr2, HRT_CONTROL_INFORMATION_V2_LEN);
        hrt_travelcard_set_period_pass(card, bArr3, HRT_PERIOD_PASS_V2_LEN);
        hrt_travelcard_set_stored_value(card, bArr4, HRT_STORED_VALUE_V2_LEN);
        hrt_travelcard_set_eticket(card, bArr5, HRT_ETICKET_V2_LEN);
        hrt_travelcard_set_history(card, bArr6, history_len);
        return;
    }
    hrt_travelcard_set_application_info(card, bArr, HRT_APPLICATION_INFORMATION_LEN);
    hrt_travelcard_set_control_info(card, bArr2, HRT_CONTROL_INFORMATION_LEN);
    hrt_travelcard_set_period_pass(card, bArr3, HRT_PERIOD_PASS_LEN);
    hrt_travelcard_set_stored_value(card, bArr4, HRT_STORED_VALUE_LEN);
    hrt_travelcard_set_eticket(card, bArr5, HRT_ETICKET_LEN);
    hrt_travelcard_set_history(card, bArr6, history_len);
}


void hrt_travelcard_init_with_error(hrt_travel_card_t *card, int error_status) {
    hrt_travelcard_init_empty(card, 0);
    card->error_status = error_status;
}

static bool hrt_copy_and_parse(uint8_t *dst,
                               const uint8_t *src,
                               size_t src_len,
                               size_t expected_len,
                               void (*parse_fn)(hrt_travel_card_t *, const uint8_t *, size_t),
                               hrt_travel_card_t *card) {
    if (!card || !dst || !src) return false;
    if (expected_len == 0 || src_len < expected_len) return false;

    memcpy(dst, src, expected_len);
    if (parse_fn) {
        parse_fn(card, dst, expected_len);
    }
    return true;
}

// Parsing Functions
void hrt_read_application_info(hrt_travel_card_t *card, const uint8_t *data, size_t data_len) {
    if (!card || !data || data_len != HRT_APPLICATION_INFORMATION_LEN) return;

    uint8_t first_byte = data[0];
    card->application_version     = first_byte & 0xF0;
    card->application_key_version = first_byte & 0x0F;

    uint8_t tmp[9];
    memcpy(tmp, &data[1], sizeof(tmp));

    // Free previous value if exists
    if (card->application_instance_id) {
        free(card->application_instance_id);
        card->application_instance_id = NULL;
    }

    card->application_instance_id = convert_get_hex_string(tmp, sizeof(tmp));

    uint8_t last_byte = data[10];
    card->platform_type  = last_byte & 0xE0;
    card->security_level = last_byte & 0x10;
}

void hrt_read_control_info(hrt_travel_card_t *card, const uint8_t *data, size_t data_len) {
    if (!card || !data) return;
    card->app_status = convert_get_byte_value(data, data_len, 14, 1);
}

void hrt_read_period_pass(hrt_travel_card_t *card, const uint8_t *data, size_t data_len) {
    if (!card || !data || data_len < HRT_PERIOD_PASS_LEN) return;

    const uint8_t *bytes = data;

    // ---- Product 1 ----
    uint16_t product1_prefix = ((uint16_t)bytes[0]) << 6;
    uint8_t product1_area_byte = bytes[1];

    card->product_code1 = (int16_t)(product1_prefix | ((product1_area_byte & 0xFC) >> 2));
    card->validity_area_type1 = (product1_area_byte & 0x02) >> 1;

    uint8_t product1_start_date_byte = bytes[2];
    card->validity_area1 =
        (uint8_t)(((product1_area_byte & 0x01) << 3) | ((product1_start_date_byte & 0xE0) >> 5));

    int16_t period1_start_days =
        (int16_t)(((product1_start_date_byte & 0x1F) << 9) |
                  ((uint16_t)bytes[3] << 1) |
                  (MSB(bytes[4]) >> 7));

    card->period_start_date1 = en5145_date_to_time(period1_start_days);

    int16_t period1_end_days =
        (int16_t)((LSB7(bytes[4]) << 7) |
                  ((bytes[5] & 0xFE) >> 1));

    card->period_end_date1 = en5145_date_to_time(period1_end_days);
    card->period_end_date1 += 86399;  // + 23:59:59
    card->period_length1 = (period1_end_days - period1_start_days) + 1;

    // ---- Product 2 ----
    uint16_t product2_prefix = ((uint16_t)bytes[6]) << 8;
    uint8_t product2_area_byte = bytes[7];

    card->product_code2 = (int16_t)((product2_prefix | (product2_area_byte & 0xFC)) >> 2);
    card->validity_area_type2 = product2_area_byte & 0x02;

    uint8_t product2_start_date_byte = bytes[8];
    card->validity_area2 =
        (uint8_t)(((product2_area_byte & 0x01) << 3) | ((product2_start_date_byte & 0xE0) >> 5));

    int16_t period2_start_days =
        (int16_t)(((product2_start_date_byte & 0x1F) << 9) |
                  ((uint16_t)bytes[9] << 1) |
                  ((bytes[10] & 0x80) >> 7));

    card->period_start_date2 = en5145_date_to_time(period2_start_days);

    int16_t period2_end_days =
        (int16_t)((LSB7(bytes[10]) << 7) |
                  ((bytes[11] & 0xFE) >> 1));

    card->period_end_date2 = en5145_date_to_time(period2_end_days);
    card->period_end_date2 += 86399;  // + 23:59:59
    card->period_length2 = (period2_end_days - period2_start_days) + 1;

    // ---- Loaded period ----
    uint16_t loaded_product_prefix = ((uint16_t)bytes[12]) << 6;
    uint8_t loaded_product_date_byte = bytes[13];

    card->loaded_period_product = (int16_t)(loaded_product_prefix | ((loaded_product_date_byte & 0xFC) >> 2));

    uint16_t loading_date_prefix =
        ((loaded_product_date_byte & 0x03) << 12) |
        ((uint16_t)bytes[14] << 4);

    uint8_t loading_date_time_byte = bytes[15];

    card->period_loading_date = en5145_datetime_to_time(
                                    (int16_t)(loading_date_prefix | ((loading_date_time_byte & 0xF0) >> 4)),
                                    (int16_t)(((bytes[16] & 0xFE) >> 1) |
                                              ((loading_date_time_byte & 0x0F) << 7))
                                );

    card->loaded_period_length =
        (int16_t)(((bytes[16] & 0x01) << 8) | bytes[17]);

    uint32_t loaded_price_prefix =
        ((uint32_t)bytes[18] << 12) |
        ((uint32_t)bytes[19] << 4);

    uint8_t loaded_price_org_byte = bytes[20];
    card->loaded_period_price = loaded_price_prefix | ((loaded_price_org_byte & 0xF0) >> 4);

    uint8_t loading_org_prefix =
        ((loaded_price_org_byte & 0x0F) << 10) |
        ((uint16_t)bytes[21] << 2);

    uint8_t loading_org_device_byte = bytes[22];

    card->period_loading_organization =
        (int16_t)(loading_org_prefix | ((loading_org_device_byte & 0xC0) >> 6));

    card->period_loading_device_number =
        (int16_t)(((loading_org_device_byte & 0x3F) << 8) | bytes[23]);

    // ---- Boarding ----
    uint16_t boarding_date_prefix = ((uint16_t)bytes[24]) << 6;
    uint8_t boarding_date_time_byte = bytes[25];

    card->boarding_date =
        en5145_datetime_to_time(
            (int16_t)(boarding_date_prefix | ((boarding_date_time_byte & 0xFC) >> 2)),
            (int16_t)(((boarding_date_time_byte & 0x03) << 9) |
                      ((uint16_t)bytes[26] << 1) |
                      ((bytes[27] & 0x80) >> 7))
        );

    uint16_t boarding_vehicle_prefix = LSB7(bytes[27]) << 7;
    uint8_t boarding_vehicle_location_type_byte = bytes[28];

    card->boarding_vehicle =
        (int16_t)(boarding_vehicle_prefix | ((boarding_vehicle_location_type_byte & 0xFE) >> 1));

    uint8_t boarding_location_type_number_byte = bytes[29];
    card->boarding_location_num_type =
        (uint8_t)(((boarding_vehicle_location_type_byte & 0x01) << 1) | ((boarding_location_type_number_byte & 0x80) >> 7));

    uint16_t boarding_location_prefix = LSB7(boarding_location_type_number_byte) << 7;
    uint8_t boarding_location_direction_byte = bytes[30];

    card->boarding_location_num =
        (int16_t)(boarding_location_prefix | ((boarding_location_direction_byte & 0xFE) >> 1));

    card->boarding_direction = boarding_location_direction_byte & 0x01;
    card->boarding_area = (bytes[31] & 0xF0) >> 4;
}

void hrt_read_period_pass_v2(hrt_travel_card_t *card, const uint8_t *data, size_t data_len) {
    if (!card || !data || data_len < HRT_PERIOD_PASS_V2_LEN) return;

    // ---- Product 1 ----
    card->product_code_type1 = convert_get_byte_value(data, data_len, 0, 1);
    card->product_code1 = convert_get_short_value(data, data_len, 1, 14);
    card->validity_area_type1 = convert_get_byte_value(data, data_len, 15, 2);
    card->validity_area1 = convert_get_short_value(data, data_len, 17, 6);

    int start1 = convert_get_short_value(data, data_len, 23, 14);
    int end1 = convert_get_short_value(data, data_len, 37, 14);

    card->period_start_date1 = en5145_date_to_time(start1);
    card->period_end_date1 = en5145_date_to_time(end1);
    card->period_length1 = (end1 - start1) + 1;

    // ---- Product 2 ----
    // In the original decompiled code, product_code_type1 is reassigned from bit offset 56.
    // This should probably be product_code_type2 instead as below
    card->product_code_type2 = convert_get_byte_value(data, data_len, 56, 1);
    card->product_code2 = convert_get_short_value(data, data_len, 57, 14);
    card->validity_area_type2 = convert_get_byte_value(data, data_len, 71, 2);
    card->validity_area2 = convert_get_short_value(data, data_len, 73, 6);

    int start2 = convert_get_short_value(data, data_len, 79, 14);
    int end2 = convert_get_short_value(data, data_len, 93, 14);

    card->period_start_date2 = en5145_date_to_time(start2);
    card->period_end_date2 = en5145_date_to_time(end2);
    card->period_length2 = (end2 - start2) + 1;

    // ---- Loaded period ----
    card->loaded_period_product_type = convert_get_byte_value(data, data_len, 112, 1);
    card->loaded_period_product = convert_get_short_value(data, data_len, 113, 14);
    card->period_loading_date =
        en5145_datetime_to_time(
            convert_get_short_value(data, data_len, 127, 14),
            convert_get_short_value(data, data_len, 141, 11)
        );
    card->loaded_period_length = convert_get_short_value(data, data_len, 152, 9);
    card->loaded_period_price = convert_get_int_value(data, data_len, 161, 20);
    card->period_loading_organization = convert_get_short_value(data, data_len, 181, 14);
    card->period_loading_device_number = convert_get_short_value(data, data_len, 195, 13);

    // ---- Boarding ----
    card->boarding_date =
        en5145_datetime_to_time(
            convert_get_short_value(data, data_len, 208, 14),
            convert_get_short_value(data, data_len, 222, 11)
        );
    card->boarding_vehicle = convert_get_short_value(data, data_len, 233, 14);
    card->boarding_location_num_type = convert_get_short_value(data, data_len, 247, 2);
    card->boarding_location_num = convert_get_short_value(data, data_len, 249, 14);
    card->boarding_direction = convert_get_byte_value(data, data_len, 263, 1);
    card->boarding_area_type = convert_get_byte_value(data, data_len, 264, 2);
    card->boarding_area = convert_get_byte_value(data, data_len, 266, 6);
}

void hrt_read_stored_value(hrt_travel_card_t *card, const uint8_t *data, size_t data_len) {
    if (!card || !data || data_len < 3) return;

    card->stored_value_counter =
        ((uint32_t)(data[2] & 0xF0) >> 4) |
        ((uint32_t)data[0] << 12) |
        ((uint32_t)data[1] << 4);
}

void hrt_read_history(hrt_travel_card_t *card, const uint8_t *data, size_t data_len) {
    if (!card || !data || !card->history_fields) return;

    size_t record_count = data_len / HRT_HISTORY_RECORD_LEN;
    if (record_count > HRT_HISTORY_RECORDS) {
        record_count = HRT_HISTORY_RECORDS;
    }

    memset(card->history_fields, 0, HRT_HISTORY_RECORDS * sizeof(hrt_history_t));
    card->history_len = 0;

    for (size_t i = 0; i < record_count; i++) {
        size_t offset = i * HRT_HISTORY_RECORD_LEN;

        if (data[offset + 1] == 0 &&
            data[offset + 2] == 0 &&
            data[offset + 3] == 0 &&
            data[offset + 4] == 0) {
            continue;
        }

        hrt_history_t *history = &card->history_fields[card->history_len];
        hrt_history_init(history);

        history->transaction_type = (data[offset] & 0x80) >> 7;

        uint8_t date_time_byte = data[offset + 3];
        int days = ((date_time_byte & 0x3F) << 8) | data[offset + 4];
        int minutes = ((data[offset + 1] & 0x01) << 10) |
                      ((uint16_t)data[offset + 2] << 2) |
                      ((date_time_byte & 0xC0) >> 6);

        int transfer_end_minutes = ((uint16_t)data[offset + 5] << 3) |
                                   ((data[offset + 6] & 0xE0) >> 5);

        if (transfer_end_minutes < minutes) {
            days--;
        }

        history->transaction_d_time = en5145_datetime_to_time(days, minutes);
        history->price = ((uint16_t)data[offset + 7] << 1) |
                         ((data[offset + 6] & 0x1F) << 9) |
                         ((data[offset + 8] & 0x80) >> 7);
        history->group_size = (data[offset + 8] & 0x7C) >> 2;

        card->history_len++;
    }
}

void hrt_read_history_v2(hrt_travel_card_t *card, const uint8_t *data, size_t data_len) {
    if (!card || !data || !card->history_fields) return;

    size_t record_count = data_len / HRT_HISTORY_RECORD_LEN;
    if (record_count > HRT_HISTORY_RECORDS) {
        record_count = HRT_HISTORY_RECORDS;
    }

    memset(card->history_fields, 0, HRT_HISTORY_RECORDS * sizeof(hrt_history_t));
    card->history_len = 0;

    for (size_t i = 0; i < record_count; i++) {
        size_t byte_offset = i * HRT_HISTORY_RECORD_LEN;

        if (data[byte_offset + 1] == 0 &&
            data[byte_offset + 2] == 0 &&
            data[byte_offset + 3] == 0 &&
            data[byte_offset + 4] == 0) {
            continue;
        }

        int bit_offset = (int)(i * 96);
        hrt_history_t *history = &card->history_fields[card->history_len];
        hrt_history_init(history);

        history->transaction_type = convert_get_byte_value(data, data_len, bit_offset, 1);
        history->transaction_d_time = en5145_datetime_to_time(
                                          convert_get_short_value(data, data_len, bit_offset + 1, 14),
                                          convert_get_short_value(data, data_len, bit_offset + 15, 11)
                                      );
        history->transfer_end_date = en5145_datetime_to_time(
                                         convert_get_short_value(data, data_len, bit_offset + 26, 14),
                                         convert_get_short_value(data, data_len, bit_offset + 40, 11)
                                     );
        history->price = convert_get_short_value(data, data_len, bit_offset + 51, 14);
        history->group_size = convert_get_byte_value(data, data_len, bit_offset + 65, 6);

        card->history_len++;
    }
}

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

bool hrt_eticket_is_defined(const hrt_eticket_t *ticket) {
    return ticket &&
           (ticket->product_code > 0 ||
            ticket->product_code_group > 0 ||
            ticket->ticket_fare > 0 ||
            ticket->ticket_fare_group > 0 ||
            ticket->group_size > 0 ||
            ticket->boarding_vehicle > 0);
}

int hrt_eticket_get_product_code(const hrt_eticket_t *ticket) {
    if (!ticket) return 0;
    return ticket->product_code_group > 0 ? ticket->product_code_group : ticket->product_code;
}

int hrt_eticket_get_validity_length_type(const hrt_eticket_t *ticket) {
    if (!ticket) return 0;
    return ticket->validity_length_type_group > 0 ? ticket->validity_length_type_group : ticket->validity_length_type;
}

int hrt_eticket_get_validity_length(const hrt_eticket_t *ticket) {
    if (!ticket) return 0;
    return ticket->validity_length_group > 0 ? ticket->validity_length_group : ticket->validity_length;
}

int hrt_eticket_get_validity_area_type(const hrt_eticket_t *ticket) {
    return ticket ? ticket->validity_area_type : 0;
}

int hrt_eticket_get_validity_area(const hrt_eticket_t *ticket) {
    return ticket ? ticket->validity_area : 0;
}

time_t hrt_eticket_get_sale_date(const hrt_eticket_t *ticket) {
    return ticket ? ticket->sale_date : (time_t)0;
}

int hrt_eticket_get_sale_time(const hrt_eticket_t *ticket) {
    return ticket ? ticket->sale_time : 0;
}

int hrt_eticket_get_ticket_fare(const hrt_eticket_t *ticket) {
    if (!ticket) return 0;
    if (ticket->ticket_fare > 0) return ticket->ticket_fare;
    return ticket->ticket_fare_group > 0 ? ticket->ticket_fare_group : 0;
}

int hrt_eticket_get_right_fare(const hrt_eticket_t *ticket) {
    if (!ticket) return 0;

    int fare = ticket->ticket_fare;
    int group_size = ticket->group_size;
    if ((ticket->extra_zone == 1 || fare > 0) && group_size > 1) {
        group_size--;
    }
    return fare + (ticket->ticket_fare_group * group_size);
}

int hrt_eticket_get_total_fare(const hrt_eticket_t *ticket) {
    if (!ticket) return 0;

    int fare = hrt_eticket_get_right_fare(ticket);
    return ticket->extra_zone == 1 ? fare + ticket->ext1_fare + ticket->ext2_fare : fare;
}

int hrt_eticket_get_group_size(const hrt_eticket_t *ticket) {
    return ticket ? ticket->group_size : 0;
}

int hrt_eticket_get_sale_status(const hrt_eticket_t *ticket) {
    return ticket ? ticket->sale_status : 0;
}

time_t hrt_eticket_get_validity_start_date(const hrt_eticket_t *ticket) {
    return ticket ? ticket->validity_start_date : (time_t)0;
}

time_t hrt_eticket_get_validity_end_date(const hrt_eticket_t *ticket) {
    if (!ticket) return (time_t)0;
    return ticket->has_validity_end_date_group ? ticket->validity_end_date_group : ticket->validity_end_date;
}

int hrt_eticket_get_validity_status(const hrt_eticket_t *ticket) {
    return ticket ? ticket->validity_status : 0;
}

time_t hrt_eticket_get_boarding_date(const hrt_eticket_t *ticket) {
    return ticket ? ticket->boarding_date : (time_t)0;
}

int hrt_eticket_get_boarding_vehicle(const hrt_eticket_t *ticket) {
    return ticket ? ticket->boarding_vehicle : 0;
}

int hrt_eticket_get_boarding_location_num_type(const hrt_eticket_t *ticket) {
    return ticket ? ticket->boarding_location_num_type : 0;
}

int hrt_eticket_get_boarding_location_num(const hrt_eticket_t *ticket) {
    return ticket ? ticket->boarding_location_num : 0;
}

int hrt_eticket_get_boarding_direction(const hrt_eticket_t *ticket) {
    return ticket ? ticket->boarding_direction : 0;
}

int hrt_eticket_get_boarding_area(const hrt_eticket_t *ticket) {
    return ticket ? ticket->boarding_area : 0;
}

int hrt_eticket_get_extra_zone(const hrt_eticket_t *ticket) {
    return ticket ? ticket->extra_zone : 0;
}

int hrt_eticket_get_ext_period_pass_validity_area(const hrt_eticket_t *ticket) {
    return ticket ? ticket->ext_period_pass_validity_area : 0;
}

int hrt_eticket_get_ext_product_code(const hrt_eticket_t *ticket) {
    return ticket ? ticket->ext_product_code : 0;
}

int hrt_eticket_get_ext1_validity_area(const hrt_eticket_t *ticket) {
    return ticket ? ticket->ext1_validity_area : 0;
}

int hrt_eticket_get_ext1_fare(const hrt_eticket_t *ticket) {
    return ticket ? ticket->ext1_fare : 0;
}

int hrt_eticket_get_ext2_validity_area(const hrt_eticket_t *ticket) {
    return ticket ? ticket->ext2_validity_area : 0;
}

int hrt_eticket_get_ext2_fare(const hrt_eticket_t *ticket) {
    return ticket ? ticket->ext2_fare : 0;
}

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

// Setter methods for API simplicity
bool hrt_travelcard_set_application_info(hrt_travel_card_t *card, const uint8_t *buf, size_t len) {
    if (!card || !buf || len == 0) return false;

    if (card->version == 2) {
        return hrt_copy_and_parse(card->application_information_data_v2, buf, len, HRT_APPLICATION_INFORMATION_LEN,
                                  hrt_read_application_info, card);
    }
    return hrt_copy_and_parse(card->application_information_data, buf, len, HRT_APPLICATION_INFORMATION_LEN,
                              hrt_read_application_info, card);
}

bool hrt_travelcard_set_control_info(hrt_travel_card_t *card, const uint8_t *buf, size_t len) {
    if (!card || !buf || len == 0) return false;

    if (card->version == 2) {
        return hrt_copy_and_parse(card->control_information_data_v2, buf, len, HRT_CONTROL_INFORMATION_V2_LEN,
                                  hrt_read_control_info, card);
    }
    return hrt_copy_and_parse(card->control_information_data, buf, len, HRT_CONTROL_INFORMATION_LEN,
                              hrt_read_control_info, card);
}

bool hrt_travelcard_set_period_pass(hrt_travel_card_t *card, const uint8_t *buf, size_t len) {
    if (!card || !buf || len == 0) return false;

    if (card->version == 2) {
        return hrt_copy_and_parse(card->period_pass_data_v2, buf, len, HRT_PERIOD_PASS_V2_LEN,
                                  hrt_read_period_pass_v2, card);
    }
    return hrt_copy_and_parse(card->period_pass_data, buf, len, HRT_PERIOD_PASS_LEN,
                              hrt_read_period_pass, card);
}

bool hrt_travelcard_set_stored_value(hrt_travel_card_t *card, const uint8_t *buf, size_t len) {
    if (!card || !buf || len == 0) return false;

    if (card->version == 2) {
        return hrt_copy_and_parse(card->stored_value_data_v2, buf, len, HRT_STORED_VALUE_V2_LEN,
                                  hrt_read_stored_value, card);
    }
    return hrt_copy_and_parse(card->stored_value_data, buf, len, HRT_STORED_VALUE_LEN,
                              hrt_read_stored_value, card);
}

bool hrt_travelcard_set_eticket(hrt_travel_card_t *card, const uint8_t *buf, size_t len) {
    if (!card || !buf || len == 0) return false;

    if (card->version == 2) {
        if (!card->eticket_data_v2 || len < HRT_ETICKET_V2_LEN) return false;
        memcpy(card->eticket_data_v2, buf, HRT_ETICKET_V2_LEN);

        free(card->value_ticket);
        card->value_ticket = hrt_eticket_create(card->eticket_data_v2, HRT_ETICKET_V2_LEN, false, 2);
        return card->value_ticket != NULL;
    }

    if (!card->eticket_data || len < HRT_ETICKET_LEN) return false;
    memcpy(card->eticket_data, buf, HRT_ETICKET_LEN);

    free(card->value_ticket);
    card->value_ticket = hrt_eticket_create(card->eticket_data, HRT_ETICKET_LEN, false, 1);
    return card->value_ticket != NULL;
}

bool hrt_travelcard_set_history(hrt_travel_card_t *card, const uint8_t *buf, size_t len) {
    if (!card || !buf || len == 0) return false;

    if (card->version == 2) {
        if (!card->history_data_v2) return false;
        if (len > HRT_HISTORY_LEN) len = HRT_HISTORY_LEN;
        memcpy(card->history_data_v2, buf, len);
        hrt_read_history_v2(card, card->history_data_v2, len);
        return true;
    }

    if (!card->history_data) return false;
    if (len > HRT_HISTORY_LEN) len = HRT_HISTORY_LEN;
    memcpy(card->history_data, buf, len);
    hrt_read_history(card, card->history_data, len);
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

int HRTParser(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
