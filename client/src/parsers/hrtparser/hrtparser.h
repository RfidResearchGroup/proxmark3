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

#ifndef HRTPARSER_H__
#define HRTPARSER_H__

#include "common.h"
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define HRT_TRAVELCARD_OK_STATUS                0
#define HRT_TRAVELCARD_NO_HSL_CARD              1
#define HRT_TRAVELCARD_HSL_CARD_DATA_FAILURE    2
#define HRT_TRAVELCARD_CARD_READ_FAILURE        3
#define HRT_TRAVELCARD_HSL_CARDNUMBER_FAILURE   4

#define MSB(b)  ((b) & 0x80)
#define LSB7(b) ((b) & 0x7F)

typedef struct {
    int    boarding_area;
    time_t boarding_date;
    int    boarding_direction;
    int    boarding_location_num;
    int    boarding_location_num_type;
    int    boarding_vehicle;
    int    child;
    int    ext1_fare;
    int    ext1_validity_area;
    int    ext2_fare;
    int    ext2_validity_area;
    int    ext_period_pass_validity_area;
    int    ext_product_code;
    int    extra_zone;
    int    group_size;
    int    language_code;
    int    product_code;
    int    product_code_group;
    time_t sale_date;
    int    sale_status;
    int    sale_time;
    int    ticket_fare;
    int    ticket_fare_group;
    int    validity_area;
    int    validity_area_type;
    time_t validity_end_date;
    time_t validity_end_date_group;
    bool   has_validity_end_date_group;
    int    validity_length;
    int    validity_length_group;
    int    validity_length_type;
    int    validity_length_type_group;
    time_t validity_start_date;
    int    validity_status;
} hrt_eticket_t;

typedef struct {
    int    group_size;
    int    price;
    time_t transaction_d_time;
    int    transaction_type;
    time_t transfer_end_date;
} PACKED hrt_history_t;

typedef struct {
    // ---- Status ----
    int app_status;
    int error_status;

    // ---- Application Information ----
    uint8_t *application_information_data;
    uint8_t *application_information_data_v2;
    char    *application_instance_id;
    int      application_key_version;
    int      application_version;
    int      version;
    int      security_level;
    int      platform_type;

    // ---- Boarding Information ----
    int    boarding_area;
    int    boarding_area_type;
    time_t boarding_date;
    int    boarding_direction;
    int    boarding_location_num;
    int    boarding_location_num_type;
    int    boarding_vehicle;
    time_t last_boarding_date_time;

    // ---- Control / Ticket data ----
    uint8_t *control_information_data;
    uint8_t *control_information_data_v2;
    uint8_t *eticket_data;
    uint8_t *eticket_data_v2;

    // ---- History ----
    uint8_t       *history_data;
    uint8_t       *history_data_v2;
    hrt_history_t *history_fields;
    int            history_len;

    // ---- Period Pass data ----
    uint8_t *period_pass_data;
    uint8_t *period_pass_data_v2;

    time_t period_loading_date;
    int    period_loading_device_number;
    int    period_loading_organization;

    time_t period_start_date1;
    time_t period_end_date1;
    int    period_length1;
    int    product_code1;
    int    product_code_type1;
    int    validity_area1;
    int    validity_area_type1;

    time_t period_start_date2;
    time_t period_end_date2;
    int    period_length2;
    int    product_code2;
    int    product_code_type2;
    int    validity_area2;
    int    validity_area_type2;

    int loaded_period_length;
    int loaded_period_price;
    int loaded_period_product;
    int loaded_period_product_type;

    // ---- Stored Value ----
    uint8_t *stored_value_data;
    uint8_t *stored_value_data_v2;
    int         stored_value_counter;

    // ---- Value Ticket ----
    hrt_eticket_t *value_ticket;
} PACKED hrt_travel_card_t;

int hrt_price_to_string(int cents, char *out, size_t out_len);
char *convert_get_hex_string(const uint8_t *data, size_t length);
int convert_get_byte_value(
    const uint8_t *data,
    size_t data_len,
    int bit_offset,
    int bit_length
);
int convert_get_int_value(
    const uint8_t *data,
    size_t data_len,
    int bit_offset,
    int bit_length
);
int convert_get_short_value(
    const uint8_t *data,
    size_t data_len,
    int bit_offset,
    int bit_length
);

time_t en5145_date_to_time(int days);
time_t en5145_datetime_to_time(int days, int minutes);

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
);

void hrt_travelcard_init_with_error(
    hrt_travel_card_t *card,
    int error_status
);

void hrt_travelcard_free(hrt_travel_card_t *card);

void hrt_history_init(hrt_history_t *history);
void hrt_history_set_transaction_datetime(hrt_history_t *history, time_t datetime);
void hrt_history_set_transaction_type(hrt_history_t *history, int type);
void hrt_history_set_group_size(hrt_history_t *history, int group_size);
void hrt_history_set_price(hrt_history_t *history, int price);
void hrt_history_set_transfer_end_date(hrt_history_t *history, time_t datetime);

// E-ticket Functions
bool   hrt_eticket_is_defined(const hrt_eticket_t *ticket);
int    hrt_eticket_get_product_code(const hrt_eticket_t *ticket);
int    hrt_eticket_get_validity_length_type(const hrt_eticket_t *ticket);
int    hrt_eticket_get_validity_length(const hrt_eticket_t *ticket);
int    hrt_eticket_get_validity_area_type(const hrt_eticket_t *ticket);
int    hrt_eticket_get_validity_area(const hrt_eticket_t *ticket);
time_t hrt_eticket_get_sale_date(const hrt_eticket_t *ticket);
int    hrt_eticket_get_sale_time(const hrt_eticket_t *ticket);
int    hrt_eticket_get_ticket_fare(const hrt_eticket_t *ticket);
int    hrt_eticket_get_right_fare(const hrt_eticket_t *ticket);
int    hrt_eticket_get_total_fare(const hrt_eticket_t *ticket);
int    hrt_eticket_get_group_size(const hrt_eticket_t *ticket);
int    hrt_eticket_get_sale_status(const hrt_eticket_t *ticket);
time_t hrt_eticket_get_validity_start_date(const hrt_eticket_t *ticket);
time_t hrt_eticket_get_validity_end_date(const hrt_eticket_t *ticket);
int    hrt_eticket_get_validity_status(const hrt_eticket_t *ticket);
time_t hrt_eticket_get_boarding_date(const hrt_eticket_t *ticket);
int    hrt_eticket_get_boarding_vehicle(const hrt_eticket_t *ticket);
int    hrt_eticket_get_boarding_location_num_type(const hrt_eticket_t *ticket);
int    hrt_eticket_get_boarding_location_num(const hrt_eticket_t *ticket);
int    hrt_eticket_get_boarding_direction(const hrt_eticket_t *ticket);
int    hrt_eticket_get_boarding_area(const hrt_eticket_t *ticket);
int    hrt_eticket_get_extra_zone(const hrt_eticket_t *ticket);
int    hrt_eticket_get_ext_period_pass_validity_area(const hrt_eticket_t *ticket);
int    hrt_eticket_get_ext_product_code(const hrt_eticket_t *ticket);
int    hrt_eticket_get_ext1_validity_area(const hrt_eticket_t *ticket);
int    hrt_eticket_get_ext1_fare(const hrt_eticket_t *ticket);
int    hrt_eticket_get_ext2_validity_area(const hrt_eticket_t *ticket);
int    hrt_eticket_get_ext2_fare(const hrt_eticket_t *ticket);

// Parsing Functions
void hrt_read_application_info(hrt_travel_card_t *card, const uint8_t *data, size_t data_len);
void hrt_read_control_info(hrt_travel_card_t *card, const uint8_t *data, size_t data_len);
void hrt_read_period_pass(hrt_travel_card_t *card, const uint8_t *data, size_t data_len);
void hrt_read_period_pass_v2(hrt_travel_card_t *card, const uint8_t *data, size_t data_len);
void hrt_read_stored_value(hrt_travel_card_t *card, const uint8_t *data, size_t data_len);
void hrt_read_history(hrt_travel_card_t *card, const uint8_t *data, size_t data_len);
void hrt_read_history_v2(hrt_travel_card_t *card, const uint8_t *data, size_t data_len);

// Getter Functions
int        hrt_travelcard_get_application_version(const hrt_travel_card_t *card);
int        hrt_travelcard_get_application_key_version(const hrt_travel_card_t *card);
const char *hrt_travelcard_get_application_instance_id(const hrt_travel_card_t *card);
int        hrt_travelcard_get_platform_type(const hrt_travel_card_t *card);
int        hrt_travelcard_get_security_level(const hrt_travel_card_t *card);

int        hrt_travelcard_get_product_code_type1(const hrt_travel_card_t *card);
int        hrt_travelcard_get_product_code1(const hrt_travel_card_t *card);
int        hrt_travelcard_get_validity_area_type1(const hrt_travel_card_t *card);
int        hrt_travelcard_get_validity_area1(const hrt_travel_card_t *card);
time_t     hrt_travelcard_get_period_start_date1(const hrt_travel_card_t *card);
time_t     hrt_travelcard_get_period_end_date1(const hrt_travel_card_t *card);
int        hrt_travelcard_get_period_length1(const hrt_travel_card_t *card);

int        hrt_travelcard_get_product_code_type2(const hrt_travel_card_t *card);
int        hrt_travelcard_get_product_code2(const hrt_travel_card_t *card);
int        hrt_travelcard_get_validity_area_type2(const hrt_travel_card_t *card);
int        hrt_travelcard_get_validity_area2(const hrt_travel_card_t *card);
time_t     hrt_travelcard_get_period_start_date2(const hrt_travel_card_t *card);
time_t     hrt_travelcard_get_period_end_date2(const hrt_travel_card_t *card);
int        hrt_travelcard_get_period_length2(const hrt_travel_card_t *card);

int        hrt_travelcard_get_stored_value_counter(const hrt_travel_card_t *card);

const hrt_eticket_t *hrt_travelcard_get_value_ticket(const hrt_travel_card_t *card);

const hrt_history_t *hrt_travelcard_get_history(const hrt_travel_card_t *card);
int        hrt_travelcard_get_history_len(const hrt_travel_card_t *card);

int        hrt_travelcard_get_boarding_area(const hrt_travel_card_t *card);
int        hrt_travelcard_get_boarding_area_type(const hrt_travel_card_t *card);
time_t     hrt_travelcard_get_boarding_date(const hrt_travel_card_t *card);
int        hrt_travelcard_get_boarding_vehicle(const hrt_travel_card_t *card);
int        hrt_travelcard_get_boarding_location_num_type(const hrt_travel_card_t *card);
int        hrt_travelcard_get_boarding_location_num(const hrt_travel_card_t *card);
int        hrt_travelcard_get_boarding_direction(const hrt_travel_card_t *card);

int        hrt_travelcard_get_loaded_period_product_type(const hrt_travel_card_t *card);
int        hrt_travelcard_get_loaded_period_product(const hrt_travel_card_t *card);
time_t     hrt_travelcard_get_period_loading_date(const hrt_travel_card_t *card);
int        hrt_travelcard_get_loaded_period_length(const hrt_travel_card_t *card);
int        hrt_travelcard_get_loaded_period_price(const hrt_travel_card_t *card);
int        hrt_travelcard_get_period_loading_organization(const hrt_travel_card_t *card);
int        hrt_travelcard_get_period_loading_device_number(const hrt_travel_card_t *card);

int        hrt_travelcard_get_app_status(const hrt_travel_card_t *card);
int        hrt_travelcard_get_version(const hrt_travel_card_t *card);

int HRTParser(const char *Cmd);

// Setter Functions
void hrt_travelcard_init_empty(hrt_travel_card_t *card, int version);
bool hrt_travelcard_set_application_info(hrt_travel_card_t *card, const uint8_t *buf, size_t len);
bool hrt_travelcard_set_control_info(hrt_travel_card_t *card, const uint8_t *buf, size_t len);
bool hrt_travelcard_set_period_pass(hrt_travel_card_t *card, const uint8_t *buf, size_t len);
bool hrt_travelcard_set_stored_value(hrt_travel_card_t *card, const uint8_t *buf, size_t len);
bool hrt_travelcard_set_eticket(hrt_travel_card_t *card, const uint8_t *buf, size_t len);
bool hrt_travelcard_set_history(hrt_travel_card_t *card, const uint8_t *buf, size_t len);

#endif
