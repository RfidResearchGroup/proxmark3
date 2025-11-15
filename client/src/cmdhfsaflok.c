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
// Saflok commands
//-----------------------------------------------------------------------------
#include "cmdhfsaflok.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <inttypes.h>
#include <time.h>
#include "cliparser.h"
#include "cmdparser.h"
#include "comms.h"
#include "ui.h"
#include "util.h"
#include "mifare/mifarehost.h"
#include "mifare.h"
#include "commonutil.h"
#include "generator.h"
#include "cmdhfmf.h"

// MiFARE Classic encoded with SafeLok encoded data
// defining this structure makes it more clear what
// is passed around, and avoids the need to pass lengths
// to many of the functions.
static const uint8_t days_in_month_lookup[] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

// TODO: consider separate structs for encrypted vs. decrypted
//       for even greater type safety.
typedef struct _saflok_mfc_data_t {
    uint8_t raw[17];
} saflok_mfc_data_t;
typedef struct _saflock_mfc_uid_t {
    uint8_t uid[4];
} saflok_mfc_uid_t;
typedef struct _saflok_mfc_key_t {
    uint8_t key[6];
} saflok_mfc_key_t;
typedef struct _saflok_mfc_datetime_t {
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
} saflok_mfc_datetime_t;
typedef struct _saflok_mfc_datetime_offset_t {
    uint8_t years;
    uint8_t months;
    uint8_t days;
    uint8_t hours;
    uint8_t minutes;
} saflok_mfc_datetime_offset_t;

#define KEY_LENGTH sizeof(saflok_mfc_key_t)

static uint32_t extract_bits(const saflok_mfc_data_t *data, size_t start_bit, size_t num_bits);
static void insert_bits(saflok_mfc_data_t *data, size_t start_bit, size_t num_bits, uint32_t value);



#if 1 // getters and setters for each bitfield in saflok_mfc_data_t
    // TODO: consider update to setter functions to use smaller type for data?
    //       avoiding for this commit, as larger change.
    //
    // card_level               field is  4 bits
    // card_type                field is  4 bits
    // card_id                  field is  8 bits
    // opening_key              field is  2 bits
    // lock_id                  field is 14 bits
    // pass_number              field is 12 bits
    // sequence_and_combination field is 12 bits
    // deadbolt_override        field is  1 bits
    // restricted_days          field is  7 bits
    // raw_expire_date          field is 24 bits -- special set processing needed
    // raw_card_creation_date   field is 28 bits -- special set processing needed
    // property_id              field is 12 bits

    static inline uint8_t get_saflok_mfc_card_level(const saflok_mfc_data_t *data) {
        return (uint8_t)extract_bits(data, 0, 4);
    }
    static inline bool set_saflok_mfc_card_level(saflok_mfc_data_t *data, uint32_t card_level) {
        if (card_level > 0xFu) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " card_level out of range (%08x)\n", card_level);
            return false;
        }
        insert_bits(data, 0, 4, card_level);
        return true;
    }
    static inline uint8_t get_saflok_mfc_card_type(const saflok_mfc_data_t *data) {
        return (uint8_t)extract_bits(data, 4, 4);
    }
    static inline bool set_saflok_mfc_card_type(saflok_mfc_data_t *data, uint32_t card_type) {
        if (card_type > 0xFu) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " card_type out of range (%08x)\n", card_type);
            return false;
        }
        insert_bits(data, 4, 4, card_type);
        return true;
    }
    static inline uint8_t get_saflok_mfc_card_id(const saflok_mfc_data_t *data) {
        return (uint8_t)extract_bits(data, 8, 8);
    }
    static inline bool set_saflok_mfc_card_id(saflok_mfc_data_t *data, uint32_t card_id) {
        if (card_id > 0xFFu) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " card_id out of range (%08x)\n", card_id);
            return false;
        }
        insert_bits(data, 8, 8, card_id);
        return true;
    }
    static inline uint8_t get_saflok_mfc_opening_key(const saflok_mfc_data_t *data) {
        return (uint8_t)extract_bits(data, 16, 2);
    }
    static inline bool set_saflok_mfc_opening_key(saflok_mfc_data_t *data, uint32_t opening_key) {
        if (opening_key > 0x3u) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " opening_key out of range (%08x)\n", opening_key);
            return false;
        }
        insert_bits(data, 16, 2, opening_key);
        return true;
    }
    static inline uint16_t get_saflok_mfc_lock_id(const saflok_mfc_data_t *data) {
        return (uint16_t)extract_bits(data, 18, 14);
    }
    static inline bool set_saflok_mfc_lock_id(saflok_mfc_data_t *data, uint32_t lock_id) {
        if (lock_id > 0x3FFFu) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " lock_id out of range (%08x)\n", lock_id);
            return false;
        }
        insert_bits(data, 18, 14, lock_id);
        return true;
    }
    static inline uint16_t get_saflok_mfc_pass_number(const saflok_mfc_data_t *data) {
        return (uint16_t)extract_bits(data, 32, 12);
    }
    static inline bool set_saflok_mfc_pass_number(saflok_mfc_data_t *data, uint32_t pass_number) {
        if (pass_number > 0xFFFu) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " pass_number out of range (%08x)\n", pass_number);
            return false;
        }
        insert_bits(data, 32, 12, pass_number);
        return true;
    }
    static inline uint16_t get_saflok_mfc_sequence_and_combination(const saflok_mfc_data_t *data) {
        return (uint16_t)extract_bits(data, 44, 12);
    }
    static inline bool set_saflok_mfc_sequence_and_combination(saflok_mfc_data_t *data, uint32_t sequence_and_combination) {
        if (sequence_and_combination > 0xFFFu) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " sequence_and_combination out of range (%08x)\n", sequence_and_combination);
            return false;
        }
        insert_bits(data, 44, 12, sequence_and_combination);
        return true;
    }
    static inline bool get_saflok_mfc_deadbolt_override(const saflok_mfc_data_t *data) {
        uint32_t result = extract_bits(data, 56, 1);
        return (result != 0);
    }
    static inline bool set_saflok_mfc_deadbolt_override(saflok_mfc_data_t *data, uint32_t deadbolt_override) {
        insert_bits(data, 56, 1, deadbolt_override ? 0x1 : 0x0);
        return true;
    }
    static inline uint8_t get_saflok_mfc_restricted_days(const saflok_mfc_data_t *data) {
        return (uint8_t)extract_bits(data, 57, 7);
    }
    static inline bool set_saflok_mfc_restricted_days(saflok_mfc_data_t *data, uint32_t restricted_days) {
        if (restricted_days > 0x7Fu) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " restricted_days out of range (%08x)\n", restricted_days);
            return false;
        }
        insert_bits(data, 57, 7, restricted_days);
        return true;
    }
    static inline uint32_t get_saflok_mfc_raw_interval_date(const saflok_mfc_data_t *data) {
        return extract_bits(data, 64, 24);
    }
    static inline bool set_saflok_mfc_raw_interval_date(saflok_mfc_data_t *data, uint32_t raw_interval_date) {
        if (raw_interval_date > 0xFFFFFFu) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " raw_interval_date out of range (%08x)\n", raw_interval_date);
            return false;
        }
        insert_bits(data, 64, 24, raw_interval_date);
        return true;
    }
    static inline uint32_t get_saflok_mfc_raw_card_creation_date(const saflok_mfc_data_t *data) {
        return extract_bits(data, 88, 28);
    }
    static inline bool set_saflok_mfc_raw_card_creation_date(saflok_mfc_data_t *data, uint32_t raw_card_creation_date) {
        if (raw_card_creation_date > 0x0FFFFFFFu) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " raw_card_creation_date out of range (%08x)\n", raw_card_creation_date);
            return false;
        }
        insert_bits(data, 88, 28, raw_card_creation_date);
        return true;
    }
    static inline uint16_t get_saflok_mfc_property_id(const saflok_mfc_data_t *data) {
        return extract_bits(data, 116, 12);
    }
    static inline bool set_saflok_mfc_property_id(saflok_mfc_data_t *data, uint32_t property_id) {
        if (property_id > 0xFFFFu) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " property_id out of range (%08x)\n", property_id);
            return false;
        }
        insert_bits(data, 116, 12, property_id);
        return true;
    }
#endif // getters and setters for each bitfield in saflok_mfc_data_t

#if 1 // helpers for get/set_saflok_mfc_card_creation_date() ... do not call these directly as does not validate...
    static inline uint16_t _get_saflok_mfc_card_creation_year_impl(const saflok_mfc_data_t *data) {
        uint8_t creation_year_bits_high = (data->raw[14] & 0xF0u);
        uint8_t creation_year_bits_low  = (data->raw[11] & 0xF0u) >> 4;
        uint8_t creation_year_bits = creation_year_bits_high | creation_year_bits_low;
        uint16_t creation_year = 1980u + creation_year_bits; // automatically extends to uint16_t
        return creation_year;
    }
    static inline bool _set_saflok_mfc_card_creation_year_impl(saflok_mfc_data_t *data, uint16_t year) {
        if (year < 1980u || year > (1980u+0xFFu)) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " year out of range (%u)\n", year);
            return false;
        }
        uint16_t year_bits = year - 1980u;
        uint8_t creation_year_bits_high = year_bits & 0xF0u;
        uint8_t creation_year_bits_low  = (year_bits & 0x0Fu) << 4;
        data->raw[14] = (data->raw[14] & 0x0Fu) | creation_year_bits_high;
        data->raw[11] = (data->raw[11] & 0x0Fu) | creation_year_bits_low;
        return true;
    }
    static inline uint8_t _get_saflok_mfc_card_creation_month_impl(const saflok_mfc_data_t *data) {
        // should be in range [1..12] ... value of zero is invalid
        return (data->raw[11] & 0x0Fu);
    }
    static inline bool _set_saflok_mfc_card_creation_month_impl(saflok_mfc_data_t *data, uint8_t month) {
        if (month < 1 || month > 12) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " month out of range (%u)\n", month);
            return false;
        }
        data->raw[11] = (data->raw[11] & 0xF0u) | (month & 0x0Fu);
        return true;
    }
    static inline uint8_t _get_saflok_mfc_card_creation_day_impl(const saflok_mfc_data_t *data) {
        return ((data->raw[12] >> 3) & 0x1Fu);
    }
    static inline bool _set_saflok_mfc_card_creation_day_impl(saflok_mfc_data_t *data, uint8_t day) {
        data->raw[12] = (data->raw[12] & 0xE0u) | ((day & 0x1Fu) << 3);
        return true;
    }
    static inline uint8_t _get_saflok_mfc_card_creation_hour_impl(const saflok_mfc_data_t *data) {
        // low three bits from raw[12]
        // high two bits from raw[13]
        return (((data->raw[12] & 0x07u) << 2) | (data->raw[13] >> 6));
    }
    static inline bool _set_saflok_mfc_card_creation_hour_impl(saflok_mfc_data_t *data, uint8_t hour) {
        data->raw[12] = (data->raw[12] & 0xF8u) | ((hour >> 2) & 0x07u);
        data->raw[13] = (data->raw[13] & 0x3Fu) | ((hour & 0x03u) << 6);
        return true;
    }
    static inline uint8_t _get_saflok_mfc_card_creation_minute_impl(const saflok_mfc_data_t *data) {
        return (data->raw[13] & 0x3Fu);
    }
    static inline bool _set_saflok_mfc_card_creation_minute_impl(saflok_mfc_data_t *data, uint8_t minute) {
        data->raw[13] = (data->raw[13] & 0xC0u) | (minute & 0x3Fu);
        return true;
    }
#endif // // helpers for get/set_saflok_mfc_card_creation_date() ... do not call these directly as does not validate...
#if 1 // getters and setters for creation date

    static inline bool is_saflok_mfc_datetime_valid(const saflok_mfc_datetime_t *date) {
        bool result = true;
        if ((date->year < 1980) || (date->year > (1980u+0xFFu)) ) {
            PrintAndLogEx(WARNING, "year out of range (%d)\n", date->year);
            result = false;
        }
        if ((date->month < 1) || (date->month > 12)) {
            PrintAndLogEx(WARNING, "month out of range (%d)\n", date->month);
            result = false;
        }
        uint8_t max_days = days_in_month_lookup[date->month];
        // Adjust for leap years
        if ((date->month == 2u) &&
            (date->year % 4u == 0u) &&
            ((date->year % 100u != 0u) || (date->year % 400u == 0u))
           ) {
            max_days = 29u;
        }
        if ((date->day < 1u) || (date->day > max_days)) {
            PrintAndLogEx(WARNING, "day out of range (%d) for month %d year %d\n", date->day, date->month, date->year);
            result = false;
        }
        if (date->hour > 23) {
            PrintAndLogEx(WARNING, "hour out of range (%d)\n", date->hour);
            result = false;
        }
        if (date->minute > 59) {
            PrintAndLogEx(WARNING, "minute out of range (%d)\n", date->minute);
            result = false;
        }
        return result;
    }
    static inline saflok_mfc_datetime_t get_saflok_mfc_card_creation_datetime(
        const saflok_mfc_data_t *data
        ) {
        saflok_mfc_datetime_t date = {
            .year = _get_saflok_mfc_card_creation_year_impl(data),
            .month = _get_saflok_mfc_card_creation_month_impl(data),
            .day = _get_saflok_mfc_card_creation_day_impl(data),
            .hour = _get_saflok_mfc_card_creation_hour_impl(data),
            .minute = _get_saflok_mfc_card_creation_minute_impl(data)
        };
        if (!is_saflok_mfc_datetime_valid(&date)) {
            PrintAndLogEx(WARNING, "Warning: creation date appears invalid: %04d-%02d-%02dT%02d:%02d\n",
                date.year, date.month, date.day, date.hour, date.minute
            );
        }
        return date;
    }
    static inline bool set_saflok_mfc_card_creation_datetime(saflok_mfc_data_t * data, const saflok_mfc_datetime_t * date) {
        if (!is_saflok_mfc_datetime_valid(date)) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " creation date is invalid\n");
            return false;
        }
        bool result =
            _set_saflok_mfc_card_creation_year_impl(data, date->year) &&
            _set_saflok_mfc_card_creation_month_impl(data, date->month) &&
            _set_saflok_mfc_card_creation_day_impl(data, date->day) &&
            _set_saflok_mfc_card_creation_hour_impl(data, date->hour) &&
            _set_saflok_mfc_card_creation_minute_impl(data, date->minute);
        if (!result) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " failed to set creation date of %04d-%02d-%02dT%02d:%02d\n",
                date->year, date->month, date->day, date->hour, date->minute
            );
        }
        return result;
    }
#endif // getters and setters for creation date components
#if 1 // helpers for get/set_saflok_mfc_expiration_date()
    static inline uint8_t _get_saflok_mfc_interval_years_impl(const saflok_mfc_data_t *data) {
        // supports up to 15 year intervals(!)
        return (data->raw[8] >> 4);
    }
    static inline bool _set_saflok_mfc_interval_years_impl(saflok_mfc_data_t *data, uint32_t years) {
        if (years > 0xFu) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " interval years out of range (%u)\n", years);
            return false;
        }
        data->raw[8] = (data->raw[8] & 0x0Fu) | ((years & 0xFFu) << 4);
        return true;
    }
    static inline uint8_t _get_saflok_mfc_interval_months_impl(const saflok_mfc_data_t *data) {
        uint8_t months = data->raw[8] & 0x0Fu;
        if (months >= 12u) {
            PrintAndLogEx(WARNING, "Warning: interval months appears invalid (%u)\n", months);
        }
        return months;
    }
    static inline bool _set_saflok_mfc_interval_months_impl(saflok_mfc_data_t *data, uint8_t months) {
        if (months >= 12u) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " interval months out of range (%u)\n", months);
            return false;
        }
        data->raw[8] = (data->raw[8] & 0xF0u) | (months & 0x0Fu);
        return true;
    }
    static inline uint8_t _get_saflok_mfc_interval_days_impl(const saflok_mfc_data_t *data) {
        uint8_t days = (data->raw[9] >> 3) & 0x1Fu;
        if (days > 31u) {
            PrintAndLogEx(WARNING, "Warning: interval days appears invalid (%u)\n", days);
        }
        return days;
    }
    static inline bool _set_saflok_mfc_interval_days_impl(saflok_mfc_data_t *data, uint8_t days) {
        if (days > 31u) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " interval days out of range (%u)\n", days);
            return false;
        }
        data->raw[9] = (data->raw[9] & 0xC7u) | ((days & 0x1Fu) << 3);
        return true;
    }
    static inline uint8_t _get_saflok_mfc_interval_hours_impl(const saflok_mfc_data_t *data) {
        // low three bits from raw[9]
        // top two bits from raw[10]
        uint8_t hours = ((data->raw[9] & 0x07u) << 2) | (data->raw[10] >> 6);
        if (hours > 23u) {
            PrintAndLogEx(WARNING, "Warning: interval hours appears invalid (%u)\n", hours);
        }
        return hours;
    }
    static inline bool _set_saflok_mfc_interval_hours_impl(saflok_mfc_data_t *data, uint8_t hours) {
        if (hours > 23u) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " interval hours out of range (%u)\n", hours);
            return false;
        }
        // five bit value split across two bytes:
        // three MSB go into the low three bits from raw[9]
        // two LSB go into the top two bits from raw[10]
        data->raw[9] = (data->raw[9] & 0xF8u) | ((hours >> 2) & 0x07u);
        data->raw[10] = (data->raw[10] & 0x3Fu) | ((hours & 0x03u) << 6);
        return true;
    }
    static inline uint8_t _get_saflok_mfc_interval_minutes_impl(const saflok_mfc_data_t *data) {
        uint8_t minutes = (data->raw[10] & 0x3Fu);
        if (minutes > 59u) {
            PrintAndLogEx(WARNING, "Warning: interval minutes appears invalid (%u)\n", minutes);
        }
        return minutes;
    }
    static inline bool _set_saflok_mfc_interval_minutes_impl(saflok_mfc_data_t *data, uint8_t minutes) {
        if (minutes > 59u) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " interval minutes out of range (%u)\n", minutes);
            return false;
        }
        data->raw[10] = (data->raw[10] & 0xC0u) | (minutes & 0x3Fu);
        return true;
    }
#endif // getters for interval (expiration) components
#if 1 // Setting the interval date is based on the creation date.

    static inline saflok_mfc_datetime_offset_t get_saflok_mfc_interval(
        const saflok_mfc_data_t *data
        ) {
        saflok_mfc_datetime_offset_t offset = {
            .years   = _get_saflok_mfc_interval_years_impl(data),
            .months  = _get_saflok_mfc_interval_months_impl(data),
            .days    = _get_saflok_mfc_interval_days_impl(data),
            .hours   = _get_saflok_mfc_interval_hours_impl(data),
            .minutes = _get_saflok_mfc_interval_minutes_impl(data)
        };
        return offset;
    }
    static inline bool set_saflok_mfc_interval(
        saflok_mfc_data_t *data,
        saflok_mfc_datetime_offset_t offset
        ) {
        bool result =
            _set_saflok_mfc_interval_years_impl(data, offset.years) &&
            _set_saflok_mfc_interval_months_impl(data, offset.months) &&
            _set_saflok_mfc_interval_days_impl(data, offset.days) &&
            _set_saflok_mfc_interval_hours_impl(data, offset.hours) &&
            _set_saflok_mfc_interval_minutes_impl(data, offset.minutes);
        return result;
    }
    static inline saflok_mfc_datetime_t add_offset(
        const saflok_mfc_datetime_t *base,
        const saflok_mfc_datetime_offset_t offset
        ) {
        // adding dates is non-trivial.
        // luckily, there's already a standard for this...
        struct tm tm = {
            .tm_year = base->year - 1900,
            .tm_mon  = base->month - 1,
            .tm_mday = base->day,
            .tm_hour = base->hour,
            .tm_min  = base->minute,
            .tm_sec  = 30, // selecting midpoint to avoid leapseconds changing minute
            .tm_isdst = 0, // UTC has no DST
        };
        // add the offsets ... and it's OK for them to be out of range
        tm.tm_year += offset.years;
        tm.tm_mon  += offset.months;
        tm.tm_mday += offset.days;
        tm.tm_hour += offset.hours;
        tm.tm_min  += offset.minutes;
        // normalize into EPOCH ... which allows out-of-bounds values
        time_t fixed = timegm(&tm);
        // convert EPOCH back into a tm structure
        gmtime_r(&fixed, &tm);
        // and finally convert back into saflok_mfc_datetime_t
        saflok_mfc_datetime_t result = {
            .year   = tm.tm_year + 1900,
            .month  = tm.tm_mon + 1,
            .day    = tm.tm_mday,
            .hour   = tm.tm_hour,
            .minute = tm.tm_min
        };
        return result;
    }
    static inline saflok_mfc_datetime_offset_t get_datetime_offset(
        const saflok_mfc_datetime_t *start,
        const saflok_mfc_datetime_t *end
        ) {
        // convert both to `struct tm`
        struct tm tm_start = {
            .tm_year = start->year - 1900,
            .tm_mon  = start->month - 1,
            .tm_mday = start->day,
            .tm_hour = start->hour,
            .tm_min  = start->minute,
            .tm_sec  = 30, // selecting midpoint to avoid leapseconds changing minute
            .tm_isdst = 0, // UTC has no DST
        };
        struct tm tm_end = {
            .tm_year = end->year - 1900,
            .tm_mon  = end->month - 1,
            .tm_mday = end->day,
            .tm_hour = end->hour,
            .tm_min  = end->minute,
            .tm_sec  = 30, // selecting midpoint to avoid leapseconds changing minute
            .tm_isdst = 0, // UTC has no DST
        };
        // convert both to EPOCH
        time_t epoch_start = timegm(&tm_start);
        time_t epoch_end = timegm(&tm_end);
        // subtract the epoch values to get delta in seconds
        if (epoch_end < epoch_start) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " end date is before start date\n");
            saflok_mfc_datetime_offset_t zero_offset = {0};
            return zero_offset;
        }
        time_t delta = epoch_end - epoch_start;
        // convert delta seconds back into `struct tm`
        struct tm result_tm = {0};
        gmtime_r(&delta, &result_tm);
        saflok_mfc_datetime_offset_t result = {
            .years   = result_tm.tm_year,
            .months  = result_tm.tm_mon,
            .days    = result_tm.tm_mday,
            .hours   = result_tm.tm_hour,
            .minutes = result_tm.tm_min
        };
        return result;
    }

    static inline saflok_mfc_datetime_t get_saflok_mfc_card_expiration_datetime(
        const saflok_mfc_data_t *data
        ) {
        saflok_mfc_datetime_t creation_date = get_saflok_mfc_card_creation_datetime(data);
        saflok_mfc_datetime_offset_t offset = get_saflok_mfc_interval(data);
        saflok_mfc_datetime_t expiration = add_offset(&creation_date, offset);
        return expiration;
    }
    static inline bool set_saflok_mfc_card_expiration_datetime(
        saflok_mfc_data_t *data,
        const saflok_mfc_datetime_t * expiration
        ) {
        if (!is_saflok_mfc_datetime_valid(expiration)) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " expiration date is invalid\n");
            return false;
        }
        saflok_mfc_datetime_t creation_datetime = get_saflok_mfc_card_creation_datetime(data);
        saflok_mfc_datetime_offset_t offset = get_datetime_offset(&creation_datetime, expiration);
        bool result = set_saflok_mfc_interval(data, offset);
        return result;
    }
#endif // Setting the interval date is based on the creation date.

static const uint8_t c_aDecode[] = {
    234, 13, 217, 116, 78, 40, 253, 186, 123, 152,
    135, 120, 221, 141, 181, 26, 14, 48, 243, 47,
    106, 59, 172, 9, 185, 32, 110, 91, 43, 182,
    33, 170, 23, 68, 90, 84, 87, 190, 10, 82,
    103, 201, 80, 53, 245, 65, 160, 148, 96, 254,
    36, 162, 54, 239, 30, 107, 247, 156, 105, 218,
    155, 111, 173, 216, 251, 151, 98, 95, 31, 56,
    194, 215, 113, 49, 240, 19, 238, 15, 163, 167,
    28, 213, 17, 76, 69, 44, 4, 219, 166, 46,
    248, 100, 154, 184, 83, 102, 220, 122, 93, 3,
    7, 128, 55, 255, 252, 6, 188, 38, 192, 149,
    74, 241, 81, 45, 34, 24, 1, 121, 94, 118,
    29, 127, 20, 227, 158, 138, 187, 52, 191, 244,
    171, 72, 99, 85, 62, 86, 140, 209, 18, 237,
    195, 73, 142, 146, 157, 202, 177, 229, 206, 77,
    63, 250, 115, 5, 224, 75, 147, 178, 203, 8,
    225, 150, 25, 61, 131, 57, 117, 236, 214, 60,
    208, 112, 129, 22, 41, 21, 108, 199, 231, 226,
    246, 183, 232, 37, 109, 58, 230, 200, 153, 70,
    176, 133, 2, 97, 27, 139, 179, 159, 11, 42,
    168, 119, 16, 193, 136, 204, 164, 222, 67, 88,
    35, 180, 161, 165, 92, 174, 169, 126, 66, 64,
    144, 210, 233, 132, 207, 228, 235, 71, 79, 130,
    212, 197, 143, 205, 211, 134, 0, 89, 223, 242,
    12, 124, 198, 189, 249, 125, 196, 145, 39, 137,
    50, 114, 51, 101, 104, 175
};
_Static_assert(ARRAYLEN(c_aDecode) == 256, "c_aDecode must have 256 elements");

static const uint8_t c_aEncode[] = {
    236, 116, 192, 99, 86, 153, 105, 100, 159, 23,
    38, 198, 240, 1, 16, 77, 202, 82, 138, 75,
    122, 175, 173, 32, 115, 162, 15, 194, 80, 120,
    54, 68, 25, 30, 114, 210, 50, 183, 107, 248,
    5, 174, 199, 28, 85, 113, 89, 19, 17, 73,
    250, 252, 127, 43, 52, 102, 69, 165, 185, 21,
    169, 163, 134, 150, 219, 45, 218, 208, 33, 84,
    189, 227, 131, 141, 110, 155, 83, 149, 4, 228,
    42, 112, 39, 94, 35, 133, 135, 36, 209, 237,
    34, 27, 214, 98, 118, 67, 48, 193, 66, 132,
    91, 253, 95, 40, 254, 58, 20, 55, 176, 184,
    26, 61, 171, 72, 251, 152, 3, 166, 119, 201,
    11, 117, 97, 8, 241, 245, 217, 121, 101, 172,
    229, 164, 223, 191, 235, 10, 204, 249, 125, 195,
    136, 13, 142, 232, 220, 247, 143, 156, 47, 109,
    161, 65, 9, 188, 92, 60, 57, 144, 124, 197,
    46, 212, 51, 78, 206, 213, 88, 79, 200, 216,
    31, 130, 22, 62, 215, 255, 190, 146, 157, 196,
    211, 14, 29, 181, 93, 24, 7, 126, 106, 243,
    37, 128, 108, 203, 70, 140, 246, 231, 242, 177,
    187, 41, 145, 158, 205, 233, 148, 224, 170, 137,
    221, 234, 230, 81, 168, 71, 63, 2, 59, 87,
    96, 12, 207, 238, 154, 160, 179, 123, 225, 147,
    186, 178, 182, 222, 0, 226, 167, 139, 76, 53,
    74, 111, 239, 18, 129, 44, 180, 56, 90, 244,
    151, 64, 104, 6, 49, 103
};
_Static_assert(ARRAYLEN(c_aEncode) == 256, "c_aEncode must have 256 elements");

uint8_t magic_table[] = {
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xF0, 0x57, 0xB3, 0x9E, 0xE3, 0xD8,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x96, 0x9D, 0x95, 0x4A, 0xC1, 0x57,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x8F, 0x43, 0x58, 0x0D, 0x2C, 0x9D,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xFF, 0xCC, 0xE0, 0x05, 0x0C, 0x43,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x34, 0x1B, 0x15, 0xA6, 0x90, 0xCC,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x89, 0x58, 0x56, 0x12, 0xE7, 0x1B,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xBB, 0x74, 0xB0, 0x95, 0x36, 0x58,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xFB, 0x97, 0xF8, 0x4B, 0x5B, 0x74,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xC9, 0xD1, 0x88, 0x35, 0x9F, 0x92,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x8F, 0x92, 0xE9, 0x7F, 0x58, 0x97,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x16, 0x6C, 0xA2, 0xB0, 0x9F, 0xD1,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x27, 0xDD, 0x93, 0x10, 0x1C, 0x6C,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xDA, 0x3E, 0x3F, 0xD6, 0x49, 0xDD,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x58, 0xDD, 0xED, 0x07, 0x8E, 0x3E,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x5C, 0xD0, 0x05, 0xCF, 0xD9, 0x07,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x11, 0x8D, 0xD0, 0x01, 0x87, 0xD0,
};
_Static_assert(ARRAYLEN(magic_table) == 192, "magic_table must have 192 elements");

static const char *level_names[] = {
    "Guest Key",                       // Index 0
    "Connectors",                      // Index 1
    "Suite",                           // Index 2
    "Limited Use",                     // Index 3
    "Failsafe",                        // Index 4
    "Inhibit",                         // Index 5
    "Pool/Meeting Master",             // Index 6
    "Housekeeping",                    // Index 7
    "Floor Key",                       // Index 8
    "Section Key",                     // Index 9
    "Rooms Master",                    // Index 10
    "Grand Master",                    // Index 11
    "Emergency",                       // Index 12
    "Electronic Lockout",              // Index 13
    "Secondary Programming Key (SPK)", // Index 14
    "Primary Programming Key (PPK)",   // Index 15
};
_Static_assert(ARRAYLEN(level_names) == 16, "level_names must have 16 elements");


static int CmdHelp(const char *Cmd);


// unsafe without static analysis hints.
// strCard       : uint8_t[length]
// decryptedCard : uint8_t[length]
// length        : ALWAYS == 17
// safelok_mfc_data_t* for both parameters?
static void saflok_decrypt(const saflok_mfc_data_t *strCard, saflok_mfc_data_t *decryptedCard) {
    
    static const size_t length = ARRAYLEN(strCard->raw);
    for (int i = 0; i < length; i++) {
        int num = c_aDecode[strCard->raw[i]] - (i + 1);
        if (num < 0) {
            num += 256;
        }
        decryptedCard->raw[i] = num;
    }

    int b = 0;
    int b2 = 0;

    if (length == 17) { // True for saflok_mfc_data_t
        b = decryptedCard->raw[10];
        b2 = b & 1;
    }

    for (int num2 = length; num2 > 0; num2--) {
        b = decryptedCard->raw[num2 - 1];
        for (int num3 = 8; num3 > 0; num3--) {
            int num4 = num2 + num3;
            if (num4 > length) {
                num4 -= length;
            }
            int b3 = decryptedCard->raw[num4 - 1];
            int b4 = (b3 & 0x80) >> 7;
            b3 = ((b3 << 1) & 0xFF) | b2;
            b2 = (b & 0x80) >> 7;
            b = ((b << 1) & 0xFF) | b4;
            decryptedCard->raw[num4 - 1] = b3;
        }
        decryptedCard->raw[num2 - 1] = b;
    }
}


static void saflok_encrypt(const saflok_mfc_data_t *keyCard, saflok_mfc_data_t *encryptedCard) {
    static const size_t length = ARRAYLEN(keyCard->raw);
    int b = 0;
    memcpy(encryptedCard->raw, keyCard->raw, length);
    for (int i = 0; i < length; i++) {
        int b2 = encryptedCard->raw[i];
        int num2 = i;
        for (int j = 0; j < 8; j++) {
            num2 += 1;
            if (num2 >= length) {
                num2 -= length;
            }
            int b3 = encryptedCard->raw[num2];
            int b4 = b2 & 1;
            b2 = (b2 >> 1) | (b << 7);
            b = b3 & 1;
            b3 = (b3 >> 1) | (b4 << 7);
            encryptedCard->raw[num2] = b3;
        }
        encryptedCard->raw[i] = b2;
    }
    if (length == 17) {
        int b2 = encryptedCard->raw[10];
        b2 |= b;
        encryptedCard->raw[10] = b2;
    }
    for (int i = 0; i < length; i++) {
        int j = encryptedCard->raw[i] + (i + 1);
        if (j > 255) {
            j -= 256;
        }
        encryptedCard->raw[i] = c_aEncode[j];
    }
}

static uint32_t extract_bits(const saflok_mfc_data_t *data, size_t start_bit, size_t num_bits) {
    static const size_t total_available_bits = ARRAYLEN(data->raw) * 8;
    if (start_bit >= total_available_bits) {
        // Out of bounds access
        assert(!"extract_bits: Out of bounds access (start_bit)");
        return 0;
    }
    if (num_bits > 32) {
        // Exceeds maximum supported bit extraction
        assert(!"extract_bits: num_bits exceeds 32");
        return 0;
    }
    if (total_available_bits - start_bit < num_bits) {
        // Out of bounds access
        assert(!"extract_bits: Out of bounds access (num_bits)");
        return 0;
    }

    uint32_t result = 0;
    for (size_t i = 0; i < num_bits; i++) {
        size_t byte_index = (start_bit + i) / 8;
        size_t bit_index = (start_bit + i) % 8;
        if (data->raw[byte_index] & (1 << (7 - bit_index))) {
            result |= (1ULL << (num_bits - 1 - i));
        }
    }
    return result;
}

static void insert_bits(saflok_mfc_data_t *data, size_t start_bit, size_t num_bits, uint32_t value) {
    static const size_t total_available_bits = ARRAYLEN(data->raw) * 8;
    if (start_bit >= total_available_bits) {
        // Out of bounds access
        assert(!"insert_bits: Out of bounds access (start_bit)");
        return;
    }
    if (num_bits > 32) {
        // Exceeds maximum supported bit extraction
        assert(!"insert_bits: num_bits exceeds 32");
        return;
    }
    if (total_available_bits - start_bit < num_bits) {
        // Out of bounds access
        assert(!"insert_bits: Out of bounds access (num_bits)");
        return;
    }
    if ((num_bits < 32) && ((value >> num_bits) != 0)) {
        // Value exceeds the size of the specified bit field
        assert(!"insert_bits: value exceeds bit field size");
        return;
    }


    for (size_t i = 0; i < num_bits; i++) {
        size_t current_bit = start_bit + i;
        size_t byte_index = current_bit / 8;
        size_t bit_index = 7 - (current_bit % 8);

        uint32_t bit_value = (value >> (num_bits - 1 - i)) & 1U;

        data->raw[byte_index] = (data->raw[byte_index] & ~(1 << bit_index)) | (bit_value << bit_index);
    }
}

// Static analysis hint: reads all bytes of `data[len]`
// * NOT THREAD SAFE ... uses a static buffer for result,
//   so multiple calls will overwrite previous results.
//   This style of design SPAWNS BUGS.
// NOTE: apparently accepted for this legacy codebase.
static char *bytes_to_hex(const uint8_t *data, size_t len) {
    static char buf[256]; // WARNING: caller must immediately use or copy the result, and it's still not thread-safe!
    // BUGBUG: previously had no bounds checking on len!
    assert(len < (ARRAYLEN(buf)/2));
    len = (len < (ARRAYLEN(buf)/2)) ? len : (ARRAYLEN(buf)/2) - 1; // prevent buffer overflow
    for (size_t i = 0; i < len; i++) {
        sprintf(buf + (i * 2), "%02X", data[i]);
    }
    buf[len * 2] = '\0';
    return buf;
}

static uint8_t calculated_saflok_checksum(const saflok_mfc_data_t *data) {
    _Static_assert(ARRAYLEN(data->raw) == 17, "saflok_mfc_data_t raw size must be 17 bytes");
    int sum = 0;
    for (int i = 0; i < 16; i++) {
        sum += data->raw[i];
    }
    sum = 255 - (sum & 0xFF);
    return sum & 0xFF;
}

static void saflok_kdf(const saflok_mfc_uid_t *uid, saflok_mfc_key_t *key_out) {

    uint8_t magic_byte = (uid->uid[3] >> 4) + (uid->uid[2] >> 4) + (uid->uid[0] & 0x0F);
    uint8_t magickal_index = (magic_byte & 0x0F) * 12 + 11;
    uint8_t carry_sum = 0;

    saflok_mfc_key_t key = {{magic_byte, uid->uid[0], uid->uid[1], uid->uid[2], uid->uid[3], magic_byte}};

    for (int i = KEY_LENGTH - 1; i >= 0; i--, magickal_index--) {
        uint16_t keysum = key.key[i] + magic_table[magickal_index];
        key.key[i] = (keysum & 0xFF) + carry_sum;
        carry_sum = keysum >> 8;
    }

    memcpy(key_out, &key, KEY_LENGTH);
}

static void saflok_decode(const saflok_mfc_data_t *data) {

    uint32_t card_level = extract_bits(data, 0, 4);
    uint32_t card_type = extract_bits(data, 4, 4);
    uint32_t card_id = extract_bits(data, 8, 8);
    uint32_t opening_key = extract_bits(data, 16, 2);
    uint32_t lock_id = extract_bits(data, 18, 14);
    uint32_t pass_number = extract_bits(data, 32, 12);
    uint32_t sequence_and_combination = extract_bits(data, 44, 12);
    uint32_t deadbolt_override = extract_bits(data, 56, 1);
    uint32_t restricted_days = extract_bits(data, 57, 7);
    //uint32_t expire_date = extract_bits(data, 64, 24);
    //uint32_t card_creation_date = extract_bits(data, 88, 28);
    uint32_t property_id = extract_bits(data, 116, 12);
    uint32_t checksum = extract_bits(data, 128, 8);

    //date parsing, stolen from flipper code
    uint16_t interval_year = (data->raw[8] >> 4);
    uint8_t interval_month = data->raw[8] & 0x0F;
    uint8_t interval_day = (data->raw[9] >> 3) & 0x1F;
    uint8_t interval_hour = ((data->raw[9] & 0x07) << 2) | (data->raw[10] >> 6);
    uint8_t interval_minute = data->raw[10] & 0x3F;

    uint8_t creation_year_bits = (data->raw[14] & 0xF0);
    uint16_t creation_year =
        (creation_year_bits | ((data->raw[11] & 0xF0) >> 4)) + 1980;
    uint8_t creation_month = data->raw[11] & 0x0F;
    uint8_t creation_day = (data->raw[12] >> 3) & 0x1F;
    uint8_t creation_hour = ((data->raw[12] & 0x07) << 2) | (data->raw[13] >> 6);
    uint8_t creation_minute = data->raw[13] & 0x3F;

    uint16_t expire_year = creation_year + interval_year;
    uint8_t expire_month = creation_month + interval_month;
    uint8_t expire_day = creation_day + interval_day;
    uint8_t expire_hour = interval_hour;
    uint8_t expire_minute = interval_minute;

    // Handle month rollover
    while (expire_month > 12) {
        expire_month -= 12;
        expire_year++;
    }

    // Handle day rollover
    while (true) {
        uint8_t max_days = days_in_month_lookup[expire_month];
        // Adjust for leap years
        if (expire_month == 2 &&
                (expire_year % 4 == 0 && (expire_year % 100 != 0 || expire_year % 400 == 0))) {
            max_days = 29;
        }
        if (expire_day <= max_days) {
            break;
        }
        expire_day -= max_days;
        expire_month++;
        if (expire_month > 12) {
            expire_month = 1;
            expire_year++;
        }
    }

    PrintAndLogEx(SUCCESS, "Card Level: " _GREEN_("%u (%s)"), card_level, level_names[card_level]);
    PrintAndLogEx(SUCCESS, "Card Type: " _GREEN_("%u"), card_type);
    PrintAndLogEx(SUCCESS, "Card ID: " _GREEN_("%u"), card_id);
    PrintAndLogEx(SUCCESS, "Opening Key: " _GREEN_("%u"), opening_key);
    PrintAndLogEx(SUCCESS, "Lock ID: " _GREEN_("%u"), lock_id);
    PrintAndLogEx(SUCCESS, "Pass Number: " _GREEN_("%u"), pass_number);
    PrintAndLogEx(SUCCESS, "Sequence and Combination: " _GREEN_("%u"), sequence_and_combination);
    PrintAndLogEx(SUCCESS, "Deadbolt Override: " _GREEN_("%u"), deadbolt_override);
    PrintAndLogEx(SUCCESS, "Restricted Days: " _GREEN_("%u"), restricted_days);
    PrintAndLogEx(SUCCESS, "Card Creation Date: " _GREEN_("%u-%02d-%02d %02d:%02d"),
                  creation_year,
                  creation_month,
                  creation_day,
                  creation_hour,
                  creation_minute);
    PrintAndLogEx(SUCCESS, "Expire Date: " _GREEN_("%u-%02d-%02d %02d:%02d"),
                  expire_year,
                  expire_month,
                  expire_day,
                  expire_hour,
                  expire_minute);
    PrintAndLogEx(SUCCESS, "Property ID: " _GREEN_("%u"), property_id);
    PrintAndLogEx(SUCCESS, "Checksum: " _GREEN_("0x%X") " (%s)", checksum, (checksum == calculated_saflok_checksum(data)) ? _GREEN_("ok") : _RED_("bad"));
    PrintAndLogEx(NORMAL, "");

}

static void saflok_encode(
    saflok_mfc_data_t *data,
    uint32_t card_level,
    uint32_t card_type,
    uint32_t card_id,
    uint32_t opening_key,
    uint32_t lock_id,
    uint32_t pass_number,
    uint32_t sequence_and_combination,
    uint32_t deadbolt_override,
    uint32_t restricted_days,
    uint32_t expire_date,
    uint32_t card_creation_date,
    uint32_t property_id,
    char *dt_expiration,
    char *dt
    ) {
    insert_bits(data, 0, 4, card_level);
    insert_bits(data, 4, 4, card_type);
    insert_bits(data, 8, 8, card_id);
    insert_bits(data, 16, 2, opening_key);
    insert_bits(data, 18, 14, lock_id);
    insert_bits(data, 32, 12, pass_number);
    insert_bits(data, 44, 12, sequence_and_combination);
    insert_bits(data, 56, 1, deadbolt_override);
    insert_bits(data, 57, 7, restricted_days);
    insert_bits(data, 64, 24, expire_date);
    insert_bits(data, 88, 28, card_creation_date);
    insert_bits(data, 116, 12, property_id);


    // Parsing date time string from "YYYY-MM-DDTHH:mm" into `saflok_mfc_datetime_t`
    static const char * fmt = "%4" SCNu16 "-%2" SCNu8 "-%2" SCNu8 "T%2" SCNu8 ":%2" SCNu8;

    saflok_mfc_datetime_t creation_dt = {0};
    if (sscanf(dt, fmt, &creation_dt.year, &creation_dt.month, &creation_dt.day, &creation_dt.hour, &creation_dt.minute) == 5) {
        // return value ignored ... function here is void(!)
        set_saflok_mfc_card_creation_datetime(data, &creation_dt);
    }
    //else{
    //insert_bits(data, 88, 28,card_creation_date);
    //PrintAndLogEx(SUCCESS, "DT BITS INSERTED");
    //}

    saflok_mfc_datetime_t expiration_dt = {0};
    if (sscanf(dt_expiration, fmt, &expiration_dt.year, &expiration_dt.month, &expiration_dt.day, &expiration_dt.hour, &expiration_dt.minute) == 5) {
        // return value ignored ... function here is void(!)
        set_saflok_mfc_card_expiration_datetime(data, &expiration_dt);
    }
    //else{
    //insert_bits(data, 64, 24, expire_date);
    //PrintAndLogEx(SUCCESS, "DTE BITS INSERTED");
    //}

    uint8_t checksum = calculated_saflok_checksum(data);
    insert_bits(data, 128, 8, checksum);

}

// TODO: make clearer how many bytes secdata must minimally point to,
//       perhaps by creating a struct to avoid having to pass a length parameter.
static int saflok_read_sector(int sector, uint8_t *secdata) {
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select failed");
        DropField();
        return PM3_ERFTRANS;
    }

    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    uint8_t key[6];
    uint64_t tmpkey = 0;
    mfc_algo_saflok_one(card.uid, sector, MF_KEY_A, &tmpkey);
    num_to_bytes(tmpkey, MIFARE_KEY_SIZE, key);

    return mf_read_sector(sector, MF_KEY_A, key, secdata);
}


static int CmdHFSaflokRead(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok read",
                  "Read Saflok card (MIFARE Classic only)",
                  "hf saflok read");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    uint8_t secdata[64];
    int res = saflok_read_sector(1, secdata);

    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Valid Saflok card found!");
    } else {
        PrintAndLogEx(FAILED, "Not a valid Saflok card");
        return PM3_EFAILED;
    }

    saflok_read_sector(0, secdata); // 64 bytes

    const saflok_mfc_data_t * encrypted = (const saflok_mfc_data_t *)(secdata + 16);
    saflok_mfc_data_t decrypted = {0};
    saflok_decrypt(encrypted, &decrypted);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Card Information"));
    PrintAndLogEx(SUCCESS, "Encrypted Data: " _GREEN_("%s"), bytes_to_hex(encrypted->raw, sizeof(saflok_mfc_data_t)));

    saflok_decode(&decrypted);

    return PM3_SUCCESS;
}


static int CmdHFSaflokEncode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok encode",
                  "Encode Saflok data",
                  "hf saflok encode");

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "level", "<decimal>", "Card Level"),
        arg_u64_1(NULL, "type", "<decimal>", "Card Type"),
        arg_u64_1(NULL, "id", "<decimal>", "Card ID"),
        arg_u64_1(NULL, "open", "<decimal>", "Opening Bits"),
        arg_u64_1(NULL, "lock_id", "<decimal>", "Lock ID"),
        arg_u64_1(NULL, "pass_num", "<decimal>", "Pass Number"),
        arg_u64_1(NULL, "seq_combo", "<decimal>", "Sequence and Combination"),
        arg_u64_1(NULL, "deadbolt", "<decimal>", "Deadbolt Override"),
        arg_u64_1(NULL, "days", "<decimal>", "Restricted Days"),
        arg_str1(NULL, "expire", "<YYYY-MM-DDTHH:mm>", "Expire Date Offset"),
        arg_str1(NULL, "created", "<YYYY-MM-DDTHH:mm>", "Card Creation Date"),
        arg_u64_1(NULL, "prop_id", "<decimal>", "Property ID"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);


    saflok_mfc_data_t decrypted = {0};
    saflok_mfc_data_t encrypted = {0};

    int slen = 0;
    char dt[100];
    CLIParamStrToBuf(arg_get_str(ctx, 11), (uint8_t *)dt, 100, &slen);

    char dt_e[100];
    CLIParamStrToBuf(arg_get_str(ctx, 10), (uint8_t *)dt_e, 100, &slen);


    saflok_encode(&decrypted,
                  arg_get_u32_def(ctx, 1, 0),
                  arg_get_u32_def(ctx, 2, 0),
                  arg_get_u32_def(ctx, 3, 0),
                  arg_get_u32_def(ctx, 4, 0),
                  arg_get_u32_def(ctx, 5, 0),
                  arg_get_u32_def(ctx, 6, 0),
                  arg_get_u32_def(ctx, 7, 0),
                  arg_get_u32_def(ctx, 8, 0),
                  arg_get_u32_def(ctx, 9, 0),
                  0,
                  0,
                  arg_get_u32_def(ctx, 12, 0),
                  dt_e,
                  dt);

    saflok_encrypt(&decrypted, &encrypted);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Encoded Card Data"));
    PrintAndLogEx(SUCCESS, "Encrypted Data: " _GREEN_("%s"), bytes_to_hex(encrypted.raw, 17));


    CLIParserFree(ctx);
    return PM3_SUCCESS;
}

static int CmdHFSaflokDecode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok decode",
                  "Decode saflok data",
                  "hf saflok decode");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", NULL, "data", "Encrypted 17 byte card data"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    saflok_mfc_data_t encrypted;
    saflok_mfc_data_t decrypted;
    int dlen;
    CLIGetHexWithReturn(ctx, 1, encrypted.raw, &dlen);
    CLIParserFree(ctx);


    if (dlen != 17) {
        PrintAndLogEx(WARNING, "saflok data must include 17 HEX bytes. Got %i", dlen);
        return PM3_EINVARG;
    }

    saflok_decrypt(&encrypted, &decrypted);
    saflok_decode(&decrypted);

    return PM3_SUCCESS;
}



static int CmdHFSaflokModify(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok modify",
                  "Modify Saflok card data",
                  "hf saflok modify");

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "level", "<decimal>", "Card Level"),
        arg_u64_0(NULL, "type", "<decimal>", "Card Type"),
        arg_u64_0(NULL, "id", "<decimal>", "Card ID"),
        arg_u64_0(NULL, "open", "<decimal>", "Opening Bits"),
        arg_u64_0(NULL, "lock_id", "<decimal>", "Lock ID"),
        arg_u64_0(NULL, "pass_num", "<decimal>", "Pass Number"),
        arg_u64_0(NULL, "seq_combo", "<decimal>", "Sequence and Combination"),
        arg_u64_0(NULL, "deadbolt", "<decimal>", "Deadbolt Override"),
        arg_u64_0(NULL, "days", "<decimal>", "Restricted Days"),
        arg_str0(NULL, "expire", "<YYYY-MM-DDTHH:mm>", "Expire Date Offset"),
        arg_str0(NULL, "created", "<YYYY-MM-DDTHH:mm>", "Card Creation Date"),
        arg_u64_0(NULL, "prop_id", "<decimal>", "Property ID"),
        arg_str1("d", NULL, "data", "Encrypted 17 byte card data"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);


    saflok_mfc_data_t encrypted;
    saflok_mfc_data_t decrypted;
    saflok_mfc_data_t reencrypted = {0};

    int dlen;
    CLIGetHexWithReturn(ctx, 13, encrypted.raw, &dlen);

    if (dlen != 17) {
        PrintAndLogEx(WARNING, "block data must include 17 HEX bytes. Got %i", dlen);
        return PM3_EINVARG;
    }

    saflok_decrypt(&encrypted, &decrypted);

    uint32_t card_level = extract_bits(&decrypted, 0, 4);
    card_level = arg_get_u32_def(ctx, 1, card_level);

    uint32_t card_type = extract_bits(&decrypted, 4, 4);
    card_type = arg_get_u32_def(ctx, 2, card_type);

    uint32_t card_id = extract_bits(&decrypted, 8, 8);
    card_id = arg_get_u32_def(ctx, 3, card_id);

    uint32_t opening_key = extract_bits(&decrypted, 16, 2);
    opening_key = arg_get_u32_def(ctx, 4, opening_key);

    uint32_t lock_id = extract_bits(&decrypted, 18, 14);
    lock_id = arg_get_u32_def(ctx, 5, lock_id);

    uint32_t pass_number = extract_bits(&decrypted, 32, 12);
    pass_number = arg_get_u32_def(ctx, 6, pass_number);

    uint32_t sequence_and_combination = extract_bits(&decrypted, 44, 12);
    sequence_and_combination = arg_get_u32_def(ctx, 7, sequence_and_combination);

    uint32_t deadbolt_override = extract_bits(&decrypted, 56, 1);
    deadbolt_override = arg_get_u32_def(ctx, 8, deadbolt_override);

    uint32_t restricted_days = extract_bits(&decrypted, 57, 7);
    restricted_days = arg_get_u32_def(ctx, 9, restricted_days);

    uint32_t expire_date = extract_bits(&decrypted, 64, 24);
    //expire_date = arg_get_u32_def(ctx, 10, expire_date);

    uint32_t card_creation_date = extract_bits(&decrypted, 88, 28);
    //card_creation_date = arg_get_u32_def(ctx, 11, card_creation_date);

    uint32_t property_id = extract_bits(&decrypted, 116, 12);
    property_id = arg_get_u32_def(ctx, 12, property_id);

    int slen = 0;
    char dt[100];
    CLIParamStrToBuf(arg_get_str(ctx, 11), (uint8_t *)dt, 100, &slen);

    int slen2 = 0;
    char dt_e[100];
    CLIParamStrToBuf(arg_get_str(ctx, 10), (uint8_t *)dt_e, 100, &slen2);

    saflok_encode(&decrypted,
                  card_level,
                  card_type,
                  card_id,
                  opening_key,
                  lock_id,
                  pass_number,
                  sequence_and_combination,
                  deadbolt_override,
                  restricted_days,
                  expire_date,
                  card_creation_date,
                  property_id,
                  dt_e,
                  dt);


    saflok_encrypt(&decrypted, &reencrypted);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Modified Card Data"));
    PrintAndLogEx(SUCCESS, "Encrypted Data: " _GREEN_("%s"), bytes_to_hex(reencrypted.raw, 17));


    CLIParserFree(ctx);
    return PM3_SUCCESS;
}


static int CmdHFSaflokEncrypt(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok encrypt",
                  "Encrypt a 17-byte Saflok block",
                  "hf saflok encrypt -d <17 byte hex>");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", NULL, "data", "17-byte unencrypted hex block"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    saflok_mfc_data_t raw = {0};
    saflok_mfc_data_t encrypted = {0};
    int len;
    CLIGetHexWithReturn(ctx, 1, raw.raw, &len);

    if (len != 17) {
        PrintAndLogEx(WARNING, "Expected 17 bytes. Got %d.", len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    saflok_encrypt(&raw, &encrypted);
    PrintAndLogEx(SUCCESS, "Encrypted: " _GREEN_("%s"), bytes_to_hex(encrypted.raw, 17));

    CLIParserFree(ctx);
    return PM3_SUCCESS;
}

static int CmdHFSaflokDecrypt(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok decrypt",
                  "Decrypt a 17-byte Saflok block",
                  "hf saflok decrypt -d <17 byte hex>");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", NULL, "data", "17-byte encrypted hex block"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    saflok_mfc_data_t encrypted = {0};
    saflok_mfc_data_t decrypted = {0};
    int len;
    CLIGetHexWithReturn(ctx, 1, encrypted.raw, &len);

    if (len != 17) {
        PrintAndLogEx(WARNING, "Expected 17 bytes. Got %d.", len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    saflok_decrypt(&encrypted, &decrypted);
    PrintAndLogEx(SUCCESS, "Decrypted: " _GREEN_("%s"), bytes_to_hex(decrypted.raw, 17));

    CLIParserFree(ctx);
    return PM3_SUCCESS;
}

static int CmdHFSaflokSelfTest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok selftest",
                  "Validate internal functionality of Saflok routines",
                  "hf saflok selftest");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    int result = PM3_SUCCESS;

    PrintAndLogEx(WARNING, "NYI: Saflok self-test not yet implemented.");



    return result;
}


static int CmdHFSaflokChecksum(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok cksum",
                  "Generate Saflok checksum and append to block",
                  "hf saflok cksum -d <16 byte hex>");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", NULL, "data", "16-byte decrypted Saflok block"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    saflok_mfc_data_t data = {0};
    int len;
    CLIGetHexWithReturn(ctx, 1, data.raw, &len);

    if (len != 16) {
        PrintAndLogEx(WARNING, "Expected 16 bytes. Got %d.", len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    data.raw[16] = calculated_saflok_checksum(&data);

    PrintAndLogEx(SUCCESS, "Block + checksum: " _GREEN_("%s"), bytes_to_hex(data.raw, 17));
    PrintAndLogEx(SUCCESS, "Checksum byte: " _GREEN_("0x%02X"), data.raw[16]);

    CLIParserFree(ctx);
    return PM3_SUCCESS;
}

static int CmdHFSaflokProvision(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok provision",
                  "Provision a Saflok card",
                  "hf saflok provision -d <17-byte encrypted hex block>");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", NULL, "data", "17-byte block"),
        arg_param_end,
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    saflok_mfc_data_t data = {0};
    int len;
    CLIGetHexWithReturn(ctx, 1, data.raw, &len);

    if (len != 17) {
        PrintAndLogEx(WARNING, "Expected 17 bytes, got %d", len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    // buffer size for UID is eight bytes ... even though saflok only uses first four bytes
    uint8_t uid[8];
    int uid_len;
    if (mf_read_uid(uid, &uid_len, NULL) != PM3_SUCCESS || uid_len < 4) {
        PrintAndLogEx(WARNING, "Failed to read UID from card.");
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    _Static_assert(ARRAYLEN(uid) >= sizeof(saflok_mfc_uid_t), "UID array too small");
    const saflok_mfc_uid_t * saflok_uid = (const saflok_mfc_uid_t *)uid;
    saflok_mfc_key_t keyA = {0};
    
    saflok_kdf(saflok_uid, &keyA);
    PrintAndLogEx(INFO, "Generated UID-derived key: " _GREEN_("%s"), bytes_to_hex(keyA.key, ARRAYLEN(keyA.key)));

    uint8_t all_F[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t block1[16];
    uint8_t block2[16] = {0};
    memcpy(block1, data.raw, 16);
    block2[0] = data.raw[16];
    block2[1] = 0x00;
    block2[2] = 0x04;
    block2[3] = 0x00;
    block2[4] = 0x01;

    bool write_success = mf_write_block(1, 0, keyA.key, block1) == PM3_SUCCESS &&
                         mf_write_block(2, 0, keyA.key, block2) == PM3_SUCCESS;

    uint8_t trailer0[16] = {0};
    uint8_t set_keys = 0;
    if (!write_success) {
        PrintAndLogEx(WARNING, "Initial write failed. Attempting to set sector 0 keys...");

        _Static_assert(sizeof(saflok_mfc_key_t) == 6u, "saflok_mfc_key_t size changed?");
        memcpy(trailer0, &keyA, sizeof(saflok_mfc_key_t));
        trailer0[6] = 0xFF;
        trailer0[7] = 0x07;
        trailer0[8] = 0x80;
        trailer0[9] = 0x69;
        memset(trailer0 + 10, 0xFF, sizeof(saflok_mfc_key_t));

        if (mf_write_block(3, 1, all_F, trailer0) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Failed to set key in sector 0. Try wiping the card first.");
            CLIParserFree(ctx);
            return PM3_ESOFT;
        }

        write_success = mf_write_block(1, 0, keyA.key, block1) == PM3_SUCCESS &&
                        mf_write_block(2, 0, keyA.key, block2) == PM3_SUCCESS;
        if (!write_success) {
            PrintAndLogEx(WARNING, "Write still failed after setting keys.");
            CLIParserFree(ctx);
            return PM3_ESOFT;
        }
        set_keys = 1;
    }

    if (set_keys) {
        uint8_t trailer7[16] = {
            0x2A, 0x2C, 0x13, 0xCC, 0x24, 0x2A,
            0xFF, 0x07, 0x80, 0x69,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
        if (mf_write_block(7, 0, all_F, trailer7) != PM3_SUCCESS) {
            //PrintAndLogEx(WARNING, "Failed to write trailer block 7.");
        }

        for (int block = 19; block <= 63; block += 4) {
            if (mf_write_block(block, 0, all_F, trailer0) != PM3_SUCCESS) {
                //PrintAndLogEx(WARNING, "Failed to write trailer at block %d", block);
            }
        }
    }
    PrintAndLogEx(SUCCESS, "Saflok card provisioned successfully.");
    CLIParserFree(ctx);
    return PM3_SUCCESS;
}

static int CmdHFSaflokInterrogate(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok interrogate",
                  "Interrogate Saflok card",
                  "hf saflok interrogate");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end,
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    uint8_t uid[8];
    int uid_len;

    if (mf_read_uid(uid, &uid_len, NULL) != PM3_SUCCESS || uid_len < 4) {
        PrintAndLogEx(WARNING, "Failed to read UID.");
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    _Static_assert(ARRAYLEN(uid) >= sizeof(saflok_mfc_uid_t), "UID array too small");
    const saflok_mfc_uid_t * saflok_uid = (const saflok_mfc_uid_t *)uid;

    saflok_mfc_key_t key;
    saflok_kdf(saflok_uid, &key);

    uint8_t block2[16];
    if (mf_read_block(2, 0, key.key, block2) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed to read block 2 with derived key.");
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    uint8_t control_byte = block2[5];
    uint8_t subblock_stop = (control_byte >> 3);
    if (subblock_stop == 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t buffer[512] = {0};
    int current_block = 16;
    int total_bytes = 0;

    while (1) {
        int current_subblocks = (current_block - 16) * 2;
        if (current_subblocks >= subblock_stop) break;

        if (current_block % 4 == 3) {
            current_block++;
            continue;
        }

        if (mf_read_block(current_block, 0, key.key, buffer + total_bytes) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Failed to read block %d", current_block);
            break;
        }

        total_bytes += 16;
        current_block++;

    }

    if (subblock_stop % 2 != 0) {
        total_bytes -= 8;
    }

    if (total_bytes > 0) {
        PrintAndLogEx(SUCCESS, "Card has variable keys to the following locks:");
    } else {
        PrintAndLogEx(SUCCESS, "Card has no variable keys");
    }
    int cursor = 0;

    while (cursor + 6 <= total_bytes) {
        uint8_t val = buffer[cursor + 1];
        if (val != 0) {
            PrintAndLogEx(SUCCESS, "%u", val);
        }
        cursor += 6;
    }

    CLIParserFree(ctx);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable, "This help"},
    {"read",  CmdHFSaflokRead,  IfPm3NfcBarcode, "Read Saflok card"},
    {"provision",  CmdHFSaflokProvision,  IfPm3NfcBarcode, "Provision Saflok card"},
    {"encode",  CmdHFSaflokEncode,  AlwaysAvailable, "Encode Saflok card data"},
    {"decode",  CmdHFSaflokDecode,  AlwaysAvailable, "Decode Saflok card data"},
    {"modify",  CmdHFSaflokModify,  AlwaysAvailable, "Modify Saflok card data"},
    {"encrypt", CmdHFSaflokEncrypt, AlwaysAvailable, "Encrypt 17-byte decrypted block"},
    {"decrypt", CmdHFSaflokDecrypt, AlwaysAvailable, "Decrypt 17-byte encrypted block"},
    {"interrogate", CmdHFSaflokInterrogate, IfPm3NfcBarcode, "Interrogate saflok card"},
    {"cksum",   CmdHFSaflokChecksum, IfPm3NfcBarcode, "Generate checksum for data block"},
    {"selftest", CmdHFSaflokSelfTest, AlwaysAvailable, "Run self-test"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFSaflok(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

