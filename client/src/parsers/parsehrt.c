#include "commonutil.h"
#include "hrtparser/hrtparser.h"
#include "iso7816/iso7816core.h"
#include "mifare/desfirecore.h"
#include "mifare/desfirecrypto.h"
#include "parsehrt.h"
#include "pm3_cmd.h"
#include "ui.h"
#include <stdio.h>
#include <string.h>

#define HRT_NEW_AID                   0xEF2014
#define HRT_OLD_AID                   0xEF2011
#define HRT_CONTROL_INFO_FILE_ID      0x00
#define HRT_PERIOD_PASS_FILE_ID       0x01
#define HRT_STORED_VALUE_FILE_ID      0x02
#define HRT_ETICKET_FILE_ID           0x03
#define HRT_HISTORY_FILE_ID           0x04
#define HRT_APPLICATION_INFO_FILE_ID  0x08
#define HRT_APPLICATION_INFO_LEN      11
#define HRT_CONTROL_INFO_LEN          6
#define HRT_CONTROL_INFO_V2_LEN       10
#define HRT_PERIOD_PASS_LEN           32
#define HRT_PERIOD_PASS_V2_LEN        35
#define HRT_STORED_VALUE_LEN          12
#define HRT_STORED_VALUE_V2_LEN       13
#define HRT_ETICKET_LEN               26
#define HRT_ETICKET_V2_LEN            45

typedef struct {
    uint32_t aid;
    int version;
} hrt_application_t;

typedef enum {
    HRT_AREA_TYPE_CITY = 0,
    HRT_AREA_TYPE_VEHICLE = 1,
    HRT_AREA_TYPE_ZONE_RANGE = 2,
} hrt_area_type_t;

typedef struct {
    int code;
    const char *name;
    const char *arc_zone;
} hrt_area_mapping_t;

static const hrt_area_mapping_t hrt_city_areas[] = {
    {0, "Not defined", NULL},
    {1, "Helsinki", "AB"},
    {2, "Espoo", "BC"},
    {4, "Vantaa", "BC"},
    {5, "Region", "ABC"},
    {6, "Kirkkonummi-Siuntio", "D"},
    {7, "Vihti", NULL},
    {8, "Nurmijarvi", NULL},
    {9, "Kerava-Sipoo-Tuusula", "D"},
    {10, "Sipoo", NULL},
    {14, "Region zone 2", "BCD"},
    {15, "Region zone 3", "ABCD"},
};

static const hrt_area_mapping_t hrt_vehicle_areas[] = {
    {0, "Not defined", NULL},
    {1, "Bus", NULL},
    {5, "Tram", NULL},
    {6, "Metro", NULL},
    {7, "Train", NULL},
    {8, "Ferry", NULL},
    {9, "U line", NULL},
};

static const char *hrt_lookup_product_name(int product_code) {
    if (product_code < 800) return "Not defined";
    return NULL;
}

static const hrt_area_mapping_t *hrt_lookup_area_mapping(const hrt_area_mapping_t *mappings, size_t mappings_len, int area) {
    for (size_t i = 0; i < mappings_len; i++) {
        if (mappings[i].code == area) {
            return &mappings[i];
        }
    }
    return NULL;
}

static bool hrt_format_zone_range(int area, char *out, size_t out_len) {
    static const char zones[] = "ABCDEFGH";
    if (out == NULL || out_len == 0) return false;

    int end = area & 0x07;
    int start = (area >> 3) & 0x07;

    if (start > end || start >= (int)strlen(zones) || end >= (int)strlen(zones)) return false;

    size_t pos = 0;
    for (int i = start; i <= end; i++) {
        if (pos + 1 >= out_len) return false;
        out[pos++] = zones[i];
    }

    out[pos] = '\0';
    return true;
}

static bool hrt_format_area(int area_type, int area, char *out, size_t out_len) {
    if (out == NULL || out_len == 0) return false;

    const hrt_area_mapping_t *mapping = NULL;
    switch ((hrt_area_type_t)area_type) {
        case HRT_AREA_TYPE_CITY:
            mapping = hrt_lookup_area_mapping(hrt_city_areas, ARRAYLEN(hrt_city_areas), area);
            if (mapping == NULL) return false;
            if (mapping->arc_zone != NULL) {
                return snprintf(out, out_len, "%s (%s)", mapping->name, mapping->arc_zone) > 0;
            }
            return snprintf(out, out_len, "%s", mapping->name) > 0;
        case HRT_AREA_TYPE_VEHICLE:
            mapping = hrt_lookup_area_mapping(hrt_vehicle_areas, ARRAYLEN(hrt_vehicle_areas), area);
            if (mapping == NULL) return false;
            return snprintf(out, out_len, "%s", mapping->name) > 0;
        case HRT_AREA_TYPE_ZONE_RANGE:
            return hrt_format_zone_range(area, out, out_len);
        default:
            return false;
    }
}

static bool hrt_format_card_number(const char *card_number, char *out, size_t out_len) {
    if (card_number == NULL || out == NULL || out_len == 0) return false;

    // Card number is printed on the physical card in groups of 6 + 4 + 4 + 4.
    if (strlen(card_number) != 18 || out_len < 22) {
        return false;
    }

    int written = snprintf(out, out_len, "%.6s %.4s %.4s %.4s",
                           card_number, card_number  + 6,
                           card_number + 10, card_number + 14);

    return written > 0 && (size_t)written < out_len;
}

static bool hrt_get_application_from_aid_list(const uint8_t *aidbuf, size_t aidbuflen, hrt_application_t *application) {
    if (aidbuf == NULL || aidbuflen < 3) return false;

    for (size_t i = 0; i + 2 < aidbuflen; i += 3) {
        uint32_t aid = DesfireAIDByteToUint(&aidbuf[i]);

        if (aid == HRT_OLD_AID) {
            if (application != NULL) {
                application->aid = HRT_OLD_AID;
                application->version = 1;
            }
            return true;
        }

        if (aid == HRT_NEW_AID) {
            if (application != NULL) {
                application->aid = HRT_NEW_AID;
                application->version = 2;
            }
            return true;
        }
    }

    return false;
}

static size_t hrt_control_info_len(int version) {
    return version == 2 ? HRT_CONTROL_INFO_V2_LEN : HRT_CONTROL_INFO_LEN;
}

static size_t hrt_period_pass_len(int version) {
    return version == 2 ? HRT_PERIOD_PASS_V2_LEN : HRT_PERIOD_PASS_LEN;
}

static size_t hrt_stored_value_len(int version) {
    return version == 2 ? HRT_STORED_VALUE_V2_LEN : HRT_STORED_VALUE_LEN;
}

static size_t hrt_eticket_len(int version) {
    return version == 2 ? HRT_ETICKET_V2_LEN : HRT_ETICKET_LEN;
}

static bool hrt_read_and_parse_application_info(DesfireContext_t *dctx, hrt_travel_card_t *card) {
    if (dctx == NULL || card == NULL) return false;

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;

    if (DesfireReadFile(dctx, HRT_APPLICATION_INFO_FILE_ID, 0, HRT_APPLICATION_INFO_LEN, buf, &len) != PM3_SUCCESS) {
        return false;
    }

    if (hrt_travelcard_set_application_info(card, buf, len) == false) {
        return false;
    }

    const char *application_id = hrt_travelcard_get_application_instance_id(card);
    return application_id != NULL && application_id[0] != '\0';
}

static bool hrt_format_time(time_t value, char *out, size_t out_len) {
    if (value == (time_t)0 || out == NULL || out_len == 0) return false;

    char buf[32] = {0};
    struct tm tm_value = {0};

#if defined(_WIN32)
    if (localtime_s(&tm_value, &value) != 0) return false;
#else
    if (localtime_r(&value, &tm_value) == NULL) return false;
#endif

    if (strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_value) == 0) return false;
    return snprintf(out, out_len, "%s", buf) > 0;
}

static void hrt_print_time(const char *label, time_t value) {
    char buf[32] = {0};
    if (hrt_format_time(value, buf, sizeof(buf)) == false) return;

    PrintAndLogEx(SUCCESS, "%s " _GREEN_("%s"), label, buf);
}

static bool hrt_has_loaded_period_info(const hrt_travel_card_t *card) {
    if (card == NULL) return false;

    return hrt_travelcard_get_loaded_period_product(card) > 0 ||
           hrt_travelcard_get_loaded_period_length(card) > 0 ||
           hrt_travelcard_get_loaded_period_price(card) > 0 ||
           hrt_travelcard_get_period_loading_date(card) != (time_t)0 ||
           hrt_travelcard_get_period_loading_organization(card) > 0 ||
           hrt_travelcard_get_period_loading_device_number(card) > 0;
}

static void hrt_print_boarding_location(int location_type, int location_num) {
    if (location_num <= 0) return;

    if (location_type == 1) {
        PrintAndLogEx(SUCCESS, "   Boarding line.......... " _GREEN_("%d"), location_num);
    } else if (location_type == 2) {
        PrintAndLogEx(SUCCESS, "   Boarding train......... " _GREEN_("%d"), location_num);
    }
}

static bool hrt_format_value_ticket_zone(const hrt_eticket_t *ticket, char *out, size_t out_len) {
    if (ticket == NULL || out == NULL || out_len == 0) return false;

    if (hrt_eticket_get_extra_zone(ticket) == 1 && hrt_eticket_get_group_size(ticket) <= 1) {
        char ext1[32] = {0};
        char ext2[32] = {0};
        bool has_ext1 = false;
        bool has_ext2 = false;
        int ext1_area = hrt_eticket_get_ext1_validity_area(ticket);
        int ext2_area = hrt_eticket_get_ext2_validity_area(ticket);

        if (ext1_area != 56) {
            has_ext1 = hrt_format_area(HRT_AREA_TYPE_ZONE_RANGE, ext1_area, ext1, sizeof(ext1));
        }
        if (ext2_area != 56) {
            has_ext2 = hrt_format_area(HRT_AREA_TYPE_ZONE_RANGE, ext2_area, ext2, sizeof(ext2));
        }

        if (has_ext1 && has_ext2) {
            return snprintf(out, out_len, "%s+%s", ext1, ext2) > 0;
        }
        if (has_ext1) return snprintf(out, out_len, "%s", ext1) > 0;
        if (has_ext2) return snprintf(out, out_len, "%s", ext2) > 0;
    }

    return hrt_format_area(hrt_eticket_get_validity_area_type(ticket),
                           hrt_eticket_get_validity_area(ticket), out, out_len);
}

static const char *hrt_history_transaction_type_name(int transaction_type) {
    return transaction_type == 0 ? "Season ticket" : "Value ticket";
}

static void hrt_print_history(const hrt_travel_card_t *card) {
    if (card == NULL) return;

    const hrt_history_t *history = hrt_travelcard_get_history(card);
    int history_len = hrt_travelcard_get_history_len(card);
    if (history == NULL || history_len <= 0) return;

    PrintAndLogEx(SUCCESS, "");
    PrintAndLogEx(SUCCESS, "History records");

    for (int i = history_len - 1; i >= 0; i--) {
        char transaction_time[32] = {0};
        char price_buf[32] = {0};

        if (hrt_format_time(history[i].transaction_d_time, transaction_time, sizeof(transaction_time)) == false) {
            continue;
        }

        PrintAndLogEx(SUCCESS, "   %s  " _GREEN_("%s"), transaction_time,
                      hrt_history_transaction_type_name(history[i].transaction_type));

        if (history[i].transaction_type != 0 &&
            (history[i].group_size > 1 || history[i].price > 0)) {
            if (history[i].group_size > 1) {
                PrintAndLogEx(SUCCESS, "      Group size.......... " _GREEN_("%d"), history[i].group_size);
            }
            if (history[i].price > 0) {
                hrt_price_to_string(history[i].price, price_buf, sizeof(price_buf));
                PrintAndLogEx(SUCCESS, "      Price............... " _GREEN_("%s"), price_buf);
            }
        }

        hrt_print_time("      Transfer ends.......", history[i].transfer_end_date);
    }
}

static void hrt_print_card(const hrt_travel_card_t *card) {
    if (card == NULL) return;

    const char *application_id = hrt_travelcard_get_application_instance_id(card);
    char price_buf[32] = {0};
    char area_buf[64] = {0};
    int product_code = hrt_travelcard_get_product_code1(card);
    const char *product_name = hrt_lookup_product_name(product_code);
    int area_type = hrt_travelcard_get_validity_area_type1(card);
    int area = hrt_travelcard_get_validity_area1(card);
    char boarding_area_buf[64] = {0};
    const hrt_eticket_t *value_ticket = hrt_travelcard_get_value_ticket(card);

    hrt_price_to_string(
        hrt_travelcard_get_stored_value_counter(card),
        price_buf,
        sizeof(price_buf)
    );

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "--- " _CYAN_("HRT travel card"));

    if (application_id != NULL && application_id[0] != '\0') {
        char card_number[22] = {0};
        if (hrt_format_card_number(application_id, card_number, sizeof(card_number))) {
            PrintAndLogEx(SUCCESS, "Card number......... " _GREEN_("%s"), card_number);
        } else {
            PrintAndLogEx(SUCCESS, "Card number......... " _GREEN_("%s"), application_id);
        }
    }

    PrintAndLogEx(SUCCESS, "Value on the card... " _GREEN_("%s"), price_buf);

    PrintAndLogEx(SUCCESS, "");
    PrintAndLogEx(SUCCESS, "Season ticket information");

    if (product_name != NULL) {
        PrintAndLogEx(SUCCESS, "   Product code........... " _GREEN_("%d (%s)"), product_code, product_name);
    } else {
        PrintAndLogEx(SUCCESS, "   Product code........... " _GREEN_("%d (unknown)"), product_code);
    }
    if (hrt_format_area(area_type, area, area_buf, sizeof(area_buf))) {
        PrintAndLogEx(SUCCESS, "   Area................... " _GREEN_("%s"), area_buf);
    } else {
        PrintAndLogEx(SUCCESS, "   Area................... " _GREEN_("%d (type %d)"), area, area_type);
    }
    hrt_print_time("   Start date.............", hrt_travelcard_get_period_start_date1(card));
    hrt_print_time("   End date...............", hrt_travelcard_get_period_end_date1(card));
    PrintAndLogEx(SUCCESS, "   Length................. " _GREEN_("%d days"), hrt_travelcard_get_period_length1(card));
    hrt_print_time("   Boarding time..........", hrt_travelcard_get_boarding_date(card));
    hrt_print_boarding_location(hrt_travelcard_get_boarding_location_num_type(card),
                                hrt_travelcard_get_boarding_location_num(card));

    if (hrt_format_area(hrt_travelcard_get_boarding_area_type(card),
                        hrt_travelcard_get_boarding_area(card),
                        boarding_area_buf, sizeof(boarding_area_buf))) {
        PrintAndLogEx(SUCCESS, "   Boarding zone.......... " _GREEN_("%s"), boarding_area_buf);
    }

    if (hrt_has_loaded_period_info(card)) {
        PrintAndLogEx(SUCCESS, "   Organization........... " _GREEN_("%d"), hrt_travelcard_get_period_loading_organization(card));
        PrintAndLogEx(SUCCESS, "   Device number.......... " _GREEN_("%d"), hrt_travelcard_get_period_loading_device_number(card));
    }

    if (hrt_eticket_is_defined(value_ticket)) {
        char fare_buf[32] = {0};
        char value_area_buf[64] = {0};
        int value_product_code = hrt_eticket_get_product_code(value_ticket);
        const char *value_product_name = hrt_lookup_product_name(value_product_code);

        hrt_price_to_string(hrt_eticket_get_total_fare(value_ticket), fare_buf, sizeof(fare_buf));

        PrintAndLogEx(SUCCESS, "");
        PrintAndLogEx(SUCCESS, "Value ticket information");

        if (value_product_name != NULL) {
            PrintAndLogEx(SUCCESS, "   Product code........... " _GREEN_("%d (%s)"), value_product_code, value_product_name);
        } else {
            PrintAndLogEx(SUCCESS, "   Product code........... " _GREEN_("%d (unknown)"), value_product_code);
        }

        if (hrt_format_value_ticket_zone(value_ticket, value_area_buf, sizeof(value_area_buf))) {
            PrintAndLogEx(SUCCESS, "   Zone................... " _GREEN_("%s"), value_area_buf);
        } else {
            PrintAndLogEx(SUCCESS, "   Zone................... " _GREEN_("unknown"));
        }

        PrintAndLogEx(SUCCESS, "   Fare................... " _GREEN_("%s"), fare_buf);
        PrintAndLogEx(SUCCESS, "   Group size............. " _GREEN_("%d"), hrt_eticket_get_group_size(value_ticket));
        hrt_print_time("   Valid from.............", hrt_eticket_get_validity_start_date(value_ticket));
        hrt_print_time("   Valid until............", hrt_eticket_get_validity_end_date(value_ticket));
        hrt_print_time("   Boarding time..........", hrt_eticket_get_boarding_date(value_ticket));
        PrintAndLogEx(SUCCESS, "   Boarding vehicle....... " _GREEN_("%d"), hrt_eticket_get_boarding_vehicle(value_ticket));
        hrt_print_boarding_location(hrt_eticket_get_boarding_location_num_type(value_ticket),
                                    hrt_eticket_get_boarding_location_num(value_ticket));
    }

    hrt_print_history(card);
}

static bool hrt_select_application(DesfireContext_t *dctx, const hrt_application_t *application) {
    if (dctx == NULL || application == NULL) return false;

    return DesfireSelectAIDHex(dctx, application->aid, false, 0) == PM3_SUCCESS;
}

static bool hrt_read_card(DesfireContext_t *dctx, const hrt_application_t *application, hrt_travel_card_t *card) {
    if (dctx == NULL || application == NULL || card == NULL) return false;

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;

    hrt_travelcard_init_empty(card, application->version);

    // File 0x08: Application info
    if (hrt_read_and_parse_application_info(dctx, card) == false) {
        return false;
    }

    // File 0x00: Control info
    len = 0;
    if (DesfireReadFile(dctx, HRT_CONTROL_INFO_FILE_ID, 0, hrt_control_info_len(application->version), buf, &len) == PM3_SUCCESS) {
        hrt_travelcard_set_control_info(card, buf, len);
    }

    // File 0x01: Period pass
    len = 0;
    if (DesfireReadFile(dctx, HRT_PERIOD_PASS_FILE_ID, 0, hrt_period_pass_len(application->version), buf, &len) == PM3_SUCCESS) {
        hrt_travelcard_set_period_pass(card, buf, len);
    }

    // File 0x02: Stored value
    len = 0;
    if (DesfireReadFile(dctx, HRT_STORED_VALUE_FILE_ID, 0, hrt_stored_value_len(application->version), buf, &len) == PM3_SUCCESS) {
        hrt_travelcard_set_stored_value(card, buf, len);
    }

    // File 0x03: eTicket
    len = 0;
    if (DesfireReadFile(dctx, HRT_ETICKET_FILE_ID, 0, hrt_eticket_len(application->version), buf, &len) == PM3_SUCCESS) {
        hrt_travelcard_set_eticket(card, buf, len);
    }

    // File 0x04: History records
    len = 0;
    if (DesfireReadRecords(dctx, HRT_HISTORY_FILE_ID, 0, 0, buf, &len) == PM3_SUCCESS) {
        hrt_travelcard_set_history(card, buf, len);
    }

    return true;
}

bool is_valid_hrt_card(DesfireContext_t *dctx, const uint8_t *aidbuf, size_t aidbuflen) {
    if (dctx == NULL) return false;

    hrt_application_t application = {0};
    if (hrt_get_application_from_aid_list(aidbuf, aidbuflen, &application) == false) {
        return false;
    }

    DesfireSetCommMode(dctx, DCMPlain);
    DesfireSetCommandSet(dctx, DCCNative);

    if (hrt_select_application(dctx, &application) == false) {
        return false;
    }

    hrt_travel_card_t card;
    hrt_travelcard_init_empty(&card, application.version);

    bool is_valid = hrt_read_and_parse_application_info(dctx, &card);

    hrt_travelcard_free(&card);
    return is_valid;
}

bool hrt_parser_parse(DesfireContext_t *dctx) {
    if (dctx == NULL) return false;

    DesfireSetCommMode(dctx, DCMPlain);
    DesfireSetCommandSet(dctx, DCCNative);

    hrt_application_t applications[] = {
        {HRT_OLD_AID, 1},
        {HRT_NEW_AID, 2},
    };

    for (size_t i = 0; i < ARRAYLEN(applications); i++) {
        if (hrt_select_application(dctx, &applications[i]) == false) {
            continue;
        }

        hrt_travel_card_t card;
        if (hrt_read_card(dctx, &applications[i], &card) == false) {
            hrt_travelcard_free(&card);
            continue;
        }

        hrt_print_card(&card);

        hrt_travelcard_free(&card);
        return true;
    }

    return false;
}
