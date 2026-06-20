#include "hrtparser/hrtparser.h"
#include "iso7816/iso7816core.h"
#include "mifare/desfirecore.h"
#include "mifare/desfirecrypto.h"
#include "parsehrt.h"
#include "pm3_cmd.h"
#include "ui.h"

#define HRT_NEW_AID             0xEF2014
#define HRT_OLD_AID             0xEF2011
#define HRT_APPLICATION_INFO_FILE_ID    0x08
#define HRT_APPLICATION_INFO_LEN        11

static bool hrt_aid_list_contains(const uint8_t *aidbuf, size_t aidbuflen) {
    if (aidbuf == NULL || aidbuflen < 3) return false;

    for (size_t i = 0; i + 2 < aidbuflen; i += 3) {
        // TODO: Also add HRT_OLD_AID check. Currently it is not
        // checked since parsing the older cards is not yet implemented.
        if (DesfireAIDByteToUint(&aidbuf[i]) == HRT_NEW_AID) {
            return true;
        }
    }

    return false;
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

bool is_valid_hrt_card(DesfireContext_t *dctx, const uint8_t *aidbuf, size_t aidbuflen) {
    if (dctx == NULL) return false;

    if (hrt_aid_list_contains(aidbuf, aidbuflen) == false) {
        return false;
    }

    DesfireSetCommMode(dctx, DCMPlain);
    DesfireSetCommandSet(dctx, DCCNative);

    // TODO: Add support for older travelcard (AID EF2011)

    if (DesfireSelectAIDHex(dctx, HRT_NEW_AID, false, 0) != PM3_SUCCESS) {
        return false;
    }

    hrt_travel_card_t card;
    hrt_travelcard_init_empty(&card, 2);

    bool is_valid = hrt_read_and_parse_application_info(dctx, &card);

    hrt_travelcard_free(&card);
    return is_valid;
}

bool hrt_parser_parse(DesfireContext_t *dctx) {
    if (dctx == NULL) return false;

    DesfireSetCommMode(dctx, DCMPlain);
    DesfireSetCommandSet(dctx, DCCNative);

    // TODO: Add support for older travelcard (AID EF2011)

    if (DesfireSelectAIDHex(dctx, HRT_NEW_AID, false, 0) == PM3_SUCCESS) {
        uint8_t buf[APDU_RES_LEN] = {0};
        size_t len = 0;

        hrt_travel_card_t card;
        hrt_travelcard_init_empty(&card, 2);

        // File 0x08: Application info (11 bytes)
        // Check that application info parses before reading other files
        if (hrt_read_and_parse_application_info(dctx, &card) == false) {
            hrt_travelcard_free(&card);
            return false;
        }
        PrintAndLogEx(SUCCESS, "HRT travel card detected (AID %06X)", HRT_NEW_AID);

        // File 0x00: Control info (10 bytes)
        len = 0;
        if (DesfireReadFile(dctx, 0x00, 0, 10, buf, &len) == PM3_SUCCESS) {
            hrt_travelcard_set_control_info(&card, buf, len);
        }

        // File 0x01: Period pass (35 bytes)
        len = 0;
        if (DesfireReadFile(dctx, 0x01, 0, 35, buf, &len) == PM3_SUCCESS) {
            hrt_travelcard_set_period_pass(&card, buf, len);
        }

        // File 0x02: Stored value (13 bytes)
        len = 0;
        if (DesfireReadFile(dctx, 0x02, 0, 13, buf, &len) == PM3_SUCCESS) {
            hrt_travelcard_set_stored_value(&card, buf, len);

            // Demo: Read card stored value
            int stored_value = hrt_travelcard_get_stored_value_counter(&card);
            char price_buf[32] = {0};
            hrt_price_to_string(stored_value, price_buf, sizeof(price_buf));
            PrintAndLogEx(SUCCESS, "HRT stored value: %s", price_buf);
        }

        // File 0x03: eTicket (45 bytes)
        len = 0;
        if (DesfireReadFile(dctx, 0x03, 0, 45, buf, &len) == PM3_SUCCESS) {
            hrt_travelcard_set_eticket(&card, buf, len);
        }

        // File 0x04: History records (all)
        len = 0;
        if (DesfireReadRecords(dctx, 0x04, 0, 0, buf, &len) == PM3_SUCCESS) {
            hrt_travelcard_set_history(&card, buf, len);
        }

        hrt_travelcard_free(&card);
        return true;
    }

    return false;
}
