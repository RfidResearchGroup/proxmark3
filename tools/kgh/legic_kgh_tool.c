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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "pm3.h"
#include "pm3_cmd.h"
#include "legic.h"
#include "cmdhflegic.h"
#include "ui.h"
#include "util.h"
#include "util_posix.h"
#include "crc.h"

static pm3 *open_pm3_with_retry(const char *port) {
    for (int i = 0; i < 3; ++i) {
        pm3 *dev = pm3_open(port);
        if (g_session.pm3_present) {
            return dev;
        }
        msleep(250);
    }
    return pm3_open(port);
}

static bool has_flag(int argc, char *argv[], const char *flag) {
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], flag) == 0) {
            return true;
        }
    }
    return false;
}

static const uint8_t k_legic_template_head[35] = {
    0x3e, 0x00, 0x00, 0xb6, 0x00, 0x60, 0xea, 0x9f, 0xff, 0x00, 0x00, 0x00, 0x11, 0x01, 0x06, 0x80,
    0x00, 0x00, 0xeb, 0xa1, 0x00, 0x00, 0x0d, 0xc0, 0x08, 0x00, 0x2f, 0x73, 0x73, 0x73, 0x73, 0x62,
    0x62, 0x62, 0x54
};

static bool encode_badge_bcd(uint32_t badge, uint8_t out[3]) {
    if (badge > 999999u) {
        return false;
    }

    uint32_t digits[6] = {0};
    for (int i = 5; i >= 0; --i) {
        digits[i] = badge % 10u;
        badge /= 10u;
    }

    out[0] = (uint8_t)((digits[0] << 4) | digits[1]);
    out[1] = (uint8_t)((digits[2] << 4) | digits[3]);
    out[2] = (uint8_t)((digits[4] << 4) | digits[5]);
    return true;
}

static bool decode_badge_bcd(const uint8_t in[3], uint32_t *badge_out) {
    uint32_t digits[6] = {
        (uint32_t)(in[0] >> 4), (uint32_t)(in[0] & 0x0F),
        (uint32_t)(in[1] >> 4), (uint32_t)(in[1] & 0x0F),
        (uint32_t)(in[2] >> 4), (uint32_t)(in[2] & 0x0F)
    };

    for (size_t i = 0; i < 6; ++i) {
        if (digits[i] > 9u) {
            return false;
        }
    }

    *badge_out = digits[0] * 100000u + digits[1] * 10000u + digits[2] * 1000u + digits[3] * 100u + digits[4] * 10u + digits[5];
    return true;
}

static bool parse_badge_text(const char *text, uint32_t *badge_out) {
    if (text == NULL || *text == '\0') {
        return false;
    }

    char *end = NULL;
    unsigned long badge = strtoul(text, &end, 10);
    if (end == text || *end != '\0' || badge > 999999UL) {
        return false;
    }

    *badge_out = (uint32_t)badge;
    return true;
}

static bool parse_stamp_hex(const char *text, uint8_t stamp[4]) {
    if (text == NULL || strlen(text) != 8) {
        return false;
    }

    for (int i = 0; i < 4; ++i) {
        char byte_str[3] = { text[i * 2], text[i * 2 + 1], '\0' };
        char *end = NULL;
        long value = strtol(byte_str, &end, 16);
        if (end == byte_str || *end != '\0' || value < 0 || value > 255) {
            return false;
        }
        stamp[i] = (uint8_t)value;
    }

    return true;
}

static bool load_stamp_file(const char *path, uint8_t stamp[4]) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return false;
    }

    uint8_t buf[4] = {0};
    size_t read_len = fread(buf, 1, sizeof(buf), fp);
    int extra = fgetc(fp);
    fclose(fp);

    if (read_len != sizeof(buf) || extra != EOF) {
        return false;
    }

    memcpy(stamp, buf, sizeof(buf));
    return true;
}

static bool save_stamp_file(const char *path, const uint8_t stamp[4]) {
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        return false;
    }

    size_t written = fwrite(stamp, 1, 4, fp);
    fclose(fp);
    return written == 4;
}

static bool get_arg_value(int argc, char *argv[], const char *flag, const char **value) {
    for (int i = 3; i < argc - 1; ++i) {
        if (strcmp(argv[i], flag) == 0) {
            *value = argv[i + 1];
            return true;
        }
    }
    return false;
}

static void apply_stamp(uint8_t *dump, size_t dump_len, const uint8_t stamp[4]) {
    if (dump_len <= 30) {
        return;
    }
    memcpy(dump + 27, stamp, 4);
}

static void build_migration_dump(uint32_t badge, const uint8_t stamp[4], uint8_t *dump, size_t dump_len) {
    memset(dump, 0, dump_len);
    memcpy(dump, k_legic_template_head, sizeof(k_legic_template_head));
    apply_stamp(dump, dump_len, stamp);
    uint8_t bcd[3] = {0};
    if (!encode_badge_bcd(badge, bcd)) {
        fprintf(stderr, "badge number out of range\n");
        exit(EXIT_FAILURE);
    }

    dump[31] = bcd[0];
    dump[32] = bcd[1];
    dump[33] = bcd[2];
    dump[34] = 0xBD;
}

typedef struct {
    uint8_t *dump;
    uint16_t len;
    legic_card_select_t card;
} legic_read_result_t;

static bool read_legic_dump(legic_read_result_t *res, bool verbose) {
    memset(res, 0, sizeof(*res));

    uint8_t prev_print = g_printAndLog;
    g_printAndLog &= ~PRINTANDLOG_PRINT;

    for (int attempt = 0; attempt < 3; ++attempt) {
        free(res->dump);
        memset(res, 0, sizeof(*res));

        if (legic_get_type(&res->card) != PM3_SUCCESS) {
            if (verbose) {
                fprintf(stderr, "read_info retry %d: legic_get_type failed\n", attempt + 1);
            }
            msleep(100);
            continue;
        }

        res->dump = calloc(res->card.cardsize, sizeof(uint8_t));
        if (res->dump == NULL) {
            g_printAndLog = prev_print;
            return false;
        }

        int status = legic_read_mem(0, res->card.cardsize, 0x55, res->dump, &res->len);
        if (status != PM3_SUCCESS || res->len < 35) {
            if (verbose) {
                fprintf(stderr, "read_info retry %d: legic_read_mem failed\n", attempt + 1);
            }
            msleep(100);
            continue;
        }

        uint8_t crc = res->dump[4];
        if (CRC8Legic(res->dump, 4) != crc) {
            if (verbose) {
                fprintf(stderr, "read_info retry %d: header crc mismatch\n", attempt + 1);
            }
            msleep(100);
            continue;
        }

        for (uint16_t i = 22; i < res->len; ++i) {
            res->dump[i] ^= crc;
        }

        g_printAndLog = prev_print;
        return true;
    }

    free(res->dump);
    memset(res, 0, sizeof(*res));
    g_printAndLog = prev_print;
    return false;
}

static void free_legic_read_result(legic_read_result_t *res) {
    free(res->dump);
    res->dump = NULL;
    res->len = 0;
    memset(&res->card, 0, sizeof(res->card));
}

static bool is_kgh_card(const uint8_t *dump, uint16_t len) {
    return len >= sizeof(k_legic_template_head) &&
           dump[5] == 0x60 && dump[6] == 0xEA &&
           dump[7] == 0x9F && dump[8] == 0xFF &&
           dump[22] == 0x0D && dump[23] == 0xC0 &&
           dump[24] == 0x08 && dump[25] == 0x00;
}

static const char *classify_legic_card(const uint8_t *dump, uint16_t len) {
    if (len < 9) {
        return "unknown";
    }

    uint16_t dcf = ((uint16_t)dump[6] << 8) | dump[5];
    if (dcf == 0xFFFF) {
        return "NM";
    }

    if (dcf > 60000u) {
        return "IAM";
    }

    if (is_kgh_card(dump, len)) {
        return "KGH";
    }

    return "unknown";
}

static bool check_kgh_crc_ok(const uint8_t *dump, uint16_t len) {
    if (strcmp(classify_legic_card(dump, len), "KGH") != 0) {
        return false;
    }

    if (len <= 34) {
        return false;
    }

    uint8_t *copy = calloc(len, sizeof(uint8_t));
    if (copy == NULL) {
        return false;
    }

    memcpy(copy, dump, len);
    const uint8_t uid[4] = { copy[0], copy[1], copy[2], copy[3] };
    bool ok = legic_clone_update_segment_crcs(copy, len, uid) && legic_clone_update_kgh_crcs(copy, len, uid) && (copy[34] == dump[34]);
    free(copy);
    return ok;
}

static bool check_kgh_crc_calc(const uint8_t *dump, uint16_t len, uint8_t *crc_out) {
    if (strcmp(classify_legic_card(dump, len), "KGH") != 0) {
        return false;
    }

    if (len <= 34) {
        return false;
    }

    uint8_t *copy = calloc(len, sizeof(uint8_t));
    if (copy == NULL) {
        return false;
    }

    memcpy(copy, dump, len);
    const uint8_t uid[4] = { copy[0], copy[1], copy[2], copy[3] };
    if (!legic_clone_update_segment_crcs(copy, len, uid) || !legic_clone_update_kgh_crcs(copy, len, uid)) {
        free(copy);
        return false;
    }

    *crc_out = copy[34];
    bool ok = (*crc_out == dump[34]);
    free(copy);
    return ok;
}

static bool has_extra_segments(const uint8_t *dump, uint16_t len) {
    size_t start = 22;
    bool saw_first = false;

    while (start + 5 <= len) {
        uint16_t seg_len = (((uint16_t)dump[start + 1] & 0x0F) << 8) | dump[start];
        bool is_last = ((dump[start + 1] & 0x08) != 0);
        if (seg_len < 5 || start + seg_len > len) {
            break;
        }

        if (saw_first) {
            return true;
        }

        saw_first = true;
        if (is_last) {
            break;
        }

        start += seg_len;
    }

    return false;
}

static bool check_segment_crc_ok(const uint8_t *dump, uint16_t len) {
    if (len < 27) {
        return false;
    }

    uint8_t prev_print = g_printAndLog;
    g_printAndLog &= ~PRINTANDLOG_PRINT;

    uint8_t *copy = calloc(len, sizeof(uint8_t));
    if (copy == NULL) {
        g_printAndLog = prev_print;
        return false;
    }

    memcpy(copy, dump, len);
    const uint8_t uid[4] = { copy[0], copy[1], copy[2], copy[3] };
    bool ok = legic_clone_update_segment_crcs(copy, len, uid) && (memcmp(copy, dump, len) == 0);
    free(copy);
    g_printAndLog = prev_print;
    return ok;
}

static bool check_segment_crc_calc(const uint8_t *dump, uint16_t len, uint8_t *crc_out) {
    if (len < 27) {
        return false;
    }

    uint8_t prev_print = g_printAndLog;
    g_printAndLog &= ~PRINTANDLOG_PRINT;

    uint8_t *copy = calloc(len, sizeof(uint8_t));
    if (copy == NULL) {
        g_printAndLog = prev_print;
        return false;
    }

    memcpy(copy, dump, len);
    const uint8_t uid[4] = { copy[0], copy[1], copy[2], copy[3] };
    if (!legic_clone_update_segment_crcs(copy, len, uid)) {
        free(copy);
        g_printAndLog = prev_print;
        return false;
    }

    *crc_out = copy[26];
    bool ok = (memcmp(copy, dump, len) == 0);
    free(copy);
    g_printAndLog = prev_print;
    return ok;
}

static bool decode_badge_value(const uint8_t *dump, uint16_t len, uint32_t *badge_out) {
    if (len < 34) {
        return false;
    }
    return decode_badge_bcd(&dump[31], badge_out);
}

static bool extract_stamp(const uint8_t *dump, uint16_t len, uint8_t stamp[4]) {
    if (len <= 30) {
        return false;
    }

    memcpy(stamp, dump + 27, 4);
    return true;
}

static void print_json_string(const char *key, const char *value, bool last) {
    printf("\"%s\": \"%s\"%s", key, value, last ? "" : ",");
}

static void print_json_bool(const char *key, bool value, bool last) {
    printf("\"%s\": %s%s", key, value ? "true" : "false", last ? "" : ",");
}

static void print_json_uint32(const char *key, uint32_t value, bool last) {
    printf("\"%s\": %u%s", key, value, last ? "" : ",");
}

static void print_json_null(const char *key, bool last) {
    printf("\"%s\": null%s", key, last ? "" : ",");
}

static void print_read_info_json(const legic_read_result_t *res) {
    const uint8_t *dump = res->dump;
    uint16_t len = res->len;
    uint32_t calc_mcc = (uint32_t)CRC8Legic((uint8_t *)dump, 4);
    bool mcc_ok = (calc_mcc == dump[4]);
    bool is_kgh = (strcmp(classify_legic_card(dump, len), "KGH") == 0);
    bool segment_crc_ok = check_segment_crc_ok(dump, len);
    bool kgh_crc_ok = check_kgh_crc_ok(dump, len);
    uint8_t segment_header_crc_calc = 0;
    uint8_t kgh_segment_crc_calc = 0;
    (void)check_segment_crc_calc(dump, len, &segment_header_crc_calc);
    (void)(is_kgh ? check_kgh_crc_calc(dump, len, &kgh_segment_crc_calc) : false);
    char segment_header_crc_calc_hex[3] = {0};
    char kgh_segment_crc_calc_hex[3] = {0};
    snprintf(segment_header_crc_calc_hex, sizeof(segment_header_crc_calc_hex), "%02X", segment_header_crc_calc);
    if (is_kgh) {
        snprintf(kgh_segment_crc_calc_hex, sizeof(kgh_segment_crc_calc_hex), "%02X", kgh_segment_crc_calc);
    }
    bool extra_segments = has_extra_segments(dump, len);

    uint32_t badge = 0;
    bool badge_ok = decode_badge_value(dump, len, &badge);
    char badge_raw[16] = {0};
    if (!badge_ok) {
        snprintf(badge_raw, sizeof(badge_raw), "0x%02X%02X%02X", dump[31], dump[32], dump[33]);
    }

    printf("{");
    print_json_string("card_type", classify_legic_card(dump, len), false);
    print_json_string("mcd", sprint_hex_inrow((uint8_t *)dump, 1), false);
    print_json_string("msn", sprint_hex_inrow((uint8_t *)dump + 1, 3), false);
    print_json_string("mcc", sprint_hex_inrow((uint8_t *)dump + 4, 1), false);
    print_json_bool("mcc_ok", mcc_ok, false);
    print_json_string("dcf", sprint_hex_inrow((uint8_t *)dump + 5, 2), false);
    print_json_bool("segment_header_crc_ok", segment_crc_ok, false);
    print_json_string("segment_header_crc", sprint_hex_inrow((uint8_t *)dump + 26, 1), false);
    print_json_string("segment_header_crc_calc", segment_header_crc_calc_hex, false);
    print_json_bool("is_kgh", is_kgh, false);
    print_json_bool("has_extra_segments", extra_segments, false);

    if (is_kgh) {
        char stamp[16] = {0};
        snprintf(stamp, sizeof(stamp), "%02X%02X%02X%02X", dump[27], dump[28], dump[29], dump[30]);
        print_json_string("stamp", stamp, false);
        print_json_string("kgh_segment_crc", sprint_hex_inrow((uint8_t *)dump + 34, 1), false);
        print_json_string("kgh_segment_crc_calc", kgh_segment_crc_calc_hex, false);
        if (badge_ok) {
            print_json_uint32("badge_number", badge, false);
            print_json_null("badge_number_raw", false);
            print_json_string("badge_number_format", "dec", false);
        } else {
            print_json_null("badge_number", false);
            print_json_string("badge_number_raw", badge_raw, false);
            print_json_string("badge_number_format", "hex", false);
        }
        print_json_bool("kgh_segment_crc_ok", kgh_crc_ok, true);
    } else {
        print_json_null("stamp", false);
        print_json_null("kgh_segment_crc", false);
        print_json_null("kgh_segment_crc_calc", false);
        print_json_null("badge_number", false);
        print_json_null("badge_number_raw", false);
        print_json_null("badge_number_format", false);
        print_json_bool("kgh_segment_crc_ok", false, true);
    }
    printf("}\n");
}

static int read_badge_from_card(uint32_t *badge_out) {
    uint8_t prev_print = g_printAndLog;
    g_printAndLog &= ~PRINTANDLOG_PRINT;

    legic_card_select_t card;
    if (legic_get_type(&card) != PM3_SUCCESS) {
        g_printAndLog = prev_print;
        return 1;
    }

    uint8_t *dump = calloc(card.cardsize, sizeof(uint8_t));
    if (dump == NULL) {
        g_printAndLog = prev_print;
        return 1;
    }

    uint16_t datalen = 0;
    int status = legic_read_mem(0, card.cardsize, 0x55, dump, &datalen);
    if (status != PM3_SUCCESS || datalen < 35) {
        free(dump);
        g_printAndLog = prev_print;
        return 1;
    }

    uint8_t crc = dump[4];
    if (CRC8Legic(dump, 4) != crc) {
        free(dump);
        g_printAndLog = prev_print;
        return 1;
    }

    for (uint16_t i = 22; i < datalen; ++i) {
        dump[i] ^= crc;
    }

    bool is_kgh = is_kgh_card(dump, datalen);
    bool ok = is_kgh && decode_badge_bcd(&dump[31], badge_out);
    if (!is_kgh) {
        fprintf(stderr, "not a supported KGH card\n");
    }
    free(dump);
    g_printAndLog = prev_print;
    return ok ? 0 : 1;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s <port> read_badge_number [-v|--verbose]\n", argv[0]);
        fprintf(stderr, "  %s <port> read_info\n", argv[0]);
        fprintf(stderr, "  %s <port> read_stamp [-o|--output-file <path>]\n", argv[0]);
        fprintf(stderr, "  %s <port> write_card <badge> (--stamp-file <path> | --stamp-hex <8hex>)\n", argv[0]);
        return EXIT_FAILURE;
    }

    g_session.incognito = true;
    bool verbose = has_flag(argc, argv, "-v") || has_flag(argc, argv, "--verbose");
    g_printAndLog = verbose ? PRINTANDLOG_PRINT : 0;
    pm3 *dev = open_pm3_with_retry(argv[1]);
    int rc = EXIT_FAILURE;

    if (strcmp(argv[2], "read_badge_number") == 0) {
        uint32_t badge = 0;
        if (read_badge_from_card(&badge) == 0) {
            printf("%u\n", badge);
            rc = EXIT_SUCCESS;
        }
    } else if (strcmp(argv[2], "read_info") == 0) {
        legic_read_result_t res;
        if (read_legic_dump(&res, verbose)) {
            print_read_info_json(&res);
            rc = EXIT_SUCCESS;
            free_legic_read_result(&res);
        } else if (verbose) {
            fprintf(stderr, "failed to read card info\n");
        }
    } else if (strcmp(argv[2], "read_stamp") == 0) {
        const char *output_file = NULL;
        bool has_output = get_arg_value(argc, argv, "-o", &output_file) || get_arg_value(argc, argv, "--output-file", &output_file);

        legic_read_result_t res;
        if (read_legic_dump(&res, verbose)) {
            uint8_t stamp[4] = {0};
            if (is_kgh_card(res.dump, res.len) && extract_stamp(res.dump, res.len, stamp)) {
                if (has_output) {
                    if (save_stamp_file(output_file, stamp)) {
                        rc = EXIT_SUCCESS;
                    } else {
                        fprintf(stderr, "failed to write stamp file\n");
                    }
                } else {
                    printf("%02X%02X%02X%02X\n", stamp[0], stamp[1], stamp[2], stamp[3]);
                    rc = EXIT_SUCCESS;
                }
            } else {
                fprintf(stderr, "not a supported KGH card\n");
            }
            free_legic_read_result(&res);
        } else if (verbose) {
            fprintf(stderr, "failed to read stamp\n");
        }
    } else if (strcmp(argv[2], "write_card") == 0) {
        if (argc < 4) {
            fprintf(stderr, "missing badge number\n");
        } else {
            uint32_t badge = 0;
            if (!parse_badge_text(argv[3], &badge)) {
                fprintf(stderr, "invalid badge number\n");
                pm3_close(dev);
                return EXIT_FAILURE;
            }
            const char *stamp_file = NULL;
            const char *stamp_hex = NULL;
            bool has_file = get_arg_value(argc, argv, "--stamp-file", &stamp_file);
            bool has_hex = get_arg_value(argc, argv, "--stamp-hex", &stamp_hex);
            if (has_file == has_hex) {
                fprintf(stderr, "specify exactly one of --stamp-file or --stamp-hex\n");
                pm3_close(dev);
                return EXIT_FAILURE;
            }

            uint8_t stamp[4] = {0};
            if (has_file) {
                if (!load_stamp_file(stamp_file, stamp)) {
                    fprintf(stderr, "failed to load stamp file\n");
                    pm3_close(dev);
                    return EXIT_FAILURE;
                }
            } else if (!parse_stamp_hex(stamp_hex, stamp)) {
                fprintf(stderr, "invalid stamp hex\n");
                pm3_close(dev);
                return EXIT_FAILURE;
            }

            uint8_t dump[35] = {0};
            build_migration_dump(badge, stamp, dump, sizeof(dump));
            if (legic_migrate_dump(dump, sizeof(dump), true, (const uint8_t[2]) {0x60, 0xEA}, true) == PM3_SUCCESS) {
                rc = EXIT_SUCCESS;
            } else {
                fprintf(stderr, "failed to write card\n");
            }
        }
    } else {
        fprintf(stderr, "unknown command: %s\n", argv[2]);
    }

    pm3_close(dev);
    return rc;
}
