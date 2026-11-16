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
// GlobalPlatform commands
//
// CRS: GPC Contactless Services v1.2 (GPC_SPE_025), section 3.11
//-----------------------------------------------------------------------------

#include "cmdhfgp.h"

#include <string.h>
#include <stdlib.h>
#include "cmdparser.h"          // command_t
#include "cliparser.h"
#include "comms.h"              // DropFieldEx
#include "ui.h"
#include "util.h"               // sprint_hex_inrow
#include "jansson.h"
#include "aidsearch.h"
#include "emv/tlv.h"
#include "iso7816/apduinfo.h"   // GetAPDUCodeDescription
#include "protocols.h"          // ISO7816_OK
#include "commonutil.h"         // ARRAYLEN

#define GP_SW_MORE_DATA     0x6310
#define GP_CRS_MAX_ROUNDS   32

static const uint8_t gp_crs_aid[] = {0xA0, 0x00, 0x00, 0x01, 0x51, 0x43, 0x52, 0x53, 0x00};

static int CmdHelp(const char *Cmd);

// longest aidlist.json entry that is a prefix of aid
static void gp_print_aid_name(json_t *root, const uint8_t *aid, size_t aid_len, int indent) {
    if (root == NULL) {
        return;
    }

    json_t *best = NULL;
    int best_len = 0;
    for (size_t i = 0; i < json_array_size(root); i++) {
        json_t *data = json_array_get(root, i);
        if (json_is_object(data) == false) {
            continue;
        }

        uint8_t vaid[64] = {0};
        int vaid_len = 0;
        if (AIDGetFromElm(data, vaid, sizeof(vaid), &vaid_len) == false || vaid_len == 0) {
            continue;
        }

        if ((size_t)vaid_len > aid_len || vaid_len <= best_len || memcmp(vaid, aid, vaid_len) != 0) {
            continue;
        }

        best = data;
        best_len = vaid_len;
    }

    if (best == NULL) {
        return;
    }

    const char *vendor = json_string_value(json_object_get(best, "Vendor"));
    const char *name = json_string_value(json_object_get(best, "Name"));
    PrintAndLogEx(SUCCESS, "%*s  " _GREEN_("%s") "%s%s%s", indent, "",
                  (name && strlen(name)) ? name : "?",
                  (vendor && strlen(vendor)) ? " | " : "",
                  (vendor) ? vendor : "",
                  ((size_t)best_len < aid_len) ? " ( prefix match )" : "");
}

static const char *gp_lifecycle_str(uint8_t lc) {
    if ((lc & 0x83) == 0x83) {
        return "LOCKED";
    }
    if ((lc & 0x87) == 0x07) {
        return "SELECTABLE";
    }
    if (lc == 0x03) {
        return "INSTALLED";
    }
    return "unknown";
}

// GPC Contactless Services, table 8-1
static const char *gp_cl_activation_str(uint8_t st) {
    if (st & 0x80) {
        return _RED_("NON_ACTIVATABLE");
    }
    return (st & 0x01) ? _GREEN_("ACTIVATED") : _YELLOW_("DEACTIVATED");
}

// display data is often UTF-8, so only control chars force hex
static void gp_print_text(const char *label, const uint8_t *p, size_t len, int indent) {
    bool text = (len > 0);
    for (size_t i = 0; i < len; i++) {
        if (p[i] < 0x20 || p[i] == 0x7F) {
            text = false;
            break;
        }
    }

    if (text) {
        PrintAndLogEx(SUCCESS, "%*s%s" _YELLOW_("%.*s"), indent, "", label, (int)len, (const char *)p);
    } else {
        PrintAndLogEx(SUCCESS, "%*s%s%s", indent, "", label, sprint_hex_inrow(p, len));
    }
}

static void gp_crs_print_tlvs(json_t *root, const uint8_t *buf, size_t len, int indent, bool verbose) {
    const uint8_t *cursor = buf;
    size_t left = len;

    while (left > 0) {
        struct tlv tlv = {0};
        if (tlv_parse_tl(&cursor, &left, &tlv) == false || tlv.len > left) {
            PrintAndLogEx(WARNING, "%*sMalformed TLV", indent, "");
            return;
        }
        const uint8_t *v = cursor;
        cursor += tlv.len;
        left -= tlv.len;

        switch (tlv.tag) {
            case 0x4F:
                PrintAndLogEx(SUCCESS, "%*sAID.............. " _YELLOW_("%s"), indent, "", sprint_hex_inrow(v, tlv.len));
                gp_print_aid_name(root, v, tlv.len, indent + 16);
                break;
            case 0x9F70:
                if (tlv.len == 2) {
                    PrintAndLogEx(SUCCESS, "%*sLifecycle........ %02X ( %s )", indent, "", v[0], gp_lifecycle_str(v[0]));
                    PrintAndLogEx(SUCCESS, "%*sContactless...... %02X ( %s )", indent, "", v[1], gp_cl_activation_str(v[1]));
                } else {
                    PrintAndLogEx(SUCCESS, "%*sLifecycle........ %s", indent, "", sprint_hex_inrow(v, tlv.len));
                }
                break;
            case 0x7F20:
                PrintAndLogEx(SUCCESS, "%*sDisplay control..", indent, "");
                gp_crs_print_tlvs(root, v, tlv.len, indent + 2, verbose);
                break;
            case 0x5F45:
                gp_print_text("Display message.. ", v, tlv.len, indent);
                break;
            case 0x5F50:
                gp_print_text("URL.............. ", v, tlv.len, indent);
                break;
            case 0x6D:
                PrintAndLogEx(SUCCESS, "%*sImage template... %zu bytes", indent, "", tlv.len);
                break;
            case 0x80: {
                uint32_t cnt = 0;
                for (size_t i = 0; i < tlv.len && i < 4; i++) {
                    cnt = (cnt << 8) | v[i];
                }
                PrintAndLogEx(SUCCESS, "%*sUpdate counter... %u", indent, "", cnt);
                break;
            }
            case 0x81:
                if (tlv.len == 1) {
                    PrintAndLogEx(SUCCESS, "%*sPriority......... %u", indent, "", v[0]);
                }
                break;
            case 0xA2:
                PrintAndLogEx(SUCCESS, "%*sGroup head.......", indent, "");
                gp_crs_print_tlvs(root, v, tlv.len, indent + 2, verbose);
                break;
            case 0xA3:
                PrintAndLogEx(SUCCESS, "%*sGroup members....", indent, "");
                gp_crs_print_tlvs(root, v, tlv.len, indent + 2, verbose);
                break;
            case 0xA4:
                PrintAndLogEx(SUCCESS, "%*sCREL apps........", indent, "");
                gp_crs_print_tlvs(root, v, tlv.len, indent + 2, verbose);
                break;
            case 0xA5:
                PrintAndLogEx(SUCCESS, "%*sPolicy restricted", indent, "");
                gp_crs_print_tlvs(root, v, tlv.len, indent + 2, verbose);
                break;
            case 0x87:
                PrintAndLogEx(SUCCESS, "%*sApp family....... %s", indent, "", sprint_hex_inrow(v, tlv.len));
                break;
            case 0x95:
                PrintAndLogEx(SUCCESS, "%*sInterface access. %s", indent, "", sprint_hex_inrow(v, tlv.len));
                break;
            default:
                if (verbose) {
                    PrintAndLogEx(SUCCESS, "%*sTag %X........... %s", indent, "", tlv.tag, sprint_hex_inrow(v, tlv.len));
                }
                break;
        }
    }
}

int gp_crs_list(Iso7816CommandChannel channel, const uint8_t *aid, size_t aid_len, bool verbose) {

    uint8_t resp[APDU_RES_LEN] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;

    int res = Iso7816Select(channel, true, true, (uint8_t *)gp_crs_aid, sizeof(gp_crs_aid), resp, sizeof(resp), &resp_len, &sw);
    if (res != PM3_SUCCESS && sw == 0) {
        PrintAndLogEx(FAILED, "No card found or exchange failed");
        DropFieldEx(channel);
        return PM3_ECARDEXCHANGE;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(FAILED, "CRS application not found ( %04X - %s )", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        PrintAndLogEx(HINT, "Hint: Phones usually expose the CRS only to the host, not over NFC");
        DropFieldEx(channel);
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "CRS application ( " _GREEN_("ok") " )");

    // search criterion 4F, empty AID = all applets
    uint8_t data[2 + 16] = {0x4F, (uint8_t)aid_len};
    memcpy(data + 2, aid, aid_len);

    json_t *root = AIDSearchInit(false);

    int found = 0;
    uint8_t p2 = 0x00;
    res = PM3_SUCCESS;
    for (int round = 0; round < GP_CRS_MAX_ROUNDS; round++) {

        sAPDU_t apdu = {0x80, 0xF2, 0x40, p2, (uint8_t)(2 + aid_len), data};
        res = Iso7816ExchangeEx(channel, false, true, apdu, true, 0, resp, sizeof(resp), &resp_len, &sw);
        // with APDU logging on, a non-9000 SW also comes back as an error
        if (res != PM3_SUCCESS && sw == 0) {
            PrintAndLogEx(FAILED, "GET STATUS exchange failed");
            res = PM3_ECARDEXCHANGE;
            break;
        }

        if (sw != ISO7816_OK && sw != GP_SW_MORE_DATA) {
            if (sw == 0x6A88 && found == 0) {
                PrintAndLogEx(INFO, "No matching contactless applets registered");
            } else if (sw != 0x6A88) {
                PrintAndLogEx(FAILED, "GET STATUS failed ( %04X - %s )", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
                res = PM3_ESOFT;
            }
            break;
        }

        if (verbose) {
            PrintAndLogEx(INFO, "Raw.. %s", sprint_hex_inrow(resp, resp_len));
        }

        const uint8_t *cursor = resp;
        size_t left = resp_len;
        while (left > 0) {
            struct tlv tlv = {0};
            if (tlv_parse_tl(&cursor, &left, &tlv) == false || tlv.len > left) {
                PrintAndLogEx(WARNING, "Malformed GET STATUS response");
                left = 0;
                break;
            }

            if (tlv.tag == 0x61) {
                found++;
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(INFO, "--- " _CYAN_("Applet %d") " ---------------------------", found);
                gp_crs_print_tlvs(root, cursor, tlv.len, 0, verbose);
            }

            cursor += tlv.len;
            left -= tlv.len;
        }

        if (sw != GP_SW_MORE_DATA) {
            break;
        }
        p2 = 0x01;
    }

    DropFieldEx(channel);
    AIDSearchFree(root);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Found " _YELLOW_("%d") " contactless applet(s)", found);
    return res;
}

// DF name (tag 84) from a SELECT response, inside FCI 6F or at top level
static bool gp_get_dfname(const uint8_t *buf, size_t len, const uint8_t **name, size_t *name_len) {
    const uint8_t *cursor = buf;
    size_t left = len;

    while (left > 0) {
        struct tlv tlv = {0};
        if (tlv_parse_tl(&cursor, &left, &tlv) == false || tlv.len > left) {
            return false;
        }

        if (tlv.tag == 0x84 && tlv.len > 0 && tlv.len <= 16) {
            *name = cursor;
            *name_len = tlv.len;
            return true;
        }

        if (tlv.tag == 0x6F) {
            return gp_get_dfname(cursor, tlv.len, name, name_len);
        }

        cursor += tlv.len;
        left -= tlv.len;
    }
    return false;
}

#define GP_AIDS_MAX         64
#define GP_AID_MAX_LEN      16
#define GP_WALK_MAX_APDUS   200000

typedef struct {
    uint8_t aid[GP_AID_MAX_LEN];
    size_t len;
} gp_aid_t;

typedef struct {
    Iso7816CommandChannel channel;
    bool reselect;          // last hit left an applet selected, it gets unmatched SELECTs forwarded
    bool abort;
    uint32_t apdus;
    json_t *root;
    gp_aid_t found[GP_AIDS_MAX];
    int count;
} gp_walk_t;

static bool gp_aid_known(const gp_aid_t *list, int count, const uint8_t *aid, size_t len) {
    for (int i = 0; i < count; i++) {
        if (list[i].len == len && memcmp(list[i].aid, aid, len) == 0) {
            return true;
        }
    }
    return false;
}

static void gp_add_aid(gp_walk_t *w, const uint8_t *aid, size_t len) {
    if (len == 0 || w->count >= GP_AIDS_MAX || gp_aid_known(w->found, w->count, aid, len)) {
        return;
    }
    memcpy(w->found[w->count].aid, aid, len);
    w->found[w->count].len = len;
    w->count++;
    PrintAndLogEx(SUCCESS, "Found............ " _YELLOW_("%s"), sprint_hex_inrow(aid, len));
    gp_print_aid_name(w->root, aid, len, 0);
}

// SELECT by DF name, first occurrence. *hit when the card selected an applet
static int gp_try_select(gp_walk_t *w, bool activate, const uint8_t *prefix, size_t len, bool *hit, gp_aid_t *dfname) {
    uint8_t resp[APDU_RES_LEN] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    *hit = false;
    dfname->len = 0;

    if (w->apdus >= GP_WALK_MAX_APDUS) {
        PrintAndLogEx(WARNING, "APDU budget exhausted, stopping");
        w->abort = true;
        return PM3_SUCCESS;
    }

    // empty DF name selects the default applet again
    if (w->reselect) {
        sAPDU_t def = {0x00, 0xA4, 0x04, 0x00, 0, NULL};
        int res = Iso7816ExchangeEx(w->channel, false, true, def, true, 0, resp, sizeof(resp), &resp_len, &sw);
        w->apdus++;
        if (res != PM3_SUCCESS && sw == 0) {
            return PM3_ECARDEXCHANGE;
        }
        w->reselect = false;
    }

    sAPDU_t apdu = {0x00, 0xA4, 0x04, 0x00, (uint8_t)len, (uint8_t *)prefix};
    int res = Iso7816ExchangeEx(w->channel, activate, true, apdu, true, 0, resp, sizeof(resp), &resp_len, &sw);
    w->apdus++;
    // with APDU logging on, a non-9000 SW also comes back as an error
    if (res != PM3_SUCCESS && sw == 0) {
        return PM3_ECARDEXCHANGE;
    }

    // 6283 = selected but blocked / invalidated
    if (sw != ISO7816_OK && sw != 0x6283) {
        return PM3_SUCCESS;
    }

    *hit = true;
    w->reselect = (len > 0);

    const uint8_t *name = NULL;
    size_t name_len = 0;
    if (gp_get_dfname(resp, resp_len, &name, &name_len) && name_len >= len && (len == 0 || memcmp(name, prefix, len) == 0)) {
        memcpy(dfname->aid, name, name_len);
        dfname->len = name_len;
    }
    return PM3_SUCCESS;
}

// extend a matching prefix one byte at a time, siblings included
static int gp_walk(gp_walk_t *w, const uint8_t *prefix, size_t len, const gp_aid_t *dfname) {
    int children = 0;

    if (len < GP_AID_MAX_LEN) {
        uint8_t next[GP_AID_MAX_LEN] = {0};
        memcpy(next, prefix, len);

        for (int b = 0; b < 256 && w->abort == false; b++) {
            if (kbd_enter_pressed()) {
                PrintAndLogEx(WARNING, "aborted via keyboard");
                w->abort = true;
                break;
            }

            next[len] = (uint8_t)b;
            bool hit = false;
            gp_aid_t dn = {0};
            int res = gp_try_select(w, false, next, len + 1, &hit, &dn);
            if (res != PM3_SUCCESS) {
                return res;
            }
            if (hit == false) {
                continue;
            }

            children++;
            res = gp_walk(w, next, len + 1, &dn);
            if (res != PM3_SUCCESS) {
                return res;
            }
        }
    }

    // nothing longer matches, so the prefix is a complete AID
    bool exact = (dfname->len == len && memcmp(dfname->aid, prefix, len) == 0);
    if ((children == 0 && w->abort == false) || exact) {
        gp_add_aid(w, prefix, len);
    }
    return PM3_SUCCESS;
}

static void gp_add_seed(gp_aid_t *seeds, size_t *n, size_t max, const uint8_t *p, size_t len) {
    if (*n >= max || gp_aid_known(seeds, (int)*n, p, len)) {
        return;
    }
    memcpy(seeds[*n].aid, p, len);
    seeds[*n].len = len;
    (*n)++;
}

int gp_find_aids(Iso7816CommandChannel channel, const uint8_t *prefix, size_t prefix_len, bool quick, bool verbose) {

    gp_walk_t *w = calloc(1, sizeof(gp_walk_t));
    if (w == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    w->channel = channel;
    w->root = AIDSearchInit(false);

    gp_aid_t *seeds = NULL;
    int res = PM3_SUCCESS;
    bool hit = false;
    gp_aid_t def = {0};

    res = gp_try_select(w, true, NULL, 0, &hit, &def);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "No card found or exchange failed");
        goto out;
    }

    if (def.len) {
        PrintAndLogEx(SUCCESS, "Default applet... " _YELLOW_("%s"), sprint_hex_inrow(def.aid, def.len));
        w->found[w->count++] = def;
    } else if (verbose) {
        PrintAndLogEx(INFO, "Default applet... none");
    }

    // a default applet that accepts any SELECT makes every prefix look like a hit
    static const uint8_t bogus[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    gp_aid_t dn = {0};
    res = gp_try_select(w, false, bogus, sizeof(bogus), &hit, &dn);
    if (res != PM3_SUCCESS) {
        goto out;
    }
    if (hit) {
        PrintAndLogEx(FAILED, "Card answers any SELECT, cannot tell real AIDs apart");
        PrintAndLogEx(HINT, "Hint: try `" _YELLOW_("hf 14a info -s") "` instead");
        res = PM3_ESOFT;
        goto out;
    }

    // shortest prefix the card accepts for partial selection, 0 = full AIDs only
    static const uint8_t isd_rid[] = {0xA0, 0x00, 0x00, 0x01, 0x51};
    const uint8_t *probe = (def.len >= 5) ? def.aid : isd_rid;
    size_t minlen = 0;
    for (size_t l = 1; l <= 5; l++) {
        res = gp_try_select(w, false, probe, l, &hit, &dn);
        if (res != PM3_SUCCESS) {
            goto out;
        }
        if (hit) {
            minlen = l;
            break;
        }
    }

    if (minlen) {
        PrintAndLogEx(INFO, "Partial selection with " _YELLOW_("%zu") " byte prefix", minlen);
    } else {
        PrintAndLogEx(WARNING, "No partial selection, trying full AIDs from aidlist.json only");
    }

    if (prefix_len && minlen && prefix_len < minlen) {
        PrintAndLogEx(FAILED, "Card needs a prefix of at least %zu bytes", minlen);
        res = PM3_EINVARG;
        goto out;
    }

    size_t seeds_max = 256 + 0x1000 + json_array_size(w->root);
    seeds = calloc(seeds_max, sizeof(gp_aid_t));
    if (seeds == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        res = PM3_EMALLOC;
        goto out;
    }
    size_t nseeds = 0;

    if (prefix_len) {
        gp_add_seed(seeds, &nseeds, seeds_max, prefix, prefix_len);
    } else if (minlen == 1) {
        for (int b = 0; b < 256; b++) {
            uint8_t p = (uint8_t)b;
            gp_add_seed(seeds, &nseeds, seeds_max, &p, 1);
        }
    } else {
        // known AIDs first, truncated to what the card accepts
        for (size_t i = 0; i < json_array_size(w->root); i++) {
            json_t *data = json_array_get(w->root, i);
            uint8_t aid[64] = {0};
            int aid_len = 0;
            if (json_is_object(data) == false || AIDGetFromElm(data, aid, sizeof(aid), &aid_len) == false) {
                continue;
            }
            if (aid_len < 5 || aid_len > GP_AID_MAX_LEN || (minlen && (size_t)aid_len < minlen)) {
                continue;
            }
            gp_add_seed(seeds, &nseeds, seeds_max, aid, minlen ? minlen : (size_t)aid_len);
        }

        // every registered RID, A0 00 00 0x xx
        if (minlen && quick == false) {
            for (int r = 0; r < 0x1000; r++) {
                uint8_t rid[5] = {0xA0, 0x00, 0x00, (uint8_t)(r >> 8), (uint8_t)(r & 0xFF)};
                gp_add_seed(seeds, &nseeds, seeds_max, rid, minlen);
            }
        }
    }

    PrintAndLogEx(INFO, "Trying " _YELLOW_("%zu") " prefixes, press " _GREEN_("<Enter>") " to abort", nseeds);

    for (size_t i = 0; i < nseeds && w->abort == false; i++) {
        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "aborted via keyboard");
            break;
        }

        res = gp_try_select(w, false, seeds[i].aid, seeds[i].len, &hit, &dn);
        if (res != PM3_SUCCESS) {
            break;
        }
        if (hit == false) {
            continue;
        }

        if (verbose) {
            PrintAndLogEx(INFO, "Prefix hit....... %s", sprint_hex_inrow(seeds[i].aid, seeds[i].len));
        }

        if (minlen) {
            res = gp_walk(w, seeds[i].aid, seeds[i].len, &dn);
            if (res != PM3_SUCCESS) {
                break;
            }
        } else {
            gp_add_aid(w, seeds[i].aid, seeds[i].len);
        }
    }

    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Exchange failed, card lost?");
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("%d AID(s)") " ( %u APDUs ) --------------", w->count, w->apdus);
    for (int i = 0; i < w->count; i++) {
        PrintAndLogEx(SUCCESS, _YELLOW_("%s"), sprint_hex_inrow(w->found[i].aid, w->found[i].len));
        gp_print_aid_name(w->root, w->found[i].aid, w->found[i].len, 0);
    }

out:
    DropFieldEx(channel);
    free(seeds);
    AIDSearchFree(w->root);
    free(w);
    return res;
}

static int CmdHFGPAids(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gp aids",
                  "Find applet AIDs without keys.\n"
                  "Selects by partial AID over all registered RIDs (A0 00 00 0x xx) and the prefixes\n"
                  "in aidlist.json, then extends every hit one byte at a time to the full AID.\n"
                  "Proprietary AIDs outside these prefixes are only found with --prefix.",
                  "hf gp aids\n"
                  "hf gp aids --quick                -> only prefixes from aidlist.json\n"
                  "hf gp aids --prefix A000000151    -> only AIDs under this prefix\n"
                  "hf gp aids -w                     -> use contact interface");

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "prefix", "<hex>", "AID prefix to enumerate"),
        arg_lit0(NULL, "quick", "Skip the registered RID sweep"),
        arg_lit0("w", "wired", "Send data via contact (iso7816) interface. (def: Contactless)"),
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t prefix[16] = {0};
    int prefix_len = 0;
    CLIGetHexWithReturn(ctx, 1, prefix, &prefix_len);
    bool quick = arg_get_lit(ctx, 2);
    bool wired = arg_get_lit(ctx, 3);
    bool apdu_log = arg_get_lit(ctx, 4);
    bool verbose = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    SetAPDULogging(apdu_log);
    int res = gp_find_aids(wired ? CC_CONTACT : CC_CONTACTLESS, prefix, prefix_len, quick, verbose);
    SetAPDULogging(false);
    return res;
}

// GP ISD, then the OpenPlatform / Visa card manager of older cards
static const uint8_t gp_isd_aid[] = {0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00};

// first TLV with tag in buf[0..len), value returned in *val / *vlen
static bool gp_tlv_find(const uint8_t *buf, size_t len, tlv_tag_t tag, const uint8_t **val, size_t *vlen) {
    const uint8_t *cursor = buf;
    size_t left = len;

    while (left > 0) {
        struct tlv tlv = {0};
        if (tlv_parse_tl(&cursor, &left, &tlv) == false || tlv.len > left) {
            return false;
        }
        if (tlv.tag == tag) {
            *val = cursor;
            *vlen = tlv.len;
            return true;
        }
        cursor += tlv.len;
        left -= tlv.len;
    }
    return false;
}

// BER OID to arcs and dotted string, returns number of arcs
static int gp_oid_decode(const uint8_t *p, size_t len, uint32_t *arcs, int max_arcs, char *str, size_t str_len) {
    int n = 0;
    str[0] = '\0';
    if (len == 0 || max_arcs < 2) {
        return 0;
    }

    arcs[n++] = (p[0] < 80) ? p[0] / 40 : 2;
    arcs[n++] = (p[0] < 80) ? p[0] % 40 : p[0] - 80;
    uint32_t acc = 0;
    for (size_t i = 1; i < len; i++) {
        acc = (acc << 7) | (p[i] & 0x7F);
        if ((p[i] & 0x80) == 0) {
            if (n < max_arcs) {
                arcs[n++] = acc;
            }
            acc = 0;
        }
    }

    size_t off = 0;
    for (int i = 0; i < n && off < str_len; i++) {
        off += snprintf(str + off, str_len - off, "%s%u", i ? "." : "", arcs[i]);
    }
    return n;
}

// GET DATA, falls back to CLA 00 on cards without the GP class byte
static int gp_get_data(Iso7816CommandChannel channel, uint16_t tag, uint8_t *resp, size_t resp_max, size_t *resp_len, uint16_t *sw) {
    uint8_t cla[] = {0x80, 0x00};
    int res = PM3_ESOFT;
    for (size_t i = 0; i < ARRAYLEN(cla); i++) {
        sAPDU_t apdu = {cla[i], 0xCA, (uint8_t)(tag >> 8), (uint8_t)(tag & 0xFF), 0, NULL};
        *sw = 0;
        res = Iso7816ExchangeEx(channel, false, true, apdu, true, 0, resp, resp_max, resp_len, sw);
        if (res != PM3_SUCCESS && *sw == 0) {
            return PM3_ECARDEXCHANGE;
        }
        if (*sw != 0x6E00 && *sw != 0x6D00) {
            break;
        }
    }
    return (*sw == ISO7816_OK) ? PM3_SUCCESS : PM3_ESOFT;
}

static void gp_print_unavailable(const char *what, uint16_t sw) {
    PrintAndLogEx(INFO, "%s not available ( %04X - %s )", what, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
}

// value of tag, with or without the tag echoed in the response
static const uint8_t *gp_unwrap(const uint8_t *resp, size_t resp_len, tlv_tag_t tag, size_t *vlen) {
    const uint8_t *v = NULL;
    if (gp_tlv_find(resp, resp_len, tag, &v, vlen)) {
        return v;
    }

    // tag present but truncated, don't read it as raw value
    const uint8_t *cursor = resp;
    size_t left = resp_len;
    struct tlv tlv = {0};
    if (tlv_parse_tl(&cursor, &left, &tlv) && tlv.tag == tag) {
        *vlen = 0;
        return resp;
    }

    *vlen = resp_len;
    return resp;
}

static const char *gp_ic_fabricator_str(uint16_t id) {
    switch (id) {
        case 0x4090:
            return "Infineon";
        case 0x4180:
            return "Atmel";
        case 0x4250:
            return "Samsung";
        case 0x4790:
            return "NXP";
        default:
            return "unknown";
    }
}

// CPLC dates are BCD YDDD, last year digit + day of year
static void gp_print_cplc_date(const char *label, const uint8_t *p) {
    bool bcd = true;
    for (int i = 0; i < 2; i++) {
        if ((p[i] >> 4) > 9 || (p[i] & 0x0F) > 9) {
            bcd = false;
        }
    }
    uint16_t day = ((p[0] & 0x0F) * 100) + ((p[1] >> 4) * 10) + (p[1] & 0x0F);
    if (bcd && day >= 1 && day <= 366) {
        PrintAndLogEx(SUCCESS, "  %s %02X%02X ( year x%u, day %u )", label, p[0], p[1], p[0] >> 4, day);
    } else {
        PrintAndLogEx(SUCCESS, "  %s %02X%02X", label, p[0], p[1]);
    }
}

static void gp_print_cplc(const uint8_t *p, size_t len) {
    if (len < 42) {
        PrintAndLogEx(WARNING, "CPLC too short ( %zu bytes ) %s", len, sprint_hex_inrow(p, len));
        return;
    }

    uint16_t fab = (p[0] << 8) | p[1];
    PrintAndLogEx(INFO, "--- " _CYAN_("CPLC") " ---------------------------------");
    PrintAndLogEx(SUCCESS, "  IC fabricator......... %04X ( " _YELLOW_("%s") " )", fab, gp_ic_fabricator_str(fab));
    PrintAndLogEx(SUCCESS, "  IC type............... %02X%02X", p[2], p[3]);
    PrintAndLogEx(SUCCESS, "  OS ID................. %02X%02X", p[4], p[5]);
    gp_print_cplc_date("OS release date.......", p + 6);
    PrintAndLogEx(SUCCESS, "  OS release level...... %02X%02X", p[8], p[9]);
    gp_print_cplc_date("IC fabrication date...", p + 10);
    PrintAndLogEx(SUCCESS, "  IC serial number...... " _YELLOW_("%s"), sprint_hex_inrow(p + 12, 4));
    PrintAndLogEx(SUCCESS, "  IC batch ID........... %02X%02X", p[16], p[17]);
    PrintAndLogEx(SUCCESS, "  Module fabricator..... %02X%02X", p[18], p[19]);
    gp_print_cplc_date("Module packaging date.", p + 20);
    PrintAndLogEx(SUCCESS, "  ICC manufacturer...... %02X%02X", p[22], p[23]);
    gp_print_cplc_date("IC embedding date.....", p + 24);
    PrintAndLogEx(SUCCESS, "  Pre-perso ID.......... %02X%02X", p[26], p[27]);
    gp_print_cplc_date("Pre-perso date........", p + 28);
    PrintAndLogEx(SUCCESS, "  Pre-perso equipment... %s", sprint_hex_inrow(p + 30, 4));
    PrintAndLogEx(SUCCESS, "  Perso ID.............. %02X%02X", p[34], p[35]);
    gp_print_cplc_date("Perso date............", p + 36);
    PrintAndLogEx(SUCCESS, "  Perso equipment....... %s", sprint_hex_inrow(p + 38, 4));
}

// GP Card Spec, Card Recognition Data (tag 66 / 73)
static void gp_print_card_data(const uint8_t *p, size_t len) {
    const uint8_t *crd = NULL;
    size_t crd_len = 0;
    size_t v66_len = 0;
    const uint8_t *v66 = gp_unwrap(p, len, 0x66, &v66_len);
    if (gp_tlv_find(v66, v66_len, 0x73, &crd, &crd_len) == false) {
        PrintAndLogEx(WARNING, "Card Recognition Data (73) not found");
        return;
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("Card Recognition Data") " ----------------");

    const uint8_t *cursor = crd;
    size_t left = crd_len;
    while (left > 0) {
        struct tlv tlv = {0};
        if (tlv_parse_tl(&cursor, &left, &tlv) == false || tlv.len > left) {
            PrintAndLogEx(WARNING, "Malformed TLV");
            return;
        }
        const uint8_t *v = cursor;
        cursor += tlv.len;
        left -= tlv.len;

        // all entries but the top-level 06 wrap an OID in tag 06
        const uint8_t *oid = v;
        size_t oid_len = tlv.len;
        if (tlv.tag != 0x06 && gp_tlv_find(v, tlv.len, 0x06, &oid, &oid_len) == false) {
            continue;
        }

        uint32_t arcs[16] = {0};
        char oidstr[96] = {0};
        int n = gp_oid_decode(oid, oid_len, arcs, ARRAYLEN(arcs), oidstr, sizeof(oidstr));
        // 1.2.840.114283 = GlobalPlatform
        bool gp = (n >= 5 && arcs[0] == 1 && arcs[1] == 2 && arcs[2] == 840 && arcs[3] == 114283);

        switch (tlv.tag) {
            case 0x06:
                PrintAndLogEx(SUCCESS, "  Card data OID......... %s", oidstr);
                break;
            case 0x60:
                if (gp && arcs[4] == 2 && n >= 7) {
                    if (n >= 8) {
                        PrintAndLogEx(SUCCESS, "  Card management....... " _YELLOW_("GlobalPlatform %u.%u.%u"), arcs[5], arcs[6], arcs[7]);
                    } else {
                        PrintAndLogEx(SUCCESS, "  Card management....... " _YELLOW_("GlobalPlatform %u.%u"), arcs[5], arcs[6]);
                    }
                } else {
                    PrintAndLogEx(SUCCESS, "  Card management....... %s", oidstr);
                }
                break;
            case 0x63:
                PrintAndLogEx(SUCCESS, "  Card ID scheme........ %s", oidstr);
                break;
            case 0x64:
                if (gp && arcs[4] == 4 && n >= 7) {
                    PrintAndLogEx(SUCCESS, "  Secure channel........ " _YELLOW_("SCP%02u") " i=%02X", arcs[5], arcs[6]);
                } else {
                    PrintAndLogEx(SUCCESS, "  Secure channel........ %s", oidstr);
                }
                break;
            case 0x65:
                PrintAndLogEx(SUCCESS, "  Card config details... %s", oidstr);
                break;
            case 0x66:
                // 1.3.6.1.4.1.42.2.110.1.x = Java Card (Sun / Oracle)
                if (n >= 11 && arcs[0] == 1 && arcs[1] == 3 && arcs[2] == 6 && arcs[3] == 1 && arcs[4] == 4 &&
                        arcs[5] == 1 && arcs[6] == 42 && arcs[7] == 2 && arcs[8] == 110 && arcs[9] == 1) {
                    PrintAndLogEx(SUCCESS, "  Card / chip details... " _YELLOW_("Java Card v%u"), arcs[10]);
                } else {
                    PrintAndLogEx(SUCCESS, "  Card / chip details... %s", oidstr);
                }
                break;
            default:
                PrintAndLogEx(SUCCESS, "  Tag %X................ %s", tlv.tag, oidstr);
                break;
        }
    }
}

static const char *gp_key_type_str(uint8_t type) {
    switch (type) {
        case 0x80:
            return "DES";
        case 0x82:
            return "3DES CBC";
        case 0x83:
            return "DES ECB";
        case 0x84:
            return "DES CBC";
        case 0x85:
            return "TLS PSK";
        case 0x88:
            return "AES";
        case 0xA0:
            return "RSA public e";
        case 0xA1:
            return "RSA public N";
        case 0xB0:
            return "ECC public";
        default:
            return "?";
    }
}

// Key Information Template, C0 entries: key id, KVN, then (type, length) pairs
static void gp_print_key_info(const uint8_t *p, size_t len) {
    size_t e0_len = 0;
    const uint8_t *e0 = gp_unwrap(p, len, 0xE0, &e0_len);

    PrintAndLogEx(INFO, "--- " _CYAN_("Key Information") " ----------------------");
    PrintAndLogEx(INFO, "  KVN  ID  Type          Len");

    const uint8_t *cursor = e0;
    size_t left = e0_len;
    while (left > 0) {
        struct tlv tlv = {0};
        if (tlv_parse_tl(&cursor, &left, &tlv) == false || tlv.len > left) {
            PrintAndLogEx(WARNING, "Malformed TLV");
            return;
        }
        const uint8_t *v = cursor;
        cursor += tlv.len;
        left -= tlv.len;

        if (tlv.tag != 0xC0 || tlv.len < 4) {
            continue;
        }

        for (size_t i = 2; i + 1 < tlv.len; i += 2) {
            uint8_t type = v[i];
            uint8_t klen = v[i + 1];
            // KVN 20-2F / 30-3F are the usual SCP02 / SCP03 key sets
            const char *scp = "";
            if (type == 0x80 && v[1] >= 0x20 && v[1] <= 0x2F) {
                scp = " ( SCP02 )";
            } else if (type == 0x88 && v[1] >= 0x30 && v[1] <= 0x3F) {
                scp = " ( SCP03 )";
            }
            PrintAndLogEx(SUCCESS, "  " _YELLOW_("%02X") "   %02X  %-12s  %3u%s", v[1], v[0], gp_key_type_str(type), klen, scp);
        }
    }
}

static void gp_print_ident(const char *label, const uint8_t *resp, size_t resp_len, tlv_tag_t tag) {
    size_t vlen = 0;
    const uint8_t *v = gp_unwrap(resp, resp_len, tag, &vlen);
    bool text = (vlen > 0);
    for (size_t i = 0; i < vlen; i++) {
        if (v[i] < 0x20 || v[i] > 0x7E) {
            text = false;
            break;
        }
    }
    if (text) {
        PrintAndLogEx(SUCCESS, "%s%s ( " _YELLOW_("%.*s") " )", label, sprint_hex_inrow(v, vlen), (int)vlen, (const char *)v);
    } else {
        PrintAndLogEx(SUCCESS, "%s" _YELLOW_("%s"), label, sprint_hex_inrow(v, vlen));
    }
}

int gp_info(Iso7816CommandChannel channel, bool verbose) {
    uint8_t resp[APDU_RES_LEN] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;

    int res = Iso7816Select(channel, true, true, (uint8_t *)gp_isd_aid, sizeof(gp_isd_aid), resp, sizeof(resp), &resp_len, &sw);
    if (res != PM3_SUCCESS && sw == 0) {
        PrintAndLogEx(FAILED, "No card found or exchange failed");
        DropFieldEx(channel);
        return PM3_ECARDEXCHANGE;
    }

    if (sw != ISO7816_OK) {
        // on the stack, a static address in a PACKED sAPDU_t is an unaligned pointer macOS ld rejects
        uint8_t op_aid[] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
        sAPDU_t op = {0x00, 0xA4, 0x04, 0x00, sizeof(op_aid), op_aid};
        res = Iso7816ExchangeEx(channel, false, true, op, true, 0, resp, sizeof(resp), &resp_len, &sw);
        if (res != PM3_SUCCESS && sw == 0) {
            PrintAndLogEx(FAILED, "Exchange failed");
            DropFieldEx(channel);
            return PM3_ECARDEXCHANGE;
        }
    }

    // ISD with a non-default AID, the default applet may be the ISD, or not
    bool isd = (sw == ISO7816_OK);
    if (isd == false) {
        sAPDU_t def = {0x00, 0xA4, 0x04, 0x00, 0, NULL};
        res = Iso7816ExchangeEx(channel, false, true, def, true, 0, resp, sizeof(resp), &resp_len, &sw);
        if ((res != PM3_SUCCESS && sw == 0) || sw != ISO7816_OK) {
            PrintAndLogEx(FAILED, "Security domain not found ( %04X )", sw);
            DropFieldEx(channel);
            return PM3_ESOFT;
        }
        PrintAndLogEx(WARNING, "ISD not selectable by AID, data below is from the default applet");
    }

    PrintAndLogEx(NORMAL, "");
    if (isd) {
        PrintAndLogEx(INFO, "--- " _CYAN_("Security Domain") " ----------------------");
    } else {
        PrintAndLogEx(INFO, "--- " _CYAN_("Default applet") " -----------------------");
    }

    const uint8_t *name = NULL;
    size_t name_len = 0;
    if (gp_get_dfname(resp, resp_len, &name, &name_len)) {
        PrintAndLogEx(SUCCESS, "  AID................... " _YELLOW_("%s"), sprint_hex_inrow(name, name_len));
    }

    const uint8_t *fci = NULL, *prop = NULL, *v = NULL;
    size_t fci_len = 0, prop_len = 0, vlen = 0;
    if (gp_tlv_find(resp, resp_len, 0x6F, &fci, &fci_len) && gp_tlv_find(fci, fci_len, 0xA5, &prop, &prop_len)) {
        if (gp_tlv_find(prop, prop_len, 0x9F6E, &v, &vlen)) {
            PrintAndLogEx(SUCCESS, "  Production data....... %s", sprint_hex_inrow(v, vlen));
        }
        if (gp_tlv_find(prop, prop_len, 0x9F65, &v, &vlen) && vlen == 1) {
            PrintAndLogEx(SUCCESS, "  Max command data...... %u bytes", v[0]);
        }
    }
    if (verbose) {
        PrintAndLogEx(INFO, "  FCI................... %s", sprint_hex_inrow(resp, resp_len));
    }

    // card recognition data, from the FCI when present, else via GET DATA
    const uint8_t *crd = NULL;
    size_t crd_len = 0;
    PrintAndLogEx(NORMAL, "");
    if (prop && gp_tlv_find(prop, prop_len, 0x73, &crd, &crd_len)) {
        gp_print_card_data(prop, prop_len);
    } else if (gp_get_data(channel, 0x0066, resp, sizeof(resp), &resp_len, &sw) == PM3_SUCCESS) {
        gp_print_card_data(resp, resp_len);
    } else {
        gp_print_unavailable("Card Recognition Data", sw);
    }

    PrintAndLogEx(NORMAL, "");
    if (gp_get_data(channel, 0x9F7F, resp, sizeof(resp), &resp_len, &sw) == PM3_SUCCESS) {
        v = gp_unwrap(resp, resp_len, 0x9F7F, &vlen);
        gp_print_cplc(v, vlen);
    } else {
        gp_print_unavailable("CPLC", sw);
    }

    PrintAndLogEx(NORMAL, "");
    if (gp_get_data(channel, 0x00E0, resp, sizeof(resp), &resp_len, &sw) == PM3_SUCCESS) {
        gp_print_key_info(resp, resp_len);
    } else {
        gp_print_unavailable("Key Information Template", sw);
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Identifiers") " --------------------------");
    if (gp_get_data(channel, 0x0042, resp, sizeof(resp), &resp_len, &sw) == PM3_SUCCESS) {
        gp_print_ident("  IIN................... ", resp, resp_len, 0x42);
    } else {
        gp_print_unavailable("  IIN", sw);
    }
    if (gp_get_data(channel, 0x0045, resp, sizeof(resp), &resp_len, &sw) == PM3_SUCCESS) {
        gp_print_ident("  CIN................... ", resp, resp_len, 0x45);
    } else {
        gp_print_unavailable("  CIN", sw);
    }
    if (gp_get_data(channel, 0x00C1, resp, sizeof(resp), &resp_len, &sw) == PM3_SUCCESS) {
        v = gp_unwrap(resp, resp_len, 0xC1, &vlen);
        PrintAndLogEx(SUCCESS, "  SCP sequence counter.. %s", sprint_hex_inrow(v, vlen));
    } else {
        gp_print_unavailable("  SCP sequence counter", sw);
    }

    DropFieldEx(channel);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(HINT, "Hint: Listing applets needs the ISD keys. Failed EXTERNAL AUTHENTICATE attempts");
    PrintAndLogEx(HINT, "      count against a small limit, then the card locks for good");
    return PM3_SUCCESS;
}

static int CmdHFGPInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gp info",
                  "Read GlobalPlatform card information without authentication.\n"
                  "Selects the Issuer Security Domain and reads Card Recognition Data, CPLC,\n"
                  "Key Information Template, IIN, CIN and the SCP sequence counter.\n"
                  "Sends no INITIALIZE UPDATE / EXTERNAL AUTHENTICATE, so no retry counter is used.",
                  "hf gp info\n"
                  "hf gp info -w     -> use contact interface");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("w", "wired", "Send data via contact (iso7816) interface. (def: Contactless)"),
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool wired = arg_get_lit(ctx, 1);
    bool apdu_log = arg_get_lit(ctx, 2);
    bool verbose = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    SetAPDULogging(apdu_log);
    int res = gp_info(wired ? CC_CONTACT : CC_CONTACTLESS, verbose);
    SetAPDULogging(false);
    return res;
}

static int CmdHFGPCrs(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gp crs",
                  "List contactless applets registered in the GlobalPlatform CRS\n"
                  "(Contactless Registry Service). GET STATUS on the CRS needs no keys.",
                  "hf gp crs\n"
                  "hf gp crs --aid A000000809     -> only CCC digital key applets\n"
                  "hf gp crs -w                   -> use contact interface");

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "aid", "<hex>", "AID or partial AID to search for (def: all)"),
        arg_lit0("w", "wired", "Send data via contact (iso7816) interface. (def: Contactless)"),
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t aid[16] = {0};
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 1, aid, &aid_len);
    bool wired = arg_get_lit(ctx, 2);
    bool apdu_log = arg_get_lit(ctx, 3);
    bool verbose = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    SetAPDULogging(apdu_log);
    int res = gp_crs_list(wired ? CC_CONTACT : CC_CONTACTLESS, aid, aid_len, verbose);
    SetAPDULogging(false);
    return res;
}

static command_t CommandTable[] = {
    {"-----------", CmdHelp,     AlwaysAvailable, "----------------------- " _CYAN_("General") " -----------------------"},
    {"help",        CmdHelp,     AlwaysAvailable, "This help"},
    {"-----------", CmdHelp,     IfPm3Iso14443,   "--------------------- " _CYAN_("Operations") " ----------------------"},
    {"aids",        CmdHFGPAids, IfPm3Iso14443,   "Find applet AIDs via partial SELECT walk"},
    {"info",        CmdHFGPInfo, IfPm3Iso14443,   "Read card info without authentication"},
    {"crs",         CmdHFGPCrs,  IfPm3Iso14443,   "List contactless applets via the CRS registry"},
    {NULL, NULL, NULL, NULL}
};

int CmdHFGP(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}
