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
// Pack a DESFire card image for emulator memory, and read one back.
// Layout and rationale live in include/desfire_em.h.
//-----------------------------------------------------------------------------

#include "desfireem.h"

#include <string.h>
#include <stdlib.h>
#include "commonutil.h"
#include "ui.h"
#include "desfirecrypto.h"   // desfire_get_key_length
#include "mifarehost.h"      // mf_eml_set_mem_xt
#include "comms.h"           // g_conn
#include "cmdhw.h"           // GetFromDevice

uint8_t desfire_em_gen_from_version(const uint8_t *versionhw, uint8_t len) {

    if (versionhw == NULL || len < 5) {
        return DESFIRE_EM_GEN_UNKNOWN;
    }

    // hardware frame: vendor, type, subtype, major, minor, storage, protocol.
    // Major and minor are what a reader keys on, see client/src/mifare/prime.c
    uint8_t type = versionhw[1];
    uint8_t major = versionhw[3];
    uint8_t minor = versionhw[4];

    if (minor != 0x00) {
        return DESFIRE_EM_GEN_UNKNOWN;
    }

    if (type != 0x01) {
        return DESFIRE_EM_GEN_UNKNOWN;
    }

    switch (major) {
        case 0x00:
            return DESFIRE_EM_GEN_D40;
        case 0x01:
            return DESFIRE_EM_GEN_EV1;
        case 0x12:
        case 0x22:
        case 0x42:
            return DESFIRE_EM_GEN_EV2;
        case 0x30:
            return DESFIRE_EM_GEN_LIGHT;
        case 0x33:
            return DESFIRE_EM_GEN_EV3;
        case 0xA0:
            return DESFIRE_EM_GEN_DUOX;
        default:
            return DESFIRE_EM_GEN_UNKNOWN;
    }
}

// NV the GetVersion storage size byte codes: 2^(n>>1) bytes, with the low bit
// meaning "between 2^n and 2^(n+1)". See client/src/mifare/prime.c, and the EV1
// spec section 9.4.7.
uint32_t desfire_em_nominal_cardsize(const uint8_t *versionhw, uint8_t len) {

    if (versionhw == NULL || len < 6) {
        return 0;
    }

    uint8_t fsize = versionhw[5];
    if (fsize == 0 || (fsize >> 1) > 24) {
        return 0;
    }

    return 1UL << (fsize >> 1);
}

const char *desfire_em_gen_str(uint8_t gen) {
    static const char *tbl[] = {"unknown", "D40", "EV1", "EV2", "EV3", "Light", "DuoX"};
    return (gen < ARRAYLEN(tbl)) ? tbl[gen] : "unknown";
}

// Bytes the committed region of one file occupies, before the shadow.
static uint32_t desfire_em_file_extent(const desfire_dump_file_t *f) {

    switch (f->type) {
        case 0x00:
        case 0x01:
            return f->size;
        case 0x02:
            // a value file's payload is the 4 byte value, but it is allocated
            // and shadowed like anything else, so give it a whole granule
            return DESFIRE_EM_GRANULE;
        case 0x03:
        case 0x04:
            // reserve the declared extent, not the records that happen to
            // exist, so WriteRecord never has to grow anything
            return f->recordsize * f->maxrecords;
        default:
            return 0;
    }
}

// True when CommitTransaction covers this file type, ie it needs a shadow.
// EV1 spec 9.6.10 names exactly these four; a standard data file writes through.
static bool desfire_em_file_has_shadow(uint8_t type) {
    return (type == 0x01 || type == 0x02 || type == 0x03 || type == 0x04);
}

uint32_t desfire_em_file_reserve(const desfire_dump_file_t *f) {

    uint32_t extent = DESFIRE_EM_ROUNDUP(desfire_em_file_extent(f));
    if (extent == 0) {
        return 0;
    }

    return desfire_em_file_has_shadow(f->type) ? (extent * 2) : extent;
}

// How many bytes of a file's committed region carry content, derived from the
// file's own declared shape rather than stored. A card holds the whole file, and
// a record file holds exactly the records that exist.
//
// Not stored because there is nothing to store: once packed, "we read 16 bytes
// of a 32 byte file" and "we read 32 bytes of which 16 were zero" are the same
// image. A dump that saw less than the whole file is an incomplete observation
// of a card, and desfire_em_pack() says so.
static uint32_t desfire_em_content_len(const desfire_dump_file_t *f) {

    if (f->read_ok == false) {
        return 0;
    }

    switch (f->type) {
        case 0x00:
        case 0x01:
            return f->size;
        case 0x03:
        case 0x04:
            return f->recordsize * f->currecords;
        default:
            return 0;   // a value file carries its payload in the value field
    }
}

static void desfire_em_fill_app(desfire_em_app_t *dst, const desfire_dump_app_t *src) {

    dst->aid[0] = src->aid & 0xFF;
    dst->aid[1] = (src->aid >> 8) & 0xFF;
    dst->aid[2] = (src->aid >> 16) & 0xFF;

    dst->keysettings = src->keysettings;
    dst->numkeysraw = src->numkeysraw;
    dst->isofid = src->isofid;
    dst->keytype = src->keytype;

    dst->dfnamelen = MIN(src->dfnamelen, (uint8_t)sizeof(dst->dfname));
    memcpy(dst->dfname, src->dfname, dst->dfnamelen);

    dst->flags = 0;
    if (src->auth_ok) {
        dst->flags |= DESFIRE_EM_APP_AUTHED;
    }
    if (src->numkeysraw & 0x20) {
        dst->flags |= DESFIRE_EM_APP_ISOFIDS;
    }
}

static void desfire_em_fill_file(desfire_em_file_t *dst, const desfire_dump_file_t *src, uint8_t appidx) {

    dst->app = appidx;
    dst->num = src->num;
    dst->type = src->type;
    dst->isofid = src->isofid;
    dst->rights = src->accessrights;

    dst->flags = (src->commmode & DESFIRE_EM_FILE_COMM_MASK);
    if (src->read_ok == false) {
        dst->flags |= DESFIRE_EM_FILE_UNKNOWN;
    }
    if (src->limitedcredit) {
        dst->flags |= DESFIRE_EM_FILE_LIMCREDIT;
    }

    switch (src->type) {
        case 0x00:
        case 0x01:
            dst->u.data.size = src->size;
            break;
        case 0x02:
            dst->u.value.lower = src->lowerlimit;
            dst->u.value.upper = src->upperlimit;
            dst->u.value.value = src->value;
            break;
        case 0x03:
        case 0x04:
            dst->u.record.recordsize = src->recordsize;
            dst->u.record.maxrecords = src->maxrecords;
            dst->u.record.currecords = src->currecords;
            break;
        default:
            break;
    }
}

static void desfire_em_fill_keys(desfire_em_key_t *tbl, uint8_t *n, const desfire_dump_app_t *app, uint8_t appidx) {

    for (uint8_t k = 0; k < DESFIRE_EM_MAX_KEYS; k++) {

        if (app->keys.present[k] == 0 && app->keys.versionknown[k] == 0) {
            continue;
        }

        desfire_em_key_t *e = &tbl[*n];
        memset(e, 0, sizeof(desfire_em_key_t));
        e->app = appidx;
        e->num = k;
        e->ver = app->keys.version[k];

        if (app->keys.versionknown[k]) {
            e->flags |= DESFIRE_EM_KEY_VERKNOWN;
        }

        if (app->keys.present[k]) {
            e->flags |= DESFIRE_EM_KEY_PRESENT;
            memcpy(e->key, app->keys.key[k], desfire_get_key_length(app->keytype));
        }

        (*n)++;
    }
}

int desfire_em_pack(const desfire_dump_t *dump, uint8_t *out, size_t outlen, size_t *used) {

    if (dump == NULL || out == NULL || used == NULL) {
        return PM3_EINVARG;
    }

    *used = 0;

    if (outlen < sizeof(desfire_em_hdr_t) || outlen > UINT16_MAX) {
        PrintAndLogEx(ERR, "Emulator memory of %zu bytes cannot hold a card image", outlen);
        return PM3_EINVARG;
    }

    if (dump->appcount > DESFIRE_EM_MAX_APPS) {
        PrintAndLogEx(ERR, "Card has %u applications, the format holds %u", dump->appcount, DESFIRE_EM_MAX_APPS);
        return PM3_EOUTOFBOUND;
    }

    memset(out, 0, outlen);
    desfire_em_hdr_t *hdr = (desfire_em_hdr_t *)out;

    hdr->magic = DESFIRE_EM_MAGIC;
    hdr->layout = DESFIRE_EM_LAYOUT_VERSION;
    hdr->size = outlen;
    hdr->generation = desfire_em_gen_from_version(dump->versionhw, dump->versionhwlen);

    hdr->uidlen = MIN(dump->card_info.uidlen, (uint8_t)sizeof(hdr->uid));
    memcpy(hdr->uid, dump->card_info.uid, hdr->uidlen);
    memcpy(hdr->atqa, dump->card_info.atqa, sizeof(hdr->atqa));
    hdr->sak = dump->card_info.sak;
    hdr->atslen = MIN(dump->card_info.ats_len, (uint8_t)sizeof(hdr->ats));
    memcpy(hdr->ats, dump->card_info.ats, hdr->atslen);

    hdr->versionhwlen = MIN(dump->versionhwlen, (uint8_t)sizeof(hdr->versionhw));
    memcpy(hdr->versionhw, dump->versionhw, hdr->versionhwlen);
    hdr->versionswlen = MIN(dump->versionswlen, (uint8_t)sizeof(hdr->versionsw));
    memcpy(hdr->versionsw, dump->versionsw, hdr->versionswlen);
    hdr->versionprodlen = MIN(dump->versionprodlen, (uint8_t)sizeof(hdr->versionprod));
    memcpy(hdr->versionprod, dump->versionprod, hdr->versionprodlen);

    hdr->signaturelen = MIN(dump->signaturelen, (uint8_t)sizeof(hdr->signature));
    memcpy(hdr->signature, dump->signature, hdr->signaturelen);

    // app[0] is the PICC, so the table is one longer than the card's own count
    uint8_t appcount = dump->appcount + 1;

    uint16_t filecount = 0;
    for (uint8_t i = 0; i < dump->appcount; i++) {
        filecount += MIN(dump->app[i].filecount, (uint8_t)DESFIRE_EM_MAX_FILES);
    }

    // keys are sparse, so count them before laying anything out
    uint16_t keycount = 0;
    for (uint8_t i = 0; i < appcount; i++) {
        const desfire_dump_app_t *a = (i == 0) ? &dump->picc : &dump->app[i - 1];
        for (uint8_t k = 0; k < DESFIRE_EM_MAX_KEYS; k++) {
            if (a->keys.present[k] || a->keys.versionknown[k]) {
                keycount++;
            }
        }
    }

    hdr->app_off = sizeof(desfire_em_hdr_t);
    hdr->file_off = hdr->app_off + (appcount * sizeof(desfire_em_app_t));
    hdr->key_off = hdr->file_off + (filecount * sizeof(desfire_em_file_t));

    uint32_t tables_end = hdr->key_off + (keycount * sizeof(desfire_em_key_t));
    if (tables_end > outlen) {
        PrintAndLogEx(ERR, "Card image tables need %u bytes, emulator memory holds %zu", tables_end, outlen);
        return PM3_EOUTOFBOUND;
    }
    hdr->tables_end = tables_end;

    desfire_em_app_t *apps = (desfire_em_app_t *)(out + hdr->app_off);
    desfire_em_file_t *files = (desfire_em_file_t *)(out + hdr->file_off);
    desfire_em_key_t *keys = (desfire_em_key_t *)(out + hdr->key_off);

    // file data grows down from the end, tables grow up: the two only have to
    // not meet, and what is between them is the card's free memory
    uint32_t data_start = outlen;
    uint32_t reserved = 0;      // NV the card has spent, for GetFreeMem
    uint8_t nkeys = 0;
    uint16_t nfiles = 0;

    for (uint8_t i = 0; i < appcount; i++) {

        const desfire_dump_app_t *a = (i == 0) ? &dump->picc : &dump->app[i - 1];

        desfire_em_fill_app(&apps[i], a);
        if (i == 0) {
            // the PICC is AID 000000 whatever the dump happens to say
            memset(apps[i].aid, 0, sizeof(apps[i].aid));
        }

        desfire_em_fill_keys(keys, &nkeys, a, i);

        // a card charges for the application itself, not only for its files
        reserved += DESFIRE_EM_ROUNDUP(DESFIRE_EM_APP_OVERHEAD
                                       + (a->numkeys * desfire_get_key_length(a->keytype)));

        if (i == 0) {
            continue;   // the PICC has no files
        }

        uint8_t fc = MIN(a->filecount, (uint8_t)DESFIRE_EM_MAX_FILES);
        for (uint8_t n = 0; n < fc; n++) {

            const desfire_dump_file_t *sf = &a->files[n];
            desfire_em_file_t *df = &files[nfiles];

            desfire_em_fill_file(df, sf, i);

            uint32_t reserve = desfire_em_file_reserve(sf);
            if (reserve == 0) {
                nfiles++;
                continue;   // a type we do not reserve for, eg transaction MAC
            }

            if (data_start < reserve || (data_start - reserve) < tables_end) {
                PrintAndLogEx(ERR, "Out of emulator memory laying out AID %06X file %02X: needs %u more bytes"
                              , a->aid, sf->num, reserve - (data_start - tables_end));
                return PM3_EOUTOFBOUND;
            }

            data_start -= reserve;
            reserved += reserve;

            uint32_t extent = desfire_em_file_has_shadow(sf->type) ? (reserve / 2) : reserve;
            df->dataoff = data_start;
            df->datalen = extent;
            df->shadow_off = desfire_em_file_has_shadow(sf->type) ? (data_start + extent) : 0;

            uint32_t content = desfire_em_content_len(sf);
            if (content && sf->data) {

                if (sf->datalen < content) {
                    PrintAndLogEx(WARNING, "AID %06X file %02X holds %u of %u bytes, the rest of the image is zero"
                                  , a->aid, sf->num, sf->datalen, content);
                    content = sf->datalen;
                }

                memcpy(out + df->dataoff, sf->data, MIN(content, extent));
            }

            nfiles++;
        }
    }

    hdr->appcount = appcount;
    hdr->filecount = nfiles;
    hdr->keycount = nkeys;
    hdr->data_start = data_start;
    hdr->reserved = reserved;

    // What the card claims to hold.
    //
    // Anchor it to the free memory the real card reported when the dump was
    // taken: cardsize = observed free + what we reserved for the same content.
    // The emulated card then answers GetFreeMem with the number its original
    // answered, and that figure falls as a reader writes. Much better than
    // deriving from the storage size byte, which understates -- a 2K part codes
    // 2048 and hands out 2560.
    //
    // With no observed figure, fall back to the storage size byte as a floor,
    // never below what this image already carries.
    uint32_t cardsize;
    if (dump->freemem_ok) {
        cardsize = dump->freemem + reserved;
    } else {
        cardsize = desfire_em_nominal_cardsize(dump->versionhw, dump->versionhwlen);
        if (cardsize < reserved) {
            cardsize = reserved;
        }
    }

    if (cardsize > outlen) {
        // a claim larger than emulator memory is one we cannot honour
        cardsize = outlen;
    }
    hdr->cardsize = cardsize;

    if (reserved > hdr->cardsize) {
        PrintAndLogEx(ERR, "Card image needs %u bytes but a %u byte card cannot hold it", reserved, hdr->cardsize);
        return PM3_EOUTOFBOUND;
    }

    *used = outlen;
    return PM3_SUCCESS;
}

int desfire_em_unpack(const uint8_t *img, size_t imglen, desfire_dump_t *dump) {
    return desfire_em_unpack_ex(img, imglen, dump, false);
}

int desfire_em_unpack_ex(const uint8_t *img, size_t imglen, desfire_dump_t *dump, bool keep_deleted) {

    if (img == NULL || dump == NULL || imglen < sizeof(desfire_em_hdr_t)) {
        return PM3_EINVARG;
    }

    const desfire_em_hdr_t *hdr = (const desfire_em_hdr_t *)img;

    if (hdr->magic != DESFIRE_EM_MAGIC) {
        PrintAndLogEx(ERR, "Not a DESFire card image, magic is %08X", hdr->magic);
        return PM3_EINVARG;
    }

    if (hdr->layout != DESFIRE_EM_LAYOUT_VERSION) {
        PrintAndLogEx(ERR, "Card image layout v%u, this client speaks v%u", hdr->layout, DESFIRE_EM_LAYOUT_VERSION);
        return PM3_EINVARG;
    }

    if (hdr->size > imglen || hdr->tables_end > imglen || hdr->data_start > imglen) {
        PrintAndLogEx(ERR, "Card image is internally inconsistent with its %zu bytes", imglen);
        return PM3_EINVARG;
    }

    memset(dump, 0, sizeof(desfire_dump_t));

    // Bound each copy by the image's own array, which is the smaller of the two
    // and the one a corrupt length could run past.  Not by the destination cast
    // to uint8_t: card_info.ats is 256 bytes, that cast wrapped to 0, and the
    // ATS was silently dropped while its length was still reported as 8.
    dump->card_info.uidlen = MIN(hdr->uidlen, sizeof(hdr->uid));
    memcpy(dump->card_info.uid, hdr->uid, dump->card_info.uidlen);
    memcpy(dump->card_info.atqa, hdr->atqa, sizeof(hdr->atqa));
    dump->card_info.sak = hdr->sak;
    dump->card_info.ats_len = MIN(hdr->atslen, sizeof(hdr->ats));
    memcpy(dump->card_info.ats, hdr->ats, dump->card_info.ats_len);

    dump->versionhwlen = hdr->versionhwlen;
    memcpy(dump->versionhw, hdr->versionhw, sizeof(dump->versionhw));
    dump->versionswlen = hdr->versionswlen;
    memcpy(dump->versionsw, hdr->versionsw, sizeof(dump->versionsw));
    dump->versionprodlen = hdr->versionprodlen;
    memcpy(dump->versionprod, hdr->versionprod, sizeof(dump->versionprod));

    dump->signaturelen = hdr->signaturelen;
    memcpy(dump->signature, hdr->signature, sizeof(dump->signature));

    // free memory is the card's, not the frontier gap: that is the number a
    // reader gets from GetFreeMem, and it has to look like the part we claim
    // to be rather than like however much emulator memory happens to be spare
    dump->freemem = (hdr->cardsize > hdr->reserved) ? (hdr->cardsize - hdr->reserved) : 0;
    dump->freemem_ok = true;

    const desfire_em_app_t *apps = (const desfire_em_app_t *)(img + hdr->app_off);
    const desfire_em_file_t *files = (const desfire_em_file_t *)(img + hdr->file_off);
    const desfire_em_key_t *keys = (const desfire_em_key_t *)(img + hdr->key_off);

    if (hdr->appcount == 0 || hdr->appcount > (DESFIRE_EM_MAX_APPS + 1)) {
        PrintAndLogEx(ERR, "Card image claims %u applications", hdr->appcount);
        return PM3_EINVARG;
    }

    // A deleted application or file is a tombstone in the image, so the memory
    // it held stays spent, but it is gone as far as a reader is concerned and it
    // does not belong in a dump of the card.  Applications are therefore packed
    // down as they are copied out, and appmap carries image index -> dump index
    // so the key and file tables, which refer to applications by image index,
    // can follow.
    int appmap[DESFIRE_EM_MAX_APPS + 1];
    for (uint16_t i = 0; i < ARRAYLEN(appmap); i++) {
        appmap[i] = -1;
    }

    dump->appcount = 0;

    for (uint8_t i = 0; i < hdr->appcount; i++) {

        const desfire_em_app_t *s = &apps[i];

        if (i > 0 && (s->flags & DESFIRE_EM_APP_DELETED) && (keep_deleted == false)) {
            continue;
        }

        desfire_dump_app_t *a;
        if (i == 0) {
            a = &dump->picc;            // app[0] is the PICC, never deleted
        } else {
            if (dump->appcount >= DESFIRE_MAX_APP_COUNT) {
                continue;
            }
            a = &dump->app[dump->appcount];
            appmap[i] = dump->appcount;
            dump->appcount++;
        }

        a->aid = s->aid[0] | (s->aid[1] << 8) | (s->aid[2] << 16);
        a->isofid = s->isofid;
        a->keysettings = s->keysettings;
        a->numkeysraw = s->numkeysraw;
        a->numkeys = s->numkeysraw & 0x1F;
        a->keytype = s->keytype;
        a->settings_ok = (s->numkeysraw != 0);
        a->auth_ok = ((s->flags & DESFIRE_EM_APP_AUTHED) != 0);
        a->dfnamelen = MIN(s->dfnamelen, (uint8_t)sizeof(a->dfname));
        memcpy(a->dfname, s->dfname, a->dfnamelen);
    }

    for (uint8_t k = 0; k < hdr->keycount; k++) {

        const desfire_em_key_t *s = &keys[k];
        if (s->app >= hdr->appcount || s->num >= DESFIRE_EM_MAX_KEYS) {
            continue;
        }

        desfire_dump_app_t *a;
        if (s->app == 0) {
            a = &dump->picc;
        } else {
            if (appmap[s->app] < 0) {
                continue;               // its application was deleted
            }
            a = &dump->app[appmap[s->app]];
        }

        if (s->flags & DESFIRE_EM_KEY_VERKNOWN) {
            a->keys.versionknown[s->num] = 1;
            a->keys.version[s->num] = s->ver;
        }

        if (s->flags & DESFIRE_EM_KEY_PRESENT) {
            a->keys.present[s->num] = 1;
            memcpy(a->keys.key[s->num], s->key, DESFIRE_MAX_KEY_SIZE);
        }
    }

    for (uint16_t n = 0; n < hdr->filecount; n++) {

        const desfire_em_file_t *s = &files[n];
        if (s->app == 0 || s->app >= hdr->appcount) {
            continue;
        }

        if ((s->flags & DESFIRE_EM_FILE_DELETED) && (keep_deleted == false)) {
            continue;
        }

        if (appmap[s->app] < 0) {
            continue;                   // its application was deleted
        }

        desfire_dump_app_t *a = &dump->app[appmap[s->app]];
        if (a->filecount >= DESFIRE_MAX_FILE_COUNT) {
            continue;
        }

        desfire_dump_file_t *f = &a->files[a->filecount];

        f->num = s->num;
        f->type = s->type;
        f->isofid = s->isofid;
        f->accessrights = s->rights;
        f->commmode = s->flags & DESFIRE_EM_FILE_COMM_MASK;
        f->limitedcredit = ((s->flags & DESFIRE_EM_FILE_LIMCREDIT) != 0);
        f->settings_ok = true;
        f->read_ok = ((s->flags & DESFIRE_EM_FILE_UNKNOWN) == 0);

        switch (s->type) {
            case 0x00:
            case 0x01:
                f->size = s->u.data.size;
                break;
            case 0x02:
                f->lowerlimit = s->u.value.lower;
                f->upperlimit = s->u.value.upper;
                f->value = s->u.value.value;
                break;
            case 0x03:
            case 0x04:
                f->recordsize = s->u.record.recordsize;
                f->maxrecords = s->u.record.maxrecords;
                f->currecords = s->u.record.currecords;
                break;
            default:
                break;
        }

        a->filecount++;

        uint32_t content = MIN(desfire_em_content_len(f), (uint32_t)s->datalen);
        if (content == 0) {
            continue;
        }

        if (s->dataoff + content > imglen) {
            PrintAndLogEx(WARNING, "AID %06X file %02X reaches past the image, skipping its contents", a->aid, f->num);
            continue;
        }

        f->data = calloc(content, sizeof(uint8_t));
        if (f->data == NULL) {
            return PM3_EMALLOC;
        }

        memcpy(f->data, img + s->dataoff, content);
        f->datalen = content;
    }

    return PM3_SUCCESS;
}

void desfire_em_print(const uint8_t *img, size_t imglen) {

    if (img == NULL || imglen < sizeof(desfire_em_hdr_t)) {
        return;
    }

    const desfire_em_hdr_t *hdr = (const desfire_em_hdr_t *)img;

    if (hdr->magic != DESFIRE_EM_MAGIC) {
        PrintAndLogEx(WARNING, "No DESFire card image here, magic is " _YELLOW_("%08X"), hdr->magic);
        PrintAndLogEx(HINT, "Hint: load one with " _YELLOW_("`hf mfdes eload -f <fn>`"));
        return;
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("DESFire card image") " -----------------------");
    PrintAndLogEx(SUCCESS, "Generation....... %s", desfire_em_gen_str(hdr->generation));
    PrintAndLogEx(SUCCESS, "UID.............. %s", sprint_hex_inrow(hdr->uid, hdr->uidlen));
    PrintAndLogEx(SUCCESS, "Applications..... %u ( incl. the PICC )", hdr->appcount);
    PrintAndLogEx(SUCCESS, "Files............ %u", hdr->filecount);
    PrintAndLogEx(SUCCESS, "Keys............. %u", hdr->keycount);
    PrintAndLogEx(SUCCESS, "Tables end at.... %u", hdr->tables_end);
    PrintAndLogEx(SUCCESS, "Data starts at... %u", hdr->data_start);
    PrintAndLogEx(SUCCESS, "Card capacity.... %u bytes, %u spent", hdr->cardsize, hdr->reserved);
    PrintAndLogEx(SUCCESS, "Free memory...... " _GREEN_("%u") " bytes"
                  , (hdr->cardsize > hdr->reserved) ? (hdr->cardsize - hdr->reserved) : 0);
    PrintAndLogEx(SUCCESS, "Emulator memory.. %u of %u bytes spare"
                  , (hdr->data_start > hdr->tables_end) ? (hdr->data_start - hdr->tables_end) : 0
                  , hdr->size);
}

//-----------------------------------------------------------------------------
// Moving an image to and from the device.
//
// No DESFire specific command is needed either way. Emulator memory is one
// region shared by every simulation, so the generic MIFARE setter and the bulk
// emulator download already reach it -- CMD_HF_MIFARE_EML_MEMSET writes through
// emlSet(), which bounds-checks, and BIG_BUF_EML reads back with the device
// clamping to the size it reports in capabilities_t.
//-----------------------------------------------------------------------------

#define DESFIRE_EM_XFER_WIDTH   16      // emlSet offset is blockno * this

int desfire_em_upload(const uint8_t *img, size_t imglen) {

    if (img == NULL || imglen == 0) {
        return PM3_EINVARG;
    }

    if ((imglen % DESFIRE_EM_XFER_WIDTH) != 0) {
        PrintAndLogEx(ERR, "Card image of %zu bytes is not a multiple of %d", imglen, DESFIRE_EM_XFER_WIDTH);
        return PM3_EINVARG;
    }

    // one MEMSET carries a header plus data, so size the chunk from what the
    // device told us it can take rather than assuming
    size_t perframe = (g_conn.max_cmd_data_size - 8) / DESFIRE_EM_XFER_WIDTH;
    if (perframe == 0) {
        return PM3_EINVARG;
    }
    if (perframe > 255) {
        perframe = 255;     // blockcnt is a uint8_t
    }

    size_t blocks = imglen / DESFIRE_EM_XFER_WIDTH;

    PrintAndLogEx(INFO, "Uploading " _YELLOW_("%zu") " bytes to emulator memory", imglen);

    for (size_t b = 0; b < blocks; b += perframe) {

        size_t n = MIN(perframe, blocks - b);

        int res = mf_eml_set_mem_xt((uint8_t *)img + (b * DESFIRE_EM_XFER_WIDTH), b, n, DESFIRE_EM_XFER_WIDTH, 0);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Upload failed at block %zu of %zu", b, blocks);
            return res;
        }
    }

    return PM3_SUCCESS;
}

int desfire_em_download(uint8_t *img, size_t imglen) {

    if (img == NULL || imglen == 0) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Downloading " _YELLOW_("%zu") " bytes from emulator memory", imglen);

    if (GetFromDevice(BIG_BUF_EML, img, imglen, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    return PM3_SUCCESS;
}
