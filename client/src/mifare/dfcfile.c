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

#include "dfcfile.h"

#include "dfc_credential.h"
#include "dfc_der.h"
#include "dfc_text.h"
#include "desfireem.h"
#include "fileutils.h"
#include "pm3_cmd.h"
#include "ui.h"

#include <stdlib.h>
#include <string.h>

static bool has_suffix(const char *filename, const char *suffix) {
    size_t filename_length = strlen(filename);
    size_t suffix_length = strlen(suffix);
    return filename_length >= suffix_length &&
           strcasecmp(filename + filename_length - suffix_length, suffix) == 0;
}

static DfcGeneration generation_from_dump(const desfire_dump_t *dump) {
    switch (desfire_em_gen_from_version(dump->versionhw, dump->versionhwlen)) {
        case DESFIRE_EM_GEN_D40:
        case DESFIRE_EM_GEN_EV1:
            return DfcGenerationEv1;
        case DESFIRE_EM_GEN_EV2:
            return DfcGenerationEv2;
        case DESFIRE_EM_GEN_EV3:
            return DfcGenerationEv3;
        default:
            return 0;
    }
}

static int import_keys(
    DfcCredential *credential,
    DfcApplication *application,
    const desfire_dump_app_t *source) {
    if (!source->settings_ok || source->numkeys > DFC_MAX_KEYS ||
            (application != NULL && source->numkeys == 0)) {
        return PM3_ENODATA;
    }
    if (source->numkeys == 0) {
        dfc_credential_keys_release(credential, application);
        return PM3_SUCCESS;
    }
    size_t key_length = dfc_credential_key_length(source->numkeysraw);
    if (!dfc_credential_keys_resize(
                credential, application, source->numkeys, key_length)) {
        return PM3_EOUTOFBOUND;
    }

    for (size_t i = 0; i < source->numkeys; i++) {
        if (!source->keys.present[i] || !source->keys.versionknown[i]) {
            return PM3_ENODATA;
        }
        uint8_t *key = dfc_credential_key(credential, application, i);
        if (source->keytype == T_DES && key_length == 16) {
            memcpy(key, source->keys.key[i], 8);
            memcpy(key + 8, source->keys.key[i], 8);
        } else {
            memcpy(key, source->keys.key[i], key_length);
        }
        if (application != NULL) {
            application->key_versions[i] = source->keys.version[i];
        } else {
            credential->picc_key_versions[i] = source->keys.version[i];
        }
    }
    return PM3_SUCCESS;
}

static int import_application(
    DfcCredential *credential,
    const desfire_dump_app_t *source,
    size_t *application_index) {
    if (credential->num_apps >= DFC_MAX_APPS) {
        return PM3_EOUTOFBOUND;
    }
    DfcApplication *application = &credential->apps[credential->num_apps];
    dfc_credential_reset_application(application);
    application->aid[0] = source->aid;
    application->aid[1] = source->aid >> 8;
    application->aid[2] = source->aid >> 16;
    application->key_settings_1 = source->keysettings;
    application->key_settings_2 = source->numkeysraw;
    application->auth_command = source->keytype == T_AES ? DFC_CMD_AUTHENTICATE_AES :
                                source->keytype == T_3K3DES ? DFC_CMD_AUTHENTICATE_ISO :
                                DFC_CMD_AUTHENTICATE_LEGACY;
    if (source->isofid) {
        application->has_iso_file_id = true;
        application->iso_file_id = source->isofid;
    }
    application->iso_aid_len = source->dfnamelen;
    memcpy(application->iso_aid, source->dfname, source->dfnamelen);

    int status = import_keys(credential, application, source);
    if (status != PM3_SUCCESS) {
        dfc_credential_keys_release(credential, application);
        return status;
    }
    *application_index = credential->num_apps++;
    return PM3_SUCCESS;
}

static int import_file(
    DfcCredential *credential,
    size_t application_index,
    const desfire_dump_file_t *source) {
    if (!source->settings_ok || !source->read_ok || source->type > 0x04) {
        return PM3_ENODATA;
    }
    DfcFile *file = dfc_credential_create_file(credential, application_index, source->num);
    if (file == NULL) {
        return PM3_EOUTOFBOUND;
    }
    file->type = source->type;
    file->comm_settings = source->commmode;
    file->access_rights = source->accessrights;
    if (source->isofid) {
        file->has_iso_file_id = true;
        file->iso_file_id = source->isofid;
    }

    if (source->type <= 0x01) {
        file->declared_size = source->size;
    } else if (source->type == 0x02) {
        file->value_lower_limit = source->lowerlimit;
        file->value_upper_limit = source->upperlimit;
        file->value = source->value;
        file->limited_credit = source->limitedcredit;
    } else {
        file->record_size = source->recordsize;
        file->max_records = source->maxrecords;
        file->record_count = source->currecords;
        file->declared_size = source->recordsize * source->maxrecords;
    }

    if (source->datalen) {
        if (source->data == NULL || !dfc_file_resize(credential, file, source->datalen)) {
            return PM3_EOUTOFBOUND;
        }
        memcpy(dfc_file_data(credential, file), source->data, source->datalen);
    }
    file->contents_complete = source->type == 0x02 ||
                              (source->type <= 0x01 && source->datalen == source->size) ||
                              (source->type >= 0x03 && source->datalen == source->recordsize * source->currecords);
    return file->contents_complete ? PM3_SUCCESS : PM3_ENODATA;
}

static int import_json(const char *filename, DfcCredential *credential) {
    desfire_dump_t *dump = calloc(1, sizeof(*dump));
    if (dump == NULL) {
        return PM3_EMALLOC;
    }
    size_t dump_length = 0;
    int status = loadFileJSON(filename, dump, sizeof(*dump), &dump_length, NULL);
    if (status != PM3_SUCCESS || dump_length != sizeof(*dump)) {
        free(dump);
        return status == PM3_SUCCESS ? PM3_EINVARG : status;
    }

    dfc_credential_clear(credential);
    credential->card.generation = generation_from_dump(dump);
    credential->card.storage = desfire_em_nominal_cardsize(dump->versionhw, dump->versionhwlen);
    credential->card.uid_provenance = DfcUidProvenanceUnknown;
    if (credential->card.generation == 0 || credential->card.storage == 0 ||
            dump->card_info.uidlen == 0 || dump->card_info.uidlen > sizeof(credential->uid)) {
        status = PM3_ENODATA;
        goto out;
    }
    credential->uid_len = dump->card_info.uidlen;
    memcpy(credential->uid, dump->card_info.uid, credential->uid_len);
    credential->picc_has_atqa = true;
    memcpy(credential->picc_atqa, dump->card_info.atqa, 2);
    credential->picc_has_sak = true;
    credential->picc_sak = dump->card_info.sak;
    size_t ats_length = dump->card_info.ats_len;
    if (ats_length > 2 && dump->card_info.ats[0] == ats_length - 2) {
        ats_length -= 2;
    }
    if (ats_length > sizeof(credential->picc_ats)) {
        status = PM3_EOUTOFBOUND;
        goto out;
    }
    credential->picc_ats_len = ats_length;
    memcpy(credential->picc_ats, dump->card_info.ats, ats_length);
    if (dump->signaturelen) {
        if (dump->signaturelen != sizeof(credential->picc_static_signature)) {
            status = PM3_ENODATA;
            goto out;
        }
        credential->picc_has_static_signature = true;
        memcpy(credential->picc_static_signature, dump->signature, dump->signaturelen);
    }
    credential->picc_key_settings_1 = dump->picc.keysettings;
    credential->picc_key_settings_2 = dump->picc.numkeysraw;
    credential->picc_auth_command = dump->picc.keytype == T_AES ? DFC_CMD_AUTHENTICATE_AES :
                                    dump->picc.keytype == T_3K3DES ? DFC_CMD_AUTHENTICATE_ISO :
                                    DFC_CMD_AUTHENTICATE_LEGACY;
    status = import_keys(credential, NULL, &dump->picc);
    if (status != PM3_SUCCESS) {
        goto out;
    }

    for (size_t i = 0; i < dump->appcount; i++) {
        size_t application_index = 0;
        status = import_application(credential, &dump->app[i], &application_index);
        if (status != PM3_SUCCESS) {
            goto out;
        }
        for (size_t j = 0; j < dump->app[i].filecount; j++) {
            status = import_file(credential, application_index, &dump->app[i].files[j]);
            if (status != PM3_SUCCESS) {
                goto out;
            }
        }
    }
    status = dfc_der_validate_model(credential) == DfcDerOk ? PM3_SUCCESS : PM3_EINVARG;

out:
    if (status == PM3_ENODATA) {
        PrintAndLogEx(ERR, "JSON dump is incomplete or contains data DFC cannot represent");
    }
    desfire_dump_free(dump);
    free(dump);
    return status;
}

static uint8_t dump_key_type(uint8_t auth_command) {
    if (auth_command == DFC_CMD_AUTHENTICATE_AES) return T_AES;
    if (auth_command == DFC_CMD_AUTHENTICATE_ISO) return T_3K3DES;
    return T_DES;
}

static int export_keys(
    DfcCredential *credential,
    DfcApplication *application,
    desfire_dump_app_t *destination) {
    size_t count = application ? application->num_keys : credential->picc_num_keys;
    size_t key_length = application ? application->key_len : credential->picc_key_len;
    const uint8_t *versions = application ? application->key_versions : credential->picc_key_versions;
    if (count > DESFIRE_MAX_KEY_COUNT || key_length > DESFIRE_MAX_KEY_SIZE) {
        return PM3_EOUTOFBOUND;
    }
    destination->numkeys = count;
    destination->numkeysraw = application ? application->key_settings_2 : credential->picc_key_settings_2;
    destination->keysettings = application ? application->key_settings_1 : credential->picc_key_settings_1;
    destination->keytype = dump_key_type(
                               application ? application->auth_command : credential->picc_auth_command);
    destination->settings_ok = true;
    for (size_t i = 0; i < count; i++) {
        uint8_t *key = dfc_credential_key(credential, application, i);
        if (key == NULL) return PM3_ENODATA;
        if (destination->keytype == T_DES && key_length == 16 &&
                memcmp(key, key + 8, 8) != 0) {
            return PM3_ENODATA;
        }
        destination->keys.present[i] = true;
        destination->keys.versionknown[i] = true;
        destination->keys.version[i] = versions[i];
        memcpy(destination->keys.key[i], key, key_length);
    }
    return PM3_SUCCESS;
}

static int export_file(
    const DfcCredential *credential,
    const DfcFile *source,
    desfire_dump_file_t *destination) {
    memset(destination, 0, sizeof(*destination));
    destination->num = source->number;
    destination->type = source->type;
    destination->commmode = source->comm_settings;
    destination->accessrights = source->access_rights;
    destination->isofid = source->has_iso_file_id ? source->iso_file_id : 0;
    destination->settings_ok = true;
    destination->read_ok = source->contents_complete;
    if (!source->contents_complete) return PM3_ENODATA;
    if (source->type <= 0x01) {
        destination->size = source->declared_size;
    } else if (source->type == 0x02) {
        destination->lowerlimit = source->value_lower_limit;
        destination->upperlimit = source->value_upper_limit;
        destination->value = source->value;
        destination->limitedcredit = source->limited_credit;
    } else if (source->type <= 0x04) {
        destination->recordsize = source->record_size;
        destination->maxrecords = source->max_records;
        destination->currecords = source->record_count;
    } else {
        return PM3_ENODATA;
    }
    destination->datalen = source->data_len;
    if (source->data_len) {
        destination->data = malloc(source->data_len);
        if (destination->data == NULL) return PM3_EMALLOC;
        memcpy(destination->data, dfc_file_data_const(credential, source), source->data_len);
    }
    return PM3_SUCCESS;
}

static int export_json(const char *filename, DfcCredential *credential) {
    if (credential->num_apps > DESFIRE_MAX_APP_COUNT || credential->uid_len == 0) {
        return PM3_EOUTOFBOUND;
    }
    desfire_dump_t *dump = calloc(1, sizeof(*dump));
    if (dump == NULL) return PM3_EMALLOC;
    dump->card_info.uidlen = credential->uid_len;
    memcpy(dump->card_info.uid, credential->uid, credential->uid_len);
    memcpy(dump->card_info.atqa, credential->picc_atqa, sizeof(dump->card_info.atqa));
    dump->card_info.sak = credential->picc_sak;
    dump->card_info.ats_len = credential->picc_ats_len;
    memcpy(dump->card_info.ats, credential->picc_ats, credential->picc_ats_len);

    uint8_t major = credential->card.generation == DfcGenerationEv1 ? 0x01 :
                    credential->card.generation == DfcGenerationEv2 ? 0x12 : 0x33;
    uint8_t storage_code = 0;
    uint32_t storage = credential->card.storage;
    while (storage > 1) {
        storage >>= 1;
        storage_code += 2;
    }
    uint8_t version[] = {0x04, 0x01, 0x01, major, 0x00, storage_code, 0x05};
    memcpy(dump->versionhw, version, sizeof(version));
    memcpy(dump->versionsw, version, sizeof(version));
    dump->versionhwlen = sizeof(version);
    dump->versionswlen = sizeof(version);
    if (credential->picc_has_static_signature) {
        memcpy(dump->signature, credential->picc_static_signature, sizeof(dump->signature));
        dump->signaturelen = sizeof(dump->signature);
    }
    dump->picc.aid = 0;
    int status = export_keys(credential, NULL, &dump->picc);
    for (size_t i = 0; status == PM3_SUCCESS && i < credential->num_apps; i++) {
        DfcApplication *source = &credential->apps[i];
        desfire_dump_app_t *destination = &dump->app[dump->appcount++];
        destination->aid = source->aid[0] | (source->aid[1] << 8) | (source->aid[2] << 16);
        destination->isofid = source->has_iso_file_id ? source->iso_file_id : 0;
        destination->dfnamelen = source->iso_aid_len;
        memcpy(destination->dfname, source->iso_aid, source->iso_aid_len);
        status = export_keys(credential, source, destination);
        for (size_t j = 0; status == PM3_SUCCESS && j < credential->num_files; j++) {
            DfcFile *file = &credential->files[j];
            if (file->app_index != i) continue;
            if (destination->filecount >= DESFIRE_MAX_FILE_COUNT) {
                status = PM3_EOUTOFBOUND;
                break;
            }
            status = export_file(credential, file, &destination->files[destination->filecount++]);
        }
    }
    if (status == PM3_SUCCESS) {
        status = pm3_save_dump_json(filename, (uint8_t *)dump, sizeof(*dump), jsfMfDesfire_v1);
    } else if (status == PM3_ENODATA) {
        PrintAndLogEx(ERR, "DFC credential contains data the JSON format cannot represent");
    }
    desfire_dump_free(dump);
    free(dump);
    return status;
}

size_t dfc_file_length(const uint8_t *data, size_t capacity) {
    return dfc_der_length(data, capacity);
}

int dfc_file_load(const char *filename, uint8_t *dfcb, size_t capacity, size_t *length) {
    DfcCredential *credential = dfc_credential_alloc();
    if (credential == NULL) {
        return PM3_EMALLOC;
    }
    int status = PM3_SUCCESS;

    if (has_suffix(filename, ".json")) {
        status = import_json(filename, credential);
    } else {
        void *input = NULL;
        size_t input_length = 0;
        status = loadFile_safeEx(filename, "", &input, &input_length, false);
        if (status == PM3_SUCCESS) {
            if (has_suffix(filename, ".dfc")) {
                DfcTextError detail = {0};
                DfcTextStatus parse = dfc_text_parse(
                                          credential, input, input_length, &detail);
                if (parse != DfcTextOk) {
                    PrintAndLogEx(ERR, "DFC line %zu: %s", detail.line, detail.message);
                    status = PM3_EINVARG;
                }
            } else if (dfc_der_decode(credential, input, input_length) != DfcDerOk) {
                PrintAndLogEx(ERR, "Invalid DFCB credential");
                status = PM3_EINVARG;
            }
        }
        free(input);
    }

    if (status == PM3_SUCCESS) {
        DfcDerStatus encoded = dfc_der_encode(credential, dfcb, capacity, length);
        if (encoded != DfcDerOk) {
            PrintAndLogEx(ERR, "Credential does not fit emulator memory: %s", dfc_der_status_name(encoded));
            status = PM3_EOUTOFBOUND;
        }
    }
    dfc_credential_free(credential);
    return status;
}

int dfc_file_save(
    const char *filename,
    const char *format,
    const uint8_t *dfcb,
    size_t length) {
    if (strcmp(format, "dfcb") == 0) {
        return saveFile(filename, ".dfcb", dfcb, length);
    }
    if (strcmp(format, "dfc") != 0 && strcmp(format, "json") != 0) {
        return PM3_EINVARG;
    }

    DfcCredential *credential = dfc_credential_alloc();
    if (credential == NULL) {
        return PM3_EMALLOC;
    }
    int status = PM3_EINVARG;
    if (dfc_der_decode(credential, dfcb, length) != DfcDerOk) {
        dfc_credential_free(credential);
        return status;
    }
    if (strcmp(format, "json") == 0) {
        status = export_json(filename, credential);
    } else {
        size_t text_length = 0;
        if (dfc_text_write(credential, NULL, 0, &text_length) == DfcTextCapacity) {
            char *text = calloc(text_length + 1, 1);
            if (text != NULL &&
                    dfc_text_write(credential, text, text_length + 1, &text_length) == DfcTextOk) {
                status = saveFileTXT(filename, ".dfc", text, text_length, spDump);
            } else {
                status = PM3_EMALLOC;
            }
            free(text);
        }
    }
    dfc_credential_free(credential);
    return status;
}

int dfc_file_print(const uint8_t *dfcb, size_t length, bool verbose) {
    DfcCredential *credential = dfc_credential_alloc();
    if (credential == NULL) return PM3_EMALLOC;
    if (dfc_der_decode(credential, dfcb, length) != DfcDerOk) {
        dfc_credential_free(credential);
        return PM3_EINVARG;
    }
    PrintAndLogEx(INFO, "DFC credential");
    PrintAndLogEx(INFO, "  UID............... %s", sprint_hex_inrow(credential->uid, credential->uid_len));
    PrintAndLogEx(INFO, "  Generation........ EV%u", credential->card.generation);
    PrintAndLogEx(INFO, "  Storage........... %u bytes", credential->card.storage);
    PrintAndLogEx(INFO, "  Applications...... %zu", credential->num_apps);
    PrintAndLogEx(INFO, "  Files............. %zu", credential->num_files);
    PrintAndLogEx(INFO, "  Dirty............. %s", credential->dirty ? "yes" : "no");
    if (verbose) {
        for (size_t i = 0; i < credential->num_apps; i++) {
            const DfcApplication *app = &credential->apps[i];
            PrintAndLogEx(INFO, "  AID %02X%02X%02X, %zu keys",
                          app->aid[0], app->aid[1], app->aid[2], app->num_keys);
            for (size_t j = 0; j < credential->num_files; j++) {
                const DfcFile *file = &credential->files[j];
                if (file->app_index == i) {
                    PrintAndLogEx(INFO, "    file %02X, type %02X, %zu bytes",
                                  file->number, file->type, file->data_len);
                }
            }
        }
    }
    dfc_credential_free(credential);
    return PM3_SUCCESS;
}
