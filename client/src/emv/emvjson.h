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
// EMV json logic
//-----------------------------------------------------------------------------
#ifndef EMVJSON_H__
#define EMVJSON_H__

#include "common.h"

#include "jansson.h"
#include "jansson_path.h"
#include "tlv.h"

typedef struct {
    tlv_tag_t Tag;
    const char *Name;
} ApplicationDataElm_t;

const char *GetApplicationDataName(tlv_tag_t tag);

int JsonSaveJsonObject(json_t *root, const char *path, json_t *value);
int JsonSaveStr(json_t *root, const char *path, const char *value);
int JsonSaveBoolean(json_t *root, const char *path, bool value);
int JsonSaveInt(json_t *root, const char *path, int value);
int JsonSaveBufAsHexCompact(json_t *elm, const char *path, uint8_t *data, size_t datalen);
int JsonSaveBufAsHex(json_t *elm, const char *path, uint8_t *data, size_t datalen);
int JsonSaveHex(json_t *elm, const char *path, uint64_t data, int datalen);

int JsonSaveTLVValue(json_t *root, const char *path, struct tlvdb *tlvdbelm);
int JsonSaveTLVElm(json_t *elm, const char *path, struct tlv *tlvelm, bool saveName, bool saveValue, bool saveAppDataLink);
int JsonSaveTLVTreeElm(json_t *elm, const char *path, struct tlvdb *tlvdbelm, bool saveName, bool saveValue, bool saveAppDataLink);

int JsonSaveTLVTree(json_t *root, json_t *elm, const char *path, struct tlvdb *tlvdbelm);

int JsonLoadStr(json_t *root, const char *path, char *value);
int JsonLoadBufAsHex(json_t *elm, const char *path, uint8_t *data, size_t maxbufferlen, size_t *datalen);

bool ParamLoadFromJson(struct tlvdb *tlv);

#endif
