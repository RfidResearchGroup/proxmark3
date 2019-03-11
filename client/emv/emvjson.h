//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// EMV json logic
//-----------------------------------------------------------------------------
#ifndef EMVJSON_H__
#define EMVJSON_H__

#include <jansson.h>
#include "tlv.h"

typedef struct {
    tlv_tag_t Tag;
    char *Name;
} ApplicationDataElm;

extern char *GetApplicationDataName(tlv_tag_t tag);

extern int JsonSaveJsonObject(json_t *root, char *path, json_t *value);
extern int JsonSaveStr(json_t *root, char *path, char *value);
extern int JsonSaveInt(json_t *root, char *path, int value);
extern int JsonSaveBufAsHexCompact(json_t *elm, char *path, uint8_t *data, size_t datalen);
extern int JsonSaveBufAsHex(json_t *elm, char *path, uint8_t *data, size_t datalen);
extern int JsonSaveHex(json_t *elm, char *path, uint64_t data, int datalen);

extern int JsonSaveTLVValue(json_t *root, char *path, struct tlvdb *tlvdbelm);
extern int JsonSaveTLVElm(json_t *elm, char *path, struct tlv *tlvelm, bool saveName, bool saveValue, bool saveAppDataLink);
extern int JsonSaveTLVTreeElm(json_t *elm, char *path, struct tlvdb *tlvdbelm, bool saveName, bool saveValue, bool saveAppDataLink);

extern int JsonSaveTLVTree(json_t *root, json_t *elm, char *path, struct tlvdb *tlvdbelm);

extern int JsonLoadStr(json_t *root, char *path, char *value);
extern int JsonLoadBufAsHex(json_t *elm, char *path, uint8_t *data, size_t maxbufferlen, size_t *datalen);

extern bool ParamLoadFromJson(struct tlvdb *tlv);

#endif
