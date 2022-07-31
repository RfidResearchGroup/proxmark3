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
// High frequency Electronic Machine Readable Travel Document commands
//-----------------------------------------------------------------------------

#ifndef CMDHFEMRTD_H__
#define CMDHFEMRTD_H__

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct emrtd_dg_s {
    uint8_t tag;
    uint8_t dgnum;
    uint16_t fileid;
    const char *filename;
    const char *desc;
    bool pace;
    bool eac; // EAC only (we can't dump these)
    bool required; // some are required only if PACE
    bool fastdump; // fast to dump
    int (*parser)(uint8_t *data, size_t datalen);
    int (*dumper)(uint8_t *data, size_t datalen, const char *path);
} emrtd_dg_t;

typedef struct emrtd_hashalg_s {
    const char *name;
    int (*hasher)(uint8_t *datain, int datainlen, uint8_t *dataout);
    size_t hashlen;
    size_t descriptorlen;
    const uint8_t descriptor[15];
} emrtd_hashalg_t;

typedef struct emrtd_pacealg_s {
    const char *name;
    int (*keygenerator)(uint8_t *datain, int datainlen, uint8_t *dataout);
    const uint8_t descriptor[10];
} emrtd_pacealg_t;

// Standardized Domain Parameters
typedef struct emrtd_pacesdp_s {
    uint8_t id;
    const char *name;
    size_t size;
} emrtd_pacesdp_t;

int CmdHFeMRTD(const char *Cmd);

int dumpHF_EMRTD(char *documentnumber, char *dob, char *expiry, bool BAC_available, const char *path);
int infoHF_EMRTD(char *documentnumber, char *dob, char *expiry, bool BAC_available, bool only_fast);
int infoHF_EMRTD_offline(const char *path);

#ifdef __cplusplus
}
#endif
#endif
