//-----------------------------------------------------------------------------
// Copyright (C) 2020 A. Ozkal
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Electronic Machine Readable Travel Document commands
//-----------------------------------------------------------------------------

#ifndef CMDHFEMRTD_H__
#define CMDHFEMRTD_H__

#include "common.h"

typedef struct emrtd_dg_s {
    uint8_t tag;
    uint8_t dgnum;
    const char *fileid;
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

int CmdHFeMRTD(const char *Cmd);

int dumpHF_EMRTD(char *documentnumber, char *dob, char *expiry, bool BAC_available, const char *path);
int infoHF_EMRTD(char *documentnumber, char *dob, char *expiry, bool BAC_available);
int infoHF_EMRTD_offline(const char *path);
#endif
