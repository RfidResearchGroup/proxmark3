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
    const char *fileid;
    const char *filename;
    const char *desc;
    bool required;
    int (*parser)(uint8_t *data, size_t datalen);
    int (*dumper)(uint8_t *data, size_t datalen);
    bool fastdump;
} emrtd_dg_t;

int CmdHFeMRTD(const char *Cmd);

int dumpHF_EMRTD(char *documentnumber, char *dob, char *expiry, bool BAC_available);
int infoHF_EMRTD(char *documentnumber, char *dob, char *expiry, bool BAC_available);
int infoHF_EMRTD_offline(const char *path);
#endif
