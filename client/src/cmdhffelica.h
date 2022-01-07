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
// High frequency ISO 18002 / FeliCa commands
//-----------------------------------------------------------------------------

#ifndef CMDHFFELICA_H__
#define CMDHFFELICA_H__

#include "common.h"
#include "iso18.h"

int CmdHFFelica(const char *Cmd);
int read_felica_uid(bool loop, bool verbose);
int send_request_service(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose);
int send_rd_plain(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose, felica_read_without_encryption_response_t *rd_noCry_resp);

#endif
