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
// Routines to support the German electronic "Personalausweis" (ID card)
//-----------------------------------------------------------------------------

#ifndef __EPA_H
#define __EPA_H

#include "common.h"
#include "pm3_cmd.h"

// this struct is used by EPA_Parse_CardAccess and contains info about the
// PACE protocol supported by the chip
typedef struct {
    uint8_t oid[10];
    uint8_t version;
    uint8_t parameter_id;
} pace_version_info_t;

// general functions
void EPA_Finish(void);
size_t EPA_Parse_CardAccess(uint8_t *data,
                            size_t length,
                            pace_version_info_t *pace_info);
int EPA_Read_CardAccess(uint8_t *buffer, size_t max_length);
int EPA_Setup(void);

// PACE related functions
int EPA_PACE_MSE_Set_AT(pace_version_info_t pace_version_info, uint8_t password);
int EPA_PACE_Get_Nonce(uint8_t requested_length, uint8_t *nonce);

void EPA_PACE_Collect_Nonce(PacketCommandNG *c);
void EPA_PACE_Replay(PacketCommandNG *c);

#endif /* __EPA_H */
