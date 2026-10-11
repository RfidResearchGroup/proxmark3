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
// Routines to load the FPGA image, and then to configure the FPGA's major
// mode once it is configured.
//-----------------------------------------------------------------------------
#ifndef __FPGALOADER_H
#define __FPGALOADER_H

#include "common.h"
#include "fpga.h"

int FpgaGetCurrent(void);
const char *FpgaGetCurrentVersionString(void);
void FpgaDownloadAndGo(int bitstream_target);
void FpgaDownloadAndGo_keep_EM(int bitstream_target);
void FpgaResetBitstream(void);
// void FpgaGatherVersion(int bitstream_target, char *dst, int len);

#endif
