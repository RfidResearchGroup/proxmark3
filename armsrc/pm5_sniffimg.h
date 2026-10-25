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
// Proxmark5 14a sniffer FPGA image, embedded and loaded into FPGA SRAM
//-----------------------------------------------------------------------------
#ifndef PM5_SNIFFIMG_H__
#define PM5_SNIFFIMG_H__

#include "common.h"

#ifdef PM5_SNIFF_EMBED

// Load the sniffer image into FPGA SRAM, unless it is there already. False when the FPGA does not run it:
// the load failed (the image in the FPGA's flash is back) or `hw fpga config -s` loaded another one.
bool Pm5SniffImgLoad(void);

// Reload the image from the FPGA's own flash if the sniffer image is loaded and not kept.
void Pm5SniffImgRestore(void);

// Keep whatever SRAM image is loaded through the FpgaDownloadAndGo() calls that follow.
void Pm5SniffImgKeep(bool keep);

// `hw fpga config` started: the SRAM image is the user's from now on (sram), or the one in the flash.
void Pm5SniffImgUserConfig(bool sram);

// `hw sethfthresh`: remembered, and sent again after each image switch.
void Pm5SniffImgSetThresholds(uint16_t value);

#endif

#endif
