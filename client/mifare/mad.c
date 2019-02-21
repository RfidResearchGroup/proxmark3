//-----------------------------------------------------------------------------
// Copyright (C) 2019 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// MIFARE Application Directory (MAD) functions
//-----------------------------------------------------------------------------

#include "mad.h"
#include "ui.h"

madAIDDescr madKnownAIDs[] = {
	{0x0000, "free"}, 
	{0x0001, "defect, e.g. access keys are destroyed or unknown"},
	{0x0002, "reserved"},
	{0x0003, "contains additional directory info"},
	{0x0004, "contains card holder information in ASCII format."},
	{0x0005, "not applicable (above memory size)}"}
};

int MAD1DecodeAndPrint(uint8_t *sector, bool verbose, bool *haveMAD2) {
	
	return 0;
};

int MAD2DecodeAndPrint(uint8_t *sector, bool verbose) {

	return 0;
};
