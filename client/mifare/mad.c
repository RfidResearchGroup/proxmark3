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
	
	uint8_t GPB = sector[3 * 16 + 9];
	PrintAndLogEx(NORMAL, "GPB: 0x%02x", GPB);
	
	// DA (MAD available)
	if (!(GPB & 0x80)) {
		PrintAndLogEx(ERR, "DA=0! MAD not available.");
		return 1;
	}
	
	// MA (multi-application card)
	if (GPB & 0x40)
		PrintAndLogEx(NORMAL, "Multi application card.");
	else
		PrintAndLogEx(NORMAL, "Single application card.");
	
	uint8_t MADVer = GPB & 0x03;
	
	//  MAD version
	if ((MADVer != 0x01) && (MADVer != 0x02)) {
		PrintAndLogEx(ERR, "Wrong MAD version: 0x%02x", MADVer);
		return 2;
	};
	
	if (haveMAD2)
		*haveMAD2 = (MADVer == 2);
	
	
	
	
	
	
	return 0;
};

int MAD2DecodeAndPrint(uint8_t *sector, bool verbose) {

	return 0;
};
