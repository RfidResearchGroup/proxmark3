//-----------------------------------------------------------------------------
// Copyright (C) 2019 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// NFC Data Exchange Format (NDEF) functions
//-----------------------------------------------------------------------------

#include "ndef.h"
#include "ui.h"

uint16_t ndefTLVGetLength(uint8_t *data, size_t *indx) {
	uint16_t len = 0;
	if (data[0] == 0xff) {
		len = (data[1] << 8) + data[2];
		*indx += 3;
	} else {
		len = data[0];
		*indx += 1;
	}
	
	return len;
}

int ndefRecordDecodeAndPrint(uint8_t *ndefRecord, size_t ndefRecordLen) {
	
	
	
	
	return 0;
}

int NDEFDecodeAndPrint(uint8_t *ndef, size_t ndefLen, bool verbose) {
	
	size_t indx = 0;
	
	PrintAndLogEx(INFO, "NDEF decoding:");
	while (indx < ndefLen) {
		switch (ndef[indx]) {
			case 0x00: {
				indx++;
				uint16_t len = ndefTLVGetLength(&ndef[indx], &indx);
				PrintAndLogEx(INFO, "-- NDEF NULL block.");
				if (len)
					PrintAndLogEx(WARNING, "NDEF NULL block size must be 0 instead of %d.", len);
				indx += len;
				break;
			}
			case 0x03: {
				indx++;
				uint16_t len = ndefTLVGetLength(&ndef[indx], &indx);
				PrintAndLogEx(INFO, "-- NDEF message. len: %d", len);
				
				int res = ndefRecordDecodeAndPrint(&ndef[indx], len);
				if (res)
					return res;
				
				indx += len;
				break;
			}
			case 0xfd: {
				indx++;
				uint16_t len = ndefTLVGetLength(&ndef[indx], &indx);
				PrintAndLogEx(INFO, "-- NDEF proprietary info. Skipped %d bytes.", len);
				indx += len;
				break;
			}
			case 0xfe: {
				PrintAndLogEx(INFO, "-- NDEF Terminator. Done.");
				return 0;
				break;
			}
			default: {
				PrintAndLogEx(ERR, "unknown tag 0x%02x", ndef[indx]);
				return 1;
			}
		}		
	}
	
	return 0;
}
