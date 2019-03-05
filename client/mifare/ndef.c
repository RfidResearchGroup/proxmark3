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
#include "emv/dump.h"

#define STRBOOL(p) ((p) ? "+" : "-")

static const char *TypeNameFormat_s[] = {
	"Empty Record",
	"Well Known Record",
	"MIME Media Record",
	"Absolute URI Record",
	"External Record",
	"Unknown Record",
	"Unchanged Record"
	"n/a"
};

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

int ndefDecodeHeader(uint8_t *data, size_t datalen, NDEFHeader_t *header) {
	header->MessageBegin	= data[0] & 0x80;
	header->MessageEnd		= data[0] & 0x40;
	header->ChunkFlag		= data[0] & 0x20;
	header->ShortRecordBit	= data[0] & 0x10;
	header->IDLenPresent	= data[0] & 0x08;
	header->TypeNameFormat	= data[0] & 0x07;
	header->len				= 1 + 1 + (header->ShortRecordBit ? 1 : 4) + (header->IDLenPresent ? 1 : 0); // header + typelen + payloadlen + idlen
	if (header->len > datalen)
		return 1;
	
	header->TypeLen			= data[1];
	
	header->PayloadLen		= (header->ShortRecordBit ? (data[2]) : ((data[2] << 24) + (data[3] << 16) + (data[4] << 8) + data[5]));
	
	if (header->IDLenPresent)
		header->IDLen = (header->ShortRecordBit ? (data[3]) : (data[6]));
	else
		header->IDLen = 0;
	
	header->RecLen			= header->len + header->TypeLen + header->PayloadLen + header->IDLen;
	
	if (header->RecLen > datalen)
		return 3;

	return 0;
}

int ndefPrintHeader(NDEFHeader_t *header) {
	PrintAndLogEx(INFO, "Header:");
	
	PrintAndLogEx(NORMAL, "\tMessage Begin:    %s", STRBOOL(header->MessageBegin));
	PrintAndLogEx(NORMAL, "\tMessage End:      %s", STRBOOL(header->MessageEnd));
	PrintAndLogEx(NORMAL, "\tChunk Flag:       %s", STRBOOL(header->ChunkFlag));
	PrintAndLogEx(NORMAL, "\tShort Record Bit: %s", STRBOOL(header->ShortRecordBit));
	PrintAndLogEx(NORMAL, "\tID Len Present:   %s", STRBOOL(header->IDLenPresent));
	PrintAndLogEx(NORMAL, "\tType Name Format: [0x%02x] %s", header->TypeNameFormat, TypeNameFormat_s[header->TypeNameFormat]);

	PrintAndLogEx(NORMAL, "\tHeader length    : %d", header->len);
	PrintAndLogEx(NORMAL, "\tType length      : %d", header->TypeLen);
	PrintAndLogEx(NORMAL, "\tPayload length   : %d", header->PayloadLen);
	PrintAndLogEx(NORMAL, "\tID length        : %d", header->IDLen);
	PrintAndLogEx(NORMAL, "\tRecord length    : %d", header->RecLen);

	return 0;
}

int ndefRecordDecodeAndPrint(uint8_t *ndefRecord, size_t ndefRecordLen) {
	
	NDEFHeader_t NDEFHeader = {0};
	int res = ndefDecodeHeader(ndefRecord, ndefRecordLen, &NDEFHeader);
	if (res)
		return res;
	
	ndefPrintHeader(&NDEFHeader);
	
	size_t indx = NDEFHeader.len;
	if (NDEFHeader.TypeLen) {
		PrintAndLogEx(INFO, "Type data:");
		dump_buffer(&ndefRecord[indx], NDEFHeader.TypeLen, stdout, 1);
		
		indx += NDEFHeader.TypeLen;
	}
	if (NDEFHeader.IDLen) {
		PrintAndLogEx(INFO, "ID data:");
		dump_buffer(&ndefRecord[indx], NDEFHeader.IDLen, stdout, 1);

		indx += NDEFHeader.IDLen;
	}
	if (NDEFHeader.PayloadLen) {
		PrintAndLogEx(INFO, "Payload data:");
		dump_buffer(&ndefRecord[indx], NDEFHeader.PayloadLen, stdout, 1);

		indx += NDEFHeader.PayloadLen;
	}

	return 0;
}

int ndefRecordsDecodeAndPrint(uint8_t *ndefRecord, size_t ndefRecordLen) {
	bool firstRec = true;
	size_t len = 0;
	
	while (len < ndefRecordLen) {
		NDEFHeader_t NDEFHeader = {0};
		int res = ndefDecodeHeader(&ndefRecord[len], ndefRecordLen - len, &NDEFHeader);
		if (res)
			return res;
		
		if (firstRec) {
			if (!NDEFHeader.MessageBegin) {
				PrintAndLogEx(ERR, "NDEF first record have MessageBegin=false!");
				return 1;
			}
			firstRec = false;
		}
		
		if (NDEFHeader.MessageEnd && len + NDEFHeader.RecLen != ndefRecordLen) {
			PrintAndLogEx(ERR, "NDEF records have wrong length. Must be %d, calculated %d", ndefRecordLen, len + NDEFHeader.RecLen);
			return 1;
		}
		
		ndefRecordDecodeAndPrint(&ndefRecord[len], NDEFHeader.RecLen);		
		
		len += NDEFHeader.len + NDEFHeader.TypeLen + NDEFHeader.PayloadLen + NDEFHeader.IDLen;
		
		if (NDEFHeader.MessageEnd)
			break;
	}	
	
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
				
				int res = ndefRecordsDecodeAndPrint(&ndef[indx], len);
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
