//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// iso14443-4 mifare commands
//-----------------------------------------------------------------------------

#include "mifare4.h"
#include <ctype.h>
#include <string.h>
#include "cmdhf14a.h"
#include "util.h"
#include "ui.h"
#include "polarssl/libpcrypto.h"

int CalulateMAC(mf4Session *session, uint8_t *data, int datalen, uint8_t *mac, bool verbose) {
	if (!session || !session->Authenticated || !mac || !data || !datalen)
		return 1;
	
	memset(mac, 0x00, 8);
	
	if (verbose)
		PrintAndLog("MAC data[%d]: %s", datalen, sprint_hex(data, datalen));
	
	return aes_cmac8(NULL, session->Key, data, mac, datalen);
}

int MifareAuth4(mf4Session *session, uint8_t *keyn, uint8_t *key, bool activateField, bool leaveSignalON, bool verbose) {
	uint8_t data[257] = {0};
	int datalen = 0;
	
	uint8_t Rnd1[17] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00};
	uint8_t Rnd2[17] = {0};
	
	if (session)
		session->Authenticated = false;	
	
	uint8_t cmd1[] = {0x70, keyn[1], keyn[0], 0x00};
	int res = ExchangeRAW14a(cmd1, sizeof(cmd1), activateField, true, data, sizeof(data), &datalen);
	if (res) {
		PrintAndLogEx(ERR, "Exchande raw error: %d", res);
		DropField();
		return 2;
	}
	
	if (verbose)
		PrintAndLogEx(INFO, "<phase1: %s", sprint_hex(data, datalen));
		
	if (datalen < 1) {
		PrintAndLogEx(ERR, "Card response wrong length: %d", datalen);
		DropField();
		return 3;
	}
	
	if (data[0] != 0x90) {
		PrintAndLogEx(ERR, "Card response error: %02x", data[2]);
		DropField();
		return 3;
	}

	if (datalen != 19) { // code 1b + 16b + crc 2b
		PrintAndLogEx(ERR, "Card response must be 19 bytes long instead of: %d", datalen);
		DropField();
		return 3;
	}
	
    aes_decode(NULL, key, &data[1], Rnd2, 16);
	Rnd2[16] = Rnd2[0];
	if (verbose)
		PrintAndLogEx(INFO, "Rnd2: %s", sprint_hex(Rnd2, 16));

	uint8_t cmd2[33] = {0};
	cmd2[0] = 0x72;

	uint8_t raw[32] = {0};
	memmove(raw, Rnd1, 16);
	memmove(&raw[16], &Rnd2[1], 16);

	aes_encode(NULL, key, raw, &cmd2[1], 32);
	if (verbose)
		PrintAndLogEx(INFO, ">phase2: %s", sprint_hex(cmd2, 33));
	
	res = ExchangeRAW14a(cmd2, sizeof(cmd2), false, true, data, sizeof(data), &datalen);
	if (res) {
		PrintAndLogEx(ERR, "Exchande raw error: %d", res);
		DropField();
		return 4;
	}
	
	if (verbose)
		PrintAndLogEx(INFO, "<phase2: %s", sprint_hex(data, datalen));

	aes_decode(NULL, key, &data[1], raw, 32);
	
	if (verbose) {
		PrintAndLogEx(INFO, "res: %s", sprint_hex(raw, 32));
		PrintAndLogEx(INFO, "Rnd1`: %s", sprint_hex(&raw[4], 16));
	}

	if (memcmp(&raw[4], &Rnd1[1], 16)) {
		PrintAndLogEx(ERR, "\nAuthentication FAILED. rnd not equal");
		if (verbose) {
			PrintAndLogEx(ERR, "rnd1 reader: %s", sprint_hex(&Rnd1[1], 16));
			PrintAndLogEx(ERR, "rnd1   card: %s", sprint_hex(&raw[4], 16));
		}
		DropField();
		return 5;
	}

	if (!leaveSignalON)
		DropField();

	if (verbose)
		PrintAndLog("");

	if (session) {
		session->Authenticated = true;
		session->KeyNum = keyn[1] + (keyn[0] << 8);
		memmove(session->Rnd1, Rnd1, 16);
		memmove(session->Rnd2, Rnd2, 16);
	}
	
	PrintAndLogEx(INFO, "Authentication OK");
	
	return 0;
}

// Mifare Memory Structure: up to 32 Sectors with 4 blocks each (1k and 2k cards),
// plus evtl. 8 sectors with 16 blocks each (4k cards)
uint8_t mfNumBlocksPerSector(uint8_t sectorNo) {
	if (sectorNo < 32) 
		return 4;
	else
		return 16;
}

uint8_t mfFirstBlockOfSector(uint8_t sectorNo) {
	if (sectorNo < 32)
		return sectorNo * 4;
	else
		return 32 * 4 + (sectorNo - 32) * 16;
}

uint8_t mfSectorTrailer(uint8_t blockNo) {
	if (blockNo < 32*4) {
		return (blockNo | 0x03);
	} else {
		return (blockNo | 0x0f);
	}
}

bool mfIsSectorTrailer(uint8_t blockNo) {
	return (blockNo == mfSectorTrailer(blockNo));
}

uint8_t mfSectorNum(uint8_t blockNo) {
	if (blockNo < 32 * 4)
		return blockNo / 4;
	else
		return 32 + (blockNo - 32 * 4) / 16;
		
}
