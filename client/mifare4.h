//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// iso14443-4 mifare commands
//-----------------------------------------------------------------------------

#ifndef MIFARE4_H
#define MIFARE4_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
	bool Authenticated;
	uint8_t Key[16];
	uint16_t KeyNum;
	uint8_t Rnd1[16];
	uint8_t Rnd2[16];
	
}mf4Session;

extern int CalulateMAC(mf4Session *session, uint8_t *data, int datalen, uint8_t *mac, bool verbose);
extern int MifareAuth4(mf4Session *session, uint8_t *keyn, uint8_t *key, bool activateField, bool leaveSignalON, bool verbose);

extern uint8_t mfNumBlocksPerSector(uint8_t sectorNo);
extern uint8_t mfFirstBlockOfSector(uint8_t sectorNo);
extern uint8_t mfSectorTrailer(uint8_t blockNo);
extern bool mfIsSectorTrailer(uint8_t blockNo);
extern uint8_t mfSectorNum(uint8_t blockNo);


#endif // mifare4.h
