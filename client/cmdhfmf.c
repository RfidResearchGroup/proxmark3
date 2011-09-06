//-----------------------------------------------------------------------------
// Copyright (C) 2011 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE commands
//-----------------------------------------------------------------------------

#include "cmdhfmf.h"
#include "proxmark3.h"

static int CmdHelp(const char *Cmd);

int CmdHF14AMifare(const char *Cmd)
{
	uint32_t uid = 0;
	uint32_t nt = 0;
	uint64_t par_list = 0, ks_list = 0, r_key = 0;
	uint8_t isOK = 0;
	uint8_t keyBlock[6] = {0,0,0,0,0,0};
	
	if (param_getchar(Cmd, 0) && param_gethex(Cmd, 0, keyBlock, 8)) {
		PrintAndLog("Nt must include 8 HEX symbols");
		return 1;
	}
	
	UsbCommand c = {CMD_READER_MIFARE, {(uint32_t)bytes_to_num(keyBlock, 4), 0, 0}};
	SendCommand(&c);
	
	//flush queue
	while (ukbhit())	getchar();

	// message
	printf("-------------------------------------------------------------------------\n");
	printf("Executing command. It may take up to 30 min.\n");
	printf("Press the key on proxmark3 device to abort proxmark3.\n");
	printf("Press the key on the proxmark3 device to abort both proxmark3 and client.\n");
	printf("-------------------------------------------------------------------------\n");
	
	// wait cycle
	while (true) {
		printf(".");
		if (ukbhit()) {
			getchar();
			printf("\naborted via keyboard!\n");
			break;
		}
		
		UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 2000);
		if (resp != NULL) {
			isOK  = resp->arg[0] & 0xff;
	
			uid = (uint32_t)bytes_to_num(resp->d.asBytes +  0, 4);
			nt =  (uint32_t)bytes_to_num(resp->d.asBytes +  4, 4);
			par_list = bytes_to_num(resp->d.asBytes +  8, 8);
			ks_list = bytes_to_num(resp->d.asBytes +  16, 8);
	
			printf("\n\n");
			PrintAndLog("isOk:%02x", isOK);
			if (!isOK) PrintAndLog("Proxmark can't get statistic info. Execution aborted.\n");
			break;
		}
	}	
	printf("\n");
	
	// error
	if (isOK != 1) return 1;
	
	// execute original function from util nonce2key
	if (nonce2key(uid, nt, par_list, ks_list, &r_key)) return 2;
	printf("------------------------------------------------------------------\n");
	PrintAndLog("Key found:%012llx \n", r_key);

	num_to_bytes(r_key, 6, keyBlock);
	isOK = mfCheckKeys(0, 0, 1, keyBlock, &r_key);
	if (!isOK) 
		PrintAndLog("Found valid key:%012llx", r_key);
	else
		PrintAndLog("Found invalid key. ( Nt=%08x", nt);	
	
	
	return 0;
}

int CmdHF14AMfWrBl(const char *Cmd)
{
	uint8_t blockNo = 0;
	uint8_t keyType = 0;
	uint8_t key[6] = {0, 0, 0, 0, 0, 0};
	uint8_t bldata[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	
	char cmdp	= 0x00;

	if (strlen(Cmd)<3) {
		PrintAndLog("Usage:  hf mf wrbl    <block number> <key A/B> <key (12 hex symbols)> <block data (32 hex symbols)>");
		PrintAndLog("        sample: hf mf wrbl 0 A FFFFFFFFFFFF 000102030405060708090A0B0C0D0E0F");
		return 0;
	}	

	blockNo = param_get8(Cmd, 0);
	cmdp = param_getchar(Cmd, 1);
	if (cmdp == 0x00) {
		PrintAndLog("Key type must be A or B");
		return 1;
	}
	if (cmdp != 'A' && cmdp != 'a') keyType = 1;
	if (param_gethex(Cmd, 2, key, 12)) {
		PrintAndLog("Key must include 12 HEX symbols");
		return 1;
	}
	if (param_gethex(Cmd, 3, bldata, 32)) {
		PrintAndLog("Block data must include 32 HEX symbols");
		return 1;
	}
	PrintAndLog("--block no:%02x key type:%02x key:%s", blockNo, keyType, sprint_hex(key, 6));
	PrintAndLog("--data: %s", sprint_hex(bldata, 16));
	
  UsbCommand c = {CMD_MIFARE_WRITEBL, {blockNo, keyType, 0}};
	memcpy(c.d.asBytes, key, 6);
	memcpy(c.d.asBytes + 10, bldata, 16);
  SendCommand(&c);
	UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 1500);

	if (resp != NULL) {
		uint8_t                isOK  = resp->arg[0] & 0xff;

		PrintAndLog("isOk:%02x", isOK);
	} else {
		PrintAndLog("Command execute timeout");
	}

	return 0;
}

int CmdHF14AMfRdBl(const char *Cmd)
{
	uint8_t blockNo = 0;
	uint8_t keyType = 0;
	uint8_t key[6] = {0, 0, 0, 0, 0, 0};
	
	char cmdp	= 0x00;


	if (strlen(Cmd)<3) {
		PrintAndLog("Usage:  hf mf rdbl    <block number> <key A/B> <key (12 hex symbols)>");
		PrintAndLog("        sample: hf mf rdbl 0 A FFFFFFFFFFFF ");
		return 0;
	}	
	
	blockNo = param_get8(Cmd, 0);
	cmdp = param_getchar(Cmd, 1);
	if (cmdp == 0x00) {
		PrintAndLog("Key type must be A or B");
		return 1;
	}
	if (cmdp != 'A' && cmdp != 'a') keyType = 1;
	if (param_gethex(Cmd, 2, key, 12)) {
		PrintAndLog("Key must include 12 HEX symbols");
		return 1;
	}
	PrintAndLog("--block no:%02x key type:%02x key:%s ", blockNo, keyType, sprint_hex(key, 6));
	
  UsbCommand c = {CMD_MIFARE_READBL, {blockNo, keyType, 0}};
	memcpy(c.d.asBytes, key, 6);
  SendCommand(&c);
	UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 1500);

	if (resp != NULL) {
		uint8_t                isOK  = resp->arg[0] & 0xff;
		uint8_t              * data  = resp->d.asBytes;

		if (isOK)
			PrintAndLog("isOk:%02x data:%s", isOK, sprint_hex(data, 16));
		else
			PrintAndLog("isOk:%02x", isOK);
	} else {
		PrintAndLog("Command execute timeout");
	}

  return 0;
}

int CmdHF14AMfRdSc(const char *Cmd)
{
	int i;
	uint8_t sectorNo = 0;
	uint8_t keyType = 0;
	uint8_t key[6] = {0, 0, 0, 0, 0, 0};
	
	uint8_t isOK  = 0;
	uint8_t * data  = NULL;

	char cmdp	= 0x00;

	if (strlen(Cmd)<3) {
		PrintAndLog("Usage:  hf mf rdsc    <sector number> <key A/B> <key (12 hex symbols)>");
		PrintAndLog("        sample: hf mf rdsc 0 A FFFFFFFFFFFF ");
		return 0;
	}	
	
	sectorNo = param_get8(Cmd, 0);
	if (sectorNo > 63) {
		PrintAndLog("Sector number must be less than 64");
		return 1;
	}
	cmdp = param_getchar(Cmd, 1);
	if (cmdp == 0x00) {
		PrintAndLog("Key type must be A or B");
		return 1;
	}
	if (cmdp != 'A' && cmdp != 'a') keyType = 1;
	if (param_gethex(Cmd, 2, key, 12)) {
		PrintAndLog("Key must include 12 HEX symbols");
		return 1;
	}
	PrintAndLog("--sector no:%02x key type:%02x key:%s ", sectorNo, keyType, sprint_hex(key, 6));
	
  UsbCommand c = {CMD_MIFARE_READSC, {sectorNo, keyType, 0}};
	memcpy(c.d.asBytes, key, 6);
  SendCommand(&c);
	UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 1500);
	PrintAndLog(" ");

	if (resp != NULL) {
		isOK  = resp->arg[0] & 0xff;
		data  = resp->d.asBytes;

		PrintAndLog("isOk:%02x", isOK);
		if (isOK) 
			for (i = 0; i < 2; i++) {
				PrintAndLog("data:%s", sprint_hex(data + i * 16, 16));
			}
	} else {
		PrintAndLog("Command1 execute timeout");
	}

		// response2
	resp = WaitForResponseTimeout(CMD_ACK, 500);
	PrintAndLog(" ");

	if (resp != NULL) {
		isOK  = resp->arg[0] & 0xff;
		data  = resp->d.asBytes;

		if (isOK) 
			for (i = 0; i < 2; i++) {
				PrintAndLog("data:%s", sprint_hex(data + i * 16, 16));
		}
	} else {
		PrintAndLog("Command2 execute timeout");
	}
	
  return 0;
}

int CmdHF14AMfDump1k(const char *Cmd)
{
	int i, j;
	
	uint8_t keyType = 0;
	uint8_t c[3][4];
	uint8_t keyA[16][6];
	uint8_t keyB[16][6];
	uint8_t rights[16][4];
	
	uint8_t isOK  = 0;
	uint8_t *data  = NULL;

	FILE *fin;
	FILE *fout;
	
	UsbCommand *resp;
	
	if ((fin = fopen("dumpkeys.bin","rb")) == NULL) {
		PrintAndLog("Could not find file keys.bin");
		return 1;
	}
	
	if ((fout = fopen("dumpdata.bin","wb")) == NULL) { 
		PrintAndLog("Could not create file name dump.bin");
		return 1;
	}
	
	// Read key file
	
	for (i=0 ; i<16 ; i++) {
		fread ( keyA[i], 1, 6, fin );
	}
	for (i=0 ; i<16 ; i++) {
		fread ( keyB[i], 1, 6, fin );
	}
	
	// Read access rights to sectors
	
	PrintAndLog("|-----------------------------------------|");
	PrintAndLog("|------ Reading sector access bits...-----|");
	PrintAndLog("|-----------------------------------------|");
	
	for (i = 0 ; i < 16 ; i++) {
		UsbCommand c = {CMD_MIFARE_READBL, {4*i + 3, 0, 0}};
		memcpy(c.d.asBytes, keyA[i], 6);
		SendCommand(&c);
		resp = WaitForResponseTimeout(CMD_ACK, 1500);

		if (resp != NULL) {
			uint8_t isOK  = resp->arg[0] & 0xff;
			uint8_t *data  = resp->d.asBytes;
			if (isOK){
				rights[i][0] = ((data[7] & 0x10)>>4) | ((data[8] & 0x1)<<1) | ((data[8] & 0x10)>>2);
				rights[i][1] = ((data[7] & 0x20)>>5) | ((data[8] & 0x2)<<0) | ((data[8] & 0x20)>>3);
				rights[i][2] = ((data[7] & 0x40)>>6) | ((data[8] & 0x4)>>1) | ((data[8] & 0x40)>>4);
				rights[i][3] = ((data[7] & 0x80)>>7) | ((data[8] & 0x8)>>2) | ((data[8] & 0x80)>>5);
				}
			else{
				PrintAndLog("Could not get access rights for block %d", i);
			}
		}
		else {
			PrintAndLog("Command execute timeout");
		}
	}
	
	// Read blocks and print to file
	
	PrintAndLog("|-----------------------------------------|");
	PrintAndLog("|----- Dumping all blocks to file... -----|");
	PrintAndLog("|-----------------------------------------|");
	
	for (i=0 ; i<16 ; i++) {
		for (j=0 ; j<4 ; j++) {
			if (j == 3){
				UsbCommand c = {CMD_MIFARE_READBL, {i*4 + j, 0, 0}};
				memcpy(c.d.asBytes, keyA[i], 6);
				SendCommand(&c);
				resp = WaitForResponseTimeout(CMD_ACK, 1500);
			}
			else{
				if ((rights[i][j] == 6) | (rights[i][j] == 5)) {
					UsbCommand c = {CMD_MIFARE_READBL, {i*4+j, 1, 0}};
					memcpy(c.d.asBytes, keyB[i], 6);
					SendCommand(&c);
					resp = WaitForResponseTimeout(CMD_ACK, 1500);
				}
				else if (rights[i][j] == 7) {
					PrintAndLog("Access rights do not allow reading of sector %d block %d",i,j);
				}
				else {
					UsbCommand c = {CMD_MIFARE_READBL, {i*4+j, 0, 0}};
					memcpy(c.d.asBytes, keyA[i], 6);
					SendCommand(&c);
					resp = WaitForResponseTimeout(CMD_ACK, 1500);
				}
			}

			if (resp != NULL) {
				uint8_t isOK  = resp->arg[0] & 0xff;
				uint8_t *data  = resp->d.asBytes;
				if (j == 3) {
					data[0]  = (keyA[i][0]);
					data[1]  = (keyA[i][1]);
					data[2]  = (keyA[i][2]);
					data[3]  = (keyA[i][3]);
					data[4]  = (keyA[i][4]);
					data[5]  = (keyA[i][5]);
					data[10] = (keyB[i][0]);
					data[11] = (keyB[i][1]);
					data[12] = (keyB[i][2]);
					data[13] = (keyB[i][3]);
					data[14] = (keyB[i][4]);
					data[15] = (keyB[i][5]);
				}
				if (isOK) {
					fwrite ( data, 1, 16, fout );
				}
				else {
					PrintAndLog("Could not get access rights for block %d", i);
				}
			}
			else {
				PrintAndLog("Command execute timeout");
			}
		}
	}
	
	fclose(fin);
	fclose(fout);
	
  return 0;
}

int CmdHF14AMfRestore1k(const char *Cmd)
{

	int i,j;
	uint8_t keyType = 0;
	uint8_t key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	uint8_t bldata[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	uint8_t keyA[16][6];
	uint8_t keyB[16][6];
	
	FILE *fdump;
	FILE *fkeys;
	
	char ch;
	
	if ((fdump = fopen("dumpdata.bin","rb")) == NULL) {
		PrintAndLog("Could not find file dump.bin");
		return 1;
	}
	if ((fkeys = fopen("dumpkeys.bin","rb")) == NULL) {
		PrintAndLog("Could not find file keys.bin");
		return 1;
	}
	
	for (i=0 ; i<16 ; i++) {
		fread(keyA[i], 1, 6, fkeys);
	}
	for (i=0 ; i<16 ; i++) {
		fread(keyB[i], 1, 6, fkeys);
	}
	
	PrintAndLog("Restoring dumpdata.bin to card");

	for (i=0 ; i<16 ; i++) {
		for( j=0 ; j<4 ; j++) {
			UsbCommand c = {CMD_MIFARE_WRITEBL, {i*4 + j, keyType, 0}};
			memcpy(c.d.asBytes, key, 6);
			
			fread(bldata, 1, 16, fdump);
					
			if (j == 3) {
				bldata[0]  = (keyA[i][0]);
				bldata[1]  = (keyA[i][1]);
				bldata[2]  = (keyA[i][2]);
				bldata[3]  = (keyA[i][3]);
				bldata[4]  = (keyA[i][4]);
				bldata[5]  = (keyA[i][5]);
				bldata[10] = (keyB[i][0]);
				bldata[11] = (keyB[i][1]);
				bldata[12] = (keyB[i][2]);
				bldata[13] = (keyB[i][3]);
				bldata[14] = (keyB[i][4]);
				bldata[15] = (keyB[i][5]);
			}		
			
			PrintAndLog("Writing to block %2d: %s Confirm? [Y,N]", i*4+j, sprint_hex(bldata, 16));
			
			scanf("%c",&ch);
			if ((ch != 'y') || (ch != 'Y')){
				PrintAndLog("Aborting !");
				return 1;
			}
			
			memcpy(c.d.asBytes + 10, bldata, 16);
			SendCommand(&c);
			UsbCommand *resp = WaitForResponseTimeout(CMD_ACK, 1500);

			if (resp != NULL) {
				uint8_t isOK  = resp->arg[0] & 0xff;
				PrintAndLog("isOk:%02x", isOK);
			} else {
				PrintAndLog("Command execute timeout");
			}
		}
	}
	
	fclose(fdump);
	fclose(fkeys);
	return 0;
}

int CmdHF14AMfNested(const char *Cmd)
{
	int i, j, res, iterations;
	sector	*	e_sector = NULL;
	uint8_t blockNo = 0;
	uint8_t keyType = 0;
	uint8_t trgBlockNo = 0;
	uint8_t trgKeyType = 0;
	uint8_t blDiff = 0;
	int  SectorsCnt = 0;
	uint8_t key[6] = {0, 0, 0, 0, 0, 0};
	uint8_t keyBlock[16 * 6];
	uint64_t key64 = 0;
	int transferToEml = 0;
	
	int createDumpFile = 0;
	FILE *fkeys;
	uint8_t standart[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	uint8_t tempkey[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	
	char cmdp, ctmp;

	if (strlen(Cmd)<3) {
		PrintAndLog("Usage:");
		PrintAndLog(" all sectors:  hf mf nested  <card memory> <block number> <key A/B> <key (12 hex symbols)> [t,d]");
		PrintAndLog(" one sector:   hf mf nested  o <block number> <key A/B> <key (12 hex symbols)>");
		PrintAndLog("               <target block number> <target key A/B> [t]");
		PrintAndLog("card memory - 0 - MINI(320 bytes), 1 - 1K, 2 - 2K, 4 - 4K, <other> - 1K");
		PrintAndLog("t - transfer keys into emulator memory");
		PrintAndLog("d - write keys to binary file");
		PrintAndLog(" ");
		PrintAndLog("      sample1: hf mf nested 1 0 A FFFFFFFFFFFF ");
		PrintAndLog("      sample1: hf mf nested 1 0 A FFFFFFFFFFFF t ");
		PrintAndLog("      sample1: hf mf nested 1 0 A FFFFFFFFFFFF d ");
		PrintAndLog("      sample2: hf mf nested o 0 A FFFFFFFFFFFF 4 A");
		return 0;
	}	
	
	cmdp = param_getchar(Cmd, 0);
	blockNo = param_get8(Cmd, 1);
	ctmp = param_getchar(Cmd, 2);
	if (ctmp == 0x00) {
		PrintAndLog("Key type must be A or B");
		return 1;
	}
	if (ctmp != 'A' && ctmp != 'a') keyType = 1;
	if (param_gethex(Cmd, 3, key, 12)) {
		PrintAndLog("Key must include 12 HEX symbols");
		return 1;
	}
	
	if (cmdp == 'o' || cmdp == 'O') {
		cmdp = 'o';
		trgBlockNo = param_get8(Cmd, 4);
		ctmp = param_getchar(Cmd, 5);
		if (ctmp == 0x00) {
			PrintAndLog("Target key type must be A or B");
			return 1;
		}
		if (ctmp != 'A' && ctmp != 'a') trgKeyType = 1;
	} else {
		switch (cmdp) {
			case '0': SectorsCnt = 05; break;
			case '1': SectorsCnt = 16; break;
			case '2': SectorsCnt = 32; break;
			case '4': SectorsCnt = 64; break;
			default:  SectorsCnt = 16;
		}
	}

	ctmp = param_getchar(Cmd, 4);
	if		(ctmp == 't' || ctmp == 'T') transferToEml = 1;
	else if (ctmp == 'd' || ctmp == 'D') createDumpFile = 1;
	
	ctmp = param_getchar(Cmd, 6);
	transferToEml |= (ctmp == 't' || ctmp == 'T');
	transferToEml |= (ctmp == 'd' || ctmp == 'D');
	
	PrintAndLog("--block no:%02x key type:%02x key:%s etrans:%d", blockNo, keyType, sprint_hex(key, 6), transferToEml);
	if (cmdp == 'o')
		PrintAndLog("--target block no:%02x target key type:%02x ", trgBlockNo, trgKeyType);

	if (cmdp == 'o') {
		if (mfnested(blockNo, keyType, key, trgBlockNo, trgKeyType, keyBlock)) {
			PrintAndLog("Nested error.");
			return 2;
		}

		for (i = 0; i < 16; i++) {
			PrintAndLog("cnt=%d key= %s", i, sprint_hex(keyBlock + i * 6, 6));
		}
	
		// test keys
		res = mfCheckKeys(trgBlockNo, trgKeyType, 8, keyBlock, &key64);
		if (res)
			res = mfCheckKeys(trgBlockNo, trgKeyType, 8, &keyBlock[6 * 8], &key64);
		if (!res) {
			PrintAndLog("Found valid key:%012llx", key64);

			// transfer key to the emulator
			if (transferToEml) {
				mfEmlGetMem(keyBlock, (trgBlockNo / 4) * 4 + 3, 1);
		
				if (!trgKeyType)
					num_to_bytes(key64, 6, keyBlock);
				else
					num_to_bytes(key64, 6, &keyBlock[10]);
				mfEmlSetMem(keyBlock, (trgBlockNo / 4) * 4 + 3, 1);		
			}
		} else {
			PrintAndLog("No valid key found");
		}
	}
	else { // ------------------------------------  multiple sectors working
		blDiff = blockNo % 4;
		PrintAndLog("Block shift=%d", blDiff);
		e_sector = calloc(SectorsCnt, sizeof(sector));
		if (e_sector == NULL) return 1;
		
		//test current key 4 sectors
		memcpy(keyBlock, key, 6);
		num_to_bytes(0xa0a1a2a3a4a5, 6, (uint8_t*)(keyBlock + 1 * 6));
		num_to_bytes(0xb0b1b2b3b4b5, 6, (uint8_t*)(keyBlock + 2 * 6));
		num_to_bytes(0xffffffffffff, 6, (uint8_t*)(keyBlock + 3 * 6));
		num_to_bytes(0x000000000000, 6, (uint8_t*)(keyBlock + 4 * 6));
		num_to_bytes(0xaabbccddeeff, 6, (uint8_t*)(keyBlock + 5 * 6));

		PrintAndLog("Testing known keys. Sector count=%d", SectorsCnt);
		for (i = 0; i < SectorsCnt; i++) {
			for (j = 0; j < 2; j++) {
				if (e_sector[i].foundKey[j]) continue;
				
				res = mfCheckKeys(i * 4 + blDiff, j, 6, keyBlock, &key64);
				
				if (!res) {
					e_sector[i].Key[j] = key64;
					e_sector[i].foundKey[j] = 1;
				}
			}
		} 
		
		// nested sectors
		iterations = 0;
		PrintAndLog("nested...");
		for (i = 0; i < NESTED_SECTOR_RETRY; i++) {
			for (trgBlockNo = blDiff; trgBlockNo < SectorsCnt * 4; trgBlockNo = trgBlockNo + 4) 
				for (trgKeyType = 0; trgKeyType < 2; trgKeyType++) { 
					if (e_sector[trgBlockNo / 4].foundKey[trgKeyType]) continue;
					if (mfnested(blockNo, keyType, key, trgBlockNo, trgKeyType, keyBlock)) continue;
					
					iterations++;
					
					//try keys from nested
					res = mfCheckKeys(trgBlockNo, trgKeyType, 8, keyBlock, &key64);
					if (res)
						res = mfCheckKeys(trgBlockNo, trgKeyType, 8, &keyBlock[6 * 8], &key64);
					if (!res) {
						PrintAndLog("Found valid key:%012llx", key64);	
						e_sector[trgBlockNo / 4].foundKey[trgKeyType] = 1;
						e_sector[trgBlockNo / 4].Key[trgKeyType] = key64;
					}
				}
		}

		PrintAndLog("Iterations count: %d", iterations);
		//print them
		PrintAndLog("|---|----------------|---|----------------|---|");
		PrintAndLog("|sec|key A           |res|key B           |res|");
		PrintAndLog("|---|----------------|---|----------------|---|");
		for (i = 0; i < SectorsCnt; i++) {
			PrintAndLog("|%03d|  %012llx  | %d |  %012llx  | %d |", i, 
				e_sector[i].Key[0], e_sector[i].foundKey[0], e_sector[i].Key[1], e_sector[i].foundKey[1]);
		}
		PrintAndLog("|---|----------------|---|----------------|---|");
		
		// transfer them to the emulator
		if (transferToEml) {
			for (i = 0; i < SectorsCnt; i++) {
				mfEmlGetMem(keyBlock, i * 4 + 3, 1);
				if (e_sector[i].foundKey[0])
					num_to_bytes(e_sector[i].Key[0], 6, keyBlock);
				if (e_sector[i].foundKey[1])
					num_to_bytes(e_sector[i].Key[1], 6, &keyBlock[10]);
				mfEmlSetMem(keyBlock, i * 4 + 3, 1);
			}		
		}
		
		// Create dump file
		if (createDumpFile) {
			if ((fkeys = fopen("dumpkeys.bin","wb")) == NULL) { 
				PrintAndLog("Could not create file keys.bin");
				free(e_sector);
				return 1;
			}
			PrintAndLog("Printing keys to bynary file dumpkeys.bin...");
			for(i=0; i<16; i++) {
				if (e_sector[i].foundKey[0]){
					num_to_bytes(e_sector[i].Key[0], 6, tempkey);
					fwrite ( tempkey, 1, 6, fkeys );
				}
				else{
					fwrite ( &standart, 1, 6, fkeys );
				}
			}
			for(i=0; i<16; i++) {
				if (e_sector[i].foundKey[1]){
					num_to_bytes(e_sector[i].Key[1], 6, tempkey);
					fwrite ( tempkey, 1, 6, fkeys );
				}
				else{
					fwrite ( &standart, 1, 6, fkeys );
				}
			}
			fclose(fkeys);
		}
		
		free(e_sector);
	}

	return 0;
}

int CmdHF14AMfChk(const char *Cmd)
{
	int i, res;
	int	keycnt = 0;
	char ctmp	= 0x00;
	uint8_t blockNo = 0;
	uint8_t keyType = 0;
	uint8_t keyBlock[8 * 6];
	uint64_t key64 = 0;

	memset(keyBlock, 0x00, sizeof(keyBlock));

	if (strlen(Cmd)<3) {
		PrintAndLog("Usage:  hf mf chk <block number> <key A/B> [<key (12 hex symbols)>]");
		PrintAndLog("      sample: hf mf chk 0 A FFFFFFFFFFFF a0a1a2a3a4a5 b0b1b2b3b4b5 ");
		return 0;
	}	
	
	blockNo = param_get8(Cmd, 0);
	ctmp = param_getchar(Cmd, 1);
	if (ctmp == 0x00) {
		PrintAndLog("Key type must be A or B");
		return 1;
	}
	if (ctmp != 'A' && ctmp != 'a') keyType = 1;
	
	for (i = 0; i < 6; i++) {
		if (!isxdigit(param_getchar(Cmd, 2 + i))) break;

		if (param_gethex(Cmd, 2 + i, keyBlock + 6 * i, 12)) {
			PrintAndLog("Key[%d] must include 12 HEX symbols", i);
			return 1;
		}
		keycnt = i + 1;
	}
	
	if (keycnt == 0) {
		PrintAndLog("There is must be at least one key");
		return 1;
	}

	PrintAndLog("--block no:%02x key type:%02x key count:%d ", blockNo, keyType, keycnt);
	
	res = mfCheckKeys(blockNo, keyType, keycnt, keyBlock, &key64);
	if (res !=1) {
		if (!res)
			PrintAndLog("isOk:%02x valid key:%012llx", 1, key64);
		else
			PrintAndLog("isOk:%02x", 0);
	} else {
		PrintAndLog("Command execute timeout");
	}

  return 0;
}

int CmdHF14AMf1kSim(const char *Cmd)
{
	uint8_t uid[4] = {0, 0, 0, 0};
	
	if (param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("Usage:  hf mf sim  <uid (8 hex symbols)>");
		PrintAndLog("           sample: hf mf sim 0a0a0a0a ");
		return 0;
	}	
	
	if (param_getchar(Cmd, 0) && param_gethex(Cmd, 0, uid, 8)) {
		PrintAndLog("UID must include 8 HEX symbols");
		return 1;
	}
	PrintAndLog(" uid:%s ", sprint_hex(uid, 4));
	
  UsbCommand c = {CMD_SIMULATE_MIFARE_CARD, {0, 0, 0}};
	memcpy(c.d.asBytes, uid, 4);
  SendCommand(&c);

  return 0;
}

int CmdHF14AMfDbg(const char *Cmd)
{
	int dbgMode = param_get32ex(Cmd, 0, 0, 10);
	if (dbgMode > 4) {
		PrintAndLog("Max debud mode parameter is 4 \n");
	}

	if (strlen(Cmd) < 1 || !param_getchar(Cmd, 0) || dbgMode > 4) {
		PrintAndLog("Usage:  hf mf dbg  <debug level>");
		PrintAndLog(" 0 - no debug messages");
		PrintAndLog(" 1 - error messages");
		PrintAndLog(" 2 - all messages");
		PrintAndLog(" 4 - extended debug mode");
		return 0;
	}	

  UsbCommand c = {CMD_MIFARE_SET_DBGMODE, {dbgMode, 0, 0}};
  SendCommand(&c);

  return 0;
}

int CmdHF14AMfEGet(const char *Cmd)
{
	uint8_t blockNo = 0;
	uint8_t data[3 * 16];
	int i;

	if (strlen(Cmd) < 1 || param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("Usage:  hf mf eget <block number>");
		PrintAndLog(" sample: hf mf eget 0 ");
		return 0;
	}	
	
	blockNo = param_get8(Cmd, 0);
	if (blockNo >= 16 * 4) {
		PrintAndLog("Block number must be in [0..63] as in MIFARE classic.");
		return 1;
	}

	PrintAndLog(" ");
	if (!mfEmlGetMem(data, blockNo, 3)) {
		for (i = 0; i < 3; i++) {
			PrintAndLog("data[%d]:%s", blockNo + i, sprint_hex(data + i * 16, 16));
		}
	} else {
		PrintAndLog("Command execute timeout");
	}

  return 0;
}

int CmdHF14AMfEClear(const char *Cmd)
{
	if (param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("Usage:  hf mf eclr");
		PrintAndLog("It set card emulator memory to empty data blocks and key A/B FFFFFFFFFFFF \n");
		return 0;
	}	

  UsbCommand c = {CMD_MIFARE_EML_MEMCLR, {0, 0, 0}};
  SendCommand(&c);
  return 0;
}

int CmdHF14AMfESet(const char *Cmd)
{
	uint8_t memBlock[16];
	uint8_t blockNo = 0;

	memset(memBlock, 0x00, sizeof(memBlock));

	if (strlen(Cmd) < 3 || param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("Usage:  hf mf eset <block number> <block data (32 hex symbols)>");
		PrintAndLog(" sample: hf mf eset 1 000102030405060708090a0b0c0d0e0f ");
		return 0;
	}	
	
	blockNo = param_get8(Cmd, 0);
	if (blockNo >= 16 * 4) {
		PrintAndLog("Block number must be in [0..63] as in MIFARE classic.");
		return 1;
	}
	
	if (param_gethex(Cmd, 1, memBlock, 32)) {
		PrintAndLog("block data must include 32 HEX symbols");
		return 1;
	}
	
	//  1 - blocks count
  UsbCommand c = {CMD_MIFARE_EML_MEMSET, {blockNo, 1, 0}};
	memcpy(c.d.asBytes, memBlock, 16);
  SendCommand(&c);
  return 0;
}

int CmdHF14AMfELoad(const char *Cmd)
{
	FILE * f;
	char filename[20];
	char * fnameptr = filename;
	char buf[64];
	uint8_t buf8[64];
	int i, len, blockNum;
	
	memset(filename, 0, sizeof(filename));
	memset(buf, 0, sizeof(buf));

	if (param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("It loads emul dump from the file `filename.eml`");
		PrintAndLog("Usage:  hf mf eload <file name w/o `.eml`>");
		PrintAndLog(" sample: hf mf eload filename");
		return 0;
	}	

	len = strlen(Cmd);
	if (len > 14) len = 14;
	
	if (len < 1) {
	}

	memcpy(filename, Cmd, len);
	fnameptr += len;

	sprintf(fnameptr, ".eml"); 
	
	// open file
	f = fopen(filename, "r");
	if (f == NULL) {
		PrintAndLog("File not found or locked.");
		return 1;
	}
	
	blockNum = 0;
	while(!feof(f)){
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), f);
		if (strlen(buf) < 32){
			PrintAndLog("File content error. Block data must include 32 HEX symbols");
			return 2;
		}
		for (i = 0; i < 32; i += 2)
		  sscanf(&buf[i], "%02x", (unsigned int *)&buf8[i / 2]);
//			PrintAndLog("data[%02d]:%s", blockNum, sprint_hex(buf8, 16));

		if (mfEmlSetMem(buf8, blockNum, 1)) {
			PrintAndLog("Cant set emul block: %d", blockNum);
			return 3;
		}
		blockNum++;
		
		if (blockNum >= 16 * 4) break;
	}
	fclose(f);
	
	if (blockNum != 16 * 4){
		PrintAndLog("File content error. There must be 64 blocks");
		return 4;
	}
	PrintAndLog("Loaded from file: %s", filename);
  return 0;
}

int CmdHF14AMfESave(const char *Cmd)
{
	FILE * f;
	char filename[20];
	char * fnameptr = filename;
	uint8_t buf[64];
	int i, j, len;
	
	memset(filename, 0, sizeof(filename));
	memset(buf, 0, sizeof(buf));

	if (param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("It saves emul dump into the file `filename.eml` or `cardID.eml`");
		PrintAndLog("Usage:  hf mf esave [file name w/o `.eml`]");
		PrintAndLog(" sample: hf mf esave ");
		PrintAndLog("         hf mf esave filename");
		return 0;
	}	

	len = strlen(Cmd);
	if (len > 14) len = 14;
	
	if (len < 1) {
		// get filename
		if (mfEmlGetMem(buf, 0, 1)) {
			PrintAndLog("Cant get block: %d", 0);
			return 1;
		}
		for (j = 0; j < 7; j++, fnameptr += 2)
			sprintf(fnameptr, "%02x", buf[j]); 
	} else {
		memcpy(filename, Cmd, len);
		fnameptr += len;
	}

	sprintf(fnameptr, ".eml"); 
	
	// open file
	f = fopen(filename, "w+");

	// put hex
	for (i = 0; i < 16 * 4; i++) {
		if (mfEmlGetMem(buf, i, 1)) {
			PrintAndLog("Cant get block: %d", i);
			break;
		}
		for (j = 0; j < 16; j++)
			fprintf(f, "%02x", buf[j]); 
		fprintf(f,"\n");
	}
	fclose(f);
	
	PrintAndLog("Saved to file: %s", filename);
	
  return 0;
}

int CmdHF14AMfECFill(const char *Cmd)
{
	uint8_t keyType = 0;

	if (strlen(Cmd) < 1 || param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("Usage:  hf mf efill <key A/B>");
		PrintAndLog("sample:  hf mf efill A");
		PrintAndLog("Card data blocks transfers to card emulator memory.");
		PrintAndLog("Keys must be laid in the simulator memory. \n");
		return 0;
	}	

	char ctmp = param_getchar(Cmd, 0);
	if (ctmp == 0x00) {
		PrintAndLog("Key type must be A or B");
		return 1;
	}
	if (ctmp != 'A' && ctmp != 'a') keyType = 1;

  UsbCommand c = {CMD_MIFARE_EML_CARDLOAD, {0, keyType, 0}};
  SendCommand(&c);
  return 0;
}

int CmdHF14AMfEKeyPrn(const char *Cmd)
{
	int i;
	uint8_t data[16];
	uint64_t keyA, keyB;
	
	PrintAndLog("|---|----------------|----------------|");
	PrintAndLog("|sec|key A           |key B           |");
	PrintAndLog("|---|----------------|----------------|");
	for (i = 0; i < 16; i++) {
		if (mfEmlGetMem(data, i * 4 + 3, 1)) {
			PrintAndLog("error get block %d", i * 4 + 3);
			break;
		}
		keyA = bytes_to_num(data, 6);
		keyB = bytes_to_num(data + 10, 6);
		PrintAndLog("|%03d|  %012llx  |  %012llx  |", i, keyA, keyB);
	}
	PrintAndLog("|---|----------------|----------------|");
	
	return 0;
}

static command_t CommandTable[] =
{
  {"help",		CmdHelp,				1, "This help"},
  {"dbg",		CmdHF14AMfDbg,			0, "Set default debug mode"},
  {"rdbl",		CmdHF14AMfRdBl,			0, "Read MIFARE classic block"},
  {"rdsc",		CmdHF14AMfRdSc,			0, "Read MIFARE classic sector"},
  {"dump1k",	CmdHF14AMfDump1k,		0, "Dump MIFARE classic tag to binary file"},
  {"restore1k",	CmdHF14AMfRestore1k,	0, "Restore MIFARE classic binary file to BLANK tag"},
  {"wrbl",		CmdHF14AMfWrBl,			0, "Write MIFARE classic block"},
  {"chk",		CmdHF14AMfChk,			0, "Test block up to 8 keys"},
  {"mifare",	CmdHF14AMifare,			0, "Read parity error messages. param - <used card nonce>"},
  {"nested",	CmdHF14AMfNested,		0, "Test nested authentication"},
  {"sim",		CmdHF14AMf1kSim,		0, "Simulate MIFARE 1k card"},
  {"eclr",  	CmdHF14AMfEClear,		0, "Clear simulator memory block"},
  {"eget",		CmdHF14AMfEGet,			0, "Get simulator memory block"},
  {"eset",		CmdHF14AMfESet,			0, "Set simulator memory block"},
  {"eload",		CmdHF14AMfELoad,		0, "Load from file emul dump"},
  {"esave",		CmdHF14AMfESave,		0, "Save to file emul dump"},
  {"ecfill",	CmdHF14AMfECFill,		0, "Fill simulator memory with help of keys from simulator"},
  {"ekeyprn",	CmdHF14AMfEKeyPrn,	0, "Print keys from simulator memory"},
  {NULL, NULL, 0, NULL}
};

int CmdHFMF(const char *Cmd)
{
	// flush
	while (WaitForResponseTimeout(CMD_ACK, 500) != NULL) ;

  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
