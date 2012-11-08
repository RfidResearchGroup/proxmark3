//-----------------------------------------------------------------------------
// Copyright (C) 2011,2012 Merlok
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
	uint8_t keyBlock[8] = {0};

	if (param_getchar(Cmd, 0) && param_gethex(Cmd, 0, keyBlock, 8)) {
		PrintAndLog("Nt must include 8 HEX symbols");
		return 1;
	}

	
	UsbCommand c = {CMD_READER_MIFARE, {(uint32_t)bytes_to_num(keyBlock, 4), 0, 0}};
start:
	SendCommand(&c);
	
	//flush queue
	while (ukbhit())	getchar();

	// message
	printf("-------------------------------------------------------------------------\n");
	printf("Executing command. It may take up to 30 min.\n");
	printf("Press the key on the proxmark3 device to abort both proxmark3 and client.\n");
	printf("-------------------------------------------------------------------------\n");
	
	// wait cycle
	while (true) {
		printf(".");
		fflush(stdout);
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
	if (nonce2key(uid, nt, par_list, ks_list, &r_key))
	{
		isOK = 2;
		PrintAndLog("Key not found (lfsr_common_prefix list is null). Nt=%08x", nt);	
	} else {
		printf("------------------------------------------------------------------\n");
		PrintAndLog("Key found:%012llx \n", r_key);

		num_to_bytes(r_key, 6, keyBlock);
		isOK = mfCheckKeys(0, 0, 1, keyBlock, &r_key);
	}
	if (!isOK) 
		PrintAndLog("Found valid key:%012llx", r_key);
	else
	{
		if (isOK != 2) PrintAndLog("Found invalid key. ( Nt=%08x ,Trying use it to run again...", nt);	
		c.arg[0] = nt;
		goto start;
	}
	
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

int CmdHF14AMfDump(const char *Cmd)
{
	int i, j;
	
	uint8_t keyA[40][6];
	uint8_t keyB[40][6];
	uint8_t rights[40][4];
	
	FILE *fin;
	FILE *fout;
	
	UsbCommand *resp;
	
	if ((fin = fopen("dumpkeys.bin","rb")) == NULL) {
		PrintAndLog("Could not find file dumpkeys.bin");
		return 1;
	}
	
	if ((fout = fopen("dumpdata.bin","wb")) == NULL) { 
		PrintAndLog("Could not create file name dumpdata.bin");
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

int CmdHF14AMfRestore(const char *Cmd)
{

	int i,j;
	uint8_t keyType = 0;
	uint8_t key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	uint8_t bldata[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	uint8_t keyA[16][6];
	uint8_t keyB[16][6];
	
	FILE *fdump;
	FILE *fkeys;
	
	if ((fdump = fopen("dumpdata.bin","rb")) == NULL) {
		PrintAndLog("Could not find file dumpdata.bin");
		return 1;
	}
	if ((fkeys = fopen("dumpkeys.bin","rb")) == NULL) {
		PrintAndLog("Could not find file dumpkeys.bin");
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
			
			PrintAndLog("Writing to block %2d: %s", i*4+j, sprint_hex(bldata, 16));
			
			/*
			PrintAndLog("Writing to block %2d: %s Confirm? [Y,N]", i*4+j, sprint_hex(bldata, 16));
			
			scanf("%c",&ch);
			if ((ch != 'y') && (ch != 'Y')){
				PrintAndLog("Aborting !");
				return 1;
			}
			*/
			
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
			PrintAndLog("count=%d key= %s", i, sprint_hex(keyBlock + i * 6, 6));
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
				PrintAndLog("Could not create file dumpkeys.bin");
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

static  uint32_t
get_trailer_block (uint32_t uiBlock)
{
  // Test if we are in the small or big sectors
  uint32_t trailer_block = 0;
  if (uiBlock < 128) {
    trailer_block = uiBlock + (3 - (uiBlock % 4));
  } else {
    trailer_block = uiBlock + (15 - (uiBlock % 16));
  }
  return trailer_block;
}
int CmdHF14AMfChk(const char *Cmd)
{
	FILE * f;
	char filename[256]={0};
	char buf[13];
	uint8_t *keyBlock = NULL, *p;
	uint8_t stKeyBlock = 20;
	
	int i, res;
	int	keycnt = 0;
	char ctmp	= 0x00;
	uint8_t blockNo = 0;
	uint8_t SectorsCnt = 1;
	uint8_t keyType = 0;
	uint64_t key64 = 0;
	
	int transferToEml = 0;
	int createDumpFile = 0;

	keyBlock = calloc(stKeyBlock, 6);
	if (keyBlock == NULL) return 1;

	num_to_bytes(0xffffffffffff, 6, (uint8_t*)(keyBlock + 0 * 6)); // Default key (first key used by program if no user defined key)
	num_to_bytes(0x000000000000, 6, (uint8_t*)(keyBlock + 1 * 6)); // Blank key
	num_to_bytes(0xa0a1a2a3a4a5, 6, (uint8_t*)(keyBlock + 2 * 6)); // NFCForum MAD key
	num_to_bytes(0xb0b1b2b3b4b5, 6, (uint8_t*)(keyBlock + 3 * 6));
	num_to_bytes(0xaabbccddeeff, 6, (uint8_t*)(keyBlock + 4 * 6));
	num_to_bytes(0x4d3a99c351dd, 6, (uint8_t*)(keyBlock + 5 * 6));
	num_to_bytes(0x1a982c7e459a, 6, (uint8_t*)(keyBlock + 6 * 6));
	num_to_bytes(0xd3f7d3f7d3f7, 6, (uint8_t*)(keyBlock + 7 * 6));
	num_to_bytes(0x714c5c886e97, 6, (uint8_t*)(keyBlock + 8 * 6));
	num_to_bytes(0x587ee5f9350f, 6, (uint8_t*)(keyBlock + 9 * 6));
	num_to_bytes(0xa0478cc39091, 6, (uint8_t*)(keyBlock + 10 * 6));
	num_to_bytes(0x533cb6c723f6, 6, (uint8_t*)(keyBlock + 11 * 6));
	num_to_bytes(0x8fd0a4f256e9, 6, (uint8_t*)(keyBlock + 12 * 6));
	
	if (strlen(Cmd)<3) {
		PrintAndLog("Usage:  hf mf chk <block number>/<*card memory> <key type (A/B/?)> [t] [<key (12 hex symbols)>] [<dic (*.dic)>]");
		PrintAndLog("          * - all sectors");
		PrintAndLog("card memory - 0 - MINI(320 bytes), 1 - 1K, 2 - 2K, 4 - 4K, <other> - 1K");
//		PrintAndLog("d - write keys to binary file\n");
		
		PrintAndLog("      sample: hf mf chk 0 A 1234567890ab keys.dic");
		PrintAndLog("              hf mf chk *1 ? t");
		return 0;
	}	
	
	if (param_getchar(Cmd, 0)=='*') {
		blockNo = 3;
		switch(param_getchar(Cmd+1, 0)) {
			case '0': SectorsCnt =  5; break;
			case '1': SectorsCnt = 16; break;
			case '2': SectorsCnt = 32; break;
			case '4': SectorsCnt = 40; break;
			default:  SectorsCnt = 16;
		}
	}
	else
		blockNo = param_get8(Cmd, 0);
	
	ctmp = param_getchar(Cmd, 1);
	switch (ctmp) {	
	case 'a': case 'A':
		keyType = !0;
		break;
	case 'b': case 'B':
		keyType = !1;
		break;
	case '?':
		keyType = 2;
		break;
	default:
		PrintAndLog("Key type must be A , B or ?");
		return 1;
	};
	
	ctmp = param_getchar(Cmd, 2);
	if		(ctmp == 't' || ctmp == 'T') transferToEml = 1;
	else if (ctmp == 'd' || ctmp == 'D') createDumpFile = 1;
	
	for (i = transferToEml || createDumpFile; param_getchar(Cmd, 2 + i); i++) {
		if (!param_gethex(Cmd, 2 + i, keyBlock + 6 * keycnt, 12)) {
			if ( stKeyBlock - keycnt < 2) {
				p = realloc(keyBlock, 6*(stKeyBlock+=10));
				if (!p) {
					PrintAndLog("Cannot allocate memory for Keys");
					free(keyBlock);
					return 2;
				}
				keyBlock = p;
			}
			PrintAndLog("chk key[%d] %02x%02x%02x%02x%02x%02x", keycnt,
			(keyBlock + 6*keycnt)[0],(keyBlock + 6*keycnt)[1], (keyBlock + 6*keycnt)[2],
			(keyBlock + 6*keycnt)[3], (keyBlock + 6*keycnt)[4],	(keyBlock + 6*keycnt)[5], 6);
			keycnt++;
		} else {
			// May be a dic file
			if ( param_getstr(Cmd, 2 + i,filename) > 255 ) {
				PrintAndLog("File name too long");
				free(keyBlock);
				return 2;
			}
			
			if ( (f = fopen( filename , "r")) ) {
				while( !feof(f) ){
					memset(buf, 0, sizeof(buf));
					fgets(buf, sizeof(buf), f);
					
					if (strlen(buf) < 12 || buf[11] == '\n')
						continue;
				
					while (fgetc(f) != '\n' && !feof(f)) ;  //goto next line
					
					if( buf[0]=='#' ) continue;	//The line start with # is remcommnet,skip

					if (!isxdigit(buf[0])){
						PrintAndLog("File content error. '%s' must include 12 HEX symbols",buf);
						continue;
					}
					
					buf[12] = 0;

					if ( stKeyBlock - keycnt < 2) {
						p = realloc(keyBlock, 6*(stKeyBlock+=10));
						if (!p) {
							PrintAndLog("Cannot allocate memory for defKeys");
							free(keyBlock);
							return 2;
						}
						keyBlock = p;
					}
					memset(keyBlock + 6 * keycnt, 0, 6);
					num_to_bytes(strtoll(buf, NULL, 16), 6, keyBlock + 6*keycnt);
					PrintAndLog("chk custom key[%d] %012llx", keycnt, bytes_to_num(keyBlock + 6*keycnt, 6));
					keycnt++;
				}
			} else {
				PrintAndLog("File: %s: not found or locked.", filename);
				free(keyBlock);
				return 1;
			fclose(f);
			}
		}
	}
	
	if (keycnt == 0) {
		PrintAndLog("No key specified,try default keys");
		for (;keycnt <=12; keycnt++)
			PrintAndLog("chk default key[%d] %02x%02x%02x%02x%02x%02x", keycnt,
			(keyBlock + 6*keycnt)[0],(keyBlock + 6*keycnt)[1], (keyBlock + 6*keycnt)[2],
			(keyBlock + 6*keycnt)[3], (keyBlock + 6*keycnt)[4],	(keyBlock + 6*keycnt)[5], 6);
	}
	
	for ( int t = !keyType ; t < 2 ; keyType==2?(t++):(t=2) ) {
		int b=blockNo;
		for (int i=0; i<SectorsCnt; ++i) {
			PrintAndLog("--SectorsCnt:%d block no:0x%02x key type:%C key count:%d ", i,	 b, t?'B':'A', keycnt);
			int size = keycnt>8?8:keycnt;
			for (int c = 0; c < keycnt; c+=size) {
				size=keycnt-c>8?8:keycnt-c;			
				res = mfCheckKeys(b, t, size, keyBlock +6*c, &key64);
				if (res !=1) {
					if (!res) {
						PrintAndLog("Found valid key:[%012llx]",key64);
						if (transferToEml) {
							uint8_t block[16];
							mfEmlGetMem(block, get_trailer_block(b), 1);
							num_to_bytes(key64, 6, block + t*10);
							mfEmlSetMem(block, get_trailer_block(b), 1);
						}
						break;
					}
					else {
						printf("Not found yet, keycnt:%d\r", c+size);
						fflush(stdout);
					}
				} else {
					PrintAndLog("Command execute timeout");
				}
			}
			b<127?(b+=4):(b+=16);	
		}
	}
	
	free(keyBlock);

/*
	// Create dump file
	if (createDumpFile) {
		if ((fkeys = fopen("dumpkeys.bin","wb")) == NULL) { 
			PrintAndLog("Could not create file dumpkeys.bin");
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
*/
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

	if (param_getchar(Cmd, 0) == 'h' || param_getchar(Cmd, 0)== 0x00) {
		PrintAndLog("It loads emul dump from the file `filename.eml`");
		PrintAndLog("Usage:  hf mf eload <file name w/o `.eml`>");
		PrintAndLog(" sample: hf mf eload filename");
		return 0;
	}	

	len = strlen(Cmd);
	if (len > 14) len = 14;

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
			if(strlen(buf) && feof(f))
				break;
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
		
		if (blockNum >= 32 * 4 + 8 * 16) break;
	}
	fclose(f);
	
	if (blockNum != 16 * 4 && blockNum != 32 * 4 + 8 * 16){
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
	for (i = 0; i < 32 * 4 + 8 * 16; i++) {
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
	int i,b=-1;
	uint8_t data[16];
	uint64_t keyA, keyB;
	
	PrintAndLog("|---|----------------|----------------|");
	PrintAndLog("|sec|key A           |key B           |");
	PrintAndLog("|---|----------------|----------------|");
	for (i = 0; i < 40; i++) {
		b<127?(b+=4):(b+=16);
		if (mfEmlGetMem(data, b, 1)) {
			PrintAndLog("error get block %d", b);
			break;
		}
		keyA = bytes_to_num(data, 6);
		keyB = bytes_to_num(data + 10, 6);
		PrintAndLog("|%03d|  %012llx  |  %012llx  |", i, keyA, keyB);
	}
	PrintAndLog("|---|----------------|----------------|");
	
	return 0;
}

int CmdHF14AMfCSetUID(const char *Cmd)
{
	uint8_t wipeCard = 0;
	uint8_t uid[8];
	uint8_t oldUid[8];
	int res;

	if (strlen(Cmd) < 1 || param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("Usage:  hf mf csetuid <UID 8 hex symbols> <w>");
		PrintAndLog("sample:  hf mf csetuid 01020304 w");
		PrintAndLog("Set UID for magic Chinese card (only works with!!!)");
		PrintAndLog("If you want wipe card then add 'w' into command line. \n");
		return 0;
	}	

	if (param_getchar(Cmd, 0) && param_gethex(Cmd, 0, uid, 8)) {
		PrintAndLog("UID must include 8 HEX symbols");
		return 1;
	}

	char ctmp = param_getchar(Cmd, 1);
	if (ctmp == 'w' || ctmp == 'W') wipeCard = 1;
	
	PrintAndLog("--wipe card:%02x uid:%s", wipeCard, sprint_hex(uid, 4));

	res = mfCSetUID(uid, oldUid, wipeCard);
	if (res) {
			PrintAndLog("Can't set UID. error=%d", res);
			return 1;
		}
	
	PrintAndLog("old UID:%s", sprint_hex(oldUid, 4));
	return 0;
}

int CmdHF14AMfCSetBlk(const char *Cmd)
{
	uint8_t uid[8];
	uint8_t memBlock[16];
	uint8_t blockNo = 0;
	int res;
	memset(memBlock, 0x00, sizeof(memBlock));

	if (strlen(Cmd) < 1 || param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("Usage:  hf mf csetblk <block number> <block data (32 hex symbols)>");
		PrintAndLog("sample:  hf mf csetblk 1 01020304050607080910111213141516");
		PrintAndLog("Set block data for magic Chinese card (only works with!!!)");
		PrintAndLog("If you want wipe card then add 'w' into command line. \n");
		return 0;
	}	

	blockNo = param_get8(Cmd, 0);

	if (param_gethex(Cmd, 1, memBlock, 32)) {
		PrintAndLog("block data must include 32 HEX symbols");
		return 1;
	}

	PrintAndLog("--block number:%02x data:%s", blockNo, sprint_hex(memBlock, 16));

	res = mfCSetBlock(blockNo, memBlock, uid, 0, CSETBLOCK_SINGLE_OPER);
	if (res) {
			PrintAndLog("Can't write block. error=%d", res);
			return 1;
		}
	
	PrintAndLog("UID:%s", sprint_hex(uid, 4));
	return 0;
}

int CmdHF14AMfCLoad(const char *Cmd)
{
	FILE * f;
	char filename[20];
	char * fnameptr = filename;
	char buf[64];
	uint8_t buf8[64];
	uint8_t fillFromEmulator = 0;
	int i, len, blockNum, flags;
	
	memset(filename, 0, sizeof(filename));
	memset(buf, 0, sizeof(buf));

	if (param_getchar(Cmd, 0) == 'h' || param_getchar(Cmd, 0)== 0x00) {
		PrintAndLog("It loads magic Chinese card (only works with!!!) from the file `filename.eml`");
		PrintAndLog("or from emulator memory (option `e`)");
		PrintAndLog("Usage:  hf mf cload <file name w/o `.eml`>");
		PrintAndLog("   or:  hf mf cload e ");
		PrintAndLog(" sample: hf mf cload filename");
		return 0;
	}	

	char ctmp = param_getchar(Cmd, 0);
	if (ctmp == 'e' || ctmp == 'E') fillFromEmulator = 1;
	
	if (fillFromEmulator) {
		flags = CSETBLOCK_INIT_FIELD + CSETBLOCK_WUPC;
		for (blockNum = 0; blockNum < 16 * 4; blockNum += 1) {
			if (mfEmlGetMem(buf8, blockNum, 1)) {
				PrintAndLog("Cant get block: %d", blockNum);
				return 2;
			}
			
			if (blockNum == 2) flags = 0;
			if (blockNum == 16 * 4 - 1) flags = CSETBLOCK_HALT + CSETBLOCK_RESET_FIELD;

			if (mfCSetBlock(blockNum, buf8, NULL, 0, flags)) {
				PrintAndLog("Cant set magic card block: %d", blockNum);
				return 3;
			}
		}
		return 0;
	} else {
		len = strlen(Cmd);
		if (len > 14) len = 14;

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
		flags = CSETBLOCK_INIT_FIELD + CSETBLOCK_WUPC;
		while(!feof(f)){
			memset(buf, 0, sizeof(buf));
			fgets(buf, sizeof(buf), f);

			if (strlen(buf) < 32){
				if(strlen(buf) && feof(f))
					break;
				PrintAndLog("File content error. Block data must include 32 HEX symbols");
				return 2;
			}
			for (i = 0; i < 32; i += 2)
				sscanf(&buf[i], "%02x", (unsigned int *)&buf8[i / 2]);

			if (blockNum == 2) flags = 0;
			if (blockNum == 16 * 4 - 1) flags = CSETBLOCK_HALT + CSETBLOCK_RESET_FIELD;

			if (mfCSetBlock(blockNum, buf8, NULL, 0, flags)) {
				PrintAndLog("Cant set magic card block: %d", blockNum);
				return 3;
			}
			blockNum++;
		
			if (blockNum >= 16 * 4) break;  // magic card type - mifare 1K
		}
		fclose(f);
	
		if (blockNum != 16 * 4 && blockNum != 32 * 4 + 8 * 16){
			PrintAndLog("File content error. There must be 64 blocks");
			return 4;
		}
		PrintAndLog("Loaded from file: %s", filename);
		return 0;
	}
}

int CmdHF14AMfCGetBlk(const char *Cmd) {
	uint8_t memBlock[16];
	uint8_t blockNo = 0;
	int res;
	memset(memBlock, 0x00, sizeof(memBlock));

	if (strlen(Cmd) < 1 || param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("Usage:  hf mf cgetblk <block number>");
		PrintAndLog("sample:  hf mf cgetblk 1");
		PrintAndLog("Get block data from magic Chinese card (only works with!!!)\n");
		return 0;
	}	

	blockNo = param_get8(Cmd, 0);

	PrintAndLog("--block number:%02x ", blockNo);

	res = mfCGetBlock(blockNo, memBlock, CSETBLOCK_SINGLE_OPER);
	if (res) {
			PrintAndLog("Can't read block. error=%d", res);
			return 1;
		}
	
	PrintAndLog("block data:%s", sprint_hex(memBlock, 16));
	return 0;
}

int CmdHF14AMfCGetSc(const char *Cmd) {
	uint8_t memBlock[16];
	uint8_t sectorNo = 0;
	int i, res, flags;
	memset(memBlock, 0x00, sizeof(memBlock));

	if (strlen(Cmd) < 1 || param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("Usage:  hf mf cgetsc <sector number>");
		PrintAndLog("sample:  hf mf cgetsc 0");
		PrintAndLog("Get sector data from magic Chinese card (only works with!!!)\n");
		return 0;
	}	

	sectorNo = param_get8(Cmd, 0);
	if (sectorNo > 15) {
		PrintAndLog("Sector number must be in [0..15] as in MIFARE classic.");
		return 1;
	}

	PrintAndLog("--sector number:%02x ", sectorNo);

	flags = CSETBLOCK_INIT_FIELD + CSETBLOCK_WUPC;
	for (i = 0; i < 4; i++) {
		if (i == 1) flags = 0;
		if (i == 3) flags = CSETBLOCK_HALT + CSETBLOCK_RESET_FIELD;

		res = mfCGetBlock(sectorNo * 4 + i, memBlock, flags);
		if (res) {
			PrintAndLog("Can't read block. %02x error=%d", sectorNo * 4 + i, res);
			return 1;
		}
	
		PrintAndLog("block %02x data:%s", sectorNo * 4 + i, sprint_hex(memBlock, 16));
	}
	return 0;
}

int CmdHF14AMfCSave(const char *Cmd) {

	FILE * f;
	char filename[20];
	char * fnameptr = filename;
	uint8_t fillFromEmulator = 0;
	uint8_t buf[64];
	int i, j, len, flags;
	
	memset(filename, 0, sizeof(filename));
	memset(buf, 0, sizeof(buf));

	if (param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("It saves `magic Chinese` card dump into the file `filename.eml` or `cardID.eml`");
		PrintAndLog("or into emulator memory (option `e`)");
		PrintAndLog("Usage:  hf mf esave [file name w/o `.eml`][e]");
		PrintAndLog(" sample: hf mf esave ");
		PrintAndLog("         hf mf esave filename");
		PrintAndLog("         hf mf esave e \n");
		return 0;
	}	

	char ctmp = param_getchar(Cmd, 0);
	if (ctmp == 'e' || ctmp == 'E') fillFromEmulator = 1;

	if (fillFromEmulator) {
		// put into emulator
		flags = CSETBLOCK_INIT_FIELD + CSETBLOCK_WUPC;
		for (i = 0; i < 16 * 4; i++) {
			if (i == 1) flags = 0;
			if (i == 16 * 4 - 1) flags = CSETBLOCK_HALT + CSETBLOCK_RESET_FIELD;
		
			if (mfCGetBlock(i, buf, flags)) {
				PrintAndLog("Cant get block: %d", i);
				break;
			}
			
			if (mfEmlSetMem(buf, i, 1)) {
				PrintAndLog("Cant set emul block: %d", i);
				return 3;
			}
		}
		return 0;
	} else {
		len = strlen(Cmd);
		if (len > 14) len = 14;
	
		if (len < 1) {
			// get filename
			if (mfCGetBlock(0, buf, CSETBLOCK_SINGLE_OPER)) {
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
		flags = CSETBLOCK_INIT_FIELD + CSETBLOCK_WUPC;
		for (i = 0; i < 16 * 4; i++) {
			if (i == 1) flags = 0;
			if (i == 16 * 4 - 1) flags = CSETBLOCK_HALT + CSETBLOCK_RESET_FIELD;
		
			if (mfCGetBlock(i, buf, flags)) {
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
}

int CmdHF14AMfSniff(const char *Cmd){
	// params
	bool wantLogToFile = 0;
	bool wantDecrypt = 0;
	//bool wantSaveToEml = 0; TODO
	bool wantSaveToEmlFile = 0;

	//var 
	int res = 0;
	int len = 0;
	int blockLen = 0;
	int num = 0;
	int pckNum = 0;
	uint8_t uid[8];
	uint8_t atqa[2];
	uint8_t sak;
	bool isTag;
	uint32_t parity;
	uint8_t buf[3000];
	uint8_t * bufPtr = buf;
	memset(buf, 0x00, 3000);
	
	if (param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("It continuously get data from the field and saves it to: log, emulator, emulator file.");
		PrintAndLog("You can specify:");
		PrintAndLog("    l - save encrypted sequence to logfile `uid.log`");
		PrintAndLog("    d - decrypt sequence and put it to log file `uid.log`");
		PrintAndLog(" n/a   e - decrypt sequence, collect read and write commands and save the result of the sequence to emulator memory");
		PrintAndLog("    r - decrypt sequence, collect read and write commands and save the result of the sequence to emulator dump file `uid.eml`");
		PrintAndLog("Usage:  hf mf sniff [l][d][e][r]");
		PrintAndLog("  sample: hf mf sniff l d e");
		return 0;
	}	
	
	for (int i = 0; i < 4; i++) {
		char ctmp = param_getchar(Cmd, i);
		if (ctmp == 'l' || ctmp == 'L') wantLogToFile = true;
		if (ctmp == 'd' || ctmp == 'D') wantDecrypt = true;
		//if (ctmp == 'e' || ctmp == 'E') wantSaveToEml = true; TODO
		if (ctmp == 'f' || ctmp == 'F') wantSaveToEmlFile = true;
	}
	
	printf("-------------------------------------------------------------------------\n");
	printf("Executing command. \n");
	printf("Press the key on the proxmark3 device to abort both proxmark3 and client.\n");
	printf("Press the key on pc keyboard to abort the client.\n");
	printf("-------------------------------------------------------------------------\n");

  UsbCommand c = {CMD_MIFARE_SNIFFER, {0, 0, 0}};
  SendCommand(&c);

	// wait cycle
	while (true) {
		printf(".");
		fflush(stdout);
		if (ukbhit()) {
			getchar();
			printf("\naborted via keyboard!\n");
			break;
		}
		
		UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 2000);
		if (resp != NULL) {
			res = resp->arg[0] & 0xff;
			len = resp->arg[1];
			num = resp->arg[2];
			
			if (res == 0) return 0;
			if (res == 1) {
				if (num ==0) {
					bufPtr = buf;
					memset(buf, 0x00, 3000);
				}
				memcpy(bufPtr, resp->d.asBytes, len);
				bufPtr += len;
				pckNum++;
			}
			if (res == 2) {
				blockLen = bufPtr - buf;
				bufPtr = buf;
				printf(">\n");
				PrintAndLog("received trace len: %d packages: %d", blockLen, pckNum);
				num = 0;
				while (bufPtr - buf + 9 < blockLen) {
				  isTag = bufPtr[3] & 0x80 ? true:false;
					bufPtr += 4;
					parity = *((uint32_t *)(bufPtr));
					bufPtr += 4;
					len = bufPtr[0];
					bufPtr++;
					if ((len == 14) && (bufPtr[0] = 0xff) && (bufPtr[1] = 0xff)) {
						memcpy(uid, bufPtr + 2, 7);
						memcpy(atqa, bufPtr + 2 + 7, 2);
						sak = bufPtr[11];
						
						PrintAndLog("tag select uid:%s atqa:%02x %02x sak:0x%02x", sprint_hex(uid, 7), atqa[0], atqa[1], sak);
						if (wantLogToFile) {
							FillFileNameByUID(logHexFileName, uid, ".log", 7);
							AddLogCurrentDT(logHexFileName);
						}						
						if (wantDecrypt) mfTraceInit(uid, atqa, sak, wantSaveToEmlFile);
					} else {
						PrintAndLog("%s(%d):%s", isTag ? "TAG":"RDR", num, sprint_hex(bufPtr, len));
						if (wantLogToFile) AddLogHex(logHexFileName, isTag ? "TAG: ":"RDR: ", bufPtr, len);
						if (wantDecrypt) mfTraceDecode(bufPtr, len, parity, wantSaveToEmlFile);
					}
					bufPtr += len;
					num++;
				}
			}
		} // resp not NILL
	} // while (true)
  return 0;
}

static command_t CommandTable[] =
{
  {"help",		CmdHelp,						1, "This help"},
  {"dbg",			CmdHF14AMfDbg,			0, "Set default debug mode"},
  {"rdbl",		CmdHF14AMfRdBl,			0, "Read MIFARE classic block"},
  {"rdsc",		CmdHF14AMfRdSc,			0, "Read MIFARE classic sector"},
  {"dump",		CmdHF14AMfDump,			0, "Dump MIFARE classic tag to binary file"},
  {"restore",	CmdHF14AMfRestore,	0, "Restore MIFARE classic binary file to BLANK tag"},
  {"wrbl",		CmdHF14AMfWrBl,			0, "Write MIFARE classic block"},
  {"chk",			CmdHF14AMfChk,			0, "Test block keys"},
  {"mifare",	CmdHF14AMifare,			0, "Read parity error messages. param - <used card nonce>"},
  {"nested",	CmdHF14AMfNested,		0, "Test nested authentication"},
  {"sniff",		CmdHF14AMfSniff,		0, "Sniff card-reader communication"},
  {"sim",			CmdHF14AMf1kSim,		0, "Simulate MIFARE card"},
  {"eclr",		CmdHF14AMfEClear,		0, "Clear simulator memory block"},
  {"eget",		CmdHF14AMfEGet,			0, "Get simulator memory block"},
  {"eset",		CmdHF14AMfESet,			0, "Set simulator memory block"},
  {"eload",		CmdHF14AMfELoad,		0, "Load from file emul dump"},
  {"esave",		CmdHF14AMfESave,		0, "Save to file emul dump"},
  {"ecfill",	CmdHF14AMfECFill,		0, "Fill simulator memory with help of keys from simulator"},
  {"ekeyprn",	CmdHF14AMfEKeyPrn,	0, "Print keys from simulator memory"},
  {"csetuid",	CmdHF14AMfCSetUID,	0, "Set UID for magic Chinese card"},
  {"csetblk",	CmdHF14AMfCSetBlk,	0, "Write block into magic Chinese card"},
  {"cgetblk",	CmdHF14AMfCGetBlk,	0, "Read block from magic Chinese card"},
  {"cgetsc",	CmdHF14AMfCGetSc,		0, "Read sector from magic Chinese card"},
  {"cload",		CmdHF14AMfCLoad,		0, "Load dump into magic Chinese card"},
  {"csave",		CmdHF14AMfCSave,		0, "Save dump from magic Chinese card into file or emulator"},
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
