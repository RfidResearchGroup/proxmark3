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
	
	char cmdp, ctmp;

	if (strlen(Cmd)<3) {
		PrintAndLog("Usage:");
		PrintAndLog(" all sectors:  hf mf nested  <card memory> <block number> <key A/B> <key (12 hex symbols)>");
		PrintAndLog(" one sector:   hf mf nested  o <block number> <key A/B> <key (12 hex symbols)>");
		PrintAndLog("               <target block number> <target key A/B>");
		PrintAndLog("card memory - 0 - MINI(320 bytes), 1 - 1K, 2 - 2K, 4 - 4K, <other> - 1K");
		PrintAndLog(" ");
		PrintAndLog("      sample1: hf mf nested 1 0 A FFFFFFFFFFFF ");
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
	
	if (cmdp =='o' || cmdp == 'O') {
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
	
	PrintAndLog("--block no:%02x key type:%02x key:%s ", blockNo, keyType, sprint_hex(key, 6));
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
		if (!res)
			PrintAndLog("Found valid key:%012llx", key64);
		else
			PrintAndLog("No valid key found");
	} else  // ------------------------------------  multiple sectors working
	{
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
		PrintAndLog("      sample: hf mf chk 0 A FFFFFFFFFFFF a0a1a2a3a4a5 b01b2b3b4b5 ");
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
	if (strlen(Cmd) < 1) {
		PrintAndLog("Usage:  hf mf dbg  <debug level>");
		PrintAndLog(" 0 - no debug messages");
		PrintAndLog(" 1 - error messages");
		PrintAndLog(" 2 - all messages");
		PrintAndLog(" 4 - extended debug mode");
		return 0;
	}	

	PrintAndLog("No code here (");
  return 0;
}

int CmdHF14AMfEGet(const char *Cmd)
{
	PrintAndLog("No code here (");
  return 0;
}

int CmdHF14AMfESet(const char *Cmd)
{
	PrintAndLog("No code here (");
  return 0;
}

int CmdHF14AMfELoad(const char *Cmd)
{
	PrintAndLog("No code here (");
  return 0;
}

int CmdHF14AMfESave(const char *Cmd)
{
	PrintAndLog("No code here (");
  return 0;
}

static command_t CommandTable[] = 
{
  {"help",		CmdHelp,						1, "This help"},
  {"dbg",			CmdHF14AMfDbg,			0, "Set default debug mode"},
  {"rdbl",		CmdHF14AMfRdBl,			0, "Read MIFARE classic block"},
  {"rdsc",		CmdHF14AMfRdSc,			0, "Read MIFARE classic sector"},
  {"wrbl",		CmdHF14AMfWrBl,			0, "Write MIFARE classic block"},
  {"chk",			CmdHF14AMfChk,			0, "Test block up to 8 keys"},
  {"mifare",	CmdHF14AMifare,			0, "Read parity error messages. param - <used card nonce>"},
  {"nested",	CmdHF14AMfNested,		0, "Test nested authentication"},
  {"sim",			CmdHF14AMf1kSim,		0, "Simulate MIFARE 1k card"},
  {"eget",		CmdHF14AMfEGet,			0, "Set simulator memory block"},
  {"eset",		CmdHF14AMfESet,			0, "Get simulator memory block"},
  {"eload",		CmdHF14AMfELoad,		0, "Load from file emul dump"},
  {"esave",		CmdHF14AMfESave,		0, "Save to file emul dump"},
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
