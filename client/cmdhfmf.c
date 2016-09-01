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

static int CmdHelp(const char *Cmd);
int usage_hf14_mifare(void){
	PrintAndLog("Usage:  hf mf mifare [h] <block number> <A|B>");
	PrintAndLog("options:");
	PrintAndLog("      h               this help");
	PrintAndLog("      <block number>  (Optional) target other block");
	PrintAndLog("      <A|B>           (optional) target key type");
	PrintAndLog("samples:");
	PrintAndLog("           hf mf mifare");
	PrintAndLog("           hf mf mifare 16");
	PrintAndLog("           hf mf mifare 16 B");
	return 0;
}
int usage_hf14_mf1ksim(void){
	PrintAndLog("Usage:  hf mf sim  [h] u <uid (8,14,20 hex symbols)> n <numreads> i x");
	PrintAndLog("options:");
	PrintAndLog("      h    this help");
	PrintAndLog("      u    (Optional) UID 4,7 or 10bytes. If not specified, the UID 4b from emulator memory will be used");
	PrintAndLog("      n    (Optional) Automatically exit simulation after <numreads> blocks have been read by reader. 0 = infinite");
	PrintAndLog("      i    (Optional) Interactive, means that console will not be returned until simulation finishes or is aborted");
	PrintAndLog("      x    (Optional) Crack, performs the 'reader attack', nr/ar attack against a legitimate reader, fishes out the key(s)");
	PrintAndLog("samples:");
	PrintAndLog("           hf mf sim u 0a0a0a0a");
	PrintAndLog("           hf mf sim u 11223344556677");
	PrintAndLog("           hf mf sim u 112233445566778899AA");	
	return 0;
}
int usage_hf14_dbg(void){
	PrintAndLog("Usage:  hf mf dbg [h] <debug level>");
	PrintAndLog("options:");
	PrintAndLog("           h    this help");	
	PrintAndLog("       <debug level>  (Optional) see list for valid levels");
	PrintAndLog("           0 - no debug messages");
	PrintAndLog("           1 - error messages");
	PrintAndLog("           2 - plus information messages");
	PrintAndLog("           3 - plus debug messages");
	PrintAndLog("           4 - print even debug messages in timing critical functions");
	PrintAndLog("               Note: this option therefore may cause malfunction itself");
	PrintAndLog("samples:");
	PrintAndLog("           hf mf dbg 3");
	return 0;
}
int usage_hf14_sniff(void){
	PrintAndLog("It continuously gets data from the field and saves it to: log, emulator, emulator file.");
	PrintAndLog("Usage:  hf mf sniff [h] [l] [d] [f]");
	PrintAndLog("options:");
	PrintAndLog("      h    this help");
	PrintAndLog("      l    save encrypted sequence to logfile `uid.log`");
	PrintAndLog("      d    decrypt sequence and put it to log file `uid.log`");
//	PrintAndLog(" n/a  e     decrypt sequence, collect read and write commands and save the result of the sequence to emulator memory");
	PrintAndLog("      f    decrypt sequence, collect read and write commands and save the result of the sequence to emulator dump file `uid.eml`");
	PrintAndLog("sample:");
	PrintAndLog("           hf mf sniff l d f");
	return 0;
}
int usage_hf14_nested(void){
	PrintAndLog("Usage:");
	PrintAndLog(" all sectors:  hf mf nested  <card memory> <block number> <key A/B> <key (12 hex symbols)> [t,d]");
	PrintAndLog(" one sector:   hf mf nested  o <block number> <key A/B> <key (12 hex symbols)>");
	PrintAndLog("               <target block number> <target key A/B> [t]");
	PrintAndLog("options:");
	PrintAndLog("      h    this help");
	PrintAndLog("      card memory - 0 - MINI(320 bytes), 1 - 1K, 2 - 2K, 4 - 4K, <other> - 1K");
	PrintAndLog("      t    transfer keys into emulator memory");
	PrintAndLog("      d    write keys to binary file");
	PrintAndLog(" ");
	PrintAndLog("samples:");
	PrintAndLog("      hf mf nested 1 0 A FFFFFFFFFFFF ");
	PrintAndLog("      hf mf nested 1 0 A FFFFFFFFFFFF t ");
	PrintAndLog("      hf mf nested 1 0 A FFFFFFFFFFFF d ");
	PrintAndLog("      hf mf nested o 0 A FFFFFFFFFFFF 4 A");
	return 0;
}
int usage_hf14_hardnested(void){
	PrintAndLog("Usage:");
	PrintAndLog("      hf mf hardnested <block number> <key A|B> <key (12 hex symbols)>");
	PrintAndLog("                       <target block number> <target key A|B> [known target key (12 hex symbols)] [w] [s]");
	PrintAndLog("  or  hf mf hardnested r [known target key]");
	PrintAndLog(" ");
	PrintAndLog("options:");
	PrintAndLog("      h    this help");	
	PrintAndLog("      w    acquire nonces and write them to binary file nonces.bin");
	PrintAndLog("      s    slower acquisition (required by some non standard cards)");
	PrintAndLog("      r    read nonces.bin and start attack");
	PrintAndLog("      t    tests?");
	PrintAndLog(" ");
	PrintAndLog("samples:");
	PrintAndLog("      hf mf hardnested 0 A FFFFFFFFFFFF 4 A");
	PrintAndLog("      hf mf hardnested 0 A FFFFFFFFFFFF 4 A w");
	PrintAndLog("      hf mf hardnested 0 A FFFFFFFFFFFF 4 A w s");
	PrintAndLog("      hf mf hardnested r");
	PrintAndLog("      hf mf hardnested r a0a1a2a3a4a5");
	PrintAndLog(" ");
	PrintAndLog("Add the known target key to check if it is present in the remaining key space:");
	PrintAndLog("      sample5: hf mf hardnested 0 A A0A1A2A3A4A5 4 A FFFFFFFFFFFF");
	return 0;
}
int usage_hf14_chk(void){
	PrintAndLog("Usage:  hf mf chk <block number>|<*card memory> <key type (A/B/?)> [t|d] [<key (12 hex symbols)>] [<dic (*.dic)>]");
	PrintAndLog("options:");
	PrintAndLog("      h    this help");	
	PrintAndLog("      *    all sectors based on card memory, other values then below defaults to 1k");
	PrintAndLog("      			0 - MINI(320 bytes)");
	PrintAndLog("      			1 - 1K");
	PrintAndLog("      			2 - 2K");
	PrintAndLog("      			4 - 4K");
	PrintAndLog("      d    write keys to binary file");
	PrintAndLog("      t    write keys to emulator memory\n");
	PrintAndLog(" ");
	PrintAndLog("samples:");
	PrintAndLog("      hf mf chk 0 A 1234567890ab keys.dic     -- target block 0, Key A");
	PrintAndLog("      hf mf chk *1 ? t                        -- target all blocks, all keys, 1K, write to emul");
	PrintAndLog("      hf mf chk *1 ? d                        -- target all blocks, all keys, 1K, write to file");
	return 0;
}
int usage_hf14_keybrute(void){
	PrintAndLog("J_Run's 2nd phase of multiple sector nested authentication key recovery");
	PrintAndLog("You have a known 4 last bytes of a key recovered with mf_nonce_brute tool.");
	PrintAndLog("First 2 bytes of key will be bruteforced");
	PrintAndLog("");
	PrintAndLog("Usage:  hf mf keybrute [h] <block number> <A|B> <key>");
	PrintAndLog("options:");
	PrintAndLog("      h               this help");
	PrintAndLog("      <block number>  target block number");
	PrintAndLog("      <A|B>           target key type");
	PrintAndLog("      <key>           candidate key from mf_nonce_brute tool");
	PrintAndLog("samples:");
	PrintAndLog("           hf mf keybrute 1 A 000011223344");
	return 0;
}

int CmdHF14AMifare(const char *Cmd) {
	uint32_t uid = 0;
	uint32_t nt = 0, nr = 0;
	uint64_t par_list = 0, ks_list = 0, r_key = 0;
	int16_t isOK = 0;
	int tmpchar; 
	uint8_t blockNo = 0, keytype = MIFARE_AUTH_KEYA;
	
	char cmdp = param_getchar(Cmd, 0);	
	if ( cmdp == 'H' || cmdp == 'h') return usage_hf14_mifare();
	
	blockNo = param_get8(Cmd, 0);	 
	
	cmdp = param_getchar(Cmd, 1);
	if (cmdp == 'B' || cmdp == 'b')
		keytype = MIFARE_AUTH_KEYB;
	
	UsbCommand c = {CMD_READER_MIFARE, {true, blockNo, keytype}};

	// message
	printf("-------------------------------------------------------------------------\n");
	printf("Executing darkside attack. Expected execution time: 25sec on average :-)\n");
	printf("Press button on the proxmark3 device to abort both proxmark3 and client.\n");
	printf("-------------------------------------------------------------------------\n");
	clock_t t1 = clock();
	time_t start, end;
	time(&start);
	
start:
    clearCommandBuffer();
    SendCommand(&c);
	
	//flush queue
	while (ukbhit()) {
		tmpchar = getchar();
		(void)tmpchar;
	}

	// wait cycle
	while (true) {
        printf(".");
		fflush(stdout);
		if (ukbhit()) {
			tmpchar = getchar();
			(void)tmpchar;
			printf("\naborted via keyboard!\n");
			break;
		}
		
		UsbCommand resp;
		if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
			isOK  = resp.arg[0];
			printf("\n");
			uid = (uint32_t)bytes_to_num(resp.d.asBytes +  0, 4);
			nt =  (uint32_t)bytes_to_num(resp.d.asBytes +  4, 4);
			par_list = bytes_to_num(resp.d.asBytes +  8, 8);
			ks_list = bytes_to_num(resp.d.asBytes +  16, 8);
			nr = bytes_to_num(resp.d.asBytes + 24, 4);

			switch (isOK) {
				case -1 : PrintAndLog("Button pressed. Aborted.\n"); break;
				case -2 : PrintAndLog("Card isn't vulnerable to Darkside attack (doesn't send NACK on authentication requests).\n"); break;
				case -3 : PrintAndLog("Card isn't vulnerable to Darkside attack (its random number generator is not predictable).\n"); break;
				case -4 : PrintAndLog("Card isn't vulnerable to Darkside attack (its random number generator seems to be based on the wellknown");
						  PrintAndLog("generating polynomial with 16 effective bits only, but shows unexpected behaviour.\n"); break;
				default: ;
			}
			break;
		}
	}	
	printf("\n");
	
	// par == 0,  and -4
	if (isOK == -4 && par_list == 0) {
		// this special attack when parities is zero, uses checkkeys. Which now with block/keytype option also needs. 
		// but it uses 0|1 instead of 0x60|0x61...
		if (nonce2key_ex(blockNo, keytype - 0x60 , uid, nt, nr, ks_list, &r_key) ){
			PrintAndLog("Key not found (lfsr_common_prefix list is null).");	
			PrintAndLog("Failing is expected to happen in 25%% of all cases. Trying again with a different reader nonce...");
			c.arg[0] = false;
			goto start;
		} else {
			PrintAndLog("Found valid key: %012"llx" \n", r_key);
			goto END;
		}
	}
	
	// error
	if (isOK != 1) return 1;
	
	// execute original function from util nonce2key
	if (nonce2key(uid, nt, nr, par_list, ks_list, &r_key)) {
		isOK = 2;
		PrintAndLog("Key not found (lfsr_common_prefix list is null). Nt=%08x", nt);	
		PrintAndLog("Failing is expected to happen in 25%% of all cases. Trying again with a different reader nonce...");
		c.arg[0] = false;
		goto start;
	} else {
		
		// nonce2key found a candidate key.  Lets verify it.
		uint8_t keyblock[] = {0,0,0,0,0,0};
		num_to_bytes(r_key, 6, keyblock);
		uint64_t key64 = 0;
		int res = mfCheckKeys(blockNo, keytype - 0x60 , false, 1, keyblock, &key64);
		if ( res > 0 ) {
			PrintAndLog("Candidate Key found (%012"llx") - Test authentication failed. Starting over darkside attack", r_key);	
			goto start;
		}
		PrintAndLog("Found valid key: %012"llx" \n", r_key);
	}
END:
	t1 = clock() - t1;
	time(&end);
	unsigned long elapsed_time = difftime(end, start);	
	if ( t1 > 0 )
		PrintAndLog("Time in darkside: %.0f ticks %u seconds\n", (float)t1, elapsed_time);
	return 0;
}

int CmdHF14AMfWrBl(const char *Cmd) {
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
	PrintAndLog("--block no:%d, key type:%c, key:%s", blockNo, keyType?'B':'A', sprint_hex(key, 6));
	PrintAndLog("--data: %s", sprint_hex(bldata, 16));
	
	UsbCommand c = {CMD_MIFARE_WRITEBL, {blockNo, keyType, 0}};
	memcpy(c.d.asBytes, key, 6);
	memcpy(c.d.asBytes + 10, bldata, 16);
	clearCommandBuffer();
	SendCommand(&c);

	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
		uint8_t isOK  = resp.arg[0] & 0xff;
		PrintAndLog("isOk:%02x", isOK);
	} else {
		PrintAndLog("Command execute timeout");
	}

	return 0;
}

int CmdHF14AMfRdBl(const char *Cmd) {
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
	PrintAndLog("--block no:%d, key type:%c, key:%s ", blockNo, keyType?'B':'A', sprint_hex(key, 6));
	
	UsbCommand c = {CMD_MIFARE_READBL, {blockNo, keyType, 0}};
	memcpy(c.d.asBytes, key, 6);
	clearCommandBuffer();
	SendCommand(&c);

	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
		uint8_t isOK  = resp.arg[0] & 0xff;
		uint8_t *data = resp.d.asBytes;

		if (isOK)
			PrintAndLog("isOk:%02x data:%s", isOK, sprint_hex(data, 16));
		else
			PrintAndLog("isOk:%02x", isOK);
	} else {
		PrintAndLog("Command execute timeout");
	}

  return 0;
}

int CmdHF14AMfRdSc(const char *Cmd) {
	int i;
	uint8_t sectorNo = 0;
	uint8_t keyType = 0;
	uint8_t key[6] = {0, 0, 0, 0, 0, 0};
	uint8_t isOK  = 0;
	uint8_t *data  = NULL;
	char cmdp	= 0x00;

	if (strlen(Cmd)<3) {
		PrintAndLog("Usage:  hf mf rdsc    <sector number> <key A/B> <key (12 hex symbols)>");
		PrintAndLog("        sample: hf mf rdsc 0 A FFFFFFFFFFFF ");
		return 0;
	}	
	
	sectorNo = param_get8(Cmd, 0);
	if (sectorNo > 39) {
		PrintAndLog("Sector number must be less than 40");
		return 1;
	}
	cmdp = param_getchar(Cmd, 1);
	if (cmdp != 'a' && cmdp != 'A' && cmdp != 'b' && cmdp != 'B') {
		PrintAndLog("Key type must be A or B");
		return 1;
	}
	if (cmdp != 'A' && cmdp != 'a') keyType = 1;
	if (param_gethex(Cmd, 2, key, 12)) {
		PrintAndLog("Key must include 12 HEX symbols");
		return 1;
	}
	PrintAndLog("--sector no:%d key type:%c key:%s ", sectorNo, keyType?'B':'A', sprint_hex(key, 6));
	
	UsbCommand c = {CMD_MIFARE_READSC, {sectorNo, keyType, 0}};
	memcpy(c.d.asBytes, key, 6);
	clearCommandBuffer();
	SendCommand(&c);
	PrintAndLog(" ");

	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
		isOK  = resp.arg[0] & 0xff;
		data  = resp.d.asBytes;

		PrintAndLog("isOk:%02x", isOK);
		if (isOK) {
			for (i = 0; i < (sectorNo<32?3:15); i++) {
				PrintAndLog("data   : %s", sprint_hex(data + i * 16, 16));
			}
			PrintAndLog("trailer: %s", sprint_hex(data + (sectorNo<32?3:15) * 16, 16));
		}
	} else {
		PrintAndLog("Command execute timeout");
	}

  return 0;
}

uint8_t FirstBlockOfSector(uint8_t sectorNo) {
	if (sectorNo < 32) {
		return sectorNo * 4;
	} else {
		return 32 * 4 + (sectorNo - 32) * 16;
	}
}

uint8_t NumBlocksPerSector(uint8_t sectorNo) {
	if (sectorNo < 32) {
		return 4;
	} else {
		return 16;
	}
}

int CmdHF14AMfDump(const char *Cmd) {
	uint8_t sectorNo, blockNo;
	
	uint8_t keyA[40][6];
	uint8_t keyB[40][6];
	uint8_t rights[40][4];
	uint8_t carddata[256][16];
	uint8_t numSectors = 16;
	
	FILE *fin;
	FILE *fout;
	
	UsbCommand resp;

	char cmdp = param_getchar(Cmd, 0);
	switch (cmdp) {
		case '0' : numSectors = 5; break;
		case '1' : 
		case '\0': numSectors = 16; break;
		case '2' : numSectors = 32; break;
		case '4' : numSectors = 40; break;
		default:   numSectors = 16;
	}	
	
	if (strlen(Cmd) > 1 || cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Usage:   hf mf dump [card memory]");
		PrintAndLog("  [card memory]: 0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K");
		PrintAndLog("");
		PrintAndLog("Samples: hf mf dump");
		PrintAndLog("         hf mf dump 4");
		return 0;
	}
	
	if ((fin = fopen("dumpkeys.bin","rb")) == NULL) {
		PrintAndLog("Could not find file dumpkeys.bin");
		return 1;
	}
	
	// Read keys A from file
	size_t bytes_read;
	for (sectorNo=0; sectorNo<numSectors; sectorNo++) {
		bytes_read = fread( keyA[sectorNo], 1, 6, fin );
		if ( bytes_read == 0) {
			PrintAndLog("File reading error.");
			fclose(fin);
			return 2;
		}
	}
	
	// Read keys B from file
	for (sectorNo=0; sectorNo<numSectors; sectorNo++) {
		bytes_read = fread( keyB[sectorNo], 1, 6, fin );
		if ( bytes_read == 0) {
			PrintAndLog("File reading error.");
			fclose(fin);
			return 2;
		}
	}
	
	fclose(fin);

	PrintAndLog("|-----------------------------------------|");
	PrintAndLog("|------ Reading sector access bits...-----|");
	PrintAndLog("|-----------------------------------------|");
	
	for (sectorNo = 0; sectorNo < numSectors; sectorNo++) {
		UsbCommand c = {CMD_MIFARE_READBL, {FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 0, 0}};
		memcpy(c.d.asBytes, keyA[sectorNo], 6);
		clearCommandBuffer();
		SendCommand(&c);

		if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
			uint8_t isOK  = resp.arg[0] & 0xff;
			uint8_t *data  = resp.d.asBytes;
			if (isOK){
				rights[sectorNo][0] = ((data[7] & 0x10)>>2) | ((data[8] & 0x1)<<1) | ((data[8] & 0x10)>>4); // C1C2C3 for data area 0
				rights[sectorNo][1] = ((data[7] & 0x20)>>3) | ((data[8] & 0x2)<<0) | ((data[8] & 0x20)>>5); // C1C2C3 for data area 1
				rights[sectorNo][2] = ((data[7] & 0x40)>>4) | ((data[8] & 0x4)>>1) | ((data[8] & 0x40)>>6); // C1C2C3 for data area 2
				rights[sectorNo][3] = ((data[7] & 0x80)>>5) | ((data[8] & 0x8)>>2) | ((data[8] & 0x80)>>7); // C1C2C3 for sector trailer
			} else {
				PrintAndLog("Could not get access rights for sector %2d. Trying with defaults...", sectorNo);
				rights[sectorNo][0] = rights[sectorNo][1] = rights[sectorNo][2] = 0x00;
				rights[sectorNo][3] = 0x01;
			}
		} else {
			PrintAndLog("Command execute timeout when trying to read access rights for sector %2d. Trying with defaults...", sectorNo);
			rights[sectorNo][0] = rights[sectorNo][1] = rights[sectorNo][2] = 0x00;
			rights[sectorNo][3] = 0x01;
		}
	}
	
	PrintAndLog("|-----------------------------------------|");
	PrintAndLog("|----- Dumping all blocks to file... -----|");
	PrintAndLog("|-----------------------------------------|");
	
	bool isOK = true;
	for (sectorNo = 0; isOK && sectorNo < numSectors; sectorNo++) {
		for (blockNo = 0; isOK && blockNo < NumBlocksPerSector(sectorNo); blockNo++) {
			bool received = false;
			
			if (blockNo == NumBlocksPerSector(sectorNo) - 1) {		// sector trailer. At least the Access Conditions can always be read with key A. 
				UsbCommand c = {CMD_MIFARE_READBL, {FirstBlockOfSector(sectorNo) + blockNo, 0, 0}};
				memcpy(c.d.asBytes, keyA[sectorNo], 6);
				clearCommandBuffer();
				SendCommand(&c);
				received = WaitForResponseTimeout(CMD_ACK,&resp,1500);
			} else {												// data block. Check if it can be read with key A or key B
				uint8_t data_area = sectorNo<32?blockNo:blockNo/5;
				if ((rights[sectorNo][data_area] == 0x03) || (rights[sectorNo][data_area] == 0x05)) {	// only key B would work
					UsbCommand c = {CMD_MIFARE_READBL, {FirstBlockOfSector(sectorNo) + blockNo, 1, 0}};
					memcpy(c.d.asBytes, keyB[sectorNo], 6);
					SendCommand(&c);
					received = WaitForResponseTimeout(CMD_ACK,&resp,1500);
				} else if (rights[sectorNo][data_area] == 0x07) {										// no key would work
					isOK = false;
					PrintAndLog("Access rights do not allow reading of sector %2d block %3d", sectorNo, blockNo);
				} else {																				// key A would work
					UsbCommand c = {CMD_MIFARE_READBL, {FirstBlockOfSector(sectorNo) + blockNo, 0, 0}};
					memcpy(c.d.asBytes, keyA[sectorNo], 6);
					clearCommandBuffer();
					SendCommand(&c);
					received = WaitForResponseTimeout(CMD_ACK,&resp,1500);
				}
			}

			if (received) {
				isOK  = resp.arg[0] & 0xff;
				uint8_t *data  = resp.d.asBytes;
				if (blockNo == NumBlocksPerSector(sectorNo) - 1) {		// sector trailer. Fill in the keys.
					data[0]  = (keyA[sectorNo][0]);
					data[1]  = (keyA[sectorNo][1]);
					data[2]  = (keyA[sectorNo][2]);
					data[3]  = (keyA[sectorNo][3]);
					data[4]  = (keyA[sectorNo][4]);
					data[5]  = (keyA[sectorNo][5]);
					data[10] = (keyB[sectorNo][0]);
					data[11] = (keyB[sectorNo][1]);
					data[12] = (keyB[sectorNo][2]);
					data[13] = (keyB[sectorNo][3]);
					data[14] = (keyB[sectorNo][4]);
					data[15] = (keyB[sectorNo][5]);
				}
				if (isOK) {
					memcpy(carddata[FirstBlockOfSector(sectorNo) + blockNo], data, 16);
                    PrintAndLog("Successfully read block %2d of sector %2d.", blockNo, sectorNo);
				} else {
					PrintAndLog("Could not read block %2d of sector %2d", blockNo, sectorNo);
					break;
				}
			}
			else {
				isOK = false;
				PrintAndLog("Command execute timeout when trying to read block %2d of sector %2d.", blockNo, sectorNo);
				break;
			}
		}
	}

	if (isOK) {
		if ((fout = fopen("dumpdata.bin","wb")) == NULL) { 
			PrintAndLog("Could not create file name dumpdata.bin");
			return 1;
		}
		uint16_t numblocks = FirstBlockOfSector(numSectors - 1) + NumBlocksPerSector(numSectors - 1);
		fwrite(carddata, 1, 16*numblocks, fout);
		fclose(fout);
		PrintAndLog("Dumped %d blocks (%d bytes) to file dumpdata.bin", numblocks, 16*numblocks);
	}
		
	return 0;
}

int CmdHF14AMfRestore(const char *Cmd) {
	uint8_t sectorNo,blockNo;
	uint8_t keyType = 0;
	uint8_t key[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	uint8_t bldata[16] = {0x00};
	uint8_t keyA[40][6];
	uint8_t keyB[40][6];
	uint8_t numSectors;
	
	FILE *fdump;
	FILE *fkeys;

	char cmdp = param_getchar(Cmd, 0);
	switch (cmdp) {
		case '0' : numSectors = 5; break;
		case '1' : 
		case '\0': numSectors = 16; break;
		case '2' : numSectors = 32; break;
		case '4' : numSectors = 40; break;
		default:   numSectors = 16;
	}	

	if (strlen(Cmd) > 1 || cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Usage:   hf mf restore [card memory]");
		PrintAndLog("  [card memory]: 0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K");
		PrintAndLog("");
		PrintAndLog("Samples: hf mf restore");
		PrintAndLog("         hf mf restore 4");
		return 0;
	}

	if ((fkeys = fopen("dumpkeys.bin","rb")) == NULL) {
		PrintAndLog("Could not find file dumpkeys.bin");
		return 1;
	}
	
	size_t bytes_read;
	for (sectorNo = 0; sectorNo < numSectors; sectorNo++) {
		bytes_read = fread( keyA[sectorNo], 1, 6, fkeys );
		if ( bytes_read == 0) {
			PrintAndLog("File reading error (dumpkeys.bin).");
			fclose(fkeys);
			return 2;
		}
	}

	for (sectorNo = 0; sectorNo < numSectors; sectorNo++) {
		bytes_read = fread( keyB[sectorNo], 1, 6, fkeys );
		if ( bytes_read == 0) {
			PrintAndLog("File reading error (dumpkeys.bin).");
			fclose(fkeys);
			return 2;
		}
	}

	fclose(fkeys);

	if ((fdump = fopen("dumpdata.bin","rb")) == NULL) {
		PrintAndLog("Could not find file dumpdata.bin");
		return 1;
	}	
	PrintAndLog("Restoring dumpdata.bin to card");

	for (sectorNo = 0; sectorNo < numSectors; sectorNo++) {
		for(blockNo = 0; blockNo < NumBlocksPerSector(sectorNo); blockNo++) {
			UsbCommand c = {CMD_MIFARE_WRITEBL, {FirstBlockOfSector(sectorNo) + blockNo, keyType, 0}};
			memcpy(c.d.asBytes, key, 6);			
			bytes_read = fread(bldata, 1, 16, fdump);
			if ( bytes_read == 0) {
				PrintAndLog("File reading error (dumpdata.bin).");
				fclose(fdump);
				return 2;
			}
					
			if (blockNo == NumBlocksPerSector(sectorNo) - 1) {	// sector trailer
				bldata[0]  = (keyA[sectorNo][0]);
				bldata[1]  = (keyA[sectorNo][1]);
				bldata[2]  = (keyA[sectorNo][2]);
				bldata[3]  = (keyA[sectorNo][3]);
				bldata[4]  = (keyA[sectorNo][4]);
				bldata[5]  = (keyA[sectorNo][5]);
				bldata[10] = (keyB[sectorNo][0]);
				bldata[11] = (keyB[sectorNo][1]);
				bldata[12] = (keyB[sectorNo][2]);
				bldata[13] = (keyB[sectorNo][3]);
				bldata[14] = (keyB[sectorNo][4]);
				bldata[15] = (keyB[sectorNo][5]);
			}		
			
			PrintAndLog("Writing to block %3d: %s", FirstBlockOfSector(sectorNo) + blockNo, sprint_hex(bldata, 16));
			
			memcpy(c.d.asBytes + 10, bldata, 16);
			clearCommandBuffer();
			SendCommand(&c);

			UsbCommand resp;
			if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
				uint8_t isOK  = resp.arg[0] & 0xff;
				PrintAndLog("isOk:%02x", isOK);
			} else {
				PrintAndLog("Command execute timeout");
			}
		}
	}
	
	fclose(fdump);
	return 0;
}

int CmdHF14AMfNested(const char *Cmd) {
	int i, j, res, iterations;
	sector *e_sector = NULL;
	uint8_t blockNo = 0;
	uint8_t keyType = 0;
	uint8_t trgBlockNo = 0;
	uint8_t trgKeyType = 0;
	uint8_t SectorsCnt = 0;
	uint8_t key[6] = {0, 0, 0, 0, 0, 0};
	uint8_t keyBlock[6*6];
	uint64_t key64 = 0;
	bool transferToEml = false;
	
	bool createDumpFile = false;
	FILE *fkeys;
	uint8_t standart[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	uint8_t tempkey[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	if (strlen(Cmd)<3) return usage_hf14_nested();
	
	char cmdp, ctmp;
	cmdp = param_getchar(Cmd, 0);
	blockNo = param_get8(Cmd, 1);
	ctmp = param_getchar(Cmd, 2);

	if (ctmp != 'a' && ctmp != 'A' && ctmp != 'b' && ctmp != 'B') {
		PrintAndLog("Key type must be A or B");
		return 1;
	}
	
	if (ctmp != 'A' && ctmp != 'a') 
		keyType = 1;
		
	if (param_gethex(Cmd, 3, key, 12)) {
		PrintAndLog("Key must include 12 HEX symbols");
		return 1;
	}
	
	if (cmdp == 'o' || cmdp == 'O') {
		cmdp = 'o';
		trgBlockNo = param_get8(Cmd, 4);
		ctmp = param_getchar(Cmd, 5);
		if (ctmp != 'a' && ctmp != 'A' && ctmp != 'b' && ctmp != 'B') {
			PrintAndLog("Target key type must be A or B");
			return 1;
		}
		if (ctmp != 'A' && ctmp != 'a') 
			trgKeyType = 1;
	} else {
				
		switch (cmdp) {
			case '0': SectorsCnt = 05; break;
			case '1': SectorsCnt = 16; break;
			case '2': SectorsCnt = 32; break;
			case '4': SectorsCnt = 40; break;
			default:  SectorsCnt = 16;
		}
	}

	ctmp = param_getchar(Cmd, 4);
	if		(ctmp == 't' || ctmp == 'T') transferToEml = true;
	else if (ctmp == 'd' || ctmp == 'D') createDumpFile = true;
	
	ctmp = param_getchar(Cmd, 6);
	transferToEml |= (ctmp == 't' || ctmp == 'T');
	transferToEml |= (ctmp == 'd' || ctmp == 'D');
	
	if (cmdp == 'o') {
		int16_t isOK = mfnested(blockNo, keyType, key, trgBlockNo, trgKeyType, keyBlock, true);
		switch (isOK) {
			case -1 : PrintAndLog("Error: No response from Proxmark.\n"); break;
			case -2 : PrintAndLog("Button pressed. Aborted.\n"); break;
			case -3 : PrintAndLog("Tag isn't vulnerable to Nested Attack (its random number generator is not predictable).\n"); break;
			case -4 : PrintAndLog("No valid key found"); break;
			case -5 : 
				key64 = bytes_to_num(keyBlock, 6);

				// transfer key to the emulator
				if (transferToEml) {
					uint8_t sectortrailer;
					if (trgBlockNo < 32*4) { 	// 4 block sector
						sectortrailer = (trgBlockNo & 0x03) + 3;
					} else {					// 16 block sector
						sectortrailer = (trgBlockNo & 0x0f) + 15;
					}
					mfEmlGetMem(keyBlock, sectortrailer, 1);
			
					if (!trgKeyType)
						num_to_bytes(key64, 6, keyBlock);
					else
						num_to_bytes(key64, 6, &keyBlock[10]);
					mfEmlSetMem(keyBlock, sectortrailer, 1);		
				}
				return 0;
			default : PrintAndLog("Unknown Error.\n");
		}
		return 2;
	}
	else { // ------------------------------------  multiple sectors working
		clock_t t1 = clock();
		unsigned long elapsed_time;
		time_t start, end;
		time(&start);
		
		e_sector = calloc(SectorsCnt, sizeof(sector));
		if (e_sector == NULL) return 1;
		
		//test current key and additional standard keys first
		memcpy(keyBlock, key, 6);
		num_to_bytes(0xffffffffffff, 6, (uint8_t*)(keyBlock + 1 * 6));
		num_to_bytes(0x000000000000, 6, (uint8_t*)(keyBlock + 2 * 6));
		num_to_bytes(0xa0a1a2a3a4a5, 6, (uint8_t*)(keyBlock + 3 * 6));
		num_to_bytes(0xb0b1b2b3b4b5, 6, (uint8_t*)(keyBlock + 4 * 6));
		num_to_bytes(0xaabbccddeeff, 6, (uint8_t*)(keyBlock + 5 * 6));

		PrintAndLog("Testing known keys. Sector count=%d", SectorsCnt);
		for (i = 0; i < SectorsCnt; i++) {
			for (j = 0; j < 2; j++) {
				if (e_sector[i].foundKey[j]) continue;
				
				res = mfCheckKeys(FirstBlockOfSector(i), j, true, 6, keyBlock, &key64);
				
				if (!res) {
					e_sector[i].Key[j] = key64;
					e_sector[i].foundKey[j] = TRUE;
				}
			}
		}
		clock_t t2 = clock() - t1;
		time(&end);
		elapsed_time = difftime(end, start);	
		if ( t2 > 0 )
			PrintAndLog("Time to check 6 known keys: %.0f ticks %u seconds\n", (float)t2 , elapsed_time);
		
		PrintAndLog("enter nested...");	
		
		// nested sectors
		iterations = 0;
		bool calibrate = true;

		for (i = 0; i < NESTED_SECTOR_RETRY; i++) {
			for (uint8_t sectorNo = 0; sectorNo < SectorsCnt; ++sectorNo) {
				for (trgKeyType = 0; trgKeyType < 2; ++trgKeyType) { 

					if (e_sector[sectorNo].foundKey[trgKeyType]) continue;
					
					int16_t isOK = mfnested(blockNo, keyType, key, FirstBlockOfSector(sectorNo), trgKeyType, keyBlock, calibrate);
					switch (isOK) {
						case -1 : PrintAndLog("Error: No response from Proxmark.\n"); break;
						case -2 : PrintAndLog("Button pressed. Aborted.\n"); break;
						case -3 : PrintAndLog("Tag isn't vulnerable to Nested Attack (its random number generator is not predictable).\n"); break;
						case -4 : //key not found
							calibrate = false;
							iterations++;
							continue; 
						case -5 :
							calibrate = false;
							iterations++;
							e_sector[sectorNo].foundKey[trgKeyType] = 1;
							e_sector[sectorNo].Key[trgKeyType] = bytes_to_num(keyBlock, 6);
							continue;
							
						default : PrintAndLog("Unknown Error.\n");
					}
					free(e_sector);
					return 2;
				}
			}
		}
		
		t1 = clock() - t1;
		time(&end);
		elapsed_time = difftime(end, start);	
		if ( t1 > 0 )
			PrintAndLog("Time in nested: %.0f ticks %u seconds\n", (float)t1, elapsed_time);


		// 20160116 If Sector A is found, but not Sector B,  try just reading it of the tag?
		PrintAndLog("trying to read key B...");
		for (i = 0; i < SectorsCnt; i++) {
			// KEY A  but not KEY B
			if ( e_sector[i].foundKey[0] && !e_sector[i].foundKey[1] ) {
				
				uint8_t sectrail = (FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1);
				
				PrintAndLog("Reading block %d", sectrail);
							
				UsbCommand c = {CMD_MIFARE_READBL, {sectrail, 0, 0}};
				num_to_bytes(e_sector[i].Key[0], 6, c.d.asBytes); // KEY A
				clearCommandBuffer();
				SendCommand(&c);

				UsbCommand resp;
				if ( !WaitForResponseTimeout(CMD_ACK,&resp,1500)) continue;
					
				uint8_t isOK  = resp.arg[0] & 0xff;
				if (!isOK) continue;

				uint8_t *data = resp.d.asBytes;
				key64 = bytes_to_num(data+10, 6);
				if (key64) {
					PrintAndLog("Data:%s", sprint_hex(data+10, 6));
					e_sector[i].foundKey[1] = TRUE;
					e_sector[i].Key[1] = key64;
				}
			}
		}

		
		//print them
		printKeyTable( SectorsCnt, e_sector );
		
		// transfer them to the emulator
		if (transferToEml) {
			for (i = 0; i < SectorsCnt; i++) {
				mfEmlGetMem(keyBlock, FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1, 1);
				if (e_sector[i].foundKey[0])
					num_to_bytes(e_sector[i].Key[0], 6, keyBlock);
				if (e_sector[i].foundKey[1])
					num_to_bytes(e_sector[i].Key[1], 6, &keyBlock[10]);
				mfEmlSetMem(keyBlock, FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1, 1);
			}		
		}
		
		// Create dump file
		if (createDumpFile) {
			if ((fkeys = fopen("dumpkeys.bin","wb")) == NULL) { 
				PrintAndLog("Could not create file dumpkeys.bin");
				free(e_sector);
				return 1;
			}
			PrintAndLog("Printing keys to binary file dumpkeys.bin...");
			for(i=0; i<SectorsCnt; i++) {
				if (e_sector[i].foundKey[0]){
					num_to_bytes(e_sector[i].Key[0], 6, tempkey);
					fwrite ( tempkey, 1, 6, fkeys );
				}
				else{
					fwrite ( &standart, 1, 6, fkeys );
				}
			}
			for(i=0; i<SectorsCnt; i++) {
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

int CmdHF14AMfNestedHard(const char *Cmd) {
	uint8_t blockNo = 0;
	uint8_t keyType = 0;
	uint8_t trgBlockNo = 0;
	uint8_t trgKeyType = 0;
	uint8_t key[6] = {0, 0, 0, 0, 0, 0};
	uint8_t trgkey[6] = {0, 0, 0, 0, 0, 0};
	
	char ctmp;
	ctmp = param_getchar(Cmd, 0);
	if (ctmp == 'H' || ctmp == 'h' ) return usage_hf14_hardnested();
	if (ctmp != 'R' && ctmp != 'r' && ctmp != 'T' && ctmp != 't' && strlen(Cmd) < 20) return usage_hf14_hardnested();
	
	bool know_target_key = false;
	bool nonce_file_read = false;
	bool nonce_file_write = false;
	bool slow = false;
	int tests = 0;
	
	if (ctmp == 'R' || ctmp == 'r') {
		nonce_file_read = true;
		if (!param_gethex(Cmd, 1, trgkey, 12)) {
			know_target_key = true;
		}
	} else if (ctmp == 'T' || ctmp == 't') {
		tests = param_get32ex(Cmd, 1, 100, 10);
	} else {
		blockNo = param_get8(Cmd, 0);
		ctmp = param_getchar(Cmd, 1);
		if (ctmp != 'a' && ctmp != 'A' && ctmp != 'b' && ctmp != 'B') {
			PrintAndLog("Key type must be A or B");
			return 1;
		}
		if (ctmp != 'A' && ctmp != 'a') { 
			keyType = 1;
		}
		
		if (param_gethex(Cmd, 2, key, 12)) {
			PrintAndLog("Key must include 12 HEX symbols");
			return 1;
		}
		
		trgBlockNo = param_get8(Cmd, 3);
		ctmp = param_getchar(Cmd, 4);
		if (ctmp != 'a' && ctmp != 'A' && ctmp != 'b' && ctmp != 'B') {
			PrintAndLog("Target key type must be A or B");
			return 1;
		}
		if (ctmp != 'A' && ctmp != 'a') {
			trgKeyType = 1;
		}

		uint16_t i = 5;

		if (!param_gethex(Cmd, 5, trgkey, 12)) {
			know_target_key = true;
			i++;
		}

		while ((ctmp = param_getchar(Cmd, i))) {
			if (ctmp == 's' || ctmp == 'S') {
				slow = true;
			} else if (ctmp == 'w' || ctmp == 'W') {
				nonce_file_write = true;
			} else {
				PrintAndLog("Possible options are w and/or s");
				return 1;
			}
			i++;
		}
	}

	PrintAndLog("--target block no:%3d, target key type:%c, known target key: 0x%02x%02x%02x%02x%02x%02x%s, file action: %s, Slow: %s, Tests: %d ", 
			trgBlockNo, 
			trgKeyType?'B':'A', 
			trgkey[0], trgkey[1], trgkey[2], trgkey[3], trgkey[4], trgkey[5],
			know_target_key ? "" : " (not set)",
			nonce_file_write ? "write": nonce_file_read ? "read" : "none",
			slow ? "Yes" : "No",
			tests);

	int16_t isOK = mfnestedhard(blockNo, keyType, key, trgBlockNo, trgKeyType, know_target_key?trgkey:NULL, nonce_file_read, nonce_file_write, slow, tests);

	if (isOK) {
		switch (isOK) {
			case 1 : PrintAndLog("Error: No response from Proxmark.\n"); break;
			case 2 : PrintAndLog("Button pressed. Aborted.\n"); break;
			default : break;
		}
		return 2;
	}

	return 0;
}

int CmdHF14AMfChk(const char *Cmd) {

	if (strlen(Cmd)<3) return usage_hf14_chk();

	FILE * f;
	char filename[FILE_PATH_SIZE]={0};
	char buf[13];
	uint8_t *keyBlock = NULL, *p;
	uint8_t stKeyBlock = 20;
	
	sector *e_sector = NULL;
	
	int i, res;
	int	keycnt = 0;
	char ctmp	= 0x00;
	uint8_t blockNo = 0;
	uint8_t SectorsCnt = 1;
	uint8_t keyType = 0;
	uint64_t key64 = 0;
	
	uint8_t tempkey[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
		
	int transferToEml = 0;
	int createDumpFile = 0;

	keyBlock = calloc(stKeyBlock, 6);
	if (keyBlock == NULL) return 1;

	uint64_t defaultKeys[] = {
		0xffffffffffff, // Default key (first key used by program if no user defined key)
		0x000000000000, // Blank key
		0xa0a1a2a3a4a5, // NFCForum MAD key
		0xb0b1b2b3b4b5,
		0xaabbccddeeff,
		0x4d3a99c351dd,
		0x1a982c7e459a,
		0xd3f7d3f7d3f7,
		0x714c5c886e97,
		0x587ee5f9350f,
		0xa0478cc39091,
		0x533cb6c723f6,
		0x8fd0a4f256e9
	};
	int defaultKeysSize = sizeof(defaultKeys) / sizeof(uint64_t);

	for (int defaultKeyCounter = 0; defaultKeyCounter < defaultKeysSize; defaultKeyCounter++)
		num_to_bytes(defaultKeys[defaultKeyCounter], 6, (uint8_t*)(keyBlock + defaultKeyCounter * 6));

	
	if (param_getchar(Cmd, 0)=='*') {
		blockNo = 3;
		switch(param_getchar(Cmd+1, 0)) {
			case '0': SectorsCnt =  5; break;
			case '1': SectorsCnt = 16; break;
			case '2': SectorsCnt = 32; break;
			case '4': SectorsCnt = 40; break;
			default:  SectorsCnt = 16;
		}
	} else {
		blockNo = param_get8(Cmd, 0);
	}
	
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
		free(keyBlock);
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
			PrintAndLog("key[%2d] %02x%02x%02x%02x%02x%02x", keycnt,
			(keyBlock + 6*keycnt)[0],(keyBlock + 6*keycnt)[1], (keyBlock + 6*keycnt)[2],
			(keyBlock + 6*keycnt)[3], (keyBlock + 6*keycnt)[4],	(keyBlock + 6*keycnt)[5], 6);
			keycnt++;
		} else {
			// May be a dic file
			if ( param_getstr(Cmd, 2 + i,filename) >= FILE_PATH_SIZE ) {
				PrintAndLog("File name too long");
				free(keyBlock);
				return 2;
			}
			
			if ( (f = fopen( filename , "r")) ) {
				while( fgets(buf, sizeof(buf), f) ){
					if (strlen(buf) < 12 || buf[11] == '\n')
						continue;
				
					while (fgetc(f) != '\n' && !feof(f)) ;  //goto next line
					
					if( buf[0]=='#' ) continue;	//The line start with # is comment, skip

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
							fclose(f);
							return 2;
						}
						keyBlock = p;
					}
					memset(keyBlock + 6 * keycnt, 0, 6);
					num_to_bytes(strtoll(buf, NULL, 16), 6, keyBlock + 6*keycnt);
					PrintAndLog("check key[%2d] %012"llx, keycnt, bytes_to_num(keyBlock + 6*keycnt, 6));
					keycnt++;
					memset(buf, 0, sizeof(buf));
				}
				fclose(f);
			} else {
				PrintAndLog("File: %s: not found or locked.", filename);
				free(keyBlock);
				return 1;
			
			}
		}
	}
	
	if (keycnt == 0) {
		PrintAndLog("No key specified, trying default keys");
		for (;keycnt < defaultKeysSize; keycnt++)
			PrintAndLog("key[%2d] %02x%02x%02x%02x%02x%02x", keycnt,
				(keyBlock + 6*keycnt)[0],(keyBlock + 6*keycnt)[1], (keyBlock + 6*keycnt)[2],
				(keyBlock + 6*keycnt)[3], (keyBlock + 6*keycnt)[4],	(keyBlock + 6*keycnt)[5], 6);
	}
	
	// initialize storage for found keys
	e_sector = calloc(SectorsCnt, sizeof(sector));
	if (e_sector == NULL) {
		free(keyBlock);
		return 1;
	}

	// empty e_sector
	for(int i = 0; i < SectorsCnt; ++i){
		e_sector[i].Key[0] = 0xffffffffffff;
		e_sector[i].Key[1] = 0xffffffffffff;
		e_sector[i].foundKey[0] = FALSE;
		e_sector[i].foundKey[1] = FALSE;
	}
		
	
	uint8_t trgKeyType = 0;
	uint32_t max_keys = keycnt > (USB_CMD_DATA_SIZE/6) ? (USB_CMD_DATA_SIZE/6) : keycnt;
	
	// time
	clock_t t1 = clock();
	time_t start, end;
	time(&start);
	
	// check keys.
	for (trgKeyType = !keyType;  trgKeyType < 2;  (keyType==2) ? (++trgKeyType) : (trgKeyType=2) ) {

		int b = blockNo;
		for (int i = 0; i < SectorsCnt; ++i) {
			
			// skip already found keys.
			if (e_sector[i].foundKey[trgKeyType]) continue;
						
			for (uint32_t c = 0; c < keycnt; c += max_keys) {
				printf(".");
				fflush(stdout);			
				uint32_t size = keycnt-c > max_keys ? max_keys : keycnt-c;
				
				res = mfCheckKeys(b, trgKeyType, true, size, &keyBlock[6*c], &key64);
				if (!res) {
					e_sector[i].Key[trgKeyType] = key64;
					e_sector[i].foundKey[trgKeyType] = TRUE;
					break;
				}
			}
			b < 127 ? ( b +=4 ) : ( b += 16 );	
		}
	}
	t1 = clock() - t1;
	time(&end);
	unsigned long elapsed_time = difftime(end, start);	
	if ( t1 > 0 )
		PrintAndLog("\nTime in checkkeys: %.0f ticks %u seconds\n", (float)t1, elapsed_time);

		
	// 20160116 If Sector A is found, but not Sector B,  try just reading it of the tag?
	if ( keyType != 1 ) {
		PrintAndLog("testing to read key B...");
		for (i = 0; i < SectorsCnt; i++) {
			// KEY A  but not KEY B
			if ( e_sector[i].foundKey[0] && !e_sector[i].foundKey[1] ) {
							
				uint8_t sectrail = (FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1);
				
				PrintAndLog("Reading block %d", sectrail);
				
				UsbCommand c = {CMD_MIFARE_READBL, {sectrail, 0, 0}};
				num_to_bytes(e_sector[i].Key[0], 6, c.d.asBytes); // KEY A
				clearCommandBuffer();
				SendCommand(&c);

				UsbCommand resp;
				if ( !WaitForResponseTimeout(CMD_ACK,&resp,1500)) continue;
					
				uint8_t isOK  = resp.arg[0] & 0xff;
				if (!isOK) continue;

				uint8_t *data = resp.d.asBytes;
				key64 = bytes_to_num(data+10, 6);
				if (key64) {
					PrintAndLog("Data:%s", sprint_hex(data+10, 6));
					e_sector[i].foundKey[1] = 1;
					e_sector[i].Key[1] = key64;
				}
			}
		}
	}


	//print them
	printKeyTable( SectorsCnt, e_sector );
	
	if (transferToEml) {
		uint8_t block[16] = {0x00};
		for (uint8_t i = 0; i < SectorsCnt; ++i ) {
			mfEmlGetMem(block, FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1, 1);
			if (e_sector[i].foundKey[0])
				num_to_bytes(e_sector[i].Key[0], 6, block);
			if (e_sector[i].foundKey[1])
				num_to_bytes(e_sector[i].Key[1], 6, block+10);
			mfEmlSetMem(block, FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1, 1);
		}
		PrintAndLog("Found keys have been transferred to the emulator memory");
	}
	
	if (createDumpFile) {
		FILE *fkeys = fopen("dumpkeys.bin","wb");
		if (fkeys == NULL) { 
			PrintAndLog("Could not create file dumpkeys.bin");
			free(keyBlock);
			free(e_sector);
			return 1;
		}
		PrintAndLog("Printing keys to binary file dumpkeys.bin...");
	
		for( i=0; i<SectorsCnt; i++) {
			num_to_bytes(e_sector[i].Key[0], 6, tempkey);
			fwrite ( tempkey, 1, 6, fkeys );
		}
		for(i=0; i<SectorsCnt; i++) {
			num_to_bytes(e_sector[i].Key[1], 6, tempkey);
			fwrite ( tempkey, 1, 6, fkeys );
		}
		fclose(fkeys);
		PrintAndLog("Found keys have been dumped to file dumpkeys.bin. 0xffffffffffff has been inserted for unknown keys.");			
	}
	
	free(keyBlock);
	free(e_sector);
	PrintAndLog("");
	return 0;
}
#define ATTACK_KEY_COUNT 8
sector *k_sector = NULL;
uint8_t k_sectorsCount = 16;
void readerAttack(nonces_t data[], bool setEmulatorMem) {

	// initialize storage for found keys
	if (k_sector == NULL)
		k_sector = calloc(k_sectorsCount, sizeof(sector));
	if (k_sector == NULL) 
		return;

	uint64_t key = 0;
		
	// empty e_sector
	for(int i = 0; i < k_sectorsCount; ++i){
		k_sector[i].Key[0] = 0xffffffffffff;
		k_sector[i].Key[1] = 0xffffffffffff;
		k_sector[i].foundKey[0] = FALSE;
		k_sector[i].foundKey[1] = FALSE;
	}

	printf("enter reader attack\n");
	for (uint8_t i = 0; i < ATTACK_KEY_COUNT; ++i) {
		if (data[i].ar2 > 0) {
			
			if (tryMfk32(data[i], &key)) {
				PrintAndLog("Found Key%s for sector %02d: [%012"llx"]"
					, (data[i].keytype) ? "B" : "A"
					, data[i].sector
					, key
				);

				k_sector[i].Key[data[i].keytype] = key;
				k_sector[i].foundKey[data[i].keytype] = TRUE;
				
				//set emulator memory for keys
				if (setEmulatorMem) {
					uint8_t	memBlock[16] = {0,0,0,0,0,0, 0xff, 0x0F, 0x80, 0x69, 0,0,0,0,0,0};
					num_to_bytes( k_sector[i].Key[0], 6, memBlock);
					num_to_bytes( k_sector[i].Key[1], 6, memBlock+10);
					mfEmlSetMem( memBlock, i*4 + 3, 1);
					PrintAndLog("Setting Emulator Memory Block %02d: [%s]"
						, i*4 + 3
						, sprint_hex( memBlock, sizeof(memBlock))
						);
				}
				break;
			}
			//moebius attack			
			// if (tryMfk32_moebius(data[i+ATTACK_KEY_COUNT], &key)) {
				// PrintAndLog("M-Found Key%s for sector %02d: [%012"llx"]"
					// ,(data[i+ATTACK_KEY_COUNT].keytype) ? "B" : "A"
					// , data[i+ATTACK_KEY_COUNT].sector
					// , key
				// );
			// }
		}
	}
}

int CmdHF14AMf1kSim(const char *Cmd) {

	uint8_t uid[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	uint8_t exitAfterNReads = 0;
	uint8_t flags = (FLAG_UID_IN_EMUL | FLAG_4B_UID_IN_DATA);
	int uidlen = 0;	
	bool setEmulatorMem = false;
	uint8_t cmdp = 0;
	bool errors = false;

	while(param_getchar(Cmd, cmdp) != 0x00) {
		switch(param_getchar(Cmd, cmdp)) {
		case 'e':
		case 'E':
			setEmulatorMem = true;
			cmdp++;
			break;
		case 'h':
		case 'H':
			return usage_hf14_mf1ksim();
		case 'i':
		case 'I':
			flags |= FLAG_INTERACTIVE;
			cmdp++;
			break;
		case 'n':
		case 'N':
			exitAfterNReads = param_get8(Cmd, cmdp+1);
			cmdp += 2;
			break;
		case 'u':
		case 'U':
			param_gethex_ex(Cmd, cmdp+1, uid, &uidlen);
			switch(uidlen) {
				case 20: flags = FLAG_10B_UID_IN_DATA; break;
				case 14: flags = FLAG_7B_UID_IN_DATA; break;
				case  8: flags = FLAG_4B_UID_IN_DATA; break;
				default: return usage_hf14_mf1ksim();
			}
			cmdp +=2;
			break;
		case 'x':
		case 'X':
			flags |= FLAG_NR_AR_ATTACK;
			cmdp++;
			break;
		default:
			PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
		if(errors) break;
	}
	//Validations
	if(errors) return usage_hf14_mf1ksim();
	
	PrintAndLog(" uid:%s, numreads:%d, flags:%d (0x%02x) "
				, (uidlen == 0 ) ? "N/A" : sprint_hex(uid, uidlen>>1)
				, exitAfterNReads
				, flags
				, flags);

	UsbCommand c = {CMD_SIMULATE_MIFARE_CARD, {flags, exitAfterNReads, 0}};
	memcpy(c.d.asBytes, uid, sizeof(uid));
	clearCommandBuffer();
	SendCommand(&c);

	if(flags & FLAG_INTERACTIVE) {		
		PrintAndLog("Press pm3-button or send another cmd to abort simulation");

		nonces_t data[ATTACK_KEY_COUNT*2];
		UsbCommand resp;		

		while( !ukbhit() ){
			if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500) ) continue;

			if ( !(flags & FLAG_NR_AR_ATTACK) ) break;
			if ( (resp.arg[0] & 0xffff) != CMD_SIMULATE_MIFARE_CARD ) break;

			memcpy( data, resp.d.asBytes, sizeof(data) );			
			readerAttack(data, setEmulatorMem);
		}
		
		if (k_sector != NULL) {
			printKeyTable(k_sectorsCount, k_sector );
			free(k_sector);
		}
	}
	return 0;
}

int CmdHF14AMfSniff(const char *Cmd){
	bool wantLogToFile = FALSE;
	bool wantDecrypt = FALSE;
	//bool wantSaveToEml = FALSE; TODO
	bool wantSaveToEmlFile = FALSE;

	//var 
	int tmpchar;
	int res = 0;
	int len = 0;
	int blockLen = 0;
	int pckNum = 0;
	int num = 0;
	uint8_t uid[10];
	uint8_t uid_len = 0;
	uint8_t atqa[2] = {0x00, 0x00};
	uint8_t sak = 0;
	bool isTag = FALSE;
	uint8_t *buf = NULL;
	uint16_t bufsize = 0;
	uint8_t *bufPtr = NULL;
	uint16_t traceLen = 0;
	
	memset(uid, 0x00, sizeof(uid));
	
	char ctmp = param_getchar(Cmd, 0);
	if ( ctmp == 'h' || ctmp == 'H' ) return usage_hf14_sniff();
	
	for (int i = 0; i < 4; i++) {
		ctmp = param_getchar(Cmd, i);
		if (ctmp == 'l' || ctmp == 'L') wantLogToFile = true;
		if (ctmp == 'd' || ctmp == 'D') wantDecrypt = true;
		//if (ctmp == 'e' || ctmp == 'E') wantSaveToEml = true; TODO
		if (ctmp == 'f' || ctmp == 'F') wantSaveToEmlFile = true;
	}
	
	printf("-------------------------------------------------------------------------\n");
	printf("Executing mifare sniffing command. \n");
	printf("Press the key on the proxmark3 device to abort both proxmark3 and client.\n");
	printf("Press the key on pc keyboard to abort the client.\n");
	printf("-------------------------------------------------------------------------\n");

	UsbCommand c = {CMD_MIFARE_SNIFFER, {0, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);

	// wait cycle
	while (true) {
		printf(".");
		fflush(stdout);
		if (ukbhit()) {
			tmpchar = getchar();
			(void)tmpchar;
			printf("\naborted via keyboard!\n");
			break;
		}
		
		UsbCommand resp;
		if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
			res = resp.arg[0] & 0xff;
			traceLen = resp.arg[1];
			len = resp.arg[2];

			// we are done?
			if (res == 0) {
				free(buf);
				return 0;
			}

			if (res == 1) {								// there is (more) data to be transferred
				if (pckNum == 0) {						// first packet, (re)allocate necessary buffer
					if (traceLen > bufsize) {
						uint8_t *p;
						if (buf == NULL)				// not yet allocated
							p = malloc(traceLen);
						else						// need more memory
							p = realloc(buf, traceLen);
						
						if (p == NULL) {
							PrintAndLog("Cannot allocate memory for trace");
							free(buf);
							return 2;
						}
						buf = p;
					}
					bufPtr = buf;
					bufsize = traceLen;
					memset(buf, 0x00, traceLen);
				}
				if (bufPtr == NULL) {
					PrintAndLog("Cannot allocate memory for trace");
					free(buf);
					return 2;
				}
				// what happens if LEN is bigger then TRACELEN --iceman
				memcpy(bufPtr, resp.d.asBytes, len);
				bufPtr += len;
				pckNum++;
			}

			if (res == 2) {								// received all data, start displaying
				blockLen = bufPtr - buf;
				bufPtr = buf;
				printf(">\n");
				PrintAndLog("received trace len: %d packages: %d", blockLen, pckNum);
				while (bufPtr - buf < blockLen) {
					bufPtr += 6;						// skip (void) timing information
					len = *((uint16_t *)bufPtr);
					if(len & 0x8000) {
						isTag = true;
						len &= 0x7fff;
					} else {
						isTag = false;
					}
					bufPtr += 2;
					if ((len == 17) && (bufPtr[0] == 0xff) && (bufPtr[1] == 0xff) && (bufPtr[15] == 0xff) && (bufPtr[16] == 0xff)) {
						memcpy(uid, bufPtr + 2, 10);
						memcpy(atqa, bufPtr + 2 + 10, 2);
						switch (atqa[0] & 0xC0) {
							case 0x80: uid_len = 10; break;
							case 0x40: uid_len = 7; break;
							default:   uid_len = 4; break;
						}
						sak = bufPtr[14];
						PrintAndLog("tag select uid| %s atqa:0x%02x%02x sak:0x%02x", 
							sprint_hex(uid, uid_len),
							atqa[1], 
							atqa[0], 
							sak);
						if (wantLogToFile || wantDecrypt) {
							FillFileNameByUID(logHexFileName, uid, ".log", uid_len);
							AddLogCurrentDT(logHexFileName);
						}						
						if (wantDecrypt)
							mfTraceInit(uid, uid_len, atqa, sak, wantSaveToEmlFile);
					} else {
						PrintAndLog("%03d| %s |%s", num, isTag ? "TAG" : "RDR", sprint_hex(bufPtr, len));
						if (wantLogToFile) 
							AddLogHex(logHexFileName, isTag ? "TAG| ":"RDR| ", bufPtr, len);
						if (wantDecrypt) 
							mfTraceDecode(bufPtr, len, wantSaveToEmlFile);
						num++;	
					}
					bufPtr += len;
					bufPtr += ((len-1)/8+1);	// ignore parity
				}
				pckNum = 0;
			}
		} // resp not NULL
	} // while (true)

	free(buf);
	return 0;
}

int CmdHF14AMfDbg(const char *Cmd) {

	char ctmp = param_getchar(Cmd, 0);
	if (strlen(Cmd) < 1 || ctmp == 'h' || ctmp == 'H') return usage_hf14_dbg();
	
	uint8_t dbgMode = param_get8ex(Cmd, 0, 0, 10);
	if (dbgMode > 4) return usage_hf14_dbg();

	UsbCommand c = {CMD_MIFARE_SET_DBGMODE, {dbgMode, 0, 0}};
	SendCommand(&c);
	return 0;
}

int CmdHF14AMfKeyBrute(const char *Cmd) {

	uint8_t blockNo = 0, keytype = 0;
	uint8_t key[6] = {0, 0, 0, 0, 0, 0};
	uint64_t foundkey = 0;
	
	char cmdp = param_getchar(Cmd, 0);	
	if ( cmdp == 'H' || cmdp == 'h') return usage_hf14_keybrute();
	
	// block number
	blockNo = param_get8(Cmd, 0);	 
	
	// keytype
	cmdp = param_getchar(Cmd, 1);
	if (cmdp == 'B' || cmdp == 'b') keytype = 1;
	
	// key
	if (param_gethex(Cmd, 2, key, 12)) return usage_hf14_keybrute();
	
	clock_t t1 = clock();
	time_t start, end;
	time(&start);
	
	if (mfKeyBrute( blockNo, keytype, key, &foundkey))
		PrintAndLog("Found valid key: %012"llx" \n", foundkey);
	else
		PrintAndLog("Key not found");
	
	t1 = clock() - t1;
	time(&end);
	unsigned long elapsed_time = difftime(end, start);	
	if ( t1 > 0 )
		PrintAndLog("\nTime in keybrute: %.0f ticks %u seconds\n", (float)t1, elapsed_time);
	
	return 0;	
}

void printKeyTable( uint8_t sectorscnt, sector *e_sector ){
	PrintAndLog("|---|----------------|---|----------------|---|");
	PrintAndLog("|sec|key A           |res|key B           |res|");
	PrintAndLog("|---|----------------|---|----------------|---|");
	for (uint8_t i = 0; i < sectorscnt; ++i) {
		PrintAndLog("|%03d|  %012"llx"  | %d |  %012"llx"  | %d |", i,
			e_sector[i].Key[0], e_sector[i].foundKey[0], 
			e_sector[i].Key[1], e_sector[i].foundKey[1]
		);
	}
	PrintAndLog("|---|----------------|---|----------------|---|");
}

// EMULATOR COMMANDS
int CmdHF14AMfEGet(const char *Cmd)
{
	uint8_t blockNo = 0;
	uint8_t data[16] = {0x00};

	if (strlen(Cmd) < 1 || param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("Usage:  hf mf eget <block number>");
		PrintAndLog(" sample: hf mf eget 0 ");
		return 0;
	}	
	
	blockNo = param_get8(Cmd, 0);

	PrintAndLog("");
	if (!mfEmlGetMem(data, blockNo, 1)) {
		PrintAndLog("data[%3d]:%s", blockNo, sprint_hex(data, 16));
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
	char filename[FILE_PATH_SIZE];
	char *fnameptr = filename;
	char buf[64] = {0x00};
	uint8_t buf8[64] = {0x00};
	int i, len, blockNum, numBlocks;
	int nameParamNo = 1;
	uint8_t blockWidth = 32;
	char ctmp = param_getchar(Cmd, 0);
		
	if ( ctmp == 'h' || ctmp == 'H' || ctmp == 0x00) {
		PrintAndLog("It loads emul dump from the file `filename.eml`");
		PrintAndLog("Usage:  hf mf eload [card memory] <file name w/o `.eml`> [numblocks]");
		PrintAndLog("  [card memory]: 0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K, u = UL");
		PrintAndLog("");
		PrintAndLog(" sample: hf mf eload filename");
		PrintAndLog("         hf mf eload 4 filename");
		return 0;
	}	

	switch (ctmp) {
		case '0' : numBlocks = 5*4; break;
		case '1' : 
		case '\0': numBlocks = 16*4; break;
		case '2' : numBlocks = 32*4; break;
		case '4' : numBlocks = 256; break;
		case 'U' : // fall through
		case 'u' : numBlocks = 255; blockWidth = 8; break;
		default:  {
			numBlocks = 16*4;
			nameParamNo = 0;
		}
	}
	uint32_t numblk2 = param_get32ex(Cmd,2,0,10);
	if (numblk2 > 0) numBlocks = numblk2;	

	len = param_getstr(Cmd,nameParamNo,filename);
	
	if (len > FILE_PATH_SIZE - 5) len = FILE_PATH_SIZE - 5;

	fnameptr += len;

	sprintf(fnameptr, ".eml"); 
	
	// open file
	f = fopen(filename, "r");
	if (f == NULL) {
		PrintAndLog("File %s not found or locked", filename);
		return 1;
	}
	
	blockNum = 0;
	while(!feof(f)){
		memset(buf, 0, sizeof(buf));
		
		if (fgets(buf, sizeof(buf), f) == NULL) {
			
			if (blockNum >= numBlocks) break;
			
			PrintAndLog("File reading error.");
			fclose(f);
			return 2;
		}
		
		if (strlen(buf) < blockWidth){
			if(strlen(buf) && feof(f))
				break;
			PrintAndLog("File content error. Block data must include %d HEX symbols", blockWidth);
			fclose(f);
			return 2;
		}
		
		for (i = 0; i < blockWidth; i += 2) {
			sscanf(&buf[i], "%02x", (unsigned int *)&buf8[i / 2]);
		}
		if (mfEmlSetMem_xt(buf8, blockNum, 1, blockWidth/2)) {
			PrintAndLog("Cant set emul block: %3d", blockNum);
			fclose(f);
			return 3;
		}
		printf(".");
		blockNum++;
		
		if (blockNum >= numBlocks) break;
	}
	fclose(f);
	printf("\n");
	
	if ((blockNum != numBlocks)) {
		PrintAndLog("File content error. Got %d must be %d blocks.",blockNum, numBlocks);
		return 4;
	}
	PrintAndLog("Loaded %d blocks from file: %s", blockNum, filename);
	return 0;
}

int CmdHF14AMfESave(const char *Cmd)
{
	FILE * f;
	char filename[FILE_PATH_SIZE];
	char * fnameptr = filename;
	uint8_t buf[64];
	int i, j, len, numBlocks;
	int nameParamNo = 1;
	
	memset(filename, 0, sizeof(filename));
	memset(buf, 0, sizeof(buf));

	char ctmp = param_getchar(Cmd, 0);
	
	if ( ctmp == 'h' || ctmp == 'H') {
		PrintAndLog("It saves emul dump into the file `filename.eml` or `cardID.eml`");
		PrintAndLog(" Usage:  hf mf esave [card memory] [file name w/o `.eml`]");
		PrintAndLog("  [card memory]: 0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K");
		PrintAndLog("");
		PrintAndLog(" sample: hf mf esave ");
		PrintAndLog("         hf mf esave 4");
		PrintAndLog("         hf mf esave 4 filename");
		return 0;
	}	

	switch (ctmp) {
		case '0' : numBlocks = 5*4; break;
		case '1' : 
		case '\0': numBlocks = 16*4; break;
		case '2' : numBlocks = 32*4; break;
		case '4' : numBlocks = 256; break;
		default:  {
			numBlocks = 16*4;
			nameParamNo = 0;
		}
	}

	len = param_getstr(Cmd,nameParamNo,filename);
	
	if (len > FILE_PATH_SIZE - 5) len = FILE_PATH_SIZE - 5;
	
	// user supplied filename?
	if (len < 1) {
		// get filename (UID from memory)
		if (mfEmlGetMem(buf, 0, 1)) {
			PrintAndLog("Can\'t get UID from block: %d", 0);
			len = sprintf(fnameptr, "dump");
			fnameptr += len;
		}
		else {
			for (j = 0; j < 7; j++, fnameptr += 2)
				sprintf(fnameptr, "%02X", buf[j]);
		}
	} else {
		fnameptr += len;
	}

	// add file extension
	sprintf(fnameptr, ".eml"); 
	
	// open file
	f = fopen(filename, "w+");

	if ( !f ) {
		PrintAndLog("Can't open file %s ", filename);
		return 1;
	}
	
	// put hex
	for (i = 0; i < numBlocks; i++) {
		if (mfEmlGetMem(buf, i, 1)) {
			PrintAndLog("Cant get block: %d", i);
			break;
		}
		for (j = 0; j < 16; j++)
			fprintf(f, "%02X", buf[j]); 
		fprintf(f,"\n");
	}
	fclose(f);
	
	PrintAndLog("Saved %d blocks to file: %s", numBlocks, filename);
	
  return 0;
}

int CmdHF14AMfECFill(const char *Cmd)
{
	uint8_t keyType = 0;
	uint8_t numSectors = 16;
	
	if (strlen(Cmd) < 1 || param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("Usage:  hf mf ecfill <key A/B> [card memory]");
		PrintAndLog("  [card memory]: 0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K");
		PrintAndLog("");
		PrintAndLog("samples:  hf mf ecfill A");
		PrintAndLog("          hf mf ecfill A 4");
		PrintAndLog("Read card and transfer its data to emulator memory.");
		PrintAndLog("Keys must be laid in the emulator memory. \n");
		return 0;
	}	

	char ctmp = param_getchar(Cmd, 0);
	if (ctmp != 'a' && ctmp != 'A' && ctmp != 'b' && ctmp != 'B') {
		PrintAndLog("Key type must be A or B");
		return 1;
	}
	if (ctmp != 'A' && ctmp != 'a') keyType = 1;

	ctmp = param_getchar(Cmd, 1);
	switch (ctmp) {
		case '0' : numSectors = 5; break;
		case '1' : 
		case '\0': numSectors = 16; break;
		case '2' : numSectors = 32; break;
		case '4' : numSectors = 40; break;
		default:   numSectors = 16;
	}	

	printf("--params: numSectors: %d, keyType:%d", numSectors, keyType);
	UsbCommand c = {CMD_MIFARE_EML_CARDLOAD, {numSectors, keyType, 0}};
	SendCommand(&c);
	return 0;
}

int CmdHF14AMfEKeyPrn(const char *Cmd)
{
	int i;
	uint8_t numSectors;
	uint8_t data[16];
	uint64_t keyA, keyB;

	char cmdp = param_getchar(Cmd, 0);
	
	if ( cmdp == 'h' || cmdp == 'H' ) {
		PrintAndLog("It prints the keys loaded in the emulator memory");
		PrintAndLog("Usage:  hf mf ekeyprn [card memory]");
		PrintAndLog("  [card memory]: 0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K");
		PrintAndLog("");
		PrintAndLog(" sample: hf mf ekeyprn 1");
		return 0;
	}	

	switch (cmdp) {
		case '0' : numSectors = 5; break;
		case '1' : 
		case '\0': numSectors = 16; break;
		case '2' : numSectors = 32; break;
		case '4' : numSectors = 40; break;
		default:   numSectors = 16;
	}		
	
	PrintAndLog("|---|----------------|----------------|");
	PrintAndLog("|sec|key A           |key B           |");
	PrintAndLog("|---|----------------|----------------|");
	for (i = 0; i < numSectors; i++) {
		if (mfEmlGetMem(data, FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1, 1)) {
			PrintAndLog("error get block %d", FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1);
			break;
		}
		keyA = bytes_to_num(data, 6);
		keyB = bytes_to_num(data + 10, 6);
		PrintAndLog("|%03d|  %012"llx"  |  %012"llx"  |", i, keyA, keyB);
	}
	PrintAndLog("|---|----------------|----------------|");
	
	return 0;
}

// CHINESE MAGIC COMMANDS 

int CmdHF14AMfCSetUID(const char *Cmd) {
	uint8_t wipeCard = 0;
	uint8_t uid[8] = {0x00};
	uint8_t oldUid[8] = {0x00};
	uint8_t atqa[2] = {0x00};
	uint8_t sak[1] = {0x00};
	uint8_t atqaPresent = 1;
	int res;
	char ctmp;
	int argi=0;

	if (strlen(Cmd) < 1 || param_getchar(Cmd, argi) == 'h') {
		PrintAndLog("Set UID, ATQA, and SAK for magic Chinese card (only works with such cards)");
		PrintAndLog("If you also want to wipe the card then add 'w' at the end of the command line.");
		PrintAndLog("");
		PrintAndLog("Usage:  hf mf csetuid <UID 8 hex symbols> [ATQA 4 hex symbols SAK 2 hex symbols] [w]");
		PrintAndLog("");
		PrintAndLog("sample:  hf mf csetuid 01020304");
		PrintAndLog("         hf mf csetuid 01020304 0004 08 w");
		return 0;
	}

	if (param_getchar(Cmd, argi) && param_gethex(Cmd, argi, uid, 8)) {
		PrintAndLog("UID must include 8 HEX symbols");
		return 1;
	}
	argi++;

	ctmp = param_getchar(Cmd, argi);
	if (ctmp == 'w' || ctmp == 'W') {
		wipeCard = 1;
		atqaPresent = 0;
	}

	if (atqaPresent) {
		if (param_getchar(Cmd, argi)) {
			if (param_gethex(Cmd, argi, atqa, 4)) {
				PrintAndLog("ATQA must include 4 HEX symbols");
				return 1;
			}
			argi++;
			if (!param_getchar(Cmd, argi) || param_gethex(Cmd, argi, sak, 2)) {
				PrintAndLog("SAK must include 2 HEX symbols");
				return 1;
			}
			argi++;
		} else
			atqaPresent = 0;
	}

	if(!wipeCard) {
		ctmp = param_getchar(Cmd, argi);
		if (ctmp == 'w' || ctmp == 'W') {
			wipeCard = 1;
		}
	}

	PrintAndLog("--wipe card:%s  uid:%s", (wipeCard)?"YES":"NO", sprint_hex(uid, 4));

	res = mfCSetUID(uid, (atqaPresent) ? atqa : NULL, (atqaPresent) ? sak : NULL, oldUid, wipeCard);
	if (res) {
			PrintAndLog("Can't set UID. error=%d", res);
			return 1;
		}
	
	PrintAndLog("old UID:%s", sprint_hex(oldUid, 4));
	PrintAndLog("new UID:%s", sprint_hex(uid, 4));
	return 0;
}

int CmdHF14AMfCSetBlk(const char *Cmd) {
	uint8_t block[16] = {0x00};
	uint8_t blockNo = 0;
	uint8_t params = MAGIC_SINGLE;
	int res;

	if (strlen(Cmd) < 1 || param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("Usage:  hf mf csetblk <block number> <block data (32 hex symbols)> [w]");
		PrintAndLog("sample:  hf mf csetblk 1 01020304050607080910111213141516");
		PrintAndLog("Set block data for magic Chinese card (only works with such cards)");
		PrintAndLog("If you also want wipe the card then add 'w' at the end of the command line");
		return 0;
	}	

	blockNo = param_get8(Cmd, 0);

	if (param_gethex(Cmd, 1, block, 32)) {
		PrintAndLog("block data must include 32 HEX symbols");
		return 1;
	}

	char ctmp = param_getchar(Cmd, 2);
	if (ctmp == 'w' || ctmp == 'W')
		params |= MAGIC_WIPE;
	
	PrintAndLog("--block number:%2d data:%s", blockNo, sprint_hex(block, 16));

	res = mfCSetBlock(blockNo, block, NULL, params);
	if (res) {
		PrintAndLog("Can't write block. error=%d", res);
		return 1;
	}
	return 0;
}

int CmdHF14AMfCLoad(const char *Cmd) {
	FILE * f;
	char filename[FILE_PATH_SIZE];
	char * fnameptr = filename;
	char buf[64] = {0x00};
	uint8_t buf8[64] = {0x00};
	uint8_t fillFromEmulator = 0;
	int i, len, blockNum, flags=0;

	memset(filename, 0, sizeof(filename));
	
	char ctmp = param_getchar(Cmd, 0);
	
	if (ctmp == 'h' || ctmp == 'H' || ctmp == 0x00) {
		PrintAndLog("It loads magic Chinese card from the file `filename.eml`");
		PrintAndLog("or from emulator memory (option `e`)");
		PrintAndLog("Usage:  hf mf cload <file name w/o `.eml`>");
		PrintAndLog("   or:  hf mf cload e ");
		PrintAndLog(" sample: hf mf cload filename");
		return 0;
	}	

	if (ctmp == 'e' || ctmp == 'E') fillFromEmulator = 1;
	
	if (fillFromEmulator) {
		for (blockNum = 0; blockNum < 16 * 4; blockNum += 1) {
			if (mfEmlGetMem(buf8, blockNum, 1)) {
				PrintAndLog("Cant get block: %d", blockNum);
				return 2;
			}
			if (blockNum == 0) flags = MAGIC_INIT + MAGIC_WUPC;				// switch on field and send magic sequence
			if (blockNum == 1) flags = 0;													// just write
			if (blockNum == 16 * 4 - 1) flags = MAGIC_HALT + MAGIC_OFF;		// Done. Magic Halt and switch off field.

			if (mfCSetBlock(blockNum, buf8, NULL, flags)) {
				PrintAndLog("Cant set magic card block: %d", blockNum);
				return 3;
			}
		}
		return 0;
	} else {
		len = strlen(Cmd);
		if (len > FILE_PATH_SIZE - 5) len = FILE_PATH_SIZE - 5;

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
			
			if (fgets(buf, sizeof(buf), f) == NULL) {
				fclose(f);
				PrintAndLog("File reading error.");
				return 2;
			}

			if (strlen(buf) < 32) {
				if(strlen(buf) && feof(f))
					break;
				PrintAndLog("File content error. Block data must include 32 HEX symbols");
				fclose(f);
				return 2;
			}
			for (i = 0; i < 32; i += 2)
				sscanf(&buf[i], "%02x", (unsigned int *)&buf8[i / 2]);

			if (blockNum == 0) flags = MAGIC_INIT + MAGIC_WUPC;				// switch on field and send magic sequence
			if (blockNum == 1) flags = 0;													// just write
			if (blockNum == 16 * 4 - 1) flags = MAGIC_HALT + MAGIC_OFF;		// Done. Switch off field.

			if (mfCSetBlock(blockNum, buf8, NULL, flags)) {
				PrintAndLog("Can't set magic card block: %d", blockNum);
				fclose(f);
				return 3;
			}
			blockNum++;
		
			if (blockNum >= 16 * 4) break;  // magic card type - mifare 1K
		}
		fclose(f);
	
		// 64 or 256blocks.
		if (blockNum != 16 * 4 && blockNum != 32 * 4 + 8 * 16){
			PrintAndLog("File content error. There must be 64 blocks");
			return 4;
		}
		PrintAndLog("Loaded from file: %s", filename);
		return 0;
	}
	return 0;
}

int CmdHF14AMfCGetBlk(const char *Cmd) {
	uint8_t data[16];
	uint8_t blockNo = 0;
	int res;
	memset(data, 0x00, sizeof(data));
	char ctmp = param_getchar(Cmd, 0);

	if (strlen(Cmd) < 1 || ctmp == 'h' || ctmp == 'H') {
		PrintAndLog("Usage:  hf mf cgetblk <block number>");
		PrintAndLog("sample:  hf mf cgetblk 1");
		PrintAndLog("Get block data from magic Chinese card (only works with such cards)\n");
		return 0;
	}	

	blockNo = param_get8(Cmd, 0);

	PrintAndLog("--block number:%2d ", blockNo);

	res = mfCGetBlock(blockNo, data, MAGIC_SINGLE);
	if (res) {
		PrintAndLog("Can't read block. error=%d", res);
		return 1;
	}
	
	PrintAndLog("data: %s", sprint_hex(data, sizeof(data)));
	return 0;
}

int CmdHF14AMfCGetSc(const char *Cmd) {
	uint8_t data[16];
	uint8_t sectorNo = 0;
	int i, res, flags;
	memset(data, 0x00, sizeof(data));
	char ctmp = param_getchar(Cmd, 0);
	
	if (strlen(Cmd) < 1 || ctmp == 'h' || ctmp == 'H') {
		PrintAndLog("Usage:  hf mf cgetsc <sector number>");
		PrintAndLog("sample:  hf mf cgetsc 0");
		PrintAndLog("Get sector data from magic Chinese card (only works with such cards)\n");
		return 0;
	}	

	sectorNo = param_get8(Cmd, 0);
	if (sectorNo > 15) {
		PrintAndLog("Sector number must be in [0..15] as in MIFARE classic.");
		return 1;
	}

	PrintAndLog("--sector number:%d ", sectorNo);
	PrintAndLog("block | data");

	flags = MAGIC_INIT + MAGIC_WUPC;
	for (i = 0; i < 4; i++) {
		if (i == 1) flags = 0;
		if (i == 3) flags = MAGIC_HALT + MAGIC_OFF;

		res = mfCGetBlock(sectorNo * 4 + i, data, flags);
		if (res) {
			PrintAndLog("Can't read block. %d error=%d", sectorNo * 4 + i, res);
			return 1;
		}	
		PrintAndLog(" %3d | %s", sectorNo * 4 + i, sprint_hex(data, sizeof(data)));
	}
	return 0;
}

int CmdHF14AMfCSave(const char *Cmd) {

	FILE * f;
	char filename[FILE_PATH_SIZE];
	char * fnameptr = filename;
	uint8_t fillFromEmulator = 0;
	uint8_t buf[64];
	int i, j, len, flags;
	
	memset(filename, 0, sizeof(filename));
	memset(buf, 0, sizeof(buf));
	char ctmp = param_getchar(Cmd, 0);
	
	if ( ctmp == 'h' || ctmp == 'H' ) {
		PrintAndLog("It saves `magic Chinese` card dump into the file `filename.eml` or `cardID.eml`");
		PrintAndLog("or into emulator memory (option `e`)");
		PrintAndLog("Usage:  hf mf esave [file name w/o `.eml`][e]");
		PrintAndLog(" sample: hf mf esave ");
		PrintAndLog("         hf mf esave filename");
		PrintAndLog("         hf mf esave e \n");
		return 0;
	}	
	if (ctmp == 'e' || ctmp == 'E') fillFromEmulator = 1;

	if (fillFromEmulator) {
		// put into emulator
		flags = MAGIC_INIT + MAGIC_WUPC;
		for (i = 0; i < 16 * 4; i++) {
			if (i == 1) flags = 0;
			if (i == 16 * 4 - 1) flags = MAGIC_HALT + MAGIC_OFF;
		
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
		if (len > FILE_PATH_SIZE - 5) len = FILE_PATH_SIZE - 5;
	
		// get filename based on UID
		if (len < 1) {
		
			if (mfCGetBlock(0, buf, MAGIC_SINGLE)) {
				PrintAndLog("Cant get block: %d", 0);
				len = sprintf(fnameptr, "dump");
				fnameptr += len;
			} else {
				for (j = 0; j < 7; j++, fnameptr += 2)
					sprintf(fnameptr, "%02x", buf[j]); 
			}
		} else {
			memcpy(filename, Cmd, len);
			fnameptr += len;
		}

		// add .eml extension
		sprintf(fnameptr, ".eml"); 
	
		// open file
		f = fopen(filename, "w+");

		if (f == NULL) {
			PrintAndLog("File not found or locked.");
			return 1;
		}

		// put hex
		flags = MAGIC_INIT + MAGIC_WUPC;
		for (i = 0; i < 16 * 4; i++) {
			if (i == 1) flags = 0;
			if (i == 16 * 4 - 1) flags = MAGIC_HALT + MAGIC_OFF;
		
			if (mfCGetBlock(i, buf, flags)) {
				PrintAndLog("Cant get block: %d", i);
				break;
			}
			for (j = 0; j < 16; j++)
				fprintf(f, "%02x", buf[j]); 
			fprintf(f,"\n");
		}
		fflush(f);
		fclose(f);
		PrintAndLog("Saved to file: %s", filename);
		return 0;
	}
}

//needs nt, ar, at, Data to decrypt
int CmdHf14MfDecryptBytes(const char *Cmd){
	uint8_t data[50];
	uint32_t nt 	= param_get32ex(Cmd,0,0,16);
	uint32_t ar_enc = param_get32ex(Cmd,1,0,16);
	uint32_t at_enc = param_get32ex(Cmd,2,0,16);

	int len = 0;
	param_gethex_ex(Cmd, 3, data, &len);
	
	len /= 2;	
	int limit = sizeof(data) / 2;
	
	if ( len >= limit )
		len = limit;
	
	return tryDecryptWord( nt, ar_enc, at_enc, data, len);
}

static command_t CommandTable[] = {
	{"help",		CmdHelp,				1, "This help"},
	{"dbg",			CmdHF14AMfDbg,			0, "Set default debug mode"},
	{"rdbl",		CmdHF14AMfRdBl,			0, "Read MIFARE classic block"},
	{"rdsc",		CmdHF14AMfRdSc,			0, "Read MIFARE classic sector"},
	{"dump",		CmdHF14AMfDump,			0, "Dump MIFARE classic tag to binary file"},
	{"restore",		CmdHF14AMfRestore,		0, "Restore MIFARE classic binary file to BLANK tag"},
	{"wrbl",		CmdHF14AMfWrBl,			0, "Write MIFARE classic block"},
	{"chk",			CmdHF14AMfChk,			0, "Check keys"},
	{"mifare",		CmdHF14AMifare,			0, "Darkside attack. read parity error messages."},
	{"nested",		CmdHF14AMfNested,		0, "Nested attack. Test nested authentication"},
	{"hardnested", 	CmdHF14AMfNestedHard, 	0, "Nested attack for hardened Mifare cards"},
	{"keybrute",	CmdHF14AMfKeyBrute,		0, "J_Run's 2nd phase of multiple sector nested authentication key recovery"},
	{"sniff",		CmdHF14AMfSniff,		0, "Sniff card-reader communication"},
	{"sim",			CmdHF14AMf1kSim,		0, "Simulate MIFARE card"},
	{"eclr",		CmdHF14AMfEClear,		0, "Clear simulator memory block"},
	{"eget",		CmdHF14AMfEGet,			0, "Get simulator memory block"},
	{"eset",		CmdHF14AMfESet,			0, "Set simulator memory block"},
	{"eload",		CmdHF14AMfELoad,		0, "Load from file emul dump"},
	{"esave",		CmdHF14AMfESave,		0, "Save to file emul dump"},
	{"ecfill",		CmdHF14AMfECFill,		0, "Fill simulator memory with help of keys from simulator"},
	{"ekeyprn",		CmdHF14AMfEKeyPrn,		0, "Print keys from simulator memory"},
	{"csetuid",		CmdHF14AMfCSetUID,		0, "Set UID for magic Chinese card"},
	{"csetblk",		CmdHF14AMfCSetBlk,		0, "Write block - Magic Chinese card"},
	{"cgetblk",		CmdHF14AMfCGetBlk,		0, "Read block - Magic Chinese card"},
	{"cgetsc",		CmdHF14AMfCGetSc,		0, "Read sector - Magic Chinese card"},
	{"cload",		CmdHF14AMfCLoad,		0, "Load dump into magic Chinese card"},
	{"csave",		CmdHF14AMfCSave,		0, "Save dump from magic Chinese card into file or emulator"},
	{"decrypt",		CmdHf14MfDecryptBytes,  1, "[nt] [ar_enc] [at_enc] [data] - to decrypt snoop or trace"},
	{NULL, NULL, 0, NULL}
};

int CmdHFMF(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
