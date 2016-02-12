//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>, Hagen Fritsch
// Copyright (C) 2011 Gerhard de Koning Gans
// Copyright (C) 2014 Midnitesnake & Andy Davies & Martin Holst Swende
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency iClass commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "iso14443crc.h" // Can also be used for iClass, using 0xE012 as CRC-type
#include "data.h"
#include "proxmark3.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhficlass.h"
#include "common.h"
#include "util.h"
#include "cmdmain.h"
#include "loclass/des.h"
#include "loclass/cipherutils.h"
#include "loclass/cipher.h"
#include "loclass/ikeys.h"
#include "loclass/elite_crack.h"
#include "loclass/fileutils.h"
#include "protocols.h"
#include "usb_cmd.h"
#include "cmdhfmfu.h"
#include "cmdhf.h"

static int CmdHelp(const char *Cmd);

#define ICLASS_KEYS_MAX 8
static uint8_t iClass_Key_Table[ICLASS_KEYS_MAX][8] = {
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }
};

typedef struct iclass_block {
    uint8_t d[8];
} iclass_block_t;

int xorbits_8(uint8_t val) {
	uint8_t res = val ^ (val >> 1); //1st pass
	res = res ^ (res >> 1); 		// 2nd pass
	res = res ^ (res >> 2); 		// 3rd pass
	res = res ^ (res >> 4); 			// 4th pass
	return res & 1;
}

int CmdHFiClassList(const char *Cmd) {
	//PrintAndLog("Deprecated command, use 'hf list iclass' instead");
	CmdHFList("iclass");
	return 0;
}

int CmdHFiClassSnoop(const char *Cmd) {
	UsbCommand c = {CMD_SNOOP_ICLASS};
	SendCommand(&c);
	return 0;
}

int usage_hf_iclass_sim(void) {
	PrintAndLog("Usage:  hf iclass sim <option> [CSN]");
	PrintAndLog("        options");
	PrintAndLog("                0 <CSN> simulate the given CSN");
	PrintAndLog("                1       simulate default CSN");
	PrintAndLog("                2       Reader-attack, gather reader responses to extract elite key");
	PrintAndLog("                3       Full simulation using emulator memory (see 'hf iclass eload')");
	PrintAndLog("        example: hf iclass sim 0 031FEC8AF7FF12E0");
	PrintAndLog("        example: hf iclass sim 2");
	PrintAndLog("        example: hf iclass eload 'tagdump.bin'");
	PrintAndLog("                 hf iclass sim 3");
	return 0;
}

#define NUM_CSNS 15
int CmdHFiClassSim(const char *Cmd) {
	uint8_t simType = 0;
	uint8_t CSN[8] = {0, 0, 0, 0, 0, 0, 0, 0};

	if (strlen(Cmd)<1) return usage_hf_iclass_sim();

	simType = param_get8ex(Cmd, 0, 0, 10);

	if(simType == 0)
	{
		if (param_gethex(Cmd, 1, CSN, 16)) {
			PrintAndLog("A CSN should consist of 16 HEX symbols");
			return usage_hf_iclass_sim();
		}

		PrintAndLog("--simtype:%02x csn:%s", simType, sprint_hex(CSN, 8));
	}

	if(simType > 3)
	{
		PrintAndLog("Undefined simptype %d", simType);
		return usage_hf_iclass_sim();
	}

	uint8_t numberOfCSNs=0;
	if(simType == 2)
	{
		UsbCommand c = {CMD_SIMULATE_TAG_ICLASS, {simType,NUM_CSNS}};
		UsbCommand resp = {0};

		uint8_t csns[8*NUM_CSNS] = {
			0x00, 0x0B, 0x0F, 0xFF, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x04, 0x0E, 0x08, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x09, 0x0D, 0x05, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x0A, 0x0C, 0x06, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x0F, 0x0B, 0x03, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x08, 0x0A, 0x0C, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x0D, 0x09, 0x09, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x0E, 0x08, 0x0A, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x03, 0x07, 0x17, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x3C, 0x06, 0xE0, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x01, 0x05, 0x1D, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x02, 0x04, 0x1E, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x07, 0x03, 0x1B, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x00, 0x02, 0x24, 0xF7, 0xFF, 0x12, 0xE0,
			0x00, 0x05, 0x01, 0x21, 0xF7, 0xFF, 0x12, 0xE0 };

		memcpy(c.d.asBytes, csns, 8*NUM_CSNS);
		clearCommandBuffer();
		SendCommand(&c);
		if (!WaitForResponseTimeout(CMD_ACK, &resp, -1)) {
			PrintAndLog("Command timed out");
			return 0;
		}

		uint8_t num_mac_responses  = resp.arg[1];
		PrintAndLog("Mac responses: %d MACs obtained (should be %d)", num_mac_responses,NUM_CSNS);

		size_t datalen = NUM_CSNS*24;
		/*
		 * Now, time to dump to file. We'll use this format:
		 * <8-byte CSN><8-byte CC><4 byte NR><4 byte MAC>....
		 * So, it should wind up as
		 * 8 * 24 bytes.
		 *
		 * The returndata from the pm3 is on the following format
		 * <4 byte NR><4 byte MAC>
		 * CC are all zeroes, CSN is the same as was sent in
		 **/
		void* dump = malloc(datalen);
		memset(dump,0,datalen);//<-- Need zeroes for the CC-field
		uint8_t i = 0;
		for(i = 0 ; i < NUM_CSNS ; i++) {
			memcpy(dump+i*24, csns+i*8, 8); //CSN
			//8 zero bytes here...
			//Then comes NR_MAC (eight bytes from the response)
			memcpy(dump+i*24+16, resp.d.asBytes+i*8, 8);
		}
		/** Now, save to dumpfile **/
		saveFile("iclass_mac_attack", "bin", dump, datalen);
		free(dump);
	} else {
		UsbCommand c = {CMD_SIMULATE_TAG_ICLASS, {simType,numberOfCSNs}};
		memcpy(c.d.asBytes, CSN, 8);
		clearCommandBuffer();
		SendCommand(&c);
	}
	return 0;
}

int HFiClassReader(const char *Cmd, bool loop, bool verbose) {
	bool tagFound = false;
	UsbCommand c = {CMD_READER_ICLASS, {FLAG_ICLASS_READER_CSN |
					FLAG_ICLASS_READER_CONF | FLAG_ICLASS_READER_AA}};
	// loop in client not device - else on windows have a communication error
	c.arg[0] |= FLAG_ICLASS_READER_ONLY_ONCE | FLAG_ICLASS_READER_ONE_TRY;
	UsbCommand resp;
	while(!ukbhit()){
		clearCommandBuffer();
		SendCommand(&c);
		if (WaitForResponseTimeout(CMD_ACK,&resp, 4500)) {
			uint8_t readStatus = resp.arg[0] & 0xff;
			uint8_t *data = resp.d.asBytes;

			if (verbose) PrintAndLog("Readstatus:%02x", readStatus);
			if( readStatus == 0){
				//Aborted
				if (verbose) PrintAndLog("Quitting...");
				return 0;
			}
			if( readStatus & FLAG_ICLASS_READER_CSN){
				PrintAndLog("CSN: %s",sprint_hex(data,8));
				tagFound = true;
			}
			if( readStatus & FLAG_ICLASS_READER_CC)   PrintAndLog("CC: %s", sprint_hex(data+16, 8));
			if( readStatus & FLAG_ICLASS_READER_CONF) printIclassDumpInfo(data);			
			if (tagFound && !loop) return 1;
		} else {
			if (verbose) PrintAndLog("Command execute timeout");
		}
		if (!loop) break;
	}
	return 0;
}

int CmdHFiClassReader(const char *Cmd) {
	return HFiClassReader(Cmd, true, true);
}

int CmdHFiClassReader_Replay(const char *Cmd) {
	uint8_t readerType = 0;
	uint8_t MAC[4]={0x00, 0x00, 0x00, 0x00};

	if (strlen(Cmd)<1) {
		PrintAndLog("Usage:  hf iclass replay <MAC>");
		PrintAndLog("        sample: hf iclass replay 00112233");
		return 0;
	}

	if (param_gethex(Cmd, 0, MAC, 8)) {
		PrintAndLog("MAC must include 8 HEX symbols");
		return 1;
	}

	UsbCommand c = {CMD_READER_ICLASS_REPLAY, {readerType}};
	memcpy(c.d.asBytes, MAC, 4);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int iclassEmlSetMem(uint8_t *data, int blockNum, int blocksCount) {
	UsbCommand c = {CMD_MIFARE_EML_MEMSET, {blockNum, blocksCount, 0}};
	memcpy(c.d.asBytes, data, blocksCount * 16);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int hf_iclass_eload_usage(void) {
	PrintAndLog("Loads iclass tag-dump into emulator memory on device");
	PrintAndLog("Usage:  hf iclass eload f <filename>");
	PrintAndLog("");
	PrintAndLog("Example: hf iclass eload f iclass_tagdump-aa162d30f8ff12f1.bin");
	return 0;
}

int CmdHFiClassELoad(const char *Cmd) {

	char opt = param_getchar(Cmd, 0);
	if (strlen(Cmd)<1 || opt == 'h' || opt == 'H') return hf_iclass_eload_usage();

	//File handling and reading
	FILE *f;
	char filename[FILE_PATH_SIZE];
	if(opt == 'f' && param_getstr(Cmd, 1, filename) > 0) {
		f = fopen(filename, "rb");
	} else {
		return hf_iclass_eload_usage();
	}

	if(!f) {
		PrintAndLog("Failed to read from file '%s'", filename);
		return 1;
	}

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (fsize < 0) 	{
		prnlog("Error, when getting filesize");
		fclose(f);
		return 1;
	}

	uint8_t *dump = malloc(fsize);

	size_t bytes_read = fread(dump, 1, fsize, f);
	fclose(f);

	printIclassDumpInfo(dump);
	//Validate

	if (bytes_read < fsize)	{
		prnlog("Error, could only read %d bytes (should be %d)",bytes_read, fsize );
		free(dump);
		return 1;
	}
	//Send to device
	uint32_t bytes_sent = 0;
	uint32_t bytes_remaining  = bytes_read;

	while(bytes_remaining > 0){
		uint32_t bytes_in_packet = MIN(USB_CMD_DATA_SIZE, bytes_remaining);
		UsbCommand c = {CMD_ICLASS_EML_MEMSET, {bytes_sent,bytes_in_packet,0}};
		memcpy(c.d.asBytes, dump, bytes_in_packet);
		clearCommandBuffer();
		SendCommand(&c);
		bytes_remaining -= bytes_in_packet;
		bytes_sent += bytes_in_packet;
	}
	free(dump);
	PrintAndLog("Sent %d bytes of data to device emulator memory", bytes_sent);
	return 0;
}

static int readKeyfile(const char *filename, size_t len, uint8_t* buffer) {
	FILE *f = fopen(filename, "rb");
	if(!f) {
		PrintAndLog("Failed to read from file '%s'", filename);
		return 1;
	}
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);
	size_t bytes_read = fread(buffer, 1, len, f);
	fclose(f);
	
	if(fsize != len) {
		PrintAndLog("Warning, file size is %d, expected %d", fsize, len);
		return 1;
	}
	
	if(bytes_read != len) {
		PrintAndLog("Warning, could only read %d bytes, expected %d" ,bytes_read, len);
		return 1;
	}
	return 0;
}

int usage_hf_iclass_decrypt(void) {
	PrintAndLog("Usage: hf iclass decrypt f <tagdump>");
	PrintAndLog("");
	PrintAndLog("OBS! In order to use this function, the file 'iclass_decryptionkey.bin' must reside");
	PrintAndLog("in the working directory. The file should be 16 bytes binary data");
	PrintAndLog("");
	PrintAndLog("example: hf iclass decrypt f tagdump_12312342343.bin");
	PrintAndLog("");
	PrintAndLog("OBS! This is pretty stupid implementation, it tries to decrypt every block after block 6. ");
	PrintAndLog("Correct behaviour would be to decrypt only the application areas where the key is valid,");
	PrintAndLog("which is defined by the configuration block.");
	return 1;
}

int CmdHFiClassDecrypt(const char *Cmd) {
	uint8_t key[16] = { 0 };
	if(readKeyfile("iclass_decryptionkey.bin", 16, key)) {
		usage_hf_iclass_decrypt();
		return 1;
	}
	PrintAndLog("Decryption file found... ");
	char opt = param_getchar(Cmd, 0);
	if (strlen(Cmd)<1 || opt == 'h' || opt == 'H') return usage_hf_iclass_decrypt();

	//Open the tagdump-file
	FILE *f;
	char filename[FILE_PATH_SIZE];
	if(opt == 'f' && param_getstr(Cmd, 1, filename) > 0) {
		if ( (f = fopen(filename, "rb")) == NULL) {
			PrintAndLog("Could not find file %s", filename);
			return 1;
		}		
	} else {
		return usage_hf_iclass_decrypt();
	}	

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);
	uint8_t enc_dump[8] = {0};
	uint8_t *decrypted = malloc(fsize);
	des3_context ctx = { DES_DECRYPT ,{ 0 } };
	des3_set2key_dec( &ctx, key);
	size_t bytes_read = fread(enc_dump, 1, 8, f);

	//Use the first block (CSN) for filename
	char outfilename[FILE_PATH_SIZE] = { 0 };
	snprintf(outfilename,FILE_PATH_SIZE,"iclass_tagdump-%02x%02x%02x%02x%02x%02x%02x%02x-decrypted",
			 enc_dump[0],enc_dump[1],enc_dump[2],enc_dump[3],
			 enc_dump[4],enc_dump[5],enc_dump[6],enc_dump[7]);

	size_t blocknum =0;
	while(bytes_read == 8)
	{
		if(blocknum < 7) {
			memcpy(decrypted+(blocknum*8), enc_dump, 8);
		} else {
			des3_crypt_ecb(&ctx, enc_dump,decrypted +(blocknum*8) );
		}
		printvar("decrypted block", decrypted +(blocknum*8), 8);
		bytes_read = fread(enc_dump, 1, 8, f);
		blocknum++;
	}
	fclose(f);
	saveFile(outfilename,"bin", decrypted, blocknum*8);
	free(decrypted);
	return 0;
}

int usage_hf_iclass_encrypt(void) {
	PrintAndLog("Usage: hf iclass encrypt <BlockData>");
	PrintAndLog("");
	PrintAndLog("OBS! In order to use this function, the file 'iclass_decryptionkey.bin' must reside");
	PrintAndLog("in the working directory. The file should be 16 bytes binary data");
	PrintAndLog("");
	PrintAndLog("example: hf iclass encrypt 0102030405060708");
	PrintAndLog("");
	return 0;
}

static int iClassEncryptBlkData(uint8_t *blkData) {
	uint8_t key[16] = { 0 };
	if(readKeyfile("iclass_decryptionkey.bin", 16, key)) {
		usage_hf_iclass_encrypt();
		return 1;
	}
	PrintAndLog("Decryption file found... ");

	uint8_t encryptedData[16];
	uint8_t *encrypted = encryptedData;
	des3_context ctx = { DES_DECRYPT ,{ 0 } };
	des3_set2key_enc( &ctx, key);
	
	des3_crypt_ecb(&ctx, blkData,encrypted);
	//printvar("decrypted block", decrypted, 8);
	memcpy(blkData,encrypted,8);

	return 1;
}

int CmdHFiClassEncryptBlk(const char *Cmd) {
	uint8_t blkData[8] = {0};
	char opt = param_getchar(Cmd, 0);
	if (strlen(Cmd)<1 || opt == 'h' || opt == 'H') return usage_hf_iclass_encrypt();

	//get the bytes to encrypt
	if (param_gethex(Cmd, 0, blkData, 16)) {
		PrintAndLog("BlockData must include 16 HEX symbols");
		return 0;
	}
	if (!iClassEncryptBlkData(blkData)) return 0;

	printvar("encrypted block", blkData, 8);
	return 1;
}

void Calc_wb_mac(uint8_t blockno, uint8_t *data, uint8_t *div_key, uint8_t MAC[4]) {
	uint8_t WB[9];
	WB[0] = blockno;
	memcpy(WB + 1,data,8);
	doMAC_N(WB,sizeof(WB),div_key,MAC);
	//printf("Cal wb mac block [%02x][%02x%02x%02x%02x%02x%02x%02x%02x] : MAC [%02x%02x%02x%02x]",WB[0],WB[1],WB[2],WB[3],WB[4],WB[5],WB[6],WB[7],WB[8],MAC[0],MAC[1],MAC[2],MAC[3]);
}

static bool select_only(uint8_t *CSN, uint8_t *CCNR, bool use_credit_key, bool verbose) {
	UsbCommand resp;

	UsbCommand c = {CMD_READER_ICLASS, {0}};
	c.arg[0] = FLAG_ICLASS_READER_ONLY_ONCE | FLAG_ICLASS_READER_CC | FLAG_ICLASS_READER_ONE_TRY;
	if (use_credit_key)
		c.arg[0] |= FLAG_ICLASS_READER_CEDITKEY;

	clearCommandBuffer();
	SendCommand(&c);
	if (!WaitForResponseTimeout(CMD_ACK,&resp,4500)) {
		PrintAndLog("Command execute timeout");
		return false;
	}

	uint8_t isOK = resp.arg[0] & 0xff;
	uint8_t *data = resp.d.asBytes;

	memcpy(CSN,data,8);
	
	if (CCNR!=NULL) 
		memcpy(CCNR,data+16,8);
	
	if(isOK > 0) {
		if (verbose) PrintAndLog("CSN: %s",sprint_hex(CSN,8));
	}
	
	if(isOK <= 1){
		PrintAndLog("Failed to obtain CC! Aborting");
		return false;
	}
	return true;	
}

static bool select_and_auth(uint8_t *KEY, uint8_t *MAC, uint8_t *div_key, bool use_credit_key, bool elite, bool rawkey, bool verbose) {
	uint8_t CSN[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t CCNR[12]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	if (!select_only(CSN, CCNR, use_credit_key, verbose))
		return false;

	//get div_key
	if(rawkey)
		memcpy(div_key, KEY, 8);
	else
		HFiClassCalcDivKey(CSN, KEY, div_key, elite);
	
	PrintAndLog("Authing with %s: %02x%02x%02x%02x%02x%02x%02x%02x", rawkey ? "raw key" : "diversified key", div_key[0],div_key[1],div_key[2],div_key[3],div_key[4],div_key[5],div_key[6],div_key[7]);

	doMAC(CCNR, div_key, MAC);
	UsbCommand resp;
	UsbCommand d = {CMD_ICLASS_AUTHENTICATION, {0}};
	memcpy(d.d.asBytes, MAC, 4);
	clearCommandBuffer();
	SendCommand(&d);
	if (!WaitForResponseTimeout(CMD_ACK,&resp,4500)) {
		PrintAndLog("Auth Command execute timeout");
		return false;
	}
	uint8_t isOK = resp.arg[0] & 0xff;
	if (!isOK) {
		PrintAndLog("Authentication error");
		return false;
	}
	return true;
}

int usage_hf_iclass_dump(void) {
	PrintAndLog("Usage:  hf iclass dump f <fileName> k <Key> c <CreditKey> e|r\n");
	PrintAndLog("Options:");
	PrintAndLog("  f <filename> : specify a filename to save dump to");
	PrintAndLog("  k <Key>      : *Access Key as 16 hex symbols or 1 hex to select key from memory");
	PrintAndLog("  c <CreditKey>: Credit Key as 16 hex symbols or 1 hex to select key from memory");
	PrintAndLog("  e            : If 'e' is specified, the key is interpreted as the 16 byte");
	PrintAndLog("                 Custom Key (KCus), which can be obtained via reader-attack");
	PrintAndLog("                 See 'hf iclass sim 2'. This key should be on iclass-format");
	PrintAndLog("  r            : If 'r' is specified, the key is interpreted as raw block 3/4");
	PrintAndLog("  NOTE: * = required");
	PrintAndLog("Samples:");
	PrintAndLog("  hf iclass dump k 001122334455667B");
	PrintAndLog("  hf iclass dump k AAAAAAAAAAAAAAAA c 001122334455667B");
	PrintAndLog("  hf iclass dump k AAAAAAAAAAAAAAAA e");
	return 0;
}

int CmdHFiClassReader_Dump(const char *Cmd) {

	uint8_t MAC[4] = {0x00,0x00,0x00,0x00};
	uint8_t div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t c_div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t blockno = 0;
	uint8_t numblks = 0;
	uint8_t maxBlk = 31;
	uint8_t app_areas = 1;
	uint8_t kb = 2;
	uint8_t KEY[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t CreditKEY[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t keyNbr = 0;
	uint8_t dataLen = 0;
	uint8_t fileNameLen = 0;
	char filename[FILE_PATH_SIZE]={0};
	char tempStr[50] = {0};
	bool have_debit_key = false;
	bool have_credit_key = false;
	bool use_credit_key = false;
	bool elite = false;
	bool rawkey = false;
	bool errors = false;
	uint8_t cmdp = 0;

	while(param_getchar(Cmd, cmdp) != 0x00)
	{
		switch(param_getchar(Cmd, cmdp))
		{
		case 'h':
		case 'H':
			return usage_hf_iclass_dump();
		case 'c':
		case 'C':
			have_credit_key = true;
			dataLen = param_getstr(Cmd, cmdp+1, tempStr);
			if (dataLen == 16) {
				errors = param_gethex(tempStr, 0, CreditKEY, dataLen);
			} else if (dataLen == 1) {
				keyNbr = param_get8(Cmd, cmdp+1);
				if (keyNbr < ICLASS_KEYS_MAX) {
					memcpy(CreditKEY, iClass_Key_Table[keyNbr], 8);
				} else {
					PrintAndLog("\nERROR: Credit KeyNbr is invalid\n");
					errors = true;
				}
			} else {
				PrintAndLog("\nERROR: Credit Key is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'e':
		case 'E':
			elite = true;
			cmdp++;
			break;
		case 'f':
		case 'F':
			fileNameLen = param_getstr(Cmd, cmdp+1, filename); 
			if (fileNameLen < 1) {
				PrintAndLog("No filename found after f");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'k':
		case 'K':
			have_debit_key = true;
			dataLen = param_getstr(Cmd, cmdp+1, tempStr);
			if (dataLen == 16) { 
				errors = param_gethex(tempStr, 0, KEY, dataLen);
			} else if (dataLen == 1) {
				keyNbr = param_get8(Cmd, cmdp+1);
				if (keyNbr < ICLASS_KEYS_MAX) {
					memcpy(KEY, iClass_Key_Table[keyNbr], 8);
				} else {
					PrintAndLog("\nERROR: Credit KeyNbr is invalid\n");
					errors = true;
				}
			} else {
				PrintAndLog("\nERROR: Credit Key is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'r':
		case 'R':
			rawkey = true;
			cmdp++;
			break;
		default:
			PrintAndLog("Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
		if(errors) return usage_hf_iclass_dump();
	}

	if (cmdp < 2) return usage_hf_iclass_dump();
	// if no debit key given try credit key on AA1 (not for iclass but for some picopass this will work)
	if (!have_debit_key && have_credit_key) use_credit_key = true;

	//get config and first 3 blocks
	UsbCommand c = {CMD_READER_ICLASS, {FLAG_ICLASS_READER_CSN |
					FLAG_ICLASS_READER_CONF | FLAG_ICLASS_READER_ONLY_ONCE | FLAG_ICLASS_READER_ONE_TRY}};
	UsbCommand resp;
	uint8_t tag_data[255*8];

	clearCommandBuffer();
	SendCommand(&c);
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
		PrintAndLog("Command execute timeout");
		ul_switch_off_field();
		return 0;
	}
	uint8_t readStatus = resp.arg[0] & 0xff;
	uint8_t * data  = resp.d.asBytes;

	if(readStatus == 0){
		PrintAndLog("No tag found...");
		ul_switch_off_field();
		return 0;
	}
	
	if( readStatus & (FLAG_ICLASS_READER_CSN|FLAG_ICLASS_READER_CONF|FLAG_ICLASS_READER_CC)){
		memcpy(tag_data, data, 8*3);
		blockno+=2; // 2 to force re-read of block 2 later. (seems to respond differently..)
		numblks = data[8];
		getMemConfig(data[13], data[12], &maxBlk, &app_areas, &kb);
		// large memory - not able to dump pages currently
		if (numblks > maxBlk) numblks = maxBlk;
	}
	
	ul_switch_off_field();
	// authenticate debit key and get div_key - later store in dump block 3
	if (!select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, false)){
		//try twice - for some reason it sometimes fails the first time...
		if (!select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, false)){
			ul_switch_off_field();
			return 0;
		}
	}
	
	// begin dump
	UsbCommand w = {CMD_ICLASS_DUMP, {blockno, numblks-blockno+1}};
	clearCommandBuffer();
	SendCommand(&w);
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
		PrintAndLog("Command execute time-out 1");
		ul_switch_off_field();
		return 1;
	}
	uint32_t blocksRead = resp.arg[1];
	uint8_t isOK = resp.arg[0] & 0xff;
	if (!isOK && !blocksRead) {
		PrintAndLog("Read Block Failed");
		ul_switch_off_field();
		return 0;
	}
	uint32_t startindex = resp.arg[2];
	if (blocksRead*8 > sizeof(tag_data)-(blockno*8)) {
		PrintAndLog("Data exceeded Buffer size!");
		blocksRead = (sizeof(tag_data)/8) - blockno;
	}
	// response ok - now get bigbuf content of the dump
	GetFromBigBuf(tag_data+(blockno*8), blocksRead*8, startindex);
	WaitForResponse(CMD_ACK,NULL);
	size_t gotBytes = blocksRead*8 + blockno*8;

	// try AA2
	if (have_credit_key) {
		//turn off hf field before authenticating with different key
		ul_switch_off_field();
		memset(MAC,0,4);
		// AA2 authenticate credit key and git c_div_key - later store in dump block 4
		if (!select_and_auth(CreditKEY, MAC, c_div_key, true, false, false, false)){
			//try twice - for some reason it sometimes fails the first time...
			if (!select_and_auth(CreditKEY, MAC, c_div_key, true, false, false, false)){
				ul_switch_off_field();
				return 0;
			}
		}
		// do we still need to read more block?  (aa2 enabled?)
		if (maxBlk > blockno+numblks+1) {
			// setup dump and start
			w.arg[0] = blockno + blocksRead;
			w.arg[1] = maxBlk - (blockno + blocksRead);
			clearCommandBuffer();
			SendCommand(&w);
			if (!WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
				PrintAndLog("Command execute timeout 2");
				ul_switch_off_field();
				return 0;
			}
			uint8_t isOK = resp.arg[0] & 0xff;
			blocksRead = resp.arg[1];
			if (!isOK && !blocksRead) {
				PrintAndLog("Read Block Failed 2");
				ul_switch_off_field();
				return 0;
			}		

			startindex = resp.arg[2];
			if (blocksRead*8 > sizeof(tag_data)-gotBytes) {
				PrintAndLog("Data exceeded Buffer size!");
				blocksRead = (sizeof(tag_data) - gotBytes)/8;
			}
			// get dumped data from bigbuf
			GetFromBigBuf(tag_data+gotBytes, blocksRead*8, startindex);
			WaitForResponse(CMD_ACK,NULL);

			gotBytes += blocksRead*8;			
		} else { //field is still on - turn it off...
			ul_switch_off_field();
		}
	}

	// add diversified keys to dump
	if (have_debit_key) memcpy(tag_data+(3*8),div_key,8);
	if (have_credit_key) memcpy(tag_data+(4*8),c_div_key,8);
	// print the dump
	printf("CSN   |00| %s |\n", sprint_hex(tag_data, 8));
	printf("CSN   |00| %s |\n", sprint_hex(tag_data, 8));
	printIclassDumpContents(tag_data, 1, (gotBytes/8)-1, gotBytes-8);

	if (filename[0] == 0){
		snprintf(filename, FILE_PATH_SIZE,"iclass_tagdump-%02x%02x%02x%02x%02x%02x%02x%02x",
		    tag_data[0],tag_data[1],tag_data[2],tag_data[3],
		    tag_data[4],tag_data[5],tag_data[6],tag_data[7]);
	}

	// save the dump to .bin file
	PrintAndLog("Saving dump file - %d blocks read", gotBytes/8);
	saveFile(filename, "bin", tag_data, gotBytes);
	return 1;
}

static int WriteBlock(uint8_t blockno, uint8_t *bldata, uint8_t *KEY, bool use_credit_key, bool elite, bool rawkey, bool verbose) {
	uint8_t MAC[4]={0x00,0x00,0x00,0x00};
	uint8_t div_key[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	if (!select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, verbose))
		return 0;

	UsbCommand resp;

	Calc_wb_mac(blockno,bldata,div_key,MAC);
	UsbCommand w = {CMD_ICLASS_WRITEBLOCK, {blockno}};
	memcpy(w.d.asBytes, bldata, 8);
	memcpy(w.d.asBytes + 8, MAC, 4);
	
	clearCommandBuffer();
	SendCommand(&w);
	if (!WaitForResponseTimeout(CMD_ACK,&resp,4500)) {
		PrintAndLog("Write Command execute timeout");
		return 0;
	}
	uint8_t isOK = resp.arg[0] & 0xff;
	if (!isOK) {
		PrintAndLog("Write Block Failed");
		return 0;
	}
	PrintAndLog("Write Block Successful");
	return 1;
}

int usage_hf_iclass_writeblock(void) {
	PrintAndLog("Options:");
	PrintAndLog("  b <Block> : The block number as 2 hex symbols");
	PrintAndLog("  d <data>  : Set the Data to write as 16 hex symbols");
	PrintAndLog("  k <Key>   : Access Key as 16 hex symbols or 1 hex to select key from memory");
	PrintAndLog("  c         : If 'c' is specified, the key set is assumed to be the credit key\n");
	PrintAndLog("  e         : If 'e' is specified, elite computations applied to key");
	PrintAndLog("  r         : If 'r' is specified, no computations applied to key");
	PrintAndLog("Samples:");
	PrintAndLog("  hf iclass writeblk b 0A d AAAAAAAAAAAAAAAA k 001122334455667B");
	PrintAndLog("  hf iclass writeblk b 1B d AAAAAAAAAAAAAAAA k 001122334455667B c");
	PrintAndLog("  hf iclass writeblk b 0A d AAAAAAAAAAAAAAAA n 0");
	return 0;
}

int CmdHFiClass_WriteBlock(const char *Cmd) {
	uint8_t blockno=0;
	uint8_t bldata[8]={0,0,0,0,0,0,0,0};
	uint8_t KEY[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t keyNbr = 0;
	uint8_t dataLen = 0;
	char tempStr[50] = {0};
	bool use_credit_key = false;
	bool elite = false;
	bool rawkey= false;
	bool errors = false;
	uint8_t cmdp = 0;
	while(param_getchar(Cmd, cmdp) != 0x00)
	{
		switch(param_getchar(Cmd, cmdp))
		{
		case 'h':
		case 'H':
			return usage_hf_iclass_writeblock();
		case 'b':
		case 'B':
			if (param_gethex(Cmd, cmdp+1, &blockno, 2)) {
				PrintAndLog("Block No must include 2 HEX symbols\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'c':
		case 'C':
			use_credit_key = true;
			cmdp++;
			break;
		case 'd':
		case 'D':
			if (param_gethex(Cmd, cmdp+1, bldata, 16))
			{
				PrintAndLog("KEY must include 16 HEX symbols\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'e':
		case 'E':
			elite = true;
			cmdp++;
			break;
		case 'k':
		case 'K':
			dataLen = param_getstr(Cmd, cmdp+1, tempStr);
			if (dataLen == 16) { 
				errors = param_gethex(tempStr, 0, KEY, dataLen);
			} else if (dataLen == 1) {
				keyNbr = param_get8(Cmd, cmdp+1);
				if (keyNbr < ICLASS_KEYS_MAX) {
					memcpy(KEY, iClass_Key_Table[keyNbr], 8);
				} else {
					PrintAndLog("\nERROR: Credit KeyNbr is invalid\n");
					errors = true;
				}
			} else {
				PrintAndLog("\nERROR: Credit Key is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'r':
		case 'R':
			rawkey = true;
			cmdp++;
			break;
		default:
			PrintAndLog("Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
		if(errors) return usage_hf_iclass_writeblock();
	}

	if (cmdp < 6) return usage_hf_iclass_writeblock();
	int ans = WriteBlock(blockno, bldata, KEY, use_credit_key, elite, rawkey, true);
	ul_switch_off_field();
	return ans;
}

int usage_hf_iclass_clone(void) {
	PrintAndLog("Usage:  hf iclass clone f <tagfile.bin> b <first block> l <last block> k <KEY> c e|r");
	PrintAndLog("Options:");
	PrintAndLog("  f <filename>: specify a filename to clone from");
	PrintAndLog("  b <Block>   : The first block to clone as 2 hex symbols");
	PrintAndLog("  l <Last Blk>: Set the Data to write as 16 hex symbols");
	PrintAndLog("  k <Key>     : Access Key as 16 hex symbols or 1 hex to select key from memory");
	PrintAndLog("  c           : If 'c' is specified, the key set is assumed to be the credit key\n");
	PrintAndLog("  e           : If 'e' is specified, elite computations applied to key");
	PrintAndLog("  r           : If 'r' is specified, no computations applied to key");
	PrintAndLog("Samples:");
	PrintAndLog("  hf iclass clone f iclass_tagdump-121345.bin b 06 l 1A k 1122334455667788 e");
	PrintAndLog("  hf iclass clone f iclass_tagdump-121345.bin b 05 l 19 k 0");
	PrintAndLog("  hf iclass clone f iclass_tagdump-121345.bin b 06 l 19 k 0 e");
	return -1;
}

int CmdHFiClassCloneTag(const char *Cmd) {
	char filename[FILE_PATH_SIZE] = { 0x00 };
	char tempStr[50]={0};
	uint8_t KEY[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t keyNbr = 0;
	uint8_t fileNameLen = 0;
	uint8_t startblock = 0;
	uint8_t endblock = 0;
	uint8_t dataLen = 0;
	bool use_credit_key = false;
	bool elite = false;
	bool rawkey = false;
	bool errors = false;
	uint8_t cmdp = 0;
	while(param_getchar(Cmd, cmdp) != 0x00)
	{
		switch(param_getchar(Cmd, cmdp))
		{
		case 'h':
		case 'H':
			return usage_hf_iclass_clone();
		case 'b':
		case 'B':
			if (param_gethex(Cmd, cmdp+1, &startblock, 2)) {
				PrintAndLog("Start Block No must include 2 HEX symbols\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'c':
		case 'C':
			use_credit_key = true;
			cmdp++;
			break;
		case 'e':
		case 'E':
			elite = true;
			cmdp++;
			break;
		case 'f':
		case 'F':
			fileNameLen = param_getstr(Cmd, cmdp+1, filename); 
			if (fileNameLen < 1) {
				PrintAndLog("No filename found after f");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'k':
		case 'K':
			dataLen = param_getstr(Cmd, cmdp+1, tempStr);
			if (dataLen == 16) { 
				errors = param_gethex(tempStr, 0, KEY, dataLen);
			} else if (dataLen == 1) {
				keyNbr = param_get8(Cmd, cmdp+1);
				if (keyNbr < ICLASS_KEYS_MAX) {
					memcpy(KEY, iClass_Key_Table[keyNbr], 8);
				} else {
					PrintAndLog("\nERROR: Credit KeyNbr is invalid\n");
					errors = true;
				}
			} else {
				PrintAndLog("\nERROR: Credit Key is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'l':
		case 'L':
			if (param_gethex(Cmd, cmdp+1, &endblock, 2)) {
				PrintAndLog("Start Block No must include 2 HEX symbols\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'r':
		case 'R':
			rawkey = true;
			cmdp++;
			break;
		default:
			PrintAndLog("Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
		if(errors) return usage_hf_iclass_clone();
	}

	if (cmdp < 8) return usage_hf_iclass_clone();

	FILE *f;

	iclass_block_t tag_data[USB_CMD_DATA_SIZE/12];

	if ((endblock-startblock+1)*12 > USB_CMD_DATA_SIZE) {
		PrintAndLog("Trying to write too many blocks at once.  Max: %d", USB_CMD_DATA_SIZE/8);
	}
	// file handling and reading
	f = fopen(filename,"rb");
	if(!f) {
		PrintAndLog("Failed to read from file '%s'", filename);
		return 1;
	}

	if (startblock<5) {
		PrintAndLog("You cannot write key blocks this way. yet... make your start block > 4");
		fclose(f);	
		return 0;
	}
	// now read data from the file from block 6 --- 19
	// ok we will use this struct [data 8 bytes][MAC 4 bytes] for each block calculate all mac number for each data
	// then copy to usbcommand->asbytes; the max is 32 - 6 = 24 block 12 bytes each block 288 bytes then we can only accept to clone 21 blocks at the time,
	// else we have to create a share memory
	int i;
	fseek(f,startblock*8,SEEK_SET);
	size_t bytes_read = fread(tag_data,sizeof(iclass_block_t),endblock - startblock + 1,f);
	if ( bytes_read == 0){
		PrintAndLog("File reading error.");
		fclose(f);
		return 2;
	}

	uint8_t MAC[4]={0x00,0x00,0x00,0x00};
	uint8_t div_key[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	if (!select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, true))
		return 0;

	UsbCommand w = {CMD_ICLASS_CLONE,{startblock,endblock}};
	uint8_t *ptr;
	// calculate all mac for every the block we will write
	for (i = startblock; i <= endblock; i++){
	    Calc_wb_mac(i,tag_data[i - startblock].d,div_key,MAC);
	    // usb command d start pointer = d + (i - 6) * 12
	    // memcpy(pointer,tag_data[i - 6],8) 8 bytes
	    // memcpy(pointer + 8,mac,sizoof(mac) 4 bytes;
	    // next one
	    ptr = w.d.asBytes + (i - startblock) * 12;
	    memcpy(ptr, &(tag_data[i - startblock].d[0]), 8);
	    memcpy(ptr + 8,MAC, 4);
	}
	uint8_t p[12];
	for (i = 0; i <= endblock - startblock;i++){
	    memcpy(p,w.d.asBytes + (i * 12),12);
	    printf("Block |%02x|",i + startblock);
	    printf(" %02x%02x%02x%02x%02x%02x%02x%02x |",p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
	    printf(" MAC |%02x%02x%02x%02x|\n",p[8],p[9],p[10],p[11]);
	}
	UsbCommand resp;
	clearCommandBuffer();
	SendCommand(&w);
	if (!WaitForResponseTimeout(CMD_ACK,&resp,4500)) {
		PrintAndLog("Command execute timeout");
		return 0;
	}
	return 1;
}

static int ReadBlock(uint8_t *KEY, uint8_t blockno, uint8_t keyType, bool elite, bool rawkey, bool verbose) {
	uint8_t MAC[4]={0x00,0x00,0x00,0x00};
	uint8_t div_key[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	if (!select_and_auth(KEY, MAC, div_key, (keyType==0x18), elite, rawkey, verbose))
		return 0;

	UsbCommand resp;
	UsbCommand w = {CMD_ICLASS_READBLOCK, {blockno}};
	clearCommandBuffer();
	SendCommand(&w);
	if (!WaitForResponseTimeout(CMD_ACK,&resp,4500)) {
		PrintAndLog("Command execute timeout");
		return 0;
	}
	
	uint8_t isOK = resp.arg[0] & 0xff;
	if (!isOK) {
		PrintAndLog("Read Block Failed");
		return 0;
	}
	//data read is stored in: resp.d.asBytes[0-15]
	if (verbose) PrintAndLog("Block %02X: %s\n",blockno, sprint_hex(resp.d.asBytes,8));
	return 1;
}

int usage_hf_iclass_readblock(void) {
	PrintAndLog("Usage:  hf iclass readblk b <Block> k <Key> c e|r\n");
	PrintAndLog("Options:");
	PrintAndLog("  b <Block> : The block number as 2 hex symbols");
	PrintAndLog("  k <Key>   : Access Key as 16 hex symbols or 1 hex to select key from memory");
	PrintAndLog("  c         : If 'c' is specified, the key set is assumed to be the credit key\n");
	PrintAndLog("  e         : If 'e' is specified, elite computations applied to key");
	PrintAndLog("  r         : If 'r' is specified, no computations applied to key");
	PrintAndLog("Samples:");
	PrintAndLog("  hf iclass readblk b 06 k 0011223344556677");
	PrintAndLog("  hf iclass readblk b 1B k 0011223344556677 c");
	PrintAndLog("  hf iclass readblk b 0A k 0");
	return 0;
}

int CmdHFiClass_ReadBlock(const char *Cmd) {
	uint8_t blockno=0;
	uint8_t keyType = 0x88; //debit key
	uint8_t KEY[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t keyNbr = 0;
	uint8_t dataLen = 0;
	char tempStr[50] = {0};
	bool elite = false;
	bool rawkey = false;
	bool errors = false;
	uint8_t cmdp = 0;
	while(param_getchar(Cmd, cmdp) != 0x00)
	{
		switch(param_getchar(Cmd, cmdp))
		{
		case 'h':
		case 'H':
			return usage_hf_iclass_readblock();
		case 'b':
		case 'B':
			if (param_gethex(Cmd, cmdp+1, &blockno, 2)) {
				PrintAndLog("Block No must include 2 HEX symbols\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'c':
		case 'C':
			keyType = 0x18;
			cmdp++;
			break;
		case 'e':
		case 'E':
			elite = true;
			cmdp++;
			break;
		case 'k':
		case 'K':
			dataLen = param_getstr(Cmd, cmdp+1, tempStr);
			if (dataLen == 16) { 
				errors = param_gethex(tempStr, 0, KEY, dataLen);
			} else if (dataLen == 1) {
				keyNbr = param_get8(Cmd, cmdp+1);
				if (keyNbr < ICLASS_KEYS_MAX) {
					memcpy(KEY, iClass_Key_Table[keyNbr], 8);
				} else {
					PrintAndLog("\nERROR: Credit KeyNbr is invalid\n");
					errors = true;
				}
			} else {
				PrintAndLog("\nERROR: Credit Key is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'r':
		case 'R':
			rawkey = true;
			cmdp++;
			break;
		default:
			PrintAndLog("Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
		if(errors) return usage_hf_iclass_readblock();
	}

	if (cmdp < 4) return usage_hf_iclass_readblock();

	return ReadBlock(KEY, blockno, keyType, elite, rawkey, true);
}

int CmdHFiClass_loclass(const char *Cmd) {
	char opt = param_getchar(Cmd, 0);

	if (strlen(Cmd)<1 || opt == 'h') {
		PrintAndLog("Usage: hf iclass loclass [options]");
		PrintAndLog("Options:");
		PrintAndLog("h             Show this help");
		PrintAndLog("t             Perform self-test");
		PrintAndLog("f <filename>  Bruteforce iclass dumpfile");
		PrintAndLog("                   An iclass dumpfile is assumed to consist of an arbitrary number of");
		PrintAndLog("                   malicious CSNs, and their protocol responses");
		PrintAndLog("                   The binary format of the file is expected to be as follows: ");
		PrintAndLog("                   <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
		PrintAndLog("                   <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
		PrintAndLog("                   <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
		PrintAndLog("                  ... totalling N*24 bytes");
		return 0;
	}
	char fileName[255] = {0};
	if(opt == 'f') 	{
		if(param_getstr(Cmd, 1, fileName) > 0) {
			return bruteforceFileNoKeys(fileName);
		} else {
			PrintAndLog("You must specify a filename");
			// no return?
		}
	}
	else if(opt == 't') {
		int errors = testCipherUtils();
		errors += testMAC();
		errors += doKeyTests(0);
		errors += testElite();
		if(errors) prnlog("OBS! There were errors!!!");
		return errors;
	}
	return 0;
}

void printIclassDumpContents(uint8_t *iclass_dump, uint8_t startblock, uint8_t endblock, size_t filesize) {
	uint8_t blockdata[8];
	uint8_t mem_config;
	memcpy(&mem_config, iclass_dump + 13,1);
	uint8_t maxmemcount;
	uint8_t filemaxblock = filesize / 8;

	if (mem_config & 0x80)
		maxmemcount = 255;
	else
		maxmemcount = 31;
	//PrintAndLog	("endblock: %d, filesize: %d, maxmemcount: %d, filemaxblock: %d", endblock,filesize, maxmemcount, filemaxblock);

	if (startblock == 0)
		startblock = 6;
	
	if ((endblock > maxmemcount) || (endblock == 0))
		endblock = maxmemcount;
	
	if (endblock > filemaxblock)
		endblock = filemaxblock;
	
	int i = startblock;
	int j;
	while (i <= endblock){
		printf("Block |%02X| ",i);
		memcpy(blockdata, iclass_dump + (i * 8), 8);
		for (j = 0;j < 8;j++)
			printf("%02X ", blockdata[j]);
		printf("|\n");
		i++;
	}
}

int usage_hf_iclass_readtagfile() {
	PrintAndLog("Usage: hf iclass readtagfile <filename> [startblock] [endblock]");
	return 1;
}

int CmdHFiClassReadTagFile(const char *Cmd) {
	int startblock = 0;
	int endblock = 0;
	char tempnum[5];
	FILE *f;
	char filename[FILE_PATH_SIZE];
	if (param_getstr(Cmd, 0, filename) < 1)
		return usage_hf_iclass_readtagfile();
	
	if (param_getstr(Cmd,1,(char *)&tempnum) < 1)
		startblock = 0;
	else
		sscanf(tempnum,"%d",&startblock);

	if (param_getstr(Cmd,2,(char *)&tempnum) < 1)
		endblock = 0;
	else
		sscanf(tempnum,"%d",&endblock);
	
	// file handling and reading
	f = fopen(filename,"rb");
	if(!f) {
		PrintAndLog("Failed to read from file '%s'", filename);
		return 1;
	}
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	if ( fsize < 0 ) {
		PrintAndLog("Error, when getting filesize");
		fclose(f);
		return 1;
	}

	uint8_t *dump = malloc(fsize);
	size_t bytes_read = fread(dump, 1, fsize, f);
	fclose(f);
	
	uint8_t *csn = dump;
	printf("CSN   [00] | %s |\n", sprint_hex(csn, 8) );
	printIclassDumpContents(dump,startblock,endblock,bytes_read);
	free(dump);
	return 0;
}

/*
uint64_t xorcheck(uint64_t sdiv,uint64_t hdiv) {
	uint64_t new_div = 0x00;
	new_div ^= sdiv;
	new_div ^= hdiv;
	return new_div;
}

uint64_t hexarray_to_uint64(uint8_t *key) {
	char temp[17];
	uint64_t uint_key;
	for (int i = 0;i < 8;i++)
		sprintf(&temp[(i *2)],"%02X",key[i]);
	temp[16] = '\0';
	if (sscanf(temp,"%016"llX,&uint_key) < 1)
		return 0;
	return uint_key;
}
*/
void HFiClassCalcDivKey(uint8_t	*CSN, uint8_t	*KEY, uint8_t *div_key, bool elite){
	uint8_t keytable[128] = {0};
	uint8_t key_index[8] = {0};
	if (elite) {
		uint8_t key_sel[8] = { 0 };
		uint8_t key_sel_p[8] = { 0 };
		hash2(KEY, keytable);
		hash1(CSN, key_index);
		for(uint8_t i = 0; i < 8 ; i++)
			key_sel[i] = keytable[key_index[i]] & 0xFF;

		//Permute from iclass format to standard format
		permutekey_rev(key_sel, key_sel_p);
		diversifyKey(CSN, key_sel_p, div_key);	
	} else {
		diversifyKey(CSN, KEY, div_key);
	}		
}

//when told CSN, oldkey, newkey, if new key is elite (elite), and if old key was elite (oldElite)
//calculate and return xor_div_key (ready for a key write command)
//print all div_keys if verbose
static void HFiClassCalcNewKey(uint8_t *CSN, uint8_t *OLDKEY, uint8_t *NEWKEY, uint8_t *xor_div_key, bool elite, bool oldElite, bool verbose){
	uint8_t old_div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t new_div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	//get old div key
	HFiClassCalcDivKey(CSN, OLDKEY, old_div_key, oldElite);
	//get new div key
	HFiClassCalcDivKey(CSN, NEWKEY, new_div_key, elite);
	
	for (uint8_t i = 0; i < sizeof(old_div_key); i++){
		xor_div_key[i] = old_div_key[i] ^ new_div_key[i];
	}
	if (verbose) {
		printf("Old Div Key : %s\n",sprint_hex(old_div_key,8));
		printf("New Div Key : %s\n",sprint_hex(new_div_key,8));
		printf("Xor Div Key : %s\n",sprint_hex(xor_div_key,8));		
	}
}

int usage_hf_iclass_calc_newkey(void) {
	PrintAndLog("HELP :  Manage iClass Keys in client memory:\n");
	PrintAndLog("Usage:  hf iclass calc_newkey o <Old key> n <New key> s [csn] e");
	PrintAndLog("  Options:");
	PrintAndLog("  o <oldkey> : *specify a key as 16 hex symbols or a key number as 1 symbol");
	PrintAndLog("  n <newkey> : *specify a key as 16 hex symbols or a key number as 1 symbol");
	PrintAndLog("  s <csn>    : specify a card Serial number to diversify the key (if omitted will attempt to read a csn)");
	PrintAndLog("  e          : specify new key as elite calc");
	PrintAndLog("  ee         : specify old and new key as elite calc");
	PrintAndLog("Samples:");
	PrintAndLog(" e key to e key given csn : hf iclass calcnewkey o 1122334455667788 n 2233445566778899 s deadbeafdeadbeaf ee");
	PrintAndLog(" std key to e key read csn: hf iclass calcnewkey o 1122334455667788 n 2233445566778899 e");
	PrintAndLog(" std to std read csn      : hf iclass calcnewkey o 1122334455667788 n 2233445566778899");
	PrintAndLog("NOTE: * = required\n");

	return 1;
}

int CmdHFiClassCalcNewKey(const char *Cmd) {
	uint8_t OLDKEY[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t NEWKEY[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t xor_div_key[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t CSN[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t CCNR[12] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t keyNbr = 0;
	uint8_t dataLen = 0;
	char tempStr[50] = {0};
	bool givenCSN = false;
	bool oldElite = false;
	bool elite = false;
	bool errors = false;
	uint8_t cmdp = 0;
	while(param_getchar(Cmd, cmdp) != 0x00)
	{
		switch(param_getchar(Cmd, cmdp))
		{
		case 'h':
		case 'H':
			return usage_hf_iclass_calc_newkey();
		case 'e':
		case 'E':
			dataLen = param_getstr(Cmd, cmdp, tempStr);
			if (dataLen==2)
				oldElite = true;
			elite = true;
			cmdp++;
			break;
		case 'n':
		case 'N':
			dataLen = param_getstr(Cmd, cmdp+1, tempStr);
			if (dataLen == 16) { 
				errors = param_gethex(tempStr, 0, NEWKEY, dataLen);
			} else if (dataLen == 1) {
				keyNbr = param_get8(Cmd, cmdp+1);
				if (keyNbr < ICLASS_KEYS_MAX) {
					memcpy(NEWKEY, iClass_Key_Table[keyNbr], 8);
				} else {
					PrintAndLog("\nERROR: NewKey Nbr is invalid\n");
					errors = true;
				}
			} else {
				PrintAndLog("\nERROR: NewKey is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'o':
		case 'O':
			dataLen = param_getstr(Cmd, cmdp+1, tempStr);
			if (dataLen == 16) { 
				errors = param_gethex(tempStr, 0, OLDKEY, dataLen);
			} else if (dataLen == 1) {
				keyNbr = param_get8(Cmd, cmdp+1);
				if (keyNbr < ICLASS_KEYS_MAX) {
					memcpy(OLDKEY, iClass_Key_Table[keyNbr], 8);
				} else {
					PrintAndLog("\nERROR: Credit KeyNbr is invalid\n");
					errors = true;
				}
			} else {
				PrintAndLog("\nERROR: Credit Key is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 's':
		case 'S':
			givenCSN = true;
			if (param_gethex(Cmd, cmdp+1, CSN, 16))
				return usage_hf_iclass_calc_newkey();
			cmdp += 2;
			break;
		default:
			PrintAndLog("Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
		if(errors) return usage_hf_iclass_calc_newkey();
	}

	if (cmdp < 4) return usage_hf_iclass_calc_newkey();

	if (!givenCSN)
		if (!select_only(CSN, CCNR, false, true))
			return 0;
	
	HFiClassCalcNewKey(CSN, OLDKEY, NEWKEY, xor_div_key, elite, oldElite, true);
	return 0;
}

static int loadKeys(char *filename) {
	FILE *f;
	f = fopen(filename,"rb");
	if(!f) {
		PrintAndLog("Failed to read from file '%s'", filename);
		return 0;
	}
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	if ( fsize < 0 ) {
		PrintAndLog("Error, when getting filesize");
		fclose(f);
		return 1;
	}

	uint8_t *dump = malloc(fsize);

	size_t bytes_read = fread(dump, 1, fsize, f);
	fclose(f);
	if (bytes_read > ICLASS_KEYS_MAX * 8){
		PrintAndLog("File is too long to load - bytes: %u", bytes_read);
		free(dump);
		return 0;
	}
	uint8_t i = 0;
	for (; i < bytes_read/8; i++){
		memcpy(iClass_Key_Table[i],dump+(i*8),8);
	}
	free(dump);
	PrintAndLog("%u keys loaded", i);
	return 1;
}

static int saveKeys(char *filename) {
	FILE *f;
	f = fopen(filename,"wb");
	if (f == NULL) {
		printf("error opening file %s\n",filename);
		return 0;
	}
	for (uint8_t i = 0; i < ICLASS_KEYS_MAX; i++){
		if (fwrite(iClass_Key_Table[i],8,1,f) != 1){
			PrintAndLog("save key failed to write to file: %s", filename);
			break;
		}
	}
	fclose(f);
	return 0;
}

static int printKeys(void) {
	PrintAndLog("");
	for (uint8_t i = 0; i < ICLASS_KEYS_MAX; i++){
		PrintAndLog("%u: %s", i, sprint_hex(iClass_Key_Table[i],8));
	}
	PrintAndLog("");	
	return 0;
}

int usage_hf_iclass_managekeys(void) {
	PrintAndLog("HELP :  Manage iClass Keys in client memory:\n");
	PrintAndLog("Usage:  hf iclass managekeys n [keynbr] k [key] f [filename] s l p\n");
	PrintAndLog("  Options:");
	PrintAndLog("  n <keynbr>  : specify the keyNbr to set in memory");
	PrintAndLog("  k <key>     : set a key in memory");
	PrintAndLog("  f <filename>: specify a filename to use with load or save operations");
	PrintAndLog("  s           : save keys in memory to file specified by filename");
	PrintAndLog("  l           : load keys to memory from file specified by filename");
	PrintAndLog("  p           : print keys loaded into memory\n");
	PrintAndLog("Samples:");
	PrintAndLog(" set key      : hf iclass managekeys n 0 k 1122334455667788");
	PrintAndLog(" save key file: hf iclass managekeys f mykeys.bin s");
	PrintAndLog(" load key file: hf iclass managekeys f mykeys.bin l");
	PrintAndLog(" print keys   : hf iclass managekeys p\n");
	return 0;
}

int CmdHFiClassManageKeys(const char *Cmd) {
	uint8_t keyNbr = 0;
	uint8_t dataLen = 0;
	uint8_t KEY[8] = {0};
	char filename[FILE_PATH_SIZE];
	uint8_t fileNameLen = 0;
	bool errors = false;
	uint8_t operation = 0;
	char tempStr[20];
	uint8_t cmdp = 0;

	while(param_getchar(Cmd, cmdp) != 0x00)
	{
		switch(param_getchar(Cmd, cmdp))
		{
		case 'h':
		case 'H':
			return usage_hf_iclass_managekeys();
		case 'f':
		case 'F':
			fileNameLen = param_getstr(Cmd, cmdp+1, filename); 
			if (fileNameLen < 1) {
				PrintAndLog("No filename found after f");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'n':
		case 'N':
			keyNbr = param_get8(Cmd, cmdp+1);
			if (keyNbr == 0) {
				PrintAndLog("Wrong block number");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'k':
		case 'K':
			operation += 3; //set key 
			dataLen = param_getstr(Cmd, cmdp+1, tempStr);
			if (dataLen == 16) { //ul-c or ev1/ntag key length
				errors = param_gethex(tempStr, 0, KEY, dataLen);
			} else {
				PrintAndLog("\nERROR: Key is incorrect length\n");
				errors = true;
			}
			cmdp += 2;
			break;
		case 'p':
		case 'P':
			operation += 4; //print keys in memory
			cmdp++;
			break;
		case 'l':
		case 'L':
			operation += 5; //load keys from file
			cmdp++;
			break;
		case 's':
		case 'S':
			operation += 6; //save keys to file
			cmdp++;
			break;
		default:
			PrintAndLog("Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
		if(errors) return usage_hf_iclass_managekeys();
	}
	if (operation == 0){
		PrintAndLog("no operation specified (load, save, or print)\n");
		return usage_hf_iclass_managekeys();
	}
	if (operation > 6){
		PrintAndLog("Too many operations specified\n");
		return usage_hf_iclass_managekeys();
	}
	if (operation > 4 && fileNameLen == 0){
		PrintAndLog("You must enter a filename when loading or saving\n");
		return usage_hf_iclass_managekeys();
	}

	switch (operation){
		case 3: memcpy(iClass_Key_Table[keyNbr], KEY, 8); return 1;
		case 4: return printKeys();
		case 5: return loadKeys(filename);
		case 6: return saveKeys(filename);
		break;
	}
	return 0;
}

static command_t CommandTable[] = {
	{"help",	CmdHelp,			1,	"This help"},
	{"calcnewkey",  CmdHFiClassCalcNewKey,      	1,	"[options..] Calc Diversified keys (blocks 3 & 4) to write new keys"},
	{"clone",       CmdHFiClassCloneTag,        	0,	"[options..] Authenticate and Clone from iClass bin file"},
	{"decrypt",     CmdHFiClassDecrypt,         	1,	"[f <fname>] Decrypt tagdump" },
	{"dump",        CmdHFiClassReader_Dump,     	0,	"[options..] Authenticate and Dump iClass tag's AA1"},
	{"eload",       CmdHFiClassELoad,           	0,	"[f <fname>] (experimental) Load data into iClass emulator memory"},
	{"encryptblk",  CmdHFiClassEncryptBlk,      	1,	"<BlockData> Encrypt given block data"},
	{"list",        CmdHFiClassList,            	0,	"            (Deprecated) List iClass history"},
	{"loclass",     CmdHFiClass_loclass,        	1,	"[options..] Use loclass to perform bruteforce of reader attack dump"},
	{"managekeys",  CmdHFiClassManageKeys,      	1,	"[options..] Manage the keys to use with iClass"},
	{"readblk",     CmdHFiClass_ReadBlock,      	0,	"[options..] Authenticate and Read iClass block"},
	{"reader",CmdHFiClassReader,	0,	"Read an iClass tag"},
	{"readtagfile", CmdHFiClassReadTagFile,     	1,	"[options..] Display Content from tagfile"},
	{"replay",      CmdHFiClassReader_Replay,   	0,	"<mac>       Read an iClass tag via Reply Attack"},
	{"sim",         CmdHFiClassSim,             	0,	"[options..] Simulate iClass tag"},
	{"snoop",       CmdHFiClassSnoop,           	0,	"            Eavesdrop iClass communication"},
	{"writeblk",    CmdHFiClass_WriteBlock,     	0,	"[options..] Authenticate and Write iClass block"},
	{NULL, NULL, 0, NULL}
};

int CmdHFiClass(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
