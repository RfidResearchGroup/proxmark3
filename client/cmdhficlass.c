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

static int CmdHelp(const char *Cmd);

int xorbits_8(uint8_t val)
{
	uint8_t res = val ^ (val >> 1); //1st pass
	res = res ^ (res >> 1); 		// 2nd pass
	res = res ^ (res >> 2); 		// 3rd pass
	res = res ^ (res >> 4); 			// 4th pass
	return res & 1;
}

int CmdHFiClassList(const char *Cmd)
{
	PrintAndLog("Deprecated command, use 'hf list iclass' instead");
	return 0;
}

int CmdHFiClassSnoop(const char *Cmd)
{
	UsbCommand c = {CMD_SNOOP_ICLASS};
	SendCommand(&c);
	return 0;
}
int usage_hf_iclass_sim()
{
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
int CmdHFiClassSim(const char *Cmd)
{
	uint8_t simType = 0;
	uint8_t CSN[8] = {0, 0, 0, 0, 0, 0, 0, 0};

	if (strlen(Cmd)<1) {
		return usage_hf_iclass_sim();
	}
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
		for(i = 0 ; i < NUM_CSNS ; i++)
		{
			memcpy(dump+i*24, csns+i*8,8); //CSN
			//8 zero bytes here...
			//Then comes NR_MAC (eight bytes from the response)
			memcpy(dump+i*24+16,resp.d.asBytes+i*8,8);

		}
		/** Now, save to dumpfile **/
		saveFile("iclass_mac_attack", "bin", dump,datalen);
		free(dump);
	}else
	{
		UsbCommand c = {CMD_SIMULATE_TAG_ICLASS, {simType,numberOfCSNs}};
		memcpy(c.d.asBytes, CSN, 8);
		SendCommand(&c);
	}

	return 0;
}

int HFiClassReader(const char *Cmd, bool loop, bool verbose)
{
	bool tagFound = false;
	UsbCommand c = {CMD_READER_ICLASS, {FLAG_ICLASS_READER_CSN|
					FLAG_ICLASS_READER_CONF|FLAG_ICLASS_READER_AA}};
	if (!loop) c.arg[0] |= FLAG_ICLASS_READER_ONLY_ONCE | FLAG_ICLASS_READER_ONE_TRY;
	SendCommand(&c);
	UsbCommand resp;
	while(!ukbhit()){
		if (WaitForResponseTimeout(CMD_ACK,&resp, 4500)) {
			uint8_t readStatus    = resp.arg[0] & 0xff;
			uint8_t *data = resp.d.asBytes;

			if (verbose)
			PrintAndLog("Readstatus:%02x", readStatus);
			if( readStatus == 0){
				//Aborted
				if (verbose) PrintAndLog("Quitting...");
				return 0;
			}
			if( readStatus & FLAG_ICLASS_READER_CSN){
				PrintAndLog("CSN: %s",sprint_hex(data,8));
				tagFound = true;
			}
			if( readStatus & FLAG_ICLASS_READER_CC)  PrintAndLog("CC: %s",sprint_hex(data+16,8));
			if( readStatus & FLAG_ICLASS_READER_CONF){
				printIclassDumpInfo(data);
			}
			if (tagFound && !loop) return 1;
		} else {
			if (verbose) PrintAndLog("Command execute timeout");
		}
		if (!loop) break;
	}
	return 0;

}

int CmdHFiClassReader(const char *Cmd)
{
	return HFiClassReader(Cmd, true, true);
}

int CmdHFiClassReader_Replay(const char *Cmd)
{
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
	SendCommand(&c);

	return 0;
}

int CmdHFiClassReader_Dump(const char *Cmd)
{
	uint8_t readerType = 0;
	uint8_t MAC[4]={0x00,0x00,0x00,0x00};
	uint8_t KEY[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t CSN[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t CCNR[12]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	//uint8_t CC_temp[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t div_key[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t keytable[128] = {0};
	int elite = 0;
	uint8_t *used_key;
	int i;
	if (strlen(Cmd)<1)
	{
		PrintAndLog("Usage:  hf iclass dump <Key> [e]");
		PrintAndLog("        Key    - A 16 byte master key");
		PrintAndLog("        e      - If 'e' is specified, the key is interpreted as the 16 byte");
		PrintAndLog("                 Custom Key (KCus), which can be obtained via reader-attack");
		PrintAndLog("                 See 'hf iclass sim 2'. This key should be on iclass-format");
		PrintAndLog("        sample: hf iclass dump 0011223344556677");


		return 0;
	}

	if (param_gethex(Cmd, 0, KEY, 16))
	{
		PrintAndLog("KEY must include 16 HEX symbols");
		return 1;
	}

	if (param_getchar(Cmd, 1) == 'e')
	{
		PrintAndLog("Elite switch on");
		elite = 1;

		//calc h2
		hash2(KEY, keytable);
		printarr_human_readable("keytable", keytable, 128);

	}

	UsbCommand resp;
	uint8_t key_sel[8] = {0};
	uint8_t key_sel_p[8] = { 0 };

	UsbCommand c = {CMD_READER_ICLASS, {0}};
	c.arg[0] = FLAG_ICLASS_READER_ONLY_ONCE| FLAG_ICLASS_READER_CC;
	SendCommand(&c);



	if (!WaitForResponseTimeout(CMD_ACK,&resp,4500))
	{
		PrintAndLog("Command execute timeout");
		return 0;
	}

	uint8_t isOK    = resp.arg[0] & 0xff;
	uint8_t * data  = resp.d.asBytes;

	memcpy(CSN,data,8);
	memcpy(CCNR,data+16,8);

	PrintAndLog("isOk:%02x", isOK);

	if(isOK > 0)
	{
		PrintAndLog("CSN: %s",sprint_hex(CSN,8));
	}
	if(isOK <= 1){
		PrintAndLog("Failed to obtain CC! Aborting");
		return 0;
	}
	//Status 2 or higher

	if(elite)
	{
		//Get the key index (hash1)
		uint8_t key_index[8] = {0};

		hash1(CSN, key_index);
		printvar("hash1", key_index,8);
		for(i = 0; i < 8 ; i++)
			key_sel[i] = keytable[key_index[i]] & 0xFF;
		PrintAndLog("Pre-fortified 'permuted' HS key that would be needed by an iclass reader to talk to above CSN:");
		printvar("k_sel", key_sel,8);
		//Permute from iclass format to standard format
		permutekey_rev(key_sel,key_sel_p);
		used_key = key_sel_p;
	}else{
		used_key = KEY;
	}

	PrintAndLog("Pre-fortified key that would be needed by the OmniKey reader to talk to above CSN:");
	printvar("Used key",used_key,8);
	diversifyKey(CSN,used_key, div_key);
	PrintAndLog("Hash0, a.k.a diversified key, that is computed using Ksel and stored in the card (Block 3):");
	printvar("Div key", div_key, 8);
	printvar("CC_NR:",CCNR,12);
	doMAC(CCNR,div_key, MAC);
	printvar("MAC", MAC, 4);

	uint8_t iclass_data[32000] = {0};
	uint32_t iclass_datalen = 0;
	uint32_t iclass_blocksFailed = 0;//Set to 1 if dump was incomplete

	UsbCommand d = {CMD_READER_ICLASS_REPLAY, {readerType}};
	memcpy(d.d.asBytes, MAC, 4);
	clearCommandBuffer();
	SendCommand(&d);
	PrintAndLog("Waiting for device to dump data. Press button on device and key on keyboard to abort...");
	while (true) {
		printf(".");
		if (ukbhit()) {
			getchar();
			printf("\naborted via keyboard!\n");
			break;
		}
		if(WaitForResponseTimeout(CMD_ACK,&resp,4500))
		{
			uint32_t dataLength = resp.arg[0];
			iclass_blocksFailed |= resp.arg[1];
			if(dataLength > 0)
			{
				PrintAndLog("Got %d bytes data (total so far %d)" ,dataLength,iclass_datalen);
				memcpy(iclass_data+iclass_datalen, resp.d.asBytes,dataLength);
				iclass_datalen += dataLength;
			}else
			{//Last transfer, datalength 0 means the dump is finished
				PrintAndLog("Dumped %d bytes of data from tag. ", iclass_datalen);
				if(iclass_blocksFailed)
				{
					PrintAndLog("OBS! Some blocks failed to be dumped correctly!");
				}
				if(iclass_datalen > 0)
				{
					char filename[100] = {0};
					//create a preferred filename
					snprintf(filename, 100,"iclass_tagdump-%02x%02x%02x%02x%02x%02x%02x%02x",
							 CSN[0],CSN[1],CSN[2],CSN[3],
							CSN[4],CSN[5],CSN[6],CSN[7]);
					//Place the div_key in block 3
					memcpy(iclass_data+(3*8), div_key, 8);
					saveFile(filename,"bin",iclass_data, iclass_datalen );
				}
				//Aaaand we're finished
				return 0;
			}
		}
	}


	return 0;
}

int hf_iclass_eload_usage()
{
	PrintAndLog("Loads iclass tag-dump into emulator memory on device");
	PrintAndLog("Usage:  hf iclass eload f <filename>");
	PrintAndLog("");
	PrintAndLog("Example: hf iclass eload f iclass_tagdump-aa162d30f8ff12f1.bin");
	return 0;

}

int iclassEmlSetMem(uint8_t *data, int blockNum, int blocksCount) {
	UsbCommand c = {CMD_MIFARE_EML_MEMSET, {blockNum, blocksCount, 0}};
	memcpy(c.d.asBytes, data, blocksCount * 16);
	SendCommand(&c);
	return 0;
}
int CmdHFiClassELoad(const char *Cmd)
{

	char opt = param_getchar(Cmd, 0);
	if (strlen(Cmd)<1 || opt == 'h')
		return hf_iclass_eload_usage();

	//File handling and reading
	FILE *f;
	char filename[FILE_PATH_SIZE];
	if(opt == 'f' && param_getstr(Cmd, 1, filename) > 0)
	{
		f = fopen(filename, "rb");
	}else{
		return hf_iclass_eload_usage();
	}

	if(!f) {
		PrintAndLog("Failed to read from file '%s'", filename);
		return 1;
	}

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	uint8_t *dump = malloc(fsize);


	size_t bytes_read = fread(dump, 1, fsize, f);
	fclose(f);

	printIclassDumpInfo(dump);
	//Validate

	if (bytes_read < fsize)
	{
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
		SendCommand(&c);
		bytes_remaining -= bytes_in_packet;
		bytes_sent += bytes_in_packet;
	}
	free(dump);
	PrintAndLog("Sent %d bytes of data to device emulator memory", bytes_sent);
	return 0;
}

int usage_hf_iclass_decrypt()
{
	PrintAndLog("Usage: hf iclass decrypt f <tagdump> o ");
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

int readKeyfile(const char *filename, size_t len, uint8_t* buffer)
{
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
	if(fsize != len)
	{
		PrintAndLog("Warning, file size is %d, expected %d", fsize, len);
		return 1;
	}
	if(bytes_read != len)
	{
		PrintAndLog("Warning, could only read %d bytes, expected %d" ,bytes_read, len);
		return 1;
	}
	return 0;
}

int CmdHFiClassDecrypt(const char *Cmd)
{
	uint8_t key[16] = { 0 };
	if(readKeyfile("iclass_decryptionkey.bin", 16, key))
	{
		usage_hf_iclass_decrypt();
		return 1;
	}
	PrintAndLog("Decryption file found... ");
	char opt = param_getchar(Cmd, 0);
	if (strlen(Cmd)<1 || opt == 'h')
		return usage_hf_iclass_decrypt();

	//Open the tagdump-file
	FILE *f;
	char filename[FILE_PATH_SIZE];
	if(opt == 'f' && param_getstr(Cmd, 1, filename) > 0)
	{
		f = fopen(filename, "rb");
	}else{
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
		if(blocknum < 7)
		{
			memcpy(decrypted+(blocknum*8), enc_dump, 8);
		}else{
			des3_crypt_ecb(&ctx, enc_dump,decrypted +(blocknum*8) );
		}
		printvar("decrypted block", decrypted +(blocknum*8), 8);
		bytes_read = fread(enc_dump, 1, 8, f);
		blocknum++;
	}
	fclose(f);

	saveFile(outfilename,"bin", decrypted, blocknum*8);

	return 0;
}

int CmdHFiClass_iso14443A_write(const char *Cmd)
{
	uint8_t readerType = 0;
	uint8_t MAC[4]={0x00,0x00,0x00,0x00};
	uint8_t KEY[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t CSN[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t CCNR[12]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t div_key[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	uint8_t blockNo=0;
	uint8_t bldata[8]={0};

	if (strlen(Cmd)<3)
	{
		PrintAndLog("Usage:  hf iclass write <Key> <Block> <Data>");
		PrintAndLog("        sample: hf iclass write 0011223344556677 10 AAAAAAAAAAAAAAAA");
		return 0;
	}

	if (param_gethex(Cmd, 0, KEY, 16))
	{
		PrintAndLog("KEY must include 16 HEX symbols");
		return 1;
	}

	blockNo = param_get8(Cmd, 1);
	if (blockNo>32)
	{
		PrintAndLog("Error: Maximum number of blocks is 32 for iClass 2K Cards!");
		return 1;
	}
	if (param_gethex(Cmd, 2, bldata, 8))
	{
		PrintAndLog("Block data must include 8 HEX symbols");
		return 1;
	}

	UsbCommand c = {CMD_ICLASS_ISO14443A_WRITE, {0}};
	SendCommand(&c);
	UsbCommand resp;

	if (WaitForResponseTimeout(CMD_ACK,&resp,4500)) {
		uint8_t isOK    = resp.arg[0] & 0xff;
		uint8_t * data  = resp.d.asBytes;

		memcpy(CSN,data,8);
		memcpy(CCNR,data+8,8);
		PrintAndLog("DEBUG: %s",sprint_hex(CSN,8));
		PrintAndLog("DEBUG: %s",sprint_hex(CCNR,8));
		PrintAndLog("isOk:%02x", isOK);
	} else {
		PrintAndLog("Command execute timeout");
	}

	diversifyKey(CSN,KEY, div_key);

	PrintAndLog("Div Key: %s",sprint_hex(div_key,8));
	doMAC(CCNR, div_key, MAC);

	UsbCommand c2 = {CMD_ICLASS_ISO14443A_WRITE, {readerType,blockNo}};
	memcpy(c2.d.asBytes, bldata, 8);
	memcpy(c2.d.asBytes+8, MAC, 4);
	SendCommand(&c2);

	if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
		uint8_t isOK    = resp.arg[0] & 0xff;
		uint8_t * data  = resp.d.asBytes;

		if (isOK)
			PrintAndLog("isOk:%02x data:%s", isOK, sprint_hex(data, 4));
		else
			PrintAndLog("isOk:%02x", isOK);
	} else {
		PrintAndLog("Command execute timeout");
	}
	return 0;
}
int CmdHFiClass_loclass(const char *Cmd)
{
	char opt = param_getchar(Cmd, 0);

	if (strlen(Cmd)<1 || opt == 'h') {
		PrintAndLog("Usage: hf iclass loclass [options]");
		PrintAndLog("Options:");
		PrintAndLog("h             Show this help");
		PrintAndLog("t             Perform self-test");
		PrintAndLog("f <filename>  Bruteforce iclass dumpfile");
		PrintAndLog("                   An iclass dumpfile is assumed to consist of an arbitrary number of");
		PrintAndLog("                   malicious CSNs, and their protocol responses");
		PrintAndLog("                   The the binary format of the file is expected to be as follows: ");
		PrintAndLog("                   <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
		PrintAndLog("                   <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
		PrintAndLog("                   <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
		PrintAndLog("                  ... totalling N*24 bytes");
		return 0;
	}
	char fileName[255] = {0};
	if(opt == 'f')
	{
		if(param_getstr(Cmd, 1, fileName) > 0)
		{
			return bruteforceFileNoKeys(fileName);
		}else
		{
			PrintAndLog("You must specify a filename");
		}
	}
	else if(opt == 't')
	{
		int errors = testCipherUtils();
		errors += testMAC();
		errors += doKeyTests(0);
		errors += testElite();
		if(errors)
		{
			prnlog("OBS! There were errors!!!");
		}
		return errors;
	}

	return 0;
}

static command_t CommandTable[] = 
{
	{"help",	CmdHelp,			1,	"This help"},
	{"list",	CmdHFiClassList,	0,	"[Deprecated] List iClass history"},
	{"snoop",	CmdHFiClassSnoop,	0,	"Eavesdrop iClass communication"},
	{"sim",	CmdHFiClassSim,		0,	"Simulate iClass tag"},
	{"reader",CmdHFiClassReader,	0,	"Read an iClass tag"},
	{"replay",CmdHFiClassReader_Replay,	0,	"Read an iClass tag via Reply Attack"},
	{"dump",	CmdHFiClassReader_Dump,	0,		"Authenticate and Dump iClass tag"},
//	{"write",	CmdHFiClass_iso14443A_write,	0,	"Authenticate and Write iClass block"},
	{"loclass",	CmdHFiClass_loclass,	1,	"Use loclass to perform bruteforce of reader attack dump"},
	{"eload",   CmdHFiClassELoad,    0,     "[experimental] Load data into iclass emulator memory"},
	{"decrypt", CmdHFiClassDecrypt,  1,     "Decrypt tagdump" },
	{NULL, NULL, 0, NULL}
};

int CmdHFiClass(const char *Cmd)
{
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd)
{
	CmdsHelp(CommandTable);
	return 0;
}
