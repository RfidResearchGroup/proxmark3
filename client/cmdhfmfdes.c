//-----------------------------------------------------------------------------
// Copyright (C) 2014 Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE Desfire commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/des.h>
#include "cmdmain.h"
#include "proxmark3.h"
#include "../include/common.h"
#include "../include/mifare.h"
#include "../common/iso14443crc.h"
#include "data.h"
#include "ui.h"
#include "cmdparser.h"
#include "util.h"
#include "cmdhfmfdes.h"


uint8_t key_zero_data[16] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
uint8_t key_defa_data[16] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
uint8_t key_ones_data[16] = { 0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01 };


static int CmdHelp(const char *Cmd);
static void xor(unsigned char * dst, unsigned char * src, size_t len);
static int32_t le24toh (uint8_t data[3]);


int CmdHF14ADesWb(const char *Cmd)
{
/* 	uint8_t blockNo = 0;
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

	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
		uint8_t isOK  = resp.arg[0] & 0xff;
		PrintAndLog("isOk:%02x", isOK);
	} else {
		PrintAndLog("Command execute timeout");
	}
 */
	return 0;
}

int CmdHF14ADesRb(const char *Cmd)
{
	// uint8_t blockNo = 0;
	// uint8_t keyType = 0;
	// uint8_t key[6] = {0, 0, 0, 0, 0, 0};
	
	// char cmdp	= 0x00;


	// if (strlen(Cmd)<3) {
		// PrintAndLog("Usage:  hf mf rdbl    <block number> <key A/B> <key (12 hex symbols)>");
		// PrintAndLog("        sample: hf mf rdbl 0 A FFFFFFFFFFFF ");
		// return 0;
	// }	
	
	// blockNo = param_get8(Cmd, 0);
	// cmdp = param_getchar(Cmd, 1);
	// if (cmdp == 0x00) {
		// PrintAndLog("Key type must be A or B");
		// return 1;
	// }
	// if (cmdp != 'A' && cmdp != 'a') keyType = 1;
	// if (param_gethex(Cmd, 2, key, 12)) {
		// PrintAndLog("Key must include 12 HEX symbols");
		// return 1;
	// }
	// PrintAndLog("--block no:%02x key type:%02x key:%s ", blockNo, keyType, sprint_hex(key, 6));
	
  // UsbCommand c = {CMD_MIFARE_READBL, {blockNo, keyType, 0}};
	// memcpy(c.d.asBytes, key, 6);
  // SendCommand(&c);

	// UsbCommand resp;
	// if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
		// uint8_t                isOK  = resp.arg[0] & 0xff;
		// uint8_t              * data  = resp.d.asBytes;

		// if (isOK)
			// PrintAndLog("isOk:%02x data:%s", isOK, sprint_hex(data, 16));
		// else
			// PrintAndLog("isOk:%02x", isOK);
	// } else {
		// PrintAndLog("Command execute timeout");
	// }

  return 0;
}

int CmdHF14ADesInfo(const char *Cmd){

	UsbCommand c = {CMD_MIFARE_DESFIRE_INFO};
    SendCommand(&c);
	UsbCommand resp;
	
	if ( !WaitForResponseTimeout(CMD_ACK,&resp,1500) ) {
		PrintAndLog("Command execute timeout");
		return 0;
	}
	uint8_t isOK  = resp.arg[0] & 0xff;
	if ( !isOK ){
		PrintAndLog("Command unsuccessful");
		return 0;
	}  
	
	PrintAndLog("---Desfire Information---------------------------------------");
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog("  UID                : %s",sprint_hex(resp.d.asBytes, 7));
	PrintAndLog("  Batch number       : %s",sprint_hex(resp.d.asBytes+28,5));
	PrintAndLog("  Production date    : week %02x, 20%02x",resp.d.asBytes[33], resp.d.asBytes[34]);
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog("  Hardware Information");
	PrintAndLog("      Vendor Id      : %s", GetVendorStr(resp.d.asBytes[7]));
	PrintAndLog("      Type           : 0x%02X",resp.d.asBytes[8]);
	PrintAndLog("      Subtype        : 0x%02X",resp.d.asBytes[9]);
	PrintAndLog("      Version        : %d.%d",resp.d.asBytes[10], resp.d.asBytes[11]);
	PrintAndLog("      Storage size   : %s",GetCardSizeStr(resp.d.asBytes[12]));
	PrintAndLog("      Protocol       : %s",GetProtocolStr(resp.d.asBytes[13]));
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog("  Software Information");
	PrintAndLog("      Vendor Id      : %s",GetVendorStr(resp.d.asBytes[14]));
	PrintAndLog("      Type           : 0x%02X",resp.d.asBytes[15]);
	PrintAndLog("      Subtype        : 0x%02X",resp.d.asBytes[16]);
	PrintAndLog("      Version        : %d.%d",resp.d.asBytes[17], resp.d.asBytes[18]);
	PrintAndLog("      storage size   : %s", GetCardSizeStr(resp.d.asBytes[19]));
	PrintAndLog("      Protocol       : %s", GetProtocolStr(resp.d.asBytes[20]));
	PrintAndLog("-------------------------------------------------------------");
	
	
	UsbCommand c1 = {CMD_MIFARE_DESFIRE, { 0x03, 0x01 }};
	c1.d.asBytes[0] = GET_KEY_SETTINGS;
    SendCommand(&c1);
	if ( !WaitForResponseTimeout(CMD_ACK,&resp,1500) ) {
		return 0;
	}  
	
	PrintAndLog("  Master Key settings");
	if (  resp.d.asBytes[3] & (1 << 3 ) )
		PrintAndLog("     0x08 Configuration changeable");
	else
		PrintAndLog("     0x08 Configuration NOT changeable");

	if (  resp.d.asBytes[3] & (1 << 2 ) )
		PrintAndLog("     0x04 PICC Master Key not required for create / delete");
	else 
		PrintAndLog("     0x04 PICC Master Key required for create / delete");

	if (  resp.d.asBytes[3] & (1 << 1 ) )
		PrintAndLog("     0x02 Free directory list access without PICC Master Key");
	else
		PrintAndLog("     0x02 Directory list access with PICC Master Key");
	
	if (  resp.d.asBytes[3] & (1 << 0 ) )
		PrintAndLog("     0x01 Allow changing the Master Key");
	else
		PrintAndLog("     0x01 Master Key is not changeable anymore");
	
	//                                      init   len
	UsbCommand c2 = {CMD_MIFARE_DESFIRE, { 0x03, 0x02 }};
    c2.d.asBytes[0] = GET_KEY_VERSION;
	c2.d.asBytes[1] = 0x00;
	SendCommand(&c2);
	if ( !WaitForResponseTimeout(CMD_ACK,&resp,1500) ) {
		return 0;
	}
	
	PrintAndLog("");
	PrintAndLog("     Max number of keys  : %d", resp.d.asBytes[4]);
	PrintAndLog("     Master key Version  : %d (0x%02x)", resp.d.asBytes[3], resp.d.asBytes[3]);
	PrintAndLog("-------------------------------------------------------------");
	

	UsbCommand c3 = {CMD_MIFARE_DESFIRE, { 0x03, 0x01 }};
	c3.d.asBytes[0] = GET_FREE_MEMORY;
    SendCommand(&c3);
	if ( !WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
		return 0;
	}  
	
	uint8_t tmp[3];
	memcpy(tmp, resp.d.asBytes+3,3); 

	PrintAndLog("     Free memory on card : %d bytes", le24toh( tmp ));
	PrintAndLog("-------------------------------------------------------------");

	/*
		Card Master key (CMK)        0x00 AID = 00 00 00 (card level)
		Application Master Key (AMK) 0x00 AID != 00 00 00
		Application keys (APK)       0x01-0x0D
		Application free             0x0E
		Application never            0x0F
		
		ACCESS RIGHTS:
		keys 0,1,2,3     C
		keys 4,5,6,7     RW
		keys 8,9,10,11   W
		keys 12,13,14,15 R
		
		Session key:
			16 : RndA(byte0-byte3) + RndB(byte0-byte3) + RndA(byte4-byte7) + RndB(byte4-byte7)
			8  : RndA(byte0-byte3) + RndB(byte0-byte3) 
			
			AES 16 : RndA(byte0-byte3) + RndB(byte0-byte3) + RndA(byte12-byte15) + RndB(byte12-byte15)
	*/
	
    return 1;
}

char * GetVendorStr( uint8_t id){
 	static char buf[30];
	char *retStr = buf;
	
	if ( id == 0x04 )
		sprintf(retStr, "0x%02X (NXP)",id);
	else 
		sprintf(retStr,"0x%02X (Unknown)",id);
	return buf;
}

/*
  The 7 MSBits (= n) code the storage size itself based on 2^n, 
  the LSBit is set to '0' if the size is exactly 2^n
	and set to '1' if the storage size is between 2^n and 2^(n+1). 
	For this version of DESFire the 7 MSBits are set to 0x0C (2^12 = 4096) and the LSBit is '0'.
*/
char * GetCardSizeStr( uint8_t fsize ){
 
 	static char buf[30];
	char *retStr = buf;

	uint16_t usize = 1 << ((fsize >>1) + 1);
	uint16_t lsize = 1 << (fsize >>1);
	
	// is  LSB set?
	if (  fsize & (1 << 0 ) )
		sprintf(retStr, "0x%02X (%d - %d bytes)",fsize, usize, lsize);
	else 
		sprintf(retStr, "0x%02X (%d bytes)", fsize, lsize);		
	return buf;
}

char * GetProtocolStr(uint8_t id){

 	static char buf[30];
	char *retStr = buf;

	if ( id == 0x05)
		sprintf(retStr,"0x%02X (ISO 14443-3, 14443-4)", id);
	else
		sprintf(retStr,"0x%02X", id);	
	return buf;
}

int CmdHF14ADesEnumApplications(const char *Cmd){
	
	uint32_t options = 0x00;
	
	options |= INIT;
	options  |= DISCONNECT;
	
	UsbCommand c = {CMD_MIFARE_DESFIRE, {options , 0x01 }};
	c.d.asBytes[0] = GET_APPLICATION_IDS;  //0x6a
    SendCommand(&c);
	UsbCommand resp;
		
	if ( !WaitForResponseTimeout(CMD_ACK,&resp,1500) ) {
		return 0;
	}  
	
	uint8_t isOK  = resp.arg[0] & 0xff;
	if ( !isOK ){
		PrintAndLog("Command unsuccessful");
		return 0;
	} 
	
	PrintAndLog("---Desfire Enum Applications --------------------------------");
	PrintAndLog("-------------------------------------------------------------");

	UsbCommand respAid;
	UsbCommand respFiles;
	
	uint8_t num = 0;
	int max = resp.arg[1] -3 -2;
	
	for(int i=3; i<=max; i+=3){
		PrintAndLog(" Aid %d : %02X %02X %02X ",num ,resp.d.asBytes[i],resp.d.asBytes[i+1],resp.d.asBytes[i+2]);
		num++;
		
		options = INIT;

		UsbCommand cAid = {CMD_MIFARE_DESFIRE, { options, 0x04 }};
		cAid.d.asBytes[0] = SELECT_APPLICATION;  // 0x5a
		cAid.d.asBytes[1] = resp.d.asBytes[i];
		cAid.d.asBytes[2] = resp.d.asBytes[i+1];		
		cAid.d.asBytes[3] = resp.d.asBytes[i+2];
		SendCommand(&cAid);
		
		if (!WaitForResponseTimeout(CMD_ACK,&respAid,1500) ) {
			PrintAndLog("   Timed-out");
			continue;
		} 
		uint8_t isOK  = respAid.arg[0] & 0xff;
		if ( !isOK ){
			PrintAndLog("   Can't select AID: %s",sprint_hex(resp.d.asBytes+i,3));	
			continue;
		}
	
		options = DISCONNECT;
		UsbCommand cFiles = {CMD_MIFARE_DESFIRE, { options, 0x01 }};
		cFiles.d.asBytes[0] = GET_FILE_IDS; // 0x6f
		SendCommand(&cFiles);
		
		if ( !WaitForResponseTimeout(CMD_ACK,&respFiles,1500) ) {
			PrintAndLog("   Timed-out");
			continue;
		} else {
		
			uint8_t isOK  = respFiles.arg[0] & 0xff;
			if ( !isOK ){
				PrintAndLog("   No files found");
				continue;
			}
		
			int respfileLen = resp.arg[1]-3-2;			
			for (int j=0; j< respfileLen; ++j){
				PrintAndLog("   Fileid %d :", resp.d.asBytes[j+3]);
			}
		}
		
	}
	PrintAndLog("-------------------------------------------------------------");
	
	
	return 1;
}

int CmdHF14ADesNonces(const char *Cmd){
	return 1;
}

//
// MIAFRE DesFire Authentication
//
#define BUFSIZE 64 
int CmdHF14ADesAuth(const char *Cmd){
    
	// NR  DESC		KEYLENGHT
	// ------------------------
	// 1 = DES		8
	// 2 = 3DES		16
	// 3 = 3K 3DES	24
	// 4 = AES		16
	
	// AUTHENTICTION MODES:
	// 1 Normal
	// 2 ISO
	// 3 AES
	
	uint8_t keylength = 8;
	//unsigned char testinput[] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00};
	unsigned char key[24]; // =       { 0x75,0x28,0x78,0x39,0x74,0x93,0xCB,0x70};	
	
    if (strlen(Cmd)<3) {
        PrintAndLog("Usage:  hf mfdes auth <1|2|3> <1|2|3|4> <keyno> <key> ");
		PrintAndLog("		    AUTH modes 1 = normal, 2 = iso, 3 = aes");
		PrintAndLog("		    Crypto: 1 = DES 2 = 3DES 3 = 3K3DES 4 = AES");
		PrintAndLog("		    keynumber");
        PrintAndLog("        sample: hf mfdes auth 1 1 0 11223344");
        return 0;
    } 
	uint8_t cmdAuthMode	= param_get8(Cmd,0);
	uint8_t cmdAuthAlgo	= param_get8(Cmd,1);
	uint8_t cmdKeyNo	= param_get8(Cmd,2);
	
	switch (cmdAuthMode)
	{
		case 1: 
			if ( cmdAuthAlgo != 1 && cmdAuthAlgo != 2) {
				PrintAndLog("Crypto algo not valid for the auth mode");
				return 1;
			}
			break;
		case 2:
			if ( cmdAuthAlgo != 1 && cmdAuthAlgo != 2 && cmdAuthAlgo != 3) {
				PrintAndLog("Crypto algo not valid for the auth mode");
				return 1;
			}
			break;
		case 3:
			if ( cmdAuthAlgo != 4) {
				PrintAndLog("Crypto algo not valid for the auth mode");
				return 1;
			}
			break;
		default:
			PrintAndLog("Wrong Auth mode");
			return 1;
			break;
	}
	
	switch (cmdAuthAlgo){
		case 2: 
			keylength = 16;
			PrintAndLog("3DES selected");
			break;
		case 3: 
			keylength = 24;
			PrintAndLog("3 key 3DES selected");
			break;
		case 4:
			keylength = 16;
			PrintAndLog("AES selected");
			break;
		default:
			cmdAuthAlgo = 1;
			keylength = 8;
			PrintAndLog("DES selected");
			break;
	}

	// key
	if (param_gethex(Cmd, 3, key, keylength*2)) {
		PrintAndLog("Key must include %d HEX symbols", keylength);
		return 1;
	}
	// algo, nyckellängd, 
	UsbCommand c = {CMD_MIFARE_DESFIRE_AUTH1, { cmdAuthMode, cmdAuthAlgo, cmdKeyNo }};
	
	c.d.asBytes[0] = keylength;
	memcpy(c.d.asBytes+1, key, keylength);
	//memcpy(c.d.asBytes + 30, testinput, keylength);
	
    SendCommand(&c);
	UsbCommand resp;
	
	if (WaitForResponseTimeout(CMD_ACK,&resp,3000)) {
		uint8_t isOK  = resp.arg[0] & 0xff;
		PrintAndLog("isOk:%02x", isOK);

	} else {
		PrintAndLog("Command execute timeout");
		return 0;
	}  

	uint8_t * data= resp.d.asBytes;
		
	// PrintAndLog("-------------------------------------------------------------");
	 PrintAndLog("  Key        :%s",sprint_hex(key, keylength));
	// PrintAndLog("  Plain      :%s",sprint_hex(testinput, keylength));
	PrintAndLog("  Encoded    :%s",sprint_hex(data, keylength));
	PrintAndLog("-------------------------------------------------------------");
	//PrintAndLog("  Expected   :B5 21 9E E8 1A A7 49 9D 21 96 68 7E 13 97 38 56");
	
    return 1;
}


static void xor(unsigned char * dst, unsigned char * src, size_t len) {
   for( ; len > 0; len--,dst++,src++)
       *dst ^= *src;
}

static int32_t le24toh (uint8_t data[3]) {
    return (data[2] << 16) | (data[1] << 8) | data[0];
}

static command_t CommandTable[] =
{
  {"help",		CmdHelp,					1, "This help"},
  {"auth",		CmdHF14ADesAuth,			0, "Tries a MIFARE DesFire Authentication"},
  {"rb",		CmdHF14ADesRb,				0, "Read MIFARE DesFire block"},
  {"wb",		CmdHF14ADesWb,				0, "write MIFARE DesFire block"},
  {"info",		CmdHF14ADesInfo,			0, "Get MIFARE DesFire information"},
  {"enum",		CmdHF14ADesEnumApplications,0, "Tries enumerate all applications"},
  {"nonce",		CmdHF14ADesNonces, 			0, "<n> Collect n>0 nonces"},
  {NULL, NULL, 0, NULL}
};

int CmdHFMFDes(const char *Cmd)
{
   // flush
   WaitForResponseTimeout(CMD_ACK,NULL,100);
   CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}


