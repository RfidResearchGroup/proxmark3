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
#define NUM_CSNS 15
int CmdHFiClassSim(const char *Cmd)
{
  uint8_t simType = 0;
  uint8_t CSN[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  if (strlen(Cmd)<1) {
	PrintAndLog("Usage:  hf iclass sim [0 <CSN>] | x");
	PrintAndLog("        options");
	PrintAndLog("                0 <CSN> simulate the given CSN");
	PrintAndLog("                1       simulate default CSN");
	PrintAndLog("                2       iterate CSNs, gather MACs");
	PrintAndLog("        sample: hf iclass sim 0 031FEC8AF7FF12E0");
	PrintAndLog("        sample: hf iclass sim 2");
	return 0;
  }	

  simType = param_get8(Cmd, 0);

  if(simType == 0)
  {
	  if (param_gethex(Cmd, 1, CSN, 16)) {
		  PrintAndLog("A CSN should consist of 16 HEX symbols");
		  return 1;
	  }
	  PrintAndLog("--simtype:%02x csn:%s", simType, sprint_hex(CSN, 8));

  }
  if(simType > 2)
  {
	  PrintAndLog("Undefined simptype %d", simType);
	  return 1;
  }
  uint8_t numberOfCSNs=0;

	if(simType == 2)
	{
		UsbCommand c = {CMD_SIMULATE_TAG_ICLASS, {simType,NUM_CSNS}};
		UsbCommand resp = {0};

		/*uint8_t csns[8 * NUM_CSNS] = {
			 0x00,0x0B,0x0F,0xFF,0xF7,0xFF,0x12,0xE0 ,
			 0x00,0x13,0x94,0x7e,0x76,0xff,0x12,0xe0 ,
			 0x2a,0x99,0xac,0x79,0xec,0xff,0x12,0xe0 ,
			 0x17,0x12,0x01,0xfd,0xf7,0xff,0x12,0xe0 ,
			 0xcd,0x56,0x01,0x7c,0x6f,0xff,0x12,0xe0 ,
			 0x4b,0x5e,0x0b,0x72,0xef,0xff,0x12,0xe0 ,
			 0x00,0x73,0xd8,0x75,0x58,0xff,0x12,0xe0 ,
			 0x0c,0x90,0x32,0xf3,0x5d,0xff,0x12,0xe0 };
*/
      
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

int CmdHFiClassReader(const char *Cmd)
{
  UsbCommand c = {CMD_READER_ICLASS, {0}};
  SendCommand(&c);
    UsbCommand resp;
  while(!ukbhit()){
      if (WaitForResponseTimeout(CMD_ACK,&resp,4500)) {
            uint8_t isOK    = resp.arg[0] & 0xff;
            uint8_t * data  = resp.d.asBytes;

            PrintAndLog("isOk:%02x", isOK);
            if( isOK == 0){
                //Aborted
                PrintAndLog("Quitting...");
                return 0;
            }
            if(isOK > 0)
            {
                PrintAndLog("CSN: %s",sprint_hex(data,8));
            }
            if(isOK >= 1)
            {
                PrintAndLog("CC: %s",sprint_hex(data+8,8));
            }else{
                PrintAndLog("No CC obtained");
            }
        } else {
            PrintAndLog("Command execute timeout");
        }
    }

  return 0;
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

  //HACK -- Below is for testing without access to a tag
  uint8_t fake_dummy_test = false;
  if(fake_dummy_test)
  {
    uint8_t xdata[16] = {0x01,0x02,0x03,0x04,0xF7,0xFF,0x12,0xE0, //CSN from http://www.proxmark.org/forum/viewtopic.php?pid=11230#p11230
                        0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; // Just a random CC. Would be good to add a real testcase here
    memcpy(resp.d.asBytes,xdata, 16);
    resp.arg[0] = 2;    
  }
  
  //End hack


  UsbCommand c = {CMD_READER_ICLASS, {0}};
  c.arg[0] = FLAG_ICLASS_READER_ONLY_ONCE| FLAG_ICLASS_READER_GET_CC;
  if(!fake_dummy_test)   
    SendCommand(&c);
  


  if (fake_dummy_test || WaitForResponseTimeout(CMD_ACK,&resp,4500)) {
        uint8_t isOK    = resp.arg[0] & 0xff;
        uint8_t * data  = resp.d.asBytes;

        memcpy(CSN,data,8);
        memcpy(CCNR,data+8,8);

        PrintAndLog("isOk:%02x", isOK);

        if(isOK > 0)
        {
            PrintAndLog("CSN: %s",sprint_hex(CSN,8));
        }
        if(isOK > 1)
        {
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
                //Perhaps this should also be permuted to std format?
                // Something like the code below? I have no std system
                // to test this with /Martin

                //uint8_t key_sel_p[8] = { 0 };
                //permutekey_rev(KEY,key_sel_p);
                //used_key = key_sel_p;

                used_key = KEY;

            }

            PrintAndLog("Pre-fortified key that would be needed by the OmniKey reader to talk to above CSN:");
            printvar("Used key",used_key,8);
            diversifyKey(CSN,used_key, div_key);
            PrintAndLog("Hash0, a.k.a diversified key, that is computed using Ksel and stored in the card (Block 3):");
            printvar("Div key", div_key, 8);
            printvar("CC_NR:",CCNR,12);
            doMAC(CCNR,12,div_key, MAC);
            printvar("MAC", MAC, 4);

            UsbCommand d = {CMD_READER_ICLASS_REPLAY, {readerType}};
            memcpy(d.d.asBytes, MAC, 4);
            if(!fake_dummy_test) SendCommand(&d);

        }else{
            PrintAndLog("Failed to obtain CC! Aborting");
        }
    } else {
        PrintAndLog("Command execute timeout");
    }

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
  doMAC(CCNR, 12,div_key, MAC);

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
	{"write",	CmdHFiClass_iso14443A_write,	0,	"Authenticate and Write iClass block"},
	{"loclass",	CmdHFiClass_loclass,	1,	"Use loclass to perform bruteforce of reader attack dump"},
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
