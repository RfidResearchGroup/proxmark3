//-----------------------------------------------------------------------------
// 2011, Merlok
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>, Hagen Fritsch
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443A commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "util.h"
#include "iso14443crc.h"
#include "data.h"
#include "proxusb.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhf14a.h"
#include "common.h"
#include "cmdmain.h"
#include "nonce2key/nonce2key.h"
#include "nonce2key/crapto1.h"
#include "mifarehost.h"

static int CmdHelp(const char *Cmd);

int CmdHF14AList(const char *Cmd)
{
  uint8_t got[1920];
  GetFromBigBuf(got, sizeof(got));

  PrintAndLog("recorded activity:");
  PrintAndLog(" ETU     :rssi: who bytes");
  PrintAndLog("---------+----+----+-----------");

  int i = 0;
  int prev = -1;

  for (;;) {
    if(i >= 1900) {
      break;
    }

    bool isResponse;
    int timestamp = *((uint32_t *)(got+i));
    if (timestamp & 0x80000000) {
      timestamp &= 0x7fffffff;
      isResponse = 1;
    } else {
      isResponse = 0;
    }

    int metric = 0;
    int parityBits = *((uint32_t *)(got+i+4));
    // 4 bytes of additional information...
    // maximum of 32 additional parity bit information
    //
    // TODO:
    // at each quarter bit period we can send power level (16 levels)
    // or each half bit period in 256 levels.


    int len = got[i+8];

    if (len > 100) {
      break;
    }
    if (i + len >= 1900) {
      break;
    }

    uint8_t *frame = (got+i+9);

    // Break and stick with current result if buffer was not completely full
    if (frame[0] == 0x44 && frame[1] == 0x44 && frame[3] == 0x44) { break; }

    char line[1000] = "";
    int j;
    for (j = 0; j < len; j++) {
      int oddparity = 0x01;
      int k;

      for (k=0;k<8;k++) {
        oddparity ^= (((frame[j] & 0xFF) >> k) & 0x01);
      }

      //if((parityBits >> (len - j - 1)) & 0x01) {
      if (isResponse && (oddparity != ((parityBits >> (len - j - 1)) & 0x01))) {
        sprintf(line+(j*4), "%02x!  ", frame[j]);
      }
      else {
        sprintf(line+(j*4), "%02x   ", frame[j]);
      }
    }

    char *crc;
    crc = "";
    if (len > 2) {
      uint8_t b1, b2;
      for (j = 0; j < (len - 1); j++) {
        // gives problems... search for the reason..
        /*if(frame[j] == 0xAA) {
          switch(frame[j+1]) {
            case 0x01:
              crc = "[1] Two drops close after each other";
            break;
            case 0x02:
              crc = "[2] Potential SOC with a drop in second half of bitperiod";
              break;
            case 0x03:
              crc = "[3] Segment Z after segment X is not possible";
              break;
            case 0x04:
              crc = "[4] Parity bit of a fully received byte was wrong";
              break;
            default:
              crc = "[?] Unknown error";
              break;
          }
          break;
        }*/
      }

      if (strlen(crc)==0) {
        ComputeCrc14443(CRC_14443_A, frame, len-2, &b1, &b2);
        if (b1 != frame[len-2] || b2 != frame[len-1]) {
          crc = (isResponse & (len < 6)) ? "" : " !crc";
        } else {
          crc = "";
        }
      }
    } else {
      crc = ""; // SHORT
    }

    char metricString[100];
    if (isResponse) {
      sprintf(metricString, "%3d", metric);
    } else {
      strcpy(metricString, "   ");
    }

    PrintAndLog(" +%7d: %s: %s %s %s",
      (prev < 0 ? 0 : (timestamp - prev)),
      metricString,
      (isResponse ? "TAG" : "   "), line, crc);

    prev = timestamp;
    i += (len + 9);
  }
	return 0;
}

void iso14a_set_timeout(uint32_t timeout) {
	UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_SET_TIMEOUT, 0, timeout}};
	SendCommand(&c);
}

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
		PrintAndLog("Found invalid key. (");	
	
	
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
		PrintAndLog("Usage:  hf 14 mfwrbl    <block number> <key A/B> <key (12 hex symbols)> <block data (32 hex symbols)>");
		PrintAndLog("        sample: hf 14a mfwrbl 0 A FFFFFFFFFFFF 000102030405060708090A0B0C0D0E0F");
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
		PrintAndLog("Usage:  hf 14 mfrdbl    <block number> <key A/B> <key (12 hex symbols)>");
		PrintAndLog("        sample: hf 14a mfrdbl 0 A FFFFFFFFFFFF ");
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
		PrintAndLog("Usage:  hf 14 mfrdsc    <sector number> <key A/B> <key (12 hex symbols)>");
		PrintAndLog("        sample: hf 14a mfrdsc 0 A FFFFFFFFFFFF ");
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
		PrintAndLog(" all sectors:  hf 14a nested  <card memory> <block number> <key A/B> <key (12 hex symbols)>");
		PrintAndLog(" one sector:   hf 14a nested  o <block number> <key A/B> <key (12 hex symbols)>");
		PrintAndLog("               <target block number> <target key A/B>");
		PrintAndLog("card memory - 1 - 1K, 2 - 2K, 4 - 4K, <other> - 1K");
		PrintAndLog(" ");
		PrintAndLog("      sample1: hf 14a nested 1 0 A FFFFFFFFFFFF ");
		PrintAndLog("      sample2: hf 14a nested o 0 A FFFFFFFFFFFF 4 A");
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
		PrintAndLog("|blk|key A           |res|key B           |res|");
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
		PrintAndLog("Usage:  hf 14a chk <block number> <key A/B> [<key (12 hex symbols)>]");
		PrintAndLog("      sample: hf 14a chk 0 A FFFFFFFFFFFF a0a1a2a3a4a5 b01b2b3b4b5 ");
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
	int i, temp;
	uint8_t uid[4] = {0, 0, 0, 0};
	
	const char *cmdp	= Cmd;


	if (strlen(Cmd)<3) {
		PrintAndLog("Usage:  hf 14a mfsim  <uid (8 hex symbols)>");
		PrintAndLog("           sample: hf 14a mfsim 0a0a0a0a ");
		return 0;
	}	
	
  // skip spaces
	while (*cmdp==' ' || *cmdp=='\t') cmdp++;

	if (strlen(cmdp) != 8) {
		PrintAndLog("Length of UID must be 8 hex symbols");
		return 0;
	}
	
	for(i = 0; i < 4; i++) {
		sscanf((char[]){cmdp[0],cmdp[1],0},"%X",&temp);
		uid[i] = temp & 0xff;
		cmdp++;
		cmdp++;
	}	
	PrintAndLog(" uid:%s ", sprint_hex(uid, 4));
	
  UsbCommand c = {CMD_SIMULATE_MIFARE_CARD, {0, 0, 0}};
	memcpy(c.d.asBytes, uid, 6);
  SendCommand(&c);

  return 0;
}


int CmdHF14AReader(const char *Cmd)
{
	UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_CONNECT, 0, 0}};
	SendCommand(&c);
	UsbCommand * resp = WaitForResponse(CMD_ACK);
	uint8_t              * uid  = resp->d.asBytes;
	iso14a_card_select_t * card = uid + 12;

	if(resp->arg[0] == 0) {
		PrintAndLog("iso14443a card select failed");
		return 0;
	}

	PrintAndLog("ATQA : %02x %02x", card->atqa[0], card->atqa[1]);
	PrintAndLog(" UID : %s", sprint_hex(uid, 12));
	PrintAndLog(" SAK : %02x [%d]", card->sak, resp->arg[0]);
	if(resp->arg[0] == 1)
		PrintAndLog(" ATS : %s", sprint_hex(card->ats, card->ats_len));
	else
		PrintAndLog("proprietary non-iso14443a card found, RATS not supported");

	return resp->arg[0];
}

// ## simulate iso14443a tag
// ## greg - added ability to specify tag UID
int CmdHF14ASim(const char *Cmd)
{                                 

  unsigned int hi = 0, lo = 0;
  int n = 0, i = 0;
  while (sscanf(&Cmd[i++], "%1x", &n ) == 1) {
    hi= (hi << 4) | (lo >> 28);
    lo= (lo << 4) | (n & 0xf);
  }

  // c.arg should be set to *Cmd or convert *Cmd to the correct format for a uid
  UsbCommand c = {CMD_SIMULATE_TAG_ISO_14443a, {hi, lo, 0}};
  PrintAndLog("Emulating 14443A TAG with UID %x%16x", hi, lo);
  SendCommand(&c);
  return 0;
}

int CmdHF14ASnoop(const char *Cmd)
{
  UsbCommand c = {CMD_SNOOP_ISO_14443a};
  SendCommand(&c);
  return 0;
}

static command_t CommandTable[] = 
{
  {"help",   CmdHelp,          1, "This help"},
  {"list",   CmdHF14AList,     0, "List ISO 14443a history"},
  {"mifare", CmdHF14AMifare,   0, "Read out sector 0 parity error messages. param - <used card nonce>"},
  {"mfrdbl", CmdHF14AMfRdBl,   0, "Read MIFARE classic block"},
  {"mfrdsc", CmdHF14AMfRdSc,   0, "Read MIFARE classic sector"},
  {"mfwrbl", CmdHF14AMfWrBl,   0, "Write MIFARE classic block"},
  {"nested", CmdHF14AMfNested, 0, "Test nested authentication"},
  {"chk",    CmdHF14AMfChk,    0, "Test block up to 8 keys"},
  {"mfsim",  CmdHF14AMf1kSim,  0, "Simulate MIFARE 1k card - NOT WORKING!!!"},
  {"reader", CmdHF14AReader,   0, "Act like an ISO14443 Type A reader"},
  {"sim",    CmdHF14ASim,      0, "<UID> -- Fake ISO 14443a tag"},
  {"snoop",  CmdHF14ASnoop,    0, "Eavesdrop ISO 14443 Type A"},
  {NULL, NULL, 0, NULL}
};

int CmdHF14A(const char *Cmd)
{
	// flush
	while (WaitForResponseTimeout(CMD_ACK, 500) != NULL) ;

	// parse
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
