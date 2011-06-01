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
#include <conio.h>
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
	
	UsbCommand c = {CMD_READER_MIFARE, {strtol(Cmd, NULL, 0), 0, 0}};
	SendCommand(&c);
	
	//flush queue
	while (kbhit())	getchar();
	while (WaitForResponseTimeout(CMD_ACK, 500) != NULL) ;

	// message
	printf("-------------------------------------------------------------------------\n");
	printf("Executing command. It may take up to 30 min.\n");
	printf("Press the key on proxmark3 device to abort proxmark3.\n");
	printf("Press the key on the proxmark3 device to abort both proxmark3 and client.\n");
	printf("-------------------------------------------------------------------------\n");
	
	// wait cycle
	while (true) {
		printf(".");
		if (kbhit()) {
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
	printf("-------------------------------------------------------------------------\n");
	PrintAndLog("Key found:%012llx \n", r_key);
	
	return 0;
}

int CmdHF14AMfWrBl(const char *Cmd)
{
	int i, temp;
	uint8_t blockNo = 0;
	uint8_t keyType = 0;
	uint8_t key[6] = {0, 0, 0, 0, 0, 0};
	uint8_t bldata[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	
	const char *cmdp	= Cmd;
	const char *cmdpe	= Cmd;

	if (strlen(Cmd)<3) {
		PrintAndLog("Usage:  hf 14 mfwrbl    <block number> <key A/B> <key (12 hex symbols)> <block data (32 hex symbols)>");
		PrintAndLog("           sample: hf 14a mfwrbl 0 A FFFFFFFFFFFF 000102030405060708090A0B0C0D0E0F");
		return 0;
	}	
	PrintAndLog("l: %s", Cmd);
	
	// skip spaces
	while (*cmdp==' ' || *cmdp=='\t') cmdp++;
	blockNo = strtol(cmdp, NULL, 0) & 0xff;
	
	// next value
	while (*cmdp!=' ' && *cmdp!='\t') cmdp++;
	while (*cmdp==' ' || *cmdp=='\t') cmdp++;
	if (*cmdp != 'A' && *cmdp != 'a')  {
		keyType = 1;
	}

	// next value
	while (*cmdp!=' ' && *cmdp!='\t') cmdp++;
	while (*cmdp==' ' || *cmdp=='\t') cmdp++;

	// next value here:cmdpe
	cmdpe = cmdp;
	while (*cmdpe!=' ' && *cmdpe!='\t') cmdpe++;
	while (*cmdpe==' ' || *cmdpe=='\t') cmdpe++;

	if ((int)cmdpe - (int)cmdp != 13) {
		PrintAndLog("Length of key must be 12 hex symbols");
		return 0;
	}
	
	for(i = 0; i < 6; i++) {
		sscanf((char[]){cmdp[0],cmdp[1],0},"%X",&temp);
		key[i] = temp & 0xff;
		cmdp++;
		cmdp++;
	}	

	// next value
	while (*cmdp!=' ' && *cmdp!='\t') cmdp++;
	while (*cmdp==' ' || *cmdp=='\t') cmdp++;

	if (strlen(cmdp) != 32) {
		PrintAndLog("Length of block data must be 32 hex symbols");
		return 0;
	}

	for(i = 0; i < 16; i++) {
		sscanf((char[]){cmdp[0],cmdp[1],0},"%X",&temp);
		bldata[i] = temp & 0xff;
		cmdp++;
		cmdp++;
	}	
	PrintAndLog(" block no:%02x key type:%02x key:%s", blockNo, keyType, sprint_hex(key, 6));
	PrintAndLog(" data: %s", sprint_hex(bldata, 16));
	
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
	int i, temp;
	uint8_t blockNo = 0;
	uint8_t keyType = 0;
	uint8_t key[6] = {0, 0, 0, 0, 0, 0};
	
	const char *cmdp	= Cmd;


	if (strlen(Cmd)<3) {
		PrintAndLog("Usage:  hf 14 mfrdbl    <block number> <key A/B> <key (12 hex symbols)>");
		PrintAndLog("           sample: hf 14a mfrdbl 0 A FFFFFFFFFFFF ");
		return 0;
	}	
	
  // skip spaces
	while (*cmdp==' ' || *cmdp=='\t') cmdp++;
	blockNo = strtol(cmdp, NULL, 0) & 0xff;
	
	// next value
	while (*cmdp!=' ' && *cmdp!='\t') cmdp++;
	while (*cmdp==' ' || *cmdp=='\t') cmdp++;
	if (*cmdp != 'A' && *cmdp != 'a')  {
		keyType = 1;
	}

	// next value
	while (*cmdp!=' ' && *cmdp!='\t') cmdp++;
	while (*cmdp==' ' || *cmdp=='\t') cmdp++;

	if (strlen(cmdp) != 12) {
		PrintAndLog("Length of key must be 12 hex symbols");
		return 0;
	}
	
	for(i = 0; i < 6; i++) {
		sscanf((char[]){cmdp[0],cmdp[1],0},"%X",&temp);
		key[i] = temp & 0xff;
		cmdp++;
		cmdp++;
	}	
	PrintAndLog(" block no:%02x key type:%02x key:%s ", blockNo, keyType, sprint_hex(key, 6));
	
  UsbCommand c = {CMD_MIFARE_READBL, {blockNo, keyType, 0}};
	memcpy(c.d.asBytes, key, 6);
  SendCommand(&c);
	UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 1500);

	if (resp != NULL) {
		uint8_t                isOK  = resp->arg[0] & 0xff;
		uint8_t              * data  = resp->d.asBytes;

		PrintAndLog("isOk:%02x data:%s", isOK, sprint_hex(data, 16));
	} else {
		PrintAndLog("Command execute timeout");
	}

  return 0;
}

int CmdHF14AMfRdSc(const char *Cmd)
{
	int i, temp;
	uint8_t sectorNo = 0;
	uint8_t keyType = 0;
	uint8_t key[6] = {0, 0, 0, 0, 0, 0};
	
	const char *cmdp	= Cmd;


	if (strlen(Cmd)<3) {
		PrintAndLog("Usage:  hf 14 mfrdsc    <sector number> <key A/B> <key (12 hex symbols)>");
		PrintAndLog("           sample: hf 14a mfrdsc 0 A FFFFFFFFFFFF ");
		return 0;
	}	
	
  // skip spaces
	while (*cmdp==' ' || *cmdp=='\t') cmdp++;
	sectorNo = strtol(cmdp, NULL, 0) & 0xff;
	
	// next value
	while (*cmdp!=' ' && *cmdp!='\t') cmdp++;
	while (*cmdp==' ' || *cmdp=='\t') cmdp++;
	if (*cmdp != 'A' && *cmdp != 'a')  {
		keyType = 1;
	}

	// next value
	while (*cmdp!=' ' && *cmdp!='\t') cmdp++;
	while (*cmdp==' ' || *cmdp=='\t') cmdp++;

	if (strlen(cmdp) != 12) {
		PrintAndLog("Length of key must be 12 hex symbols");
		return 0;
	}
	
	for(i = 0; i < 6; i++) {
		sscanf((char[]){cmdp[0],cmdp[1],0},"%X",&temp);
		key[i] = temp & 0xff;
		cmdp++;
		cmdp++;
	}	
	PrintAndLog(" sector no:%02x key type:%02x key:%s ", sectorNo, keyType, sprint_hex(key, 6));
	
  UsbCommand c = {CMD_MIFARE_READSC, {sectorNo, keyType, 0}};
	memcpy(c.d.asBytes, key, 6);
  SendCommand(&c);
	UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 1500);
	PrintAndLog(" ");

	if (resp != NULL) {
		uint8_t                isOK  = resp->arg[0] & 0xff;
		uint8_t              * data  = resp->d.asBytes;

		PrintAndLog("isOk:%02x", isOK);
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
		uint8_t              * data  = resp->d.asBytes;

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
	int i, temp, len;
	uint8_t sectorNo = 0;
	uint8_t keyType = 0;
	uint8_t key[6] = {0, 0, 0, 0, 0, 0};
	uint8_t isEOF;
	uint8_t * data;
	uint32_t uid;
	fnVector * vector = NULL;
	int lenVector = 0;
	UsbCommand * resp = NULL;
	
	const char *cmdp	= Cmd;

	if (strlen(Cmd)<3) {
		PrintAndLog("Usage:  hf 14a nested    <sector number> <key A/B> <key (12 hex symbols)>");
		PrintAndLog("           sample: hf 14a nested 0 A FFFFFFFFFFFF ");
		return 0;
	}	
	
  // skip spaces
	while (*cmdp==' ' || *cmdp=='\t') cmdp++;
	sectorNo = strtol(cmdp, NULL, 0) & 0xff;
	
	// next value
	while (*cmdp!=' ' && *cmdp!='\t') cmdp++;
	while (*cmdp==' ' || *cmdp=='\t') cmdp++;
	if (*cmdp != 'A' && *cmdp != 'a')  {
		keyType = 1;
	}

	// next value
	while (*cmdp!=' ' && *cmdp!='\t') cmdp++;
	while (*cmdp==' ' || *cmdp=='\t') cmdp++;

	if (strlen(cmdp) != 12) {
		PrintAndLog("Length of key must be 12 hex symbols");
		return 0;
	}
	
	for(i = 0; i < 6; i++) {
		sscanf((char[]){cmdp[0],cmdp[1],0},"%X",&temp);
		key[i] = temp & 0xff;
		cmdp++;
		cmdp++;
	}	
	PrintAndLog(" sector no:%02x key type:%02x key:%s ", sectorNo, keyType, sprint_hex(key, 6));

	// flush queue
	while (WaitForResponseTimeout(CMD_ACK, 500) != NULL) ;
	
  UsbCommand c = {CMD_MIFARE_NESTED, {sectorNo, keyType, 0}};
	memcpy(c.d.asBytes, key, 6);
  SendCommand(&c);

	PrintAndLog("\n");
	printf("-------------------------------------------------------------------------\n");

	// wait cycle
	while (true) {
		printf(".");
		if (kbhit()) {
			getchar();
			printf("\naborted via keyboard!\n");
			break;
		}

		resp = WaitForResponseTimeout(CMD_ACK, 1500);

		if (resp != NULL) {
			isEOF  = resp->arg[0] & 0xff;
			data  = resp->d.asBytes;

			PrintAndLog("isEOF:%02x", isEOF);	
			for (i = 0; i < 2; i++) {
				PrintAndLog("data:%s", sprint_hex(data + i * 16, 16));
			}
			if (isEOF) break;
			
			len = resp->arg[1] & 0xff;
			if (len == 0) continue;
			
			memcpy(&uid, resp->d.asBytes, 4); 
			PrintAndLog("uid:%08x len=%d trgbl=%d trgkey=%d", uid, len, resp->arg[2] & 0xff, (resp->arg[2] >> 8) & 0xff);

			vector = (fnVector *) realloc((void *)vector, (lenVector + len) * sizeof(fnVector) + 200);
			if (vector == NULL) {
				PrintAndLog("Memory allocation error for fnVector. len: %d bytes: %d", lenVector + len, (lenVector + len) * sizeof(fnVector)); 
				break;
			}
			
			for (i = 0; i < len; i++) {
				vector[lenVector + i].blockNo = resp->arg[2] & 0xff;
				vector[lenVector + i].keyType = (resp->arg[2] >> 8) & 0xff;
				vector[lenVector + i].uid = uid;

				memcpy(&vector[lenVector + i].nt,  (void *)(resp->d.asBytes + 8 + i * 8 + 0), 4);
				memcpy(&vector[lenVector + i].ks1, (void *)(resp->d.asBytes + 8 + i * 8 + 4), 4);

				PrintAndLog("i=%d nt:%08x ks1:%08x", i, vector[lenVector + i].nt, vector[lenVector + i].ks1);
			}

			lenVector += len;
		}
	}
	
	
	
	// finalize
	free(vector);

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
  {"mfsim",  CmdHF14AMf1kSim,  0, "Simulate MIFARE 1k card - NOT WORKING!!!"},
  {"reader", CmdHF14AReader,   0, "Act like an ISO14443 Type A reader"},
  {"sim",    CmdHF14ASim,      0, "<UID> -- Fake ISO 14443a tag"},
  {"snoop",  CmdHF14ASnoop,    0, "Eavesdrop ISO 14443 Type A"},
  {NULL, NULL, 0, NULL}
};

int CmdHF14A(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
