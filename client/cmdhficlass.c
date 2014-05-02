//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>, Hagen Fritsch
// Copyright (C) 2011 Gerhard de Koning Gans
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
#include "iso14443crc.h" // Can also be used for iClass, using 0xE012 as CRC-type
#include "data.h"
//#include "proxusb.h"
#include "proxmark3.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhficlass.h"
#include "common.h"
#include "util.h"
#include "loclass/des.h"
#include "loclass/cipherutils.h"
#include "loclass/cipher.h"
#include "loclass/ikeys.h"

static int CmdHelp(const char *Cmd);

int CmdHFiClassList(const char *Cmd)
{
  uint8_t got[1920];
  GetFromBigBuf(got,sizeof(got),0);

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
	if(!isResponse && len == 4) {
		// Rough guess that this is a command from the reader
		// For iClass the command byte is not part of the CRC
	        ComputeCrc14443(CRC_ICLASS, &frame[1], len-3, &b1, &b2);
	}
	else {
		// For other data.. CRC might not be applicable (UPDATE commands etc.)
	        ComputeCrc14443(CRC_ICLASS, frame, len-2, &b1, &b2);
	}
	//printf("%1x %1x",(unsigned)b1,(unsigned)b2);
        if (b1 != frame[len-2] || b2 != frame[len-1]) {
          crc = (isResponse & (len < 8)) ? "" : " !crc";
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

/*void iso14a_set_timeout(uint32_t timeout) {
	UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_SET_TIMEOUT, 0, timeout}};
	SendCommand(&c);
}*/

int CmdHFiClassSnoop(const char *Cmd)
{
  UsbCommand c = {CMD_SNOOP_ICLASS};
  SendCommand(&c);
  return 0;
}

int CmdHFiClassSim(const char *Cmd)
{
  uint8_t simType = 0;
  uint8_t CSN[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  if (strlen(Cmd)<2) {
	PrintAndLog("Usage:  hf iclass sim    <sim type> <CSN (16 hex symbols)>");
	PrintAndLog("        sample: hf iclass sim 0 031FEC8AF7FF12E0");
	return 0;
  }	

  simType = param_get8(Cmd, 0);
  if (param_gethex(Cmd, 1, CSN, 16)) {
	PrintAndLog("A CSN should consist of 16 HEX symbols");
	return 1;
  }
  PrintAndLog("--simtype:%02x csn:%s", simType, sprint_hex(CSN, 8));

  UsbCommand c = {CMD_SIMULATE_TAG_ICLASS, {simType}};
  memcpy(c.d.asBytes, CSN, 8);
  SendCommand(&c);

  /*UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 1500);
  if (resp != NULL) {
	uint8_t                isOK  = resp->arg[0] & 0xff;
	PrintAndLog("isOk:%02x", isOK);
  } else {
	PrintAndLog("Command execute timeout");
  }*/

  return 0;
}

int CmdHFiClassReader(const char *Cmd)
{
  uint8_t readerType = 0;

  if (strlen(Cmd)<1) {
	PrintAndLog("Usage:  hf iclass reader    <reader type>");
	PrintAndLog("        sample: hf iclass reader 0");
	return 0;
  }	

  readerType = param_get8(Cmd, 0);
  PrintAndLog("--readertype:%02x", readerType);

  UsbCommand c = {CMD_READER_ICLASS, {readerType}};
  SendCommand(&c);

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
  uint8_t CC_temp[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  uint8_t result[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  uint8_t div_key[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  des_context ctx_enc;
  uint64_t crypted_id=0;

  if (strlen(Cmd)<3) {
    PrintAndLog("Usage:  hf iclass dump <Key> <CSN> <CC>");
    PrintAndLog("        sample: hf iclass dump 0011223344556677 aabbccddeeffgghh FFFFFFFFFFFFFFFF");
    return 0;
  }

  if (param_gethex(Cmd, 0, KEY, 16)) {
    PrintAndLog("KEY must include 16 HEX symbols");
    return 1;
  }
  
  if (param_gethex(Cmd, 1, CSN, 16)) {
    PrintAndLog("CSN must include 16 HEX symbols");
    return 1;
  }
  if (param_gethex(Cmd, 2, CC_temp, 16)) {
    PrintAndLog("CC must include 16 HEX symbols");
    return 1;
  }
  
  memcpy(CCNR,CC_temp,8);
  des_setkey_enc( &ctx_enc, KEY);
  des_crypt_ecb(&ctx_enc,CSN,result);
  PrintAndLog("DES Key: %s",sprint_hex(result,8));
    uint64_t newz=0;
	crypted_id = bytes_to_num(result,8);
	uint64_t x = (crypted_id & 0xFFFF000000000000 );
	pushbackSixBitByte(&newz, getSixBitByte(crypted_id,0),7);
	pushbackSixBitByte(&newz, getSixBitByte(crypted_id,1),6);
	pushbackSixBitByte(&newz, getSixBitByte(crypted_id,2),5);
	pushbackSixBitByte(&newz, getSixBitByte(crypted_id,3),4);
	pushbackSixBitByte(&newz, getSixBitByte(crypted_id,4),3);
	pushbackSixBitByte(&newz, getSixBitByte(crypted_id,5),2);
	pushbackSixBitByte(&newz, getSixBitByte(crypted_id,6),1);
	pushbackSixBitByte(&newz, getSixBitByte(crypted_id,7),0);
	newz|= x;
	crypted_id=newz;
	num_to_bytes(crypted_id,8,result);
  PrintAndLog("DESr Key: %s",sprint_hex(result,8));	
  //crypted_id = bytes_to_num(result,8);
  //memset(result,0,8);
  hash0(crypted_id,div_key);
  //memcpy(div_key,result,8);
  PrintAndLog("Div Key: %s",sprint_hex(div_key,8));
  calc_iclass_mac(CCNR,div_key,MAC);

  UsbCommand c = {CMD_READER_ICLASS_REPLAY, {readerType}};
  memcpy(c.d.asBytes, MAC, 4);
  SendCommand(&c);

  return 0;
}


static command_t CommandTable[] = 
{
  {"help",    CmdHelp,        1, "This help"},
  {"list",    CmdHFiClassList,   0, "List iClass history"},
  {"snoop",   CmdHFiClassSnoop,  0, "Eavesdrop iClass communication"},
  {"sim",     CmdHFiClassSim,    0, "Simulate iClass tag"},
  {"reader",  CmdHFiClassReader, 0, "Read an iClass tag"},
  {"replay",  CmdHFiClassReader_Replay, 0, "Read an iClass tag via Reply Attack"},
  {"dump",	  CmdHFiClassReader_Dump, 0, "Authenticate and Dump iClass tag"},
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
