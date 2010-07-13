//-----------------------------------------------------------------------------
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
#include "iso14443crc.h"
#include "data.h"
#include "proxusb.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhf14a.h"
#include "common.h"

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
  UsbCommand c = {CMD_READER_MIFARE, {strtol(Cmd, NULL, 0), 0, 0}};
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
  {"help",    CmdHelp,        1, "This help"},
  {"list",    CmdHF14AList,   0, "List ISO 14443a history"},
  {"mifare",  CmdHF14AMifare, 0, "Read out sector 0 parity error messages"},
  {"reader",  CmdHF14AReader, 0, "Act like an ISO14443 Type A reader"},
  {"sim",     CmdHF14ASim,    0, "<UID> -- Fake ISO 14443a tag"},
  {"snoop",   CmdHF14ASnoop,  0, "Eavesdrop ISO 14443 Type A"},
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
