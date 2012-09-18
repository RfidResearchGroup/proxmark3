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
#include "util.h"
#include "iso14443crc.h"
#include "data.h"
#include "proxusb.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhf14a.h"
#include "common.h"
#include "cmdmain.h"

static int CmdHelp(const char *Cmd);

int CmdHF14AList(const char *Cmd)
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

int CmdHF14AReader(const char *Cmd)
{
	UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_CONNECT, 0, 0}};
	SendCommand(&c);
	UsbCommand * resp = WaitForResponse(CMD_ACK);
	uint8_t              * uid  = resp->d.asBytes;
	iso14a_card_select_t * card = (iso14a_card_select_t *)(uid + 12);

	if(resp->arg[0] == 0) {
		PrintAndLog("iso14443a card select failed");
		return 0;
	}

	PrintAndLog("ATQA : %02x %02x", card->atqa[0], card->atqa[1]);
	PrintAndLog(" UID : %s", sprint_hex(uid, 12));
	PrintAndLog(" SAK : %02x [%d]", card->sak, resp->arg[0]);

	switch (card->sak) {
		case 0x00: PrintAndLog(" SAK : NXP MIFARE Ultralight | Ultralight C"); break;
		case 0x04: PrintAndLog(" SAK : NXP MIFARE (various !DESFire !DESFire EV1)"); break;

		case 0x08: PrintAndLog(" SAK : NXP MIFARE CLASSIC 1k | Plus 2k"); break;
		case 0x09: PrintAndLog(" SAK : NXP MIFARE Mini 0.3k"); break;
		case 0x10: PrintAndLog(" SAK : NXP MIFARE Plus 2k"); break;
		case 0x11: PrintAndLog(" SAK : NXP MIFARE Plus 4k"); break;
		case 0x18: PrintAndLog(" SAK : NXP MIFARE Classic 4k | Plus 4k"); break;
		case 0x20: PrintAndLog(" SAK : NXP MIFARE DESFire 4k | DESFire EV1 2k/4k/8k | Plus 2k/4k | JCOP 31/41"); break;
		case 0x24: PrintAndLog(" SAK : NXP MIFARE DESFire | DESFire EV1"); break;
		case 0x28: PrintAndLog(" SAK : JCOP31 or JCOP41 v2.3.1"); break;
		case 0x38: PrintAndLog(" SAK : Nokia 6212 or 6131 MIFARE CLASSIC 4K"); break;
		case 0x88: PrintAndLog(" SAK : Infineon MIFARE CLASSIC 1K"); break;
		case 0x98: PrintAndLog(" SAK : Gemplus MPCOS"); break;
		default: ;
	}
	if(resp->arg[0] == 1) {
		bool ta1 = 0, tb1 = 0, tc1 = 0;
		int pos;

		PrintAndLog(" ATS : %s", sprint_hex(card->ats, card->ats_len));
		if (card->ats_len > 0) {
			PrintAndLog("       -  TL : length is %d bytes", card->ats[0]);
		}
		if (card->ats_len > 1) {
			ta1 = (card->ats[1] & 0x10) == 0x10;
			tb1 = (card->ats[1] & 0x20) == 0x20;
			tc1 = (card->ats[1] & 0x40) == 0x40;
			PrintAndLog("       -  T0 : TA1 is%s present, TB1 is%s present, "
					"TC1 is%s present, FSCI is %d",
				(ta1 ? "" : " NOT"), (tb1 ? "" : " NOT"), (tc1 ? "" : " NOT"),
				(card->ats[1] & 0x0f));
		}
		pos = 2;
		if (ta1 && card->ats_len > pos) {
			char dr[16], ds[16];
			dr[0] = ds[0] = '\0';
			if (card->ats[pos] & 0x10) strcat(ds, "2, ");
			if (card->ats[pos] & 0x20) strcat(ds, "4, ");
			if (card->ats[pos] & 0x40) strcat(ds, "8, ");
			if (card->ats[pos] & 0x01) strcat(dr, "2, ");
			if (card->ats[pos] & 0x02) strcat(dr, "4, ");
			if (card->ats[pos] & 0x04) strcat(dr, "8, ");
			if (strlen(ds) != 0) ds[strlen(ds) - 2] = '\0';
			if (strlen(dr) != 0) dr[strlen(dr) - 2] = '\0';
			PrintAndLog("       - TA1 : different divisors are%s supported, "
					"DR: [%s], DS: [%s]",
					(card->ats[pos] & 0x80 ? " NOT" : ""), dr, ds);
			pos++;
		}
		if (tb1 && card->ats_len > pos) {
			PrintAndLog("       - TB1 : SFGI = %d, FWI = %d",
					(card->ats[pos] & 0x08),
					(card->ats[pos] & 0x80) >> 4);
			pos++;
		}
		if (tc1 && card->ats_len > pos) {
			PrintAndLog("       - TC1 : NAD is%s supported, CID is%s supported",
					(card->ats[pos] & 0x01) ? "" : " NOT",
					(card->ats[pos] & 0x02) ? "" : " NOT");
			pos++;
		}
		if (card->ats_len > pos) {
			char *tip = "";
			if (card->ats_len - pos > 7) {
				if (memcmp(card->ats + pos, "\xC1\x05\x2F\x2F\x01\xBC\xD6", 7) == 0) {
					tip = "-> MIFARE Plus X 2K or 4K";
				} else if (memcmp(card->ats + pos, "\xC1\x05\x2F\x2F\x00\x35\xC7", 7) == 0) {
					tip = "-> MIFARE Plus S 2K or 4K";
				}
			} 
			PrintAndLog("       -  HB : %s%s", sprint_hex(card->ats + pos, card->ats_len - pos - 2), tip);
			if (card->ats[pos] == 0xC1) {
				PrintAndLog("               c1 -> Mifare or (multiple) virtual cards of various type");
				PrintAndLog("                  %02x -> Length is %d bytes",
						card->ats[pos + 1], card->ats[pos + 1]);
				switch (card->ats[pos + 2] & 0xf0) {
					case 0x10:
						PrintAndLog("                     1x -> MIFARE DESFire");
						break;
					case 0x20:
						PrintAndLog("                     2x -> MIFARE Plus");
						break;
				}
				switch (card->ats[pos + 2] & 0x0f) {
					case 0x00:
						PrintAndLog("                     x0 -> <1 kByte");
						break;
					case 0x01:
						PrintAndLog("                     x0 -> 1 kByte");
						break;
					case 0x02:
						PrintAndLog("                     x0 -> 2 kByte");
						break;
					case 0x03:
						PrintAndLog("                     x0 -> 4 kByte");
						break;
					case 0x04:
						PrintAndLog("                     x0 -> 8 kByte");
						break;
				}
				switch (card->ats[pos + 3] & 0xf0) {
					case 0x00:
						PrintAndLog("                        0x -> Engineering sample");
						break;
					case 0x20:
						PrintAndLog("                        2x -> Released");
						break;
				}
				switch (card->ats[pos + 3] & 0x0f) {
					case 0x00:
						PrintAndLog("                        x0 -> Generation 1");
						break;
					case 0x01:
						PrintAndLog("                        x1 -> Generation 2");
						break;
					case 0x02:
						PrintAndLog("                        x2 -> Generation 3");
						break;
				}
				switch (card->ats[pos + 4] & 0x0f) {
					case 0x00:
						PrintAndLog("                           x0 -> Only VCSL supported");
						break;
					case 0x01:
						PrintAndLog("                           x1 -> VCS, VCSL, and SVC supported");
						break;
					case 0x0E:
						PrintAndLog("                           xE -> no VCS command supported");
						break;
				}
			}
		}
	}
	else
		PrintAndLog("proprietary non-iso14443a card found, RATS not supported");

	return resp->arg[0];
}

// Collect ISO14443 Type A UIDs
int CmdHF14ACUIDs(const char *Cmd)
{
	// requested number of UIDs
	int n = atoi(Cmd);
	// collect at least 1 (e.g. if no parameter was given)
	n = n > 0 ? n : 1;

	PrintAndLog("Collecting %d UIDs", n);
	PrintAndLog("Start: %u", time(NULL));
	// repeat n times
	for (int i = 0; i < n; i++) {
		// execute anticollision procedure
		UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_CONNECT, 0, 0}};
		SendCommand(&c);
		UsbCommand *resp = WaitForResponse(CMD_ACK);
		uint8_t *uid  = resp->d.asBytes;
		iso14a_card_select_t *card = (iso14a_card_select_t *)(uid + 12);

		// check if command failed
		if (resp->arg[0] == 0) {
			PrintAndLog("Card select failed.");
		} else {
			// check if UID is 4 bytes
			if ((card->atqa[1] & 0xC0) == 0) {
				PrintAndLog("%02X%02X%02X%02X",
				            *uid, *(uid + 1), *(uid + 2), *(uid + 3));
			} else {
				PrintAndLog("UID longer than 4 bytes");
			}
		}
	}
	PrintAndLog("End: %u", time(NULL));

	return 1;
}

// ## simulate iso14443a tag
// ## greg - added ability to specify tag UID
int CmdHF14ASim(const char *Cmd)
{
	UsbCommand c = {CMD_SIMULATE_TAG_ISO_14443a,{0,0,0}};
	
	// Retrieve the tag type
	uint8_t tagtype = param_get8ex(Cmd,0,0,10);
	
	// When no argument was given, just print help message
	if (tagtype == 0) {
		PrintAndLog("");
		PrintAndLog(" Emulating ISO/IEC 14443 type A tag with 4 or 7 byte UID");
		PrintAndLog("");
		PrintAndLog("   syntax: hf 14a sim <type> <uid>");
		PrintAndLog("    types: 1 = MIFARE Classic");
		PrintAndLog("           2 = MIFARE Ultralight");
		PrintAndLog("           3 = MIFARE DESFIRE");
		PrintAndLog("           4 = ISO/IEC 14443-4");
		PrintAndLog("");
		return 1;
	}
	
	// Store the tag type
	c.arg[0] = tagtype;
	
	// Retrieve the full 4 or 7 byte long uid 
	uint64_t long_uid = param_get64ex(Cmd,1,0,16);

	// Are we handling the (optional) second part uid?
	if (long_uid > 0xffffffff) {
		PrintAndLog("Emulating ISO/IEC 14443 type A tag with 7 byte UID (%014llx)",long_uid);
		// Store the second part
		c.arg[2] = (long_uid & 0xffffffff);
		long_uid >>= 32;
		// Store the first part, ignore the first byte, it is replaced by cascade byte (0x88)
		c.arg[1] = (long_uid & 0xffffff);
	} else {
		PrintAndLog("Emulating ISO/IEC 14443 type A tag with 4 byte UID (%08x)",long_uid);
		// Only store the first part
		c.arg[1] = long_uid & 0xffffffff;
	}
/*
		// At lease save the mandatory first part of the UID
		c.arg[0] = long_uid & 0xffffffff;

	
	// At lease save the mandatory first part of the UID
	c.arg[0] = long_uid & 0xffffffff;
	
	if (c.arg[1] == 0) {
		PrintAndLog("Emulating ISO/IEC 14443 type A tag with UID %01d %08x %08x",c.arg[0],c.arg[1],c.arg[2]);
	}
	
	switch (c.arg[0]) {
		case 1: {
			PrintAndLog("Emulating ISO/IEC 14443-3 type A tag with 4 byte UID");
			UsbCommand c = {CMD_SIMULATE_TAG_ISO_14443a,param_get32ex(Cmd,0,0,10),param_get32ex(Cmd,1,0,16),param_get32ex(Cmd,2,0,16)};
		} break;
		case 2: {
			PrintAndLog("Emulating ISO/IEC 14443-4 type A tag with 7 byte UID");
		} break;
		default: {
			PrintAndLog("Error: unkown tag type (%d)",c.arg[0]);
			PrintAndLog("syntax: hf 14a sim <uid>",c.arg[0]);
			PrintAndLog(" type1: 4 ",c.arg[0]);

			return 1;
		} break;
	}	
*/
/*
  unsigned int hi = 0, lo = 0;
  int n = 0, i = 0;
  while (sscanf(&Cmd[i++], "%1x", &n ) == 1) {
    hi= (hi << 4) | (lo >> 28);
    lo= (lo << 4) | (n & 0xf);
  }
*/
//	UsbCommand c = {CMD_SIMULATE_TAG_ISO_14443a,param_get32ex(Cmd,0,0,10),param_get32ex(Cmd,1,0,16),param_get32ex(Cmd,2,0,16)};
//  PrintAndLog("Emulating ISO/IEC 14443 type A tag with UID %01d %08x %08x",c.arg[0],c.arg[1],c.arg[2]);
  SendCommand(&c);
  return 0;
}

int CmdHF14ASnoop(const char *Cmd) {
	int param = 0;
	
	if (param_getchar(Cmd, 0) == 'h') {
		PrintAndLog("It get data from the field and saves it into command buffer.");
		PrintAndLog("Buffer accessible from command hf 14a list.");
		PrintAndLog("Usage:  hf 14a snoop [c][r]");
		PrintAndLog("c - triggered by first data from card");
		PrintAndLog("r - triggered by first 7-bit request from reader (REQ,WUP,...)");
		PrintAndLog("sample: hf 14a snoop c r");
		return 0;
	}	
	
	for (int i = 0; i < 2; i++) {
		char ctmp = param_getchar(Cmd, i);
		if (ctmp == 'c' || ctmp == 'C') param |= 0x01;
		if (ctmp == 'r' || ctmp == 'R') param |= 0x02;
	}

  UsbCommand c = {CMD_SNOOP_ISO_14443a, {param, 0, 0}};
  SendCommand(&c);
  return 0;
}

static command_t CommandTable[] = 
{
  {"help",   CmdHelp,              1, "This help"},
  {"list",   CmdHF14AList,         0, "List ISO 14443a history"},
  {"reader", CmdHF14AReader,       0, "Act like an ISO14443 Type A reader"},
  {"cuids",  CmdHF14ACUIDs,        0, "<n> Collect n>0 ISO14443 Type A UIDs in one go"},
  {"sim",    CmdHF14ASim,          0, "<UID> -- Fake ISO 14443a tag"},
  {"snoop",  CmdHF14ASnoop,        0, "Eavesdrop ISO 14443 Type A"},
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
