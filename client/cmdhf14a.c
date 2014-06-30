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
#include "proxmark3.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhf14a.h"
#include "common.h"
#include "cmdmain.h"
#include "mifare.h"

static int CmdHelp(const char *Cmd);
static void waitCmd(uint8_t iLen);

int CmdHF14AList(const char *Cmd)
{
	bool ShowWaitCycles = false;
	char param = param_getchar(Cmd, 0);
	
	if (param == 'h' || (param != 0 && param != 'f')) {
		PrintAndLog("List data in trace buffer.");
		PrintAndLog("Usage:  hf 14a list [f]");
		PrintAndLog("f - show frame delay times as well");
		PrintAndLog("sample: hf 14a list f");
		return 0;
	}	

	if (param == 'f') {
		ShowWaitCycles = true;
	}
		
	uint8_t got[1920];
	GetFromBigBuf(got,sizeof(got),0);
	WaitForResponse(CMD_ACK,NULL);

	PrintAndLog("Recorded Activity");
	PrintAndLog("");
	PrintAndLog("Start = Start of Start Bit, End = End of last modulation. Src = Source of Transfer");
	PrintAndLog("All times are in carrier periods (1/13.56Mhz)");
	PrintAndLog("");
	PrintAndLog("     Start |       End | Src | Data");
	PrintAndLog("-----------|-----------|-----|--------");

	int i = 0;
	uint32_t first_timestamp = 0;
	uint32_t timestamp;
	uint32_t EndOfTransmissionTimestamp = 0;
	
	for (;;) {
		if(i >= 1900) {
			break;
		}

		bool isResponse;
		timestamp = *((uint32_t *)(got+i));
		if (timestamp & 0x80000000) {
		  timestamp &= 0x7fffffff;
		  isResponse = true;
		} else {
		  isResponse = false;
		}

		if(i==0) {
			first_timestamp = timestamp;
		}
		
		int parityBits = *((uint32_t *)(got+i+4));

		int len = got[i+8];

		if (len > 100) {
			break;
		}
		if (i + len >= 1900) {
			break;
		}

		uint8_t *frame = (got+i+9);

		// Break and stick with current result if buffer was not completely full
		if (frame[0] == 0x44 && frame[1] == 0x44 && frame[2] == 0x44 && frame[3] == 0x44) break; 

		char line[1000] = "";
		int j;
		if (len) {
			for (j = 0; j < len; j++) {
				int oddparity = 0x01;
				int k;

				for (k=0;k<8;k++) {
					oddparity ^= (((frame[j] & 0xFF) >> k) & 0x01);
				}

				//if((parityBits >> (len - j - 1)) & 0x01) {
				if (isResponse && (oddparity != ((parityBits >> (len - j - 1)) & 0x01))) {
					sprintf(line+(j*4), "%02x!  ", frame[j]);
				} else {
					sprintf(line+(j*4), "%02x   ", frame[j]);
				}
			}
		} else {
			if (ShowWaitCycles) {
				uint32_t next_timestamp = (*((uint32_t *)(got+i+9))) & 0x7fffffff;
				sprintf(line, "fdt (Frame Delay Time): %d", (next_timestamp - timestamp));
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

		i += (len + 9);

		EndOfTransmissionTimestamp = (*((uint32_t *)(got+i))) & 0x7fffffff;
		
		if (!ShowWaitCycles) i += 9;
		
		PrintAndLog(" %9d | %9d | %s | %s %s",
			(timestamp - first_timestamp),
			(EndOfTransmissionTimestamp - first_timestamp),
			(len?(isResponse ? "Tag" : "Rdr"):"   "),
			line, crc);

	}
	return 0;
}

void iso14a_set_timeout(uint32_t timeout) {
	UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_SET_TIMEOUT, 0, timeout}};
	SendCommand(&c);
}

int CmdHF14AReader(const char *Cmd)
{
	UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0}};
	SendCommand(&c);

	UsbCommand resp;
	WaitForResponse(CMD_ACK,&resp);
	
	iso14a_card_select_t card;
	memcpy(&card, (iso14a_card_select_t *)resp.d.asBytes, sizeof(iso14a_card_select_t));

	uint64_t select_status = resp.arg[0];
	
	if(select_status == 0) {
		PrintAndLog("iso14443a card select failed");
		return 0;
	}

	PrintAndLog("ATQA : %02x %02x", card.atqa[1], card.atqa[0]);
	PrintAndLog(" UID : %s", sprint_hex(card.uid, card.uidlen));
	PrintAndLog(" SAK : %02x [%d]", card.sak, resp.arg[0]);

	switch (card.sak) {
		case 0x00: PrintAndLog("TYPE : NXP MIFARE Ultralight | Ultralight C"); break;
		case 0x04: PrintAndLog("TYPE : NXP MIFARE (various !DESFire !DESFire EV1)"); break;
		case 0x08: PrintAndLog("TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1"); break;
		case 0x09: PrintAndLog("TYPE : NXP MIFARE Mini 0.3k"); break;
		case 0x10: PrintAndLog("TYPE : NXP MIFARE Plus 2k SL2"); break;
		case 0x11: PrintAndLog("TYPE : NXP MIFARE Plus 4k SL2"); break;
		case 0x18: PrintAndLog("TYPE : NXP MIFARE Classic 4k | Plus 4k SL1"); break;
		case 0x20: PrintAndLog("TYPE : NXP MIFARE DESFire 4k | DESFire EV1 2k/4k/8k | Plus 2k/4k SL3 | JCOP 31/41"); break;
		case 0x24: PrintAndLog("TYPE : NXP MIFARE DESFire | DESFire EV1"); break;
		case 0x28: PrintAndLog("TYPE : JCOP31 or JCOP41 v2.3.1"); break;
		case 0x38: PrintAndLog("TYPE : Nokia 6212 or 6131 MIFARE CLASSIC 4K"); break;
		case 0x88: PrintAndLog("TYPE : Infineon MIFARE CLASSIC 1K"); break;
		case 0x98: PrintAndLog("TYPE : Gemplus MPCOS"); break;
		default: ;
	}

	
	// try to request ATS even if tag claims not to support it
	if (select_status == 2) {
		uint8_t rats[] = { 0xE0, 0x80 }; // FSDI=8 (FSD=256), CID=0
		c.arg[0] = ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_DISCONNECT;
		c.arg[1] = 2;
		c.arg[2] = 0;
		memcpy(c.d.asBytes, rats, 2);
		SendCommand(&c);
		WaitForResponse(CMD_ACK,&resp);
		
	    memcpy(&card.ats, resp.d.asBytes, resp.arg[0]);
		card.ats_len = resp.arg[0];
	} 

	// disconnect
	c.arg[0] = 0;
	c.arg[1] = 0;
	c.arg[2] = 0;
	SendCommand(&c);

	
	if(card.ats_len >= 3) {			// a valid ATS consists of at least the length byte TL and 2 CRC bytes
		bool ta1 = 0, tb1 = 0, tc1 = 0;
		int pos;

		if (!(card.sak & 0x02)) {
			PrintAndLog("SAK incorrectly claims that card doesn't support RATS");
		}
		PrintAndLog(" ATS : %s", sprint_hex(card.ats, card.ats_len));
		if (card.ats_len > 0) {
			PrintAndLog("       -  TL : length is %d bytes", card.ats[0]);
		}
		if (card.ats_len > 1) {
			ta1 = (card.ats[1] & 0x10) == 0x10;
			tb1 = (card.ats[1] & 0x20) == 0x20;
			tc1 = (card.ats[1] & 0x40) == 0x40;
			PrintAndLog("       -  T0 : TA1 is%s present, TB1 is%s present, "
					"TC1 is%s present, FSCI is %d",
				(ta1 ? "" : " NOT"), (tb1 ? "" : " NOT"), (tc1 ? "" : " NOT"),
				(card.ats[1] & 0x0f));
		}
		pos = 2;
		if (ta1 && card.ats_len > pos) {
			char dr[16], ds[16];
			dr[0] = ds[0] = '\0';
			if (card.ats[pos] & 0x10) strcat(ds, "2, ");
			if (card.ats[pos] & 0x20) strcat(ds, "4, ");
			if (card.ats[pos] & 0x40) strcat(ds, "8, ");
			if (card.ats[pos] & 0x01) strcat(dr, "2, ");
			if (card.ats[pos] & 0x02) strcat(dr, "4, ");
			if (card.ats[pos] & 0x04) strcat(dr, "8, ");
			if (strlen(ds) != 0) ds[strlen(ds) - 2] = '\0';
			if (strlen(dr) != 0) dr[strlen(dr) - 2] = '\0';
			PrintAndLog("       - TA1 : different divisors are%s supported, "
					"DR: [%s], DS: [%s]",
					(card.ats[pos] & 0x80 ? " NOT" : ""), dr, ds);
			pos++;
		}
		if (tb1 && card.ats_len > pos) {
			PrintAndLog("       - TB1 : SFGI = %d, FWI = %d",
					(card.ats[pos] & 0x08),
					(card.ats[pos] & 0x80) >> 4);
			pos++;
		}
		if (tc1 && card.ats_len > pos) {
			PrintAndLog("       - TC1 : NAD is%s supported, CID is%s supported",
					(card.ats[pos] & 0x01) ? "" : " NOT",
					(card.ats[pos] & 0x02) ? "" : " NOT");
			pos++;
		}
		if (card.ats_len > pos) {
			char *tip = "";
			if (card.ats_len - pos > 7) {
				if (memcmp(card.ats + pos, "\xC1\x05\x2F\x2F\x01\xBC\xD6", 7) == 0) {
					tip = "-> MIFARE Plus X 2K or 4K";
				} else if (memcmp(card.ats + pos, "\xC1\x05\x2F\x2F\x00\x35\xC7", 7) == 0) {
					tip = "-> MIFARE Plus S 2K or 4K";
				}
			} 
			PrintAndLog("       -  HB : %s%s", sprint_hex(card.ats + pos, card.ats_len - pos - 2), tip);
			if (card.ats[pos] == 0xC1) {
				PrintAndLog("               c1 -> Mifare or (multiple) virtual cards of various type");
				PrintAndLog("                  %02x -> Length is %d bytes",
						card.ats[pos + 1], card.ats[pos + 1]);
				switch (card.ats[pos + 2] & 0xf0) {
					case 0x10:
						PrintAndLog("                     1x -> MIFARE DESFire");
						break;
					case 0x20:
						PrintAndLog("                     2x -> MIFARE Plus");
						break;
				}
				switch (card.ats[pos + 2] & 0x0f) {
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
				switch (card.ats[pos + 3] & 0xf0) {
					case 0x00:
						PrintAndLog("                        0x -> Engineering sample");
						break;
					case 0x20:
						PrintAndLog("                        2x -> Released");
						break;
				}
				switch (card.ats[pos + 3] & 0x0f) {
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
				switch (card.ats[pos + 4] & 0x0f) {
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
	} else {
		PrintAndLog("proprietary non iso14443-4 card found, RATS not supported");
	}

	return select_status;
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
    
		UsbCommand resp;
		WaitForResponse(CMD_ACK,&resp);

		iso14a_card_select_t *card = (iso14a_card_select_t *) resp.d.asBytes;

		// check if command failed
		if (resp.arg[0] == 0) {
			PrintAndLog("Card select failed.");
		} else {
			char uid_string[20];
			for (uint16_t i = 0; i < card->uidlen; i++) {
				sprintf(&uid_string[2*i], "%02X", card->uid[i]);
			}
			PrintAndLog("%s", uid_string);
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
		PrintAndLog("Emulating ISO/IEC 14443 type A tag with 7 byte UID (%014"llx")",long_uid);
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

int CmdHF14ACmdRaw(const char *cmd) {
    UsbCommand c = {CMD_READER_ISO_14443a, {0, 0, 0}};
    uint8_t reply=1;
    uint8_t crc=0;
    uint8_t power=0;
    uint8_t active=0;
    uint8_t active_select=0;
    uint16_t numbits=0;
    char buf[5]="";
    int i=0;
    uint8_t data[100];
    unsigned int datalen=0, temp;

    if (strlen(cmd)<2) {
        PrintAndLog("Usage: hf 14a raw [-r] [-c] [-p] [-f] [-b] <number of bits> <0A 0B 0C ... hex>");
        PrintAndLog("       -r    do not read response");
        PrintAndLog("       -c    calculate and append CRC");
        PrintAndLog("       -p    leave the signal field ON after receive");
        PrintAndLog("       -a    active signal field ON without select");
        PrintAndLog("       -s    active signal field ON with select");
        PrintAndLog("       -b    number of bits to send. Useful for send partial byte");
        return 0;
    }

    // strip
    while (*cmd==' ' || *cmd=='\t') cmd++;

    while (cmd[i]!='\0') {
        if (cmd[i]==' ' || cmd[i]=='\t') { i++; continue; }
        if (cmd[i]=='-') {
            switch (cmd[i+1]) {
                case 'r': 
                    reply=0;
                    break;
                case 'c':
                    crc=1;
                    break;
                case 'p':
                    power=1;
                    break;
                case 'a':
                    active=1;
                    break;
                case 's':
                    active_select=1;
                    break;
                case 'b': 
                    sscanf(cmd+i+2,"%d",&temp);
                    numbits = temp & 0xFFFF;
                    i+=3;
                    while(cmd[i]!=' ' && cmd[i]!='\0') { i++; }
                    i-=2;
                    break;
                default:
                    PrintAndLog("Invalid option");
                    return 0;
            }
            i+=2;
            continue;
        }
        if ((cmd[i]>='0' && cmd[i]<='9') ||
            (cmd[i]>='a' && cmd[i]<='f') ||
            (cmd[i]>='A' && cmd[i]<='F') ) {
            buf[strlen(buf)+1]=0;
            buf[strlen(buf)]=cmd[i];
            i++;

            if (strlen(buf)>=2) {
                sscanf(buf,"%x",&temp);
                data[datalen]=(uint8_t)(temp & 0xff);
                datalen++;
                *buf=0;
            }
            continue;
        }
        PrintAndLog("Invalid char on input");
        return 0;
    }
    if(crc && datalen>0)
    {
        uint8_t first, second;
        ComputeCrc14443(CRC_14443_A, data, datalen, &first, &second);
        data[datalen++] = first;
        data[datalen++] = second;
    }

    if(active || active_select)
    {
        c.arg[0] |= ISO14A_CONNECT;
        if(active)
            c.arg[0] |= ISO14A_NO_SELECT;
    }
    if(power)
        c.arg[0] |= ISO14A_NO_DISCONNECT;
    if(datalen>0)
        c.arg[0] |= ISO14A_RAW;

    c.arg[1] = datalen;
    c.arg[2] = numbits;
    memcpy(c.d.asBytes,data,datalen);

    SendCommand(&c);

    if (reply) {
        if(active_select)
            waitCmd(1);
        if(datalen>0)
            waitCmd(0);
    } // if reply
    return 0;
}

static void waitCmd(uint8_t iSelect)
{
    uint8_t *recv;
    UsbCommand resp;
    char *hexout;

    if (WaitForResponseTimeout(CMD_ACK,&resp,1000)) {
        recv = resp.d.asBytes;
        uint8_t iLen = iSelect ? resp.arg[1] : resp.arg[0];
        PrintAndLog("received %i octets",iLen);
        if(!iLen)
            return;
        hexout = (char *)malloc(iLen * 3 + 1);
        if (hexout != NULL) {
            for (int i = 0; i < iLen; i++) { // data in hex
                sprintf(&hexout[i * 3], "%02X ", recv[i]);
            }
            PrintAndLog("%s", hexout);
            free(hexout);
        } else {
            PrintAndLog("malloc failed your client has low memory?");
        }
    } else {
        PrintAndLog("timeout while waiting for reply.");
    }
}

static command_t CommandTable[] = 
{
  {"help",   CmdHelp,              1, "This help"},
  {"list",   CmdHF14AList,         0, "List ISO 14443a history"},
  {"reader", CmdHF14AReader,       0, "Act like an ISO14443 Type A reader"},
  {"cuids",  CmdHF14ACUIDs,        0, "<n> Collect n>0 ISO14443 Type A UIDs in one go"},
  {"sim",    CmdHF14ASim,          0, "<UID> -- Fake ISO 14443a tag"},
  {"snoop",  CmdHF14ASnoop,        0, "Eavesdrop ISO 14443 Type A"},
  {"raw",    CmdHF14ACmdRaw,       0, "Send raw hex data to tag"},
  {NULL, NULL, 0, NULL}
};

int CmdHF14A(const char *Cmd) {
	// flush
	WaitForResponseTimeout(CMD_ACK,NULL,100);

	// parse
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
