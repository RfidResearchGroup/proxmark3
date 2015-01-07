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


// structure and database for uid -> tagtype lookups 
typedef struct { 
	uint8_t uid;
	char* desc;
} manufactureName; 

const manufactureName manufactureMapping[] = {
	// ID,  "Vendor Country"
	{ 0x01, "Motorola UK" },
	{ 0x02, "ST Microelectronics SA France" },
	{ 0x03, "Hitachi, Ltd Japan" }, 
	{ 0x04, "NXP Semiconductors Germany" }, 
	{ 0x05, "Infineon Technologies AG Germany" }, 
	{ 0x06, "Cylink USA" }, 
	{ 0x07, "Texas Instrument France" },
	{ 0x08, "Fujitsu Limited Japan" }, 
	{ 0x09, "Matsushita Electronics Corporation, Semiconductor Company Japan" }, 
	{ 0x0A, "NEC Japan" }, 
	{ 0x0B, "Oki Electric Industry Co. Ltd Japan" },
	{ 0x0C, "Toshiba Corp. Japan" },
	{ 0x0D, "Mitsubishi Electric Corp. Japan" },
	{ 0x0E, "Samsung Electronics Co. Ltd Korea" },
	{ 0x0F, "Hynix / Hyundai, Korea" },
	{ 0x10, "LG-Semiconductors Co. Ltd Korea" },
	{ 0x11, "Emosyn-EM Microelectronics USA" },
	{ 0x12, "INSIDE Technology France" },
	{ 0x13, "ORGA Kartensysteme GmbH Germany" },
	{ 0x14, "SHARP Corporation Japan" },
	{ 0x15, "ATMEL France" },
	{ 0x16, "EM Microelectronic-Marin SA Switzerland" },
	{ 0x17, "KSW Microtec GmbH Germany" },
	{ 0x18, "ZMD AG Germany" },
	{ 0x19, "XICOR, Inc. USA" },
	{ 0x1A, "Sony Corporation Japan Identifier Company Country" },
	{ 0x1B, "Malaysia Microelectronic Solutions Sdn. Bhd Malaysia" },
	{ 0x1C, "Emosyn USA" },
	{ 0x1D, "Shanghai Fudan Microelectronics Co. Ltd. P.R. China" },
	{ 0x1E, "Magellan Technology Pty Limited Australia" },
	{ 0x1F, "Melexis NV BO Switzerland" },
	{ 0x20, "Renesas Technology Corp. Japan" },
	{ 0x21, "TAGSYS France" },
	{ 0x22, "Transcore USA" },
	{ 0x23, "Shanghai belling corp., ltd. China" },
	{ 0x24, "Masktech Germany Gmbh Germany" },
	{ 0x25, "Innovision Research and Technology Plc UK" },
	{ 0x26, "Hitachi ULSI Systems Co., Ltd. Japan" },
	{ 0x27, "Cypak AB Sweden" },
	{ 0x28, "Ricoh Japan" },
	{ 0x29, "ASK France" },
	{ 0x2A, "Unicore Microsystems, LLC Russian Federation" },
	{ 0x2B, "Dallas Semiconductor/Maxim USA" },
	{ 0x2C, "Impinj, Inc. USA" },
	{ 0x2D, "RightPlug Alliance USA" },
	{ 0x2E, "Broadcom Corporation USA" },
	{ 0x2F, "MStar Semiconductor, Inc Taiwan, ROC" },
	{ 0x30, "BeeDar Technology Inc. USA" },
	{ 0x31, "RFIDsec Denmark" },
	{ 0x32, "Schweizer Electronic AG Germany" },
	{ 0x33, "AMIC Technology Corp Taiwan" }, 
	{ 0x34, "Mikron JSC Russia" },
	{ 0x35, "Fraunhofer Institute for Photonic Microsystems Germany" },
	{ 0x36, "IDS Microchip AG Switzerland" },
	{ 0x37, "Kovio USA" },
	{ 0x38, "HMT Microelectronic Ltd Switzerland Identifier Company Country" },
	{ 0x39, "Silicon Craft Technology Thailand" },
	{ 0x3A, "Advanced Film Device Inc. Japan" },
	{ 0x3B, "Nitecrest Ltd UK" },
	{ 0x3C, "Verayo Inc. USA" },
	{ 0x3D, "HID Global USA" },
	{ 0x3E, "Productivity Engineering Gmbh Germany" },
	{ 0x3F, "Austriamicrosystems AG (reserved) Austria" }, 
	{ 0x40, "Gemalto SA France" },
	{ 0x41, "Renesas Electronics Corporation Japan" },
	{ 0x42, "3Alogics Inc Korea" },
	{ 0x43, "Top TroniQ Asia Limited Hong Kong" },
	{ 0x44, "Gentag Inc (USA) USA" },
	{ 0x00, "no tag-info available" } // must be the last entry
};


// get a product description based on the UID
//		uid[8] 	tag uid
// returns description of the best match	
char* getTagInfo(uint8_t uid) {

	int i, best = -1;	
	int len = sizeof(manufactureMapping) / sizeof(manufactureName);
	
	for ( i = 0; i < len; ++i ) {
		if ( uid == manufactureMapping[i].uid) {
			if (best == -1) { 
				best = i;
			} 
		} 
	} 

	if (best>=0) return manufactureMapping[best].desc;
	
	return manufactureMapping[i].desc; 
}

int CmdHF14AList(const char *Cmd)
{
	PrintAndLog("Deprecated command, use 'hf list 14a' instead");
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

	uint64_t select_status = resp.arg[0];		// 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS
	
	if(select_status == 0) {
		PrintAndLog("iso14443a card select failed");
		// disconnect
		c.arg[0] = 0;
		c.arg[1] = 0;
		c.arg[2] = 0;
		SendCommand(&c);
		return 0;
	}

	PrintAndLog("ATQA : %02x %02x", card.atqa[1], card.atqa[0]);
	PrintAndLog(" UID : %s", sprint_hex(card.uid, card.uidlen));
	PrintAndLog(" SAK : %02x [%d]", card.sak, resp.arg[0]);

	// Double & triple sized UID, can be mapped to a manufacturer.
	// HACK: does this apply for Ultralight cards?
	if ( card.uidlen > 4 ) {
		PrintAndLog("MANUFACTURER : %s", getTagInfo(card.uid[0]));
	}

	switch (card.sak) {
		case 0x00: PrintAndLog("TYPE : NXP MIFARE Ultralight | Ultralight C"); break;
		case 0x01: PrintAndLog("TYPE : NXP TNP3xxx Activision Game Appliance"); break;
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
		card.ats_len = resp.arg[0];				// note: ats_len includes CRC Bytes
	} 

	if(card.ats_len >= 3) {			// a valid ATS consists of at least the length byte (TL) and 2 CRC bytes
		bool ta1 = 0, tb1 = 0, tc1 = 0;
		int pos;

		if (select_status == 2) {
			PrintAndLog("SAK incorrectly claims that card doesn't support RATS");
		}
		PrintAndLog(" ATS : %s", sprint_hex(card.ats, card.ats_len));
		PrintAndLog("       -  TL : length is %d bytes", card.ats[0]);
		if (card.ats[0] != card.ats_len - 2) {
			PrintAndLog("ATS may be corrupted. Length of ATS (%d bytes incl. 2 Bytes CRC) doesn't match TL", card.ats_len);
		}
		
		if (card.ats[0] > 1) {		// there is a format byte (T0)
			ta1 = (card.ats[1] & 0x10) == 0x10;
			tb1 = (card.ats[1] & 0x20) == 0x20;
			tc1 = (card.ats[1] & 0x40) == 0x40;
			int16_t fsci = card.ats[1] & 0x0f;
			PrintAndLog("       -  T0 : TA1 is%s present, TB1 is%s present, "
					"TC1 is%s present, FSCI is %d (FSC = %ld)",
				(ta1 ? "" : " NOT"), (tb1 ? "" : " NOT"), (tc1 ? "" : " NOT"),
				fsci,
				fsci < 5 ? (fsci - 2) * 8 : 
					fsci < 8 ? (fsci - 3) * 32 :
					fsci == 8 ? 256 :
					-1
				);
		}
		pos = 2;
		if (ta1) {
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
		if (tb1) {
			uint32_t sfgi = card.ats[pos] & 0x0F;
			uint32_t fwi = card.ats[pos] >> 4;
			PrintAndLog("       - TB1 : SFGI = %d (SFGT = %s%ld/fc), FWI = %d (FWT = %ld/fc)",
					(sfgi),
					sfgi ? "" : "(not needed) ",
					sfgi ? (1 << 12) << sfgi : 0,
					fwi,
					(1 << 12) << fwi
					);
			pos++;
		}
		if (tc1) {
			PrintAndLog("       - TC1 : NAD is%s supported, CID is%s supported",
					(card.ats[pos] & 0x01) ? "" : " NOT",
					(card.ats[pos] & 0x02) ? "" : " NOT");
			pos++;
		}
		if (card.ats[0] > pos) {
			char *tip = "";
			if (card.ats[0] - pos >= 7) {
				if (memcmp(card.ats + pos, "\xC1\x05\x2F\x2F\x01\xBC\xD6", 7) == 0) {
					tip = "-> MIFARE Plus X 2K or 4K";
				} else if (memcmp(card.ats + pos, "\xC1\x05\x2F\x2F\x00\x35\xC7", 7) == 0) {
					tip = "-> MIFARE Plus S 2K or 4K";
				}
			} 
			PrintAndLog("       -  HB : %s%s", sprint_hex(card.ats + pos, card.ats[0] - pos), tip);
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

	
	// try to see if card responses to "chinese magic backdoor" commands.
	c.cmd = CMD_MIFARE_CIDENT;
	c.arg[0] = 0;
	c.arg[1] = 0;
	c.arg[2] = 0;	
	SendCommand(&c);
	WaitForResponse(CMD_ACK,&resp);
	uint8_t isOK  = resp.arg[0] & 0xff;
	PrintAndLog(" Answers to chinese magic backdoor commands: %s", (isOK ? "YES" : "NO") );
	
	// disconnect
	c.cmd = CMD_READER_ISO_14443a;
	c.arg[0] = 0;
	c.arg[1] = 0;
	c.arg[2] = 0;
	SendCommand(&c);

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
		PrintAndLog("           5 = MIFARE TNP3XXX");		
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
		PrintAndLog("Buffer accessible from command hf list 14a.");
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

    if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
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
  {"list",   CmdHF14AList,         0, "[Deprecated] List ISO 14443a history"},
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
