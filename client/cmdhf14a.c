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
#include "cmdhfmf.h"
#include "cmdhfmfu.h"
#include "nonce2key/nonce2key.h"
#include "cmdhf.h"

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

	int i;
	int len = sizeof(manufactureMapping) / sizeof(manufactureName);
	
	for ( i = 0; i < len; ++i ) 
		if ( uid == manufactureMapping[i].uid) 
			return manufactureMapping[i].desc;

	//No match, return default
	return manufactureMapping[len-1].desc; 
}

int usage_hf_14a_sim(void) {
//	PrintAndLog("\n Emulating ISO/IEC 14443 type A tag with 4,7 or 10 byte UID\n");
	PrintAndLog("\n Emulating ISO/IEC 14443 type A tag with 4,7 byte UID\n");
	PrintAndLog("Usage: hf 14a sim t <type> u <uid> x");
	PrintAndLog("  Options : ");
	PrintAndLog("    h     : this help");
	PrintAndLog("    t     : 1 = MIFARE Classic");
	PrintAndLog("            2 = MIFARE Ultralight");
	PrintAndLog("            3 = MIFARE Desfire");
	PrintAndLog("            4 = ISO/IEC 14443-4");
	PrintAndLog("            5 = MIFARE Tnp3xxx");
	PrintAndLog("            6 = MIFARE Mini");
	PrintAndLog("            7 = AMIIBO (NTAG 215),  pack 0x8080");
//	PrintAndLog("    u     : 4, 7 or 10 byte UID");
	PrintAndLog("    u     : 4, 7 byte UID");
	PrintAndLog("    x     : (Optional) performs the 'reader attack', nr/ar attack against a legitimate reader");
	PrintAndLog("\n   sample : hf 14a sim t 1 u 11223344 x");
	PrintAndLog("          : hf 14a sim t 1 u 11223344");
	PrintAndLog("          : hf 14a sim t 1 u 11223344556677");
//	PrintAndLog("          : hf 14a sim t 1 u 11223445566778899AA\n");
	return 0;
}
int usage_hf_14a_sniff(void){
	PrintAndLog("It get data from the field and saves it into command buffer.");
	PrintAndLog("Buffer accessible from command 'hf list 14a'");
	PrintAndLog("Usage:  hf 14a sniff [c][r]");
	PrintAndLog("c - triggered by first data from card");
	PrintAndLog("r - triggered by first 7-bit request from reader (REQ,WUP,...)");
	PrintAndLog("sample: hf 14a sniff c r");
	return 0;
}
int usage_hf_14a_raw(void){
	PrintAndLog("Usage: hf 14a raw [-h] [-r] [-c] [-p] [-a] [-T] [-t] <milliseconds> [-b] <number of bits>  <0A 0B 0C ... hex>");
	PrintAndLog("       -h    this help");
	PrintAndLog("       -r    do not read response");
	PrintAndLog("       -c    calculate and append CRC");
	PrintAndLog("       -p    leave the signal field ON after receive");
	PrintAndLog("       -a    active signal field ON without select");
	PrintAndLog("       -s    active signal field ON with select");
	PrintAndLog("       -b    number of bits to send. Useful for send partial byte");
	PrintAndLog("       -t    timeout in ms");
	PrintAndLog("       -T    use Topaz protocol to send command");
	return 0;
}

int CmdHF14AList(const char *Cmd) {
	//PrintAndLog("Deprecated command, use 'hf list 14a' instead");
	CmdHFList("14a");
	return 0;
}

int CmdHF14AReader(const char *Cmd) {
	UsbCommand cDisconnect = {CMD_READER_ISO_14443a, {0,0,0}};
	UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	WaitForResponse(CMD_ACK,&resp);
	
	iso14a_card_select_t card;
	memcpy(&card, (iso14a_card_select_t *)resp.d.asBytes, sizeof(iso14a_card_select_t));

	uint64_t select_status = resp.arg[0];		// 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision
	
	if(select_status == 0) {
		if (Cmd[0] != 's') PrintAndLog("iso14443a card select failed");
		SendCommand(&cDisconnect);
		return 0;
	}

	if(select_status == 3) {
		PrintAndLog("Card doesn't support standard iso14443-3 anticollision");
		PrintAndLog("ATQA : %02x %02x", card.atqa[1], card.atqa[0]);
		SendCommand(&cDisconnect);
		return 0;
	}

	PrintAndLog(" UID : %s", sprint_hex(card.uid, card.uidlen));
	PrintAndLog("ATQA : %02x %02x", card.atqa[1], card.atqa[0]);
	PrintAndLog(" SAK : %02x [%d]", card.sak, resp.arg[0]);

	switch (card.sak) {
		case 0x00: 

			// ******** is card of the MFU type (UL/ULC/NTAG/ etc etc)
			ul_switch_off_field();
			
			uint32_t tagT = GetHF14AMfU_Type();
			ul_print_type(tagT, 0);

			// reconnect for further tests
			c.arg[0] = ISO14A_CONNECT | ISO14A_NO_DISCONNECT;
			c.arg[1] = 0;
			c.arg[2] = 0;

			clearCommandBuffer();
			SendCommand(&c);

			UsbCommand resp;
			WaitForResponse(CMD_ACK, &resp);
			
			memcpy(&card, (iso14a_card_select_t *)resp.d.asBytes, sizeof(iso14a_card_select_t));

			select_status = resp.arg[0];		// 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS
			
			if(select_status == 0) {
				ul_switch_off_field();
				return 0;
			}
			break;
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

	// Double & triple sized UID, can be mapped to a manufacturer.
	if ( card.uidlen > 4 ) {
		PrintAndLog("MANUFACTURER : %s", getTagInfo(card.uid[0]));
	}
	
	// try to request ATS even if tag claims not to support it
	if (select_status == 2) {
		uint8_t rats[] = { 0xE0, 0x80 }; // FSDI=8 (FSD=256), CID=0
		c.arg[0] = ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_DISCONNECT;
		c.arg[1] = 2;
		c.arg[2] = 0;
		memcpy(c.d.asBytes, rats, 2);
		clearCommandBuffer();
		SendCommand(&c);
		WaitForResponse(CMD_ACK,&resp);
		
	    memcpy(card.ats, resp.d.asBytes, resp.arg[0]);
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
					case 0x10: PrintAndLog("                     1x -> MIFARE DESFire"); break;
					case 0x20: PrintAndLog("                     2x -> MIFARE Plus"); break;
				}
				switch (card.ats[pos + 2] & 0x0f) {
					case 0x00: PrintAndLog("                     x0 -> <1 kByte"); break;
					case 0x01: PrintAndLog("                     x1 -> 1 kByte"); break;
					case 0x02: PrintAndLog("                     x2 -> 2 kByte"); break;
					case 0x03: PrintAndLog("                     x3 -> 4 kByte"); break;
					case 0x04: PrintAndLog("                     x4 -> 8 kByte"); break;
				}
				switch (card.ats[pos + 3] & 0xf0) {
					case 0x00: PrintAndLog("                        0x -> Engineering sample"); break;
					case 0x20: PrintAndLog("                        2x -> Released"); break;
				}
				switch (card.ats[pos + 3] & 0x0f) {
					case 0x00: PrintAndLog("                        x0 -> Generation 1"); break;
					case 0x01: PrintAndLog("                        x1 -> Generation 2"); break;
					case 0x02: PrintAndLog("                        x2 -> Generation 3"); break;
				}
				switch (card.ats[pos + 4] & 0x0f) {
					case 0x00: PrintAndLog("                           x0 -> Only VCSL supported");	break;
					case 0x01: PrintAndLog("                           x1 -> VCS, VCSL, and SVC supported"); break;
					case 0x0E: PrintAndLog("                           xE -> no VCS command supported"); break;
				}
			}
		}
	} else {
		PrintAndLog("proprietary non iso14443-4 card found, RATS not supported");
	}

	
	// try to see if card responses to "chinese magic backdoor" commands.
	uint8_t isOK = 0;
	clearCommandBuffer();
	c.cmd = CMD_MIFARE_CIDENT;
	c.arg[0] = 0;
	c.arg[1] = 0;
	c.arg[2] = 0;	
	SendCommand(&c);
	if (WaitForResponseTimeout(CMD_ACK, &resp, 1500))
		isOK  = resp.arg[0] & 0xff;

	PrintAndLog("Answers to magic commands (GEN1): %s", (isOK ? "YES" : "NO") );
	
	// disconnect
	SendCommand(&cDisconnect);

	return select_status;
}

// Collect ISO14443 Type A UIDs
int CmdHF14ACUIDs(const char *Cmd) {
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
int CmdHF14ASim(const char *Cmd) {
	#define ATTACK_KEY_COUNT 8
	bool errors = FALSE;
	uint8_t flags = 0;
	uint8_t tagtype = 1;	
	uint8_t cmdp = 0;
	uint8_t uid[10] = {0,0,0,0,0,0,0,0,0,0};
	int uidlen = 0;
	bool useUIDfromEML = TRUE;

	while(param_getchar(Cmd, cmdp) != 0x00) {
		switch(param_getchar(Cmd, cmdp)) {
			case 'h':
			case 'H':
				return usage_hf_14a_sim();
			case 't':
			case 'T':
				// Retrieve the tag type
				tagtype = param_get8ex(Cmd, cmdp+1, 0, 10);
				if (tagtype == 0)
					errors = true; 
				cmdp += 2;
				break;
			case 'u':
			case 'U':
				// Retrieve the full 4,7,10 byte long uid 
				param_gethex_ex(Cmd, cmdp+1, uid, &uidlen);
				switch(uidlen) {
					//case 20: flags |= FLAG_10B_UID_IN_DATA; break;
					case 14: flags |= FLAG_7B_UID_IN_DATA; break;
					case  8: flags |= FLAG_4B_UID_IN_DATA; break;
					default: errors = TRUE;	break;
				}				
				if (!errors) {
					PrintAndLog("Emulating ISO/IEC 14443 type A tag with %d byte UID (%s)", uidlen>>1, sprint_hex(uid, uidlen>>1));
					useUIDfromEML = FALSE;
				}
				cmdp += 2;
				break;
			case 'x':
			case 'X':
				flags |= FLAG_NR_AR_ATTACK;
				cmdp++;
				break;
			default:
				PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
				errors = true;
				break;
			}
		if(errors) break;
	}

	//Validations
	if (errors) return usage_hf_14a_sim();

	if ( useUIDfromEML ) 
		flags |= FLAG_UID_IN_EMUL;
	
	PrintAndLog("Press pm3-button to abort simulation");
	
	UsbCommand c = {CMD_SIMULATE_TAG_ISO_14443a,{ tagtype, flags, 0 }};	
	memcpy(c.d.asBytes, uid, uidlen>>1);
	clearCommandBuffer();
	SendCommand(&c);	

	nonces_t data[ATTACK_KEY_COUNT*2];
	UsbCommand resp;

	while( !ukbhit() ){
		if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500) ) continue;

		if ( !(flags & FLAG_NR_AR_ATTACK) ) break;
		if ( (resp.arg[0] & 0xffff) != CMD_SIMULATE_MIFARE_CARD ) break;
			
		memcpy( data, resp.d.asBytes, sizeof(data) );
		readerAttack(data, TRUE);
	}
	return 0;
}

int CmdHF14ASniff(const char *Cmd) {
	int param = 0;	
	uint8_t ctmp = param_getchar(Cmd, 0) ;
	if (ctmp == 'h' || ctmp == 'H') return usage_hf_14a_sniff();
	
	for (int i = 0; i < 2; i++) {
		ctmp = param_getchar(Cmd, i);
		if (ctmp == 'c' || ctmp == 'C') param |= 0x01;
		if (ctmp == 'r' || ctmp == 'R') param |= 0x02;
	}

  UsbCommand c = {CMD_SNOOP_ISO_14443a, {param, 0, 0}};
  clearCommandBuffer();
  SendCommand(&c);
  return 0;
}

int CmdHF14ACmdRaw(const char *cmd) {
    UsbCommand c = {CMD_READER_ISO_14443a, {0, 0, 0}};
    bool reply=1;
    bool crc = FALSE;
    bool power = FALSE;
    bool active = FALSE;
    bool active_select = FALSE;
    uint16_t numbits=0;
	bool bTimeout = FALSE;
	uint32_t timeout=0;
	bool topazmode = FALSE;
    char buf[5]="";
    int i=0;
    uint8_t data[USB_CMD_DATA_SIZE];
	uint16_t datalen=0;
	uint32_t temp;

    if (strlen(cmd)<2) return usage_hf_14a_raw();

    // strip
    while (*cmd==' ' || *cmd=='\t') cmd++;

    while (cmd[i]!='\0') {
        if (cmd[i]==' ' || cmd[i]=='\t') { i++; continue; }
        if (cmd[i]=='-') {
            switch (cmd[i+1]) {
				case 'H':
				case 'h':
					return usage_hf_14a_raw();
                case 'r': 
                    reply = FALSE;
                    break;
                case 'c':
                    crc = TRUE;
                    break;
                case 'p':
                    power = TRUE;
                    break;
                case 'a':
                    active = TRUE;
                    break;
                case 's':
                    active_select = TRUE;
                    break;
                case 'b': 
                    sscanf(cmd+i+2,"%d",&temp);
                    numbits = temp & 0xFFFF;
                    i+=3;
                    while(cmd[i]!=' ' && cmd[i]!='\0') { i++; }
                    i-=2;
                    break;
				case 't':
					bTimeout = TRUE;
					sscanf(cmd+i+2,"%d",&temp);
					timeout = temp;
					i+=3;
					while(cmd[i]!=' ' && cmd[i]!='\0') { i++; }
					i-=2;
					break;
                case 'T':
					topazmode = TRUE;
					break;
                default:
                    return usage_hf_14a_raw();
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
                *buf=0;
				if (++datalen >= sizeof(data)){
					if (crc)
						PrintAndLog("Buffer is full, we can't add CRC to your data");
					break;
				}
            }
            continue;
        }
        PrintAndLog("Invalid char on input");
        return 0;
    }

    if(crc && datalen>0 && datalen<sizeof(data)-2)
    {
        uint8_t first, second;
		if (topazmode) {
			ComputeCrc14443(CRC_14443_B, data, datalen, &first, &second);
		} else {
			ComputeCrc14443(CRC_14443_A, data, datalen, &first, &second);
		}
        data[datalen++] = first;
        data[datalen++] = second;
    }

    if(active || active_select)
    {
        c.arg[0] |= ISO14A_CONNECT;
        if(active)
            c.arg[0] |= ISO14A_NO_SELECT;
    }

	if(bTimeout){
	    #define MAX_TIMEOUT 40542464 	// = (2^32-1) * (8*16) / 13560000Hz * 1000ms/s
        c.arg[0] |= ISO14A_SET_TIMEOUT;
        if(timeout > MAX_TIMEOUT) {
            timeout = MAX_TIMEOUT;
            PrintAndLog("Set timeout to 40542 seconds (11.26 hours). The max we can wait for response");
        }
		c.arg[2] = 13560000 / 1000 / (8*16) * timeout; // timeout in ETUs (time to transfer 1 bit, approx. 9.4 us)
	}

    if(power)
        c.arg[0] |= ISO14A_NO_DISCONNECT;

    if(datalen>0)
        c.arg[0] |= ISO14A_RAW;

	if(topazmode)
		c.arg[0] |= ISO14A_TOPAZMODE;
			
	// Max buffer is USB_CMD_DATA_SIZE
	datalen = (datalen > USB_CMD_DATA_SIZE) ? USB_CMD_DATA_SIZE : datalen;
		
    c.arg[1] = (datalen & 0xFFFF) | (uint32_t)(numbits << 16);
    memcpy(c.d.asBytes, data, datalen);

	clearCommandBuffer();
    SendCommand(&c);

    if (reply) {
        if(active_select)
            waitCmd(1);
        if(datalen>0)
            waitCmd(0);
    } // if reply
    return 0;
}

static void waitCmd(uint8_t iSelect) {
    UsbCommand resp;
    uint16_t len = 0;

    if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {        
        len = iSelect ? (resp.arg[1] & 0xffff) : (resp.arg[0]  & 0xffff);
        PrintAndLog("received %i octets", len);
        if(!len)
            return;
		PrintAndLog("%s", sprint_hex(resp.d.asBytes, len) );
    } else {
        PrintAndLog("timeout while waiting for reply.");
    }
}

static command_t CommandTable[] = {
  {"help",   CmdHelp,              1, "This help"},
  {"list",   CmdHF14AList,         0, "[Deprecated] List ISO 14443a history"},
  {"reader", CmdHF14AReader,       0, "Act like an ISO14443 Type A reader"},
  {"cuids",  CmdHF14ACUIDs,        0, "<n> Collect n>0 ISO14443 Type A UIDs in one go"},
  {"sim",    CmdHF14ASim,          0, "<UID> -- Simulate ISO 14443a tag"},
  {"sniff",  CmdHF14ASniff,        0, "sniff ISO 14443 Type A traffic"},
  {"raw",    CmdHF14ACmdRaw,       0, "Send raw hex data to tag"},
  {NULL, NULL, 0, NULL}
};

int CmdHF14A(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
  CmdsHelp(CommandTable);
  return 0;
}
