//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>, Hagen Fritsch
// 2011, 2017 Merlok
// 2014, Peter Fillmore
// 2015, 2016, 2017 Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443A commands
//-----------------------------------------------------------------------------
#include "cmdhf14a.h"

static int CmdHelp(const char *Cmd);
static int waitCmd(uint8_t iLen);

static const manufactureName manufactureMapping[] = {
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
	{ 0x1A, "Sony Corporation Japan" },
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
	{ 0x38, "HMT Microelectronic Ltd Switzerland" },
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
	{ 0x44, "Gentag Inc. USA" },
	{ 0x56, "Sensible Object. UK" },
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
//	PrintAndLogEx(NORMAL, "\n Emulating ISO/IEC 14443 type A tag with 4,7 or 10 byte UID\n");
	PrintAndLogEx(NORMAL, "\n Emulating ISO/IEC 14443 type A tag with 4,7 byte UID\n");
	PrintAndLogEx(NORMAL, "Usage: hf 14a sim [h] t <type> u <uid> [x] [e] [v]");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "    h     : This help");
	PrintAndLogEx(NORMAL, "    t     : 1 = MIFARE Classic 1k");
	PrintAndLogEx(NORMAL, "            2 = MIFARE Ultralight");
	PrintAndLogEx(NORMAL, "            3 = MIFARE Desfire");
	PrintAndLogEx(NORMAL, "            4 = ISO/IEC 14443-4");
	PrintAndLogEx(NORMAL, "            5 = MIFARE Tnp3xxx");
	PrintAndLogEx(NORMAL, "            6 = MIFARE Mini");
	PrintAndLogEx(NORMAL, "            7 = AMIIBO (NTAG 215),  pack 0x8080");
	PrintAndLogEx(NORMAL, "            8 = MIFARE Classic 4k");
	PrintAndLogEx(NORMAL, "            9 = FM11RF005SH Shanghai Metro");
//	PrintAndLogEx(NORMAL, "    u     : 4, 7 or 10 byte UID");
	PrintAndLogEx(NORMAL, "    u     : 4, 7 byte UID");
	PrintAndLogEx(NORMAL, "    x     : (Optional) Performs the 'reader attack', nr/ar attack against a reader");
	PrintAndLogEx(NORMAL, "    e     : (Optional) Fill simulator keys from found keys");	
	PrintAndLogEx(NORMAL, "    v     : (Optional) Verbose");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "          hf 14a sim t 1 u 11223344 x");
	PrintAndLogEx(NORMAL, "          hf 14a sim t 1 u 11223344");
	PrintAndLogEx(NORMAL, "          hf 14a sim t 1 u 11223344556677");
//	PrintAndLogEx(NORMAL, "          hf 14a sim t 1 u 11223445566778899AA\n");
	return 0;
}
int usage_hf_14a_sniff(void) {
	PrintAndLogEx(NORMAL, "It get data from the field and saves it into command buffer.");
	PrintAndLogEx(NORMAL, "Buffer accessible from command 'hf list 14a'");
	PrintAndLogEx(NORMAL, "Usage:  hf 14a sniff [c][r]");
	PrintAndLogEx(NORMAL, "c - triggered by first data from card");
	PrintAndLogEx(NORMAL, "r - triggered by first 7-bit request from reader (REQ,WUP,...)");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        hf 14a sniff c r");
	return 0;
}
int usage_hf_14a_raw(void) {
	PrintAndLogEx(NORMAL, "Usage: hf 14a raw [-h] [-r] [-c] [-p] [-a] [-T] [-t] <milliseconds> [-b] <number of bits>  <0A 0B 0C ... hex>");
	PrintAndLogEx(NORMAL, "       -h    this help");
	PrintAndLogEx(NORMAL, "       -r    do not read response");
	PrintAndLogEx(NORMAL, "       -c    calculate and append CRC");
	PrintAndLogEx(NORMAL, "       -p    leave the signal field ON after receive");
	PrintAndLogEx(NORMAL, "       -a    active signal field ON without select");
	PrintAndLogEx(NORMAL, "       -s    active signal field ON with select");
	PrintAndLogEx(NORMAL, "       -b    number of bits to send. Useful for send partial byte");
	PrintAndLogEx(NORMAL, "       -t    timeout in ms");
	PrintAndLogEx(NORMAL, "       -T    use Topaz protocol to send command");
	PrintAndLogEx(NORMAL, "       -3    ISO14443-3 select only (skip RATS)");
	return 0;
}
int usage_hf_14a_reader(void) {
	PrintAndLogEx(NORMAL, "Usage: hf 14a reader [k|s|x] [3]");
	PrintAndLogEx(NORMAL, "       k    keep the field active after command executed");
	PrintAndLogEx(NORMAL, "       s    silent (no messages)");
	PrintAndLogEx(NORMAL, "       x    just drop the signal field");
	PrintAndLogEx(NORMAL, "       3    ISO14443-3 select only (skip RATS)");
	return 0;
}
int usage_hf_14a_info(void){
	PrintAndLogEx(NORMAL, "This command makes more extensive tests against a ISO14443a tag in order to collect information");
	PrintAndLogEx(NORMAL, "Usage: hf 14a info [h|s]");
	PrintAndLogEx(NORMAL, "       s    silent (no messages)");
	PrintAndLogEx(NORMAL, "       n    test for nack bug");
	return 0;
}
int usage_hf_14a_apdu(void) {
	PrintAndLogEx(NORMAL, "Usage: hf 14a apdu [-s] [-k] [-t] <APDU (hex)>");
	PrintAndLogEx(NORMAL, "       -s    activate field and select card");
	PrintAndLogEx(NORMAL, "       -k    leave the signal field ON after receive response");
	PrintAndLogEx(NORMAL, "       -t    executes TLV decoder if it possible. TODO!!!!");
	return 0;
}
int usage_hf_14a_antifuzz(void) {
	PrintAndLogEx(NORMAL, "Usage: hf 14a antifuzz [4|7|10]");
	PrintAndLogEx(NORMAL, "       <len>    determine which anticollision phase the command will target.");
	return 0;
}

int CmdHF14AList(const char *Cmd) {
	//PrintAndLogEx(NORMAL, "Deprecated command, use 'hf list 14a' instead");
	CmdTraceList("14a");
	return 0;
}

int CmdHF14AReader(const char *Cmd) {
	bool silent = false;

	uint32_t cm = ISO14A_CONNECT;
	bool disconnectAfter = true;
	
	int cmdp = 0;
	while(param_getchar(Cmd, cmdp) != 0x00) {
		switch(param_getchar(Cmd, cmdp)) {
		case 'h':
		case 'H':
			return usage_hf_14a_reader();
		case '3':
			cm |= ISO14A_NO_RATS; 
			break;
		case 'k':
		case 'K':
			disconnectAfter = false;
			break;
		case 's':
		case 'S':	
		      silent = true;
			  break;
		case 'x':
		case 'X':
			cm &= ~ISO14A_CONNECT;
			break;
		default:
			PrintAndLogEx(WARNING, "Unknown command.");
			return 1;
		}	
		
		cmdp++;
	}

	if (!disconnectAfter)
		cm |= ISO14A_NO_DISCONNECT; 
	
	UsbCommand c = {CMD_READER_ISO_14443a, {cm, 0, 0}};
	
	clearCommandBuffer();
	SendCommand(&c);

	if (ISO14A_CONNECT & cm) {
		UsbCommand resp;
		if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
			if (!silent) PrintAndLogEx(WARNING, "iso14443a card select failed");
			DropField();
			return 1;
		}
	
		iso14a_card_select_t card;
		memcpy(&card, (iso14a_card_select_t *)resp.d.asBytes, sizeof(iso14a_card_select_t));

		/* 
			0: couldn't read
			1: OK, with ATS
			2: OK, no ATS
			3: proprietary Anticollision	
		*/
		uint64_t select_status = resp.arg[0];
		
		if (select_status == 0) {
			if (!silent) PrintAndLogEx(WARNING, "iso14443a card select failed");
			DropField();
			return 1;
		}

		if (select_status == 3) {
			PrintAndLogEx(NORMAL, "Card doesn't support standard iso14443-3 anticollision");
			PrintAndLogEx(NORMAL, "ATQA : %02x %02x", card.atqa[1], card.atqa[0]);
			DropField();
			return 1;
		}

		PrintAndLogEx(NORMAL, " UID : %s", sprint_hex(card.uid, card.uidlen));
		PrintAndLogEx(NORMAL, "ATQA : %02x %02x", card.atqa[1], card.atqa[0]);
		PrintAndLogEx(NORMAL, " SAK : %02x [%" PRIu64 "]", card.sak, resp.arg[0]);

		if(card.ats_len >= 3) {			// a valid ATS consists of at least the length byte (TL) and 2 CRC bytes
			PrintAndLogEx(NORMAL, " ATS : %s", sprint_hex(card.ats, card.ats_len));
		}
		
		if (!disconnectAfter) {
			if (!silent) PrintAndLogEx(SUCCESS, "Card is selected. You can now start sending commands");
		}
	}

	if (disconnectAfter) {
		if (!silent) PrintAndLogEx(SUCCESS, "field dropped.");
	}

	return 0;
}

int CmdHF14AInfo(const char *Cmd) {
	
	if (Cmd[0] == 'h' || Cmd[0] ==  'H') return usage_hf_14a_info();
	
	bool silent = (Cmd[0] == 's' || Cmd[0] ==  'S');
	bool do_nack_test = (Cmd[0] == 'n' || Cmd[0] ==  'N');
	
	UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
		if (!silent) PrintAndLogEx(WARNING, "iso14443a card select failed");
		DropField();
		return 0;
	}
	
	iso14a_card_select_t card;
	memcpy(&card, (iso14a_card_select_t *)resp.d.asBytes, sizeof(iso14a_card_select_t));

	/* 
		0: couldn't read
		1: OK, with ATS
		2: OK, no ATS
		3: proprietary Anticollision	
	*/
	uint64_t select_status = resp.arg[0];
	
	if (select_status == 0) {
		if (!silent) PrintAndLogEx(WARNING, "iso14443a card select failed");
		DropField();
		return 0;
	}

	if (select_status == 3) {
		PrintAndLogEx(NORMAL, "Card doesn't support standard iso14443-3 anticollision");
		PrintAndLogEx(NORMAL, "ATQA : %02x %02x", card.atqa[1], card.atqa[0]);
		DropField();
		return select_status;
	}

	PrintAndLogEx(NORMAL, " UID : %s", sprint_hex(card.uid, card.uidlen));
	PrintAndLogEx(NORMAL, "ATQA : %02x %02x", card.atqa[1], card.atqa[0]);
	PrintAndLogEx(NORMAL, " SAK : %02x [%" PRIu64 "]", card.sak, resp.arg[0]);

	bool isMifareClassic = true;
	switch (card.sak) {
		case 0x00: 
			isMifareClassic = false;
			
			// ******** is card of the MFU type (UL/ULC/NTAG/ etc etc)
			DropField();
			
			uint32_t tagT = GetHF14AMfU_Type();
			if (tagT != UL_ERROR)
				ul_print_type(tagT, 0);
			else 
				PrintAndLogEx(NORMAL, "TYPE: Possible AZTEK (iso14443a compliant)");

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
				DropField();
				return 0;
			}
			break;
		case 0x01: PrintAndLogEx(NORMAL, "TYPE : NXP TNP3xxx Activision Game Appliance"); break;
		case 0x04: PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE (various !DESFire !DESFire EV1)"); isMifareClassic = false; break;
		case 0x08: PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1 | 1k Ev1"); break;
		case 0x09: PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE Mini 0.3k"); break;
		case 0x0A: PrintAndLogEx(NORMAL, "TYPE : FM11RF005SH (Shanghai Metro)"); break;
		case 0x10: PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE Plus 2k SL2"); break;
		case 0x11: PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE Plus 4k SL2"); break;
		case 0x18: PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE Classic 4k | Plus 4k SL1 | 4k Ev1"); break;
		case 0x20: PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE DESFire 4k | DESFire EV1 2k/4k/8k | Plus 2k/4k SL3 | JCOP 31/41"); isMifareClassic = false; break;
		case 0x24: PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE DESFire | DESFire EV1"); isMifareClassic = false; break;
		case 0x28: PrintAndLogEx(NORMAL, "TYPE : JCOP31 or JCOP41 v2.3.1"); break;
		case 0x38: PrintAndLogEx(NORMAL, "TYPE : Nokia 6212 or 6131 MIFARE CLASSIC 4K"); break;
		case 0x88: PrintAndLogEx(NORMAL, "TYPE : Infineon MIFARE CLASSIC 1K"); break;
		case 0x98: PrintAndLogEx(NORMAL, "TYPE : Gemplus MPCOS"); break;
		default: ;
	}

	// Double & triple sized UID, can be mapped to a manufacturer.
	if ( card.uidlen > 4 ) {
		PrintAndLogEx(NORMAL, "MANUFACTURER : %s", getTagInfo(card.uid[0]));
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
			PrintAndLogEx(NORMAL, "SAK incorrectly claims that card doesn't support RATS");
		}
		PrintAndLogEx(NORMAL, " ATS : %s", sprint_hex(card.ats, card.ats_len));
		PrintAndLogEx(NORMAL, "       -  TL : length is %d bytes", card.ats[0]);
		if (card.ats[0] != card.ats_len - 2) {
			PrintAndLogEx(NORMAL, "ATS may be corrupted. Length of ATS (%d bytes incl. 2 Bytes CRC) doesn't match TL", card.ats_len);
		}
		
		if (card.ats[0] > 1) {		// there is a format byte (T0)
			ta1 = (card.ats[1] & 0x10) == 0x10;
			tb1 = (card.ats[1] & 0x20) == 0x20;
			tc1 = (card.ats[1] & 0x40) == 0x40;
			int16_t fsci = card.ats[1] & 0x0f;
			
			PrintAndLogEx(NORMAL, "       -  T0 : TA1 is%s present, TB1 is%s present, "
					"TC1 is%s present, FSCI is %d (FSC = %ld)",
				(ta1 ? "" : " NOT"),
				(tb1 ? "" : " NOT"),
				(tc1 ? "" : " NOT"),
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
			PrintAndLogEx(NORMAL, "       - TA1 : different divisors are%s supported, "
					"DR: [%s], DS: [%s]",
					(card.ats[pos] & 0x80 ? " NOT" : ""), dr, ds);
			pos++;
		}
		if (tb1) {
			uint32_t sfgi = card.ats[pos] & 0x0F;
			uint32_t fwi = card.ats[pos] >> 4;
			PrintAndLogEx(NORMAL, "       - TB1 : SFGI = %d (SFGT = %s%ld/fc), FWI = %d (FWT = %ld/fc)",
					(sfgi),
					sfgi ? "" : "(not needed) ",
					sfgi ? (1 << 12) << sfgi : 0,
					fwi,
					(1 << 12) << fwi
					);
			pos++;
		}
		if (tc1) {
			PrintAndLogEx(NORMAL, "       - TC1 : NAD is%s supported, CID is%s supported",
					(card.ats[pos] & 0x01) ? "" : " NOT",
					(card.ats[pos] & 0x02) ? "" : " NOT");
			pos++;
		}
		if (card.ats[0] > pos && card.ats[0] <  card.ats_len - 2 ) {
			char *tip = "";
			if (card.ats[0] - pos >= 7) {
				if (memcmp(card.ats + pos, "\xC1\x05\x2F\x2F\x01\xBC\xD6", 7) == 0) {
					tip = "-> MIFARE Plus X 2K or 4K";
				} else if (memcmp(card.ats + pos, "\xC1\x05\x2F\x2F\x00\x35\xC7", 7) == 0) {
					tip = "-> MIFARE Plus S 2K or 4K";
				}
			} 
			PrintAndLogEx(NORMAL, "       -  HB : %s%s", sprint_hex(card.ats + pos, card.ats[0] - pos), tip);
			if (card.ats[pos] == 0xC1) {
				PrintAndLogEx(NORMAL, "               c1 -> Mifare or (multiple) virtual cards of various type");
				PrintAndLogEx(NORMAL, "                  %02x -> Length is %d bytes", card.ats[pos + 1], card.ats[pos + 1]);
				switch (card.ats[pos + 2] & 0xf0) {
					case 0x10: PrintAndLogEx(NORMAL, "                     1x -> MIFARE DESFire"); break;
					case 0x20: PrintAndLogEx(NORMAL, "                     2x -> MIFARE Plus"); break;
				}
				switch (card.ats[pos + 2] & 0x0f) {
					case 0x00: PrintAndLogEx(NORMAL, "                     x0 -> <1 kByte"); break;
					case 0x01: PrintAndLogEx(NORMAL, "                     x1 -> 1 kByte"); break;
					case 0x02: PrintAndLogEx(NORMAL, "                     x2 -> 2 kByte"); break;
					case 0x03: PrintAndLogEx(NORMAL, "                     x3 -> 4 kByte"); break;
					case 0x04: PrintAndLogEx(NORMAL, "                     x4 -> 8 kByte"); break;
				}
				switch (card.ats[pos + 3] & 0xf0) {
					case 0x00: PrintAndLogEx(NORMAL, "                        0x -> Engineering sample"); break;
					case 0x20: PrintAndLogEx(NORMAL, "                        2x -> Released"); break;
				}
				switch (card.ats[pos + 3] & 0x0f) {
					case 0x00: PrintAndLogEx(NORMAL, "                        x0 -> Generation 1"); break;
					case 0x01: PrintAndLogEx(NORMAL, "                        x1 -> Generation 2"); break;
					case 0x02: PrintAndLogEx(NORMAL, "                        x2 -> Generation 3"); break;
				}
				switch (card.ats[pos + 4] & 0x0f) {
					case 0x00: PrintAndLogEx(NORMAL, "                           x0 -> Only VCSL supported");	break;
					case 0x01: PrintAndLogEx(NORMAL, "                           x1 -> VCS, VCSL, and SVC supported"); break;
					case 0x0E: PrintAndLogEx(NORMAL, "                           xE -> no VCS command supported"); break;
				}
			}
		}
	} else {
		PrintAndLogEx(INFO, "proprietary non iso14443-4 card found, RATS not supported");
	}
	
	detect_classic_magic();
	
	if (isMifareClassic) {
		int res = detect_classic_prng();
		if ( res == 1 )
			PrintAndLogEx(SUCCESS, "Prng detection: WEAK");
		else if (res == 0 )
			PrintAndLogEx(SUCCESS, "Prng detection: HARD");
		else
			PrintAndLogEx(FAILED, "prng detection: failed");
		
		if ( do_nack_test )
			detect_classic_nackbug(silent);
	}
	
	return select_status;
}

// Collect ISO14443 Type A UIDs
int CmdHF14ACUIDs(const char *Cmd) {
	// requested number of UIDs
	int n = atoi(Cmd);
	// collect at least 1 (e.g. if no parameter was given)
	n = n > 0 ? n : 1;

	uint64_t t1 =  msclock();
	PrintAndLogEx(SUCCESS, "collecting %d UIDs", n);

	// repeat n times
	for (int i = 0; i < n; i++) {

		if (ukbhit()) {
			int gc = getchar(); (void)gc;
			PrintAndLogEx(NORMAL, "\n[!] aborted via keyboard!\n");
			break;
		}
		
		// execute anticollision procedure
		UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_CONNECT | ISO14A_NO_RATS, 0, 0}};
		SendCommand(&c);
    
		UsbCommand resp;
		WaitForResponse(CMD_ACK,&resp);

		iso14a_card_select_t *card = (iso14a_card_select_t *) resp.d.asBytes;

		// check if command failed
		if (resp.arg[0] == 0) {
			PrintAndLogEx(WARNING, "card select failed.");
		} else {
			char uid_string[20];
			for (uint16_t i = 0; i < card->uidlen; i++) {
				sprintf(&uid_string[2*i], "%02X", card->uid[i]);
			}
			PrintAndLogEx(NORMAL, "%s", uid_string);
		}
	}
	PrintAndLogEx(SUCCESS, "end: %" PRIu64 " seconds", (msclock()-t1)/1000);
	return 1;
}

// ## simulate iso14443a tag
int CmdHF14ASim(const char *Cmd) {
	bool errors = false;
	uint8_t flags = 0;
	uint8_t tagtype = 1;	
	uint8_t cmdp = 0;
	uint8_t uid[10] = {0,0,0,0,0,0,0,0,0,0};
	int uidlen = 0;
	bool useUIDfromEML = true;
	bool setEmulatorMem = false;
	bool verbose = false;
	nonces_t data[1];
	
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
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
					default: errors = true;	break;
				}				
				if (!errors) {
					PrintAndLogEx(SUCCESS, "Emulating ISO/IEC 14443 type A tag with %d byte UID (%s)", uidlen>>1, sprint_hex(uid, uidlen>>1));
					useUIDfromEML = false;
				}
				cmdp += 2;
				break;
			case 'v':
			case 'V':
				verbose = true;
				cmdp++;
				break;
			case 'x':
			case 'X':
				flags |= FLAG_NR_AR_ATTACK;
				cmdp++;
				break;
			case 'e':
			case 'E':
				setEmulatorMem = true;
				cmdp++;
				break;				
			default:
				PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
				errors = true;
				break;
			}
	}

	//Validations
	if (errors || cmdp == 0) return usage_hf_14a_sim();

	if ( useUIDfromEML ) 
		flags |= FLAG_UID_IN_EMUL;
	
	UsbCommand c = {CMD_SIMULATE_TAG_ISO_14443a,{ tagtype, flags, 0 }};	
	memcpy(c.d.asBytes, uid, uidlen>>1);
	clearCommandBuffer();
	SendCommand(&c);	
	UsbCommand resp;
	
	PrintAndLogEx(SUCCESS, "press pm3-button to abort simulation");
	
	while( !ukbhit() ){
		if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500) ) continue;
		if ( !(flags & FLAG_NR_AR_ATTACK) ) break;
		if ( (resp.arg[0] & 0xffff) != CMD_SIMULATE_MIFARE_CARD ) break;
			
		memcpy(data, resp.d.asBytes, sizeof(data) );
		readerAttack(data[0], setEmulatorMem, verbose);
	}
	showSectorTable();
	return 0;
}

int CmdHF14ASniff(const char *Cmd) {
	int param = 0;	
	uint8_t ctmp;
	for (int i = 0; i < 2; i++) {
		ctmp = param_getchar(Cmd, i);
		if (ctmp == 'h' || ctmp == 'H') return usage_hf_14a_sniff();
		if (ctmp == 'c' || ctmp == 'C') param |= 0x01;
		if (ctmp == 'r' || ctmp == 'R') param |= 0x02;
	}
	UsbCommand c = {CMD_SNOOP_ISO_14443a, {param, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int ExchangeAPDU14a(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
	uint16_t cmdc = 0;
	
	if (activateField) {
		cmdc |= ISO14A_CONNECT;
	}
	if (leaveSignalON)
		cmdc |= ISO14A_NO_DISCONNECT;

	// "Command APDU" length should be 5+255+1, but javacard's APDU buffer might be smaller - 133 bytes
	// https://stackoverflow.com/questions/32994936/safe-max-java-card-apdu-data-command-and-respond-size
	// here length USB_CMD_DATA_SIZE=512
	// timeout must be authomatically set by "get ATS"
	UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_APDU | cmdc, (datainlen & 0xFFFF), 0}}; 
	memcpy(c.d.asBytes, datain, datainlen);
	SendCommand(&c);
	
    uint8_t *recv;
    UsbCommand resp;

	if (activateField) {
		if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
			PrintAndLogEx(NORMAL, "APDU ERROR: Proxmark connection timeout.");
			return 1;
		}
		if (resp.arg[0] != 1) {
			PrintAndLogEx(NORMAL, "APDU ERROR: Proxmark error %d.", resp.arg[0]);
			return 1;
		}
	}

    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        recv = resp.d.asBytes;
        int iLen = resp.arg[0];
		
		*dataoutlen = iLen - 2;
		if (*dataoutlen < 0)
			*dataoutlen = 0;
		
		if (maxdataoutlen && *dataoutlen > maxdataoutlen) {
			PrintAndLogEx(NORMAL, "APDU ERROR: Buffer too small(%d). Needs %d bytes", *dataoutlen, maxdataoutlen);
			return 2;
		}
		
		memcpy(dataout, recv, *dataoutlen);
		
        if(!iLen) {
			PrintAndLogEx(NORMAL, "APDU ERROR: No APDU response.");
            return 1;
		}

		// check block TODO
		if (iLen == -2) {
			PrintAndLogEx(NORMAL, "APDU ERROR: Block type mismatch.");
			return 2;
		}
		
		// CRC Check
		if (iLen == -1) {
			PrintAndLogEx(NORMAL, "APDU ERROR: ISO 14443A CRC error.");
			return 3;
		}

		// check apdu length
		if (iLen < 4) {
			PrintAndLogEx(NORMAL, "APDU ERROR: Small APDU response. Len=%d", iLen);
			return 2;
		}
		
    } else {
        PrintAndLogEx(NORMAL, "APDU ERROR: Reply timeout.");
		return 4;
    }
	
	return 0;
}

int CmdHF14AAPDU(const char *cmd) {
	uint8_t data[USB_CMD_DATA_SIZE];
	int datalen = 0;
	bool activateField = false;
	bool leaveSignalON = false;
	bool decodeTLV = false;
	
	if (strlen(cmd) < 2) return usage_hf_14a_apdu();

	int cmdp = 0;
	while(param_getchar(cmd, cmdp) != 0x00) {
		char c = param_getchar(cmd, cmdp);
		if ((c == '-') && (param_getlength(cmd, cmdp) == 2))
			switch (param_getchar_indx(cmd, 1, cmdp)) {
				case 'h':
				case 'H':
					return usage_hf_14a_apdu();
				case 's':
				case 'S':
					activateField = true;
					break;
				case 'k':
				case 'K':
					leaveSignalON = true;
					break;
				case 't':
				case 'T':
					decodeTLV = true;
					break;
				default:
					PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar_indx(cmd, 1, cmdp));
					return 1;
			}
			
		if (isxdigit(c)) {
			// len = data + PCB(1b) + CRC(2b)
			switch(param_gethex_to_eol(cmd, cmdp, data, sizeof(data) - 1 - 2, &datalen)) {
			case 1:
				PrintAndLogEx(WARNING, "invalid HEX value.");
				return 1;
			case 2:
				PrintAndLogEx(WARNING, "APDU too large.");
				return 1;
			case 3:
				PrintAndLogEx(WARNING, "hex must have even number of digits.");
				return 1;
			}
			
			// we get all the hex to end of line with spaces
			break;
		}
		
		cmdp++;
	}

	PrintAndLogEx(NORMAL, ">>>>[%s%s%s] %s", activateField ? "sel ": "", leaveSignalON ? "keep ": "", decodeTLV ? "TLV": "", sprint_hex(data, datalen));
	
	int res = ExchangeAPDU14a(data, datalen, activateField, leaveSignalON, data, USB_CMD_DATA_SIZE, &datalen);

	if (res)
		return res;

	PrintAndLogEx(NORMAL, "<<<< %s", sprint_hex(data, datalen));
	
	PrintAndLogEx(SUCCESS, "APDU response: %02x %02x - %s", data[datalen - 2], data[datalen - 1], GetAPDUCodeDescription(data[datalen - 2], data[datalen - 1])); 

	// TLV decoder
	if (decodeTLV && datalen > 4) {
		TLVPrintFromBuffer(data, datalen - 2);
	}
	
	return 0;
}

int CmdHF14ACmdRaw(const char *cmd) {
    UsbCommand c = {CMD_READER_ISO_14443a, {0, 0, 0}};
    bool reply = 1;
    bool crc = false;
    bool power = false;
    bool active = false;
    bool active_select = false;
	bool no_rats = false;
    uint16_t numbits = 0;
	bool bTimeout = false;
	uint32_t timeout = 0;
	bool topazmode = false;
    char buf[5]="";
    int i = 0;
    uint8_t data[USB_CMD_DATA_SIZE];
	uint16_t datalen = 0;
	uint32_t temp;

    if (strlen(cmd) < 2) return usage_hf_14a_raw();

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
                    reply = false;
                    break;
                case 'c':
                    crc = true;
                    break;
                case 'p':
                    power = true;
                    break;
                case 'a':
                    active = true;
                    break;
                case 's':
                    active_select = true;
                    break;
                case 'b': 
                    sscanf(cmd+i+2, "%d", &temp);
                    numbits = temp & 0xFFFF;
                    i+=3;
                    while(cmd[i]!=' ' && cmd[i]!='\0') { i++; }
                    i-=2;
                    break;
				case 't':
					bTimeout = true;
					sscanf(cmd+i+2, "%d", &temp);
					timeout = temp;
					i+=3;
					while(cmd[i]!=' ' && cmd[i]!='\0') { i++; }
					i-=2;
					break;
                case 'T':
					topazmode = true;
					break;
				case '3':
					no_rats = true;
					break;
                default:
                    return usage_hf_14a_raw();
            }
            i += 2;
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
						PrintAndLogEx(NORMAL, "Buffer is full, we can't add CRC to your data");
					break;
				}
            }
            continue;
        }
        PrintAndLogEx(NORMAL, "Invalid char on input");
        return 0;
    }

    if (crc && datalen>0 && datalen < sizeof(data)-2) {
        uint8_t first, second;
		if (topazmode) {
			compute_crc(CRC_14443_B, data, datalen, &first, &second);
		} else {
			compute_crc(CRC_14443_A, data, datalen, &first, &second);
		}
        data[datalen++] = first;
        data[datalen++] = second;
    }

    if (active || active_select) {
        c.arg[0] |= ISO14A_CONNECT;
        if (active)
            c.arg[0] |= ISO14A_NO_SELECT;
    }

	if (bTimeout){
	    #define MAX_TIMEOUT 40542464 	// = (2^32-1) * (8*16) / 13560000Hz * 1000ms/s
        c.arg[0] |= ISO14A_SET_TIMEOUT;
        if(timeout > MAX_TIMEOUT) {
            timeout = MAX_TIMEOUT;
            PrintAndLogEx(NORMAL, "Set timeout to 40542 seconds (11.26 hours). The max we can wait for response");
        }
		c.arg[2] = 13560000 / 1000 / (8*16) * timeout; // timeout in ETUs (time to transfer 1 bit, approx. 9.4 us)
	}

    if (power) {
        c.arg[0] |= ISO14A_NO_DISCONNECT;
	}
	
    if (datalen > 0) {
        c.arg[0] |= ISO14A_RAW;
	}
	
	if (topazmode) {
		c.arg[0] |= ISO14A_TOPAZMODE;
	}
	if (no_rats) {
		c.arg[0] |= ISO14A_NO_RATS;
	}
			
	// Max buffer is USB_CMD_DATA_SIZE
	datalen = (datalen > USB_CMD_DATA_SIZE) ? USB_CMD_DATA_SIZE : datalen;
		
    c.arg[1] = (datalen & 0xFFFF) | ((uint32_t)(numbits << 16));
    memcpy(c.d.asBytes, data, datalen);

	clearCommandBuffer();
    SendCommand(&c);

    if (reply) {
		int res = 0;
        if (active_select)
			res = waitCmd(1);
		if (!res && datalen > 0)
            waitCmd(0);
    }
    return 0;
}

static int waitCmd(uint8_t iSelect) {
    UsbCommand resp;
    uint16_t len = 0;

    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {        
		len = (resp.arg[0] & 0xFFFF);
		if (iSelect){
			len = (resp.arg[1] & 0xFFFF);
			if (len){
				PrintAndLogEx(NORMAL, "Card selected. UID[%i]:", len);
			} else {
				PrintAndLogEx(WARNING, "Can't select card.");
			}
		} else {
			PrintAndLogEx(NORMAL, "received %i bytes:", len);
		}
		
        if (!len)
            return 1;
		
		PrintAndLogEx(NORMAL, "%s", sprint_hex(resp.d.asBytes, len) );
    } else {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
		return 3;
    }
	return 0;
}

int CmdHF14AAntiFuzz(const char *cmd) {
	
	if (strlen(cmd) < 1) return usage_hf_14a_antifuzz();

	//	read param length
	uint8_t arg0 = 4;
	
	UsbCommand c = {CMD_ANTIFUZZ_ISO_14443a, {arg0, 0, 0}};	
	clearCommandBuffer();
    SendCommand(&c);	
	return 0;
}

static command_t CommandTable[] = {
  {"help",		CmdHelp,              1, "This help"},
  {"list",		CmdHF14AList,         0, "[Deprecated] List ISO 14443-a history"},
  {"info",		CmdHF14AInfo,         0, "Tag information"},
  {"reader",	CmdHF14AReader,       0, "Act like an ISO14443-a reader"},
  {"cuids",		CmdHF14ACUIDs,        0, "<n> Collect n>0 ISO14443-a UIDs in one go"},
  {"sim",		CmdHF14ASim,          0, "<UID> -- Simulate ISO 14443-a tag"},
  {"sniff",		CmdHF14ASniff,        0, "sniff ISO 14443-a traffic"},
  {"apdu",		CmdHF14AAPDU,         0, "Send ISO 14443-4 APDU to tag"},
  {"raw",		CmdHF14ACmdRaw,       0, "Send raw hex data to tag"},
  {"antifuzz",	CmdHF14AAntiFuzz,     0, "Fuzzing the anticollision phase.  Warning! Readers may react strange"},
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
