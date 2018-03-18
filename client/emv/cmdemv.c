//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
// modified 2017 iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// EMV commands
//-----------------------------------------------------------------------------

#include "cmdemv.h"
#include "test/cryptotest.h"

static int CmdHelp(const char *Cmd);

int usage_emv_select(void) {
	PrintAndLogEx(NORMAL, "Executes select applet command:\n");
	PrintAndLogEx(NORMAL, "Usage:  hf emv select [-s][-k][-a][-t] <HEX applet AID>\n");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "  -s       : select card");
	PrintAndLogEx(NORMAL, "  -k       : keep field for next command");
	PrintAndLogEx(NORMAL, "  -a       : show APDU reqests and responses\n");
	PrintAndLogEx(NORMAL, "  -t       : TLV decode results\n");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, " hf emv select -s a00000000101        -> select card, select applet");
	PrintAndLogEx(NORMAL, " hf emv select -s -t a00000000101     -> select card, select applet, show result in TLV");
	return 0;
}

int CmdHFEMVSelect(const char *cmd) {
	uint8_t data[APDU_AID_LEN] = {0};
	int datalen = 0;
	bool activateField = false;
	bool leaveSignalON = false;
	bool decodeTLV = false;

	if (strlen(cmd) < 1)
		return usage_emv_select();
	
	SetAPDULogging(false);
	
	int cmdp = 0;
	while(param_getchar(cmd, cmdp) != 0x00) {
		char c = param_getchar(cmd, cmdp);
		if ((c == '-') && (param_getlength(cmd, cmdp) == 2))
			switch (param_getchar_indx(cmd, 1, cmdp)) {
				case 'h':
				case 'H':
					return usage_emv_select();
				case 's':
				case 'S':
					activateField = true;
					break;
				case 'k':
				case 'K':
					leaveSignalON = true;
					break;
				case 'a':
				case 'A':
					SetAPDULogging(true);
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
			switch(param_gethex_to_eol(cmd, cmdp, data, sizeof(data), &datalen)) {
			case 1:
				PrintAndLogEx(WARNING, "Invalid HEX value.");
				return 1;
			case 2:
				PrintAndLogEx(WARNING, "AID too large.");
				return 1;
			case 3:
				PrintAndLogEx(WARNING, "Hex must have even number of digits.");
				return 1;
			}
			
			// we get all the hex to end of line with spaces
			break;
		}
		cmdp++;
	}
	
	// exec
	uint8_t buf[APDU_RES_LEN] = {0};
	size_t len = 0;
	uint16_t sw = 0;
	int res = EMVSelect(activateField, leaveSignalON, data, datalen, buf, sizeof(buf), &len, &sw, NULL);

	if (sw)
		PrintAndLogEx(NORMAL, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff)); 
	
	if (res)
		return res;
	
	if (decodeTLV)
		TLVPrintFromBuffer(buf, len);

	return 0;
}

int usage_emv_search(void) {
	PrintAndLogEx(NORMAL, "Tries to select all applets from applet list:\n");
	PrintAndLogEx(NORMAL, "Usage:  hf emv search [-s][-k][-a][-t]\n");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "  -s       : select card");
	PrintAndLogEx(NORMAL, "  -k       : keep field for next command");
	PrintAndLogEx(NORMAL, "  -a       : show APDU reqests and responses\n");
	PrintAndLogEx(NORMAL, "  -t       : TLV decode results of selected applets\n");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, " hf emv search -s         -> select card and search");
	PrintAndLogEx(NORMAL, " hf emv search -s -t      -> select card, search and show result in TLV");
	return 0;
}

int CmdHFEMVSearch(const char *cmd) {

	bool activateField = false;
	bool leaveSignalON = false;
	bool decodeTLV = false;

	if (strlen(cmd) < 1)
		return usage_emv_search();
	
	SetAPDULogging(false);
	
	int cmdp = 0;
	while(param_getchar(cmd, cmdp) != 0x00) {
		char c = param_getchar(cmd, cmdp);
		if ((c == '-') && (param_getlength(cmd, cmdp) == 2))
			switch (param_getchar_indx(cmd, 1, cmdp)) {
				case 'h':
				case 'H':
					return usage_emv_search();
				case 's':
				case 'S':
					activateField = true;
					break;
				case 'k':
				case 'K':
					leaveSignalON = true;
					break;
				case 'a':
				case 'A':
					SetAPDULogging(true);
					break;
				case 't':
				case 'T':
					decodeTLV = true;
					break;
				default:
					PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar_indx(cmd, 1, cmdp));
					return 1;
		}
		cmdp++;
	}

	struct tlvdb *t = NULL;
	const char *al = "Applets list";
	t = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

	if (EMVSearch(activateField, leaveSignalON, decodeTLV, t)) {
		tlvdb_free(t);
		return 2;
	}
	
	PrintAndLogEx(NORMAL, "Search completed.");

	// print list here
	if (!decodeTLV) {  
		TLVPrintAIDlistFromSelectTLV(t);
	}
	
	tlvdb_free(t);
	
	return 0;
}

int usage_emv_ppse(void) {
	PrintAndLogEx(NORMAL, "Executes PSE/PPSE select command. It returns list of applet on the card:\n");
	PrintAndLogEx(NORMAL, "Usage:  hf emv pse [-s][-k][-1][-2][-a][-t]\n");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "  -s       : select card");
	PrintAndLogEx(NORMAL, "  -k       : keep field for next command");
	PrintAndLogEx(NORMAL, "  -1       : ppse (1PAY.SYS.DDF01)");
	PrintAndLogEx(NORMAL, "  -2       : pse (2PAY.SYS.DDF01)");
	PrintAndLogEx(NORMAL, "  -a       : show APDU reqests and responses\n");
	PrintAndLogEx(NORMAL, "  -t       : TLV decode results\n");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, " hf emv pse -s -1         -> select, get pse");
	PrintAndLogEx(NORMAL, " hf emv pse -s -k -2      -> select, get ppse, keep field");
	PrintAndLogEx(NORMAL, " hf emv pse -s -t -2      -> select, get ppse, show result in TLV");
	return 0;
}

int CmdHFEMVPPSE(const char *cmd) {
	
	uint8_t PSENum = 2;
	bool activateField = false;
	bool leaveSignalON = false;
	bool decodeTLV = false;

	if (strlen(cmd) < 1)
		return usage_emv_ppse();

	SetAPDULogging(false);
	
	int cmdp = 0;
	while(param_getchar(cmd, cmdp) != 0x00) {
		char c = param_getchar(cmd, cmdp);
		if ((c == '-') && (param_getlength(cmd, cmdp) == 2))
			switch (param_getchar_indx(cmd, 1, cmdp)) {
				case 'h':
				case 'H':
					return usage_emv_ppse();
				case 's':
				case 'S':
					activateField = true;
					break;
				case 'k':
				case 'K':
					leaveSignalON = true;
					break;
				case 'a':
				case 'A':
					SetAPDULogging(true);
					break;
				case 't':
				case 'T':
					decodeTLV = true;
					break;
				case '1':
					PSENum = 1;
					break;
				case '2':
					PSENum = 2;
					break;
				default:
					PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar_indx(cmd, 1, cmdp));
					return 1;
		}
		cmdp++;
	}
	
	// exec
	uint8_t buf[APDU_RES_LEN] = {0};
	size_t len = 0;
	uint16_t sw = 0;
	int res = EMVSelectPSE(activateField, leaveSignalON, PSENum, buf, sizeof(buf), &len, &sw);
	
	if (sw)
		PrintAndLogEx(NORMAL, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff)); 

	if (res)
		return res;	
	
	if (decodeTLV)
		TLVPrintFromBuffer(buf, len);

	return 0;
}

int usage_emv_exec(void) {
	PrintAndLogEx(NORMAL, "Executes EMV contactless transaction:\n");
	PrintAndLogEx(NORMAL, "Usage:  hf emv exec [-s][-a][-t][-f][-v][-c][-x][-g]\n");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "  -s       : select card");
	PrintAndLogEx(NORMAL, "  -a       : show APDU reqests and responses\n");
	PrintAndLogEx(NORMAL, "  -t       : TLV decode results\n");
	PrintAndLogEx(NORMAL, "  -f       : force search AID. Search AID instead of execute PPSE.\n");
	PrintAndLogEx(NORMAL, "  -v       : transaction type - qVSDC or M/Chip.\n");
	PrintAndLogEx(NORMAL, "  -c       : transaction type - qVSDC or M/Chip plus CDA (SDAD generation).\n");
	PrintAndLogEx(NORMAL, "  -x       : transaction type - VSDC. For test only. Not a standart behavior.\n");
	PrintAndLogEx(NORMAL, "  -g       : VISA. generate AC from GPO\n");
	PrintAndLogEx(NORMAL, "By default : transaction type - MSD.\n");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, " hf emv exec -s -a -t         -> execute MSD transaction");
	PrintAndLogEx(NORMAL, " hf emv exec -s -a -t -c      -> execute CDA transaction");
	return 0;
}

#define TLV_ADD(tag, value)( tlvdb_add(tlvRoot, tlvdb_fixed(tag, sizeof(value) - 1, (const unsigned char *)value)) )
#define dreturn(n) {free(pdol_data_tlv);tlvdb_free(tlvSelect);tlvdb_free(tlvRoot);DropField();return n;}

int CmdHFEMVExec(const char *cmd) {
	bool activateField = false;
	bool showAPDU = false;
	bool decodeTLV = false;
	bool forceSearch = false;
	enum TransactionType TrType = TT_MSD;
	bool GenACGPO = false;

	uint8_t buf[APDU_RES_LEN] = {0};
	size_t len = 0;
	uint16_t sw = 0;
	uint8_t AID[APDU_AID_LEN] = {0};
	size_t AIDlen = 0;
	uint8_t ODAiList[4096];
	size_t ODAiListLen = 0;
	
	int res;
	
	struct tlvdb *tlvSelect = NULL;
	struct tlvdb *tlvRoot = NULL;
	struct tlv *pdol_data_tlv = NULL;
	if (strlen(cmd) < 1)
		return usage_emv_exec();
	
	int cmdp = 0;
	while(param_getchar(cmd, cmdp) != 0x00) {
		char c = param_getchar(cmd, cmdp);
		if ((c == '-') && (param_getlength(cmd, cmdp) == 2))
			switch (param_getchar_indx(cmd, 1, cmdp)) {
				case 'h':
				case 'H':
					return usage_emv_exec();
				case 's':
				case 'S':
					activateField = true;
					break;
				case 'a':
				case 'A':
					showAPDU = true;
					break;
				case 't':
				case 'T':
					decodeTLV = true;
					break;
				case 'f':
				case 'F':
					forceSearch = true;
					break;
				case 'x':
				case 'X':
					TrType = TT_VSDC;
					break;
				case 'v':
				case 'V':
					TrType = TT_QVSDCMCHIP;
					break;
				case 'c':
				case 'C':
					TrType = TT_CDA;
					break;
				case 'g':
				case 'G':
					GenACGPO = true;
					break;
				default:
					PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar_indx(cmd, 1, cmdp));
					return 1;
		}
		cmdp++;
	}
	
	// init applets list tree
	const char *al = "Applets list";
	tlvSelect = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

	// Application Selection
	// https://www.openscdp.org/scripts/tutorial/emv/applicationselection.html
	if (!forceSearch) {
		// PPSE
		PrintAndLogEx(NORMAL, "\n* PPSE.");
		SetAPDULogging(showAPDU);
		res = EMVSearchPSE(activateField, true, decodeTLV, tlvSelect);

		// check PPSE and select application id
		if (!res) {	
			TLVPrintAIDlistFromSelectTLV(tlvSelect);
			EMVSelectApplication(tlvSelect, AID, &AIDlen);
		}
	}
	
	// Search
	if (!AIDlen) {
		PrintAndLogEx(NORMAL, "\n* Search AID in list.");
		SetAPDULogging(false);
		if (EMVSearch(activateField, true, decodeTLV, tlvSelect)) {
			dreturn(2);
		}

		// check search and select application id
		TLVPrintAIDlistFromSelectTLV(tlvSelect);
		EMVSelectApplication(tlvSelect, AID, &AIDlen);
	}
	
	// Init TLV tree
	const char *alr = "Root terminal TLV tree";
	tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);
	
	// check if we found EMV application on card
	if (!AIDlen) {
		PrintAndLogEx(WARNING, "Can't select AID. EMV AID not found");
		dreturn(2);
	}
	
	// Select
	PrintAndLogEx(NORMAL, "\n* Selecting AID:%s", sprint_hex_inrow(AID, AIDlen));
	SetAPDULogging(showAPDU);
	res = EMVSelect(false, true, AID, AIDlen, buf, sizeof(buf), &len, &sw, tlvRoot);
	
	if (res) {	
		PrintAndLogEx(WARNING, "Can't select AID (%d). Exit...", res);
		dreturn(3);
	}
	
	if (decodeTLV)
		TLVPrintFromBuffer(buf, len);
	
	PrintAndLogEx(NORMAL, "* Selected.");	
	PrintAndLogEx(NORMAL, "\n* Init transaction parameters.");

    //9F66:(Terminal Transaction Qualifiers (TTQ)) len:4
	char *qVSDC = "\x26\x00\x00\x00";
	if (GenACGPO) {
		qVSDC = "\x26\x80\x00\x00";
	}
	switch(TrType) {
		case TT_MSD:
			TLV_ADD(0x9F66, "\x86\x00\x00\x00"); // MSD
			break;
		// not standard for contactless. just for test.
		case TT_VSDC:  
			TLV_ADD(0x9F66, "\x46\x00\x00\x00"); // VSDC
			break;
		case TT_QVSDCMCHIP:
			TLV_ADD(0x9F66, qVSDC); // qVSDC
			break;
		case TT_CDA:
			TLV_ADD(0x9F66, qVSDC); // qVSDC (VISA CDA not enabled)
			break;
		default:
			TLV_ADD(0x9F66, "\x26\x00\x00\x00"); // qVSDC
			break;
	}
	
    //9F02:(Amount, authorized (Numeric)) len:6
	TLV_ADD(0x9F02, "\x00\x00\x00\x00\x01\x00");
    //9F1A:(Terminal Country Code) len:2
	TLV_ADD(0x9F1A, "ru");
    //5F2A:(Transaction Currency Code) len:2
    // USD 840, EUR 978, RUR 810, RUB 643, RUR 810(old), UAH 980, AZN 031, n/a 999
	TLV_ADD(0x5F2A, "\x09\x80");
    //9A:(Transaction Date) len:3
	TLV_ADD(0x9A,   "\x00\x00\x00");
    //9C:(Transaction Type) len:1   |  00 => Goods and service #01 => Cash
	TLV_ADD(0x9C,   "\x00");
	// 9F37 Unpredictable Number len:4
	TLV_ADD(0x9F37, "\x01\x02\x03\x04");
	// 9F6A Unpredictable Number (MSD for UDOL) len:4
	TLV_ADD(0x9F6A, "\x01\x02\x03\x04");

	TLVPrintFromTLV(tlvRoot); // TODO delete!!!
	
	PrintAndLogEx(NORMAL, "\n* Calc PDOL.");
	pdol_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x9f38, NULL), tlvRoot, 0x83);
	if (!pdol_data_tlv){
		PrintAndLogEx(WARNING, "Error: can't create PDOL TLV.");
		dreturn(4);
	}
	
	size_t pdol_data_tlv_data_len;
	unsigned char *pdol_data_tlv_data = tlv_encode(pdol_data_tlv, &pdol_data_tlv_data_len);
	if (!pdol_data_tlv_data) {
		PrintAndLogEx(WARNING, "Error: can't create PDOL data.");
		dreturn(4);
	}
	PrintAndLogEx(NORMAL, "PDOL data[%d]: %s", pdol_data_tlv_data_len, sprint_hex(pdol_data_tlv_data, pdol_data_tlv_data_len));

	PrintAndLogEx(NORMAL, "\n* GPO.");
	res = EMVGPO(true, pdol_data_tlv_data, pdol_data_tlv_data_len, buf, sizeof(buf), &len, &sw, tlvRoot);
	
	free(pdol_data_tlv_data);
	//free(pdol_data_tlv); --- free on exit.
	
	if (res) {	
		PrintAndLogEx(NORMAL, "GPO error(%d): %4x. Exit...", res, sw);
		dreturn(5);
	}

	// process response template format 1 [id:80  2b AIP + x4b AFL] and format 2 [id:77 TLV]
	if (buf[0] == 0x80) {
		if (decodeTLV){
			PrintAndLogEx(NORMAL, "GPO response format1:");
			TLVPrintFromBuffer(buf, len);
		}
		
		if (len < 4 || (len - 4) % 4) {
			PrintAndLogEx(WARNING, "Error: GPO response format1 parsing error. length=%d", len);
		} else {
			// AIP
			struct tlvdb * f1AIP = tlvdb_fixed(0x82, 2, buf + 2);
			tlvdb_add(tlvRoot, f1AIP);
			if (decodeTLV){
				PrintAndLogEx(NORMAL, "\n* * Decode response format 1 (0x80) AIP and AFL:");
				TLVPrintFromTLV(f1AIP);
			}

			// AFL
			struct tlvdb * f1AFL = tlvdb_fixed(0x94, len - 4, buf + 2 + 2);
			tlvdb_add(tlvRoot, f1AFL);
			if (decodeTLV)
				TLVPrintFromTLV(f1AFL);
		}		
	} else {
		if (decodeTLV)
			TLVPrintFromBuffer(buf, len);
	}
	
	// extract PAN from track2
	{
		const struct tlv *track2 = tlvdb_get(tlvRoot, 0x57, NULL);
		if (!tlvdb_get(tlvRoot, 0x5a, NULL) && track2 && track2->len >= 8) {
			struct tlvdb *pan = GetPANFromTrack2(track2);
			if (pan) {
				tlvdb_add(tlvRoot, pan); 
				
				const struct tlv *pantlv = tlvdb_get(tlvRoot, 0x5a, NULL);	
				PrintAndLogEx(NORMAL, "\n* * Extracted PAN from track2: %s", sprint_hex(pantlv->value, pantlv->len));
			} else {
				PrintAndLogEx(NORMAL, "\n* * WARNING: Can't extract PAN from track2.");
			}
		}
	}
	
	PrintAndLogEx(NORMAL, "\n* Read records from AFL.");
	const struct tlv *AFL = tlvdb_get(tlvRoot, 0x94, NULL);

	if (!AFL || !AFL->len)
		PrintAndLogEx(NORMAL, "WARNING: AFL not found.");
	
	while (AFL && AFL->len) {
		if (AFL->len % 4) {
			PrintAndLogEx(WARNING, "Error: Wrong AFL length: %d", AFL->len);
			break;
		}

		for (int i = 0; i < AFL->len / 4; i++) {
			uint8_t SFI = AFL->value[i * 4 + 0] >> 3;
			uint8_t SFIstart = AFL->value[i * 4 + 1];
			uint8_t SFIend = AFL->value[i * 4 + 2];
			uint8_t SFIoffline = AFL->value[i * 4 + 3];
			
			PrintAndLogEx(NORMAL, "* * SFI[%02x] start:%02x end:%02x offline:%02x", SFI, SFIstart, SFIend, SFIoffline);
			if (SFI == 0 || SFI == 31 || SFIstart == 0 || SFIstart > SFIend) {
				PrintAndLogEx(NORMAL, "SFI ERROR! Skipped...");
				continue;
			}
			
			for (int n = SFIstart; n <= SFIend; n++) {
				PrintAndLogEx(NORMAL, "* * * SFI[%02x] %d", SFI, n);
				
				res = EMVReadRecord(true, SFI, n, buf, sizeof(buf), &len, &sw, tlvRoot);
				if (res) {
					PrintAndLogEx(WARNING, "Error SFI[%02x]. APDU error %4x", SFI, sw);
					continue;
				}
				
				if (decodeTLV) {
					TLVPrintFromBuffer(buf, len);
					PrintAndLogEx(NORMAL, "");
				}
				
				// Build Input list for Offline Data Authentication
				// EMV 4.3 book3 10.3, page 96
				if (SFIoffline) {
					if (SFI < 11) {
						const unsigned char *abuf = buf;
						size_t elmlen = len;
						struct tlv e;
						if (tlv_parse_tl(&abuf, &elmlen, &e)) {
							memcpy(&ODAiList[ODAiListLen], &buf[len - elmlen], elmlen);
							ODAiListLen += elmlen;
						} else {
							PrintAndLogEx(WARNING, "Error SFI[%02x]. Creating input list for Offline Data Authentication error.", SFI);
						}
					} else {
						memcpy(&ODAiList[ODAiListLen], buf, len);
						ODAiListLen += len;
					}
				}
			}
		}
		
		break;
	}	
	
	// copy Input list for Offline Data Authentication
	if (ODAiListLen) {
		struct tlvdb *oda = tlvdb_fixed(0x21, ODAiListLen, ODAiList); // not a standard tag
		tlvdb_add(tlvRoot, oda); 
		PrintAndLogEx(NORMAL, "* Input list for Offline Data Authentication added to TLV. len=%d \n", ODAiListLen);
	}	
	
	// get AIP
	const struct tlv *AIPtlv = tlvdb_get(tlvRoot, 0x82, NULL);	
	uint16_t AIP = AIPtlv->value[0] + AIPtlv->value[1] * 0x100;
	PrintAndLogEx(NORMAL, "* * AIP=%04x", AIP);

	// SDA
	if (AIP & 0x0040) {
		PrintAndLogEx(NORMAL, "\n* SDA");
		trSDA(tlvRoot);
	}

	// DDA
	if (AIP & 0x0020) {
		PrintAndLogEx(NORMAL, "\n* DDA");		
		trDDA(decodeTLV, tlvRoot);
	}	
	
	// transaction check

	// qVSDC
	if (TrType == TT_QVSDCMCHIP|| TrType == TT_CDA){
		// 9F26: Application Cryptogram
		const struct tlv *AC = tlvdb_get(tlvRoot, 0x9F26, NULL);
		if (AC) {
			PrintAndLogEx(NORMAL, "\n--> qVSDC transaction.");
			PrintAndLogEx(NORMAL, "* AC path");
			
			// 9F36: Application Transaction Counter (ATC)
			const struct tlv *ATC = tlvdb_get(tlvRoot, 0x9F36, NULL);
			if (ATC) {
			
				// 9F10: Issuer Application Data - optional
				const struct tlv *IAD = tlvdb_get(tlvRoot, 0x9F10, NULL);

				// print AC data
				PrintAndLogEx(NORMAL, "ATC: %s", sprint_hex(ATC->value, ATC->len));
				PrintAndLogEx(NORMAL, "AC: %s", sprint_hex(AC->value, AC->len));
				if (IAD){
					PrintAndLogEx(NORMAL, "IAD: %s", sprint_hex(IAD->value, IAD->len));
					
					if (IAD->len >= IAD->value[0] + 1) {
						PrintAndLogEx(NORMAL, "\tKey index:  0x%02x", IAD->value[1]);
						PrintAndLogEx(NORMAL, "\tCrypto ver: 0x%02x(%03d)", IAD->value[2], IAD->value[2]);
						PrintAndLogEx(NORMAL, "\tCVR:", sprint_hex(&IAD->value[3], IAD->value[0] - 2));
						struct tlvdb * cvr = tlvdb_fixed(0x20, IAD->value[0] - 2, &IAD->value[3]);
						TLVPrintFromTLVLev(cvr, 1);
					}
				} else {
					PrintAndLogEx(NORMAL, "WARNING: IAD not found.");
				}
				
			} else {
				PrintAndLogEx(WARNING, "Error AC: Application Transaction Counter (ATC) not found.");
			}
		}
	}
	
	// Mastercard M/CHIP
	if (GetCardPSVendor(AID, AIDlen) == CV_MASTERCARD && (TrType == TT_QVSDCMCHIP || TrType == TT_CDA)){
		const struct tlv *CDOL1 = tlvdb_get(tlvRoot, 0x8c, NULL);
		if (CDOL1 && GetCardPSVendor(AID, AIDlen) == CV_MASTERCARD) { // and m/chip transaction flag
			PrintAndLogEx(NORMAL, "\n--> Mastercard M/Chip transaction.");

			PrintAndLogEx(NORMAL, "* * Generate challenge");
			res = EMVGenerateChallenge(true, buf, sizeof(buf), &len, &sw, tlvRoot);
			if (res) {
				PrintAndLogEx(WARNING, "Error GetChallenge. APDU error %4x", sw);
				dreturn(6);
			}
			if (len < 4) {
				PrintAndLogEx(WARNING, "Error GetChallenge. Wrong challenge length %d", len);
				dreturn(6);
			}
			
			// ICC Dynamic Number
			struct tlvdb * ICCDynN = tlvdb_fixed(0x9f4c, len, buf);
			tlvdb_add(tlvRoot, ICCDynN);
			if (decodeTLV){
				PrintAndLogEx(NORMAL, "\n* * ICC Dynamic Number:");
				TLVPrintFromTLV(ICCDynN);
			}
			
			PrintAndLogEx(NORMAL, "* * Calc CDOL1");
			struct tlv *cdol_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x8c, NULL), tlvRoot, 0x01); // 0x01 - dummy tag
			if (!cdol_data_tlv){
				PrintAndLogEx(WARNING, "Error: can't create CDOL1 TLV.");
				dreturn(6);
			}
			PrintAndLogEx(NORMAL, "CDOL1 data[%d]: %s", cdol_data_tlv->len, sprint_hex(cdol_data_tlv->value, cdol_data_tlv->len));
			
			PrintAndLogEx(NORMAL, "* * AC1");
			// EMVAC_TC + EMVAC_CDAREQ --- to get SDAD
			res = EMVAC(true, (TrType == TT_CDA) ? EMVAC_TC + EMVAC_CDAREQ : EMVAC_TC, (uint8_t *)cdol_data_tlv->value, cdol_data_tlv->len, buf, sizeof(buf), &len, &sw, tlvRoot);
			
			if (res) {	
				PrintAndLogEx(NORMAL, "AC1 error(%d): %4x. Exit...", res, sw);
				dreturn(7);
			}
			
			if (decodeTLV)
				TLVPrintFromBuffer(buf, len);
			
			// CDA
			PrintAndLogEx(NORMAL, "\n* CDA:");
			struct tlvdb *ac_tlv = tlvdb_parse_multi(buf, len);
			res = trCDA(tlvRoot, ac_tlv, pdol_data_tlv, cdol_data_tlv);
			if (res) {	
				PrintAndLogEx(NORMAL, "CDA error (%d)", res);
			}
			free(ac_tlv);
			free(cdol_data_tlv);
			
			PrintAndLogEx(NORMAL, "\n* M/Chip transaction result:");
			// 9F27: Cryptogram Information Data (CID)
			const struct tlv *CID = tlvdb_get(tlvRoot, 0x9F27, NULL);
			if (CID) {
				emv_tag_dump(CID, stdout, 0);
				PrintAndLogEx(NORMAL, "------------------------------");
				if (CID->len > 0) {
					switch(CID->value[0] & EMVAC_AC_MASK){
						case EMVAC_AAC:
							PrintAndLogEx(NORMAL, "Transaction DECLINED.");
							break;
						case EMVAC_TC:
							PrintAndLogEx(NORMAL, "Transaction approved OFFLINE.");
							break;
						case EMVAC_ARQC:
							PrintAndLogEx(NORMAL, "Transaction approved ONLINE.");
							break;
						default:
							PrintAndLogEx(WARNING, "Error: CID transaction code error %2x", CID->value[0] & EMVAC_AC_MASK);
							break;
					}
				} else {
					PrintAndLogEx(WARNING, "Error: Wrong CID length %d", CID->len);
				}
			} else {
				PrintAndLogEx(WARNING, "Error: CID(9F27) not found.");
			}
		
		}
	}
		
	// MSD
	if (AIP & 0x8000 && TrType == TT_MSD) { 
		PrintAndLogEx(NORMAL, "\n--> MSD transaction.");
		
		PrintAndLogEx(NORMAL, "* MSD dCVV path. Check dCVV");

		const struct tlv *track2 = tlvdb_get(tlvRoot, 0x57, NULL);
		if (track2) {
			PrintAndLogEx(NORMAL, "Track2: %s", sprint_hex(track2->value, track2->len));

			struct tlvdb *dCVV = GetdCVVRawFromTrack2(track2);
			PrintAndLogEx(NORMAL, "dCVV raw data:");
			TLVPrintFromTLV(dCVV);
			
			if (GetCardPSVendor(AID, AIDlen) == CV_MASTERCARD) {
				PrintAndLogEx(NORMAL, "\n* Mastercard calculate UDOL");

				// UDOL (9F69)
				const struct tlv *UDOL = tlvdb_get(tlvRoot, 0x9F69, NULL);
				// UDOL(9F69) default: 9F6A (Unpredictable number) 4 bytes
				const struct tlv defUDOL = {
					.tag = 0x01,
					.len = 3,
					.value = (uint8_t *)"\x9f\x6a\x04",
				};
				if (!UDOL)
					PrintAndLogEx(NORMAL, "Use default UDOL.");

				struct tlv *udol_data_tlv = dol_process(UDOL ? UDOL : &defUDOL, tlvRoot, 0x01); // 0x01 - dummy tag
				if (!udol_data_tlv){
					PrintAndLogEx(WARNING, "Error: can't create UDOL TLV.");
					dreturn(8);
				}

				PrintAndLogEx(NORMAL, "UDOL data[%d]: %s", udol_data_tlv->len, sprint_hex(udol_data_tlv->value, udol_data_tlv->len));
				
				PrintAndLogEx(NORMAL, "\n* Mastercard compute cryptographic checksum(UDOL)");
				
				res = MSCComputeCryptoChecksum(true, (uint8_t *)udol_data_tlv->value, udol_data_tlv->len, buf, sizeof(buf), &len, &sw, tlvRoot);
				if (res) {
					PrintAndLogEx(WARNING, "Error Compute Crypto Checksum. APDU error %4x", sw);
					free(udol_data_tlv);
					dreturn(9);
				}
				
				if (decodeTLV) {
					TLVPrintFromBuffer(buf, len);
					PrintAndLogEx(NORMAL, "");
				}
				free(udol_data_tlv);

			}
		} else {
			PrintAndLogEx(WARNING, "Error MSD: Track2 data not found.");
		}
	}

	DropField();
	
	// Destroy TLV's
	free(pdol_data_tlv);
	tlvdb_free(tlvSelect);
	tlvdb_free(tlvRoot);

	PrintAndLogEx(NORMAL, "\n* Transaction completed.");
	return 0;
}

int usage_emv_getrnd(void){
	PrintAndLogEx(NORMAL, "retrieve the UN number from a terminal");
	PrintAndLogEx(NORMAL, "Usage:  hf emv getrnd [h]");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "      h             : this help");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "      hf emv getrnd");
	return 0;
}

//retrieve the UN number from a terminal
int CmdHfEMVGetrng(const char *Cmd) {
	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'h' || cmdp == 'H') return usage_emv_getrnd();

	return 0;
}

int CmdHfEMVList(const char *Cmd) {
	return CmdTraceList("7816");
}

int CmdHFEMVTest(const char *cmd) {
	return ExecuteCryptoTests(true);
}
static command_t CommandTable[] =  {
	{"help",	CmdHelp,		1,	"This help"},
	{"exec",	CmdHFEMVExec,	0,	"Executes EMV contactless transaction."},
	{"pse",		CmdHFEMVPPSE,	0,	"Execute PPSE. It selects 2PAY.SYS.DDF01 or 1PAY.SYS.DDF01 directory."},
	{"search",	CmdHFEMVSearch,	0,	"Try to select all applets from applets list and print installed applets."},
	{"select",	CmdHFEMVSelect,	0,	"Select applet."},
	{"test",	CmdHFEMVTest,	0,	"Crypto logic test."},
	/*
	{"getrng",		CmdHfEMVGetrng,	  0, "get random number from terminal"}, 
	{"eload",		CmdHfEmvELoad, 	  0, "load EMV tag into device"},
	{"dump",		CmdHfEmvDump,	  0, "dump EMV tag values"},
	{"sim",			CmdHfEmvSim,	  0, "simulate EMV tag"},
	{"clone",		CmdHfEmvClone,	  0, "clone an EMV tag"}, 
	*/
	{"list",	CmdHfEMVList,	  0, "[Deprecated] List ISO7816 history"}, 
	{NULL, NULL, 0, NULL}
};

int CmdHFEMV(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
