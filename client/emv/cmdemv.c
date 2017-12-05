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

static int CmdHelp(const char *Cmd);

int usage_emv_select(void) {
	PrintAndLog("Executes select applet command:\n");
	PrintAndLog("Usage:  hf emv select [-s][-k][-a][-t] <HEX applet AID>\n");
	PrintAndLog("  Options:");
	PrintAndLog("  -s       : select card");
	PrintAndLog("  -k       : keep field for next command");
	PrintAndLog("  -a       : show APDU reqests and responses\n");
	PrintAndLog("  -t       : TLV decode results\n");
	PrintAndLog("Samples:");
	PrintAndLog(" hf emv select -s a00000000101        -> select card, select applet");
	PrintAndLog(" hf emv select -s -t a00000000101     -> select card, select applet, show result in TLV");
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
					PrintAndLog("Unknown parameter '%c'", param_getchar_indx(cmd, 1, cmdp));
					return 1;
		}

		if (isxdigit(c)) {
			switch(param_gethex_to_eol(cmd, cmdp, data, sizeof(data), &datalen)) {
			case 1:
				PrintAndLog("Invalid HEX value.");
				return 1;
			case 2:
				PrintAndLog("AID too large.");
				return 1;
			case 3:
				PrintAndLog("Hex must have even number of digits.");
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
		PrintAndLog("APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff)); 
	
	if (res)
		return res;
	
	if (decodeTLV)
		TLVPrintFromBuffer(buf, len);

	return 0;
}

int usage_emv_search(void) {
	PrintAndLog("Tries to select all applets from applet list:\n");
	PrintAndLog("Usage:  hf emv search [-s][-k][-a][-t]\n");
	PrintAndLog("  Options:");
	PrintAndLog("  -s       : select card");
	PrintAndLog("  -k       : keep field for next command");
	PrintAndLog("  -a       : show APDU reqests and responses\n");
	PrintAndLog("  -t       : TLV decode results of selected applets\n");
	PrintAndLog("Samples:");
	PrintAndLog(" hf emv search -s         -> select card and search");
	PrintAndLog(" hf emv search -s -t      -> select card, search and show result in TLV");
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
					PrintAndLog("Unknown parameter '%c'", param_getchar_indx(cmd, 1, cmdp));
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
	
	PrintAndLog("Search completed.");

	// print list here
	if (!decodeTLV) {  
		TLVPrintAIDlistFromSelectTLV(t);
	}
	
	tlvdb_free(t);
	
	return 0;
}

int usage_emv_ppse(void) {
	PrintAndLog("Executes PSE/PPSE select command. It returns list of applet on the card:\n");
	PrintAndLog("Usage:  hf emv pse [-s][-k][-1][-2][-a][-t]\n");
	PrintAndLog("  Options:");
	PrintAndLog("  -s       : select card");
	PrintAndLog("  -k       : keep field for next command");
	PrintAndLog("  -1       : ppse (1PAY.SYS.DDF01)");
	PrintAndLog("  -2       : pse (2PAY.SYS.DDF01)");
	PrintAndLog("  -a       : show APDU reqests and responses\n");
	PrintAndLog("  -t       : TLV decode results\n");
	PrintAndLog("Samples:");
	PrintAndLog(" hf emv pse -s -1         -> select, get pse");
	PrintAndLog(" hf emv pse -s -k -2      -> select, get ppse, keep field");
	PrintAndLog(" hf emv pse -s -t -2      -> select, get ppse, show result in TLV");
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
					PrintAndLog("Unknown parameter '%c'", param_getchar_indx(cmd, 1, cmdp));
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
		PrintAndLog("APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff)); 

	if (res)
		return res;	
	
	if (decodeTLV)
		TLVPrintFromBuffer(buf, len);

	return 0;
}

int usage_emv_exec(void) {
	PrintAndLog("Executes EMV contactless transaction:\n");
	PrintAndLog("Usage:  hf emv exec [-s][-a][-t]\n");
	PrintAndLog("  Options:");
	PrintAndLog("  -s       : select card");
	PrintAndLog("  -a       : show APDU reqests and responses\n");
	PrintAndLog("  -t       : TLV decode results\n");
	PrintAndLog("  -f       : force search AID. Search AID instead of execute PPSE.\n");
	PrintAndLog("  -v       : transaction type - qVSDC or M/Chip.\n");
	PrintAndLog("  -c       : transaction type - qVSDC or M/Chip plus CDA (SDAD generation).\n");
	PrintAndLog("  -x       : transaction type - VSDC. For test only. Not a standart behavior.\n");
	PrintAndLog("By default : transaction type - MSD.\n");
	PrintAndLog("Samples:");
	PrintAndLog(" hf emv pse -s            -> select card");
	PrintAndLog(" hf emv pse -s -t -a      -> select card, show responses in TLV, show APDU");
	return 0;
}

int CmdHFEMVExec(const char *cmd) {
	bool activateField = false;
	bool showAPDU = false;
	bool decodeTLV = false;
	bool forceSearch = false;
	enum TransactionType TrType = TT_MSD;

	uint8_t buf[APDU_RES_LEN] = {0};
	size_t len = 0;
	uint16_t sw = 0;
	uint8_t AID[APDU_AID_LEN] = {0};
	size_t AIDlen = 0;
	
	int res;
	
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
				default:
					PrintAndLog("Unknown parameter '%c'", param_getchar_indx(cmd, 1, cmdp));
					return 1;
		}
		cmdp++;
	}
	
	// init applets list tree
	struct tlvdb *tlvSelect = NULL;
	const char *al = "Applets list";
	tlvSelect = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

	// Application Selection
	// https://www.openscdp.org/scripts/tutorial/emv/applicationselection.html
	if (!forceSearch) {
		// PPSE
		PrintAndLog("\n* PPSE.");
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
		PrintAndLog("\n* Search AID in list.");
		SetAPDULogging(false);
		if (EMVSearch(activateField, true, decodeTLV, tlvSelect)) {
			tlvdb_free(tlvSelect);
			return 2;
		}

		// check search and select application id
		TLVPrintAIDlistFromSelectTLV(tlvSelect);
		EMVSelectApplication(tlvSelect, AID, &AIDlen);
	}
	
	// Init TLV tree
	struct tlvdb *tlvRoot = NULL;
	const char *alr = "Root terminal TLV tree";
	tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);
	
	// check if we found EMV application on card
	if (!AIDlen) {
		PrintAndLog("Can't select AID. EMV AID not found");
		return 2;
	}
	
	// Select
	PrintAndLog("\n* Selecting AID:%s", sprint_hex_inrow(AID, AIDlen));
	SetAPDULogging(showAPDU);
	res = EMVSelect(false, true, AID, AIDlen, buf, sizeof(buf), &len, &sw, tlvRoot);
	
	if (res) {	
		PrintAndLog("Can't select AID (%d). Exit...", res);
		return 3;
	}
	
	if (decodeTLV)
		TLVPrintFromBuffer(buf, len);
	
	PrintAndLog("* Selected.");	
	PrintAndLog("\n* Init transaction parameters.");

    //9F66:(Terminal Transaction Qualifiers (TTQ)) len:4
	switch(TrType) {
		case TT_MSD:
			TLV_ADD(0x9F66, "\x86\x00\x00\x00"); // MSD
			break;
		// not standart for contactless. just for test.
		case TT_VSDC:  
			TLV_ADD(0x9F66, "\x46\x00\x00\x00"); // VSDC
			break;
		case TT_QVSDCMCHIP:
			TLV_ADD(0x9F66, "\x26\x00\x00\x00"); // qVSDC
			break;
		case TT_CDA:
			TLV_ADD(0x9F66, "\x86\x80\x00\x00"); // CDA
			break;
		default:
			TLV_ADD(0x9F66, "\x26\x00\x00\x00"); // qVSDC
			break;
	}
    //9F02:(Amount, Authorised (Numeric)) len:6
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
	
	PrintAndLog("\n* Calc PDOL.");
	struct tlv *pdol_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x9f38, NULL), tlvRoot, 0x83);
	if (!pdol_data_tlv){
		PrintAndLog("ERROR: can't create PDOL TLV.");
		return 4;
	}
	
	size_t pdol_data_tlv_data_len;
	unsigned char *pdol_data_tlv_data = tlv_encode(pdol_data_tlv, &pdol_data_tlv_data_len);
	if (!pdol_data_tlv_data) {
		PrintAndLog("ERROR: can't create PDOL data.");
		return 4;
	}
	PrintAndLog("PDOL data[%d]: %s", pdol_data_tlv_data_len, sprint_hex(pdol_data_tlv_data, pdol_data_tlv_data_len));

	PrintAndLog("\n* GPO.");
	res = EMVGPO(true, pdol_data_tlv_data, pdol_data_tlv_data_len, buf, sizeof(buf), &len, &sw, tlvRoot);
	
	free(pdol_data_tlv_data);
	free(pdol_data_tlv);
	
	if (res) {	
		PrintAndLog("GPO error(%d): %4x. Exit...", res, sw);
		return 5;
	}

	// process response template format 1 [id:80  2b AIP + x4b AFL] and format 2 [id:77 TLV]
	if (buf[0] == 0x80) {
		if (decodeTLV){
			PrintAndLog("GPO response format1:");
			TLVPrintFromBuffer(buf, len);
		}
		
		if (len < 4 || (len - 4) % 4) {
			PrintAndLog("ERROR: GPO response format1 parsing error. length=%d", len);
		} else {
			// AIP
			struct tlvdb * f1AIP = tlvdb_fixed(0x82, 2, buf + 2);
			tlvdb_add(tlvRoot, f1AIP);
			if (decodeTLV){
				PrintAndLog("\n* * Decode response format 1 (0x80) AIP and AFL:");
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
				PrintAndLog("\n* * Extracted PAN from track2: %s", sprint_hex(pantlv->value, pantlv->len));
			} else {
				PrintAndLog("\n* * WARNING: Can't extract PAN from track2.");
			}
		}
	}
	
	PrintAndLog("\n* Read records from AFL.");
	const struct tlv *AFL = tlvdb_get(tlvRoot, 0x94, NULL);

	if (!AFL || !AFL->len)
		PrintAndLog("WARNING: AFL not found.");
	
	while (AFL && AFL->len) {
		if (AFL->len % 4) {
			PrintAndLog("ERROR: Wrong AFL length: %d", AFL->len);
			break;
		}

		for (int i = 0; i < AFL->len / 4; i++) {
			uint8_t SFI = AFL->value[i * 4 + 0] >> 3;
			uint8_t SFIstart = AFL->value[i * 4 + 1];
			uint8_t SFIend = AFL->value[i * 4 + 2];
			uint8_t SFIoffline = AFL->value[i * 4 + 3];
			
			PrintAndLog("* * SFI[%02x] start:%02x end:%02x offline:%02x", SFI, SFIstart, SFIend, SFIoffline);
			if (SFI == 0 || SFI == 31 || SFIstart == 0 || SFIstart > SFIend) {
				PrintAndLog("SFI ERROR! Skipped...");
				continue;
			}
			
			for (int n = SFIstart; n <= SFIend; n++) {
				PrintAndLog("* * * SFI[%02x] %d", SFI, n);
				
				res = EMVReadRecord(true, SFI, n, buf, sizeof(buf), &len, &sw, tlvRoot);
				if (res) {
					PrintAndLog("ERROR SFI[%02x]. APDU error %4x", SFI, sw);
					continue;
				}
				
				if (decodeTLV) {
					TLVPrintFromBuffer(buf, len);
					PrintAndLog("");
				}
				
				if (SFIoffline) {
					// here will be offline records storing...
					// dont foget: if (sfi < 11)
				}
			}
		}		
		break;
	}	
	
	// get AIP
	const struct tlv *AIPtlv = tlvdb_get(tlvRoot, 0x82, NULL);	
	uint16_t AIP = AIPtlv->value[0] + AIPtlv->value[1] * 0x100;
	PrintAndLog("* * AIP=%04x", AIP);

	// SDA
	if (AIP & 0x0040) {
		PrintAndLog("\n* SDA");
		trSDA(AID, AIDlen, tlvRoot);
	}

	// DDA
	if (AIP & 0x0020) {
		PrintAndLog("\n* DDA");		
	}	
	// transaction check

	// qVSDC
	if (TrType == TT_QVSDCMCHIP|| TrType == TT_CDA){
		// 9F26: Application Cryptogram
		const struct tlv *AC = tlvdb_get(tlvRoot, 0x9F26, NULL);
		if (AC) {
			PrintAndLog("\n--> qVSDC transaction.");
			PrintAndLog("* AC path");
			
			// 9F36: Application Transaction Counter (ATC)
			const struct tlv *ATC = tlvdb_get(tlvRoot, 0x9F36, NULL);
			if (ATC) {
			
				// 9F10: Issuer Application Data - optional
				const struct tlv *IAD = tlvdb_get(tlvRoot, 0x9F10, NULL);

				// print AC data
				PrintAndLog("ATC: %s", sprint_hex(ATC->value, ATC->len));
				PrintAndLog("AC: %s", sprint_hex(AC->value, AC->len));
				if (IAD){
					PrintAndLog("IAD: %s", sprint_hex(IAD->value, IAD->len));
					
					if (IAD->len >= IAD->value[0] + 1) {
						PrintAndLog("\tKey index:  0x%02x", IAD->value[1]);
						PrintAndLog("\tCrypto ver: 0x%02x(%03d)", IAD->value[2], IAD->value[2]);
						PrintAndLog("\tCVR:", sprint_hex(&IAD->value[3], IAD->value[0] - 2));
						struct tlvdb * cvr = tlvdb_fixed(0x20, IAD->value[0] - 2, &IAD->value[3]);
						TLVPrintFromTLVLev(cvr, 1);
					}
				} else {
					PrintAndLog("WARNING: IAD not found.");
				}
				
			} else {
				PrintAndLog("ERROR AC: Application Transaction Counter (ATC) not found.");
			}
		}
	}
	
	// Mastercard M/CHIP
	if (GetCardPSVendor(AID, AIDlen) == CV_MASTERCARD && (TrType == TT_QVSDCMCHIP || TrType == TT_CDA)){
		const struct tlv *CDOL1 = tlvdb_get(tlvRoot, 0x8c, NULL);
		if (CDOL1 && GetCardPSVendor(AID, AIDlen) == CV_MASTERCARD) { // and m/chip transaction flag
			PrintAndLog("\n--> Mastercard M/Chip transaction.");

			PrintAndLog("* * Generate challenge");
			res = EMVGenerateChallenge(true, buf, sizeof(buf), &len, &sw, tlvRoot);
			if (res) {
				PrintAndLog("ERROR GetChallenge. APDU error %4x", sw);
				return 5;
			}
			if (len < 4) {
				PrintAndLog("ERROR GetChallenge. Wrong challenge length %d", len);
				return 5;
			}
			
			// ICC Dynamic Number
			struct tlvdb * ICCDynN = tlvdb_fixed(0x9f4c, len, buf);
			tlvdb_add(tlvRoot, ICCDynN);
			if (decodeTLV){
				PrintAndLog("\n* * ICC Dynamic Number:");
				TLVPrintFromTLV(ICCDynN);
			}
			
			PrintAndLog("* * Calc CDOL1");
			struct tlv *cdol_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x8c, NULL), tlvRoot, 0x01); // 0x01 - dummy tag
			if (!cdol_data_tlv){
				PrintAndLog("ERROR: can't create CDOL1 TLV.");
				return 4;
			}
			PrintAndLog("CDOL1 data[%d]: %s", cdol_data_tlv->len, sprint_hex(cdol_data_tlv->value, cdol_data_tlv->len));
			
			PrintAndLog("* * AC1");
			// EMVAC_TC + EMVAC_CDAREQ --- to get SDAD
			res = EMVAC(true, (TrType == TT_CDA) ? EMVAC_TC + EMVAC_CDAREQ : EMVAC_TC, (uint8_t *)cdol_data_tlv->value, cdol_data_tlv->len, buf, sizeof(buf), &len, &sw, tlvRoot);
			
			free(cdol_data_tlv);
			
			if (res) {	
				PrintAndLog("AC1 error(%d): %4x. Exit...", res, sw);
				return 5;
			}
			
			if (decodeTLV)
				TLVPrintFromBuffer(buf, len);
			
			PrintAndLog("* M/Chip transaction result:");
			// 9F27: Cryptogram Information Data (CID)
			const struct tlv *CID = tlvdb_get(tlvRoot, 0x9F27, NULL);
			if (CID) {
				emv_tag_dump(CID, stdout, 0);
				PrintAndLog("------------------------------");
				if (CID->len > 0) {
					switch(CID->value[0] & EMVAC_AC_MASK){
						case EMVAC_AAC:
							PrintAndLog("Transaction DECLINED.");
							break;
						case EMVAC_TC:
							PrintAndLog("Transaction approved OFFLINE.");
							break;
						case EMVAC_ARQC:
							PrintAndLog("Transaction approved ONLINE.");
							break;
						default:
							PrintAndLog("ERROR: CID transaction code error %2x", CID->value[0] & EMVAC_AC_MASK);
							break;
					}
				} else {
					PrintAndLog("ERROR: Wrong CID length %d", CID->len);
				}
			} else {
				PrintAndLog("ERROR: CID(9F27) not found.");
			}
		
		}
	}
		
	// MSD
	if (AIP & 0x8000 && TrType == TT_MSD) { 
		PrintAndLog("\n--> MSD transaction.");
		
		PrintAndLog("* MSD dCVV path. Check dCVV");

		const struct tlv *track2 = tlvdb_get(tlvRoot, 0x57, NULL);
		if (track2) {
			PrintAndLog("Track2: %s", sprint_hex(track2->value, track2->len));

			struct tlvdb *dCVV = GetdCVVRawFromTrack2(track2);
			PrintAndLog("dCVV raw data:");
			TLVPrintFromTLV(dCVV);
			
			if (GetCardPSVendor(AID, AIDlen) == CV_MASTERCARD) {
				PrintAndLog("\n* Mastercard calculate UDOL");

				// UDOL (9F69)
				const struct tlv *UDOL = tlvdb_get(tlvRoot, 0x9F69, NULL);
				// UDOL(9F69) default: 9F6A (Unpredictable number) 4 bytes
				const struct tlv defUDOL = {
					.tag = 0x01,
					.len = 3,
					.value = (uint8_t *)"\x9f\x6a\x04",
				};
				if (!UDOL)
					PrintAndLog("Use default UDOL.");

				struct tlv *udol_data_tlv = dol_process(UDOL ? UDOL : &defUDOL, tlvRoot, 0x01); // 0x01 - dummy tag
				if (!udol_data_tlv){
					PrintAndLog("ERROR: can't create UDOL TLV.");
					return 4;
				}

				PrintAndLog("UDOL data[%d]: %s", udol_data_tlv->len, sprint_hex(udol_data_tlv->value, udol_data_tlv->len));
				
				PrintAndLog("\n* Mastercard compute cryptographic checksum(UDOL)");
				
				res = MSCComputeCryptoChecksum(true, (uint8_t *)udol_data_tlv->value, udol_data_tlv->len, buf, sizeof(buf), &len, &sw, tlvRoot);
				if (res) {
					PrintAndLog("ERROR Compute Crypto Checksum. APDU error %4x", sw);
					return 5;
				}
				
				if (decodeTLV) {
					TLVPrintFromBuffer(buf, len);
					PrintAndLog("");
				}
			}
		} else {
			PrintAndLog("ERROR MSD: Track2 data not found.");
		}
	}

	DropField();
	
	// Destroy TLV's
	tlvdb_free(tlvSelect);
	tlvdb_free(tlvRoot);

	PrintAndLog("\n* Transaction completed.");
	return 0;
}

int usage_emv_getrnd(void){
	PrintAndLog("retrieve the UN number from a terminal");
	PrintAndLog("Usage:  hf emv getrnd [h]");
	PrintAndLog("Options:");
	PrintAndLog("      h             : this help");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      hf emv getrnd");
	return 0;
}

//retrieve the UN number from a terminal
int CmdHfEMVGetrng(const char *Cmd) {
	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'h' || cmdp == 'H') return usage_emv_getrnd();

	return 0;
}

int CmdHfEMVList(const char *Cmd) {
	return CmdHFList("7816");
}

static command_t CommandTable[] =  {
	{"help",	CmdHelp,		1,	"This help"},
	{"exec",	CmdHFEMVExec,	0,	"Executes EMV contactless transaction."},
	{"pse",		CmdHFEMVPPSE,	0,	"Execute PPSE. It selects 2PAY.SYS.DDF01 or 1PAY.SYS.DDF01 directory."},
	{"search",	CmdHFEMVSearch,	0,	"Try to select all applets from applets list and print installed applets."},
	{"select",	CmdHFEMVSelect,	0,	"Select applet."},

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
