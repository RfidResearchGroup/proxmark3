//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// EMV core functions
//-----------------------------------------------------------------------------

#include "emvcore.h"

// Got from here. Thanks)
// https://eftlab.co.uk/index.php/site-map/knowledge-base/211-emv-aid-rid-pix
const char *PSElist [] = { 
	"325041592E5359532E4444463031", // 2PAY.SYS.DDF01 - Visa Proximity Payment System Environment - PPSE
	"315041592E5359532E4444463031"  // 1PAY.SYS.DDF01 - Visa Payment System Environment - PSE
};
const size_t PSElistLen = sizeof(PSElist)/sizeof(char*);

const char *AIDlist [] = { 
	// Visa International
	"A00000000305076010",	// VISA ELO Credit	
	"A0000000031010",		// VISA Debit/Credit (Classic)	
	"A0000000031010",		// ddddddddddddddddddddddddddddddddddddddddddddddddddddddddd	
	"A000000003101001",		// VISA Credit	
	"A000000003101002",		// VISA Debit	
	"A0000000032010",		// VISA Electron
	"A0000000032020",		// VISA	
	"A0000000033010",		// VISA Interlink	
	"A0000000034010",		// VISA Specific	
	"A0000000035010",		// VISA Specific	
	"A0000000036010",		// Domestic Visa Cash Stored Value	
	"A0000000036020",		// International Visa Cash Stored Value	
	"A0000000038002",		// VISA Auth, VisaRemAuthen EMV-CAP (DPA)	
	"A0000000038010",		// VISA Plus	
	"A0000000039010",		// VISA Loyalty	
	"A000000003999910",		// VISA Proprietary ATM	
	// Visa USA
	"A000000098",			// Debit Card
	"A0000000980848",		// Debit Card
	// Mastercard International
	"A00000000401",			// MasterCard PayPass	
	"A0000000041010",		// MasterCard Credit
	"A00000000410101213",	// MasterCard Credit
	"A00000000410101215",	// MasterCard Credit
	"A0000000042010",		// MasterCard Specific
	"A0000000043010",		// MasterCard Specific
	"A0000000043060",		// Maestro (Debit)
	"A000000004306001",		// Maestro (Debit)
	"A0000000044010",		// MasterCard Specific
	"A0000000045010",		// MasterCard Specific
	"A0000000046000",		// Cirrus
	"A0000000048002",		// SecureCode Auth EMV-CAP
	"A0000000049999",		// MasterCard PayPass	
	// American Express
	"A000000025",
	"A0000000250000",
	"A00000002501",
	"A000000025010402",
	"A000000025010701",
	"A000000025010801",
	// Groupement des Cartes Bancaires "CB"
	"A0000000421010",		// Cartes Bancaire EMV Card	
	"A0000000422010",		
	"A0000000423010",		
	"A0000000424010",		
	"A0000000425010",		
	// JCB CO., LTD.
	"A00000006510",			// JCB	
	"A0000000651010",		// JCB J Smart Credit	
	"A0000001544442",		// Banricompras Debito - Banrisul - Banco do Estado do Rio Grande do SUL - S.A.
	"F0000000030001",		// BRADESCO
	"A0000005241010",		// RuPay - RuPay
	"D5780000021010"		// Bankaxept - Bankaxept	
};
const size_t AIDlistLen = sizeof(AIDlist)/sizeof(char*);

static bool APDULogging = false;
void SetAPDULogging(bool logging) {
	APDULogging = logging;
}

static bool print_cb(void *data, const struct tlv *tlv, int level, bool is_leaf) {
	emv_tag_dump(tlv, stdout, level);
	if (is_leaf) {
		dump_buffer(tlv->value, tlv->len, stdout, level);
	}

	return true;
}

void TLVPrintFromBuffer(uint8_t *data, int datalen) {
	struct tlvdb *t = NULL;
	t = tlvdb_parse_multi(data, datalen);
	if (t) {
		PrintAndLog("-------------------- TLV decoded --------------------");
		
		tlvdb_visit(t, print_cb, NULL, 0);
		tlvdb_free(t);
	} else {
		PrintAndLog("TLV ERROR: Can't parse response as TLV tree.");
	}
}

void TLVPrintFromTLV(struct tlvdb *tlv) {
	if (!tlv) 
		return;
	
	tlvdb_visit(tlv, print_cb, NULL, 0);
}

void TLVPrintAIDlistFromSelectTLV(struct tlvdb *tlv) {
	PrintAndLog("|------------------|--------|-------------------------|");
	PrintAndLog("|    AID           |Priority| Name                    |");
	PrintAndLog("|------------------|--------|-------------------------|");

	struct tlvdb *ttmp = tlvdb_find(tlv, 0x6f);
	if (!ttmp)
		PrintAndLog("|                         none                        |");
		
	while (ttmp) {
		const struct tlv *tgAID = tlvdb_get_inchild(ttmp, 0x84, NULL);
		const struct tlv *tgName = tlvdb_get_inchild(ttmp, 0x50, NULL);
		const struct tlv *tgPrio = tlvdb_get_inchild(ttmp, 0x87, NULL);
		if (!tgAID)
			break;
		PrintAndLog("|%s|   %s  |%s|", 
			sprint_hex_inrow_ex(tgAID->value, tgAID->len, 18), 
			(tgPrio) ? sprint_hex(tgPrio->value, 1) : "   ", 
			(tgName) ? sprint_ascii_ex(tgName->value, tgName->len, 25) : "                         ");
		
		ttmp = tlvdb_find_next(ttmp, 0x6f);
	}

	PrintAndLog("|------------------|--------|-------------------------|");
}


int EMVSelect(bool ActivateField, bool LeaveFieldON, uint8_t *AID, size_t AIDLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
	uint8_t data[APDU_RES_LEN] = {0};
	*ResultLen = 0;
	if (sw)	*sw = 0;
	uint16_t isw = 0;
	
	// select APDU
	data[0] = 0x00;
	data[1] = 0xA4;
	data[2] = 0x04;
	data[3] = 0x00;
	data[4] = AIDLen;
	memcpy(&data[5], AID, AIDLen);
	
	if (ActivateField)
		DropField();
	
	if (APDULogging)
		PrintAndLog(">>>> %s", sprint_hex(data, AIDLen + 6));

	int res = ExchangeAPDU14a(data, AIDLen + 6, ActivateField, LeaveFieldON, Result, (int)MaxResultLen, (int *)ResultLen);
	
	if (APDULogging)
		PrintAndLog("<<<< %s", sprint_hex(Result, *ResultLen));
	
	if (res) {
		return res;
	}
	
	if (*ResultLen < 2) {
		PrintAndLog("SELECT ERROR: returned %d bytes", *ResultLen);
		return 5;
	}
	
	*ResultLen -= 2;
	isw = Result[*ResultLen] * 0x0100 + Result[*ResultLen + 1];
	if (sw)
		*sw = isw;

	if (isw != 0x9000) {
		if (APDULogging)
			PrintAndLog("SELECT ERROR: [%4X] %s", isw, GetAPDUCodeDescription(*sw >> 8, *sw & 0xff));
		return 5;
	}

	// add to tlv tree
	if (tlv) {
		struct tlvdb *t = tlvdb_parse_multi(Result, *ResultLen);
		tlvdb_add(tlv, t);
	}
	
	return 0;
}

int EMVSelectPSE(bool ActivateField, bool LeaveFieldON, uint8_t PSENum, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
	uint8_t buf[APDU_AID_LEN] = {0};
	*ResultLen = 0;
	int len = 0;
	int res = 0;
	switch (PSENum) {
		case 1:
			param_gethex_to_eol(PSElist[1], 0, buf, sizeof(buf), &len);
			break;
		case 2:
			param_gethex_to_eol(PSElist[0], 0, buf, sizeof(buf), &len);
			break;
		default:
			return -1;
	}
	
	// select
	res = EMVSelect(ActivateField, LeaveFieldON, buf, len, Result, MaxResultLen, ResultLen, sw, NULL);

	return res;
}

int EMVSearchPSE(bool ActivateField, bool LeaveFieldON, bool decodeTLV, struct tlvdb *tlv) {
	uint8_t data[APDU_RES_LEN] = {0};
	size_t datalen = 0;
	uint16_t sw = 0;
	int res;

	// select PPSE
	res = EMVSelectPSE(ActivateField, true, 2, data, sizeof(data), &datalen, &sw);

	if (!res){
		struct tlvdb *t = NULL;
		t = tlvdb_parse_multi(data, datalen);
		if (t) {
			int retrycnt = 0;
			struct tlvdb *ttmp = tlvdb_find_path(t, (tlv_tag_t[]){0x6f, 0xa5, 0xbf0c, 0x61, 0x00});
			if (!ttmp)
				PrintAndLog("PPSE don't have records.");
			
			while (ttmp) {
				const struct tlv *tgAID = tlvdb_get_inchild(ttmp, 0x4f, NULL);
				if (tgAID) {
					res = EMVSelect(false, true, (uint8_t *)tgAID->value, tgAID->len, data, sizeof(data), &datalen, &sw, tlv);

					// retry if error and not returned sw error
					if (res && res != 5) {
						if (++retrycnt < 3){
							continue;
						} else {
							// card select error, proxmark error
							if (res == 1) {
								PrintAndLog("Exit...");
								return 1;
							}
							
							retrycnt = 0;
							PrintAndLog("Retry failed [%s]. Skiped...", sprint_hex_inrow(tgAID->value, tgAID->len));
						}
						
						// next element
						ttmp = tlvdb_find_next(ttmp, 0x61);
						continue;
					}
					retrycnt = 0;

					// all is ok
					if (decodeTLV){
						PrintAndLog("%s:", sprint_hex_inrow(tgAID->value, tgAID->len));
						TLVPrintFromBuffer(data, datalen);
					}
				}
				
				ttmp = tlvdb_find_next(ttmp, 0x61);
			}

			tlvdb_free(t);
		} else {
			PrintAndLog("PPSE ERROR: Can't get TLV from response.");
		}		
	} else {
		PrintAndLog("PPSE ERROR: Can't select PPSE AID. Error: %d", res);
	}
	
	if(!LeaveFieldON)
		DropField();
	
	return res;
}

int EMVSearch(bool ActivateField, bool LeaveFieldON, bool decodeTLV, struct tlvdb *tlv) {
	uint8_t aidbuf[APDU_AID_LEN] = {0};
	int aidlen = 0;
	uint8_t data[APDU_RES_LEN] = {0};
	size_t datalen = 0;
	uint16_t sw = 0;
	
	int res = 0;
	int retrycnt = 0;
	for(int i = 0; i < AIDlistLen; i ++) {
		param_gethex_to_eol(AIDlist[i], 0, aidbuf, sizeof(aidbuf), &aidlen);
		res = EMVSelect((i == 0) ? ActivateField : false, (i == AIDlistLen - 1) ? LeaveFieldON : true, aidbuf, aidlen, data, sizeof(data), &datalen, &sw, tlv);
		// retry if error and not returned sw error
		if (res && res != 5) {
			if (++retrycnt < 3){
				i--;
			} else {
				// card select error, proxmark error
				if (res == 1) {
					PrintAndLog("Exit...");
					return 1;
				}
				
				retrycnt = 0;
				PrintAndLog("Retry failed [%s]. Skiped...", AIDlist[i]);
			}
			continue;
		}
		retrycnt = 0;
		
		if (res)
			continue;
		
		if (decodeTLV){
			PrintAndLog("%s:", AIDlist[i]);
			TLVPrintFromBuffer(data, datalen);
		}
	}

	return 0;
}

int EMVSelectApplication(struct tlvdb *tlv, uint8_t *AID, size_t *AIDlen) {
	// needs to check priority. 0x00 - highest
	int prio = 0xffff;
	
	*AIDlen = 0;

	struct tlvdb *ttmp = tlvdb_find(tlv, 0x6f);
	if (!ttmp)
		return 1;
		
	while (ttmp) {
		const struct tlv *tgAID = tlvdb_get_inchild(ttmp, 0x84, NULL);
		const struct tlv *tgPrio = tlvdb_get_inchild(ttmp, 0x87, NULL);
		
		if (!tgAID)
			break;

		if (tgPrio) {
			int pt = bytes_to_num((uint8_t*)tgPrio->value, (tgPrio->len < 2) ? tgPrio->len : 2); 
			if (pt < prio) {
				prio = pt;
				
				memcpy(AID, tgAID->value, tgAID->len);
				*AIDlen = tgAID->len;
			}
		} else {
			// takes the first application from list wo priority
			if (!*AIDlen) {
			memcpy(AID, tgAID->value, tgAID->len);
			*AIDlen = tgAID->len;				
			}
		}
		
		ttmp = tlvdb_find_next(ttmp, 0x6f);
	}
	
	return 0;
}

int EMVGPO(bool LeaveFieldON, uint8_t *PDOL, size_t PDOLLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
	uint8_t data[APDU_RES_LEN] = {0};
	*ResultLen = 0;
	if (sw)	*sw = 0;
	uint16_t isw = 0;
	
	// GPO APDU
	data[0] = 0x80;
	data[1] = 0xA8;
	data[2] = 0x00;
	data[3] = 0x00;
	data[4] = PDOLLen;
	if (PDOL)
		memcpy(&data[5], PDOL, PDOLLen);
	
	
	if (APDULogging)
		PrintAndLog(">>>> %s", sprint_hex(data, PDOLLen + 5));

	int res = ExchangeAPDU14a(data, PDOLLen + 5, false, LeaveFieldON, Result, (int)MaxResultLen, (int *)ResultLen);
	
	if (APDULogging)
		PrintAndLog("<<<< %s", sprint_hex(Result, *ResultLen));
	
	if (res) {
		return res;
	}
	
	if (*ResultLen < 2) {
		PrintAndLog("GPO ERROR: returned %d bytes", *ResultLen);
		return 5;
	}
	
	*ResultLen -= 2;
	isw = Result[*ResultLen] * 0x0100 + Result[*ResultLen + 1];
	if (sw)
		*sw = isw;

	if (isw != 0x9000) {
		if (APDULogging)
			PrintAndLog("GPO ERROR: [%4X] %s", isw, GetAPDUCodeDescription(*sw >> 8, *sw & 0xff));
		return 5;
	}

	// add to tlv tree
	if (tlv) {
		struct tlvdb *t = tlvdb_parse_multi(Result, *ResultLen);
		tlvdb_add(tlv, t);
	}
	
	return 0;
}

int EMVReadRecord(bool LeaveFieldON, uint8_t SFI, uint8_t SFIrec, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
	uint8_t data[10] = {0};
	*ResultLen = 0;
	if (sw)	*sw = 0;
	uint16_t isw = 0;
	
	// read record APDU
	data[0] = 0x00;
	data[1] = 0xb2;
	data[2] = SFIrec;
	data[3] = (SFI << 3) | 0x04;
	data[4] = 0;
	
	if (APDULogging)
		PrintAndLog(">>>> %s", sprint_hex(data, 5));

	int res = ExchangeAPDU14a(data, 5, false, LeaveFieldON, Result, (int)MaxResultLen, (int *)ResultLen);
	
	if (APDULogging)
		PrintAndLog("<<<< %s", sprint_hex(Result, *ResultLen));
	
	if (res) {
		return res;
	}

	*ResultLen -= 2;
	isw = Result[*ResultLen] * 0x0100 + Result[*ResultLen + 1];
	if (sw)
		*sw = isw;

	if (isw != 0x9000) {
		if (APDULogging)
			PrintAndLog("Read record ERROR: [%4X] %s", isw, GetAPDUCodeDescription(*sw >> 8, *sw & 0xff));
		return 5;
	}

	// add to tlv tree
	if (tlv) {
		struct tlvdb *t = tlvdb_parse_multi(Result, *ResultLen);
		tlvdb_add(tlv, t);
	}
	
	return 0;
}


