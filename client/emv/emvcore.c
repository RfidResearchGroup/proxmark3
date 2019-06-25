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
#include "emvjson.h"
#include "util_posix.h"

// Got from here. Thanks)
// https://eftlab.co.uk/index.php/site-map/knowledge-base/211-emv-aid-rid-pix
static const char *PSElist [] = {
    "325041592E5359532E4444463031", // 2PAY.SYS.DDF01 - Visa Proximity Payment System Environment - PPSE
    "315041592E5359532E4444463031"  // 1PAY.SYS.DDF01 - Visa Payment System Environment - PSE
};
//static const size_t PSElistLen = sizeof(PSElist)/sizeof(char*);

const char *TransactionTypeStr[] = {
    "MSD",
    "VSDC",
    "qVCDCMCHIP",
    "CDA"
};

typedef struct {
    enum CardPSVendor vendor;
    const char *aid;
} TAIDList;

static const TAIDList AIDlist [] = {
    // Visa International
    { CV_VISA, "A00000000305076010" },           // VISA ELO Credit
    { CV_VISA, "A0000000031010" },               // VISA Debit/Credit (Classic)
    { CV_VISA, "A000000003101001" },             // VISA Credit
    { CV_VISA, "A000000003101002" },             // VISA Debit
    { CV_VISA, "A0000000032010" },               // VISA Electron
    { CV_VISA, "A0000000032020" },               // VISA
    { CV_VISA, "A0000000033010" },               // VISA Interlink
    { CV_VISA, "A0000000034010" },               // VISA Specific
    { CV_VISA, "A0000000035010" },               // VISA Specific
    { CV_VISA, "A0000000036010" },               // Domestic Visa Cash Stored Value
    { CV_VISA, "A0000000036020" },               // International Visa Cash Stored Value
    { CV_VISA, "A0000000038002" },               // VISA Auth, VisaRemAuthen EMV-CAP (DPA)
    { CV_VISA, "A0000000038010" },               // VISA Plus
    { CV_VISA, "A0000000039010" },               // VISA Loyalty
    { CV_VISA, "A000000003999910" },             // VISA Proprietary ATM
    // Visa USA
    { CV_VISA, "A000000098" },                   // Debit Card
    { CV_VISA, "A0000000980848" },               // Debit Card
    // Mastercard International
    { CV_MASTERCARD, "A00000000401" },           // MasterCard PayPass
    { CV_MASTERCARD, "A0000000041010" },         // MasterCard Credit
    { CV_MASTERCARD, "A00000000410101213" },     // MasterCard Credit
    { CV_MASTERCARD, "A00000000410101215" },     // MasterCard Credit
    { CV_MASTERCARD, "A0000000042010" },         // MasterCard Specific
    { CV_MASTERCARD, "A0000000043010" },         // MasterCard Specific
    { CV_MASTERCARD, "A0000000043060" },         // Maestro (Debit)
    { CV_MASTERCARD, "A000000004306001" },       // Maestro (Debit)
    { CV_MASTERCARD, "A0000000044010" },         // MasterCard Specific
    { CV_MASTERCARD, "A0000000045010" },         // MasterCard Specific
    { CV_MASTERCARD, "A0000000046000" },         // Cirrus
    { CV_MASTERCARD, "A0000000048002" },         // SecureCode Auth EMV-CAP
    { CV_MASTERCARD, "A0000000049999" },         // MasterCard PayPass
    { CV_MASTERCARD, "B012345678" },             // Maestro TEST Used for development
    // American Express
    { CV_AMERICANEXPRESS, "A000000025" },
    { CV_AMERICANEXPRESS, "A0000000250000" },
    { CV_AMERICANEXPRESS, "A00000002501" },
    { CV_AMERICANEXPRESS, "A000000025010402" },
    { CV_AMERICANEXPRESS, "A000000025010701" },
    { CV_AMERICANEXPRESS, "A000000025010801" },
    // Groupement des Cartes Bancaires "CB"
    { CV_CB, "A0000000421010" },                 // Cartes Bancaire EMV Card
    { CV_CB, "A0000000422010" },
    { CV_CB, "A0000000423010" },
    { CV_CB, "A0000000424010" },
    { CV_CB, "A0000000425010" },
    // JCB CO., LTD.
    { CV_JCB, "A00000006510" },                  // JCB
    { CV_JCB, "A0000000651010" },                // JCB J Smart Credit
    // Switch Card Services Ltd.
    { CV_SWITCH, "A0000000050001" },             // Maestro UK
    { CV_SWITCH, "A0000000050002" },             // Solo
    // Diners Club International Ltd.
    { CV_DINERS, "A0000001523010" },             // Discover, Pulse D Pas Discover Card
    { CV_DINERS, "A0000001524010" },             // Discover, Discover Debit Common Card
    // Other
    { CV_OTHER, "A00000002401" },                // Midland Bank Plc - Self Service
    { CV_OTHER, "A0000000291010" },              // LINK Interchange Network Ltd - Link / American Express
    { CV_OTHER, "A00000006900" },                // Société Européenne de Monnaie Electronique SEME - Moneo
    { CV_OTHER, "A000000077010000021000000000003B" },  // Oberthur Technologies France - Visa AEPN
    { CV_OTHER, "A0000001211010" },              // PBS Danmark A/S - Denmark - Dankort (VISA GEM Vision) - Danish domestic debit card
    { CV_OTHER, "A0000001410001" },              // Associazione Bancaria Italiana - Italy - PagoBANCOMAT - CoGeBan Consorzio BANCOMAT (Italian domestic debit card)
    { CV_OTHER, "A0000001544442" },              // Banricompras Debito - Banrisul - Banco do Estado do Rio Grande do SUL - S.A.
    { CV_OTHER, "A000000172950001" },            // Financial Information Service Co. Ltd. - Taiwan - BAROC Financial Application Taiwan- The Bankers Association of the Republic of China
    { CV_OTHER, "A0000001850002" },              // Post Office Limited - United Kingdom - UK Post Office Account card
    { CV_OTHER, "A0000002281010" },              // Saudi Arabian Monetary Agency (SAMA) - Kingdom of Saudi Arabia - SPAN (M/Chip) - SPAN2 (Saudi Payments Network) - Saudi Arabia domestic credit/debit card (Saudi Arabia Monetary Agency)
    { CV_OTHER, "A0000002282010" },              // Saudi Arabian Monetary Agency (SAMA) - Kingdom of Saudi Arabia - SPAN (VIS) - SPAN2 (Saudi Payments Network) - Saudi Arabia domestic credit/debit card (Saudi Arabia Monetary Agency)
    { CV_OTHER, "A0000002771010" },              // Interac Association - Canada - INTERAC - Canadian domestic credit/debit card
    { CV_OTHER, "A00000031510100528" },          // Currence Holding/PIN BV - The Netherlands- Currence PuC
    { CV_OTHER, "A0000003156020" },              // Currence Holding/PIN BV - The Netherlands - Chipknip
    { CV_OTHER, "A0000003591010028001" },        // Euro Alliance of Payment Schemes s.c.r.l. (EAPS) - Belgium - Girocard EAPS - ZKA (Germany)
    { CV_OTHER, "A0000003710001" },              // Verve - Nigeria - InterSwitch Verve Card - Nigerian local switch company
    { CV_OTHER, "A0000004540010" },              // eTranzact - Nigeria - Etranzact Genesis Card - Nigerian local switch company
    { CV_OTHER, "A0000004540011" },              // eTranzact - Nigeria - Etranzact Genesis Card 2 - Nigerian local switch company
    { CV_OTHER, "A0000004766C" },                // Google - United States - GOOGLE_PAYMENT_AID
    { CV_OTHER, "A0000005241010" },              // RuPay - India - RuPay - RuPay (India)
    { CV_OTHER, "A0000006723010" },              // TROY - Turkey - TROY chip credit card - Turkey's Payment Method
    { CV_OTHER, "A0000006723020" },              // TROY - Turkey - TROY chip debit card - Turkey's Payment Method
    { CV_OTHER, "A0000007705850" },              // Indian Oil Corporation Limited - India - XTRAPOWER Fleet Card Program - Indian Oil’s Pre Paid Program
    { CV_OTHER, "D27600002545500100" },          // ZKA - Germany - Girocard - ZKA Girocard (Geldkarte) (Germany)
    { CV_OTHER, "D4100000030001" },              // KS X 6923/6924 (T-Money, South Korea and Snapper+, Wellington, New Zealand)
    { CV_OTHER, "D5280050218002" },              // The Netherlands - ? - (Netherlands)
    { CV_OTHER, "D5780000021010" },              // Bankaxept    Norway  Bankaxept   Norwegian domestic debit card
    { CV_OTHER, "F0000000030001" },              // BRADESCO - Brazilian Bank Banco Bradesco
};
static const size_t AIDlistLen = sizeof(AIDlist) / sizeof(TAIDList);

static bool APDULogging = false;
void SetAPDULogging(bool logging) {
    APDULogging = logging;
}

enum CardPSVendor GetCardPSVendor(uint8_t *AID, size_t AIDlen) {
    char buf[100] = {0};
    if (AIDlen < 1)
        return CV_NA;

    hex_to_buffer((uint8_t *)buf, AID, AIDlen, sizeof(buf) - 1, 0, 0, true);

    for (int i = 0; i < AIDlistLen; i ++) {
        if (strncmp(AIDlist[i].aid, buf, strlen(AIDlist[i].aid)) == 0) {
            return AIDlist[i].vendor;
        }
    }

    return CV_NA;
}

static bool print_cb(void *data, const struct tlv *tlv, int level, bool is_leaf) {
    emv_tag_dump(tlv, stdout, level);
    if (is_leaf) {
        dump_buffer(tlv->value, tlv->len, stdout, level);
    }

    return true;
}

bool TLVPrintFromBuffer(uint8_t *data, int datalen) {
    struct tlvdb *t = NULL;
    t = tlvdb_parse_multi(data, datalen);
    if (t) {
        PrintAndLogEx(NORMAL, "-------------------- TLV decoded --------------------");

        tlvdb_visit(t, print_cb, NULL, 0);
        tlvdb_free(t);
        return true;
    } else {
        PrintAndLogEx(WARNING, "TLV ERROR: Can't parse response as TLV tree.");
    }
    return false;
}

void TLVPrintFromTLVLev(struct tlvdb *tlv, int level) {
    if (!tlv)
        return;

    tlvdb_visit(tlv, print_cb, NULL, level);
}

void TLVPrintFromTLV(struct tlvdb *tlv) {
    TLVPrintFromTLVLev(tlv, 0);
}

void TLVPrintAIDlistFromSelectTLV(struct tlvdb *tlv) {
    PrintAndLogEx(NORMAL, "|------------------|--------|-------------------------|");
    PrintAndLogEx(NORMAL, "|    AID           |Priority| Name                    |");
    PrintAndLogEx(NORMAL, "|------------------|--------|-------------------------|");

    struct tlvdb *ttmp = tlvdb_find(tlv, 0x6f);
    if (!ttmp)
        PrintAndLogEx(NORMAL, "|                         none                        |");

    while (ttmp) {
        const struct tlv *tgAID = tlvdb_get_inchild(ttmp, 0x84, NULL);
        const struct tlv *tgName = tlvdb_get_inchild(ttmp, 0x50, NULL);
        const struct tlv *tgPrio = tlvdb_get_inchild(ttmp, 0x87, NULL);
        if (!tgAID)
            break;
        PrintAndLogEx(NORMAL, "|%s|   %s  |%s|",
                      sprint_hex_inrow_ex(tgAID->value, tgAID->len, 18),
                      (tgPrio) ? sprint_hex(tgPrio->value, 1) : "   ",
                      (tgName) ? sprint_ascii_ex(tgName->value, tgName->len, 25) : "                         ");

        ttmp = tlvdb_find_next(ttmp, 0x6f);
    }

    PrintAndLogEx(NORMAL, "|------------------|--------|-------------------------|");
}

struct tlvdb *GetPANFromTrack2(const struct tlv *track2) {
    char track2Hex[200] = {0};
    uint8_t PAN[100] = {0};
    int PANlen = 0;
    char *tmp = track2Hex;

    if (!track2)
        return NULL;

    for (int i = 0; i < track2->len; ++i, tmp += 2)
        sprintf(tmp, "%02x", (unsigned int)track2->value[i]);

    int posD = strchr(track2Hex, 'd') - track2Hex;
    if (posD < 1)
        return NULL;

    track2Hex[posD] = 0;
    if (strlen(track2Hex) % 2) {
        track2Hex[posD] = 'F';
        track2Hex[posD + 1] = '\0';
    }

    param_gethex_to_eol(track2Hex, 0, PAN, sizeof(PAN), &PANlen);

    return tlvdb_fixed(0x5a, PANlen, PAN);
}

struct tlvdb *GetdCVVRawFromTrack2(const struct tlv *track2) {
    char track2Hex[200] = {0};
    char dCVVHex[100] = {0};
    uint8_t dCVV[100] = {0};
    int dCVVlen = 0;
    const int PINlen = 5; // must calculated from 9F67 MSD Offset but i have not seen this tag)
    char *tmp = track2Hex;

    if (!track2)
        return NULL;

    for (int i = 0; i < track2->len; ++i, tmp += 2)
        sprintf(tmp, "%02x", (unsigned int)track2->value[i]);

    int posD = strchr(track2Hex, 'd') - track2Hex;
    if (posD < 1)
        return NULL;

    memset(dCVVHex, '0', 32);
    // ATC
    memcpy(dCVVHex + 0, track2Hex + posD + PINlen + 11, 4);
    // PAN 5 hex
    memcpy(dCVVHex + 4, track2Hex, 5);
    // expire date
    memcpy(dCVVHex + 9, track2Hex + posD + 1, 4);
    // service code
    memcpy(dCVVHex + 13, track2Hex + posD + 5, 3);

    param_gethex_to_eol(dCVVHex, 0, dCVV, sizeof(dCVV), &dCVVlen);

    return tlvdb_fixed(0x02, dCVVlen, dCVV);
}

static int EMVExchangeEx(EMVCommandChannel channel, bool ActivateField, bool LeaveFieldON, sAPDU apdu, bool IncludeLe, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    uint8_t data[APDU_RES_LEN] = {0};

    *ResultLen = 0;
    if (sw) *sw = 0;
    uint16_t isw = 0;
    int res = 0;

    if (ActivateField) {
        DropFieldEx(channel);
        msleep(50);
    }

    // COMPUTE APDU
    memcpy(data, &apdu, 5);
    if (apdu.data)
        memcpy(&data[5], apdu.data, apdu.Lc);

    if (APDULogging)
        PrintAndLogEx(SUCCESS, ">>>> %s", sprint_hex(data, (IncludeLe ? 6 : 5) + apdu.Lc));

    switch (channel) {
        case ECC_CONTACTLESS:
            // 6 byes + data = INS + CLA + P1 + P2 + Lc + <data = Nc> + Le(?IncludeLe)
            res = ExchangeAPDU14a(data, (IncludeLe ? 6 : 5) + apdu.Lc, ActivateField, LeaveFieldON, Result, (int)MaxResultLen, (int *)ResultLen);
            if (res) {
                return res;
            }
            break;
        case ECC_CONTACT:
            if (IfPm3Smartcard())
                res = ExchangeAPDUSC(data, (IncludeLe ? 6 : 5) + apdu.Lc, ActivateField, LeaveFieldON, Result, (int)MaxResultLen, (int *)ResultLen);
            else
                res = 1;
            if (res) {
                return res;
            }
            break;
    }

    if (APDULogging)
        PrintAndLogEx(SUCCESS, "<<<< %s", sprint_hex(Result, *ResultLen));

    if (*ResultLen < 2) {
        return 200;
    }

    *ResultLen -= 2;
    isw = Result[*ResultLen] * 0x0100 + Result[*ResultLen + 1];
    if (sw)
        *sw = isw;

    if (isw != 0x9000) {
        if (APDULogging) {
            if (*sw >> 8 == 0x61) {
                PrintAndLogEx(ERR, "APDU chaining len:%02x -->", *sw & 0xff);
            } else {
                PrintAndLogEx(ERR, "APDU(%02x%02x) ERROR: [%4X] %s", apdu.CLA, apdu.INS, isw, GetAPDUCodeDescription(*sw >> 8, *sw & 0xff));
                return 5;
            }
        }
    }

    // add to tlv tree
    if (tlv) {
        struct tlvdb *t = tlvdb_parse_multi(Result, *ResultLen);
        tlvdb_add(tlv, t);
    }

    return 0;
}

int EMVExchange(EMVCommandChannel channel, bool LeaveFieldON, sAPDU apdu, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    return EMVExchangeEx(channel, false, LeaveFieldON, apdu, (channel == ECC_CONTACTLESS), Result, MaxResultLen, ResultLen, sw, tlv);
}

int EMVSelect(EMVCommandChannel channel, bool ActivateField, bool LeaveFieldON, uint8_t *AID, size_t AIDLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    return EMVExchangeEx(channel, ActivateField, LeaveFieldON, (sAPDU) {0x00, 0xa4, 0x04, 0x00, AIDLen, AID}, (channel == ECC_CONTACTLESS), Result, MaxResultLen, ResultLen, sw, tlv);
}

int EMVSelectPSE(EMVCommandChannel channel, bool ActivateField, bool LeaveFieldON, uint8_t PSENum, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
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
    res = EMVSelect(channel, ActivateField, LeaveFieldON, buf, len, Result, MaxResultLen, ResultLen, sw, NULL);

    return res;
}

static int EMVSelectWithRetry(EMVCommandChannel channel, bool ActivateField, bool LeaveFieldON, uint8_t *AID, size_t AIDLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    int retrycnt = 0;
    int res = 0;
    do {
        res = EMVSelect(channel, false, true, AID, AIDLen, Result, MaxResultLen, ResultLen, sw, tlv);

        // retry if error and not returned sw error
        if (res && res != 5) {
            if (++retrycnt < 3) {
                continue;
            } else {
                // card select error, proxmark error
                if (res == 1) {
                    PrintAndLogEx(WARNING, "Exit...");
                    return 1;
                }

                retrycnt = 0;
                PrintAndLogEx(NORMAL, "Retry failed [%s]. Skiped...", sprint_hex_inrow(AID, AIDLen));
                return res;
            }
        }
    } while (res && res != 5);

    return res;
}

static int EMVCheckAID(EMVCommandChannel channel, bool decodeTLV, struct tlvdb *tlvdbelm, struct tlvdb *tlv) {
    uint8_t data[APDU_RES_LEN] = {0};
    size_t datalen = 0;
    int res = 0;
    uint16_t sw = 0;

    while (tlvdbelm) {
        const struct tlv *tgAID = tlvdb_get_inchild(tlvdbelm, 0x4f, NULL);
        if (tgAID) {
            res = EMVSelectWithRetry(channel, false, true, (uint8_t *)tgAID->value, tgAID->len, data, sizeof(data), &datalen, &sw, tlv);

            // if returned sw error
            if (res == 5) {
                // next element
                tlvdbelm = tlvdb_find_next(tlvdbelm, 0x61);
                continue;
            }

            if (res)
                break;

            // all is ok
            if (decodeTLV) {
                PrintAndLogEx(NORMAL, "%s:", sprint_hex_inrow(tgAID->value, tgAID->len));
                TLVPrintFromBuffer(data, datalen);
            }
        }
        tlvdbelm = tlvdb_find_next(tlvdbelm, 0x61);
    }
    return res;
}

int EMVSearchPSE(EMVCommandChannel channel, bool ActivateField, bool LeaveFieldON, uint8_t PSENum, bool decodeTLV, struct tlvdb *tlv) {
    uint8_t data[APDU_RES_LEN] = {0};
    size_t datalen = 0;
    uint8_t sfidata[0x11][APDU_RES_LEN];
    size_t sfidatalen[0x11] = {0};
    uint16_t sw = 0;
    int res;
    bool fileFound = false;

    const char *PSE_or_PPSE = PSENum == 1 ? "PSE" : "PPSE";

    // select PPSE
    res = EMVSelectPSE(channel, ActivateField, true, PSENum, data, sizeof(data), &datalen, &sw);

    if (!res) {
        if (sw != 0x9000) {
            PrintAndLogEx(FAILED, "Select PSE error. APDU error: %04x.", sw);
            return 1;
        }

        struct tlvdb *t = NULL;
        t = tlvdb_parse_multi(data, datalen);
        if (t) {
            // PSE/PPSE with SFI
            struct tlvdb *tsfi = tlvdb_find_path(t, (tlv_tag_t[]) {0x6f, 0xa5, 0x88, 0x00});
            if (tsfi) {
                uint8_t sfin = 0;
                tlv_get_uint8(tlvdb_get_tlv(tsfi), &sfin);
                PrintAndLogEx(INFO, "* PPSE get SFI: 0x%02x.", sfin);

                for (uint8_t ui = 0x01; ui <= 0x10; ui++) {
                    PrintAndLogEx(INFO, "* * Get SFI: 0x%02x. num: 0x%02x", sfin, ui);
                    res = EMVReadRecord(channel, true, sfin, ui, sfidata[ui], APDU_RES_LEN, &sfidatalen[ui], &sw, NULL);

                    // end of records
                    if (sw == 0x6a83) {
                        sfidatalen[ui] = 0;
                        PrintAndLogEx(INFO, "* * PPSE get SFI. End of records.");
                        break;
                    }

                    // error catch!
                    if (sw != 0x9000) {
                        sfidatalen[ui] = 0;
                        PrintAndLogEx(FAILED, "PPSE get Error. APDU error: %04x.", sw);
                        break;
                    }

                    if (decodeTLV) {
                        TLVPrintFromBuffer(sfidata[ui], sfidatalen[ui]);
                    }
                }

                for (uint8_t ui = 0x01; ui <= 0x10; ui++) {
                    if (sfidatalen[ui]) {
                        struct tlvdb *tsfi = NULL;
                        tsfi = tlvdb_parse_multi(sfidata[ui], sfidatalen[ui]);
                        if (tsfi) {
                            struct tlvdb *tsfitmp = tlvdb_find_path(tsfi, (tlv_tag_t[]) {0x70, 0x61, 0x00});
                            if (!tsfitmp) {
                                PrintAndLogEx(FAILED, "SFI 0x%02d doesn't have any records.", sfidatalen[ui]);
                                continue;
                            }
                            res = EMVCheckAID(channel, decodeTLV, tsfitmp, tlv);
                            fileFound = true;
                        }
                        tlvdb_free(tsfi);
                    }
                }
            }


            // PSE/PPSE plain (wo SFI)
            struct tlvdb *ttmp = tlvdb_find_path(t, (tlv_tag_t[]) {0x6f, 0xa5, 0xbf0c, 0x61, 0x00});
            if (ttmp) {
                res = EMVCheckAID(channel, decodeTLV, ttmp, tlv);
                fileFound = true;
            }

            if (!fileFound)
                PrintAndLogEx(FAILED, "PPSE doesn't have any records.");

            tlvdb_free(t);
        } else {
            PrintAndLogEx(WARNING, "%s ERROR: Can't get TLV from response.", PSE_or_PPSE);
        }
    } else {
        PrintAndLogEx(WARNING, "%s ERROR: Can't select PPSE AID. Error: %d", PSE_or_PPSE, res);
    }

    if (!LeaveFieldON)
        DropFieldEx(channel);

    return res;
}

int EMVSearch(EMVCommandChannel channel, bool ActivateField, bool LeaveFieldON, bool decodeTLV, struct tlvdb *tlv) {
    uint8_t aidbuf[APDU_AID_LEN] = {0};
    int aidlen = 0;
    uint8_t data[APDU_RES_LEN] = {0};
    size_t datalen = 0;
    uint16_t sw = 0;

    int res = 0;
    int retrycnt = 0;
    for (int i = 0; i < AIDlistLen; i ++) {
        param_gethex_to_eol(AIDlist[i].aid, 0, aidbuf, sizeof(aidbuf), &aidlen);
        res = EMVSelect(channel, (i == 0) ? ActivateField : false, (i == AIDlistLen - 1) ? LeaveFieldON : true, aidbuf, aidlen, data, sizeof(data), &datalen, &sw, tlv);
        // retry if error and not returned sw error
        if (res && res != 5) {
            if (++retrycnt < 3) {
                i--;
            } else {
                // (1) - card select error, proxmark error OR (200) - result length = 0
                if (res == 1 || res == 200) {
                    PrintAndLogEx(WARNING, "Exit...");
                    return 1;
                }

                retrycnt = 0;
                PrintAndLogEx(FAILED, "Retry failed [%s]. Skipped...", AIDlist[i].aid);
            }
            continue;
        }
        retrycnt = 0;

        if (res)
            continue;

        if (!datalen)
            continue;

        if (decodeTLV) {
            PrintAndLogEx(SUCCESS, "%s", AIDlist[i].aid);
            TLVPrintFromBuffer(data, datalen);
        }
    }

    return 0;
}

int EMVSelectApplication(struct tlvdb *tlv, uint8_t *AID, size_t *AIDlen) {
    // check priority. 0x00 - highest
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
            int pt = bytes_to_num((uint8_t *)tgPrio->value, (tgPrio->len < 2) ? tgPrio->len : 2);
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

int EMVGPO(EMVCommandChannel channel, bool LeaveFieldON, uint8_t *PDOL, size_t PDOLLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    return EMVExchange(channel, LeaveFieldON, (sAPDU) {0x80, 0xa8, 0x00, 0x00, PDOLLen, PDOL}, Result, MaxResultLen, ResultLen, sw, tlv);
}

int EMVReadRecord(EMVCommandChannel channel, bool LeaveFieldON, uint8_t SFI, uint8_t SFIrec, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    int res = EMVExchange(channel, LeaveFieldON, (sAPDU) {0x00, 0xb2, SFIrec, (SFI << 3) | 0x04, 0, NULL}, Result, MaxResultLen, ResultLen, sw, tlv);
    if (*sw == 0x6700) {
        PrintAndLogEx(INFO, ">>> trying to reissue command withouth Le...");
        res = EMVExchangeEx(channel, false, LeaveFieldON, (sAPDU) {0x00, 0xb2, SFIrec, (SFI << 3) | 0x04, 0, NULL}, false, Result, MaxResultLen, ResultLen, sw, tlv);
    }
    return res;
}

int EMVAC(EMVCommandChannel channel, bool LeaveFieldON, uint8_t RefControl, uint8_t *CDOL, size_t CDOLLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    return EMVExchange(channel, LeaveFieldON, (sAPDU) {0x80, 0xae, RefControl, 0x00, CDOLLen, CDOL}, Result, MaxResultLen, ResultLen, sw, tlv);
}

int EMVGenerateChallenge(EMVCommandChannel channel, bool LeaveFieldON, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    int res = EMVExchange(channel, LeaveFieldON, (sAPDU) {0x00, 0x84, 0x00, 0x00, 0x00, NULL}, Result, MaxResultLen, ResultLen, sw, tlv);
    if (*sw == 0x6700) {
        PrintAndLogEx(INFO, ">>> trying to reissue command withouth Le...");
        res = EMVExchangeEx(channel, false, LeaveFieldON, (sAPDU) {0x00, 0x84, 0x00, 0x00, 0x00, NULL}, false, Result, MaxResultLen, ResultLen, sw, tlv);
    }
    return res;
}

int EMVInternalAuthenticate(EMVCommandChannel channel, bool LeaveFieldON, uint8_t *DDOL, size_t DDOLLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    return EMVExchangeEx(channel, false, LeaveFieldON, (sAPDU) {0x00, 0x88, 0x00, 0x00, DDOLLen, DDOL}, true, Result, MaxResultLen, ResultLen, sw, tlv);
}

int MSCComputeCryptoChecksum(EMVCommandChannel channel, bool LeaveFieldON, uint8_t *UDOL, uint8_t UDOLlen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    return EMVExchange(channel, LeaveFieldON, (sAPDU) {0x80, 0x2a, 0x8e, 0x80, UDOLlen, UDOL}, Result, MaxResultLen, ResultLen, sw, tlv);
}

// Authentication
struct emv_pk *get_ca_pk(struct tlvdb *db) {
    const struct tlv *df_tlv = tlvdb_get(db, 0x84, NULL);
    const struct tlv *caidx_tlv = tlvdb_get(db, 0x8f, NULL);

    if (!df_tlv || !caidx_tlv || df_tlv->len < 6 || caidx_tlv->len != 1)
        return NULL;

    PrintAndLogEx(NORMAL, "CA public key index 0x%0x", caidx_tlv->value[0]);
    return emv_pk_get_ca_pk(df_tlv->value, caidx_tlv->value[0]);
}

int trSDA(struct tlvdb *tlv) {

    struct emv_pk *pk = get_ca_pk(tlv);
    if (!pk) {
        PrintAndLogEx(WARNING, "Error: Key not found. Exit.");
        return 2;
    }

    struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(pk, tlv);
    if (!issuer_pk) {
        emv_pk_free(pk);
        PrintAndLogEx(WARNING, "Error: Issuer certificate not found. Exit.");
        return 2;
    }

    PrintAndLogEx(SUCCESS, "Issuer PK recovered. RID %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx CSN %02hhx:%02hhx:%02hhx",
                  issuer_pk->rid[0],
                  issuer_pk->rid[1],
                  issuer_pk->rid[2],
                  issuer_pk->rid[3],
                  issuer_pk->rid[4],
                  issuer_pk->index,
                  issuer_pk->serial[0],
                  issuer_pk->serial[1],
                  issuer_pk->serial[2]
                 );

    const struct tlv *sda_tlv = tlvdb_get(tlv, 0x21, NULL);
    if (!sda_tlv || sda_tlv->len < 1) {
        emv_pk_free(issuer_pk);
        emv_pk_free(pk);
        PrintAndLogEx(WARNING, "Can't find input list for Offline Data Authentication. Exit.");
        return 3;
    }

    struct tlvdb *dac_db = emv_pki_recover_dac(issuer_pk, tlv, sda_tlv);
    if (dac_db) {
        const struct tlv *dac_tlv = tlvdb_get(dac_db, 0x9f45, NULL);
        PrintAndLogEx(NORMAL, "SDA verified OK. (Data Authentication Code: %02hhx:%02hhx)\n", dac_tlv->value[0], dac_tlv->value[1]);
        tlvdb_add(tlv, dac_db);
    } else {
        emv_pk_free(issuer_pk);
        emv_pk_free(pk);
        PrintAndLogEx(WARNING, "SSAD verify error");
        return 4;
    }

    emv_pk_free(issuer_pk);
    emv_pk_free(pk);
    return 0;
}

static const unsigned char default_ddol_value[] = {0x9f, 0x37, 0x04};
static struct tlv default_ddol_tlv = {.tag = 0x9f49, .len = 3, .value = default_ddol_value };

int trDDA(EMVCommandChannel channel, bool decodeTLV, struct tlvdb *tlv) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    struct emv_pk *pk = get_ca_pk(tlv);
    if (!pk) {
        PrintAndLogEx(WARNING, "Error: Key not found. Exit.");
        return 2;
    }

    const struct tlv *sda_tlv = tlvdb_get(tlv, 0x21, NULL);
    /* if (!sda_tlv || sda_tlv->len < 1) { it may be 0!!!!
            emv_pk_free(pk);
            PrintAndLogEx(WARNING, "Error: Can't find input list for Offline Data Authentication. Exit.");
            return 3;
        }
    */
    struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(pk, tlv);
    if (!issuer_pk) {
        emv_pk_free(pk);
        PrintAndLogEx(WARNING, "Error: Issuer certificate not found. Exit.");
        return 2;
    }
    PrintAndLogEx(SUCCESS, "Issuer PK recovered. RID %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx CSN %02hhx:%02hhx:%02hhx\n",
                  issuer_pk->rid[0],
                  issuer_pk->rid[1],
                  issuer_pk->rid[2],
                  issuer_pk->rid[3],
                  issuer_pk->rid[4],
                  issuer_pk->index,
                  issuer_pk->serial[0],
                  issuer_pk->serial[1],
                  issuer_pk->serial[2]
                 );

    struct emv_pk *icc_pk = emv_pki_recover_icc_cert(issuer_pk, tlv, sda_tlv);
    if (!icc_pk) {
        emv_pk_free(pk);
        emv_pk_free(issuer_pk);
        PrintAndLogEx(WARNING, "Error: ICC certificate not found. Exit.");
        return 2;
    }
    PrintAndLogEx(SUCCESS, "ICC PK recovered. RID %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx CSN %02hhx:%02hhx:%02hhx\n",
                  icc_pk->rid[0],
                  icc_pk->rid[1],
                  icc_pk->rid[2],
                  icc_pk->rid[3],
                  icc_pk->rid[4],
                  icc_pk->index,
                  icc_pk->serial[0],
                  icc_pk->serial[1],
                  icc_pk->serial[2]
                 );

    if (tlvdb_get(tlv, 0x9f2d, NULL)) {
        struct emv_pk *icc_pe_pk = emv_pki_recover_icc_pe_cert(issuer_pk, tlv);
        if (!icc_pe_pk) {
            PrintAndLogEx(WARNING, "WARNING: ICC PE PK recover error. ");
        } else {
            PrintAndLogEx(SUCCESS, "ICC PE PK recovered. RID %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx CSN %02hhx:%02hhx:%02hhx\n",
                          icc_pe_pk->rid[0],
                          icc_pe_pk->rid[1],
                          icc_pe_pk->rid[2],
                          icc_pe_pk->rid[3],
                          icc_pe_pk->rid[4],
                          icc_pe_pk->index,
                          icc_pe_pk->serial[0],
                          icc_pe_pk->serial[1],
                          icc_pe_pk->serial[2]
                         );
        }
    } else {
        PrintAndLogEx(INFO, "ICC PE PK (PIN Encipherment Public Key Certificate) not found.\n");
    }

    // 9F4B: Signed Dynamic Application Data
    const struct tlv *sdad_tlv = tlvdb_get(tlv, 0x9f4b, NULL);
    // DDA with internal authenticate OR fDDA with filled 0x9F4B tag (GPO result)
    // EMV kernel3 v2.4, contactless book C-3, C.1., page 147
    if (sdad_tlv) {
        PrintAndLogEx(NORMAL, "\n* * Got Signed Dynamic Application Data (9F4B) form GPO. Maybe fDDA...");

        const struct tlvdb *atc_db = emv_pki_recover_atc_ex(icc_pk, tlv, true);
        if (!atc_db) {
            PrintAndLogEx(WARNING, "Error: Can't recover IDN (ICC Dynamic Number)");
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            return 8;
        }

        // 9f36 Application Transaction Counter (ATC)
        const struct tlv *atc_tlv = tlvdb_get(atc_db, 0x9f36, NULL);
        if (atc_tlv) {
            PrintAndLogEx(NORMAL, "\nATC (Application Transaction Counter) [%zu] %s", atc_tlv->len, sprint_hex_inrow(atc_tlv->value, atc_tlv->len));

            const struct tlv *core_atc_tlv = tlvdb_get(tlv, 0x9f36, NULL);
            if (tlv_equal(core_atc_tlv, atc_tlv)) {
                PrintAndLogEx(SUCCESS, "ATC check OK.");
                PrintAndLogEx(SUCCESS, "fDDA (fast DDA) verified OK.");
            } else {
                PrintAndLogEx(WARNING, "Error: fDDA verified, but ATC in the certificate and ATC in the record not the same.");
            }
        } else {
            PrintAndLogEx(NORMAL, "\nERROR: fDDA (fast DDA) verify error");
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            return 9;
        }
    } else {
        struct tlvdb *dac_db = emv_pki_recover_dac(issuer_pk, tlv, sda_tlv);
        if (dac_db) {
            const struct tlv *dac_tlv = tlvdb_get(dac_db, 0x9f45, NULL);
            PrintAndLogEx(NORMAL, "SDAD verified OK. (Data Authentication Code: %02hhx:%02hhx)\n", dac_tlv->value[0], dac_tlv->value[1]);
            tlvdb_add(tlv, dac_db);
        } else {
            PrintAndLogEx(WARNING, "Error: SSAD verify error");
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            return 4;
        }

        PrintAndLogEx(NORMAL, "\n* Calc DDOL");
        const struct tlv *ddol_tlv = tlvdb_get(tlv, 0x9f49, NULL);
        if (!ddol_tlv) {
            ddol_tlv = &default_ddol_tlv;
            PrintAndLogEx(NORMAL, "DDOL [9f49] not found. Using default DDOL");
        }

        struct tlv *ddol_data_tlv = dol_process(ddol_tlv, tlv, 0);
        if (!ddol_data_tlv) {
            PrintAndLogEx(WARNING, "Error: Can't create DDOL TLV");
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            return 5;
        }

        PrintAndLogEx(NORMAL, "DDOL data[%d]: %s", ddol_data_tlv->len, sprint_hex(ddol_data_tlv->value, ddol_data_tlv->len));

        PrintAndLogEx(NORMAL, "\n* Internal Authenticate");
        int res = EMVInternalAuthenticate(channel, true, (uint8_t *)ddol_data_tlv->value, ddol_data_tlv->len, buf, sizeof(buf), &len, &sw, NULL);
        if (res) {
            PrintAndLogEx(WARNING, "Internal Authenticate error(%d): %4x. Exit...", res, sw);
            free(ddol_data_tlv);
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            return 6;
        }

        struct tlvdb *dda_db = NULL;
        if (buf[0] == 0x80) {
            if (len < 3) {
                PrintAndLogEx(WARNING, "Error: Internal Authenticate format1 parsing error. length=%d", len);
            } else {
                // parse response 0x80
                struct tlvdb *t80 = tlvdb_parse_multi(buf, len);
                const struct tlv *t80tlv = tlvdb_get_tlv(t80);

                // 9f4b Signed Dynamic Application Data
                dda_db = tlvdb_fixed(0x9f4b, t80tlv->len, t80tlv->value);
                tlvdb_add(tlv, dda_db);

                tlvdb_free(t80);

                if (decodeTLV) {
                    PrintAndLogEx(NORMAL, "* * Decode response format 1:");
                    TLVPrintFromTLV(dda_db);
                }
            }
        } else {
            dda_db = tlvdb_parse_multi(buf, len);
            if (!dda_db) {
                PrintAndLogEx(WARNING, "Error: Can't parse Internal Authenticate result as TLV");
                free(ddol_data_tlv);
                emv_pk_free(pk);
                emv_pk_free(issuer_pk);
                emv_pk_free(icc_pk);
                return 7;
            }
            tlvdb_add(tlv, dda_db);

            if (decodeTLV)
                TLVPrintFromTLV(dda_db);
        }

        struct tlvdb *idn_db = emv_pki_recover_idn_ex(icc_pk, dda_db, ddol_data_tlv, true);
        free(ddol_data_tlv);
        if (!idn_db) {
            PrintAndLogEx(WARNING, "Error: Can't recover IDN (ICC Dynamic Number)");
            tlvdb_free(dda_db);
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            return 8;
        }
        tlvdb_free(dda_db);

        // 9f4c ICC Dynamic Number
        const struct tlv *idn_tlv = tlvdb_get(idn_db, 0x9f4c, NULL);
        if (idn_tlv) {
            PrintAndLogEx(INFO, "\nIDN (ICC Dynamic Number) [%zu] %s", idn_tlv->len, sprint_hex_inrow(idn_tlv->value, idn_tlv->len));
            PrintAndLogEx(INFO, "DDA verified OK.");
            tlvdb_add(tlv, idn_db);
            tlvdb_free(idn_db);
        } else {
            PrintAndLogEx(ERR, "\nDDA verify error");
            tlvdb_free(idn_db);

            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            return 9;
        }
    }

    emv_pk_free(pk);
    emv_pk_free(issuer_pk);
    emv_pk_free(icc_pk);
    return 0;
}

int trCDA(struct tlvdb *tlv, struct tlvdb *ac_tlv, struct tlv *pdol_data_tlv, struct tlv *ac_data_tlv) {

    struct emv_pk *pk = get_ca_pk(tlv);
    if (!pk) {
        PrintAndLogEx(WARNING, "Error: Key not found. Exit.");
        return 2;
    }

    const struct tlv *sda_tlv = tlvdb_get(tlv, 0x21, NULL);
    if (!sda_tlv || sda_tlv->len < 1) {
        PrintAndLogEx(WARNING, "Error: Can't find input list for Offline Data Authentication. Exit.");
        emv_pk_free(pk);
        return 3;
    }

    struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(pk, tlv);
    if (!issuer_pk) {
        PrintAndLogEx(WARNING, "Error: Issuer certificate not found. Exit.");
        emv_pk_free(pk);
        return 2;
    }
    PrintAndLogEx(SUCCESS, "Issuer PK recovered. RID %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx CSN %02hhx:%02hhx:%02hhx\n",
                  issuer_pk->rid[0],
                  issuer_pk->rid[1],
                  issuer_pk->rid[2],
                  issuer_pk->rid[3],
                  issuer_pk->rid[4],
                  issuer_pk->index,
                  issuer_pk->serial[0],
                  issuer_pk->serial[1],
                  issuer_pk->serial[2]
                 );

    struct emv_pk *icc_pk = emv_pki_recover_icc_cert(issuer_pk, tlv, sda_tlv);
    if (!icc_pk) {
        PrintAndLogEx(WARNING, "Error: ICC certificate not found. Exit.");
        emv_pk_free(pk);
        emv_pk_free(issuer_pk);
        return 2;
    }
    PrintAndLogEx(SUCCESS, "ICC PK recovered. RID %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx CSN %02hhx:%02hhx:%02hhx\n",
                  icc_pk->rid[0],
                  icc_pk->rid[1],
                  icc_pk->rid[2],
                  icc_pk->rid[3],
                  icc_pk->rid[4],
                  icc_pk->index,
                  icc_pk->serial[0],
                  icc_pk->serial[1],
                  icc_pk->serial[2]
                 );

    struct tlvdb *dac_db = emv_pki_recover_dac(issuer_pk, tlv, sda_tlv);
    if (dac_db) {
        const struct tlv *dac_tlv = tlvdb_get(dac_db, 0x9f45, NULL);
        PrintAndLogEx(NORMAL, "SSAD verified OK. (%02hhx:%02hhx)", dac_tlv->value[0], dac_tlv->value[1]);
        tlvdb_add(tlv, dac_db);
    } else {
        PrintAndLogEx(WARNING, "Error: SSAD verify error");
        emv_pk_free(pk);
        emv_pk_free(issuer_pk);
        emv_pk_free(icc_pk);
        return 4;
    }

    PrintAndLogEx(NORMAL, "\n* * Check Signed Dynamic Application Data (SDAD)");
    struct tlvdb *idn_db = emv_pki_perform_cda_ex(icc_pk, tlv, ac_tlv,
                                                  pdol_data_tlv, // pdol
                                                  ac_data_tlv,   // cdol1
                                                  NULL,          // cdol2
                                                  true);
    if (idn_db) {
        const struct tlv *idn_tlv = tlvdb_get(idn_db, 0x9f4c, NULL);
        PrintAndLogEx(NORMAL, "\nIDN (ICC Dynamic Number) [%zu] %s", idn_tlv->len, sprint_hex_inrow(idn_tlv->value, idn_tlv->len));
        PrintAndLogEx(NORMAL, "CDA verified OK.");
        tlvdb_add(tlv, idn_db);
    } else {
        PrintAndLogEx(ERR, "\nERROR: CDA verify error");
    }

    emv_pk_free(pk);
    emv_pk_free(issuer_pk);
    emv_pk_free(icc_pk);
    return 0;
}

int RecoveryCertificates(struct tlvdb *tlvRoot, json_t *root) {

    struct emv_pk *pk = get_ca_pk(tlvRoot);
    if (!pk) {
        PrintAndLogEx(ERR, "ERROR: Key not found. Exit.");
        return 1;
    }

    struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(pk, tlvRoot);
    if (!issuer_pk) {
        emv_pk_free(pk);
        PrintAndLogEx(WARNING, "WARNING: Issuer certificate not found. Exit.");
        return 2;
    }
    PrintAndLogEx(SUCCESS, "Issuer PK recovered. RID %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx CSN %02hhx:%02hhx:%02hhx",
                  issuer_pk->rid[0],
                  issuer_pk->rid[1],
                  issuer_pk->rid[2],
                  issuer_pk->rid[3],
                  issuer_pk->rid[4],
                  issuer_pk->index,
                  issuer_pk->serial[0],
                  issuer_pk->serial[1],
                  issuer_pk->serial[2]
                 );

    JsonSaveBufAsHex(root, "$.ApplicationData.RID", issuer_pk->rid, 5);

    char *issuer_pk_c = emv_pk_dump_pk(issuer_pk);
    JsonSaveStr(root, "$.ApplicationData.IssuerPublicKeyDec", issuer_pk_c);
    JsonSaveBufAsHex(root, "$.ApplicationData.IssuerPublicKeyModulus", issuer_pk->modulus, issuer_pk->mlen);
    free(issuer_pk_c);

    struct emv_pk *icc_pk = emv_pki_recover_icc_cert(issuer_pk, tlvRoot, NULL);
    if (!icc_pk) {
        emv_pk_free(pk);
        emv_pk_free(issuer_pk);
        PrintAndLogEx(WARNING, "WARNING: ICC certificate not found. Exit.");
        return 2;
    }
    PrintAndLogEx(SUCCESS, "ICC PK recovered. RID %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx CSN %02hhx:%02hhx:%02hhx\n",
                  icc_pk->rid[0],
                  icc_pk->rid[1],
                  icc_pk->rid[2],
                  icc_pk->rid[3],
                  icc_pk->rid[4],
                  icc_pk->index,
                  icc_pk->serial[0],
                  icc_pk->serial[1],
                  icc_pk->serial[2]
                 );

    char *icc_pk_c = emv_pk_dump_pk(icc_pk);
    JsonSaveStr(root, "$.ApplicationData.ICCPublicKeyDec", icc_pk_c);
    JsonSaveBufAsHex(root, "$.ApplicationData.ICCPublicKeyModulus", icc_pk->modulus, icc_pk->mlen);
    free(issuer_pk_c);

    return 0;
}
