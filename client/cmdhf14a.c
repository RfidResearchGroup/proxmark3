//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>, Hagen Fritsch
// 2011, 2017 - 2019 Merlok
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

bool APDUInFramingEnable = true;

static int CmdHelp(const char *Cmd);
static int waitCmd(uint8_t iSelect);

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
    { 0x45, "Invengo Information Technology Co.Ltd China" },
    { 0x46, "Guangzhou Sysur Microelectronics, Inc China" },
    { 0x47, "CEITEC S.A. Brazil" },
    { 0x48, "Shanghai Quanray Electronics Co. Ltd. China" },
    { 0x49, "MediaTek Inc Taiwan" },
    { 0x4A, "Angstrem PJSC Russia" },
    { 0x4B, "Celisic Semiconductor (Hong Kong) Limited China" },
    { 0x4C, "LEGIC Identsystems AG Switzerland" },
    { 0x4D, "Balluff GmbH Germany" },
    { 0x4E, "Oberthur Technologies France" },
    { 0x4F, "Silterra Malaysia Sdn. Bhd. Malaysia" },
    { 0x50, "DELTA Danish Electronics, Light & Acoustics Denmark" },
    { 0x51, "Giesecke & Devrient GmbH Germany" },
    { 0x52, "Shenzhen China Vision Microelectronics Co., Ltd. China" },
    { 0x53, "Shanghai Feiju Microelectronics Co. Ltd. China" },
    { 0x54, "Intel Corporation USA" },
    { 0x55, "Microsensys GmbH Germany" },
    { 0x56, "Sonix Technology Co., Ltd. Taiwan" },
    { 0x57, "Qualcomm Technologies Inc USA" },
    { 0x58, "Realtek Semiconductor Corp Taiwan" },
    { 0x59, "Freevision Technologies Co. Ltd China" },
    { 0x5A, "Giantec Semiconductor Inc. China" },
    { 0x5B, "JSC Angstrem-T Russia" },
    { 0x5C, "STARCHIP France" },
    { 0x5D, "SPIRTECH France" },
    { 0x5E, "GANTNER Electronic GmbH Austria" },
    { 0x5F, "Nordic Semiconductor Norway" },
    { 0x60, "Verisiti Inc USA" },
    { 0x61, "Wearlinks Technology Inc. China" },
    { 0x62, "Userstar Information Systems Co., Ltd Taiwan" },
    { 0x63, "Pragmatic Printing Ltd. UK" },
    { 0x64, "Associacao do Laboratorio de Sistemas Integraveis Tecnologico – LSI-TEC Brazil" },
    { 0x65, "Tendyron Corporation China" },
    { 0x66, "MUTO Smart Co., Ltd. Korea" },
    { 0x67, "ON Semiconductor USA" },
    { 0x68, "TUBITAK BILGEM Turkey" },
    { 0x69, "Huada Semiconductor Co., Ltd China" },
    { 0x6A, "SEVENEY France" },
    { 0x6B, "ISSM France" },
    { 0x6C, "Wisesec Ltd Israel" },
    { 0x7C, "DB HiTek Co Ltd Korea" },
    { 0x7D, "SATO Vicinity Australia" },
    { 0x7E, "Holtek Taiwan" },
    { 0x00, "no tag-info available" } // must be the last entry
};

// get a product description based on the UID
//  uid[8] tag uid
// returns description of the best match
const char *getTagInfo(uint8_t uid) {

    int i;
    int len = sizeof(manufactureMapping) / sizeof(manufactureName);

    for (i = 0; i < len; ++i)
        if (uid == manufactureMapping[i].uid)
            return manufactureMapping[i].desc;

    //No match, return default
    return manufactureMapping[len - 1].desc;
}

// iso14a apdu input frame length
static uint16_t frameLength = 0;
uint16_t atsFSC[] = {16, 24, 32, 40, 48, 64, 96, 128, 256};

static int usage_hf_14a_sim(void) {
//  PrintAndLogEx(NORMAL, "\n Emulating ISO/IEC 14443 type A tag with 4,7 or 10 byte UID\n");
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
//  PrintAndLogEx(NORMAL, "    u     : 4, 7 or 10 byte UID");
    PrintAndLogEx(NORMAL, "    u     : 4, 7 byte UID");
    PrintAndLogEx(NORMAL, "    x     : (Optional) Performs the 'reader attack', nr/ar attack against a reader");
    PrintAndLogEx(NORMAL, "    e     : (Optional) Fill simulator keys from found keys");
    PrintAndLogEx(NORMAL, "    v     : (Optional) Verbose");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "          hf 14a sim t 1 u 11223344 x");
    PrintAndLogEx(NORMAL, "          hf 14a sim t 1 u 11223344");
    PrintAndLogEx(NORMAL, "          hf 14a sim t 1 u 11223344556677");
//  PrintAndLogEx(NORMAL, "          hf 14a sim t 1 u 11223445566778899AA\n");
    return 0;
}
static int usage_hf_14a_sniff(void) {
    PrintAndLogEx(NORMAL, "It get data from the field and saves it into command buffer.");
    PrintAndLogEx(NORMAL, "Buffer accessible from command 'hf list 14a'");
    PrintAndLogEx(NORMAL, "Usage:  hf 14a sniff [c][r]");
    PrintAndLogEx(NORMAL, "c - triggered by first data from card");
    PrintAndLogEx(NORMAL, "r - triggered by first 7-bit request from reader (REQ,WUP,...)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf 14a sniff c r");
    return 0;
}
static int usage_hf_14a_raw(void) {
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
static int usage_hf_14a_reader(void) {
    PrintAndLogEx(NORMAL, "Usage: hf 14a reader [k|s|x] [3]");
    PrintAndLogEx(NORMAL, "       k    keep the field active after command executed");
    PrintAndLogEx(NORMAL, "       s    silent (no messages)");
    PrintAndLogEx(NORMAL, "       x    just drop the signal field");
    PrintAndLogEx(NORMAL, "       3    ISO14443-3 select only (skip RATS)");
    return 0;
}
static int usage_hf_14a_info(void) {
    PrintAndLogEx(NORMAL, "This command makes more extensive tests against a ISO14443a tag in order to collect information");
    PrintAndLogEx(NORMAL, "Usage: hf 14a info [h|s]");
    PrintAndLogEx(NORMAL, "       s    silent (no messages)");
    PrintAndLogEx(NORMAL, "       n    test for nack bug");
    return 0;
}

static int CmdHF14AList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    //PrintAndLogEx(NORMAL, "Deprecated command, use 'hf list 14a' instead");
    CmdTraceList("14a");
    return 0;
}

int Hf14443_4aGetCardData(iso14a_card_select_t *card) {
    SendCommandMIX(CMD_READER_ISO_14443a, ISO14A_CONNECT, 0, 0, NULL, 0);

    PacketResponseNG resp;
    WaitForResponse(CMD_ACK, &resp);

    memcpy(card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    uint64_t select_status = resp.oldarg[0]; // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision

    if (select_status == 0) {
        PrintAndLogEx(ERR, "E->iso14443a card select failed");
        return 1;
    }

    if (select_status == 2) {
        PrintAndLogEx(ERR, "E->Card doesn't support iso14443-4 mode");
        return 1;
    }

    if (select_status == 3) {
        PrintAndLogEx(NORMAL, "E->Card doesn't support standard iso14443-3 anticollision");
        PrintAndLogEx(NORMAL, "\tATQA : %02x %02x", card->atqa[1], card->atqa[0]);
        return 1;
    }

    PrintAndLogEx(NORMAL, " UID: %s", sprint_hex(card->uid, card->uidlen));
    PrintAndLogEx(NORMAL, "ATQA: %02x %02x", card->atqa[1], card->atqa[0]);
    PrintAndLogEx(NORMAL, " SAK: %02x [%" PRIu64 "]", card->sak, resp.oldarg[0]);
    if (card->ats_len < 3) { // a valid ATS consists of at least the length byte (TL) and 2 CRC bytes
        PrintAndLogEx(NORMAL, "E-> Error ATS length(%d) : %s", card->ats_len, sprint_hex(card->ats, card->ats_len));
        return 1;
    }

    PrintAndLogEx(NORMAL, " ATS: %s", sprint_hex(card->ats, card->ats_len));
    return 0;
}

static int CmdHF14AReader(const char *Cmd) {

    uint32_t cm = ISO14A_CONNECT;
    bool disconnectAfter = true, silent = false;
    int cmdp = 0;

    while (param_getchar(Cmd, cmdp) != 0x00) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_14a_reader();
            case '3':
                cm |= ISO14A_NO_RATS;
                break;
            case 'k':
                disconnectAfter = false;
                break;
            case 's':
                silent = true;
                break;
            case 'x':
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

    clearCommandBuffer();
    SendCommandMIX(CMD_READER_ISO_14443a, cm, 0, 0, NULL, 0);

    if (ISO14A_CONNECT & cm) {
        PacketResponseNG resp;
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
            if (!silent) PrintAndLogEx(WARNING, "iso14443a card select failed");
            DropField();
            return 1;
        }

        iso14a_card_select_t card;
        memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

        /*
            0: couldn't read
            1: OK, with ATS
            2: OK, no ATS
            3: proprietary Anticollision
        */
        uint64_t select_status = resp.oldarg[0];

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
        PrintAndLogEx(NORMAL, " SAK : %02x [%" PRIu64 "]", card.sak, resp.oldarg[0]);

        if (card.ats_len >= 3) { // a valid ATS consists of at least the length byte (TL) and 2 CRC bytes
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

static int CmdHF14AInfo(const char *Cmd) {

    if (Cmd[0] == 'h' || Cmd[0] ==  'H') return usage_hf_14a_info();

    bool verbose = !(Cmd[0] == 's' || Cmd[0] ==  'S');
    bool do_nack_test = (Cmd[0] == 'n' || Cmd[0] ==  'N');
    infoHF14A(verbose, do_nack_test);
    return 0;
}

// Collect ISO14443 Type A UIDs
static int CmdHF14ACUIDs(const char *Cmd) {
    // requested number of UIDs
    int n = atoi(Cmd);
    // collect at least 1 (e.g. if no parameter was given)
    n = n > 0 ? n : 1;

    uint64_t t1 =  msclock();
    PrintAndLogEx(SUCCESS, "collecting %d UIDs", n);

    // repeat n times
    for (int i = 0; i < n; i++) {

        if (ukbhit()) {
            int gc = getchar();
            (void)gc;
            PrintAndLogEx(WARNING, "\n[!] aborted via keyboard!\n");
            break;
        }

        // execute anticollision procedure
        SendCommandMIX(CMD_READER_ISO_14443a, ISO14A_CONNECT | ISO14A_NO_RATS, 0, 0, NULL, 0);

        PacketResponseNG resp;
        WaitForResponse(CMD_ACK, &resp);

        iso14a_card_select_t *card = (iso14a_card_select_t *) resp.data.asBytes;

        // check if command failed
        if (resp.oldarg[0] == 0) {
            PrintAndLogEx(WARNING, "card select failed.");
        } else {
            char uid_string[20];
            for (uint16_t m = 0; m < card->uidlen; m++) {
                sprintf(&uid_string[2 * m], "%02X", card->uid[m]);
            }
            PrintAndLogEx(NORMAL, "%s", uid_string);
        }
    }
    PrintAndLogEx(SUCCESS, "end: %" PRIu64 " seconds", (msclock() - t1) / 1000);
    return 1;
}
// ## simulate iso14443a tag
int CmdHF14ASim(const char *Cmd) {

    int uidlen = 0;
    uint8_t flags = 0, tagtype = 1, cmdp = 0;
    uint8_t uid[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    bool useUIDfromEML = true;
    bool setEmulatorMem = false;
    bool verbose = false;
    bool errors = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_14a_sim();
            case 't':
                // Retrieve the tag type
                tagtype = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (tagtype == 0)
                    errors = true;
                cmdp += 2;
                break;
            case 'u':
                // Retrieve the full 4,7,10 byte long uid
                param_gethex_ex(Cmd, cmdp + 1, uid, &uidlen);
                uidlen >>= 1;
                switch (uidlen) {
                    //case 10: flags |= FLAG_10B_UID_IN_DATA; break;
                    case 7:
                        flags |= FLAG_7B_UID_IN_DATA;
                        break;
                    case 4:
                        flags |= FLAG_4B_UID_IN_DATA;
                        break;
                    default:
                        errors = true;
                        break;
                }
                if (!errors) {
                    PrintAndLogEx(SUCCESS, "Emulating ISO/IEC 14443 type A tag with %d byte UID (%s)", uidlen, sprint_hex(uid, uidlen));
                    useUIDfromEML = false;
                }
                cmdp += 2;
                break;
            case 'v':
                verbose = true;
                cmdp++;
                break;
            case 'x':
                flags |= FLAG_NR_AR_ATTACK;
                cmdp++;
                break;
            case 'e':
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

    if (useUIDfromEML)
        flags |= FLAG_UID_IN_EMUL;

    struct {
        uint8_t tagtype;
        uint8_t flags;
        uint8_t uid[10];
    } PACKED payload;

    payload.tagtype = tagtype;
    payload.flags = flags;
    memcpy(payload.uid, uid, uidlen);

    clearCommandBuffer();
    SendCommandNG(CMD_SIMULATE_TAG_ISO_14443a, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;

    PrintAndLogEx(SUCCESS, "press pm3-button to abort simulation");

    while (!ukbhit()) {
        if (WaitForResponseTimeout(CMD_SIMULATE_MIFARE_CARD, &resp, 1500) == 0) continue;
        if (resp.status != PM3_SUCCESS) break;

        if ((flags & FLAG_NR_AR_ATTACK) != FLAG_NR_AR_ATTACK) break;

        nonces_t *data = (nonces_t *)resp.data.asBytes;
        readerAttack(data[0], setEmulatorMem, verbose);
    }
    if (resp.status == PM3_EOPABORTED && ((flags & FLAG_NR_AR_ATTACK) == FLAG_NR_AR_ATTACK))
        showSectorTable();

    PrintAndLogEx(INFO, "Done");
    return PM3_SUCCESS;
}

int CmdHF14ASniff(const char *Cmd) {
    uint8_t param = 0;
    for (uint8_t i = 0; i < 2; i++) {
        uint8_t ctmp = tolower(param_getchar(Cmd, i));
        if (ctmp == 'h') return usage_hf_14a_sniff();
        if (ctmp == 'c') param |= 0x01;
        if (ctmp == 'r') param |= 0x02;
    }
    clearCommandBuffer();
    SendCommandNG(CMD_SNIFF_ISO_14443a, (uint8_t *)&param, sizeof(uint8_t));
    return PM3_SUCCESS;
}

int ExchangeRAW14a(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    static uint8_t responseNum = 0;
    uint16_t cmdc = 0;
    *dataoutlen = 0;

    if (activateField) {
        responseNum = 1;
        PacketResponseNG resp;

        // Anticollision + SELECT card
        SendCommandMIX(CMD_READER_ISO_14443a, ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
            PrintAndLogEx(ERR, "Proxmark3 connection timeout.");
            return 1;
        }

        // check result
        if (resp.oldarg[0] == 0) {
            PrintAndLogEx(ERR, "No card in field.");
            return 1;
        }

        if (resp.oldarg[0] != 1 && resp.oldarg[0] != 2) {
            PrintAndLogEx(ERR, "Card not in iso14443-4. res=%d.", resp.oldarg[0]);
            return 1;
        }

        if (resp.oldarg[0] == 2) { // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision
            // get ATS
            uint8_t rats[] = { 0xE0, 0x80 }; // FSDI=8 (FSD=256), CID=0
            SendCommandOLD(CMD_READER_ISO_14443a, ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_DISCONNECT, 2, 0, rats, 2);
            if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
                PrintAndLogEx(ERR, "Proxmark3 connection timeout.");
                return 1;
            }

            if (resp.oldarg[0] == 0) { // ats_len
                PrintAndLogEx(ERR, "Can't get ATS.");
                return 1;
            }
        }
    }

    if (leaveSignalON)
        cmdc |= ISO14A_NO_DISCONNECT;

    uint8_t data[PM3_CMD_DATA_SIZE] = { 0x0a | responseNum, 0x00};
    responseNum ^= 1;
    memcpy(&data[2], datain, datainlen & 0xFFFF);
    SendCommandOLD(CMD_READER_ISO_14443a, ISO14A_RAW | ISO14A_APPEND_CRC | cmdc, (datainlen & 0xFFFF) + 2, 0, data, (datainlen & 0xFFFF) + 2);

    uint8_t *recv;
    PacketResponseNG resp;

    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        recv = resp.data.asBytes;
        int iLen = resp.oldarg[0];

        if (!iLen) {
            PrintAndLogEx(ERR, "No card response.");
            return 1;
        }

        *dataoutlen = iLen - 2;
        if (*dataoutlen < 0)
            *dataoutlen = 0;

        if (maxdataoutlen && *dataoutlen > maxdataoutlen) {
            PrintAndLogEx(ERR, "Buffer too small(%d). Needs %d bytes", *dataoutlen, maxdataoutlen);
            return 2;
        }

        if (recv[0] != data[0]) {
            PrintAndLogEx(ERR, "iso14443-4 framing error. Card send %2x must be %2x", dataout[0], data[0]);
            return 2;
        }

        memcpy(dataout, &recv[2], *dataoutlen);

        // CRC Check
        if (iLen == -1) {
            PrintAndLogEx(ERR, "ISO 14443A CRC error.");
            return 3;
        }

    } else {
        PrintAndLogEx(ERR, "Reply timeout.");
        return 4;
    }

    return 0;
}

static int SelectCard14443_4(bool disconnect, iso14a_card_select_t *card) {
    PacketResponseNG resp;

    frameLength = 0;

    if (card)
        memset(card, 0, sizeof(iso14a_card_select_t));

    DropField();

    // Anticollision + SELECT card
    SendCommandMIX(CMD_READER_ISO_14443a, ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        PrintAndLogEx(ERR, "Proxmark3 connection timeout.");
        return 1;
    }

    // check result
    if (resp.oldarg[0] == 0) {
        PrintAndLogEx(ERR, "No card in field.");
        return 1;
    }

    if (resp.oldarg[0] != 1 && resp.oldarg[0] != 2) {
        PrintAndLogEx(ERR, "Card not in iso14443-4. res=%d.", resp.oldarg[0]);
        return 1;
    }

    if (resp.oldarg[0] == 2) { // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision
        // get ATS
        uint8_t rats[] = { 0xE0, 0x80 }; // FSDI=8 (FSD=256), CID=0
        SendCommandOLD(CMD_READER_ISO_14443a, ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_DISCONNECT, sizeof(rats), 0, rats, sizeof(rats));
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
            PrintAndLogEx(ERR, "Proxmark3 connection timeout.");
            return 1;
        }

        if (resp.oldarg[0] == 0) { // ats_len
            PrintAndLogEx(ERR, "Can't get ATS.");
            return 1;
        }

        // get frame length from ATS in data field
        if (resp.oldarg[0] > 1) {
            uint8_t fsci = resp.data.asBytes[1] & 0x0f;
            if (fsci < ARRAYLEN(atsFSC))
                frameLength = atsFSC[fsci];
        }
    } else {
        // get frame length from ATS in card data structure
        iso14a_card_select_t *vcard = (iso14a_card_select_t *) resp.data.asBytes;
        if (vcard->ats_len > 1) {
            uint8_t fsci = vcard->ats[1] & 0x0f;
            if (fsci < ARRAYLEN(atsFSC))
                frameLength = atsFSC[fsci];
        }

        if (card)
            memcpy(card, vcard, sizeof(iso14a_card_select_t));
    }

    if (disconnect)
        DropField();

    return 0;
}

static int CmdExchangeAPDU(bool chainingin, uint8_t *datain, int datainlen, bool activateField, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, bool *chainingout) {
    *chainingout = false;

    if (activateField) {
        // select with no disconnect and set frameLength
        int selres = SelectCard14443_4(false, NULL);
        if (selres)
            return selres;
    }

    uint16_t cmdc = 0;
    if (chainingin)
        cmdc = ISO14A_SEND_CHAINING;

    // "Command APDU" length should be 5+255+1, but javacard's APDU buffer might be smaller - 133 bytes
    // https://stackoverflow.com/questions/32994936/safe-max-java-card-apdu-data-command-and-respond-size
    // here length PM3_CMD_DATA_SIZE=512
    // timeout must be authomatically set by "get ATS"
    if (datain)
        SendCommandOLD(CMD_READER_ISO_14443a, ISO14A_APDU | ISO14A_NO_DISCONNECT | cmdc, (datainlen & 0xFFFF), 0, datain, datainlen & 0xFFFF);
    else
        SendCommandMIX(CMD_READER_ISO_14443a, ISO14A_APDU | ISO14A_NO_DISCONNECT | cmdc, 0, 0, NULL, 0);

    PacketResponseNG resp;

    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t *recv = resp.data.asBytes;
        int iLen = resp.oldarg[0];
        uint8_t res = resp.oldarg[1];

        int dlen = iLen - 2;
        if (dlen < 0)
            dlen = 0;
        *dataoutlen += dlen;

        if (maxdataoutlen && *dataoutlen > maxdataoutlen) {
            PrintAndLogEx(ERR, "APDU: Buffer too small(%d). Needs %d bytes", *dataoutlen, maxdataoutlen);
            return 2;
        }

        // I-block ACK
        if ((res & 0xf2) == 0xa2) {
            *dataoutlen = 0;
            *chainingout = true;
            return 0;
        }

        if (!iLen) {
            PrintAndLogEx(ERR, "APDU: No APDU response.");
            return 1;
        }

        // check apdu length
        if (iLen < 2 && iLen >= 0) {
            PrintAndLogEx(ERR, "APDU: Small APDU response. Len=%d", iLen);
            return 2;
        }

        // check block TODO
        if (iLen == -2) {
            PrintAndLogEx(ERR, "APDU: Block type mismatch.");
            return 2;
        }

        memcpy(dataout, recv, dlen);

        // chaining
        if ((res & 0x10) != 0) {
            *chainingout = true;
        }

        // CRC Check
        if (iLen == -1) {
            PrintAndLogEx(ERR, "APDU: ISO 14443A CRC error.");
            return 3;
        }
    } else {
        PrintAndLogEx(ERR, "APDU: Reply timeout.");
        return 4;
    }

    return 0;
}

int ExchangeAPDU14a(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    *dataoutlen = 0;
    bool chaining = false;
    int res;

    // 3 byte here - 1b framing header, 2b crc16
    if (APDUInFramingEnable &&
            ((frameLength && (datainlen > frameLength - 3)) || (datainlen > PM3_CMD_DATA_SIZE - 3))) {
        int clen = 0;

        bool vActivateField = activateField;

        do {
            int vlen = MIN(frameLength - 3, datainlen - clen);
            bool chainBlockNotLast = ((clen + vlen) < datainlen);

            *dataoutlen = 0;
            res = CmdExchangeAPDU(chainBlockNotLast, &datain[clen], vlen, vActivateField, dataout, maxdataoutlen, dataoutlen, &chaining);
            if (res) {
                if (!leaveSignalON)
                    DropField();

                return 200;
            }

            // check R-block ACK
//TODO check this one...
            if ((*dataoutlen == 0) && (*dataoutlen != 0 || chaining != chainBlockNotLast)) { // *dataoutlen!=0. 'A && (!A || B)' is equivalent to 'A && B'
                if (!leaveSignalON)
                    DropField();

                return 201;
            }

            clen += vlen;
            vActivateField = false;
            if (*dataoutlen) {
                if (clen != datainlen)
                    PrintAndLogEx(WARNING, "APDU: I-block/R-block sequence error. Data len=%d, Sent=%d, Last packet len=%d", datainlen, clen, *dataoutlen);
                break;
            }
        } while (clen < datainlen);
    } else {
        res = CmdExchangeAPDU(false, datain, datainlen, activateField, dataout, maxdataoutlen, dataoutlen, &chaining);
        if (res) {
            if (!leaveSignalON)
                DropField();

            return res;
        }
    }

    while (chaining) {
        // I-block with chaining
        res = CmdExchangeAPDU(false, NULL, 0, false, &dataout[*dataoutlen], maxdataoutlen, dataoutlen, &chaining);

        if (res) {
            if (!leaveSignalON)
                DropField();

            return 100;
        }
    }

    if (!leaveSignalON)
        DropField();

    return 0;
}

// ISO14443-4. 7. Half-duplex block transmission protocol
static int CmdHF14AAPDU(const char *Cmd) {
    uint8_t data[PM3_CMD_DATA_SIZE];
    int datalen = 0;
    bool activateField = false;
    bool leaveSignalON = false;
    bool decodeTLV = false;

    CLIParserInit("hf 14a apdu",
                  "Sends an ISO 7816-4 APDU via ISO 14443-4 block transmission protocol (T=CL)",
                  "Sample:\n\thf 14a apdu -st 00A404000E325041592E5359532E444446303100\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("sS",  "select",  "activate field and select card"),
        arg_lit0("kK",  "keep",    "leave the signal field ON after receive response"),
        arg_lit0("tT",  "tlv",     "executes TLV decoder if it possible"),
        arg_strx1(NULL, NULL,      "<APDU (hex)>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    activateField = arg_get_lit(1);
    leaveSignalON = arg_get_lit(2);
    decodeTLV = arg_get_lit(3);
    // len = data + PCB(1b) + CRC(2b)
    CLIGetHexBLessWithReturn(4, data, &datalen, 1 + 2);

    CLIParserFree();
    PrintAndLogEx(NORMAL, ">>>>[%s%s%s] %s", activateField ? "sel " : "", leaveSignalON ? "keep " : "", decodeTLV ? "TLV" : "", sprint_hex(data, datalen));

    int res = ExchangeAPDU14a(data, datalen, activateField, leaveSignalON, data, PM3_CMD_DATA_SIZE, &datalen);

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

static int CmdHF14ACmdRaw(const char *Cmd) {
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
    char buf[5] = "";
    int i = 0;
    uint8_t data[PM3_CMD_DATA_SIZE];
    uint16_t datalen = 0;
    uint32_t temp;

    if (strlen(Cmd) < 2) return usage_hf_14a_raw();

    // strip
    while (*Cmd == ' ' || *Cmd == '\t') Cmd++;

    while (Cmd[i] != '\0') {
        if (Cmd[i] == ' ' || Cmd[i] == '\t') { i++; continue; }
        if (Cmd[i] == '-') {
            switch (Cmd[i + 1]) {
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
                    sscanf(Cmd + i + 2, "%d", &temp);
                    numbits = temp & 0xFFFF;
                    i += 3;
                    while (Cmd[i] != ' ' && Cmd[i] != '\0') { i++; }
                    i -= 2;
                    break;
                case 't':
                    bTimeout = true;
                    sscanf(Cmd + i + 2, "%d", &temp);
                    timeout = temp;
                    i += 3;
                    while (Cmd[i] != ' ' && Cmd[i] != '\0') { i++; }
                    i -= 2;
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
        if ((Cmd[i] >= '0' && Cmd[i] <= '9') ||
                (Cmd[i] >= 'a' && Cmd[i] <= 'f') ||
                (Cmd[i] >= 'A' && Cmd[i] <= 'F')) {
            buf[strlen(buf) + 1] = 0;
            buf[strlen(buf)] = Cmd[i];
            i++;

            if (strlen(buf) >= 2) {
                sscanf(buf, "%x", &temp);
                data[datalen] = (uint8_t)(temp & 0xff);
                *buf = 0;
                if (++datalen >= sizeof(data)) {
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

    if (crc && datalen > 0 && datalen < sizeof(data) - 2) {
        uint8_t first, second;
        if (topazmode) {
            compute_crc(CRC_14443_B, data, datalen, &first, &second);
        } else {
            compute_crc(CRC_14443_A, data, datalen, &first, &second);
        }
        data[datalen++] = first;
        data[datalen++] = second;
    }

    uint16_t flags = 0;
    if (active || active_select) {
        flags |= ISO14A_CONNECT;
        if (active)
            flags |= ISO14A_NO_SELECT;
    }

    uint32_t argtimeout = 0;
    if (bTimeout) {
#define MAX_TIMEOUT 40542464 // = (2^32-1) * (8*16) / 13560000Hz * 1000ms/s
        flags |= ISO14A_SET_TIMEOUT;
        if (timeout > MAX_TIMEOUT) {
            timeout = MAX_TIMEOUT;
            PrintAndLogEx(NORMAL, "Set timeout to 40542 seconds (11.26 hours). The max we can wait for response");
        }
        argtimeout = 13560000 / 1000 / (8 * 16) * timeout; // timeout in ETUs (time to transfer 1 bit, approx. 9.4 us)
    }

    if (power) {
        flags |= ISO14A_NO_DISCONNECT;
    }

    if (datalen > 0) {
        flags |= ISO14A_RAW;
    }

    if (topazmode) {
        flags |= ISO14A_TOPAZMODE;
    }
    if (no_rats) {
        flags |= ISO14A_NO_RATS;
    }

    // Max buffer is PM3_CMD_DATA_SIZE
    datalen = (datalen > PM3_CMD_DATA_SIZE) ? PM3_CMD_DATA_SIZE : datalen;

    clearCommandBuffer();
    SendCommandOLD(CMD_READER_ISO_14443a, flags, (datalen & 0xFFFF) | ((uint32_t)(numbits << 16)), argtimeout, data, datalen & 0xFFFF);

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
    PacketResponseNG resp;

    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint16_t len = (resp.oldarg[0] & 0xFFFF);
        if (iSelect) {
            len = (resp.oldarg[1] & 0xFFFF);
            if (len) {
                PrintAndLogEx(NORMAL, "Card selected. UID[%i]:", len);
            } else {
                PrintAndLogEx(WARNING, "Can't select card.");
            }
        } else {
            PrintAndLogEx(NORMAL, "received %i bytes", len);
        }

        if (!len)
            return 1;

        PrintAndLogEx(NORMAL, "%s", sprint_hex(resp.data.asBytes, len));
    } else {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return 3;
    }
    return 0;
}

static int CmdHF14AAntiFuzz(const char *Cmd) {

    CLIParserInit("hf 14a antifuzz",
                  "Tries to fuzz the ISO14443a anticollision phase",
                  "Usage:\n"
                  "\thf 14a antifuzz -4\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("4",   NULL,  "4 byte uid"),
        arg_lit0("7",   NULL,  "7 byte uid"),
        arg_lit0(NULL,  "10",  "10 byte uid"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    uint8_t arg0 = FLAG_4B_UID_IN_DATA;
    if (arg_get_lit(2))
        arg0 = FLAG_7B_UID_IN_DATA;
    if (arg_get_lit(3))
        arg0 = FLAG_10B_UID_IN_DATA;

    CLIParserFree();
    clearCommandBuffer();
    SendCommandMIX(CMD_ANTIFUZZ_ISO_14443a, arg0, 0, 0, NULL, 0);
    return 0;
}

static int CmdHF14AChaining(const char *Cmd) {

    CLIParserInit("hf 14a chaining",
                  "Enable/Disable ISO14443a input chaining. Maximum input length goes from ATS.",
                  "Usage:\n"
                  "\thf 14a chaining disable -> disable chaining\n"
                  "\thf 14a chaining         -> show chaining enable/disable state\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, NULL,      "<enable/disable or 0/1>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    struct arg_str *str = arg_get_str(1);
    int len = arg_get_str_len(1);

    if (len && (!strcmp(str->sval[0], "enable") || !strcmp(str->sval[0], "1")))
        APDUInFramingEnable = true;

    if (len && (!strcmp(str->sval[0], "disable") || !strcmp(str->sval[0], "0")))
        APDUInFramingEnable = false;

    CLIParserFree();

    PrintAndLogEx(INFO, "\nISO 14443-4 input chaining %s.\n", APDUInFramingEnable ? "enabled" : "disabled");

    return 0;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,              AlwaysAvailable, "This help"},
    {"list",        CmdHF14AList,         AlwaysAvailable,  "List ISO 14443-a history"},
    {"info",        CmdHF14AInfo,         IfPm3Iso14443a,  "Tag information"},
    {"reader",      CmdHF14AReader,       IfPm3Iso14443a,  "Act like an ISO14443-a reader"},
    {"cuids",       CmdHF14ACUIDs,        IfPm3Iso14443a,  "<n> Collect n>0 ISO14443-a UIDs in one go"},
    {"sim",         CmdHF14ASim,          IfPm3Iso14443a,  "<UID> -- Simulate ISO 14443-a tag"},
    {"sniff",       CmdHF14ASniff,        IfPm3Iso14443a,  "sniff ISO 14443-a traffic"},
    {"apdu",        CmdHF14AAPDU,         IfPm3Iso14443a,  "Send ISO 14443-4 APDU to tag"},
    {"chaining",    CmdHF14AChaining,     IfPm3Iso14443a,  "Control ISO 14443-4 input chaining"},
    {"raw",         CmdHF14ACmdRaw,       IfPm3Iso14443a,  "Send raw hex data to tag"},
    {"antifuzz",    CmdHF14AAntiFuzz,     IfPm3Iso14443a,  "Fuzzing the anticollision phase.  Warning! Readers may react strange"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return 0;
}

int CmdHF14A(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int infoHF14A(bool verbose, bool do_nack_test) {
    clearCommandBuffer();
    SendCommandMIX(CMD_READER_ISO_14443a, ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        if (verbose) PrintAndLogEx(WARNING, "iso14443a card select failed");
        DropField();
        return 0;
    }

    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    /*
        0: couldn't read
        1: OK, with ATS
        2: OK, no ATS
        3: proprietary Anticollision
    */
    uint64_t select_status = resp.oldarg[0];

    if (select_status == 0) {
        if (verbose) PrintAndLogEx(WARNING, "iso14443a card select failed");
        DropField();
        return select_status;
    }

    if (select_status == 3) {
        PrintAndLogEx(NORMAL, "Card doesn't support standard iso14443-3 anticollision");
        PrintAndLogEx(NORMAL, "ATQA : %02x %02x", card.atqa[1], card.atqa[0]);
        DropField();
        return select_status;
    }

    PrintAndLogEx(NORMAL, " UID : %s", sprint_hex(card.uid, card.uidlen));
    PrintAndLogEx(NORMAL, "ATQA : %02x %02x", card.atqa[1], card.atqa[0]);
    PrintAndLogEx(NORMAL, " SAK : %02x [%" PRIu64 "]", card.sak, resp.oldarg[0]);

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
            clearCommandBuffer();
            SendCommandMIX(CMD_READER_ISO_14443a, ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
            WaitForResponse(CMD_ACK, &resp);

            memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

            select_status = resp.oldarg[0]; // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS

            if (select_status == 0) {
                DropField();
                return select_status;
            }
            break;
        case 0x01:
            PrintAndLogEx(NORMAL, "TYPE : NXP TNP3xxx Activision Game Appliance");
            break;
        case 0x04:
            PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE (various !DESFire !DESFire EV1)");
            isMifareClassic = false;
            break;
        case 0x08:
            PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1 | 1k Ev1");
            break;
        case 0x09:
            PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE Mini 0.3k");
            break;
        case 0x0A:
            PrintAndLogEx(NORMAL, "TYPE : FM11RF005SH (Shanghai Metro)");
            break;
        case 0x10:
            PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE Plus 2k SL2");
            break;
        case 0x11:
            PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE Plus 4k SL2");
            break;
        case 0x18:
            PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE Classic 4k | Plus 4k SL1 | 4k Ev1");
            break;
        case 0x20:
            PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE DESFire 4k | DESFire EV1 2k/4k/8k | Plus 2k/4k SL3 | JCOP 31/41");
            isMifareClassic = false;
            break;
        case 0x24:
            PrintAndLogEx(NORMAL, "TYPE : NXP MIFARE DESFire | DESFire EV1");
            isMifareClassic = false;
            break;
        case 0x28:
            PrintAndLogEx(NORMAL, "TYPE : JCOP31 or JCOP41 v2.3.1");
            break;
        case 0x38:
            PrintAndLogEx(NORMAL, "TYPE : Nokia 6212 or 6131 MIFARE CLASSIC 4K");
            break;
        case 0x88:
            PrintAndLogEx(NORMAL, "TYPE : Infineon MIFARE CLASSIC 1K");
            break;
        case 0x98:
            PrintAndLogEx(NORMAL, "TYPE : Gemplus MPCOS");
            break;
        default:
            ;
    }

    // Double & triple sized UID, can be mapped to a manufacturer.
    if (card.uidlen > 4) {
        PrintAndLogEx(NORMAL, "MANUFACTURER : %s", getTagInfo(card.uid[0]));
    }

    // try to request ATS even if tag claims not to support it
    if (select_status == 2) {
        uint8_t rats[] = { 0xE0, 0x80 }; // FSDI=8 (FSD=256), CID=0
        clearCommandBuffer();
        SendCommandOLD(CMD_READER_ISO_14443a, ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_DISCONNECT, 2, 0, rats, sizeof(rats));
        WaitForResponse(CMD_ACK, &resp);

        memcpy(card.ats, resp.data.asBytes, resp.oldarg[0]);
        card.ats_len = resp.oldarg[0]; // note: ats_len includes CRC Bytes
    }

    if (card.ats_len >= 3) {        // a valid ATS consists of at least the length byte (TL) and 2 CRC bytes
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

        if (card.ats[0] > 1) { // there is a format byte (T0)
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
                          fsci < ARRAYLEN(atsFSC) ? atsFSC[fsci] : -1
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
                          ((card.ats[pos] & 0x80) ? " NOT" : ""),
                          dr,
                          ds
                         );

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
        if (card.ats[0] > pos && card.ats[0] <  card.ats_len - 2) {
            const char *tip = "";
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
                    case 0x10:
                        PrintAndLogEx(NORMAL, "                     1x -> MIFARE DESFire");
                        break;
                    case 0x20:
                        PrintAndLogEx(NORMAL, "                     2x -> MIFARE Plus");
                        break;
                }
                switch (card.ats[pos + 2] & 0x0f) {
                    case 0x00:
                        PrintAndLogEx(NORMAL, "                     x0 -> <1 kByte");
                        break;
                    case 0x01:
                        PrintAndLogEx(NORMAL, "                     x1 -> 1 kByte");
                        break;
                    case 0x02:
                        PrintAndLogEx(NORMAL, "                     x2 -> 2 kByte");
                        break;
                    case 0x03:
                        PrintAndLogEx(NORMAL, "                     x3 -> 4 kByte");
                        break;
                    case 0x04:
                        PrintAndLogEx(NORMAL, "                     x4 -> 8 kByte");
                        break;
                }
                switch (card.ats[pos + 3] & 0xf0) {
                    case 0x00:
                        PrintAndLogEx(NORMAL, "                        0x -> Engineering sample");
                        break;
                    case 0x20:
                        PrintAndLogEx(NORMAL, "                        2x -> Released");
                        break;
                }
                switch (card.ats[pos + 3] & 0x0f) {
                    case 0x00:
                        PrintAndLogEx(NORMAL, "                        x0 -> Generation 1");
                        break;
                    case 0x01:
                        PrintAndLogEx(NORMAL, "                        x1 -> Generation 2");
                        break;
                    case 0x02:
                        PrintAndLogEx(NORMAL, "                        x2 -> Generation 3");
                        break;
                }
                switch (card.ats[pos + 4] & 0x0f) {
                    case 0x00:
                        PrintAndLogEx(NORMAL, "                           x0 -> Only VCSL supported");
                        break;
                    case 0x01:
                        PrintAndLogEx(NORMAL, "                           x1 -> VCS, VCSL, and SVC supported");
                        break;
                    case 0x0E:
                        PrintAndLogEx(NORMAL, "                           xE -> no VCS command supported");
                        break;
                }
            }
        }
    } else {
        PrintAndLogEx(INFO, "proprietary non iso14443-4 card found, RATS not supported");
    }

    detect_classic_magic();

    if (isMifareClassic) {
        int res = detect_classic_prng();
        if (res == 1)
            PrintAndLogEx(SUCCESS, "Prng detection: " _GREEN_("WEAK"));
        else if (res == 0)
            PrintAndLogEx(SUCCESS, "Prng detection: " _YELLOW_("HARD"));
        else
            PrintAndLogEx(FAILED, "prng detection:  " _RED_("Fail"));

        if (do_nack_test)
            detect_classic_nackbug(!verbose);
    }

    return select_status;
}

