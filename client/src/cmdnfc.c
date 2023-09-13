//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// NFC commands
//-----------------------------------------------------------------------------
#include "cmdnfc.h"
#include "nfc/ndef.h"
#include "cliparser.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhf14a.h"
#include "cmdhf14b.h"
#include "cmdhfmf.h"
#include "cmdhfmfp.h"
#include "cmdhfmfu.h"
#include "cmdhfst25ta.h"
#include "cmdhfthinfilm.h"
#include "cmdhftopaz.h"
#include "cmdnfc.h"
#include "fileutils.h"
#include "mifare/mifaredefault.h"
#include "mifare/mad.h"

void print_type4_cc_info(uint8_t *d, uint8_t n) {
    if (n < 0x0F) {
        PrintAndLogEx(WARNING, "Not enough bytes read from CC file");
        return;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "------------ " _CYAN_("Capability Container file") " ------------");
    PrintAndLogEx(SUCCESS, " Version... %s ( " _GREEN_("0x%02X") " )", (d[2] == 0x20) ? "v2.0" : "v1.0", d[2]);
    PrintAndLogEx(SUCCESS, " Len....... %u bytes ( " _GREEN_("0x%02X") " )", d[1], d[1]);
    uint16_t maxr = (d[3] << 8 | d[4]);
    PrintAndLogEx(SUCCESS, " Max bytes read  %u bytes ( 0x%04X )", maxr, maxr);
    uint16_t maxw = (d[5] << 8 | d[6]);
    PrintAndLogEx(SUCCESS, " Max bytes write %u bytes ( 0x%04X )", maxw, maxw);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, " NDEF file control TLV");
    PrintAndLogEx(SUCCESS, "    (t) type of file.... %02X", d[7]);
    PrintAndLogEx(SUCCESS, "    (v) ................ %02X", d[8]);
    PrintAndLogEx(SUCCESS, "    file id............. %02X%02X", d[9], d[10]);

    uint16_t maxndef = (d[11] << 8 | d[12]);
    PrintAndLogEx(SUCCESS, "    Max NDEF filesize... %u bytes ( 0x%04X )", maxndef, maxndef);
    PrintAndLogEx(SUCCESS, "    " _CYAN_("Access rights"));
    PrintAndLogEx(SUCCESS, "    read   ( %02X ) protection: %s", d[13], ((d[13] & 0x80) == 0x80) ? _RED_("enabled") : _GREEN_("disabled"));
    PrintAndLogEx(SUCCESS, "    write  ( %02X ) protection: %s", d[14], ((d[14] & 0x80) == 0x80) ? _RED_("enabled") : _GREEN_("disabled"));
    PrintAndLogEx(SUCCESS, "");
    PrintAndLogEx(SUCCESS, "----------------- " _CYAN_("raw") " -----------------");
    PrintAndLogEx(SUCCESS, "%s", sprint_hex_inrow(d, n));
    PrintAndLogEx(NORMAL, "");
}

static int CmdNfcDecode(const char *Cmd) {

#ifndef MAX_NDEF_LEN
#define MAX_NDEF_LEN  2048
#endif

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "nfc decode",
                  "Decode and print NFC Data Exchange Format (NDEF)\n"
                  "You must provide either data in hex or a filename, but not both",
                  "nfc decode -d 9101085402656e48656c6c6f5101085402656e576f726c64\n"
                  "nfc decode -d 0103d020240203e02c040300fe\n"
                  "nfc decode -f myfilename"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("d",  "data", "<hex>", "NDEF data to decode"),
        arg_str0("f", "file", "<fn>", "file to load"),
        arg_lit0("v",  "verbose", "verbose mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int datalen = 0;
    uint8_t data[MAX_NDEF_LEN] = {0};
    CLIGetHexWithReturn(ctx, 1, data, &datalen);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool verbose = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);
    if (((datalen != 0) && (fnlen != 0)) || ((datalen == 0) && (fnlen == 0))) {
        PrintAndLogEx(ERR, "You must provide either data in hex or a filename");
        return PM3_EINVARG;
    }
    int res = PM3_SUCCESS;
    if (fnlen != 0) {

        // read dump file
        uint8_t *dump = NULL;
        size_t bytes_read = 4096;
        res = pm3_load_dump(filename, (void **)&dump, &bytes_read, 4096);
        if (res != PM3_SUCCESS || dump == NULL || bytes_read > 4096) {
            return res;
        }

        // convert from MFC dump file to a pure NDEF byte array
        if (HasMADKey(dump)) {
            PrintAndLogEx(SUCCESS, "MFC dump file detected. Converting...");
            uint8_t ndef[4096] = {0};
            uint16_t ndeflen = 0;

            if (convert_mad_to_arr(dump, bytes_read, ndef, &ndeflen) != PM3_SUCCESS) {
                PrintAndLogEx(FAILED, "Failed converting, aborting...");
                free(dump);
                return PM3_ESOFT;
            }

            memcpy(dump, ndef, ndeflen);
            bytes_read = ndeflen;
        }

        res = NDEFDecodeAndPrint(dump, bytes_read, verbose);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(INFO, "Trying to parse NDEF records w/o NDEF header");
            res = NDEFRecordsDecodeAndPrint(dump, bytes_read, verbose);
        }

        free(dump);

    } else {
        res = NDEFDecodeAndPrint(data, datalen, verbose);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(INFO, "Trying to parse NDEF records w/o NDEF header");
            res = NDEFRecordsDecodeAndPrint(data, datalen, verbose);
        }
    }
    return res;
}

static int CmdNFCType1Read(const char *Cmd) {
    return CmdHFTopazInfo(Cmd);
}

static int CmdNFCType1Help(const char *Cmd);

static command_t CommandNFCType1Table[] = {

    {"--------",    CmdNFCType1Help,  AlwaysAvailable, "-------------- " _CYAN_("NFC Forum Tag Type 1") " ---------------"},
//    {"format",     CmdNFCType1Format,  IfPm3Iso14443a,  "format ISO-14443-a tag as NFC Tag"},
    {"read",        CmdNFCType1Read,  IfPm3Iso14443a,  "read NFC Forum Tag Type 1"},
//    {"write",        CmdNFCType1Write, IfPm3Iso14443a, "write NFC Forum Tag Type 1"},
    {"--------",    CmdNFCType1Help,  AlwaysAvailable, "--------------------- " _CYAN_("General") " ---------------------"},
    {"help",        CmdNFCType1Help,  AlwaysAvailable, "This help"},
    {NULL, NULL, NULL, NULL}
};

static int CmdNFCType1(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandNFCType1Table, Cmd);
}

static int CmdNFCType1Help(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandNFCType1Table);
    return PM3_SUCCESS;
}

static int CmdNFCType2Read(const char *Cmd) {
    return CmdHF14MfuNDEFRead(Cmd);
}

static int CmdNFCType2Help(const char *Cmd);

static command_t CommandNFCType2Table[] = {

    {"--------",    CmdNFCType2Help,  AlwaysAvailable, "-------------- " _CYAN_("NFC Forum Tag Type 2") " ---------------"},
//    {"format",     CmdNFCType2Format,  IfPm3Iso14443a,  "format ISO-14443-a tag as NFC Tag"},
    {"read",        CmdNFCType2Read,  IfPm3Iso14443a,  "read NFC Forum Tag Type 2"},
//    {"write",        CmdNFCType2Write, IfPm3Iso14443a, "write NFC Forum Tag Type 2"},
    {"--------",    CmdNFCType2Help,  AlwaysAvailable, "--------------------- " _CYAN_("General") " ---------------------"},
    {"help",        CmdNFCType2Help,  AlwaysAvailable, "This help"},
    {NULL, NULL, NULL, NULL}
};

static int CmdNFCType2(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandNFCType2Table, Cmd);
}

static int CmdNFCType2Help(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandNFCType2Table);
    return PM3_SUCCESS;
}

/*
static int CmdNFCType3Read(const char *Cmd) {
    return CmdHFFelicaXXX(Cmd);
}

static int CmdNFCType3Help(const char *Cmd);

static command_t CommandNFCType3Table[] = {

    {"--------",    CmdNFCType3Help,  AlwaysAvailable, "-------------- " _CYAN_("NFC Forum Tag Type 3") " ---------------"},
//    {"format",        CmdNFCType3Format,  IfPm3Felica, "format FeliCa tag as NFC Tag"},
    {"read",        CmdNFCType3Read,  IfPm3Felica, "read NFC Forum Tag Type 3"},
//    {"write",       CmdNFCType3Write, IfPm3Felica, "write NFC Forum Tag Type 3"},
    {"--------",    CmdNFCType3Help,  AlwaysAvailable, "--------------------- " _CYAN_("General") " ---------------------"},
    {"help",        CmdNFCType3Help,  AlwaysAvailable, "This help"},
    {NULL, NULL, NULL, NULL}
};

static int CmdNFCType3(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandNFCType3Table, Cmd);
}

static int CmdNFCType3Help(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandNFCType3Table);
    return PM3_SUCCESS;
}
*/

static int CmdNFCType4ARead(const char *Cmd) {
    return CmdHF14ANdefRead(Cmd);
}

static int CmdNFCST25TARead(const char *Cmd) {
    return CmdHFST25TANdefRead(Cmd);
}

static int CmdNFCType4AFormat(const char *Cmd) {
    return CmdHF14ANdefFormat(Cmd);
}

static int CmdNFCType4AWrite(const char *Cmd) {
    return CmdHF14ANdefWrite(Cmd);
}

static int CmdNFCType4AHelp(const char *Cmd);

static command_t CommandNFCType4ATable[] = {

    {"--------",     CmdNFCType4AHelp,   AlwaysAvailable, "--------- " _CYAN_("NFC Forum Tag Type 4 ISO14443A") " ----------"},
    {"format",       CmdNFCType4AFormat, IfPm3Iso14443a,  "format ISO-14443-a tag as NFC Tag"},
    {"read",         CmdNFCType4ARead,   IfPm3Iso14443a,  "read NFC Forum Tag Type 4 A"},
    {"write",        CmdNFCType4AWrite,  IfPm3Iso14443a,  "write NFC Forum Tag Type 4 A"},
//    {"mfdesread",    CmdNFCMFDESRead,   IfPm3Iso14443a,  "read NDEF from MIFARE DESfire"}, // hf mfdes ndefread
//    {"mfdesformat",  CmdNFCMFDESFormat, IfPm3Iso14443a,  "format MIFARE DESfire as NFC Forum Tag Type 4"},
    {"st25taread",   CmdNFCST25TARead,   IfPm3Iso14443a,  "read ST25TA as NFC Forum Tag Type 4"},

    {"--------",     CmdNFCType4AHelp,   AlwaysAvailable, "--------------------- " _CYAN_("General") " ---------------------"},
    {"help",         CmdNFCType4AHelp,   AlwaysAvailable, "This help"},
    {NULL, NULL, NULL, NULL}
};

static int CmdNFCType4A(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandNFCType4ATable, Cmd);
}

static int CmdNFCType4AHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandNFCType4ATable);
    return PM3_SUCCESS;
}

static int CmdNFCType4BRead(const char *Cmd) {
    return CmdHF14BNdefRead(Cmd);
}

static int CmdNFCType4BHelp(const char *Cmd);

static command_t CommandNFCType4BTable[] = {

    {"--------",    CmdNFCType4BHelp,  AlwaysAvailable, "--------- " _CYAN_("NFC Forum Tag Type 4 ISO14443B") " -------------"},
//    {"format",     CmdNFCType4BFormat,  IfPm3Iso14443b,  "format ISO-14443-b tag as NFC Tag"},
    {"read",        CmdNFCType4BRead,  IfPm3Iso14443b,  "read NFC Forum Tag Type 4 B"},
//    {"write",       CmdNFCType4BWrite, IfPm3Iso14443b,  "write NFC Forum Tag Type 4 B"},
    {"--------",    CmdNFCType4BHelp,  AlwaysAvailable, "--------------------- " _CYAN_("General") " ---------------------"},
    {"help",        CmdNFCType4BHelp,  AlwaysAvailable, "This help"},
    {NULL, NULL, NULL, NULL}
};

static int CmdNFCType4B(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandNFCType4BTable, Cmd);
}

static int CmdNFCType4BHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandNFCType4BTable);
    return PM3_SUCCESS;
}

/*
static int CmdNFCType5Read(const char *Cmd) {
    return CmdHF15XXX(Cmd);
}

static int CmdNFCType5Help(const char *Cmd);

static command_t CommandNFCType5Table[] = {

    {"--------",    CmdNFCType5Help,  AlwaysAvailable, "-------------- " _CYAN_("NFC Forum Tag Type 5") " ---------------"},
//    {"format",     CmdNFCType5Format,  IfPm3Iso15693,  "format ISO-15693 tag as NFC Tag"},
    {"read",        CmdNFCType5Read,  IfPm3Iso15693,   "read NFC Forum Tag Type 5"},
//    {"write",       CmdNFCType5Write, IfPm3Iso15693,   "write NFC Forum Tag Type 5"},
    {"--------",    CmdNFCType5Help,  AlwaysAvailable, "--------------------- " _CYAN_("General") " ---------------------"},
    {"help",        CmdNFCType5Help,  AlwaysAvailable, "This help"},
    {NULL, NULL, NULL, NULL}
};

static int CmdNFCType5(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandNFCType5Table, Cmd);
}

static int CmdNFCType5Help(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandNFCType5Table);
    return PM3_SUCCESS;
}
*/

static int CmdNFCMFCRead(const char *Cmd) {
    return CmdHFMFNDEFRead(Cmd);
}

static int CmdNFCMFCFormat(const char *Cmd) {
    return CmdHFMFNDEFFormat(Cmd);
}

static int CmdNFCMFCWrite(const char *Cmd) {
    return CmdHFMFNDEFWrite(Cmd);
}


static int CmdNFCMFPRead(const char *Cmd) {
    return CmdHFMFPNDEFRead(Cmd);
}

static int CmdNFCMFHelp(const char *Cmd);

static command_t CommandMFTable[] = {

    {"--------",    CmdNFCMFHelp,     AlwaysAvailable, "--------- " _CYAN_("NFC Type MIFARE Classic/Plus Tag") " --------"},
    {"cformat",     CmdNFCMFCFormat,  IfPm3Iso14443a,  "format MIFARE Classic Tag as NFC Tag"},
    {"cread",       CmdNFCMFCRead,    IfPm3Iso14443a,  "read NFC Type MIFARE Classic Tag"},
    {"cwrite",      CmdNFCMFCWrite,  IfPm3Iso14443a,   "write NFC Type MIFARE Classic Tag"},
    {"pread",       CmdNFCMFPRead,    IfPm3Iso14443a,  "read NFC Type MIFARE Plus Tag"},
    {"--------",    CmdNFCMFHelp,     AlwaysAvailable, "--------------------- " _CYAN_("General") " ---------------------"},
    {"help",        CmdNFCMFHelp,     AlwaysAvailable, "This help"},
    {NULL, NULL, NULL, NULL}
};

static int CmdNFCMF(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandMFTable, Cmd);
}

static int CmdNFCMFHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandMFTable);
    return PM3_SUCCESS;
}

static int CmdNFCBarcodeRead(const char *Cmd) {
    return CmdHfThinFilmInfo(Cmd);
}

static int CmdNFCBarcodeSim(const char *Cmd) {
    return CmdHfThinFilmSim(Cmd);
}

static int CmdNFCBarcodeHelp(const char *Cmd);

static command_t CommandBarcodeTable[] = {

    {"--------",    CmdNFCBarcodeHelp,     AlwaysAvailable, "------------------ " _CYAN_("NFC Barcode") " --------------------"},
    {"read",        CmdNFCBarcodeRead,     IfPm3Iso14443a,  "read NFC Barcode"},
    {"sim",         CmdNFCBarcodeSim,      IfPm3Iso14443a,  "simulate NFC Barcode"},
    {"--------",    CmdNFCBarcodeHelp,     AlwaysAvailable, "--------------------- " _CYAN_("General") " ---------------------"},
    {"help",        CmdNFCBarcodeHelp,     AlwaysAvailable, "This help"},
    {NULL, NULL, NULL, NULL}
};

static int CmdNFCBarcode(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandBarcodeTable, Cmd);
}

static int CmdNFCBarcodeHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandBarcodeTable);
    return PM3_SUCCESS;
}

static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {

    {"--------",    CmdHelp,          AlwaysAvailable, "--------------------- " _CYAN_("NFC Tags") " --------------------"},
    {"type1",       CmdNFCType1,      AlwaysAvailable, "{ NFC Forum Tag Type 1...             }"},
    {"type2",       CmdNFCType2,      AlwaysAvailable, "{ NFC Forum Tag Type 2...             }"},
//    {"type3",       CmdNFCType3,      AlwaysAvailable, "{ NFC Forum Tag Type 3...             }"},
    {"type4a",      CmdNFCType4A,     AlwaysAvailable, "{ NFC Forum Tag Type 4 ISO14443A...   }"},
    {"type4b",      CmdNFCType4B,     AlwaysAvailable, "{ NFC Forum Tag Type 4 ISO14443B...   }"},
//    {"type5",       CmdNFCType5,      AlwaysAvailable, "{ NFC Forum Tag Type 5...             }"},
    {"mf",          CmdNFCMF,         AlwaysAvailable, "{ NFC Type MIFARE Classic/Plus Tag... }"},
    {"barcode",     CmdNFCBarcode,    AlwaysAvailable, "{ NFC Barcode Tag...                  }"},
//    {"--------",    CmdHelp,          AlwaysAvailable, "--------------------- " _CYAN_("NFC peer-to-peer") " ------------"},
//    {"isodep",      CmdISODEP,        AlwaysAvailable, "{ ISO-DEP protocol...                 }"},
//    {"llcp",        CmdNFCLLCP,       AlwaysAvailable, "{ Logical Link Control Protocol...    }"},
//    {"snep",        CmdNFCSNEP,       AlwaysAvailable, "{ Simple NDEF Exchange Protocol...    }"},
    {"--------",    CmdHelp,          AlwaysAvailable, "--------------------- " _CYAN_("General") " ---------------------"},
    {"help",        CmdHelp,          AlwaysAvailable, "This help"},
    {"decode",      CmdNfcDecode,     AlwaysAvailable, "Decode NDEF records"},
//    {"encode",      CmdNfcEncode,     AlwaysAvailable, "Encode NDEF records"},
    {NULL, NULL, NULL, NULL}
};

int CmdNFC(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}
