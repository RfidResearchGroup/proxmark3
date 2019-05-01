//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// Merlok - 2017
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency commands
//-----------------------------------------------------------------------------
#include "cmdhf.h"

static int CmdHelp(const char *Cmd);

static int usage_hf_search() {
    PrintAndLogEx(NORMAL, "Usage: hf search");
    PrintAndLogEx(NORMAL, "Will try to find a HF read out of the unknown tag. Stops when found.");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h               - This help");
    PrintAndLogEx(NORMAL, "");
    return 0;
}
static int usage_hf_sniff() {
    PrintAndLogEx(NORMAL, "The high frequence sniffer will assign all available memory on device for sniffed data");
    PrintAndLogEx(NORMAL, "Use " _YELLOW_("'data samples'")" command to download from device,  and " _YELLOW_("'data plot'")" to look at it");
    PrintAndLogEx(NORMAL, "Press button to quit the sniffing.\n");
    PrintAndLogEx(NORMAL, "Usage: hf sniff <skip pairs> <skip triggers>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h               - This help");
    PrintAndLogEx(NORMAL, "       <skip pairs>    - skip sample pairs");
    PrintAndLogEx(NORMAL, "       <skip triggers> - skip number of triggers");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           hf sniff");
    PrintAndLogEx(NORMAL, "           hf sniff 1000 0");
    return 0;
}

int CmdHFSearch(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_search();

    PrintAndLogEx(INFO, "Checking for known tags...\n");

    if (infoHF14A(false, false) > 0) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("ISO14443-A tag") " found\n");
        return 1;
    }
    if (readHF15Uid(false) == 1) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("ISO15693 tag") " found\n");
        return 1;
    }
    if (readLegicUid(false) == 0) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("LEGIC tag") " found\n");
        return 1;
    }
    if (readTopazUid() == 0) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Topaz tag") " found\n");
        return 1;
    }
    // 14b and iclass is the longest test (put last)
    if (readHF14B(false) == 1) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("ISO14443-B tag") " found\n");
        return 1;
    }
    if (readIclass(false, false) == 1) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("iClass tag / PicoPass tag") " found\n");
        return 1;
    }

    /*
    ans = CmdHFFelicaReader("s");
    if (ans) {
        PrintAndLogEx(NORMAL, "\nValid " _GREEN_("ISO18092 / FeliCa tag") " found\n");
        return ans;
    }
    */

    PrintAndLogEx(FAILED, "\nno known/supported 13.56 MHz tags found\n");
    return 0;
}

int CmdHFTune(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    PrintAndLogEx(SUCCESS, "Measuring HF antenna, press button to exit");
    clearCommandBuffer();
    SendCommandOLD(CMD_MEASURE_ANTENNA_TUNING_HF, 0, 0, 0, NULL, 0);
    return 0;
}

int CmdHFSniff(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_sniff();

    int skippairs =  param_get32ex(Cmd, 0, 0, 10);
    int skiptriggers =  param_get32ex(Cmd, 1, 0, 10);

    clearCommandBuffer();
    SendCommandOLD(CMD_HF_SNIFFER, skippairs, skiptriggers, 0, NULL, 0);
    return 0;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,          AlwaysAvailable, "This help"},
    {"14a",         CmdHF14A,         AlwaysAvailable, "{ ISO14443A RFIDs...               }"},
    {"14b",         CmdHF14B,         AlwaysAvailable, "{ ISO14443B RFIDs...               }"},
    {"15",          CmdHF15,          AlwaysAvailable, "{ ISO15693 RFIDs...                }"},
    {"epa",         CmdHFEPA,         AlwaysAvailable, "{ German Identification Card...    }"},
    {"felica",      CmdHFFelica,      AlwaysAvailable, "{ ISO18092 / Felica RFIDs...       }"},
    {"legic",       CmdHFLegic,       AlwaysAvailable, "{ LEGIC RFIDs...                   }"},
    {"iclass",      CmdHFiClass,      AlwaysAvailable, "{ ICLASS RFIDs...                  }"},
    {"mf",          CmdHFMF,          AlwaysAvailable, "{ MIFARE RFIDs...                  }"},
    {"mfp",         CmdHFMFP,         AlwaysAvailable, "{ MIFARE Plus RFIDs...             }"},
    {"mfu",         CmdHFMFUltra,     AlwaysAvailable, "{ MIFARE Ultralight RFIDs...       }"},
    {"mfdes",       CmdHFMFDes,       AlwaysAvailable, "{ MIFARE Desfire RFIDs...          }"},
    {"topaz",       CmdHFTopaz,       AlwaysAvailable, "{ TOPAZ (NFC Type 1) RFIDs...      }"},
    {"fido",        CmdHFFido,        AlwaysAvailable, "{ FIDO and FIDO2 authenticators... }"},
    {"list",        CmdTraceList,     IfPm3Present,    "List protocol data in trace buffer"},
    {"tune",        CmdHFTune,        IfPm3Present,    "Continuously measure HF antenna tuning"},
    {"search",      CmdHFSearch,      AlwaysAvailable, "Search for known HF tags [preliminary]"},
    {"sniff",       CmdHFSniff,       IfPm3Hfsniff,    "<samples to skip (10000)> <triggers to skip (1)> Generic HF Sniff"},
    {NULL, NULL, NULL, NULL}
};

int CmdHF(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return 0;
}
