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

static int usage_hf_tune() {
    PrintAndLogEx(NORMAL, "Usage: hf tune [<iter>]");
    PrintAndLogEx(NORMAL, "Continuously measure HF antenna tuning.");
    PrintAndLogEx(NORMAL, "Press button or keyboard to interrupt.");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       <iter>               - number of iterations (default: infinite)");
    PrintAndLogEx(NORMAL, "");
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
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_tune();
    int iter =  param_get32ex(Cmd, 0, 0, 10);

    PacketResponseNG resp;
    PrintAndLogEx(SUCCESS, "Measuring HF antenna, click button or press a key to exit");
    clearCommandBuffer();
    uint8_t mode[] = {1};
    SendCommandNG(CMD_MEASURE_ANTENNA_TUNING_HF, mode, sizeof(mode));
    if (!WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING_HF, &resp, 1000)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for Proxmark HF initialization, aborting");
        return PM3_ETIMEOUT;
    }
    mode[0] = 2;
    // loop forever (till button pressed) if iter = 0 (default)
    for (uint8_t i = 0; iter == 0 || i < iter; i++) {
        if (ukbhit()) { // abort by keyboard press
            int gc = getchar();
            (void)gc;
            break;
        }
        SendCommandNG(CMD_MEASURE_ANTENNA_TUNING_HF, mode, sizeof(mode));
        if (!WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING_HF, &resp, 1000)) {
            PrintAndLogEx(WARNING, "Timeout while waiting for Proxmark HF measure, aborting");
            return PM3_ETIMEOUT;
        }
        if ((resp.status == PM3_EOPABORTED) || (resp.length != sizeof(uint16_t)))
            break;
        uint16_t volt = resp.data.asDwords[0];
        PrintAndLogEx(INPLACE, "%u mV / %5u V", volt, (uint16_t)(volt / 1000));
    }
    mode[0] = 3;
    SendCommandNG(CMD_MEASURE_ANTENNA_TUNING_HF, mode, sizeof(mode));
    if (!WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING_HF, &resp, 1000)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for Proxmark HF shutdown, aborting");
        return PM3_ETIMEOUT;
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Done.");
    return PM3_SUCCESS;
}

int CmdHFSniff(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_sniff();

    int skippairs =  param_get32ex(Cmd, 0, 0, 10);
    int skiptriggers =  param_get32ex(Cmd, 1, 0, 10);

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_SNIFFER, skippairs, skiptriggers, 0, NULL, 0);
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
    {"list",        CmdTraceList,     AlwaysAvailable,    "List protocol data in trace buffer"},
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
