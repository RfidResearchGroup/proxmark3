//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// Merlok - 2017
// Doegox - 2019
// Iceman - 2019
// Piwi - 2019
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency commands
//-----------------------------------------------------------------------------
#include "cmdhf.h"

#include <ctype.h>          // tolower

#include "cmdparser.h"      // command_t
#include "cliparser/cliparser.h"  // parse
#include "comms.h"          // clearCommandBuffer
#include "lfdemod.h"        // computeSignalProperties
#include "cmdhf14a.h"       // ISO14443-A
#include "cmdhf14b.h"       // ISO14443-B
#include "cmdhf15.h"        // ISO15693
#include "cmdhfepa.h"
#include "cmdhflegic.h"     // LEGIC
#include "cmdhficlass.h"    // ICLASS
#include "cmdhfmf.h"        // CLASSIC
#include "cmdhfmfu.h"       // ULTRALIGHT/NTAG etc
#include "cmdhfmfp.h"       // Mifare Plus
#include "cmdhfmfdes.h"     // DESFIRE
#include "cmdhftopaz.h"     // TOPAZ
#include "cmdhffelica.h"    // ISO18092 / FeliCa
#include "cmdhffido.h"      // FIDO authenticators
#include "cmdhfthinfilm.h"  // Thinfilm
#include "cmdhflto.h"       // LTO-CM
#include "cmdhfcryptorf.h"  // CryptoRF
#include "cmdtrace.h"       // trace list
#include "ui.h"
#include "cmddata.h"
#include "graph.h"
#include "../../common_fpga/fpga.h"

static int CmdHelp(const char *Cmd);

static int usage_hf_search() {
    PrintAndLogEx(NORMAL, "Usage: hf search");
    PrintAndLogEx(NORMAL, "Will try to find a HF read out of the unknown tag. Stops when found.");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h               - This help");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
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
    return PM3_SUCCESS;
}

static int usage_hf_tune() {
    PrintAndLogEx(NORMAL, "Continuously measure HF antenna tuning.");
    PrintAndLogEx(NORMAL, "Press button or Enter to interrupt.");
    PrintAndLogEx(NORMAL, "Usage: hf tune [h] [<iter>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             - This help");
    PrintAndLogEx(NORMAL, "       <iter>        - number of iterations (default: 0=infinite)");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

#define PROMPT_CLEARLINE PrintAndLogEx(INPLACE, "                                          ")

int CmdHFSearch(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_search();

    int res = PM3_ESOFT;

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, "Searching for ThinFilm tag...");
    if (IfPm3NfcBarcode()) {
        if (infoThinFilm(false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Thinfilm tag") "found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, "Searching for LTO-CM tag...");
    if (IfPm3Iso14443a()) {
        if (infoLTO(false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("LTO-CM tag") "found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, "Searching for ISO14443-A tag...");
    if (IfPm3Iso14443a()) {
        if (infoHF14A(false, false, false) > 0) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("ISO14443-A tag") "found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, "Searching for ISO15693 tag...");
    if (IfPm3Iso15693()) {
        if (readHF15Uid(false)) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("ISO15693 tag") "found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, "Searching for LEGIC tag...");
    if (IfPm3Legicrf()) {
        if (readLegicUid(false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("LEGIC Prime tag") "found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, "Searching for Topaz tag...");
    if (IfPm3Iso14443a()) {
        if (readTopazUid(false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Topaz tag") "found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, "Searching for FeliCa tag...");
    if (IfPm3Felica()) {
        if (readFelicaUid(false) == PM3_SUCCESS) {
            PrintAndLogEx(NORMAL, "\nValid " _GREEN_("ISO18092 / FeliCa tag") "found\n");
            res = PM3_SUCCESS;
        }
    }
    /*
        // 14b and iclass is the longest test (put last)
        PROMPT_CLEARLINE;
        PrintAndLogEx(INPLACE, "Searching for CryptoRF tag...");
        if (IfPm3Iso14443b()) {
            if (readHFCryptoRF(false) == PM3_SUCCESS) {
                PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("CryptoRF tag") "found\n");
                res = PM3_SUCCESS;
            }
        }
    */

    // 14b and iclass is the longest test (put last)
    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, "Searching for ISO14443-B tag...");
    if (IfPm3Iso14443b()) {
        if (readHF14B(false) == 1) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("ISO14443-B tag") "found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, "Searching for iClass / PicoPass tag...");
    if (IfPm3Iclass()) {
        if (readIclass(false, false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("iClass tag / PicoPass tag") "found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    if (res != PM3_SUCCESS) {

        PrintAndLogEx(INPLACE, _RED_("No known/supported 13.56 MHz tags found"));
        res = PM3_ESOFT;
    }
    printf("\n");
    return res;
}

int CmdHFTune(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_tune();
    int iter =  param_get32ex(Cmd, 0, 0, 10);

    PrintAndLogEx(INFO, "Measuring HF antenna, click " _GREEN_("pm3 button") "or press " _GREEN_("Enter") "to exit");
    PacketResponseNG resp;
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
        if (kbd_enter_pressed()) {
            break;
        }

        SendCommandNG(CMD_MEASURE_ANTENNA_TUNING_HF, mode, sizeof(mode));
        if (!WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING_HF, &resp, 1000)) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "Timeout while waiting for Proxmark HF measure, aborting");
            return PM3_ETIMEOUT;
        }

        if ((resp.status == PM3_EOPABORTED) || (resp.length != sizeof(uint16_t))) {
            break;
        }

        uint16_t volt = resp.data.asDwords[0] & 0xFFFF;
        PrintAndLogEx(INPLACE, "%u mV / %2u V", volt, (uint16_t)(volt / 1000));
    }
    mode[0] = 3;

    SendCommandNG(CMD_MEASURE_ANTENNA_TUNING_HF, mode, sizeof(mode));
    if (!WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING_HF, &resp, 1000)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for Proxmark HF shutdown, aborting");
        return PM3_ETIMEOUT;
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Done.");
    return PM3_SUCCESS;
}

int CmdHFSniff(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_sniff();

    int skippairs =  param_get32ex(Cmd, 0, 0, 10);
    int skiptriggers =  param_get32ex(Cmd, 1, 0, 10);

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_SNIFF, skippairs, skiptriggers, 0, NULL, 0);
    return PM3_SUCCESS;
}

int CmdHFPlot(const char *Cmd) {
    CLIParserInit("hf plot",
                  "Plots HF signal after RF signal path and A/D conversion.",
                  "This can be used after any hf command and will show the last few milliseconds of the HF signal.\n"
                  "Note: If the last hf command terminated because of a timeout you will most probably see nothing.\n");
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    uint8_t buf[FPGA_TRACE_SIZE];

    PacketResponseNG response;
    if (!GetFromDevice(FPGA_MEM, buf, FPGA_TRACE_SIZE, 0, NULL, 0, &response, 4000, true)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    for (size_t i = 0; i < FPGA_TRACE_SIZE; i++) {
        GraphBuffer[i] = ((int)buf[i]) - 127;
    }

    GraphTraceLen = FPGA_TRACE_SIZE;

    ShowGraphWindow();

    // remove signal offset
    CmdHpf("");

    setClockGrid(0, 0);
    DemodBufferLen = 0;
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,          AlwaysAvailable, "This help"},
    {"14a",         CmdHF14A,         AlwaysAvailable, "{ ISO14443A RFIDs...               }"},
    {"14b",         CmdHF14B,         AlwaysAvailable, "{ ISO14443B RFIDs...               }"},
    {"15",          CmdHF15,          AlwaysAvailable, "{ ISO15693 RFIDs...                }"},
//    {"cryptorf",    CmdHFCryptoRF,    AlwaysAvailable, "{ CryptoRF RFIDs...                }"},
    {"epa",         CmdHFEPA,         AlwaysAvailable, "{ German Identification Card...    }"},
    {"felica",      CmdHFFelica,      AlwaysAvailable, "{ ISO18092 / Felica RFIDs...       }"},
    {"fido",        CmdHFFido,        AlwaysAvailable, "{ FIDO and FIDO2 authenticators... }"},
    {"iclass",      CmdHFiClass,      AlwaysAvailable, "{ ICLASS RFIDs...                  }"},
    {"legic",       CmdHFLegic,       AlwaysAvailable, "{ LEGIC RFIDs...                   }"},
    {"lto",         CmdHFLTO,         AlwaysAvailable, "{ LTO Cartridge Memory RFIDs...    }"},
    {"mf",          CmdHFMF,          AlwaysAvailable, "{ MIFARE RFIDs...                  }"},
    {"mfp",         CmdHFMFP,         AlwaysAvailable, "{ MIFARE Plus RFIDs...             }"},
    {"mfu",         CmdHFMFUltra,     AlwaysAvailable, "{ MIFARE Ultralight RFIDs...       }"},
    {"mfdes",       CmdHFMFDes,       AlwaysAvailable, "{ MIFARE Desfire RFIDs...          }"},
    {"thinfilm",    CmdHFThinfilm,    AlwaysAvailable, "{ Thinfilm RFIDs...                }"},
    {"topaz",       CmdHFTopaz,       AlwaysAvailable, "{ TOPAZ (NFC Type 1) RFIDs...      }"},
    {"list",        CmdTraceList,     AlwaysAvailable,    "List protocol data in trace buffer"},
    {"plot",        CmdHFPlot,        IfPm3Hfplot,     "Plot signal"},
    {"tune",        CmdHFTune,        IfPm3Present,    "Continuously measure HF antenna tuning"},
    {"search",      CmdHFSearch,      AlwaysAvailable, "Search for known HF tags"},
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
    return PM3_SUCCESS;
}
