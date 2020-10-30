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
#include "cliparser.h"  // parse
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
#include "cmdhfst.h"        // ST rothult
#include "cmdhfwaveshare.h" // Waveshare
#include "cmdtrace.h"       // trace list
#include "ui.h"
#include "proxgui.h"
#include "cmddata.h"
#include "graph.h"
#include "fpga.h"

static int CmdHelp(const char *Cmd);

static int usage_hf_search(void) {
    PrintAndLogEx(NORMAL, "Usage: hf search");
    PrintAndLogEx(NORMAL, "Will try to find a HF read out of the unknown tag.");
    PrintAndLogEx(NORMAL, "Continues to search for all different HF protocols");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h               - This help");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int usage_hf_sniff(void) {
    PrintAndLogEx(NORMAL, "The high frequency sniffer will assign all available memory on device for sniffed data");
    PrintAndLogEx(NORMAL, "Use " _YELLOW_("'data samples'")" command to download from device,  and " _YELLOW_("'data plot'")" to look at it");
    PrintAndLogEx(NORMAL, "Press button to quit the sniffing.\n");
    PrintAndLogEx(NORMAL, "Usage: hf sniff <skip pairs> <skip triggers>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h               - This help");
    PrintAndLogEx(NORMAL, "       <skip pairs>    - skip sample pairs");
    PrintAndLogEx(NORMAL, "       <skip triggers> - skip number of triggers");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("           hf sniff"));
    PrintAndLogEx(NORMAL, _YELLOW_("           hf sniff 1000 0"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int usage_hf_tune(void) {
    PrintAndLogEx(NORMAL, "Continuously measure HF antenna tuning.");
    PrintAndLogEx(NORMAL, "Press button or `enter` to interrupt.");
    PrintAndLogEx(NORMAL, "Usage: hf tune [h] [<iter>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             - This help");
    PrintAndLogEx(NORMAL, "       <iter>        - number of iterations (default: 0=infinite)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("           hf tune 1"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

int CmdHFSearch(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_search();

    int res = PM3_ESOFT;

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for ThinFilm tag...");
    if (IfPm3NfcBarcode()) {
        if (infoThinFilm(false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Thinfilm tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for LTO-CM tag...");
    if (IfPm3Iso14443a()) {
        if (infoLTO(false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("LTO-CM tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for ISO14443-A tag...");
    if (IfPm3Iso14443a()) {
        if (infoHF14A(false, false, false) > 0) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("ISO14443-A tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for ISO15693 tag...");
    if (IfPm3Iso15693()) {
        if (readHF15Uid(false, false)) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("ISO15693 tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for iCLASS / PicoPass tag...");
    if (IfPm3Iclass()) {
        if (read_iclass_csn(false, false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("iCLASS tag / PicoPass tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for LEGIC tag...");
    if (IfPm3Legicrf()) {
        if (readLegicUid(false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("LEGIC Prime tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for Topaz tag...");
    if (IfPm3Iso14443a()) {
        if (readTopazUid(false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Topaz tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    // 14b  is the longest test (put last)
    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for ISO14443-B tag...");
    if (IfPm3Iso14443b()) {
        if (readHF14B(false) == 1) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("ISO14443-B tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    /*
        PROMPT_CLEARLINE;
        PrintAndLogEx(INPLACE, " Searching for FeliCa tag...");
        if (IfPm3Felica()) {
            if (readFelicaUid(false) == PM3_SUCCESS) {
                PrintAndLogEx(NORMAL, "\nValid " _GREEN_("ISO18092 / FeliCa tag") " found\n");
                res = PM3_SUCCESS;
            }
        }
    */
    /*
        PROMPT_CLEARLINE;
        PrintAndLogEx(INPLACE, " Searching for CryptoRF tag...");
        if (IfPm3Iso14443b()) {
            if (readHFCryptoRF(false) == PM3_SUCCESS) {
                PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("CryptoRF tag") " found\n");
                res = PM3_SUCCESS;
            }
        }
    */

    PROMPT_CLEARLINE;
    if (res != PM3_SUCCESS) {

        PrintAndLogEx(WARNING, _RED_("No known/supported 13.56 MHz tags found"));
        res = PM3_ESOFT;
    }

    return res;
}

int CmdHFTune(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_tune();
    int iter = param_get32ex(Cmd, 0, 0, 10);

    PrintAndLogEx(INFO, "Measuring HF antenna, click " _GREEN_("pm3 button") " or press " _GREEN_("Enter") " to exit");
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
        PrintAndLogEx(INPLACE, " %u mV / %2u V", volt, (uint16_t)(volt / 1000));
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

// Collects pars of u8,
// uses 16bit transfers from FPGA for speed
// Takes all available bigbuff memory
// data sample to download?   Not sure what we can do with the data.
int CmdHFSniff(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_sniff();

    struct {
        uint32_t samplesToSkip;
        uint32_t triggersToSkip;
    } PACKED params;

    params.samplesToSkip = param_get32ex(Cmd, 0, 0, 10);
    params.triggersToSkip = param_get32ex(Cmd, 1, 0, 10);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_SNIFF, (uint8_t *)&params, sizeof(params));

    for (;;) {

        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(INFO, "User aborted");
            break;
        }

        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_SNIFF, &resp, 1000)) {

            if (resp.status == PM3_EOPABORTED) {
                PrintAndLogEx(INFO, "Button pressed, user aborted");
                break;
            }
            if (resp.status == PM3_SUCCESS) {

                struct r {
                    uint16_t len;
                } PACKED;
                struct r *retval = (struct r *)resp.data.asBytes;

                PrintAndLogEx(INFO, "HF sniff (%u samples)", retval->len);

                PrintAndLogEx(HINT, "Use `" _YELLOW_("data hpf") "` to remove offset");
                PrintAndLogEx(HINT, "Use `" _YELLOW_("data plot") "` to view");
                PrintAndLogEx(HINT, "Use `" _YELLOW_("data save") "` to save");

                // download bigbuf_malloc:d.
                // it reserve memory from the higher end.
                // At the moment, sniff takes all free memory in bigbuff. If this changes,
                // we can't start from beginning idx 0 but from that hi-to-start-of-allocated.
                uint32_t start = pm3_capabilities.bigbuf_size - retval->len;
                int res = getSamplesEx(start, start, false);
                if (res != PM3_SUCCESS) {
                    PrintAndLogEx(WARNING, "failed to download samples to client");
                    return res;
                }
                break;
            }
        }
    }
    PrintAndLogEx(INFO, "Done.");
    return PM3_SUCCESS;
}

int handle_hf_plot(void) {
    
    uint8_t buf[FPGA_TRACE_SIZE];

    PacketResponseNG response;
    if (!GetFromDevice(FPGA_MEM, buf, FPGA_TRACE_SIZE, 0, NULL, 0, &response, 4000, true)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    for (size_t i = 0; i < FPGA_TRACE_SIZE; i++) {
        GraphBuffer[i] = ((int)buf[i]) - 128;
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

int CmdHFPlot(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf plot",
                  "Plots HF signal after RF signal path and A/D conversion.",
                  "This can be used after any hf command and will show the last few milliseconds of the HF signal.\n"
                  "Note: If the last hf command terminated because of a timeout you will most probably see nothing.\n");
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    return handle_hf_plot();
}

static command_t CommandTable[] = {
    
    {"--------",    CmdHelp,          AlwaysAvailable, "----------------------- " _CYAN_("High Frequency") " -----------------------"},
    {"14a",         CmdHF14A,         AlwaysAvailable, "{ ISO14443A RFIDs...               }"},
    {"14b",         CmdHF14B,         AlwaysAvailable, "{ ISO14443B RFIDs...               }"},
    {"15",          CmdHF15,          AlwaysAvailable, "{ ISO15693 RFIDs...                }"},
//    {"cryptorf",    CmdHFCryptoRF,    AlwaysAvailable, "{ CryptoRF RFIDs...                }"},
    {"epa",         CmdHFEPA,         AlwaysAvailable, "{ German Identification Card...    }"},
    {"felica",      CmdHFFelica,      AlwaysAvailable, "{ ISO18092 / FeliCa RFIDs...       }"},
    {"fido",        CmdHFFido,        AlwaysAvailable, "{ FIDO and FIDO2 authenticators... }"},
    {"iclass",      CmdHFiClass,      AlwaysAvailable, "{ ICLASS RFIDs...                  }"},
    {"legic",       CmdHFLegic,       AlwaysAvailable, "{ LEGIC RFIDs...                   }"},
    {"lto",         CmdHFLTO,         AlwaysAvailable, "{ LTO Cartridge Memory RFIDs...    }"},
    {"mf",          CmdHFMF,          AlwaysAvailable, "{ MIFARE RFIDs...                  }"},
    {"mfp",         CmdHFMFP,         AlwaysAvailable, "{ MIFARE Plus RFIDs...             }"},
    {"mfu",         CmdHFMFUltra,     AlwaysAvailable, "{ MIFARE Ultralight RFIDs...       }"},
    {"mfdes",       CmdHFMFDes,       AlwaysAvailable, "{ MIFARE Desfire RFIDs...          }"},
    {"st",          CmdHF_ST,         AlwaysAvailable, "{ ST Rothult RFIDs...              }"},
    {"thinfilm",    CmdHFThinfilm,    AlwaysAvailable, "{ Thinfilm RFIDs...                }"},
    {"topaz",       CmdHFTopaz,       AlwaysAvailable, "{ TOPAZ (NFC Type 1) RFIDs...      }"},
    {"waveshare",   CmdHFWaveshare,   AlwaysAvailable, "{ Waveshare NFC ePaper...          }"},
    {"-----------", CmdHelp,          AlwaysAvailable, "--------------------- " _CYAN_("General") " ---------------------"},    
    {"help",        CmdHelp,          AlwaysAvailable, "This help"},
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
