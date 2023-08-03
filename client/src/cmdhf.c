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
// High frequency commands
//-----------------------------------------------------------------------------
#include "cmdhf.h"

#include <ctype.h>          // tolower
#include "cmdparser.h"      // command_t
#include "cliparser.h"      // parse
#include "comms.h"          // clearCommandBuffer
#include "lfdemod.h"        // computeSignalProperties
#include "cmdhf14a.h"       // ISO14443-A
#include "cmdhf14b.h"       // ISO14443-B
#include "cmdhf15.h"        // ISO15693
#include "cmdhfepa.h"
#include "cmdhfemrtd.h"     // eMRTD
#include "cmdhflegic.h"     // LEGIC
#include "cmdhficlass.h"    // ICLASS
#include "cmdhfjooki.h"     // MFU based Jooki
#include "cmdhfmf.h"        // CLASSIC
#include "cmdhfmfu.h"       // ULTRALIGHT/NTAG etc
#include "cmdhfmfp.h"       // Mifare Plus
#include "cmdhfmfdes.h"     // DESFIRE
#include "cmdhfntag424.h"   // NTAG 424 DNA
#include "cmdhftopaz.h"     // TOPAZ
#include "cmdhffelica.h"    // ISO18092 / FeliCa
#include "cmdhffido.h"      // FIDO authenticators
#include "cmdhffudan.h"     // Fudan cards
#include "cmdhfgallagher.h" // Gallagher DESFire cards
#include "cmdhfksx6924.h"   // KS X 6924
#include "cmdhfcipurse.h"   // CIPURSE transport cards
#include "cmdhfthinfilm.h"  // Thinfilm
#include "cmdhflto.h"       // LTO-CM
#include "cmdhfcryptorf.h"  // CryptoRF
#include "cmdhfseos.h"      // SEOS
#include "cmdhfst25ta.h"    // ST25TA
#include "cmdhftesla.h"     // Tesla
#include "cmdhftexkom.h"    // Texkom
#include "cmdhfvas.h"       // Value added services
#include "cmdhfwaveshare.h" // Waveshare
#include "cmdhfxerox.h"     // Xerox
#include "cmdtrace.h"       // trace list
#include "ui.h"
#include "proxgui.h"
#include "cmddata.h"
#include "graph.h"
#include "fpga.h"

static int CmdHelp(const char *Cmd);

int CmdHFSearch(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf search",
                  "Will try to find a HF read out of the unknown tag.\n"
                  "Continues to search for all different HF protocols.",
                  "hf search"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);

    CLIParserFree(ctx);

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
        if (reader_lto(false, false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("LTO-CM tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for ISO14443-A tag...");
    if (IfPm3Iso14443a()) {
        int sel_state = infoHF14A(false, false, false);
        if (sel_state > 0) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("ISO 14443-A tag") " found\n");
            res = PM3_SUCCESS;

            if (sel_state == 1)
                infoHF14A4Applications(verbose);
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for LEGIC tag...");
    if (IfPm3Legicrf()) {
        if (readLegicUid(false, false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("LEGIC Prime tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for Topaz tag...");
    if (IfPm3Iso14443a()) {
        if (readTopazUid(false, false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Topaz tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    // texkom
    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for TEXKOM tag...");
    if (read_texkom_uid(false, false) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("TEXKOM tag") " found\n");
        res = PM3_SUCCESS;
    }

    // xerox
    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for Fuji/Xerox tag...");
    if (IfPm3Iso14443b()) {
        if (read_xerox_uid(false, false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Fuji/Xerox tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    // 14b is the longest test
    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for ISO14443-B tag...");
    if (IfPm3Iso14443b()) {
        if (readHF14B(false, false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("ISO 14443-B tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    // OBS!  This triggers a swap to FPGA_BITSTREAM_HF_15 == 1.5sec delay

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for ISO15693 tag...");
    if (IfPm3Iso15693()) {
        if (readHF15Uid(false, false)) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("ISO 15693 tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for iCLASS / PicoPass tag...");
    if (IfPm3Iclass()) {
        if (read_iclass_csn(false, false, false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("iCLASS tag / PicoPass tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    // OBS!  This triggers a swap to FPGA_BITSTREAM_HF_FELICA == 1.5sec delay

    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for FeliCa tag...");
    if (IfPm3Felica()) {
        if (read_felica_uid(false, false) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("ISO 18092 / FeliCa tag") " found\n");
            res = PM3_SUCCESS;
        }
    }

    /*
    PROMPT_CLEARLINE;
    PrintAndLogEx(INPLACE, " Searching for CryptoRF tag...");
    if (IfPm3Iso14443b()) {
        if (readHFCryptoRF(false, false) == PM3_SUCCESS) {
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

    DropField();
    return res;
}

int CmdHFTune(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf tune",
                  "Continuously measure HF antenna tuning.\n"
                  "Press button or <Enter> to interrupt.",
                  "hf tune\n"
                  "hf tune --mix"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("n", "iter", "<dec>", "number of iterations (default: 0=infinite)"),
        arg_lit0(NULL, "bar", "bar style"),
        arg_lit0(NULL, "mix", "mixed style"),
        arg_lit0(NULL, "value", "values style"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t iter = arg_get_u32_def(ctx, 1, 0);
    bool is_bar = arg_get_lit(ctx, 2);
    bool is_mix = arg_get_lit(ctx, 3);
    bool is_value = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if ((is_bar + is_mix + is_value) > 1) {
        PrintAndLogEx(ERR, "Select only one output style");
        return PM3_EINVARG;
    }

    barMode_t style = g_session.bar_mode;
    if (is_bar)
        style = STYLE_BAR;
    if (is_mix)
        style = STYLE_MIXED;
    if (is_value)
        style = STYLE_VALUE;

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

    uint32_t max = 0xFFFF;
    bool first = true;

    print_progress(0, max, style);

    // loop forever (till button pressed) if iter = 0 (default)
    for (uint32_t i = 0; iter == 0 || i < iter; i++) {
        if (kbd_enter_pressed()) {
            break;
        }

        SendCommandNG(CMD_MEASURE_ANTENNA_TUNING_HF, mode, sizeof(mode));
        if (!WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING_HF, &resp, 1000)) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "Timeout while waiting for Proxmark HF measure, aborting");
            break;
        }

        if ((resp.status == PM3_EOPABORTED) || (resp.length != sizeof(uint16_t))) {
            PrintAndLogEx(NORMAL, "");
            break;
        }

        uint16_t volt = resp.data.asDwords[0] & 0xFFFF;
        if (first) {
            max = (volt * 1.03);
            first = false;
        }
        if (volt > max) {
            max = (volt * 1.03);
        }
        print_progress(volt, max, style);
    }
    mode[0] = 3;

    SendCommandNG(CMD_MEASURE_ANTENNA_TUNING_HF, mode, sizeof(mode));
    if (!WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING_HF, &resp, 1000)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for Proxmark HF shutdown, aborting");
        return PM3_ETIMEOUT;
    }
    PrintAndLogEx(NORMAL, "\x1b%c[2K\r", 30);
    PrintAndLogEx(INFO, "Done.");
    return PM3_SUCCESS;
}

typedef enum {
    HF_SNOOP_SKIP_NONE = 0x00,
    HF_SNOOP_SKIP_DROP = 0x01,
    HF_SNOOP_SKIP_MAX = 0x02,
    HF_SNOOP_SKIP_MIN = 0x03,
    HF_SNOOP_SKIP_AVG = 0x04
} HFSnoopSkipMode;

const CLIParserOption HFSnoopSkipModeOpts[] = {
    {HF_SNOOP_SKIP_NONE, "none"},
    {HF_SNOOP_SKIP_DROP, "drop"},
    {HF_SNOOP_SKIP_MAX,  "min"},
    {HF_SNOOP_SKIP_MIN,  "max"},
    {HF_SNOOP_SKIP_AVG,  "avg"},
    {0,    NULL},
};

// Collects pars of u8,
// uses 16bit transfers from FPGA for speed
// Takes all available bigbuff memory
// data sample to download?   Not sure what we can do with the data.
int CmdHFSniff(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf sniff",
                  "The high frequency sniffer will assign all available memory on device for sniffed data.\n"
                  "Use `data samples` to download from device and `data plot` to visualize it.\n"
                  "Press button to quit the sniffing.",
                  "hf sniff\n"
                  "hf sniff --sp 1000 --st 0   -> skip 1000 pairs, skip 0 triggers"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "sp",    "<dec>", "skip sample pairs"),
        arg_u64_0(NULL, "st",    "<dec>", "skip number of triggers"),
        arg_str0(NULL,  "smode", "[none|drop|min|max|avg]", "Skip mode. It switches on the function that applies to several samples before they saved to memory"),
        arg_int0(NULL,  "sratio",  "<dec, ms>", "Skip ratio. It applied the function above to (ratio * 2) samples. For ratio = 1 it 2 samples."),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct {
        uint32_t samplesToSkip;
        uint32_t triggersToSkip;
        uint8_t skipMode;
        uint8_t skipRatio;
    } PACKED params;

    params.samplesToSkip = arg_get_u32_def(ctx, 1, 0);
    params.triggersToSkip = arg_get_u32_def(ctx, 2, 0);

    int smode = 0;
    if (CLIGetOptionList(arg_get_str(ctx, 3), HFSnoopSkipModeOpts, &smode)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    params.skipMode = smode;
    params.skipRatio = arg_get_int_def(ctx, 4, 0);

    CLIParserFree(ctx);

    if (params.skipMode != HF_SNOOP_SKIP_NONE) {
        PrintAndLogEx(INFO, "Skip mode. Function: %s, each: %d sample",
                      CLIGetOptionListStr(HFSnoopSkipModeOpts, params.skipMode),
                      params.skipRatio * 2
                     );
    }

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
                uint32_t start = g_pm3_capabilities.bigbuf_size - retval->len;
                int res = getSamplesEx(start, start, false, true);
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

    uint8_t buf[FPGA_TRACE_SIZE] = {0};

    PacketResponseNG resp;
    if (GetFromDevice(FPGA_MEM, buf, FPGA_TRACE_SIZE, 0, NULL, 0, &resp, 4000, true) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    for (size_t i = 0; i < FPGA_TRACE_SIZE; i++) {
        g_GraphBuffer[i] = ((int)buf[i]) - 128;
    }

    g_GraphTraceLen = FPGA_TRACE_SIZE;

    ShowGraphWindow();

    // remove signal offset
    CmdHpf("");

    setClockGrid(0, 0);
    g_DemodBufferLen = 0;
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

static int CmdHFList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf", "raw");
}

static command_t CommandTable[] = {

    {"--------",    CmdHelp,          AlwaysAvailable, "----------------------- " _CYAN_("High Frequency") " -----------------------"},
    {"14a",         CmdHF14A,         AlwaysAvailable, "{ ISO14443A RFIDs...                  }"},
    {"14b",         CmdHF14B,         AlwaysAvailable, "{ ISO14443B RFIDs...                  }"},
    {"15",          CmdHF15,          AlwaysAvailable, "{ ISO15693 RFIDs...                   }"},
//    {"cryptorf",    CmdHFCryptoRF,    AlwaysAvailable, "{ CryptoRF RFIDs...                   }"},
    {"cipurse",     CmdHFCipurse,     AlwaysAvailable, "{ Cipurse transport Cards...          }"},
    {"epa",         CmdHFEPA,         AlwaysAvailable, "{ German Identification Card...       }"},
    {"emrtd",       CmdHFeMRTD,       AlwaysAvailable, "{ Machine Readable Travel Document... }"},
    {"felica",      CmdHFFelica,      AlwaysAvailable, "{ ISO18092 / FeliCa RFIDs...          }"},
    {"fido",        CmdHFFido,        AlwaysAvailable, "{ FIDO and FIDO2 authenticators...    }"},
    {"fudan",       CmdHFFudan,       AlwaysAvailable, "{ Fudan RFIDs...                      }"},
    {"gallagher",   CmdHFGallagher,   AlwaysAvailable, "{ Gallagher DESFire RFIDs...          }"},
    {"ksx6924",     CmdHFKSX6924,     AlwaysAvailable, "{ KS X 6924 (T-Money, Snapper+) RFIDs }"},
    {"jooki",       CmdHF_Jooki,      AlwaysAvailable, "{ Jooki RFIDs...                      }"},
    {"iclass",      CmdHFiClass,      AlwaysAvailable, "{ ICLASS RFIDs...                     }"},
    {"legic",       CmdHFLegic,       AlwaysAvailable, "{ LEGIC RFIDs...                      }"},
    {"lto",         CmdHFLTO,         AlwaysAvailable, "{ LTO Cartridge Memory RFIDs...       }"},
    {"mf",          CmdHFMF,          AlwaysAvailable, "{ MIFARE RFIDs...                     }"},
    {"mfp",         CmdHFMFP,         AlwaysAvailable, "{ MIFARE Plus RFIDs...                }"},
    {"mfu",         CmdHFMFUltra,     AlwaysAvailable, "{ MIFARE Ultralight RFIDs...          }"},
    {"mfdes",       CmdHFMFDes,       AlwaysAvailable, "{ MIFARE Desfire RFIDs...             }"},
    {"ntag424",     CmdHF_ntag424,    AlwaysAvailable, "{ NXP NTAG 4242 DNA RFIDs...          }"},
    {"seos",        CmdHFSeos,        AlwaysAvailable, "{ SEOS RFIDs...                       }"},
    {"st25ta",      CmdHFST25TA,      AlwaysAvailable, "{ ST25TA RFIDs...                     }"},
    {"tesla",       CmdHFTESLA,       AlwaysAvailable, "{ TESLA Cards...                      }"},
    {"texkom",      CmdHFTexkom,      AlwaysAvailable, "{ Texkom RFIDs...                     }"},
    {"thinfilm",    CmdHFThinfilm,    AlwaysAvailable, "{ Thinfilm RFIDs...                   }"},
    {"topaz",       CmdHFTopaz,       AlwaysAvailable, "{ TOPAZ (NFC Type 1) RFIDs...         }"},
    {"vas",         CmdHFVAS,         AlwaysAvailable, "{ Apple Value Added Service           }"},
    {"waveshare",   CmdHFWaveshare,   AlwaysAvailable, "{ Waveshare NFC ePaper...             }"},
    {"xerox",       CmdHFXerox,       AlwaysAvailable, "{ Fuji/Xerox cartridge RFIDs...       }"},
    {"-----------", CmdHelp,          AlwaysAvailable, "--------------------- " _CYAN_("General") " ---------------------"},
    {"help",        CmdHelp,          AlwaysAvailable, "This help"},
    {"list",        CmdHFList,        AlwaysAvailable, "List protocol data in trace buffer"},
    {"plot",        CmdHFPlot,        IfPm3Hfplot,     "Plot signal"},
    {"tune",        CmdHFTune,        IfPm3Present,    "Continuously measure HF antenna tuning"},
    {"search",      CmdHFSearch,      AlwaysAvailable, "Search for known HF tags"},
    {"sniff",       CmdHFSniff,       IfPm3Hfsniff,    "Generic HF Sniff"},
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
