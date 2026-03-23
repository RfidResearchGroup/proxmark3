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
// Low frequency HID commands (known)
//
// Useful resources:
// RF interface, programming a T55x7 clone, 26-bit HID H10301 encoding:
// http://www.proxmark.org/files/Documents/125%20kHz%20-%20HID/HID_format_example.pdf
//
// "Understanding Card Data Formats"
// https://www.hidglobal.com/sites/default/files/hid-understanding_card_data_formats-wp-en.pdf
//
// "What Format Do You Need?"
// https://www.hidglobal.com/sites/default/files/resource_files/hid-prox-br-en.pdf
//-----------------------------------------------------------------------------

#include "cmdlfhid.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "commonutil.h"   // ARRAYLEN
#include "cliparser.h"
#include "ui.h"
#include "graph.h"
#include "cmddata.h"      // g_debugMode, demodbuff cmds
#include "cmdlf.h"        // lf_read, lfsim_wait_check
#include "util_posix.h"
#include "lfdemod.h"
#include "wiegand_formats.h"
#include "wiegand_formatutils.h"
#include "cmdlfem4x05.h"  // EM defines

static int CmdHelp(const char *Cmd);

typedef struct {
    char format[16];
    int format_len;
    wiegand_card_t card;
    uint8_t raw[12];
    int raw_len;
    uint8_t bin[97];
    int bin_len;
    uint8_t new_pacs[13];
    int new_pacs_len;
} lf_hid_cli_input_t;

// Reject credentials that exceed the absolute 84-bit packed HID transport limit.
// The shared Wiegand layer can normalize credentials that are wider than the LF HID
// transport, so check packed_valid here rather than relying on the caller.
static int lf_hid_validate_packed_transport(const wiegand_input_t *input, const char *command_name) {
    if (input->packed_valid == false) {
        PrintAndLogEx(ERR, "%s: %" PRIuMAX "-bit credential exceeds the 84-bit packed HID transport limit", command_name, (uintmax_t)input->bin_len);
        return PM3_EINVARG;
    }

    return PM3_SUCCESS;
}

static int lf_hid_rebuild_transport(wiegand_input_t *input) {
    // The long HID prox transport uses one extra sentinel/start bit ahead of the user payload.
    // That leaves room for at most 83 payload bits on the `--bin`/`--new`/formatted paths even
    // though raw HID transport can still carry 84 bits total.
    if (input->bin_len > 83) {
        PrintAndLogEx(ERR, "LF HID payload encoding supports up to 83 bits (`--raw` supports 84 transport bits)");
        input->packed_valid = false;
        return PM3_EINVARG;
    }

    int res = wiegand_pack_bin_with_hid_prox(input->binstr, &input->packed);
    input->packed_valid = (res == PM3_SUCCESS);
    return res;
}

static int lf_hid_pack_formatted_legacy_short(int format_idx, const wiegand_card_t *card, wiegand_input_t *input) {
    // Short HID formats worked before the long-format regression because they used the
    // original HID formatter directly, without rebuilding from a synthetic sentinel-framed
    // bitstring. Keep that path for <=37-bit formatted cards so H10304 stays 37-bit on
    // external readers while >37-bit formats continue through the new long transport path.
    int res = wiegand_pack_from_formatted(format_idx, (wiegand_card_t *)card, true, input);
    input->packed_valid = (res == PM3_SUCCESS);
    return res;
}

// Resolve the CLI's mutually exclusive HID input modes into one normalized representation
// that downstream sim/clone code can consume without caring about the original encoding.
static int lf_hid_resolve_input(const lf_hid_cli_input_t *cli, wiegand_input_t *input, int *format_idx) {
    int input_modes = 0;
    input_modes += (cli->raw_len > 0);
    input_modes += (cli->bin_len > 0);
    input_modes += (cli->new_pacs_len > 0);
    input_modes += (cli->format_len > 0 || cli->card.FacilityCode != 0 || cli->card.CardNumber != 0 || cli->card.IssueLevel != 0 || cli->card.OEM != 0);
    if (input_modes != 1) {
        PrintAndLogEx(ERR, "Use exactly one of `--raw`, `--bin`, `--new`, or `--wiegand/--fc/--cn`");
        return PM3_EINVARG;
    }

    *format_idx = -1;
    if (cli->raw_len == 0 && cli->bin_len == 0 && cli->new_pacs_len == 0) {
        *format_idx = HIDFindCardFormat(cli->format);
    }

    if (*format_idx == -1 && cli->raw_len == 0 && cli->bin_len == 0 && cli->new_pacs_len == 0) {
        PrintAndLogEx(WARNING, "Unknown format: " _YELLOW_("%s"), cli->format);
        return PM3_EINVARG;
    }

    // Normalize every accepted CLI form into the same wiegand_input_t so sim/clone can
    // share validation and transport handling regardless of where the credential came from.
    if (cli->raw_len) {
        return wiegand_pack_from_raw_hid(cli->raw, cli->raw_len, input);
    }
    if (cli->bin_len) {
        int res = wiegand_set_plain_binstr((char *)cli->bin, input);
        if (res != PM3_SUCCESS) {
            return res;
        }
        return lf_hid_rebuild_transport(input);
    }
    if (cli->new_pacs_len) {
        int res = wiegand_set_new_pacs_binstr(cli->new_pacs, cli->new_pacs_len, input);
        if (res != PM3_SUCCESS) {
            return res;
        }
        return lf_hid_rebuild_transport(input);
    }

    int res = wiegand_pack_from_formatted(*format_idx, (wiegand_card_t *)&cli->card, false, input);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (input->bin_len <= 37) {
        return lf_hid_pack_formatted_legacy_short(*format_idx, &cli->card, input);
    }

    return lf_hid_rebuild_transport(input);
}

// sending three times.  Didn't seem to break the previous sim?
static int sendPing(void) {
    SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
    SendCommandNG(CMD_PING, NULL, 0);
    clearCommandBuffer();
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_PING, &resp, 1000) == false) {
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}
static int sendTry(uint8_t format_idx, wiegand_card_t *card, uint32_t delay, bool verbose) {

    wiegand_message_t packed;
    memset(&packed, 0, sizeof(wiegand_message_t));

    if (HIDPack(format_idx, card, &packed, true) == false) {
        PrintAndLogEx(WARNING, "The card data could not be encoded in the selected format.");
        return PM3_ESOFT;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Trying FC: " _YELLOW_("%u") " CN: " _YELLOW_("%"PRIu64) " Issue level: " _YELLOW_("%u") " OEM: " _YELLOW_("%u")
                      , card->FacilityCode
                      , card->CardNumber
                      , card->IssueLevel
                      , card->OEM
                     );
    }

    lf_hidsim_t payload = {
        .EM = false,
        .Q5 = false,
        .hi2 = packed.Top,
        .hi = packed.Mid,
        .lo = packed.Bot,
        .longFMT = (packed.Length > 37)
    };

    clearCommandBuffer();

    SendCommandNG(CMD_LF_HID_SIMULATE, (uint8_t *)&payload,  sizeof(payload));
    /*
        PacketResponseNG resp;
        WaitForResponse(CMD_LF_HID_SIMULATE, &resp);
        if (resp.status == PM3_EOPABORTED)
            return resp.status;
    */
    msleep(delay);
    return sendPing();
}

//by marshmellow (based on existing demod + holiman's refactor)
//HID Prox demod - FSK RF/50 with preamble of 00011101 (then manchester encoded)
//print full HID Prox ID and some bit format details if found
int demodHID(bool verbose) {
    (void) verbose; // unused so far

    // HID simulation etc uses 0/1 as signal data. This must be converted in order to demod it back again
    if (isGraphBitstream()) {
        convertGraphFromBitstream();
    }

    //raw fsk demod no manchester decoding no start bit finding just get binary from wave
    uint32_t hi2 = 0, hi = 0, lo = 0;

    uint8_t *bits = calloc(g_GraphTraceLen, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    size_t size = getFromGraphBuffer(bits);
    if (size == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID not enough samples"));
        free(bits);
        return PM3_ESOFT;
    }
    //get binary from fsk wave
    int waveIdx = 0;
    int idx = HIDdemodFSK(bits, &size, &hi2, &hi, &lo, &waveIdx);
    if (idx < 0) {

        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID not enough samples"));
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID just noise detected"));
        else if (idx == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID problem during FSK demod"));
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID preamble not found"));
        else if (idx == -5)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID error in Manchester data, size %zu"), size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID error demoding fsk %d"), idx);

        free(bits);
        return PM3_ESOFT;
    }

    setDemodBuff(bits, size, idx);
    setClockGrid(50, waveIdx + (idx * 50));
    free(bits);

    if (hi2 == 0 && hi == 0 && lo == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID no values found"));
        return PM3_ESOFT;
    }

    if (!decode_wiegand(hi2, hi, lo, 0)) { // if failed to unpack wiegand
        printDemodBuff(0, false, false, true);
    }
    PrintAndLogEx(INFO, "raw: " _GREEN_("%08x%08x%08x"), hi2, hi, lo);

    PrintAndLogEx(DEBUG, "DEBUG: HID idx: %d, Len: %zu, Printing DemodBuffer: ", idx, size);
    if (g_debugMode) {
        PrintAndLogEx(DEBUG, "raw: " _GREEN_("%08x%08x%08x"), hi2, hi, lo);

        printDemodBuff(0, false, false, false);
    }

    return PM3_SUCCESS;
}

static int CmdHIDDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hid demod",
                  "Try to find HID Prox preamble, if found decode / descramble data",
                  "lf hid demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodHID(true);
}

// this read is the "normal" read,  which download lf signal and tries to demod here.
static int CmdHIDReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hid reader",
                  "read a HID Prox tag",
                  "lf hid reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    do {
        lf_read(false, 16000);
        demodHID(!cm);
    } while (cm && (kbd_enter_pressed() == false));

    return PM3_SUCCESS;
}

// this read loops on device side.
// uses the demod in lfops.c
static int CmdHIDWatch(const char *Cmd) {
    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf hid watch",
                  "Enables HID compatible reader mode printing details.\n"
                  "By default, values are printed and logged until the button is pressed or another USB command is issued.\n",
                  "lf hid watch"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(SUCCESS, "Watching for HID Prox cards - place tag on antenna");
    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " to stop reading cards");
    clearCommandBuffer();
    SendCommandNG(CMD_LF_HID_WATCH, NULL, 0);
    return lfsim_wait_check(CMD_LF_HID_WATCH);
}

static int CmdHIDSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hid sim",
                  "Enables simulation of HID card with card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n"
                  "Use `--timeout` to stop automatically after a fixed number of milliseconds.\n"
                  "`--bin`, `--new`, and formatted inputs support up to 83 payload bits; `--raw` supports 84 transport bits.",
                  "lf hid sim -r 2006ec0c86                -> HID 10301 26 bit\n"
                  "lf hid sim --bin 10001111100000001010100011\n"
                  "lf hid sim --new 068F80A8C0\n"
                  "lf hid sim -r 2e0ec00c87                -> HID Corporate 35 bit\n"
                  "lf hid sim -w H10301 --fc 118 --cn 1603 -> HID 10301 26 bit\n"
                  "lf hid sim -w H10301 --fc 118 --cn 1603 --timeout 2000\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("w",   "wiegand", "<format>", "see " _YELLOW_("`wiegand list`") " for available formats"),
        arg_u64_0(NULL, "fc",      "<dec>", "facility code"),
        arg_u64_0(NULL, "cn",      "<dec>", "card number"),
        arg_u64_0("i",    NULL,     "<dec>", "issue level"),
        arg_u64_0("o",   "oem",     "<dec>", "OEM code"),
        arg_u64_0("t", "timeout", "<ms>", "timeout in ms (0 will run until button or <Enter> - def 0)"),
        arg_str0("r",  "raw",     "<hex>", "raw bytes"),
        arg_str0(NULL, "bin", "<bin>", "Binary string i.e 0001001001"),
        arg_str0(NULL, "new", "<hex>", "new ASN.1 PACS hex from `wiegand encode --new`"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    lf_hid_cli_input_t cli;
    memset(&cli, 0, sizeof(cli));
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)cli.format, sizeof(cli.format), &cli.format_len);
    cli.card.FacilityCode = arg_get_u32_def(ctx, 2, 0);
    cli.card.CardNumber = arg_get_u32_def(ctx, 3, 0);
    cli.card.IssueLevel = arg_get_u32_def(ctx, 4, 0);
    cli.card.OEM = arg_get_u32_def(ctx, 5, 0);
    uint32_t timeout_ms = arg_get_u32_def(ctx, 6, 0);
    int res = CLIParamHexToBuf(arg_get_str(ctx, 7), cli.raw, sizeof(cli.raw), &cli.raw_len);
    cli.bin_len = sizeof(cli.bin) - 1;
    CLIGetStrWithReturn(ctx, 8, cli.bin, &cli.bin_len);
    cli.bin[cli.bin_len] = '\0';
    res |= CLIParamHexToBuf(arg_get_str(ctx, 9), cli.new_pacs, sizeof(cli.new_pacs), &cli.new_pacs_len);
    CLIParserFree(ctx);

    if (res) {
        PrintAndLogEx(ERR, "Error parsing hex input");
        return PM3_EINVARG;
    }

    if (cli.bin_len > 96) {
        PrintAndLogEx(ERR, "Binary wiegand string must be less than 97 bits");
        return PM3_EINVARG;
    }

    wiegand_input_t input;
    memset(&input, 0, sizeof(input));
    int format_idx = -1;
    res = lf_hid_resolve_input(&cli, &input, &format_idx);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to encode HID input");
        return res;
    }

    res = lf_hid_validate_packed_transport(&input, "lf hid sim");
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (cli.raw_len == 0) {
        PrintAndLogEx(INFO, "Simulating HID tag");
        HIDTryUnpack(&input.packed);
    } else {
        PrintAndLogEx(INFO, "Simulating HID tag using raw " _GREEN_("%s"), sprint_hex_inrow(cli.raw, cli.raw_len));
    }

    lf_hidsim_t payload;
    payload.hi2 = input.packed.Top;
    payload.hi = input.packed.Mid;
    payload.lo = input.packed.Bot;
    payload.longFMT = (input.bin_len > 37);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HID_SIMULATE, (uint8_t *)&payload,  sizeof(payload));
    return lfsim_wait_check_timeout(CMD_LF_HID_SIMULATE, timeout_ms);
}

static int CmdHIDClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hid clone",
                  "clone a HID Prox tag to a T55x7, Q5/T5555 or EM4305/4469 tag.\n"
                  "Tag must be on the antenna when issuing this command.\n"
                  "`--bin`, `--new`, and formatted inputs support up to 83 payload bits; `--raw` supports 84 transport bits.",
                  "lf hid clone -r 2006ec0c86                      -> write raw value for T55x7 tag (HID 10301 26 bit)\n"
                  "lf hid clone --bin 10001111100000001010100011  -> write binary HID payload for T55x7 tag\n"
                  "lf hid clone --new 068F80A8C0                  -> write PACS-encoded HID payload for T55x7 tag\n"
                  "lf hid clone -r 2e0ec00c87                      -> write raw value for T55x7 tag (HID Corporate 35 bit)\n"
                  "lf hid clone -r 01f0760643c3                    -> write raw value for T55x7 tag (HID P10001 40 bit)\n"
                  "lf hid clone -r 01400076000c86                  -> write raw value for T55x7 tag (HID Corporate 48 bit)\n"
                  "lf hid clone -w H10301 --fc 118 --cn 1603       -> HID 10301 26 bit, encode for T55x7 tag\n"
                  "lf hid clone -w H10301 --fc 118 --cn 1603 --q5  -> HID 10301 26 bit, encode for Q5/T5555 tag\n"
                  "lf hid clone -w H10301 --fc 118 --cn 1603 --em  -> HID 10301 26 bit, encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("w",   "wiegand", "<format>", "see " _YELLOW_("`wiegand list`") " for available formats"),
        arg_u64_0(NULL, "fc",      "<dec>", "facility code"),
        arg_u64_0(NULL, "cn",      "<dec>", "card number"),
        arg_int0("i",    NULL,     "<dec>", "issue level"),
        arg_int0("o",   "oem",     "<dec>", "OEM code"),
        arg_str0("r",  "raw",     "<hex>", "raw bytes"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_str0(NULL, "bin", "<bin>", "Binary string i.e 0001001001"),
        arg_str0(NULL, "new", "<hex>", "new ASN.1 PACS hex from `wiegand encode --new`"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    lf_hid_cli_input_t cli;
    memset(&cli, 0, sizeof(cli));
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)cli.format, sizeof(cli.format), &cli.format_len);
    cli.card.FacilityCode = arg_get_u32_def(ctx, 2, 0);
    cli.card.CardNumber = arg_get_u32_def(ctx, 3, 0);
    cli.card.IssueLevel = arg_get_u32_def(ctx, 4, 0);
    cli.card.OEM = arg_get_u32_def(ctx, 5, 0);
    int res = CLIParamHexToBuf(arg_get_str(ctx, 6), cli.raw, sizeof(cli.raw), &cli.raw_len);

    bool q5 = arg_get_lit(ctx, 7);
    bool em = arg_get_lit(ctx, 8);

    cli.bin_len = sizeof(cli.bin) - 1;
    CLIGetStrWithReturn(ctx, 9, cli.bin, &cli.bin_len);
    cli.bin[cli.bin_len] = '\0';
    res |= CLIParamHexToBuf(arg_get_str(ctx, 10), cli.new_pacs, sizeof(cli.new_pacs), &cli.new_pacs_len);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    if (res) {
        PrintAndLogEx(ERR, "Error parsing hex input");
        return PM3_EINVARG;
    }

    wiegand_input_t input;
    memset(&input, 0, sizeof(input));
    int format_idx = -1;
    res = lf_hid_resolve_input(&cli, &input, &format_idx);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to encode HID input");
        return res;
    }

    res = lf_hid_validate_packed_transport(&input, "lf hid clone");
    if (res != PM3_SUCCESS) {
        return res;
    }

    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        PrintAndLogEx(WARNING, "Beware some EM4305 tags don't support FSK and datarate = RF/50, check your tag copy!");
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    if (cli.raw_len == 0) {
        PrintAndLogEx(INFO, "Preparing to clone HID tag");
        if (format_idx >= 0) {
            HIDUnpack(format_idx, &input.packed);
        } else {
            HIDTryUnpack(&input.packed);
        }
    } else {
        PrintAndLogEx(INFO, "Preparing to clone HID tag using raw " _YELLOW_("%s"), sprint_hex_inrow(cli.raw, cli.raw_len));
    }

    lf_hidsim_t payload;
    payload.hi2 = input.packed.Top;
    payload.hi = input.packed.Mid;
    payload.lo = input.packed.Bot;
    payload.longFMT = (input.bin_len > 37);
    payload.Q5 = q5;
    payload.EM = em;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HID_CLONE, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_HID_CLONE, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Done!");
        PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`lf hid reader`") " to verify");
    } else {
        PrintAndLogEx(FAILED, "cloning ( " _RED_("fail") " )");
    }
    return resp.status;
}

/*
    PrintAndLogEx(NORMAL, "HID | OEM | FC   | CN      |  Wiegand  |  HID Formatted");
    PrintAndLogEx(NORMAL, "----+-----+------+---------+-----------+--------------------");
    PrintAndLogEx(NORMAL, " %u | %03u | %03u  | %" PRIu64 "  | %" PRIX64 "  |  %" PRIX64,
                      fmtlen[i],
                      oem,
                      fc,
                      cardnum,
                      wiegand,
                      blocks
                     );
    }
    PrintAndLogEx(NORMAL, "----+-----+-----+-------+-----------+--------------------");
*/

static int CmdHIDBrute(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hid brute",
                  "Enables bruteforce of HID readers with specified facility code or card number. This is an attack against the reader.\n"
                  "If the field being bruteforced is provided, it starts with it and goes up / down one step while maintaining other supplied values.\n"
                  "If the field being bruteforced is not provided, it will iterate through the full range while maintaining other supplied values.",
                  "lf hid brute -w H10301 --field fc --fc 224 --cn 6278\n"
                  "lf hid brute -w H10301 --field cn --fc 21 -d 2000\n"
                  "lf hid brute -v -w H10301 --field cn --fc 21 --cn 200 -d 2000\n"
                  "lf hid brute -v -w H10301 --field fc --fc 21 --cn 200 -d 2000 --up\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose",             "verbose output"),
        arg_str1("w", "wiegand", "<format>", "see " _YELLOW_("`wiegand list`") " for available formats"),
        arg_str1(NULL, "field",   "<fc|cn>", "field to bruteforce"),
        arg_u64_0(NULL, "fc",     "<dec>",   "facility code"),
        arg_u64_0(NULL, "cn",     "<dec>",   "card number"),
        arg_u64_0("i",  "issue",  "<dec>",   "issue level"),
        arg_u64_0("o", "oem",     "<dec>",   "OEM code"),
        arg_u64_0("d", "delay",   "<dec>",   "delay betweens attempts in ms. (def is 1000)"),
        arg_lit0(NULL, "up",                 "direction to increment field value. (def is both directions)"),
        arg_lit0(NULL, "down",               "direction to decrement field value. (def is both directions)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool verbose = arg_get_lit(ctx, 1);

    char format[16] = {0};
    int format_len = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)format, sizeof(format), &format_len);

    int format_idx = HIDFindCardFormat(format);
    if (format_idx == -1) {
        PrintAndLogEx(WARNING, "Unknown format: " _YELLOW_("%s"), format);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    wiegand_card_t card_hi, card_low;
    cardformatdescriptor_t card_descriptor = HIDGetCardFormat(format_idx).Fields;
    memset(&card_hi, 0, sizeof(wiegand_card_t));

    char field[3] = {0};
    int field_len = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)field, sizeof(field), &field_len);

    card_hi.FacilityCode = arg_get_u32_def(ctx, 4, 0);
    card_hi.CardNumber = arg_get_u32_def(ctx, 5, 0);
    card_hi.IssueLevel = arg_get_u32_def(ctx, 6, 0);
    card_hi.OEM = arg_get_u32_def(ctx, 7, 0);

    uint32_t delay = arg_get_u32_def(ctx, 8, 1000);

    int direction = 0;
    if (arg_get_lit(ctx, 9) && arg_get_lit(ctx, 10)) {
        direction = 0;
    } else if (arg_get_lit(ctx, 9)) {
        direction = 1;
    } else if (arg_get_lit(ctx, 10)) {
        direction = 2;
    }

    CLIParserFree(ctx);

    if (verbose) {
        PrintAndLogEx(INFO, "Wiegand format... %i", format_idx);
        PrintAndLogEx(INFO, "OEM.............. %u", card_hi.OEM);
        PrintAndLogEx(INFO, "ISSUE............ %u", card_hi.IssueLevel);
        PrintAndLogEx(INFO, "Facility code.... %u", card_hi.FacilityCode);
        PrintAndLogEx(INFO, "Card number...... %" PRIu64, card_hi.CardNumber);
        PrintAndLogEx(INFO, "Delay............ " _YELLOW_("%d"), delay);

        if (strcmp(field, "fc") == 0) {
            PrintAndLogEx(INFO, "Field............ " _YELLOW_("fc"));
        } else if (strcmp(field, "cn") == 0) {
            PrintAndLogEx(INFO, "Field............ " _YELLOW_("cn"));
        }

        switch (direction) {
            case 0:
                PrintAndLogEx(INFO, "Direction........ " _YELLOW_("both"));
                break;
            case 1:
                PrintAndLogEx(INFO, "Direction........ " _YELLOW_("up"));
                break;
            case 2:
                PrintAndLogEx(INFO, "Direction........ " _YELLOW_("down"));
                break;
            default:
                break;
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Started bruteforcing HID Prox reader");
    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to abort simulation");
    PrintAndLogEx(NORMAL, "");
    // copy values to low.
    card_low = card_hi;

    // main loop
    bool exitloop = false;
    bool fin_hi, fin_low;
    fin_hi = fin_low = false;
    do {

        if (g_session.pm3_present == false) {
            PrintAndLogEx(WARNING, "Device offline\n");
            return PM3_ENODATA;
        }

        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "aborted via keyboard!");
            return sendPing();
        }

        // do one up
        if (direction != 2 && fin_hi != true) {
            if (sendTry(format_idx, &card_hi, delay, verbose) != PM3_SUCCESS) {
                return PM3_ESOFT;
            }
            if (strcmp(field, "fc") == 0) {
                if (card_hi.FacilityCode < card_descriptor.MaxFC) {
                    card_hi.FacilityCode++;
                } else {
                    fin_hi = true;
                }
            } else if (strcmp(field, "cn") == 0) {
                if (card_hi.CardNumber < card_descriptor.MaxCN) {
                    card_hi.CardNumber++;
                } else {
                    fin_hi = true;
                }
            }
        }

        // do one down
        if (direction != 1 && fin_low != true) {
            if (sendTry(format_idx, &card_low, delay, verbose) != PM3_SUCCESS) {
                return PM3_ESOFT;
            }
            if (strcmp(field, "fc") == 0) {
                if (card_low.FacilityCode > 0) {
                    card_low.FacilityCode--;
                } else {
                    fin_low = true;
                }
            } else if (strcmp(field, "cn") == 0) {
                if (card_low.CardNumber > 0) {
                    card_low.CardNumber--;
                } else {
                    fin_low = true;
                }
            }
        }

        switch (direction) {
            case 0:
                if (fin_hi && fin_low) {
                    exitloop = true;
                }
                break;
            case 1:
                exitloop = fin_hi;
                break;
            case 2:
                exitloop = fin_low;
                break;
            default:
                break;
        }

    } while (exitloop == false);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Bruteforcing finished");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        AlwaysAvailable, "this help"},
    {"demod",   CmdHIDDemod,    AlwaysAvailable, "demodulate HID Prox tag from the GraphBuffer"},
    {"reader",  CmdHIDReader,   IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",   CmdHIDClone,    IfPm3Lf,         "clone HID tag to T55x7, Q5/T5555 or EM4305/4469"},
    {"sim",     CmdHIDSim,      IfPm3Lf,         "simulate HID tag"},
    {"brute",   CmdHIDBrute,    IfPm3Lf,         "bruteforce facility code or card number against reader"},
    {"watch",   CmdHIDWatch,    IfPm3Lf,         "continuously watch for cards.  Reader mode"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFHID(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
