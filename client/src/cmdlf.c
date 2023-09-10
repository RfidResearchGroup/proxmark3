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
// Low frequency commands
//-----------------------------------------------------------------------------
#include "cmdlf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include "cmdparser.h"      // command_t
#include "comms.h"
#include "commonutil.h"     // ARRAYLEN
#include "lfdemod.h"        // device/client demods of LF signals
#include "ui.h"             // for show graph controls
#include "proxgui.h"
#include "cliparser.h"      // args parsing
#include "graph.h"          // for graph data
#include "cmddata.h"        // for `lf search`
#include "cmdlfawid.h"      // for awid menu
#include "cmdlfem.h"        // for em menu
#include "cmdlfem410x.h"      // for em4x menu
#include "cmdlfem4x05.h"    // for em4x05 / 4x69
#include "cmdlfem4x50.h"    // for em4x50
#include "cmdlfem4x70.h"    // for em4x70
#include "cmdlfhid.h"       // for hid menu
#include "cmdlfhitag.h"     // for hitag menu
#include "cmdlfidteck.h"    // for idteck menu
#include "cmdlfio.h"        // for ioprox menu
#include "cmdlfcotag.h"     // for COTAG menu
#include "cmdlfdestron.h"   // for FDX-A FECAVA Destron menu
#include "cmdlffdxb.h"      // for FDX-B menu
#include "cmdlfgallagher.h" // for GALLAGHER menu
#include "cmdlfguard.h"     // for gproxii menu
#include "cmdlfindala.h"    // for indala menu
#include "cmdlfjablotron.h" // for JABLOTRON menu
#include "cmdlfkeri.h"      // for keri menu
#include "cmdlfmotorola.h"  // for Motorola menu
#include "cmdlfnedap.h"     // for NEDAP menu
#include "cmdlfnexwatch.h"  // for nexwatch menu
#include "cmdlfnoralsy.h"   // for NORALSY menu
#include "cmdlfpac.h"       // for pac menu
#include "cmdlfparadox.h"   // for paradox menu
#include "cmdlfpcf7931.h"   // for pcf7931 menu
#include "cmdlfpresco.h"    // for presco menu
#include "cmdlfpyramid.h"   // for pyramid menu
#include "cmdlfsecurakey.h" // for securakey menu
#include "cmdlft55xx.h"     // for t55xx menu
#include "cmdlfti.h"        // for ti menu
#include "cmdlfviking.h"    // for viking menu
#include "cmdlfvisa2000.h"  // for VISA2000 menu
#include "cmdlfzx8211.h"    // for ZX8211 menu
#include "crc.h"
#include "pm3_cmd.h"        // for LF_CMDREAD_MAX_EXTRA_SYMBOLS

static bool gs_lf_threshold_set = false;

static int CmdHelp(const char *Cmd);

// Informative user function.
// loop and wait for either keyboard press or pm3 button to exit
// if key event, send break loop cmd to Pm3
int lfsim_wait_check(uint32_t cmd) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " or pm3-button to abort simulation");

    for (;;) {
        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, "User aborted");
            break;
        }

        PacketResponseNG resp;
        if (WaitForResponseTimeout(cmd, &resp, 1000)) {
            if (resp.status == PM3_EOPABORTED) {
                PrintAndLogEx(DEBUG, "Button pressed, user aborted");
                break;
            }
        }
    }
    PrintAndLogEx(INFO, "Done");
    return PM3_SUCCESS;
}

static int CmdLFTune(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf tune",
                  "Continuously measure LF antenna tuning.\n"
                  "Press button or <Enter> to interrupt.",
                  "lf tune\n"
                  "lf tune --mix"
                 );

    char q_str[60];
    snprintf(q_str, sizeof(q_str), "Frequency divisor. %d -> 134 kHz, %d -> 125 kHz", LF_DIVISOR_134, LF_DIVISOR_125);
    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("n", "iter", "<dec>", "number of iterations (default: 0=infinite)"),
        arg_u64_0("q", "divisor", "<dec>", q_str),
        arg_dbl0("f", "freq", "<float>", "Frequency in kHz"),
        arg_lit0(NULL, "bar", "bar style"),
        arg_lit0(NULL, "mix", "mixed style"),
        arg_lit0(NULL, "value", "values style"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t iter = arg_get_u32_def(ctx, 1, 0);
    uint8_t divisor = arg_get_u32_def(ctx, 2, LF_DIVISOR_125);
    double freq = arg_get_dbl_def(ctx, 3, 125);

    bool is_bar = arg_get_lit(ctx, 4);
    bool is_mix = arg_get_lit(ctx, 5);
    bool is_value = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (divisor < 19) {
        PrintAndLogEx(ERR, "divisor must be between 19 and 255");
        return PM3_EINVARG;
    }

    if ((freq < 47) || (freq > 600)) {
        PrintAndLogEx(ERR, "freq must be between 47 and 600");
        return PM3_EINVARG;
    }

    if (divisor != LF_DIVISOR_125 && freq != 125) {
        PrintAndLogEx(ERR, "Select either `divisor` or `frequency`");
        return PM3_EINVARG;
    }

    if (freq != 125)
        divisor = LF_FREQ2DIV(freq);


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

    PrintAndLogEx(INFO, "Measuring LF antenna at " _YELLOW_("%.2f") " kHz, click " _GREEN_("pm3 button") " or press " _GREEN_("Enter") " to exit", LF_DIV2FREQ(divisor));

    uint8_t params[] = {1, 0};
    params[1] = divisor;
    PacketResponseNG resp;
    clearCommandBuffer();

    SendCommandNG(CMD_MEASURE_ANTENNA_TUNING_LF, params, sizeof(params));
    if (!WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING_LF, &resp, 1000)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for Proxmark LF initialization, aborting");
        return PM3_ETIMEOUT;
    }

    params[0] = 2;

//    #define MAX_ADC_LF_VOLTAGE 140800
    uint32_t max = 71000;
    bool first = true;

    print_progress(0, max, style);

    // loop forever (till button pressed) if iter = 0 (default)
    for (uint32_t i = 0; iter == 0 || i < iter; i++) {
        if (kbd_enter_pressed()) {
            break;
        }

        SendCommandNG(CMD_MEASURE_ANTENNA_TUNING_LF, params, sizeof(params));
        if (!WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING_LF, &resp, 1000)) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "Timeout while waiting for Proxmark LF measure, aborting");
            break;
        }

        if ((resp.status == PM3_EOPABORTED) || (resp.length != sizeof(uint32_t))) {
            PrintAndLogEx(NORMAL, "");
            break;
        }

        uint32_t volt = resp.data.asDwords[0];
        if (first) {
            max = (volt * 1.03);
            first = false;
        }
        if (volt > max) {
            max = (volt * 1.03);
        }
        print_progress(volt, max, style);
    }

    params[0] = 3;
    SendCommandNG(CMD_MEASURE_ANTENNA_TUNING_LF, params, sizeof(params));
    if (!WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING_LF, &resp, 1000)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for Proxmark LF shutdown, aborting");
        return PM3_ETIMEOUT;
    }
    PrintAndLogEx(NORMAL, "\x1b%c[2K\r", 30);
    PrintAndLogEx(INFO, "Done.");
    return PM3_SUCCESS;
}

/* send a LF command before reading */
int CmdLFCommandRead(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf cmdread",
                  "Modulate LF reader field to send command before read. All periods in microseconds.\n"
                  " - use " _YELLOW_("`lf config`") _CYAN_(" to set parameters"),
                  "lf cmdread -d 50 -z 116 -o 166 -e W3000 -c W00110                           --> probing for Hitag 1/S\n"
                  "lf cmdread -d 50 -z 116 -o 166 -e W3000 -c W11000                           --> probing for Hitag 2\n"
                  "lf cmdread -d 50 -z 116 -o 166 -e W3000 -c W11000 -s 2000 -@                --> probing for Hitag 2, oscilloscope style\n"
                  "lf cmdread -d 48 -z 112 -o 176 -e W3000 -e S240 -e E336 -c W0S00000010000E  --> probing for Hitag (us)\n"
                 );

    char div_str[70] = {0};
    snprintf(div_str, sizeof(div_str), "Extra symbol definition and duration (up to %i)", LF_CMDREAD_MAX_EXTRA_SYMBOLS);

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("d", "duration", "<us>", "delay OFF period, (0 for bitbang mode)"),
        arg_str0("c", "cmd", "<0|1|...>", "command symbols"),
        arg_strx0("e", "extra", "<us>", div_str),
        arg_u64_0("o", "one", "<us>", "ONE time period"),
        arg_u64_0("z", "zero", "<us>", "ZERO time period"),
        arg_u64_0("s", "samples", "<dec>", "number of samples to collect"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("k", "keep", "keep signal field ON after receive"),
        arg_lit0(NULL, "crc-ht", "calculate and append CRC-8/HITAG (also for ZX8211)"),
        arg_lit0("@", NULL, "continuous mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint32_t delay = arg_get_u32_def(ctx, 1, 0);

    int cmd_len = 128;
    char cmd[128] = {0};
    CLIGetStrWithReturn(ctx, 2, (uint8_t *)cmd, &cmd_len);

    int extra_arg_len = 250;
    char extra_arg[250] = {0};
    CLIGetStrWithReturn(ctx, 3, (uint8_t *)extra_arg, &extra_arg_len);

    uint16_t period_1 = arg_get_u32_def(ctx, 4, 0);
    uint16_t period_0 = arg_get_u32_def(ctx, 5, 0);
    uint32_t samples = arg_get_u32_def(ctx, 6, 0);
    bool verbose = arg_get_lit(ctx, 7);
    bool keep_field_on = arg_get_lit(ctx, 8);
    bool add_crc_ht = arg_get_lit(ctx, 9);
    bool cm = arg_get_lit(ctx, 10);
    CLIParserFree(ctx);

    if (g_session.pm3_present == false)
        return PM3_ENOTTY;

#define PAYLOAD_HEADER_SIZE (12 + (3 * LF_CMDREAD_MAX_EXTRA_SYMBOLS))
    struct p {
        uint32_t delay;
        uint16_t period_0;
        uint16_t period_1;
        uint8_t  symbol_extra[LF_CMDREAD_MAX_EXTRA_SYMBOLS];
        uint16_t period_extra[LF_CMDREAD_MAX_EXTRA_SYMBOLS];
        uint32_t samples : 30;
        bool     keep_field_on : 1;
        bool     verbose : 1;
        uint8_t data[PM3_CMD_DATA_SIZE - PAYLOAD_HEADER_SIZE];
    } PACKED payload;
    payload.delay = delay;
    payload.period_1 = period_1;
    payload.period_0 = period_0;
    payload.samples = samples;
    payload.keep_field_on = keep_field_on;
    payload.verbose = verbose;

    if (add_crc_ht && (cmd_len <= 120)) {
        // Hitag 1, Hitag S, ZX8211
        // width=8 poly=0x1d init=0xff refin=false refout=false xorout=0x00 check=0xb4 residue=0x00 name="CRC-8/HITAG"
        crc_t crc;
        uint8_t data = 0;
        uint8_t n = 0;
        crc_init_ref(&crc, 8, 0x1d, 0xff, 0, false, false);
        uint8_t i;
        for (i = 0; i < cmd_len; i++) {
            if ((cmd[i] != '0') && (cmd[i] != '1')) {
                continue;
            }
            data <<= 1;
            data += cmd[i] - '0';
            n += 1;
            if (n == 8) {
                crc_update2(&crc, data, n);
                n = 0;
                data = 0;
            }
        }
        if (n > 0) {
            crc_update2(&crc, data, n);
        }
        uint8_t crc_final = crc_finish(&crc);
        for (int j = 7; j >= 0; j--) {
            cmd[cmd_len] = ((crc_final >> j) & 1) ? '1' : '0';
            cmd_len++;
        }
    }

    memcpy(payload.data, cmd, cmd_len);

    // extra symbol definition
    uint8_t index_extra = 0;
    int i = 0;
    for (; i < extra_arg_len;) {

        if (index_extra < LF_CMDREAD_MAX_EXTRA_SYMBOLS - 1) {
            payload.symbol_extra[index_extra] = extra_arg[i];
            int tmp = atoi(extra_arg + (i + 1));
            payload.period_extra[index_extra] = tmp;
            index_extra++;
            i++;
            while (extra_arg[i] >= 0x30 && extra_arg[i] <= 0x39)
                i++;

        } else {
            PrintAndLogEx(WARNING, "Too many extra symbols, please define up to %i symbols", LF_CMDREAD_MAX_EXTRA_SYMBOLS);
        }
    }

    // bitbang mode
    if (payload.delay == 0) {
        if (payload.period_0 < 7 || payload.period_1 < 7) {
            PrintAndLogEx(WARNING, "periods cannot be less than 7us in bit bang mode");
            return PM3_EINVARG;
        }
    }

    PrintAndLogEx(DEBUG, _CYAN_("Cmd read - settings"));
    PrintAndLogEx(DEBUG, "-------------------");
    PrintAndLogEx(DEBUG, "delay... " _YELLOW_("%u")" zero... " _YELLOW_("%u") " one... " _YELLOW_("%u")" samples... %u", payload.delay, payload.period_0,  payload.period_1, payload.samples);
    PrintAndLogEx(DEBUG, "");
    PrintAndLogEx(DEBUG, _CYAN_("Extra symbols"));
    PrintAndLogEx(DEBUG, "-------------");
    for (i = 0; i < LF_CMDREAD_MAX_EXTRA_SYMBOLS; i++) {
        if (payload.symbol_extra[i] == 0x00)
            continue;

        PrintAndLogEx(DEBUG, "  %c ... " _YELLOW_("%u"), payload.symbol_extra[i], payload.period_extra[i]);
    }
    PrintAndLogEx(DEBUG, "");
    PrintAndLogEx(DEBUG, "data... " _YELLOW_("%s"), payload.data);
    PrintAndLogEx(DEBUG, "");

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "Sending command...");
    }

    int ret = PM3_SUCCESS;
    do {
        clearCommandBuffer();
        SendCommandNG(CMD_LF_MOD_THEN_ACQ_RAW_ADC, (uint8_t *)&payload, PAYLOAD_HEADER_SIZE + cmd_len);

        PacketResponseNG resp;
        // init to ZERO
        resp.cmd = 0,
        resp.length = 0,
        resp.magic = 0,
        resp.status = 0,
        resp.crc = 0,
        resp.ng = false,
        resp.oldarg[0] = 0;
        resp.oldarg[1] = 0;
        resp.oldarg[2] = 0;
        memset(resp.data.asBytes, 0, PM3_CMD_DATA_SIZE);

        i = 10;
        // 20sec wait loop
        while (!WaitForResponseTimeout(CMD_LF_MOD_THEN_ACQ_RAW_ADC, &resp, 2000) && i != 0) {
            if (verbose) {
                PrintAndLogEx(NORMAL, "." NOLF);
            }
            i--;
        }
        if (verbose) {
            PrintAndLogEx(NORMAL, "");
        }
        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "command failed.");
            return PM3_ESOFT;
        }

        if (i) {
            if (verbose) {
                PrintAndLogEx(SUCCESS, "downloading response signal data");
            }
            getSamples(samples, false);
            ret = PM3_SUCCESS;
        } else {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            return PM3_ETIMEOUT;
        }

    } while (cm && kbd_enter_pressed() == false);
    return ret;
}

int CmdFlexdemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

#ifndef LONG_WAIT
#define LONG_WAIT 100
#endif
    int i, j, start, bit, sum;

    int data[g_GraphTraceLen];
    memcpy(data, g_GraphBuffer, g_GraphTraceLen);

    size_t size = g_GraphTraceLen;

    for (i = 0; i < g_GraphTraceLen; ++i)
        data[i] = (data[i] < 0) ? -1 : 1;

    for (start = 0; start < size - LONG_WAIT; start++) {
        int first = data[start];
        for (i = start; i < start + LONG_WAIT; i++) {
            if (data[i] != first) {
                break;
            }
        }
        if (i == (start + LONG_WAIT))
            break;
    }

    if (start == size - LONG_WAIT) {
        PrintAndLogEx(WARNING, "nothing to wait for");
        return PM3_ENODATA;
    }

    data[start] = 4;
    data[start + 1] = 0;

    uint8_t bits[64] = {0x00};

    i = start;
    for (bit = 0; bit < 64; bit++) {
        sum = 0;
        for (j = 0; j < 16; j++) {
            sum += data[i++];
        }
        bits[bit] = (sum > 0) ? 1 : 0;
        PrintAndLogEx(NORMAL, "bit %d sum %d", bit, sum);
    }

    for (bit = 0; bit < 64; bit++) {
        sum = 0;
        for (j = 0; j < 16; j++)
            sum += data[i++];

        if (sum > 0 && bits[bit] != 1) PrintAndLogEx(WARNING, "oops1 at %d", bit);

        if (sum < 0 && bits[bit] != 0) PrintAndLogEx(WARNING, "oops2 at %d", bit);

    }

    // iceman,  use g_DemodBuffer?  blue line?
    // HACK writing back to graphbuffer.
    g_GraphTraceLen = 32 * 64;
    i = 0;
    for (bit = 0; bit < 64; bit++) {

        int phase = (bits[bit] == 0) ? 0 : 1;

        for (j = 0; j < 32; j++) {
            g_GraphBuffer[i++] = phase;
            phase = !phase;
        }
    }
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

/*
*  this function will save a copy of the current lf config value, and set config to default values.
*
*/
int lf_config_savereset(sample_config *config) {

    if (config == NULL) {
        return PM3_EINVARG;
    }

    memset(config, 0, sizeof(sample_config));

    int res = lf_getconfig(config);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "failed to get current device LF config");
        return res;
    }

    sample_config def_config = {
        .decimation = 1,
        .bits_per_sample = 8,
        .averaging = 1,
        .divisor = LF_DIVISOR_125,
        .trigger_threshold = 0,
        .samples_to_skip = 0,
        .verbose = false,
    };

    res = lf_config(&def_config);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "failed to reset LF configuration to default values");
        return res;
    }

    // disable output on save config object
    config->verbose = false;

    return PM3_SUCCESS;
}

int lf_getconfig(sample_config *config) {
    if (!g_session.pm3_present) return PM3_ENOTTY;

    if (config == NULL)
        return PM3_EINVARG;

    clearCommandBuffer();

    SendCommandNG(CMD_LF_SAMPLING_GET_CONFIG, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_SAMPLING_GET_CONFIG, &resp, 2000)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }
    memcpy(config, resp.data.asBytes, sizeof(sample_config));
    return PM3_SUCCESS;
}

int lf_config(sample_config *config) {
    if (!g_session.pm3_present) return PM3_ENOTTY;

    clearCommandBuffer();
    if (config != NULL)
        SendCommandNG(CMD_LF_SAMPLING_SET_CONFIG, (uint8_t *)config, sizeof(sample_config));
    else
        SendCommandNG(CMD_LF_SAMPLING_PRINT_CONFIG, NULL, 0);

    return PM3_SUCCESS;
}

int CmdLFConfig(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf config",
                  "Get/Set config for LF sampling, bit/sample, decimation, frequency\n"
                  "These changes are temporary, will be reset after a power cycle.\n\n"
                  " - use " _YELLOW_("`lf read`") _CYAN_(" performs a read (active field)\n")
                  _CYAN_(" - use ") _YELLOW_("`lf sniff`") _CYAN_(" performs a sniff (no active field)"),
                  "lf config                    --> shows current config\n"
                  "lf config -b 8 --125         --> samples at 125 kHz, 8 bps\n"
                  "lf config -b 4 --134 --dec 3 --> samples at 134 kHz, averages three samples into one, stored with a resolution of 4 bits per sample\n"
                  "lf config --trig 20 -s 10000 --> trigger sampling when above 20, skip 10 000 first samples after triggered\n"
                  "lf config --reset            --> reset back to default values\n"
                 );

    char div_str[70] = {0};
    snprintf(div_str, sizeof(div_str), "Manually set freq divisor. %d -> 134 kHz, %d -> 125 kHz", LF_DIVISOR_134, LF_DIVISOR_125);

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "125", "125 kHz frequency"),
        arg_lit0(NULL, "134", "134 kHz frequency"),
        arg_int0("a", "avg", "<0|1>", "averaging - if set, will average the stored sample value when decimating (default 1)"),
        arg_int0("b", "bps", "<1-8>", "sets resolution of bits per sample (default 8)"),
        arg_int0(NULL, "dec", "<1-8>", "sets decimation. A value of N saves only 1 in N samples (default 1)"),
        arg_int0(NULL, "divisor", "<19-255>", div_str),
        arg_int0("f", "freq", "<47-600>", "manually set frequency in kHz"),
        arg_lit0("r", "reset", "reset values to defaults"),
        arg_int0("s", "skip", "<dec>", "sets a number of samples to skip before capture (default 0)"),
        arg_int0("t", "trig", "<0-128>", "sets trigger threshold. 0 means no threshold"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool use_125 = arg_get_lit(ctx, 1);
    bool use_134 = arg_get_lit(ctx, 2);
    int8_t avg = arg_get_int_def(ctx, 3, 0);
    int8_t bps = arg_get_int_def(ctx, 4, -1);
    int8_t dec = arg_get_int_def(ctx, 5, -1);
    int16_t divisor = arg_get_int_def(ctx, 6, -1);
    int16_t freq = arg_get_int_def(ctx, 7, -1);
    bool reset = arg_get_lit(ctx, 8);
    int32_t skip = arg_get_int_def(ctx, 9, -1);
    int16_t trigg = arg_get_int_def(ctx, 10, -1);
    CLIParserFree(ctx);

    if (g_session.pm3_present == false)
        return PM3_ENOTTY;

    // if called with no params, just print the device config
    if (strlen(Cmd) == 0) {
        return lf_config(NULL);
    }

    if (use_125 + use_134 > 1) {
        PrintAndLogEx(ERR, "use only one of 125 or 134 params");
        return PM3_EINVARG;
    }

    sample_config config = {
        .decimation = -1,
        .bits_per_sample = -1,
        .averaging = -1,
        .divisor = -1,
        .trigger_threshold = -1,
        .samples_to_skip = -1,
        .verbose = true
    };

    if (reset) {
        config.decimation = 1;
        config.bits_per_sample = 8;
        config.averaging = 1,
        config.divisor = LF_DIVISOR_125;
        config.samples_to_skip = 0;
        config.trigger_threshold = 0;
        gs_lf_threshold_set = false;
    }

    if (use_125)
        config.divisor = LF_DIVISOR_125;

    if (use_134)
        config.divisor = LF_DIVISOR_134;

    // check if the config.averaging is not set by if(reset){...}
    if (config.averaging == -1)
        config.averaging = (avg == 1);

    if (bps > -1) {
        // bps is limited to 8
        config.bits_per_sample = (bps & 0x0F);
        if (config.bits_per_sample > 8)
            config.bits_per_sample = 8;
    }

    if (dec > -1) {
        // decimation is limited to 8
        config.decimation = (dec & 0x0F);
        if (config.decimation > 8)
            config.decimation = 8;
    }

    if (divisor > -1) {
        config.divisor = divisor;
        if (config.divisor < 19) {
            PrintAndLogEx(ERR, "divisor must be between 19 and 255");
            return PM3_EINVARG;
        }
    }

    if (freq > -1) {
        config.divisor = LF_FREQ2DIV(freq);
        if (config.divisor < 19) {
            PrintAndLogEx(ERR, "freq must be between 47 and 600");
            return PM3_EINVARG;
        }
    }

    if (trigg > -1) {
        config.trigger_threshold = trigg;
        gs_lf_threshold_set = (config.trigger_threshold > 0);
    }

    config.samples_to_skip = skip;
    return lf_config(&config);
}

int lf_read(bool verbose, uint32_t samples) {
    if (!g_session.pm3_present) return PM3_ENOTTY;

    struct p {
        uint32_t samples : 31;
        bool     verbose : 1;
    } PACKED;

    struct p payload;
    payload.verbose = verbose;
    payload.samples = samples;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ACQ_RAW_ADC, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (gs_lf_threshold_set) {
        WaitForResponse(CMD_LF_ACQ_RAW_ADC, &resp);
    } else {
        if (!WaitForResponseTimeout(CMD_LF_ACQ_RAW_ADC, &resp, 2500)) {
            PrintAndLogEx(WARNING, "(lf_read) command execution time out");
            return PM3_ETIMEOUT;
        }
    }

    // response is number of bits read
    uint32_t size = (resp.data.asDwords[0] / 8);
    getSamples(size, verbose);
    return PM3_SUCCESS;
}

int CmdLFRead(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf read",
                  "Sniff low frequency signal.\n"
                  " - use " _YELLOW_("`lf config`") _CYAN_(" to set parameters.\n")
                  _CYAN_(" - use ") _YELLOW_("`data plot`") _CYAN_(" to look at it"),
                  "lf read -v -s 12000   --> collect 12000 samples\n"
                  "lf read -s 3000 -@    --> oscilloscope style \n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("s", "samples", "<dec>", "number of samples to collect"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("@", NULL, "continuous reading mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t samples = arg_get_u32_def(ctx, 1, 0);
    bool verbose = arg_get_lit(ctx, 2);
    bool cm = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (g_session.pm3_present == false)
        return PM3_ENOTTY;

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }
    int ret = PM3_SUCCESS;
    do {
        ret = lf_read(verbose, samples);
    } while (cm && kbd_enter_pressed() == false);
    return ret;
}

int lf_sniff(bool verbose, uint32_t samples) {
    if (!g_session.pm3_present) return PM3_ENOTTY;

    struct p {
        uint32_t samples : 31;
        bool     verbose : 1;
    } PACKED payload;

    payload.samples = (samples & 0xFFFF);
    payload.verbose = verbose;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_SNIFF_RAW_ADC, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (gs_lf_threshold_set) {
        WaitForResponse(CMD_LF_SNIFF_RAW_ADC, &resp);
    } else {
        if (WaitForResponseTimeout(CMD_LF_SNIFF_RAW_ADC, &resp, 2500) == false) {
            PrintAndLogEx(WARNING, "(lf_read) command execution time out");
            return PM3_ETIMEOUT;
        }
    }

    // response is number of bits read
    uint32_t size = (resp.data.asDwords[0] / 8);
    getSamples(size, verbose);
    return PM3_SUCCESS;
}

int CmdLFSniff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf sniff",
                  "Sniff low frequency signal. You need to configure the LF part on the Proxmark3 device manually.\n"
                  "Usually a trigger and skip samples is a good thing to set before doing a low frequency sniff.\n"
                  "\n"
                  " - use " _YELLOW_("`lf config`") _CYAN_(" to set parameters.\n")
                  _CYAN_(" - use ") _YELLOW_("`data plot`") _CYAN_(" to look at sniff signal.\n")
                  _CYAN_(" - use ") _YELLOW_("`lf search -1`") _CYAN_(" to see if signal can be automatic decoded\n"),
                  "lf sniff -v\n"
                  "lf sniff -s 3000 -@    --> oscilloscope style \n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("s", "samples", "<dec>", "number of samples to collect"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("@", NULL, "continuous sniffing mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t samples = (arg_get_u32_def(ctx, 1, 0) & 0xFFFF);
    bool verbose = arg_get_lit(ctx, 2);
    bool cm = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (g_session.pm3_present == false)
        return PM3_ENOTTY;

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }
    int ret = PM3_SUCCESS;
    do {
        ret = lf_sniff(verbose, samples);
    } while (cm && !kbd_enter_pressed());
    return ret;
}

static void lf_chk_bitstream(void) {
    // convert to bitstream if necessary
    for (int i = 0; i < (int)(g_GraphTraceLen / 2); i++) {
        if (g_GraphBuffer[i] > 1 || g_GraphBuffer[i] < 0) {
            CmdGetBitStream("");
            PrintAndLogEx(INFO, "converted Graphbuffer to bitstream values (0|1)");
            break;
        }
    }
}

// Uploads g_GraphBuffer to device, in order to be used for LF SIM.
int lfsim_upload_gb(void) {
    PrintAndLogEx(DEBUG, "DEBUG: Uploading %zu bytes", g_GraphTraceLen);

    struct pupload {
        uint8_t flag;
        uint16_t offset;
        uint8_t data[PM3_CMD_DATA_SIZE - 3];
    } PACKED payload_up;

    // flag =
    //    b0  0
    //        1 clear bigbuff
    payload_up.flag = 0x1;

    // fast push mode
    g_conn.block_after_ACK = true;

    PacketResponseNG resp;

    //can send only 512 bits at a time (1 byte sent per bit...)
    PrintAndLogEx(INFO, "." NOLF);
    for (size_t i = 0; i < g_GraphTraceLen; i += PM3_CMD_DATA_SIZE - 3) {

        size_t len = MIN((g_GraphTraceLen - i), PM3_CMD_DATA_SIZE - 3);
        clearCommandBuffer();
        payload_up.offset = i;

        for (size_t j = 0; j < len; j++)
            payload_up.data[j] = g_GraphBuffer[i + j];

        SendCommandNG(CMD_LF_UPLOAD_SIM_SAMPLES, (uint8_t *)&payload_up, sizeof(struct pupload));
        WaitForResponse(CMD_LF_UPLOAD_SIM_SAMPLES, &resp);
        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(INFO, "Bigbuf is full");
            break;
        }
        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);
        payload_up.flag = 0;
    }
    PrintAndLogEx(NORMAL, "");

    // Disable fast mode before last command
    g_conn.block_after_ACK = false;
    return PM3_SUCCESS;
}

//Attempt to simulate any wave in buffer (one bit per output sample)
// converts g_GraphBuffer to bitstream (based on zero crossings) if needed.
int CmdLFSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf sim",
                  "Simulate low frequency tag from graphbuffer\n"
                  "Use " _YELLOW_("`lf config`") _CYAN_(" to set parameters"),
                  "lf sim\n"
                  "lf sim --gap 240 --> start simulating with 240ms gap"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("g", "gap", "<ms>", "start gap in microseconds"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint16_t gap = arg_get_u32_def(ctx, 1, 0);
    CLIParserFree(ctx);

    if (g_session.pm3_present == false) {
        PrintAndLogEx(DEBUG, "DEBUG: no proxmark present");
        return PM3_ENOTTY;
    }

    // sanity check
    if (g_GraphTraceLen < 20) {
        PrintAndLogEx(ERR, "No data in Graphbuffer");
        return PM3_ENODATA;
    }

    // convert to bitstream if necessary
    lf_chk_bitstream();

    lfsim_upload_gb();

    struct p {
        uint16_t len;
        uint16_t gap;
    } PACKED payload;
    payload.len = g_GraphTraceLen;
    payload.gap = gap;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_SIMULATE, (uint8_t *)&payload, sizeof(payload));
    return lfsim_wait_check(CMD_LF_SIMULATE);
}

// sim fsk data given clock, fcHigh, fcLow, invert
// - allow pull data from g_DemodBuffer
int CmdLFfskSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf simfsk",
                  "Simulate FSK tag from DemodBuffer or input. There are about four FSK modulations to know of.\n"
                  "FSK1  -  where fc/8 = high  and fc/5 = low\n"
                  "FSK1a -  is inverted FSK1,  ie:   fc/5 = high and fc/8 = low\n"
                  "FSK2  -  where fc/10 = high  and fc/8 = low\n"
                  "FSK2a -  is inverted FSK2,  ie:   fc/10 = high and fc/8 = low\n\n"
                  "NOTE: if you set one clock manually set them all manually",
                  "lf simfsk -c 40 --high 8 --low 5 -d 010203  --> FSK1  rf/40  data 010203\n"
                  "lf simfsk -c 40 --high 5 --low 8 -d 010203  --> FSK1a rf/40  data 010203\n"
                  "lf simfsk -c 64 --high 10 --low 8 -d 010203 --> FSK2  rf/64  data 010203\n"
                  "lf simfsk -c 64 --high 8 --low 10 -d 010203 --> FSK2a rf/64  data 010203\n\n"
                  "lf simfsk -c 50 --high 10 --low 8 -d 1D5559555569A9A555A59569        --> simulate HID Prox tag manually\n"
                  "lf simfsk -c 50 --high 10 --low 8 --stt -d 011DB2487E8D811111111111  --> simulate AWID tag manually"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("c", "clk", "<dec>", "manually set clock - can autodetect if using DemodBuffer (default 64)"),
        arg_u64_0(NULL, "low", "<dec>", "manually set larger Field Clock"),
        arg_u64_0(NULL, "high", "<dec>", "manually set smaller Field Clock"),
        arg_lit0(NULL, "stt", "TBD! - STT to enable a gap between playback repetitions (default: no gap)"),
        arg_str0("d", "data", "<hex>", "data to sim - omit to use DemodBuffer"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint8_t clk = arg_get_u32_def(ctx, 1, 0);
    uint8_t fclow = arg_get_u32_def(ctx, 2, 0);
    uint8_t fchigh = arg_get_u32_def(ctx, 3, 0);
    bool separator = arg_get_lit(ctx, 4);

    int raw_len = 64;
    char raw[64] = {0};
    CLIGetStrWithReturn(ctx, 5, (uint8_t *)raw, &raw_len);
    bool verbose = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    // No args
    if (raw_len == 0 && g_DemodBufferLen == 0) {
        PrintAndLogEx(ERR, "No user supplied data nor inside DemodBuffer");
        return PM3_EINVARG;
    }

    if (verbose && separator) {
        PrintAndLogEx(INFO, "STT gap isn't implemented yet. Skipping...");
        separator = 0;
    }

    uint8_t bs[256] = {0x00};
    int bs_len = hextobinarray((char *)bs, raw);
    if (bs_len == 0) {
        // Using data from g_DemodBuffer
        // might be able to autodetect FC and clock from Graphbuffer if using g_DemodBuffer
        // will need clock, fchigh, fclow and bitstream
        PrintAndLogEx(INFO, "No user supplied data, using DemodBuffer...");

        if (clk == 0 || fchigh == 0 || fclow == 0) {
            int firstClockEdge = 0;
            bool res = fskClocks(&fchigh, &fclow, &clk, &firstClockEdge);
            if (res == false) {
                clk = 0;
                fchigh = 0;
                fclow = 0;
            }
        }
        PrintAndLogEx(DEBUG, "Detected rf/%u, High fc/%u, Low fc/%u, n %zu ", clk, fchigh, fclow, g_DemodBufferLen);

    } else {
        setDemodBuff(bs, bs_len, 0);
    }

    //default if not found
    if (clk == 0) {
        clk = 50;
        PrintAndLogEx(DEBUG, "Autodetection of clock failed, falling back to rf/%u", clk);
    }

    if (fchigh == 0) {
        fchigh = 10;
        PrintAndLogEx(DEBUG, "Autodetection of larger clock failed, falling back to fc/%u", fchigh);
    }

    if (fclow == 0) {
        fclow = 8;
        PrintAndLogEx(DEBUG, "Autodetection of smaller clock failed, falling back to fc/%u", fclow);
    }

    size_t size = g_DemodBufferLen;
    if (size > (PM3_CMD_DATA_SIZE - sizeof(lf_fsksim_t))) {
        PrintAndLogEx(WARNING, "DemodBuffer too long for current implementation - length: %zu - max: %zu", size, PM3_CMD_DATA_SIZE - sizeof(lf_fsksim_t));
        PrintAndLogEx(INFO, "Continuing with trimmed down data");
        size = PM3_CMD_DATA_SIZE - sizeof(lf_fsksim_t);
    }

    lf_fsksim_t *payload = calloc(1, sizeof(lf_fsksim_t) + size);
    payload->fchigh = fchigh;
    payload->fclow =  fclow;
    payload->separator = separator;
    payload->clock = clk;
    memcpy(payload->data, g_DemodBuffer, size);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_FSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_fsksim_t) + size);
    free(payload);
    setClockGrid(clk, 0);

    return lfsim_wait_check(CMD_LF_FSK_SIMULATE);
}

// sim ask data given clock, invert, manchester or raw, separator
// - allow pull data from g_DemodBuffer
int CmdLFaskSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf simask",
                  "Simulate ASK tag from DemodBuffer or input",
                  "lf simask --clk 32 --am -d 0102030405   --> simulate ASK/MAN rf/32\n"
                  "lf simask --clk 32 --bi -d 0102030405   --> simulate ASK/BIPHASE rf/32\n\n"
                  "lf simask --clk 64 --am -d ffbd8001686f1924               --> simulate a EM410x tag\n"
                  "lf simask --clk 64 --am --stt -d 5649533200003F340000001B --> simulate a VISA2K tag"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("i", "inv", "invert data"),
        arg_u64_0("c", "clk", "<dec>", "manually set clock - can autodetect if using DemodBuffer (default 64)"),
        arg_lit0(NULL, "bi", "ask/biphase encoding"),
        arg_lit0(NULL, "am", "ask/manchester encoding (default)"),
        arg_lit0(NULL, "ar", "ask/raw encoding"),
        arg_lit0(NULL, "stt", "add t55xx Sequence Terminator gap - default: no gaps (only manchester)"),
        arg_str0("d", "data", "<hex>", "data to sim - omit to use DemodBuffer"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool invert = arg_get_lit(ctx, 1);
    uint8_t clk = arg_get_u32_def(ctx, 2, 0);
    bool use_bi = arg_get_lit(ctx, 3);
    bool use_am = arg_get_lit(ctx, 4);
    bool use_ar = arg_get_lit(ctx, 5);
    bool separator = arg_get_lit(ctx, 6);

    int raw_len = 64;
    char raw[64] = {0};
    CLIGetStrWithReturn(ctx, 7, (uint8_t *)raw, &raw_len);
    bool verbose = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    if ((use_bi + use_am + use_ar) > 1) {
        PrintAndLogEx(ERR, "only one encoding can be set");
        return PM3_EINVARG;
    }

    uint8_t encoding = 1;
    if (use_bi)
        encoding = 2;
    else if (use_ar)
        encoding = 0;

    // No args
    if (raw_len == 0 && g_DemodBufferLen == 0) {
        PrintAndLogEx(ERR, "No user supplied data nor any inside DemodBuffer");
        return PM3_EINVARG;
    }

    uint8_t bs[256] = {0x00};
    int bs_len = hextobinarray((char *)bs, raw);
    if (bs_len == 0) {
        // Using data from g_DemodBuffer
        // might be able to autodetect FC and clock from Graphbuffer if using g_DemodBuffer
        // will need carrier, clock, and bitstream
        PrintAndLogEx(INFO, "No user supplied data, using DemodBuffer...");

        if (clk == 0) {
            int res = GetAskClock("0", verbose);
            if (res < 1) {
                clk = 64;
            } else {
                clk = (uint8_t)res;
            }
        }

        PrintAndLogEx(DEBUG, "Detected rf/%u, n %zu ", clk, g_DemodBufferLen);

    } else {
        setDemodBuff(bs, bs_len, 0);
    }


    if (clk == 0) {
        clk = 32;
        PrintAndLogEx(DEBUG, "Autodetection of clock failed, falling back to rf/%u", clk);
    }

    if (encoding == 0) {
        clk /= 2; // askraw needs to double the clock speed
        PrintAndLogEx(DEBUG, "ASK/RAW needs half rf. Using rf/%u", clk);
    }

    size_t size = g_DemodBufferLen;
    if (size > (PM3_CMD_DATA_SIZE - sizeof(lf_asksim_t))) {
        PrintAndLogEx(WARNING, "DemodBuffer too long for current implementation - length: %zu - max: %zu", size, PM3_CMD_DATA_SIZE - sizeof(lf_asksim_t));
        PrintAndLogEx(INFO, "Continuing with trimmed down data");
        size = PM3_CMD_DATA_SIZE - sizeof(lf_asksim_t);
    }

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + size);
    payload->encoding = encoding;
    payload->invert = invert;
    payload->separator = separator;
    payload->clock = clk;
    memcpy(payload->data, g_DemodBuffer, size);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload,  sizeof(lf_asksim_t) + size);
    free(payload);
    setClockGrid(clk, 0);

    return lfsim_wait_check(CMD_LF_ASK_SIMULATE);
}

// sim psk data given carrier, clock, invert
// - allow pull data from g_DemodBuffer or parameters
int CmdLFpskSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf simpsk",
                  "Simulate PSK tag from DemodBuffer or input",
                  "lf simpsk -1 --clk 40 --fc 4 -d 01020304   --> simulate PSK1 rf/40 psksub fc/4, data 01020304\n\n"
                  "lf simpsk -1 --clk 32 --fc 2 -d a0000000bd989a11   --> simulate a indala tag manually"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("1", "psk1", "set PSK1 (default)"),
        arg_lit0("2", "psk2", "set PSK2"),
        arg_lit0("3", "psk3", "set PSK3"),
        arg_lit0("i", "inv", "invert data"),
        arg_u64_0("c", "clk", "<dec>", "manually set clock - can autodetect if using DemodBuffer (default 32)"),
        arg_u64_0(NULL, "fc", "<dec>", "2|4|8 are valid carriers (default 2)"),
        arg_str0("d", "data", "<hex>", "data to sim - omit to use DemodBuffer"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool use_psk1 = arg_get_lit(ctx, 1);
    bool use_psk2 = arg_get_lit(ctx, 2);
    bool use_psk3 = arg_get_lit(ctx, 3);
    bool invert = arg_get_lit(ctx, 4);
    uint8_t clk = arg_get_u32_def(ctx, 5, 0);
    uint8_t carrier = arg_get_u32_def(ctx, 6, 2);
    int raw_len = 64;
    char raw[64] = {0};
    CLIGetStrWithReturn(ctx, 7, (uint8_t *)raw, &raw_len);
    bool verbose = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    if ((use_psk1 + use_psk2 + use_psk3) > 1) {
        PrintAndLogEx(ERR, "only one PSK mode can be set");
        return PM3_EINVARG;
    }

    if (carrier != 2 && carrier != 4 && carrier != 8) {
        PrintAndLogEx(ERR, "Wrong carrier given, expected <2|4|8>");
        return PM3_EINVARG;
    }

    uint8_t psk_type = 1;
    if (use_psk2)
        psk_type = 2;
    if (use_psk3)
        psk_type = 3;

    // No args
    if (raw_len == 0 && g_DemodBufferLen == 0) {
        PrintAndLogEx(ERR, "No user supplied data nor any inside DemodBuffer");
        return PM3_EINVARG;
    }

    uint8_t bs[256] = {0x00};
    int bs_len = hextobinarray((char *)bs, raw);

    if (bs_len == 0) {
        // Using data from g_DemodBuffer
        // might be able to autodetect FC and clock from Graphbuffer if using g_DemodBuffer
        // will need carrier, clock, and bitstream
        PrintAndLogEx(INFO, "No user supplied data, using DemodBuffer...");

        int res;
        if (clk == 0) {
            res = GetPskClock("", verbose);
            if (res < 1) {
                clk = 32;
            } else {
                clk = (uint8_t)res;
            }
        }

        if (carrier == 0) {
            res = GetPskCarrier(verbose);
            if (res < 1) {
                carrier = 2;
            } else {
                carrier = (uint8_t)res;
            }
        }

        PrintAndLogEx(DEBUG, "Detected rf/%u, fc/%u, n %zu ", clk, carrier, g_DemodBufferLen);

    } else {
        setDemodBuff(bs, bs_len, 0);
    }

    if (clk == 0) {
        clk = 32;
        PrintAndLogEx(DEBUG, "Autodetection of clock failed, falling back to rf/%u", clk);
    }

    if (psk_type == 2) {
        //need to convert psk2 to psk1 data before sim
        psk2TOpsk1(g_DemodBuffer, g_DemodBufferLen);
    } else if (psk_type == 3) {
        PrintAndLogEx(INFO, "PSK3 not yet available. Falling back to PSK1");
    }

    size_t size = g_DemodBufferLen;
    if (size > (PM3_CMD_DATA_SIZE - sizeof(lf_psksim_t))) {
        PrintAndLogEx(WARNING, "DemodBuffer too long for current implementation - length: %zu - max: %zu", size, PM3_CMD_DATA_SIZE - sizeof(lf_psksim_t));
        PrintAndLogEx(INFO, "Continuing with trimmed down data");
        size = PM3_CMD_DATA_SIZE - sizeof(lf_psksim_t);
    }

    lf_psksim_t *payload = calloc(1, sizeof(lf_psksim_t) + size);
    payload->carrier =  carrier;
    payload->invert = invert;
    payload->clock = clk;
    memcpy(payload->data, g_DemodBuffer, size);
    clearCommandBuffer();
    SendCommandNG(CMD_LF_PSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_psksim_t) + size);
    free(payload);
    setClockGrid(clk, 0);

    return lfsim_wait_check(CMD_LF_PSK_SIMULATE);
}

int CmdLFSimBidir(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf simbidir",
                  "Simulate LF tag with bidirectional data transmission between reader and tag",
                  "lf simbidir"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // Set ADC to twice the carrier for a slight supersampling
    // HACK: not implemented in ARMSRC.
    PrintAndLogEx(INFO, "Not implemented yet.");
//    SendCommandMIX(CMD_LF_SIMULATE_BIDIR, 47, 384, 0, NULL, 0);
    return PM3_SUCCESS;
}

// ICEMAN,  Verichip is Animal tag.  Tested against correct reader
/*

int CmdVchDemod(const char *Cmd) {

    if (g_GraphTraceLen < 4096) {
        PrintAndLogEx(DEBUG, "debug; VchDemod - too few samples");
        return PM3_EINVARG;
    }

    // Is this the entire sync pattern, or does this also include some
    // data bits that happen to be the same everywhere? That would be
    // lovely to know.
    static const int SyncPattern[] = {
        1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
        1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
        1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
        1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
        1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
        1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };

    // iceman, using correlate as preamble detect seems way better than our current memcompare

    // So first, we correlate for the sync pattern, and mark that.
    int bestCorrel = 0, bestPos = 0;
    int i, j, sum = 0;

    // It does us no good to find the sync pattern, with fewer than 2048 samples after it.

    for (i = 0; i < (g_GraphTraceLen - 2048); i++) {
        for (j = 0; j < ARRAYLEN(SyncPattern); j++) {
            sum += g_GraphBuffer[i + j] * SyncPattern[j];
        }
        if (sum > bestCorrel) {
            bestCorrel = sum;
            bestPos = i;
        }
    }
    PrintAndLogEx(NORMAL, "best sync at %d [metric %d]", bestPos, bestCorrel);

    char bits[257];
    bits[256] = '\0';

    int worst = INT_MAX, worstPos = 0;

    for (i = 0; i < 2048; i += 8) {
        sum = 0;
        for (j = 0; j < 8; j++)
            sum += g_GraphBuffer[bestPos + i + j];

        if (sum < 0)
            bits[i / 8] = '.';
        else
            bits[i / 8] = '1';

        if (abs(sum) < worst) {
            worst = abs(sum);
            worstPos = i;
        }
    }
    PrintAndLogEx(NORMAL, "bits:");
    PrintAndLogEx(NORMAL, "%s", bits);
    PrintAndLogEx(NORMAL, "worst metric: %d at pos %d", worst, worstPos);

    // clone
    if (strcmp(Cmd, "clone") == 0) {
        g_GraphTraceLen = 0;
        char *s;
        for (s = bits; *s; s++) {
            for (j = 0; j < 16; j++) {
                g_GraphBuffer[g_GraphTraceLen++] = (*s == '1') ? 1 : 0;
            }
        }
        RepaintGraphWindow();
    }
    return PM3_SUCCESS;
}
*/

static bool CheckChipType(bool getDeviceData) {

    bool retval = false;

    if (!getDeviceData) return retval;

    save_restoreGB(GRAPH_SAVE);
    save_restoreDB(GRAPH_SAVE);

    //check for em4x05/em4x69 chips first
    uint32_t word = 0;
    if (em4x05_isblock0(&word)) {
        PrintAndLogEx(SUCCESS, "Chipset detection: " _GREEN_("EM4x05 / EM4x69"));
        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf em 4x05`") " commands");
        retval = true;
        goto out;
    }

    //check for t55xx chip...
    if (tryDetectP1(true)) {
        PrintAndLogEx(SUCCESS, "Chipset detection: " _GREEN_("T55xx"));
        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf t55xx`") " commands");
        retval = true;
        goto out;
    }

#if !defined ICOPYX
    // check for em4x50 chips
    if (detect_4x50_block()) {
        PrintAndLogEx(SUCCESS, "Chipset detection: " _GREEN_("EM4x50"));
        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf em 4x50`") " commands");
        retval = true;
        goto out;
    }

    // check for em4x70 chips
    if (detect_4x70_block()) {
        PrintAndLogEx(SUCCESS, "Chipset detection: " _GREEN_("EM4x70"));
        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf em 4x70`") " commands");
        retval = true;
        goto out;
    }
#endif

    PrintAndLogEx(INFO, "Couldn't identify a chipset");
out:
    save_restoreGB(GRAPH_RESTORE);
    save_restoreDB(GRAPH_RESTORE);
    return retval;
}

int CmdLFfind(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf search",
                  "Read and search for valid known tag. For offline mode, you can `data load` first then search.",
                  "lf search       -> try reading data from tag & search for known tag\n"
                  "lf search -1    -> use data from the GraphBuffer & search for known tag\n"
                  "lf search -u    -> try reading data from tag & search for known and unknown tag\n"
                  "lf search -1u   -> use data from the GraphBuffer & search for known and unknown tag\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("1", NULL, "Use data from Graphbuffer to search"),
        arg_lit0("c", NULL, "Continue searching even after a first hit"),
        arg_lit0("u", NULL, "Search for unknown tags. If not set, reads only known tags"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool use_gb = arg_get_lit(ctx, 1);
    bool search_cont = arg_get_lit(ctx, 2);
    bool search_unk = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);
    int found = 0;
    bool is_online = (g_session.pm3_present && (use_gb == false));
    if (is_online)
        lf_read(false, 30000);

    size_t min_length = 2000;
    if (g_GraphTraceLen < min_length) {
        PrintAndLogEx(FAILED, "Data in Graphbuffer was too small.");
        return PM3_ESOFT;
    }

    if (search_cont) {
        PrintAndLogEx(INFO, "Continuous search enabled");
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "NOTE: some demods output possible binary");
    PrintAndLogEx(INFO, "if it finds something that looks like a tag");
    PrintAndLogEx(INFO, "False Positives " _YELLOW_("ARE") " possible");
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Checking for known tags...");
    PrintAndLogEx(INFO, "");

    // only run these tests if device is online
    if (is_online) {

        if (IfPm3Hitag()) {
            if (readHitagUid()) {
                PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Hitag") " found!");
                if (search_cont) {
                    found++;
                } else {
                    return PM3_SUCCESS;
                }
            }
        }

#if !defined ICOPYX
        if (IfPm3EM4x50()) {
            if (read_em4x50_uid() == PM3_SUCCESS) {
                PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("EM4x50 ID") " found!");
                if (search_cont) {
                    found++;
                } else {
                    return PM3_SUCCESS;
                }
            }
        }
#endif

        // only run if graphbuffer is just noise as it should be for hitag
        // The improved noise detection will find Cotag.
        if (getSignalProperties()->isnoise) {

            PrintAndLogEx(INPLACE, "Searching for MOTOROLA tag...");
            if (readMotorolaUid()) {
                PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Motorola FlexPass ID") " found!");
                if (search_cont) {
                    found++;
                } else {
                    return PM3_SUCCESS;
                }
            }

            PrintAndLogEx(INPLACE, "Searching for COTAG tag...");
            if (readCOTAGUid()) {
                PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("COTAG ID") " found!");
                if (search_cont) {
                    found++;
                } else {
                    return PM3_SUCCESS;
                }
            }

            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(FAILED, _RED_("No data found!"));
            PrintAndLogEx(HINT, "Maybe not an LF tag?");
            PrintAndLogEx(NORMAL, "");
            if (search_cont == 0) {
                return PM3_ESOFT;
            }
        }
    }

    int retval = PM3_SUCCESS;

    // ask / man
    if (demodEM410x(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("EM410x ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodDestron(true) == PM3_SUCCESS) { // to do before HID
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("FDX-A FECAVA Destron ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodGallagher(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("GALLAGHER ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodNoralsy(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Noralsy ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodPresco(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Presco ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodSecurakey(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Securakey ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodViking(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Viking ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodVisa2k(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Visa2000 ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }

    // ask / bi
    if (demodFDXB(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("FDX-B ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodJablotron(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Jablotron ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodGuard(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Guardall G-Prox II ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodNedap(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("NEDAP ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }

    // nrz
    if (demodPac(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("PAC/Stanley ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }

    // fsk
    if (demodHID(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("HID Prox ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodAWID(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("AWID ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodIOProx(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("IO Prox ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodPyramid(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Pyramid ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodParadox(true, false) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Paradox ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }

    // psk
    if (demodIdteck(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Idteck ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodKeri(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("KERI ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodNexWatch(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("NexWatch ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodIndala(true) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Indala ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    /*
    if (demodTI() == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Texas Instrument ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    if (demodFermax() == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Fermax ID") " found!");
        if (search_cont) {
            found++;
        } else {
            goto out;
        }
    }
    */
    if (found == 0) {
        PrintAndLogEx(FAILED, _RED_("No known 125/134 kHz tags found!"));
    }

    if (search_unk) {
        //test unknown tag formats (raw mode)
        PrintAndLogEx(INFO, "\nChecking for unknown tags:\n");
        int ans = AutoCorrelate(g_GraphBuffer, g_GraphBuffer, g_GraphTraceLen, 8000, false, false);
        if (ans > 0) {

            PrintAndLogEx(INFO, "Possible auto correlation of %d repeating samples", ans);

            if (ans % 8 == 0)
                PrintAndLogEx(INFO, "Possible %d bytes", (ans / 8));
        }

        //fsk
        if (GetFskClock("", false)) {
            if (FSKrawDemod(0, 0, 0, 0, true) == PM3_SUCCESS) {
                PrintAndLogEx(INFO, "Unknown FSK Modulated Tag found!");
                if (search_cont) {
                    found++;
                } else {
                    goto out;
                }
            }
        }

        bool st = true;
        if (ASKDemod_ext(0, 0, 0, 0, false, true, false, 1, &st) == PM3_SUCCESS) {
            PrintAndLogEx(INFO, "Unknown ASK Modulated and Manchester encoded Tag found!");
            PrintAndLogEx(INFO, "if it does not look right it could instead be ASK/Biphase - try " _YELLOW_("'data rawdemod --ab'"));
            if (search_cont) {
                found++;
            } else {
                goto out;
            }
        }

        if (CmdPSK1rawDemod("") == PM3_SUCCESS) {
            PrintAndLogEx(INFO, "Possible unknown PSK1 Modulated Tag found above!");
            PrintAndLogEx(INFO, "    Could also be PSK2 - try " _YELLOW_("'data rawdemod --p2'"));
            PrintAndLogEx(INFO, "    Could also be PSK3 - [currently not supported]");
            PrintAndLogEx(INFO, "    Could also be  NRZ - try " _YELLOW_("'data rawdemod --nr"));
            if (search_cont) {
                found++;
            } else {
                goto out;
            }
        }

        if (found == 0) {
            PrintAndLogEx(FAILED, _RED_("No data found!"));
        }
    }

    if (found == 0) {
        retval = PM3_ESOFT;
    }

out:
    // identify chipset
    if (CheckChipType(is_online) == false) {
        PrintAndLogEx(DEBUG, "Automatic chip type detection " _RED_("failed"));
    }
    return retval;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,            AlwaysAvailable, "This help"},
    {"-----------", CmdHelp,            AlwaysAvailable, "-------------- " _CYAN_("Low Frequency") " --------------"},
    {"awid",        CmdLFAWID,          AlwaysAvailable, "{ AWID RFIDs...              }"},
    {"cotag",       CmdLFCOTAG,         AlwaysAvailable, "{ COTAG CHIPs...             }"},
    {"destron",     CmdLFDestron,       AlwaysAvailable, "{ FDX-A Destron RFIDs...     }"},
    {"em",          CmdLFEM,            AlwaysAvailable, "{ EM CHIPs & RFIDs...        }"},
    {"fdxb",        CmdLFFdxB,          AlwaysAvailable, "{ FDX-B RFIDs...             }"},
    {"gallagher",   CmdLFGallagher,     AlwaysAvailable, "{ GALLAGHER RFIDs...         }"},
    {"gproxii",     CmdLFGuard,         AlwaysAvailable, "{ Guardall Prox II RFIDs...  }"},
    {"hid",         CmdLFHID,           AlwaysAvailable, "{ HID Prox RFIDs...          }"},
    {"hitag",       CmdLFHitag,         AlwaysAvailable, "{ Hitag CHIPs...             }"},
    {"idteck",      CmdLFIdteck,        AlwaysAvailable, "{ Idteck RFIDs...            }"},
    {"indala",      CmdLFINDALA,        AlwaysAvailable, "{ Indala RFIDs...            }"},
    {"io",          CmdLFIO,            AlwaysAvailable, "{ ioProx RFIDs...            }"},
    {"jablotron",   CmdLFJablotron,     AlwaysAvailable, "{ Jablotron RFIDs...         }"},
    {"keri",        CmdLFKeri,          AlwaysAvailable, "{ KERI RFIDs...              }"},
    {"motorola",    CmdLFMotorola,      AlwaysAvailable, "{ Motorola Flexpass RFIDs... }"},
    {"nedap",       CmdLFNedap,         AlwaysAvailable, "{ Nedap RFIDs...             }"},
    {"nexwatch",    CmdLFNEXWATCH,      AlwaysAvailable, "{ NexWatch RFIDs...          }"},
    {"noralsy",     CmdLFNoralsy,       AlwaysAvailable, "{ Noralsy RFIDs...           }"},
    {"pac",         CmdLFPac,           AlwaysAvailable, "{ PAC/Stanley RFIDs...       }"},
    {"paradox",     CmdLFParadox,       AlwaysAvailable, "{ Paradox RFIDs...           }"},
    {"pcf7931",     CmdLFPCF7931,       AlwaysAvailable, "{ PCF7931 CHIPs...           }"},
    {"presco",      CmdLFPresco,        AlwaysAvailable, "{ Presco RFIDs...            }"},
    {"pyramid",     CmdLFPyramid,       AlwaysAvailable, "{ Farpointe/Pyramid RFIDs... }"},
    {"securakey",   CmdLFSecurakey,     AlwaysAvailable, "{ Securakey RFIDs...         }"},
    {"ti",          CmdLFTI,            AlwaysAvailable, "{ TI CHIPs...                }"},
    {"t55xx",       CmdLFT55XX,         AlwaysAvailable, "{ T55xx CHIPs...             }"},
    {"viking",      CmdLFViking,        AlwaysAvailable, "{ Viking RFIDs...            }"},
    {"visa2000",    CmdLFVisa2k,        AlwaysAvailable, "{ Visa2000 RFIDs...          }"},
//    {"zx",          CmdLFZx8211,        AlwaysAvailable, "{ ZX8211 RFIDs...            }"},
    {"-----------", CmdHelp,            AlwaysAvailable, "--------------------- " _CYAN_("General") " ---------------------"},
    {"config",      CmdLFConfig,        IfPm3Lf,         "Get/Set config for LF sampling, bit/sample, decimation, frequency"},
    {"cmdread",     CmdLFCommandRead,   IfPm3Lf,         "Modulate LF reader field to send command before read"},
    {"read",        CmdLFRead,          IfPm3Lf,         "Read LF tag"},
    {"search",      CmdLFfind,          AlwaysAvailable, "Read and Search for valid known tag"},
    {"sim",         CmdLFSim,           IfPm3Lf,         "Simulate LF tag from buffer"},
    {"simask",      CmdLFaskSim,        IfPm3Lf,         "Simulate " _YELLOW_("ASK") " tag"},
    {"simfsk",      CmdLFfskSim,        IfPm3Lf,         "Simulate " _YELLOW_("FSK") " tag"},
    {"simpsk",      CmdLFpskSim,        IfPm3Lf,         "Simulate " _YELLOW_("PSK") " tag"},
//    {"simnrz",      CmdLFnrzSim,        IfPm3Lf,         "Simulate " _YELLOW_("NRZ") " tag"},
    {"simbidir",    CmdLFSimBidir,      IfPm3Lf,         "Simulate LF tag (with bidirectional data transmission between reader and tag)"},
    {"sniff",       CmdLFSniff,         IfPm3Lf,         "Sniff LF traffic between reader and tag"},
    {"tune",        CmdLFTune,          IfPm3Lf,         "Continuously measure LF antenna tuning"},
//    {"vchdemod",    CmdVchDemod,        AlwaysAvailable, "Demodulate samples for VeriChip"},
//    {"flexdemod",   CmdFlexdemod,       AlwaysAvailable, "Demodulate samples for Motorola FlexPass"},
    {NULL, NULL, NULL, NULL}
};

int CmdLF(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}
