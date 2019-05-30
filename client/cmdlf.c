//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency commands
//-----------------------------------------------------------------------------
#include "cmdlf.h"

bool g_lf_threshold_set = false;

static int CmdHelp(const char *Cmd);

static int usage_lf_cmdread(void) {
    PrintAndLogEx(NORMAL, "Usage: lf cmdread d <delay period> z <zero period> o <one period> c <cmdbytes>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             This help");
    PrintAndLogEx(NORMAL, "       d <delay>     delay OFF period, (0 for bitbang mode) (decimal)");
    PrintAndLogEx(NORMAL, "       z <zero>      time period ZERO, (decimal)");
    PrintAndLogEx(NORMAL, "       o <one>       time period ONE, (decimal)");
    PrintAndLogEx(NORMAL, "       c <cmd>       Command bytes  (in ones and zeros)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "       ************* All periods in microseconds (ms)");
    PrintAndLogEx(NORMAL, "       ************* Use lf config to configure options.");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf cmdread d 80 z 100 o 200 c 11000");
    return PM3_SUCCESS;
}
static int usage_lf_read(void) {
    PrintAndLogEx(NORMAL, "Usage: lf read [h] [s] [d numofsamples]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h            This help");
    PrintAndLogEx(NORMAL, "       s            silent run no printout");
    PrintAndLogEx(NORMAL, "       d #samples   # samples to collect (optional)");
    PrintAndLogEx(NORMAL, "Use 'lf config' to set parameters.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         lf read s d 12000     - collects 12000samples silent");
    PrintAndLogEx(NORMAL, "         lf read s");
    return PM3_SUCCESS;
}
static int usage_lf_sim(void) {
    PrintAndLogEx(NORMAL, "Simulate low frequence tag from graphbuffer.");
    PrintAndLogEx(NORMAL, "Use " _YELLOW_("'lf config'")" to set parameters.");
    PrintAndLogEx(NORMAL, "Usage: lf sim [h] <gap>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         This help");
    PrintAndLogEx(NORMAL, "       <gap>     Start gap (in microseconds)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         lf sim 240     - start simulating with 240ms gap");
    PrintAndLogEx(NORMAL, "         lf sim");
    return PM3_SUCCESS;
}
static int usage_lf_sniff(void) {
    PrintAndLogEx(NORMAL, "Sniff low frequence signal.");
    PrintAndLogEx(NORMAL, "Use " _YELLOW_("'lf config'")" to set parameters.");
    PrintAndLogEx(NORMAL, "Use " _YELLOW_("'data samples'")" command to download from device,  and " _YELLOW_("'data plot'")" to look at it");

    PrintAndLogEx(NORMAL, "Usage: lf sniff [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         This help");
    return PM3_SUCCESS;
}
static int usage_lf_config(void) {
    PrintAndLogEx(NORMAL, "Usage: lf config [h] [H|<divisor>] [b <bps>] [d <decim>] [a 0|1]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             This help");
    PrintAndLogEx(NORMAL, "       L             Low frequency (125 kHz)");
    PrintAndLogEx(NORMAL, "       H             High frequency (134 kHz)");
    PrintAndLogEx(NORMAL, "       q <divisor>   Manually set divisor. 88-> 134 kHz, 95-> 125 kHz");
    PrintAndLogEx(NORMAL, "       b <bps>       Sets resolution of bits per sample. Default (max): 8");
    PrintAndLogEx(NORMAL, "       d <decim>     Sets decimation. A value of N saves only 1 in N samples. Default: 1");
    PrintAndLogEx(NORMAL, "       a [0|1]       Averaging - if set, will average the stored sample value when decimating. Default: 1");
    PrintAndLogEx(NORMAL, "       t <threshold> Sets trigger threshold. 0 means no threshold (range: 0-128)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf config b 8 L");
    PrintAndLogEx(NORMAL, "                    Samples at 125 kHz, 8bps.");
    PrintAndLogEx(NORMAL, "      lf config H b 4 d 3");
    PrintAndLogEx(NORMAL, "                    Samples at 134 kHz, averages three samples into one, stored with ");
    PrintAndLogEx(NORMAL, "                    a resolution of 4 bits per sample.");
    PrintAndLogEx(NORMAL, "      lf read");
    PrintAndLogEx(NORMAL, "                    Performs a read (active field)");
    PrintAndLogEx(NORMAL, "      lf sniff");
    PrintAndLogEx(NORMAL, "                    Performs a sniff (no active field)");
    return PM3_SUCCESS;
}
static int usage_lf_simfsk(void) {
    PrintAndLogEx(NORMAL, "Usage: lf simfsk [h] [c <clock>] [H <fcHigh>] [L <fcLow>] [d <hexdata>]");
    PrintAndLogEx(NORMAL, "there are about four FSK modulations to know of.");
    PrintAndLogEx(NORMAL, "FSK1  -  where fc/8 = high  and fc/5 = low");
    PrintAndLogEx(NORMAL, "FSK1a -  is inverted FSK1,  ie:   fc/5 = high and fc/8 = low");
    PrintAndLogEx(NORMAL, "FSK2  -  where fc/10 = high  and fc/8 = low");
    PrintAndLogEx(NORMAL, "FSK2a -  is inverted FSK2,  ie:   fc/10 = high and fc/8 = low");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h              This help");
    PrintAndLogEx(NORMAL, "       c <clock>      Manually set clock - can autodetect if using DemodBuffer");
    PrintAndLogEx(NORMAL, "       H <fcHigh>     Manually set the larger Field Clock");
    PrintAndLogEx(NORMAL, "       L <fcLow>      Manually set the smaller Field Clock");
    //PrintAndLogEx(NORMAL, "       s              TBD- -STT to enable a gap between playback repetitions - default: no gap");
    PrintAndLogEx(NORMAL, "       d <hexdata>    Data to sim as hex - omit to sim from DemodBuffer");
    PrintAndLogEx(NORMAL, "\n  NOTE: if you set one clock manually set them all manually");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf simfsk c 40 H 8 L 5 d 010203      -  FSK1  rf/40  data 010203");
    PrintAndLogEx(NORMAL, "       lf simfsk c 40 H 5 L 8 d 010203      -  FSK1a rf/40  data 010203");
    PrintAndLogEx(NORMAL, "       lf simfsk c 64 H 10 L 8 d 010203     -  FSK2  rf/64  data 010203");
    PrintAndLogEx(NORMAL, "       lf simfsk c 64 H 8 L 10 d 010203     -  FSK2a rf/64  data 010203");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_simask(void) {
    PrintAndLogEx(NORMAL, "Usage: lf simask [c <clock>] [i] [b|m|r] [s] [d <raw hex to sim>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h              This help");
    PrintAndLogEx(NORMAL, "       c <clock>      Manually set clock - can autodetect if using DemodBuffer");
    PrintAndLogEx(NORMAL, "       i              invert data");
    PrintAndLogEx(NORMAL, "       b              sim ask/biphase");
    PrintAndLogEx(NORMAL, "       m              sim ask/manchester - Default");
    PrintAndLogEx(NORMAL, "       r              sim ask/raw");
    PrintAndLogEx(NORMAL, "       s              add t55xx Sequence Terminator gap - default: no gaps (only manchester)");
    PrintAndLogEx(NORMAL, "       d <hexdata>    Data to sim as hex - omit to sim from DemodBuffer");
    return PM3_SUCCESS;
}
static int usage_lf_simpsk(void) {
    PrintAndLogEx(NORMAL, "Usage: lf simpsk [1|2|3] [c <clock>] [i] [r <carrier>] [d <raw hex to sim>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h              This help");
    PrintAndLogEx(NORMAL, "       c <clock>      Manually set clock - can autodetect if using DemodBuffer");
    PrintAndLogEx(NORMAL, "       i              invert data");
    PrintAndLogEx(NORMAL, "       1              set PSK1 (default)");
    PrintAndLogEx(NORMAL, "       2              set PSK2");
    PrintAndLogEx(NORMAL, "       3              set PSK3");
    PrintAndLogEx(NORMAL, "       r <carrier>    2|4|8 are valid carriers: default = 2");
    PrintAndLogEx(NORMAL, "       d <hexdata>    Data to sim as hex - omit to sim from DemodBuffer");
    return PM3_SUCCESS;
}
static int usage_lf_find(void) {
    PrintAndLogEx(NORMAL, "Usage:  lf search [h] <0|1> [u]");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             This help");
    PrintAndLogEx(NORMAL, "       <0|1>         Use data from Graphbuffer, if not set, try reading data from tag.");
    PrintAndLogEx(NORMAL, "       u             Search for Unknown tags, if not set, reads only known tags.");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf search     = try reading data from tag & search for known tags");
    PrintAndLogEx(NORMAL, "      lf search 1   = use data from GraphBuffer & search for known tags");
    PrintAndLogEx(NORMAL, "      lf search u   = try reading data from tag & search for known and unknown tags");
    PrintAndLogEx(NORMAL, "      lf search 1 u = use data from GraphBuffer & search for known and unknown tags");
    return PM3_SUCCESS;
}


/* send a LF command before reading */
int CmdLFCommandRead(const char *Cmd) {

    if (!session.pm3_present) return PM3_ENOTTY;

    bool errors = false;
    uint16_t datalen = 0;

    struct p {
        uint32_t delay;
        uint16_t ones;
        uint16_t zeros;
        uint8_t data[PM3_CMD_DATA_SIZE - 8];
    } PACKED payload;

    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_cmdread();
            case 'c':  // cmd bytes 1010
                datalen = param_getstr(Cmd, cmdp + 1, (char *)&payload.data, sizeof(payload.data));
                cmdp += 2;
                break;
            case 'd':  // delay
                payload.delay = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            case 'z':  // zero
                payload.zeros = param_get32ex(Cmd, cmdp + 1, 0, 10) & 0xFFFF;
                cmdp += 2;
                break;
            case 'o':  // ones
                payload.ones = param_get32ex(Cmd, cmdp + 1, 0, 10) & 0xFFFF;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors || cmdp == 0)  return usage_lf_cmdread();

    PrintAndLogEx(SUCCESS, "Sending");
    clearCommandBuffer();
    SendCommandNG(CMD_MOD_THEN_ACQUIRE_RAW_ADC_SAMPLES_125K, (uint8_t*)&payload, 8 + datalen );

    printf("\n");
    uint8_t i = 10;
    while ( !WaitForResponseTimeout(CMD_MOD_THEN_ACQUIRE_RAW_ADC_SAMPLES_125K, NULL, 2000 ) && i != 0) {
        printf(".");
        fflush(stdout);
        i--;
    }
    printf("\n");

    if ( i ) {
        PrintAndLogEx(SUCCESS, "Downloading response signal data");
        getSamples(0, true);
        return PM3_SUCCESS;
    }
    PrintAndLogEx(WARNING, "timeout while waiting for reply.");
    return PM3_ETIMEOUT;
}

int CmdFlexdemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

#ifndef LONG_WAIT
#define LONG_WAIT 100
#endif
    int i, j, start, bit, sum;

    int data[GraphTraceLen];
    memcpy(data, GraphBuffer, GraphTraceLen);

    size_t size = GraphTraceLen;

    for (i = 0; i < GraphTraceLen; ++i)
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

    // iceman,  use demod buffer?  blue line?
    // HACK writing back to graphbuffer.
    GraphTraceLen = 32 * 64;
    i = 0;
    for (bit = 0; bit < 64; bit++) {

        int phase = (bits[bit] == 0) ? 0 : 1;

        for (j = 0; j < 32; j++) {
            GraphBuffer[i++] = phase;
            phase = !phase;
        }
    }
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

int CmdLFSetConfig(const char *Cmd) {

    if (!session.pm3_present) return PM3_ENOTTY;

    uint8_t divisor =  0;//Frequency divisor
    uint8_t bps = 0; // Bits per sample
    uint8_t decimation = 0; //How many to keep
    bool averaging = 1; // Defaults to true
    bool errors = false;
    int trigger_threshold = -1;//Means no change
    uint8_t unsigned_trigg = 0;

    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (param_getchar(Cmd, cmdp)) {
            case 'h':
                return usage_lf_config();
            case 'H':
                divisor = 88;
                cmdp++;
                break;
            case 'L':
                divisor = 95;
                cmdp++;
                break;
            case 'q':
                errors |= param_getdec(Cmd, cmdp + 1, &divisor);
                cmdp += 2;
                break;
            case 't':
                errors |= param_getdec(Cmd, cmdp + 1, &unsigned_trigg);
                cmdp += 2;
                if (!errors) {
                    trigger_threshold = unsigned_trigg;
                    g_lf_threshold_set = (trigger_threshold > 0);
                }
                break;
            case 'b':
                errors |= param_getdec(Cmd, cmdp + 1, &bps);
                cmdp += 2;
                break;
            case 'd':
                errors |= param_getdec(Cmd, cmdp + 1, &decimation);
                cmdp += 2;
                break;
            case 'a':
                averaging = param_getchar(Cmd, cmdp + 1) == '1';
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = 1;
                break;
        }
    }

    //Validations
    if (errors || cmdp == 0) return usage_lf_config();

    //Bps is limited to 8
    if (bps >> 4) bps = 8;

    sample_config config = { decimation, bps, averaging, divisor, trigger_threshold };

    clearCommandBuffer();
    SendCommandNG(CMD_SET_LF_SAMPLING_CONFIG, (uint8_t *)&config, sizeof(sample_config));
    return PM3_SUCCESS;
}

int lf_read(bool silent, uint32_t samples) {
    if (!session.pm3_present) return PM3_ENOTTY;

    struct p {
        uint8_t silent;
        uint32_t samples;
    } PACKED;

    struct p payload;
    payload.silent = silent;
    payload.samples = samples;

    clearCommandBuffer();
    SendCommandNG(CMD_ACQUIRE_RAW_ADC_SAMPLES_125K, (uint8_t *)&payload, sizeof(payload));

    PacketResponseNG resp;
    if (g_lf_threshold_set) {
        WaitForResponse(CMD_ACQUIRE_RAW_ADC_SAMPLES_125K, &resp);
    } else {
        if (!WaitForResponseTimeout(CMD_ACQUIRE_RAW_ADC_SAMPLES_125K, &resp, 2500)) {
            PrintAndLogEx(WARNING, "command execution time out");
            return PM3_ETIMEOUT;
        }
    }

    // resp.oldarg[0] is bits read not bytes read.
    uint32_t bits = (resp.data.asDwords[0] / 8 );
    getSamples(bits, silent);

    return PM3_SUCCESS;
}

int CmdLFRead(const char *Cmd) {

    if (!session.pm3_present) return PM3_ENOTTY;

    bool errors = false;
    bool silent = false;
    uint32_t samples = 0;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_read();
            case 's':
                silent = true;
                cmdp++;
                break;
            case 'd':
                samples = param_get32ex(Cmd, cmdp, 0, 10);
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors) return usage_lf_read();

    return lf_read(silent, samples);
}

int CmdLFSniff(const char *Cmd) {

    if (!session.pm3_present) return PM3_ENOTTY;

    uint8_t cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_lf_sniff();

    clearCommandBuffer();
    SendCommandNG(CMD_LF_SNIFF_RAW_ADC_SAMPLES, NULL, 0);
    WaitForResponse(CMD_ACK, NULL);
    getSamples(0, false);
    return PM3_SUCCESS;
}

static void ChkBitstream() {
    // convert to bitstream if necessary
    for (int i = 0; i < (int)(GraphTraceLen / 2); i++) {
        if (GraphBuffer[i] > 1 || GraphBuffer[i] < 0) {
            CmdGetBitStream("");
	    PrintAndLogEx(INFO, "Converted to bitstream");
            break;
        }
    }
}
//Attempt to simulate any wave in buffer (one bit per output sample)
// converts GraphBuffer to bitstream (based on zero crossings) if needed.
int CmdLFSim(const char *Cmd) {

    if (!session.pm3_present) return PM3_ENOTTY;

    // sanity check
    if ( GraphTraceLen < 20 ) {
        PrintAndLogEx(ERR, "No data in Graphbuffer");
        return PM3_ENODATA;
    }

    uint8_t cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_lf_sim();

    uint16_t gap = param_get32ex(Cmd, 0, 0, 10) & 0xFFFF;

    // convert to bitstream if necessary
    ChkBitstream();

    PrintAndLogEx(DEBUG, "DEBUG: Uploading %d bytes", GraphTraceLen);

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
    conn.block_after_ACK = true;

    //can send only 512 bits at a time (1 byte sent per bit...)
    for (uint16_t i = 0; i < GraphTraceLen; i += PM3_CMD_DATA_SIZE - 3) {

        size_t len = MIN((GraphTraceLen - i), PM3_CMD_DATA_SIZE - 3);
        clearCommandBuffer();
        payload_up.offset = i;

        for(uint16_t j = 0; j < len; j++)
            payload_up.data[j] = GraphBuffer[i+j];

      
        SendCommandNG(CMD_UPLOAD_SIM_SAMPLES_125K, (uint8_t *)&payload_up, sizeof(struct pupload));
        WaitForResponse(CMD_UPLOAD_SIM_SAMPLES_125K, NULL);
        printf(".");
        fflush(stdout);
        payload_up.flag = 0;
    }

    // Disable fast mode before last command
    conn.block_after_ACK = false;
    printf("\n");

    PrintAndLogEx(INFO, "Simulating");

    struct p {
        uint16_t len;
        uint16_t gap;
    } PACKED payload;
    payload.len = GraphTraceLen;
    payload.gap = gap;	

    clearCommandBuffer();
    SendCommandNG(CMD_SIMULATE_TAG_125K, (uint8_t *)&payload, sizeof(payload));

    PacketResponseNG resp;
    WaitForResponse(CMD_SIMULATE_TAG_125K, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

// by marshmellow - sim fsk data given clock, fcHigh, fcLow, invert
// - allow pull data from DemodBuffer
int CmdLFfskSim(const char *Cmd) {
    //might be able to autodetect FCs and clock from Graphbuffer if using demod buffer
    // otherwise will need FChigh, FClow, Clock, and bitstream
    uint8_t fcHigh = 0, fcLow = 0, clk = 0;
    bool errors = false, separator = false;
    char hexData[64] = {0x00}; // store entered hex data
    uint8_t data[255] = {0x00};
    int dataLen = 0;
    uint8_t cmdp = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (param_getchar(Cmd, cmdp)) {
            case 'h':
                return usage_lf_simfsk();
            case 'c':
                errors |= param_getdec(Cmd, cmdp + 1, &clk);
                cmdp += 2;
                break;
            case 'H':
                errors |= param_getdec(Cmd, cmdp + 1, &fcHigh);
                cmdp += 2;
                break;
            case 'L':
                errors |= param_getdec(Cmd, cmdp + 1, &fcLow);
                cmdp += 2;
                break;
            case 's':
                separator = true;
                cmdp++;
                break;
            case 'd':
                dataLen = param_getstr(Cmd, cmdp + 1, hexData, sizeof(hexData));
                if (dataLen == 0)
                    errors = true;
                else
                    dataLen = hextobinarray((char *)data, hexData);

                if (dataLen == 0) errors = true;
                if (errors) PrintAndLogEx(WARNING, "Error getting hex data");
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    // No args
    if (cmdp == 0 && DemodBufferLen == 0) return usage_lf_simfsk();

    //Validations
    if (errors) return usage_lf_simfsk();

    int firstClockEdge = 0;
    if (dataLen == 0) { //using DemodBuffer
        if (clk == 0 || fcHigh == 0 || fcLow == 0) { //manual settings must set them all
            uint8_t ans = fskClocks(&fcHigh, &fcLow, &clk, &firstClockEdge);
            if (ans == 0) {
                if (!fcHigh) fcHigh = 10;
                if (!fcLow) fcLow = 8;
                if (!clk) clk = 50;
            }
        }
    } else {
        setDemodBuff(data, dataLen, 0);
    }

    //default if not found
    if (clk == 0) clk = 50;
    if (fcHigh == 0) fcHigh = 10;
    if (fcLow == 0) fcLow = 8;

    size_t size = DemodBufferLen;
    if (size > (PM3_CMD_DATA_SIZE - sizeof(lf_fsksim_t))) {
        PrintAndLogEx(NORMAL, "DemodBuffer too long for current implementation - length: %d - max: %d", size, PM3_CMD_DATA_SIZE - sizeof(lf_fsksim_t));
        size = PM3_CMD_DATA_SIZE - sizeof(lf_fsksim_t);
    }

    lf_fsksim_t *payload = calloc(1, sizeof(lf_fsksim_t) + size);
    payload->fchigh = fcHigh;
    payload->fclow =  fcLow;
    payload->separator = separator;
    payload->clock = clk;
    memcpy(payload->data, DemodBuffer, size);

    PrintAndLogEx(INFO, "Simulating");

    clearCommandBuffer();
    SendCommandNG(CMD_FSK_SIM_TAG, (uint8_t *)payload,  sizeof(lf_fsksim_t) + size);
    free(payload);

    setClockGrid(clk, 0);
    PacketResponseNG resp;
    WaitForResponse(CMD_FSK_SIM_TAG, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

// by marshmellow - sim ask data given clock, invert, manchester or raw, separator
// - allow pull data from DemodBuffer
int CmdLFaskSim(const char *Cmd) {
    // autodetect clock from Graphbuffer if using demod buffer
    // needs clock, invert, manchester/raw as m or r, separator as s, and bitstream
    uint8_t encoding = 1, separator = 0, clk = 0, invert = 0;
    bool errors = false;
    char hexData[64] = {0x00};
    uint8_t data[255] = {0x00}; // store entered hex data
    int dataLen = 0;
    uint8_t cmdp = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_simask();
            case 'i':
                invert = 1;
                cmdp++;
                break;
            case 'c':
                errors |= param_getdec(Cmd, cmdp + 1, &clk);
                cmdp += 2;
                break;
            case 'b':
                encoding = 2; //biphase
                cmdp++;
                break;
            case 'm':
                encoding = 1; //manchester
                cmdp++;
                break;
            case 'r':
                encoding = 0; //raw
                cmdp++;
                break;
            case 's':
                separator = 1;
                cmdp++;
                break;
            case 'd':
                dataLen = param_getstr(Cmd, cmdp + 1, hexData, sizeof(hexData));
                if (dataLen == 0)
                    errors = true;
                else
                    dataLen = hextobinarray((char *)data, hexData);

                if (dataLen == 0) errors = true;
                if (errors) PrintAndLogEx(WARNING, "Error getting hex data, datalen: %d", dataLen);
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    // No args
    if (cmdp == 0 && DemodBufferLen == 0) return usage_lf_simask();

    //Validations
    if (errors) return usage_lf_simask();

    if (dataLen == 0) { //using DemodBuffer
        if (clk == 0)
            clk = GetAskClock("0", false);
    } else {
        setDemodBuff(data, dataLen, 0);
    }
    if (clk == 0) clk = 64;
    if (encoding == 0) clk /= 2; //askraw needs to double the clock speed

    size_t size = DemodBufferLen;
    if (size > (PM3_CMD_DATA_SIZE - sizeof(lf_asksim_t))) {
        PrintAndLogEx(NORMAL, "DemodBuffer too long for current implementation - length: %d - max: %d", size, PM3_CMD_DATA_SIZE - sizeof(lf_asksim_t));
        size = PM3_CMD_DATA_SIZE - sizeof(lf_asksim_t);
    }

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + size);
    payload->encoding =  encoding;
    payload->invert = invert;
    payload->separator = separator;
    payload->clock = clk;
    memcpy(payload->data, DemodBuffer, size);

    PrintAndLogEx(INFO, "Simulating");

    clearCommandBuffer();
    SendCommandNG(CMD_ASK_SIM_TAG, (uint8_t *)payload,  sizeof(lf_asksim_t) + size);
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_ASK_SIM_TAG, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

// by marshmellow - sim psk data given carrier, clock, invert
// - allow pull data from DemodBuffer or parameters
int CmdLFpskSim(const char *Cmd) {
    //might be able to autodetect FC and clock from Graphbuffer if using demod buffer
    //will need carrier, Clock, and bitstream
    uint8_t carrier = 0, clk = 0;
    uint8_t invert = 0;
    bool errors = false;
    char hexData[64] = {0x00}; // store entered hex data
    uint8_t data[255] = {0x00};
    int dataLen = 0;
    uint8_t cmdp = 0;
    uint8_t pskType = 1;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_simpsk();
            case 'i':
                invert = 1;
                cmdp++;
                break;
            case 'c':
                errors |= param_getdec(Cmd, cmdp + 1, &clk);
                cmdp += 2;
                break;
            case 'r':
                errors |= param_getdec(Cmd, cmdp + 1, &carrier);
                cmdp += 2;
                break;
            case '1':
                pskType = 1;
                cmdp++;
                break;
            case '2':
                pskType = 2;
                cmdp++;
                break;
            case '3':
                pskType = 3;
                cmdp++;
                break;
            case 'd':
                dataLen = param_getstr(Cmd, cmdp + 1, hexData, sizeof(hexData));
                if (dataLen == 0)
                    errors = true;
                else
                    dataLen = hextobinarray((char *)data, hexData);

                if (dataLen == 0) errors = true;
                if (errors) PrintAndLogEx(WARNING, "Error getting hex data");
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    // No args
    if (cmdp == 0 && DemodBufferLen == 0)
        errors = true;

    //Validations
    if (errors) return usage_lf_simpsk();

    if (dataLen == 0) { //using DemodBuffer
        PrintAndLogEx(NORMAL, "Getting Clocks");

        if (clk == 0) clk = GetPskClock("", false);
        PrintAndLogEx(NORMAL, "clk: %d", clk);

        if (!carrier) carrier = GetPskCarrier("", false);
        PrintAndLogEx(NORMAL, "carrier: %d", carrier);

    } else {
        setDemodBuff(data, dataLen, 0);
    }

    if (clk == 0) clk = 32;

    if (carrier != 2 && carrier != 4 && carrier != 8)
        carrier = 2;

    if (pskType != 1) {
        if (pskType == 2) {
            //need to convert psk2 to psk1 data before sim
            psk2TOpsk1(DemodBuffer, DemodBufferLen);
        } else {
            PrintAndLogEx(NORMAL, "Sorry, PSK3 not yet available");
        }
    }
    size_t size = DemodBufferLen;
    if (size > (PM3_CMD_DATA_SIZE - sizeof(lf_psksim_t))) {
        PrintAndLogEx(NORMAL, "DemodBuffer too long for current implementation - length: %d - max: %d", size, PM3_CMD_DATA_SIZE - sizeof(lf_psksim_t));
        size = PM3_CMD_DATA_SIZE - sizeof(lf_psksim_t);
    }

    lf_psksim_t *payload = calloc(1, sizeof(lf_psksim_t) + size);
    payload->carrier =  carrier;
    payload->invert = invert;
    payload->clock = clk;
    memcpy(payload->data, DemodBuffer, size);

    PrintAndLogEx(INFO, "Simulating");

    clearCommandBuffer();
    SendCommandNG(CMD_PSK_SIM_TAG, (uint8_t *)payload,  sizeof(lf_psksim_t) + size);
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_PSK_SIM_TAG, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

int CmdLFSimBidir(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    // Set ADC to twice the carrier for a slight supersampling
    // HACK: not implemented in ARMSRC.
    PrintAndLogEx(INFO, "Not implemented yet.");
    SendCommandMIX(CMD_LF_SIMULATE_BIDIR, 47, 384, 0, NULL, 0);
    return PM3_SUCCESS;
}

// ICEMAN,  todo,   swap from Graphbuffer.
int CmdVchDemod(const char *Cmd) {
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

    // So first, we correlate for the sync pattern, and mark that.
    int bestCorrel = 0, bestPos = 0;
    int i, j, sum = 0;

    // It does us no good to find the sync pattern, with fewer than 2048 samples after it.

    for (i = 0; i < (GraphTraceLen - 2048); i++) {
        for (j = 0; j < ARRAYLEN(SyncPattern); j++) {
            sum += GraphBuffer[i + j] * SyncPattern[j];
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
            sum += GraphBuffer[bestPos + i + j];

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
        GraphTraceLen = 0;
        char *s;
        for (s = bits; *s; s++) {
            for (j = 0; j < 16; j++) {
                GraphBuffer[GraphTraceLen++] = (*s == '1') ? 1 : 0;
            }
        }
        RepaintGraphWindow();
    }
    return PM3_SUCCESS;
}

//by marshmellow
static bool CheckChipType(bool getDeviceData) {

    bool retval = false;

    if (!getDeviceData) return retval;

    save_restoreGB(GRAPH_SAVE);
    save_restoreDB(GRAPH_SAVE);

    //check for em4x05/em4x69 chips first
    uint32_t word = 0;
    if (EM4x05IsBlock0(&word)) {
        PrintAndLogEx(SUCCESS, "\nChipset detection : " _GREEN_("EM4x05/EM4x69") "found");
        PrintAndLogEx(SUCCESS, "Try " _YELLOW_("`lf em 4x05`") " commands");
        retval = true;
        goto out;
    }

    //check for t55xx chip...
    if (tryDetectP1(true)) {
        PrintAndLogEx(SUCCESS, "\nChipset detection : " _GREEN_("T55xx") "found");
        PrintAndLogEx(SUCCESS, "Try " _YELLOW_("`lf t55xx`")"commands");
        retval = true;
        goto out;
    }

out:
    save_restoreGB(GRAPH_RESTORE);
    save_restoreDB(GRAPH_RESTORE);
    return retval;
}

//by marshmellow
int CmdLFfind(const char *Cmd) {
    int ans = 0;
    size_t minLength = 2000;
    char cmdp = tolower(param_getchar(Cmd, 0));
    char testRaw = param_getchar(Cmd, 1);

    if (strlen(Cmd) > 3 || cmdp == 'h') return usage_lf_find();

    if (cmdp == 'u') testRaw = 'u';

    bool isOnline = (session.pm3_present && (cmdp != '1'));

    if (isOnline)
        lf_read(true, 30000);

    if (GraphTraceLen < minLength) {
        PrintAndLogEx(FAILED, "Data in Graphbuffer was too small.");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "NOTE: some demods output possible binary");
    PrintAndLogEx(INFO, "if it finds something that looks like a tag");
    PrintAndLogEx(INFO, "False Positives " _YELLOW_("ARE") "possible");
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Checking for known tags...\n");

    // only run these tests if device is online
    if (isOnline) {
        // only run if graphbuffer is just noise as it should be for hitag
        // The improved noise detection will find Cotag.
        if (getSignalProperties()->isnoise) {

            if (IfPm3Hitag()) {
                if (readHitagUid()) { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Hitag") "found!"); return PM3_SUCCESS;}
            }
            if (readCOTAGUid()) { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("COTAG ID") "found!"); return PM3_SUCCESS;}

            PrintAndLogEx(FAILED, "\n" _YELLOW_("No data found!") " - Signal looks like noise. Maybe not an LF tag?");
            return PM3_ESOFT;
        }
    }

    if (EM4x50Read("", false) == PM3_SUCCESS)  { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("EM4x50 ID") "found!"); return PM3_SUCCESS;}

    if (demodHID() == PM3_SUCCESS)             { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("HID Prox ID") "found!"); goto out;}
    if (demodAWID() == PM3_SUCCESS)            { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("AWID ID") "found!"); goto out;}
    if (demodParadox() == PM3_SUCCESS)         { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Paradox ID") "found!"); goto out;}

    if (demodEM410x() == PM3_SUCCESS)          { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("EM410x ID") "found!"); goto out;}
    if (demodFDX() == PM3_SUCCESS)             { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("FDX-B ID") "found!"); goto out;}
    if (demodGuard() == PM3_SUCCESS)           { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Guardall G-Prox II ID") "found!"); goto out; }
    if (demodIdteck() == PM3_SUCCESS)          { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Idteck ID") "found!"); goto out;}
    if (demodIndala() == PM3_SUCCESS)          { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Indala ID") "found!");  goto out;}
    if (demodIOProx() == PM3_SUCCESS)          { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("IO Prox ID") "found!"); goto out;}
    if (demodJablotron() == PM3_SUCCESS)       { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Jablotron ID") "found!"); goto out;}
    if (demodNedap() == PM3_SUCCESS)           { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("NEDAP ID") "found!"); goto out;}
    if (demodNexWatch() == PM3_SUCCESS)        { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("NexWatch ID") "found!"); goto out;}
    if (demodNoralsy() == PM3_SUCCESS)         { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Noralsy ID") "found!"); goto out;}
    if (demodKeri() == PM3_SUCCESS)            { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("KERI ID") "found!"); goto out;}
    if (demodPac() == PM3_SUCCESS)             { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("PAC/Stanley ID") "found!"); goto out;}

    if (demodPresco() == PM3_SUCCESS)          { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Presco ID") "found!"); goto out;}
    if (demodPyramid() == PM3_SUCCESS)         { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Pyramid ID") "found!"); goto out;}
    if (demodSecurakey() == PM3_SUCCESS)       { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Securakey ID") "found!"); goto out;}
    if (demodViking() == PM3_SUCCESS)          { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Viking ID") "found!"); goto out;}
    if (demodVisa2k() == PM3_SUCCESS)          { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Visa2000 ID") "found!"); goto out;}
    if (demodTI() == PM3_SUCCESS)              { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Texas Instrument ID") "found!"); goto out;}
    //if (demodFermax() == PM3_SUCCESS)          { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Fermax ID") "found!"); goto out;}
    //if (demodFlex() == PM3_SUCCESS)            { PrintAndLogEx(SUCCESS, "\nValid " _GREEN_("Flex ID") "found!"); goto out;}

    PrintAndLogEx(FAILED, _RED_("No known 125/134 kHz tags found!"));

    if (testRaw == 'u') {
        //test unknown tag formats (raw mode)
        PrintAndLogEx(INFO, "\nChecking for unknown tags:\n");
        ans = AutoCorrelate(GraphBuffer, GraphBuffer, GraphTraceLen, 8000, false, false);
        if (ans > 0) {

            PrintAndLogEx(INFO, "Possible auto correlation of %d repeating samples", ans);

            if (ans % 8 == 0)
                PrintAndLogEx(INFO, "Possible %d bytes", (ans / 8));
        }

        //fsk
        if (GetFskClock("", false)) {
            if (FSKrawDemod("", true) == PM3_SUCCESS) {
                PrintAndLogEx(NORMAL, "\nUnknown FSK Modulated Tag found!");
                goto out;
            }
        }

        bool st = true;
        if (ASKDemod_ext("0 0 0", true, false, 1, &st) == PM3_SUCCESS) {
            PrintAndLogEx(NORMAL, "\nUnknown ASK Modulated and Manchester encoded Tag found!");
            PrintAndLogEx(NORMAL, "if it does not look right it could instead be ASK/Biphase - try " _YELLOW_("'data rawdemod ab'"));
            goto out;
        }

        if (CmdPSK1rawDemod("") == PM3_SUCCESS) {
            PrintAndLogEx(NORMAL, "Possible unknown PSK1 Modulated Tag found above!");
            PrintAndLogEx(NORMAL, "    Could also be PSK2 - try " _YELLOW_("'data rawdemod p2'"));
            PrintAndLogEx(NORMAL, "    Could also be PSK3 - [currently not supported]");
            PrintAndLogEx(NORMAL, "    Could also be  NRZ - try " _YELLOW_("'data rawdemod nr"));
            goto out;
        }

        PrintAndLogEx(FAILED, _RED_("\nNo data found!"));
    }
out:
    // identify chipset
    CheckChipType(isOnline);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,            AlwaysAvailable, "This help"},
    {"awid",        CmdLFAWID,          AlwaysAvailable, "{ AWID RFIDs...              }"},
    {"cotag",       CmdLFCOTAG,         AlwaysAvailable, "{ COTAG CHIPs...             }"},
    {"em",          CmdLFEM4X,          AlwaysAvailable, "{ EM4X CHIPs & RFIDs...      }"},
    {"fdx",         CmdLFFdx,           AlwaysAvailable, "{ FDX-B RFIDs...             }"},
    {"gproxii",     CmdLFGuard,         AlwaysAvailable, "{ Guardall Prox II RFIDs...  }"},
    {"hid",         CmdLFHID,           AlwaysAvailable, "{ HID RFIDs...               }"},
    {"hitag",       CmdLFHitag,         AlwaysAvailable, "{ Hitag CHIPs...             }"},
    {"indala",      CmdLFINDALA,        AlwaysAvailable, "{ Indala RFIDs...            }"},
    {"io",          CmdLFIO,            AlwaysAvailable, "{ ioProx RFIDs...            }"},
    {"jablotron",   CmdLFJablotron,     AlwaysAvailable, "{ Jablotron RFIDs...         }"},
    {"keri",        CmdLFKeri,          AlwaysAvailable, "{ KERI RFIDs...              }"},
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
    {"config",      CmdLFSetConfig,     IfPm3Lf,         "Set config for LF sampling, bit/sample, decimation, frequency"},
    {"cmdread",     CmdLFCommandRead,   IfPm3Lf,         "<off period> <'0' period> <'1' period> <command> ['h' 134] \n\t\t-- Modulate LF reader field to send command before read (all periods in microseconds)"},
    {"flexdemod",   CmdFlexdemod,       AlwaysAvailable, "Demodulate samples for FlexPass"},
    {"read",        CmdLFRead,          IfPm3Lf,         "['s' silent] Read 125/134 kHz LF ID-only tag. Do 'lf read h' for help"},
    {"search",      CmdLFfind,          AlwaysAvailable, "[offline] ['u'] Read and Search for valid known tag (in offline mode it you can load first then search) \n\t\t-- 'u' to search for unknown tags"},
    {"sim",         CmdLFSim,           IfPm3Lf,         "[GAP] -- Simulate LF tag from buffer with optional GAP (in microseconds)"},
    {"simask",      CmdLFaskSim,        IfPm3Lf,         "[clock] [invert <1|0>] [biphase/manchester/raw <'b'|'m'|'r'>] [msg separator 's'] [d <hexdata>] \n\t\t-- Simulate LF ASK tag from demodbuffer or input"},
    {"simfsk",      CmdLFfskSim,        IfPm3Lf,         "[c <clock>] [i] [H <fcHigh>] [L <fcLow>] [d <hexdata>] \n\t\t-- Simulate LF FSK tag from demodbuffer or input"},
    {"simpsk",      CmdLFpskSim,        IfPm3Lf,         "[1|2|3] [c <clock>] [i] [r <carrier>] [d <raw hex to sim>] \n\t\t-- Simulate LF PSK tag from demodbuffer or input"},
    {"simbidir",    CmdLFSimBidir,      IfPm3Lf,         "Simulate LF tag (with bidirectional data transmission between reader and tag)"},
    {"sniff",       CmdLFSniff,         IfPm3Lf,         "Sniff LF traffic between reader and tag"},
    {"vchdemod",    CmdVchDemod,        AlwaysAvailable, "['clone'] -- Demodulate samples for VeriChip"},
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
