//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Indala commands
// PSK1, rf/32, 64 or 224 bits (known)
//-----------------------------------------------------------------------------

#include "cmdlfindala.h"

static int CmdHelp(const char *Cmd);

//large 224 bit indala formats (different preamble too...)
static uint8_t preamble224[] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

// standard 64 bit indala formats including 26 bit 40134 format
static uint8_t preamble64[] =  {1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

int usage_lf_indala_demod(void) {
    PrintAndLogEx(NORMAL, "Enables Indala compatible reader mode printing details of scanned tags.");
    PrintAndLogEx(NORMAL, "By default, values are printed and logged until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf indala demod [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h :  This help");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        lf indala demod");
    return 0;
}

int usage_lf_indala_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of Indala card with specified uid.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf indala sim [h] <uid>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "            h :  This help");
    PrintAndLogEx(NORMAL, "        <uid> :  64/224 UID");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf indala sim deadc0de");
    return 0;
}

int usage_lf_indala_clone(void) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf indala clone [h]<l> <uid> [Q5]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "            h :  This help");
    PrintAndLogEx(NORMAL, "            l :  long uid 64/224");
    PrintAndLogEx(NORMAL, "        <uid> :  UID");
    PrintAndLogEx(NORMAL, "           Q5 :  optional - clone to Q5 (T5555) instead of T55x7 chip");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf indala clone 112233      -- 64");
    PrintAndLogEx(NORMAL, "       lf indala clone l 112233    -- long 224");
    return 0;
}

// redesigned by marshmellow adjusted from existing decode functions
// indala id decoding
int detectIndala(uint8_t *dest, size_t *size, uint8_t *invert) {

    uint8_t preamble64_i[]  = {0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0};
    uint8_t preamble224_i[] = {0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0};

    size_t idx = 0;
    size_t found_size = *size;

    // PSK1
    bool res = preambleSearch(dest, preamble64, sizeof(preamble64), &found_size, &idx);
    if (res) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK1 found 64");
        goto out;
    }
    idx = 0;
    found_size = *size;
    res = preambleSearch(dest, preamble64_i, sizeof(preamble64_i), &found_size, &idx);
    if (res) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK1 found 64 inverted preamble");
        goto inv;
    }

    /*
    idx = 0;
    found_size = *size;
    res = preambleSearch(dest, preamble224, sizeof(preamble224), &found_size, &idx);
    if ( res ) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK1 found 224");
        goto out;
    }

    idx = 0;
    found_size = *size;
    res = preambleSearch(dest, preamble224_i, sizeof(preamble224_i), &found_size, &idx);
    if ( res ) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK1 found 224 inverted preamble");
        goto inv;
    }
    */

    // PSK2
    psk1TOpsk2(dest, *size);
    PrintAndLogEx(DEBUG, "DEBUG: detectindala Converting PSK1 -> PSK2");

    idx = 0;
    found_size = *size;
    res = preambleSearch(dest, preamble64, sizeof(preamble64), &found_size, &idx);
    if (res) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK2 found 64 preamble");
        goto out;
    }

    idx = 0;
    found_size = *size;
    res = preambleSearch(dest, preamble224, sizeof(preamble224), &found_size, &idx);
    if (res) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK2 found 224 preamble");
        goto out;
    }

    idx = 0;
    found_size = *size;
    res = preambleSearch(dest, preamble64_i, sizeof(preamble64_i), &found_size, &idx);
    if (res) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK2 found 64 inverted preamble");
        goto inv;
    }

    idx = 0;
    found_size = *size;
    res = preambleSearch(dest, preamble224_i, sizeof(preamble224_i), &found_size, &idx);
    if (res) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK2 found 224 inverted preamble");
        goto inv;
    }

inv:
    if (res == 0) {
        return -4;
    }

    *invert ^= 1;

    if (*invert && idx > 0) {
        for (size_t i = idx - 1; i < found_size + idx + 2; i++) {
            dest[i] ^= 1;
        }
    }

    PrintAndLogEx(DEBUG, "DEBUG: Warning - Indala had to invert bits");

out:

    *size = found_size;

    //PrintAndLogEx(INFO, "DEBUG: detectindala RES = %d | %d | %d", res, found_size, idx);

    if (found_size != 224 && found_size != 64) {
        PrintAndLogEx(INFO, "DEBUG: detectindala | %d", found_size);
        return -5;
    }

    // 224 formats are typically PSK2 (afaik 2017 Marshmellow)
    // note loses 1 bit at beginning of transformation...
    return (int) idx;

}

// this read is the "normal" read,  which download lf signal and tries to demod here.
int CmdIndalaRead(const char *Cmd) {
    lf_read(true, 30000);
    return CmdIndalaDemod(Cmd);
}

// Indala 26 bit decode
// by marshmellow
// optional arguments - same as PSKDemod (clock & invert & maxerr)
int CmdIndalaDemod(const char *Cmd) {
    int ans;
    if (strlen(Cmd) > 0)
        ans = PSKDemod(Cmd, true);
    else
        ans = PSKDemod("32", true);

    if (!ans) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Indala can't demod signal: %d", ans);
        return 0;
    }

    uint8_t invert = 0;
    size_t size = DemodBufferLen;
    int idx = detectIndala(DemodBuffer, &size, &invert);
    if (idx < 0) {
        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Indala: not enough samples");
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Indala: only noise found");
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Indala: preamble not found");
        else if (idx == -5)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Indala: size not correct: %d", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Indala: error demoding psk idx: %d", idx);
        return 0;
    }
    setDemodBuf(DemodBuffer, size, idx);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (idx * g_DemodClock));

    //convert UID to HEX
    uint32_t uid1, uid2, uid3, uid4, uid5, uid6, uid7;
    uid1 = bytebits_to_byte(DemodBuffer, 32);
    uid2 = bytebits_to_byte(DemodBuffer + 32, 32);
    uint64_t foo = (((uint64_t)uid1 << 32) & 0x1FFFFFFF) | (uid2 & 0x7FFFFFFF);

    if (DemodBufferLen == 64) {
        PrintAndLogEx(
            SUCCESS
            , "Indala Found - bitlength %d, Raw %x%08x"
            , DemodBufferLen
            , uid1
            , uid2
        );

        uint16_t p1  = 0;
        p1 |= DemodBuffer[32 + 3] << 8;
        p1 |= DemodBuffer[32 + 6] << 5;
        p1 |= DemodBuffer[32 + 8] << 4;
        p1 |= DemodBuffer[32 + 9] << 3;
        p1 |= DemodBuffer[32 + 11] << 1;
        p1 |= DemodBuffer[32 + 16] << 6;
        p1 |= DemodBuffer[32 + 19] << 7;
        p1 |= DemodBuffer[32 + 20] << 10;
        p1 |= DemodBuffer[32 + 21] << 2;
        p1 |= DemodBuffer[32 + 22] << 0;
        p1 |= DemodBuffer[32 + 24] << 9;

        /*
                uint16_t fc = 0;
                fc |= DemodBuffer[32+ 1] << 0;
                fc |= DemodBuffer[32+ 2] << 1;
                fc |= DemodBuffer[32+ 4] << 2;
                fc |= DemodBuffer[32+ 5] << 3;
                fc |= DemodBuffer[32+ 7] << 4;
                fc |= DemodBuffer[32+10] << 5;
                fc |= DemodBuffer[32+14] << 6;
                fc |= DemodBuffer[32+15] << 7;
                fc |= DemodBuffer[32+17] << 8;
        */

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, "Possible de-scramble patterns");
        PrintAndLogEx(SUCCESS, "\tPrinted     | __%04d__ [0x%X]", p1, p1);
        //PrintAndLogEx(SUCCESS, "\tPrinted     | __%04d__ [0x%X]", fc, fc);
        PrintAndLogEx(SUCCESS, "\tInternal ID | %" PRIu64, foo);


    } else {
        uid3 = bytebits_to_byte(DemodBuffer + 64, 32);
        uid4 = bytebits_to_byte(DemodBuffer + 96, 32);
        uid5 = bytebits_to_byte(DemodBuffer + 128, 32);
        uid6 = bytebits_to_byte(DemodBuffer + 160, 32);
        uid7 = bytebits_to_byte(DemodBuffer + 192, 32);
        PrintAndLogEx(SUCCESS, "Indala Found - bitlength %d, UID = 0x%x%08x%08x%08x%08x%08x%08x"
                      , DemodBufferLen
                      , uid1
                      , uid2
                      , uid3
                      , uid4
                      , uid5
                      , uid6
                      , uid7
                     );
    }

    if (g_debugMode) {
        PrintAndLogEx(DEBUG, "DEBUG: Indala - printing demodbuffer");
        printDemodBuff();
    }
    return 1;
}

// older alternative indala demodulate (has some positives and negatives)
// returns false positives more often - but runs against more sets of samples
// poor psk signal can be difficult to demod this approach might succeed when the other fails
// but the other appears to currently be more accurate than this approach most of the time.
int CmdIndalaDemodAlt(const char *Cmd) {
    // Usage: recover 64bit UID by default, specify "224" as arg to recover a 224bit UID
    int state = -1;
    int count = 0;
    int i, j;

    // worst case with GraphTraceLen=40000 is < 4096
    // under normal conditions it's < 2048
    uint8_t data[MAX_GRAPH_TRACE_LEN] = {0};
    size_t datasize = getFromGraphBuf(data);

    uint8_t rawbits[4096];
    int rawbit = 0;
    int worst = 0, worstPos = 0;

    //clear clock grid and demod plot
    setClockGrid(0, 0);
    DemodBufferLen = 0;

    // PrintAndLogEx(NORMAL, "Expecting a bit less than %d raw bits", GraphTraceLen / 32);
    // loop through raw signal - since we know it is psk1 rf/32 fc/2 skip every other value (+=2)
    for (i = 0; i < datasize - 1; i += 2) {
        count += 1;
        if ((data[i] > data[i + 1]) && (state != 1)) {
            // appears redundant - marshmellow
            if (state == 0) {
                for (j = 0; j <  count - 8; j += 16) {
                    rawbits[rawbit++] = 0;
                }
                if ((abs(count - j)) > worst) {
                    worst = abs(count - j);
                    worstPos = i;
                }
            }
            state = 1;
            count = 0;
        } else if ((data[i] < data[i + 1]) && (state != 0)) {
            //appears redundant
            if (state == 1) {
                for (j = 0; j <  count - 8; j += 16) {
                    rawbits[rawbit++] = 1;
                }
                if ((abs(count - j)) > worst) {
                    worst = abs(count - j);
                    worstPos = i;
                }
            }
            state = 0;
            count = 0;
        }
    }

    if (rawbit > 0) {
        PrintAndLogEx(INFO, "Recovered %d raw bits, expected: %d", rawbit, GraphTraceLen / 32);
        PrintAndLogEx(INFO, "worst metric (0=best..7=worst): %d at pos %d", worst, worstPos);
    } else {
        return 0;
    }

    // Finding the start of a UID
    int uidlen, long_wait;
    if (strcmp(Cmd, "224") == 0) {
        uidlen = 224;
        long_wait = 30;
    } else {
        uidlen = 64;
        long_wait = 29;
    }

    int start;
    int first = 0;
    for (start = 0; start <= rawbit - uidlen; start++) {
        first = rawbits[start];
        for (i = start; i < start + long_wait; i++) {
            if (rawbits[i] != first) {
                break;
            }
        }
        if (i == (start + long_wait)) {
            break;
        }
    }

    if (start == rawbit - uidlen + 1) {
        PrintAndLogEx(FAILED, "nothing to wait for");
        return 0;
    }

    // Inverting signal if needed
    if (first == 1) {
        for (i = start; i < rawbit; i++) {
            rawbits[i] = !rawbits[i];
        }
    }

    // Dumping UID
    uint8_t bits[224] = {0x00};
    char showbits[225] = {0x00};
    int bit;
    i = start;
    int times = 0;

    if (uidlen > rawbit) {
        PrintAndLogEx(WARNING, "Warning: not enough raw bits to get a full UID");
        for (bit = 0; bit < rawbit; bit++) {
            bits[bit] = rawbits[i++];
            // As we cannot know the parity, let's use "." and "/"
            showbits[bit] = '.' + bits[bit];
        }
        showbits[bit + 1] = '\0';
        PrintAndLogEx(SUCCESS, "Partial UID | %s", showbits);
        return 0;
    } else {
        for (bit = 0; bit < uidlen; bit++) {
            bits[bit] = rawbits[i++];
            showbits[bit] = '0' + bits[bit];
        }
        times = 1;
    }

    //convert UID to HEX
    uint32_t uid1, uid2, uid3, uid4, uid5, uid6, uid7;
    int idx;
    uid1 = uid2 = 0;

    if (uidlen == 64) {
        for (idx = 0; idx < 64; idx++) {
            if (showbits[idx] == '0') {
                uid1 = (uid1 << 1) | (uid2 >> 31);
                uid2 = (uid2 << 1) | 0;
            } else {
                uid1 = (uid1 << 1) | (uid2 >> 31);
                uid2 = (uid2 << 1) | 1;
            }
        }
        PrintAndLogEx(SUCCESS, "UID | %s (%x%08x)", showbits, uid1, uid2);
    } else {
        uid3 = uid4 = uid5 = uid6 = uid7 = 0;

        for (idx = 0; idx < 224; idx++) {
            uid1 = (uid1 << 1) | (uid2 >> 31);
            uid2 = (uid2 << 1) | (uid3 >> 31);
            uid3 = (uid3 << 1) | (uid4 >> 31);
            uid4 = (uid4 << 1) | (uid5 >> 31);
            uid5 = (uid5 << 1) | (uid6 >> 31);
            uid6 = (uid6 << 1) | (uid7 >> 31);

            if (showbits[idx] == '0')
                uid7 = (uid7 << 1) | 0;
            else
                uid7 = (uid7 << 1) | 1;
        }
        PrintAndLogEx(SUCCESS, "UID | %s (%x%08x%08x%08x%08x%08x%08x)", showbits, uid1, uid2, uid3, uid4, uid5, uid6, uid7);
    }

    // Checking UID against next occurrences
    int failed = 0;
    for (; i + uidlen <= rawbit;) {
        failed = 0;
        for (bit = 0; bit < uidlen; bit++) {
            if (bits[bit] != rawbits[i++]) {
                failed = 1;
                break;
            }
        }
        if (failed == 1) {
            break;
        }
        times += 1;
    }

    PrintAndLogEx(DEBUG, "Occurrences: %d (expected %d)", times, (rawbit - start) / uidlen);

    // Remodulating for tag cloning
    // HACK: 2015-01-04 this will have an impact on our new way of seening lf commands (demod)
    // since this changes graphbuffer data.
    GraphTraceLen = 32 * uidlen;
    i = 0;
    int phase = 0;
    for (bit = 0; bit < uidlen; bit++) {
        if (bits[bit] == 0) {
            phase = 0;
        } else {
            phase = 1;
        }
        int j;
        for (j = 0; j < 32; j++) {
            GraphBuffer[i++] = phase;
            phase = !phase;
        }
    }

    RepaintGraphWindow();
    return 1;
}

int CmdIndalaSim(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_indala_sim();

    uint8_t bits[224];
    size_t size = sizeof(bits);
    memset(bits, 0x00, size);

    // uid
    uint8_t hexuid[100];
    int len = 0;
    param_gethex_ex(Cmd, 0, hexuid, &len);
    if (len > 28)
        return usage_lf_indala_sim();

    // convert to binarray
    uint8_t counter = 223;
    for (uint8_t i = 0; i < len; i++) {
        for (uint8_t j = 0; j < 8; j++) {
            bits[counter--] = hexuid[i] & 1;
            hexuid[i] >>= 1;
        }
    }

    // indala PSK
    uint8_t clk = 32, carrier = 2, invert = 0;
    uint16_t arg1, arg2;
    arg1 = clk << 8 | carrier;
    arg2 = invert;

    // It has to send either 64bits (8bytes) or 224bits (28bytes).  Zero padding needed if not.
    // lf simpsk 1 c 32 r 2 d 0102030405060708

    PrintAndLogEx(SUCCESS, "Simulating Indala UID: %s",  sprint_hex(hexuid, len));
    PrintAndLogEx(SUCCESS, "Press pm3-button to abort simulation or run another command");

    UsbCommand c = {CMD_PSK_SIM_TAG, {arg1, arg2, size}};
    memcpy(c.d.asBytes, bits, size);
    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

// iceman - needs refactoring
int CmdIndalaClone(const char *Cmd) {

    bool isLongUid = false;
    uint8_t data[7 * 4];
    int datalen = 0;

    CLIParserInit("lf indala clone",
                  "Enables cloning of Indala card with specified uid onto T55x7\n"
                  "defaults to 64.\n",
                  "\n"
                  "Samples:\n"
                  "\tlf indala clone a0000000a0002021\n"
                  "\tlf indala clone -l 80000001b23523a6c2e31eba3cbee4afb3c6ad1fcf649393928c14e5");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("lL",  "long",  "long UID 224 bits"),
        arg_strx1(NULL, NULL,    "<uid (hex)>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    isLongUid = arg_get_lit(1);
    CLIGetHexWithReturn(2, data, &datalen);
    CLIParserFree();

    UsbCommand c = {0, {0, 0, 0}};

    if (isLongUid) {
        PrintAndLogEx(INFO, "Preparing to clone Indala 224bit tag with UID %s", sprint_hex(data, datalen));
        c.cmd = CMD_INDALA_CLONE_TAG_L;
        c.d.asDwords[0] = bytes_to_num(data, 4);
        c.d.asDwords[1] = bytes_to_num(data +  4, 4);
        c.d.asDwords[2] = bytes_to_num(data +  8, 4);
        c.d.asDwords[3] = bytes_to_num(data + 12, 4);
        c.d.asDwords[4] = bytes_to_num(data + 16, 4);
        c.d.asDwords[5] = bytes_to_num(data + 20, 4);
        c.d.asDwords[6] = bytes_to_num(data + 24, 4);
    } else {
        PrintAndLogEx(INFO, "Preparing to clone Indala 64bit tag with UID %s", sprint_hex(data, datalen));
        c.cmd = CMD_INDALA_CLONE_TAG;
        c.d.asDwords[0] = bytes_to_num(data, 4);
        c.d.asDwords[1] = bytes_to_num(data + 4, 4);
    }

    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,            1, "this help"},
    {"demod",    CmdIndalaDemod,     1, "demodulate an indala tag (PSK1) from GraphBuffer"},
    {"altdemod", CmdIndalaDemodAlt,  1, "alternative method to Demodulate samples for Indala 64 bit UID (option '224' for 224 bit)"},
    {"read",     CmdIndalaRead,      0, "read an Indala Prox tag from the antenna"},
    {"clone",    CmdIndalaClone,     0, "clone Indala to T55x7"},
    {"sim",      CmdIndalaSim,       0, "simulate Indala tag"},
    {NULL, NULL, 0, NULL}
};

int CmdLFINDALA(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
