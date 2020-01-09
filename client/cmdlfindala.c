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

#include <stdlib.h>
#include <string.h>

#include <ctype.h>
#include <inttypes.h>

#include "cmdparser.h"    // command_t
#include "comms.h"
#include "graph.h"
#include "cliparser/cliparser.h"
#include "commonutil.h"
#include "ui.h"         // PrintAndLog
#include "lfdemod.h"    // parityTest, bitbytes_to_byte
#include "cmddata.h"
#include "cmdlf.h"      // lf_read
#include "protocols.h"  // t55 defines
#include "cmdlft55xx.h" // verifywrite

static int CmdHelp(const char *Cmd);

//large 224 bit indala formats (different preamble too...)
static uint8_t preamble224[] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

// standard 64 bit indala formats including 26 bit 40134 format
static uint8_t preamble64[] =  {1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

static int usage_lf_indala_demod(void) {
    PrintAndLogEx(NORMAL, "Tries to psk demodulate the graphbuffer as Indala ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf indala demod [h] <clock> <0|1> <maxerror>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h        :  This help");
    PrintAndLogEx(NORMAL, "      clock    :  Set clock (as integer) optional, if not set, autodetect.");
    PrintAndLogEx(NORMAL, "      invert   :  1 for invert output");
    PrintAndLogEx(NORMAL, "      maxerror :  Set maximum allowed errors, default = 100.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        lf indala demod");
    PrintAndLogEx(NORMAL, "        lf indala demod 32       = demod a Indala tag from GraphBuffer using a clock of RF/32");
    PrintAndLogEx(NORMAL, "        lf indala demod 32 1     = demod a Indala tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLogEx(NORMAL, "        lf indala demod 64 1 0   = demod a Indala tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
    return PM3_SUCCESS;
}

static int usage_lf_indala_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of Indala card with specified uid.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf indala sim [h] <u uid> <c cardnum>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "        h           :  This help");
    PrintAndLogEx(NORMAL, "        u <uid>     :  64/224 UID");
    PrintAndLogEx(NORMAL, "        c <cardnum> :  Cardnumber for Heden 2L format (decimal)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf indala sim deadc0de");
    return PM3_SUCCESS;
}

#define HEDEN2L_OFFSET 31
static void encodeHeden2L(uint8_t *dest, uint32_t cardnumber) {

    uint8_t template[] = {
       1,0,1,0,0,0,0,0,
       0,0,0,0,0,0,0,0,
       0,0,0,0,0,0,0,0,
       0,0,0,0,0,0,0,0,
       1,0,0,0,1,0,0,0,
       1,0,0,0,0,0,0,0,
       0,0,0,0,1,0,0,1,
       0,0,0,0,0,0,1,0
    };
    uint8_t cardbits[32];

    num_to_bytebits(cardnumber, sizeof(cardbits), cardbits);
    
    if (cardbits[31] == 1) template[HEDEN2L_OFFSET + 8] = 0x1;
    if (cardbits[30] == 1) template[HEDEN2L_OFFSET + 10] = 0x1;
    if (cardbits[29] == 1) template[HEDEN2L_OFFSET + 14] = 0x1;
    if (cardbits[28] == 1) template[HEDEN2L_OFFSET + 15] = 0x1;
    if (cardbits[27] == 1) template[HEDEN2L_OFFSET + 12] = 0x1;
    if (cardbits[26] == 1) template[HEDEN2L_OFFSET + 28] = 0x1;
    if (cardbits[25] == 1) template[HEDEN2L_OFFSET + 3] = 0x1;
    if (cardbits[24] == 1) template[HEDEN2L_OFFSET + 11] = 0x1;
    if (cardbits[23] == 1) template[HEDEN2L_OFFSET + 19] = 0x1;
    if (cardbits[22] == 1) template[HEDEN2L_OFFSET + 26] = 0x1;
    if (cardbits[21] == 1) template[HEDEN2L_OFFSET + 17] = 0x1;
    if (cardbits[20] == 1) template[HEDEN2L_OFFSET + 18] = 0x1;
    if (cardbits[19] == 1) template[HEDEN2L_OFFSET + 20] = 0x1;
    if (cardbits[18] == 1) template[HEDEN2L_OFFSET + 13] = 0x1;
    if (cardbits[17] == 1) template[HEDEN2L_OFFSET + 7] = 0x1;
    if (cardbits[16] == 1) template[HEDEN2L_OFFSET + 23] = 0x1;

    // Parity
    uint8_t counter = 0;
    for (int i=0; i< sizeof(template) - HEDEN2L_OFFSET; i++) {
       if (template[i]) 
           counter++;
    }   
    template[63] = (counter & 0x1);
   
    for (int i = 0; i< sizeof(template); i += 8) {
        dest[i/8] = bytebits_to_byte(template + i, 8);
    }

    PrintAndLogEx(INFO, "Heden-2L card number %u", cardnumber);
}

static void decodeHeden2L(uint8_t *bits) {

    uint32_t cardnumber = 0;
    uint8_t offset = HEDEN2L_OFFSET;

    if ( bits[offset +  8] ) cardnumber += 1;
    if ( bits[offset + 10] ) cardnumber += 2;
    if ( bits[offset + 14] ) cardnumber += 4;
    if ( bits[offset + 15] ) cardnumber += 8;
    if ( bits[offset + 12] ) cardnumber += 16;
    if ( bits[offset + 28] ) cardnumber += 32;
    if ( bits[offset +  3] ) cardnumber += 64;
    if ( bits[offset + 11] ) cardnumber += 128;
    if ( bits[offset + 19] ) cardnumber += 256;
    if ( bits[offset + 26] ) cardnumber += 512;
    if ( bits[offset + 17] ) cardnumber += 1024;
    if ( bits[offset + 18] ) cardnumber += 2048;
    if ( bits[offset + 20] ) cardnumber += 4096;
    if ( bits[offset + 13] ) cardnumber += 8192;
    if ( bits[offset +  7] ) cardnumber += 16384;
    if ( bits[offset + 23] ) cardnumber += 32768;

    PrintAndLogEx(SUCCESS, "\tHeden-2L    | %u", cardnumber);
}

// Indala 26 bit decode
// by marshmellow, martinbeier
// optional arguments - same as PSKDemod (clock & invert & maxerr)
static int CmdIndalaDemod(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_lf_indala_demod();

    int ans;
    if (strlen(Cmd) > 0)
        ans = PSKDemod(Cmd, true);
    else
        ans = PSKDemod("32", true);

    if (ans != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Indala can't demod signal: %d", ans);
        return PM3_ESOFT;
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
            PrintAndLogEx(DEBUG, "DEBUG: Error - Indala: size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Indala: error demoding psk idx: %d", idx);
        return PM3_ESOFT;
    }
    setDemodBuff(DemodBuffer, size, idx);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (idx * g_DemodClock));

    //convert UID to HEX
    uint32_t uid1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t uid2 = bytebits_to_byte(DemodBuffer + 32, 32);
    // To be checked, what's this internal ID ?
    // foo is only used for 64b ids and in that case uid1 must be only preamble, plus the following code is wrong as x<<32 & 0x1FFFFFFF is always zero
    //uint64_t foo = (((uint64_t)uid1 << 32) & 0x1FFFFFFF) | (uid2 & 0x7FFFFFFF);
    uint64_t foo = uid2 & 0x7FFFFFFF;

    if (DemodBufferLen == 64) {
        PrintAndLogEx(
            SUCCESS
            , "Indala Found - bitlength %zu, Raw %x%08x"
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

        uint8_t fc = 0;
        fc |= DemodBuffer[57] << 7; // b8
        fc |= DemodBuffer[49] << 6; // b7
        fc |= DemodBuffer[44] << 5; // b6
        fc |= DemodBuffer[47] << 4; // b5
        fc |= DemodBuffer[48] << 3; // b4
        fc |= DemodBuffer[53] << 2; // b3
        fc |= DemodBuffer[39] << 1; // b2
        fc |= DemodBuffer[58] << 0; // b1

        uint16_t csn = 0;
        csn |= DemodBuffer[42] << 15; // b16
        csn |= DemodBuffer[45] << 14; // b15
        csn |= DemodBuffer[43] << 13; // b14
        csn |= DemodBuffer[40] << 12; // b13
        csn |= DemodBuffer[52] << 11; // b12
        csn |= DemodBuffer[36] << 10; // b11
        csn |= DemodBuffer[35] << 9; // b10
        csn |= DemodBuffer[51] << 8; // b9
        csn |= DemodBuffer[46] << 7; // b8
        csn |= DemodBuffer[33] << 6; // b7
        csn |= DemodBuffer[37] << 5; // b6
        csn |= DemodBuffer[54] << 4; // b5
        csn |= DemodBuffer[56] << 3; // b4
        csn |= DemodBuffer[59] << 2; // b3
        csn |= DemodBuffer[50] << 1; // b2
        csn |= DemodBuffer[41] << 0; // b1

        uint8_t checksum = 0;
        checksum |= DemodBuffer[62] << 1; // b2
        checksum |= DemodBuffer[63] << 0; // b1

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, "Possible de-scramble patterns");
        PrintAndLogEx(SUCCESS, "\tPrinted     | __%04d__ [0x%X]", p1, p1);
        PrintAndLogEx(SUCCESS, "\tInternal ID | %" PRIu64, foo);
        decodeHeden2L(DemodBuffer);

        PrintAndLogEx(SUCCESS, "Fmt 26 bit  FC %u , CSN %u , checksum %1d%1d", fc, csn, checksum >> 1 & 0x01, checksum & 0x01);


    } else {
        uint32_t uid3 = bytebits_to_byte(DemodBuffer + 64, 32);
        uint32_t uid4 = bytebits_to_byte(DemodBuffer + 96, 32);
        uint32_t uid5 = bytebits_to_byte(DemodBuffer + 128, 32);
        uint32_t uid6 = bytebits_to_byte(DemodBuffer + 160, 32);
        uint32_t uid7 = bytebits_to_byte(DemodBuffer + 192, 32);
        PrintAndLogEx(
            SUCCESS
            , "Indala Found - bitlength %zu, Raw 0x%x%08x%08x%08x%08x%08x%08x"
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
    return PM3_SUCCESS;
}

// older alternative indala demodulate (has some positives and negatives)
// returns false positives more often - but runs against more sets of samples
// poor psk signal can be difficult to demod this approach might succeed when the other fails
// but the other appears to currently be more accurate than this approach most of the time.
static int CmdIndalaDemodAlt(const char *Cmd) {
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
        PrintAndLogEx(INFO, "Recovered %d raw bits, expected: %zu", rawbit, GraphTraceLen / 32);
        PrintAndLogEx(INFO, "worst metric (0=best..7=worst): %d at pos %d", worst, worstPos);
    } else {
        return PM3_ESOFT;
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
        return PM3_ESOFT;
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
        return PM3_SUCCESS;
    } else {
        for (bit = 0; bit < uidlen; bit++) {
            bits[bit] = rawbits[i++];
            showbits[bit] = '0' + bits[bit];
        }
        times = 1;
    }

    //convert UID to HEX
    int idx;
    uint32_t uid1 = 0;
    uint32_t uid2 = 0;

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
        uint32_t uid3 = 0;
        uint32_t uid4 = 0;
        uint32_t uid5 = 0;
        uint32_t uid6 = 0;
        uint32_t uid7 = 0;

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
    for (; i + uidlen <= rawbit;) {
        int failed = 0;
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
    int phase;
    for (bit = 0; bit < uidlen; bit++) {
        if (bits[bit] == 0) {
            phase = 0;
        } else {
            phase = 1;
        }
        for (j = 0; j < 32; j++) {
            GraphBuffer[i++] = phase;
            phase = !phase;
        }
    }

    RepaintGraphWindow();
    return PM3_SUCCESS;
}

// this read is the "normal" read,  which download lf signal and tries to demod here.
static int CmdIndalaRead(const char *Cmd) {
    lf_read(false, 30000);
    return CmdIndalaDemod(Cmd);
}

static int CmdIndalaSim(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_indala_sim();

    uint8_t bs[224];
    memset(bs, 0x00, sizeof(bs));

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
            bs[counter--] = hexuid[i] & 1;
            hexuid[i] >>= 1;
        }
    }

    // indala PSK
    // It has to send either 64bits (8bytes) or 224bits (28bytes).  Zero padding needed if not.
    // lf simpsk 1 c 32 r 2 d 0102030405060708

    PrintAndLogEx(SUCCESS, "Simulating Indala UID: %s",  sprint_hex(hexuid, len));
    PrintAndLogEx(SUCCESS, "Press pm3-button to abort simulation or run another command");

    // indala PSK,  clock 32, carrier 0
    lf_psksim_t *payload = calloc(1, sizeof(lf_psksim_t) + sizeof(bs));
    payload->carrier =  2;
    payload->invert = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    PrintAndLogEx(INFO, "Simulating");

    clearCommandBuffer();
    SendCommandNG(CMD_LF_PSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_psksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_PSK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

static int CmdIndalaClone(const char *Cmd) {

    bool is_long_uid = false, got_cn = false;
    bool is_t5555 = false;
    int32_t cardnumber;
    uint32_t blocks[8] = {0};
    uint8_t max = 0;
    uint8_t data[7 * 4];
    int datalen = 0;

    CLIParserInit("lf indala clone",
                  "clone INDALA tag to T55x7 (or to q5/T5555)",
                  "Examples:\n"
                  "\tlf indala clone -c 888\n"
                  "\tlf indala clone -r a0000000a0002021\n"
                  "\tlf indala clone -l -r 80000001b23523a6c2e31eba3cbee4afb3c6ad1fcf649393928c14e5");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("lL", "long", "optional - long UID 224 bits"),
        arg_int0("cC", "cn",   "<decimal>", "Cardnumber for Heden 2L format"),
        arg_strx0("rR", "raw", "<hex>", "raw bytes"),
        arg_lit0("qQ", "Q5",   "optional - specify write to Q5 (t5555 instead of t55x7)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    is_long_uid = arg_get_lit(1);
    if (is_long_uid == false) {
        cardnumber = arg_get_int_def(2, -1);
        got_cn = (cardnumber != -1);
    }

    if (got_cn == false) {
        CLIGetHexWithReturn(3, data, &datalen);
    }
    
    is_t5555 = arg_get_lit(4);

    CLIParserFree();

    if (is_long_uid) {
        // 224 BIT UID
        // config for Indala (RF/32;PSK2 with RF/2;Maxblock=7)
        PrintAndLogEx(INFO, "Preparing to clone Indala 224bit tag with RawID %s", sprint_hex(data, datalen));
        
        if (is_t5555)
            blocks[0] = T5555_SET_BITRATE(32) | T5555_MODULATION_PSK2 | (7 << T5555_MAXBLOCK_SHIFT);
        else
            blocks[0] = T55x7_BITRATE_RF_32 | T55x7_MODULATION_PSK2 | (7 << T55x7_MAXBLOCK_SHIFT);
        
        blocks[1] = bytes_to_num(data, 4);
        blocks[2] = bytes_to_num(data +  4, 4);
        blocks[3] = bytes_to_num(data +  8, 4);
        blocks[4] = bytes_to_num(data + 12, 4);
        blocks[5] = bytes_to_num(data + 16, 4);
        blocks[6] = bytes_to_num(data + 20, 4);
        blocks[7] = bytes_to_num(data + 24, 4);
        max = 8;
    } else {
        // 64 BIT UID
        if (got_cn) {
            encodeHeden2L(data, cardnumber);
            datalen = 8;
        }

        // config for Indala 64 format (RF/32;PSK1 with RF/2;Maxblock=2)
        PrintAndLogEx(INFO, "Preparing to clone Indala 64bit tag with RawID %s", sprint_hex(data, datalen));
        
        if (is_t5555)
            blocks[0] = T5555_SET_BITRATE(32) | T5555_MODULATION_PSK1 | (2 << T5555_MAXBLOCK_SHIFT);
        else
            blocks[0] = T55x7_BITRATE_RF_32 | T55x7_MODULATION_PSK1 | (2 << T55x7_MAXBLOCK_SHIFT);
        
        blocks[1] = bytes_to_num(data, 4);
        blocks[2] = bytes_to_num(data + 4, 4);
        max = 3;
    }

    print_blocks(blocks, max);
    return clone_t55xx_tag(blocks, max);
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,            AlwaysAvailable, "this help"},
    {"demod",    CmdIndalaDemod,     AlwaysAvailable, "demodulate an indala tag (PSK1) from GraphBuffer"},
    {"altdemod", CmdIndalaDemodAlt,  AlwaysAvailable, "alternative method to Demodulate samples for Indala 64 bit UID (option '224' for 224 bit)"},
    {"read",     CmdIndalaRead,      IfPm3Lf,         "read an Indala Prox tag from the antenna"},
    {"clone",    CmdIndalaClone,     IfPm3Lf,         "clone Indala tag to T55x7"},
    {"sim",      CmdIndalaSim,       IfPm3Lf,         "simulate Indala tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFINDALA(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
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

    if (found_size != 224 && found_size != 64) {
        PrintAndLogEx(INFO, "DEBUG: detectindala | %zu", found_size);
        return -5;
    }

    // 224 formats are typically PSK2 (afaik 2017 Marshmellow)
    // note loses 1 bit at beginning of transformation...
    return (int) idx;

}

int demodIndala(void) {
    return CmdIndalaDemod("");
}
