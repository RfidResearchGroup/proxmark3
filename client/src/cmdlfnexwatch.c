//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Honeywell NexWatch tag commands
// PSK1 RF/16, RF/2, 128 bits long (known)
//-----------------------------------------------------------------------------

#include "cmdlfnexwatch.h"
#include <inttypes.h>      // PRIu
#include <string.h>
#include <ctype.h>         // tolower
#include <stdlib.h>        // free, alloc
#include "commonutil.h"    // ARRAYLEN
#include "cmdparser.h"     // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"       // preamblesearch
#include "cmdlf.h"
#include "lfdemod.h"
#include "protocols.h"     // t55xx defines
#include "cmdlft55xx.h"    // clone..
#include "cmdlfem4x05.h"   //
#include "cliparser.h"
#include <math.h>


typedef enum {
    SCRAMBLE,
    DESCRAMBLE
} NexWatchScramble_t;

typedef unsigned char BYTE;

static int CmdHelp(const char *Cmd);

// scramble parity (1234) -> (4231)
static uint8_t nexwatch_parity_swap(uint8_t parity) {
    uint8_t a = (((parity >> 3) & 1));
    a |= (((parity >> 1) & 1) << 1);
    a |= (((parity >> 2) & 1) << 2);
    a |= ((parity & 1) << 3);
    return a;
}
// parity check
// from 32b hex id, 4b mode,
static uint8_t nexwatch_parity(uint8_t hexid[5]) {
    uint8_t p = 0;
    for (uint8_t i = 0; i < 5; i++) {
        p ^= NIBBLE_HIGH(hexid[i]);
        p ^= NIBBLE_LOW(hexid[i]);
    }
    return nexwatch_parity_swap(p);
}

/// NETWATCH checksum
/// @param magic =  0xBE  Quadrakey,  0x88 Nexkey, 0x86 EC
/// @param id = descrambled id (printed card number)
/// @param parity =  the parity based upon the scrambled raw id.
static uint8_t nexwatch_checksum(uint8_t magic, uint32_t id, uint8_t parity) {
    uint8_t a = ((id >> 24) & 0xFF);
    a -= ((id >> 16) & 0xFF);
    a -= ((id >> 8) & 0xFF);
    a -= (id & 0xFF);
    a -= magic;
    a -= (reflect8(parity) >> 4);
    return reflect8(a);
}

// Scrambled id ( 88 bit cardnumber format)
// ref::  http://www.proxmark.org/forum/viewtopic.php?pid=14662#p14662
static int nexwatch_scamble(NexWatchScramble_t action, uint32_t *id, uint32_t *scambled) {

    // 255 = Not used/Unknown other values are the bit offset in the ID/FC values
    uint8_t hex_2_id [] = {
        31, 27, 23, 19, 15, 11, 7, 3,
        30, 26, 22, 18, 14, 10, 6, 2,
        29, 25, 21, 17, 13, 9, 5, 1,
        28, 24, 20, 16, 12, 8, 4, 0
    };

    switch (action) {
        case DESCRAMBLE: {
            *id = 0;
            for (uint8_t idx = 0; idx < 32; idx++) {

                if (hex_2_id[idx] == 255)
                    continue;

                bool bit_state = (*scambled >> hex_2_id[idx]) & 1;
                *id |= (bit_state << (31 - idx));
            }
            break;
        }
        case SCRAMBLE: {
            *scambled = 0;
            for (uint8_t idx = 0; idx < 32; idx++) {

                if (hex_2_id[idx] == 255)
                    continue;

                bool bit_state = (*id >> idx) & 1;
                *scambled |= (bit_state << (31 - hex_2_id[idx]));
            }
            break;
        }
        default:
            break;
    }
    return PM3_SUCCESS;
}

static int nexwatch_magic_bruteforce(uint32_t cn, uint8_t calc_parity, uint8_t chk) {
    uint8_t magic = 0;
    uint8_t temp_checksum;
    for (; magic < 255; magic++) {
        temp_checksum = nexwatch_checksum(magic, cn, calc_parity);
        if (temp_checksum == chk) {
            PrintAndLogEx(SUCCESS, "    Magic number : " _GREEN_("0x%X"),  magic);
            return PM3_SUCCESS;
        }
    }
    PrintAndLogEx(DEBUG, "DEBUG: Error - Magic number not found");
    return PM3_ESOFT;
}


int demodNexWatch(bool verbose) {
    (void) verbose; // unused so far
    if (PSKDemod(0, 0, 100, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch can't demod signal");
        return PM3_ESOFT;
    }
    bool invert = false;
    size_t size = DemodBufferLen;
    int idx = detectNexWatch(DemodBuffer, &size, &invert);
    if (idx < 0) {
        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch not enough samples");
        // else if (idx == -2)
        // PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch only noise found");
        // else if (idx == -3)
        // PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch problem during PSK demod");
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch preamble not found");
        // else if (idx == -5)
        // PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch size not correct: %d", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch error %d", idx);

        return PM3_ESOFT;
    }

    // skip the 4 first bits from the nexwatch preamble identification (we use 4 extra zeros..)
    idx += 4;

    setDemodBuff(DemodBuffer, size, idx);
    PrintAndLogEx(SUCCESS, "Indice: %x %s", DemodBuffer, DemodBuffer);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (idx * g_DemodClock));

    if (invert) {
        PrintAndLogEx(INFO, "Inverted the demodulated data");
        for (size_t i = 0; i < size; i++)
            DemodBuffer[i] ^= 1;
    }

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(DemodBuffer + 32 + 32, 32);

    // get rawid
    uint32_t rawid = 0;
    for (uint8_t k = 0; k < 4; k++) {
        for (uint8_t m = 0; m < 8; m++) {
            rawid = (rawid << 1) | DemodBuffer[m + k + (m * 4)];
        }
    }

    // descrambled id
    uint32_t cn = 0;
    uint32_t scambled = bytebits_to_byte(DemodBuffer + 8 + 32, 32);
    nexwatch_scamble(DESCRAMBLE, &cn, &scambled);

    uint8_t mode = bytebits_to_byte(DemodBuffer + 72, 4);
    uint8_t parity = bytebits_to_byte(DemodBuffer + 76, 4);
    uint8_t chk = bytebits_to_byte(DemodBuffer + 80, 8);

    // parity check
    // from 32b hex id, 4b mode
    uint8_t hex[5] = {0};
    for (uint8_t i = 0; i < 5; i++) {
        hex[i] = bytebits_to_byte(DemodBuffer + 8 + 32 + (i * 8), 8);
    }
    // mode is only 4 bits.
    hex[4] &= 0xf0;
    uint8_t calc_parity = nexwatch_parity(hex);

    // Checksum
    typedef struct {
        uint8_t magic;
        char desc[13];
        uint8_t chk;
    } nexwatch_magic_t;
    nexwatch_magic_t items[] = {
        {0xBE, "Quadrakey", 0},
        {0x88, "Nexkey", 0},
        {0x86, "Honeywell", 0}
    };

    uint8_t m_idx;
    for (m_idx = 0; m_idx < ARRAYLEN(items); m_idx++) {

        items[m_idx].chk = nexwatch_checksum(items[m_idx].magic, cn, calc_parity);
        if (items[m_idx].chk == chk) {
            break;
        }
    }

    // output
    PrintAndLogEx(SUCCESS, " NexWatch raw id : " _YELLOW_("0x%08"PRIx32), rawid);

    if (m_idx < ARRAYLEN(items)) {
        PrintAndLogEx(SUCCESS, "     fingerprint : " _GREEN_("%s"),  items[m_idx].desc);
    } else {
        nexwatch_magic_bruteforce(cn, calc_parity, chk);
    }
    PrintAndLogEx(SUCCESS, "            mode : %x", mode);
    PrintAndLogEx(SUCCESS, "        88bit id : " _YELLOW_("%"PRIu32) " ("  _YELLOW_("0x%08"PRIx32)")", cn, cn);
    PrintAndLogEx(SUCCESS, "        Scambled : " _YELLOW_("%"PRIu32) " ("  _YELLOW_("0x%08"PRIx32)")", scambled, scambled);


    if (parity == calc_parity) {
        PrintAndLogEx(DEBUG, "          parity : %s (0x%X)", _GREEN_("ok"), parity);
    } else {
        PrintAndLogEx(DEBUG, "          parity : %s (0x%X != 0x%X)", _RED_("fail"), parity, calc_parity);
    }

    PrintAndLogEx(DEBUG, "        checksum : %s (0x%02X)", (m_idx < ARRAYLEN(items)) ? _GREEN_("ok") : _RED_("fail"), chk);

    PrintAndLogEx(INFO, " Raw : " _YELLOW_("%08"PRIX32"%08"PRIX32"%08"PRIX32), raw1, raw2, raw3);
    return PM3_SUCCESS;
}

static int CmdNexWatchDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf nexwatch demod",
                  "Try to find Nexwatch preamble, if found decode / descramble data",
                  "lf nexwatch demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodNexWatch(true);
}

static int CmdNexWatchReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf nexwatch reader",
                  "read a Nexwatch tag",
                  "lf nexwatch reader -@   -> continuous reader mode"
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
        lf_read(true, 20000);
        demodNexWatch(!cm);
    } while (cm && !kbd_enter_pressed());
    return PM3_SUCCESS;
}
//TOCHANGE

static unsigned int bin2int(unsigned char *b, int size) {
    unsigned int val = 0;
    for (int i = 0; i < size; i++) {
        if (b[i] == '1') {
            val += pow(2, size - 1 - i);
        }
    }
    return val;
}
static BYTE xor_parity(BYTE *stream_, int bit_number) {
    BYTE parity_res = '0';
    for (int i = bit_number - 1; i < 36; i += 4) {
        if (stream_[i] == parity_res) {
            parity_res = '0';
        } else {
            parity_res = '1';
        }
    }
    return parity_res;
}

static BYTE *parity(BYTE *stream_) {
    BYTE *parity_res = malloc(4 * sizeof(BYTE));
    parity_res[0] = xor_parity(stream_, 4);
    parity_res[1] = xor_parity(stream_, 2);
    parity_res[2] = xor_parity(stream_, 3);
    parity_res[3] = xor_parity(stream_, 1);
    return parity_res;
}

static BYTE *convertUint8toByte(uint8_t number) {
    BYTE *res = malloc(8 * sizeof(char));
    uint8_t temp = number;
    for (int i = 1; i < 9; i++) {
        if (temp % 2) {
            res[8 - i] = '1';
        } else {
            res[8 - i] = '0';
        }
        temp = temp / 2;
    }
    return res;
}

static BYTE *convertUint32toByte(uint32_t number) {
    BYTE *res = malloc(32 * sizeof(char));
    uint32_t temp = number;
    for (int i = 0; i < 32; i++) {
        res[i] = '0';
    }
    for (int i = 1; i < 33; i++) {
        if (temp % 2) {
            res[32 - i] = '1';
        } else {
            res[32 - i] = '0';
        }
        temp = temp / 2;
    }
    return res;
}


static void TOpsk2(BYTE *bits, size_t size) {
    BYTE lastbit = '0';
    for (size_t i = 1; i < size; i++) {
        //ignore errors
        if (bits[i] == 7) continue;

        if (lastbit != bits[i]) {
            lastbit = bits[i];
            bits[i] = '1';
        } else {
            bits[i] = '0';
        }
    }
}
//ENDTOCHANGE
static int CmdNexWatchClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf nexwatch clone",
                  "clone a Nexwatch tag to a T55x7, Q5/T5555 or EM4305/4469 tag.\n"
                  "You can use raw hex values or create a credential based on id, mode\n"
                  "and type of credential (Nexkey / Quadrakey / Russian)",
                  "lf nexwatch clone --raw 5600000000213C9F8F150C00\n"
                  "lf nexwatch clone --cn 521512301 -m 1 --nc    -> Nexkey credential\n"
                  "lf nexwatch clone --cn 521512301 -m 1 --qc    -> Quadrakey credential\n"
                  "lf nexwatch clone --cn 521512301 -m 1 --hc    -> Honeywell credential\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw hex data. 12 bytes"),
        arg_u64_0(NULL, "cn", "<dec>", "card id"),
        arg_u64_0("m", "mode", "<dec>", "mode (decimal) (0-15, defaults to 1)"),
        arg_lit0(NULL, "nc", "Nexkey credential"),
        arg_lit0(NULL, "qc", "Quadrakey credential"),
        arg_lit0(NULL, "hc", "Honeywell credential"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_str0(NULL, "magic", "<hex>", "optional - magic hex data. 1 byte"),
        arg_lit0(NULL, "psk2", "optional - specify writing a tag in psk2 modulation"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    // skip first block,  3*4 = 12 bytes left
    uint8_t raw[12] = {0x56, 0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);

    uint32_t cn = arg_get_u32_def(ctx, 2, -1);
    uint32_t mode = arg_get_u32_def(ctx, 3, -1);
    bool use_nexkey = arg_get_lit(ctx, 4);
    bool use_quadrakey = arg_get_lit(ctx, 5);
    bool use_unk = arg_get_lit(ctx, 6);
    bool q5 = arg_get_lit(ctx, 7);
    bool em = arg_get_lit(ctx, 8);
    bool use_psk2 = arg_get_lit(ctx, 10);
    uint8_t magic_arg;
    int magic_len = 0;
    CLIGetHexWithReturn(ctx, 9, &magic_arg, &magic_len);
    CLIParserFree(ctx);

    if (use_nexkey && use_quadrakey) {
        PrintAndLogEx(FAILED, "Can't specify both Nexkey and Quadrakey at the same time");
        return PM3_EINVARG;
    }

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    // 56000000 00213C9F 8F150C00
    bool use_raw = (raw_len != 0);

    bool use_custom_magic = (magic_len != 0);

    if (magic_len > 1) {
        PrintAndLogEx(FAILED, "Can't specify a magic number bigger than one byte");
        return PM3_EINVARG;
    }

    if (use_raw && cn != -1) {
        PrintAndLogEx(FAILED, "Can't specify both Raw and Card id at the same time");
        return PM3_EINVARG;
    }

    if (cn != -1) {
        uint32_t scrambled;
        nexwatch_scamble(SCRAMBLE, &cn, &scrambled);
        num_to_bytes(scrambled, 4, raw + 5);
        PrintAndLogEx(SUCCESS, "Scrambled : %u", scrambled);
    }

    if (mode != -1) {
        if (mode > 15) {
            mode = 1;
        }
        mode &= 0x0F;
        raw[9] |= (mode << 4);
    }

    uint8_t magic = 0xBE;
    if (use_custom_magic) {
        magic = magic_arg;
    } else {
        if (use_nexkey)
            magic = 0x88;

        if (use_quadrakey)
            magic = 0xBE;

        if (use_unk)
            magic = 0x86;

    }
    PrintAndLogEx(INFO, "Magic byte selected : 0x%X", magic);

    char cardtype[16] = {"T55x7"};
    uint32_t blocks[4];
    if (use_psk2) {
        uint32_t scrambled;
        nexwatch_scamble(SCRAMBLE, &cn, &scrambled);
        num_to_bytes(scrambled, 4, raw + 5);
        PrintAndLogEx(SUCCESS, "Scrambled : %u", scrambled);
        blocks[0] = 270464;
        raw[0] = 0xFA;
        BYTE *byteId = convertUint32toByte(scrambled);
        BYTE newmode[4] = "0001";
        BYTE idAndMode[36];
        memcpy(idAndMode, byteId, 32 * sizeof(BYTE));
        memcpy(&idAndMode[32], newmode, 4 * sizeof(BYTE));
        BYTE *newparity = parity(idAndMode);
        uint8_t par = bin2int(newparity, 4);
        uint8_t checksum = nexwatch_checksum(magic, cn, par);
        printf("\x1b[1;92m[+]\x1b[0m Checksum : %s --> %u\n", convertUint8toByte(checksum), checksum);
        BYTE Psk_card[128];
        BYTE Psk2_card[128];
        memcpy(Psk_card, "00000000000000000000000000000000", 32 * sizeof(BYTE));
        memcpy(&Psk_card[32], "0101011000000000000000000000000000000000", 40 * sizeof(BYTE));
        memcpy(&Psk_card[72], byteId, 32 * sizeof(BYTE));
        memcpy(&Psk_card[104], newmode, 4 * sizeof(BYTE));
        memcpy(&Psk_card[108], newparity, 4 * sizeof(BYTE));
        memcpy(&Psk_card[112], convertUint8toByte(checksum), 8 * sizeof(BYTE));
        memcpy(&Psk_card[120], "00000000", 8 * sizeof(BYTE));
        TOpsk2(Psk_card, 128);
        memcpy(&Psk2_card[31], &Psk_card[32], 96 * sizeof(BYTE));
        Psk2_card[127] = '0';
        memcpy(Psk2_card, "00000000000001000010000010000000", 32 * sizeof(BYTE));
        blocks[0] = bin2int(&Psk2_card[0], 32);
        blocks[1] = bin2int(&Psk2_card[32], 32);
        blocks[2] = bin2int(&Psk2_card[64], 32);
        blocks[3] = bin2int(&Psk2_card[96], 32);
    } else {
        //Nexwatch - compat mode, PSK, data rate 40, 3 data blocks
        blocks[0] = T55x7_MODULATION_PSK1 | T55x7_BITRATE_RF_16 | 3 << T55x7_MAXBLOCK_SHIFT;

        // Q5
        if (q5) {
            blocks[0] = T5555_FIXED | T5555_MODULATION_MANCHESTER | T5555_SET_BITRATE(64) | T5555_ST_TERMINATOR | 3 << T5555_MAXBLOCK_SHIFT;
            snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
        }

        // EM4305
        if (em) {
            blocks[0] = EM4305_NEXWATCH_CONFIG_BLOCK;
            snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
        }

        if (use_raw == false) {
            uint8_t parity = nexwatch_parity(raw + 5) & 0xF;
            raw[9] |= parity;
            raw[10] |= nexwatch_checksum(magic, cn, parity);
        }

        if (use_unk)
            magic = 0x86;

        for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
            blocks[i] = bytes_to_num(raw + ((i - 1) * 4), sizeof(uint32_t));
        }
    }
    PrintAndLogEx(INFO, "Preparing to clone NexWatch to " _YELLOW_("%s") " raw " _YELLOW_("%s"), cardtype, sprint_hex_inrow(raw, sizeof(raw)));
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf nexwatch reader`") " to verify");
    return res;
}

static int CmdNexWatchSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf nexwatch sim",
                  "Enables simulation of secura card with specified card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n"
                  "You can use raw hex values or create a credential based on id, mode\n"
                  "and type of credential (Nexkey/Quadrakey)",
                  "lf nexwatch sim --raw 5600000000213C9F8F150C00\n"
                  "lf nexwatch sim --cn 521512301 -m 1 --nc    -> Nexkey credential\n"
                  "lf nexwatch sim --cn 521512301 -m 1 --qc    -> Quadrakey credential\n"
                  "lf nexwatch sim --cn 521512301 -m 1 --hc    -> Honeywell credential\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw hex data. 12 bytes"),
        arg_u64_0(NULL, "cn", "<dec>", "card id"),
        arg_u64_0("m", "mode", "<dec>", "mode (decimal) (0-15, defaults to 1)"),
        arg_lit0(NULL, "nc", "Nexkey credential"),
        arg_lit0(NULL, "qc", "Quadrakey credential"),
        arg_lit0(NULL, "hc", "Honeywell credential"),
        arg_str0(NULL, "magic", "<hex>", "optional - magic hex data. 1 byte"),
        arg_lit0(NULL, "psk2", "optional - specify writing a tag in psk2 modulation"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    // skip first block,  3*4 = 12 bytes left
    uint8_t raw[12] = {0x56, 0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);

    uint32_t cn = arg_get_u32_def(ctx, 2, -1);
    uint32_t mode = arg_get_u32_def(ctx, 3, -1);
    bool use_nexkey = arg_get_lit(ctx, 4);
    bool use_quadrakey = arg_get_lit(ctx, 5);
    bool use_unk = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (use_nexkey && use_quadrakey) {
        PrintAndLogEx(FAILED, "Can't specify both Nexkey and Quadrakey at the same time");
        return PM3_EINVARG;
    }

    bool use_raw = (raw_len != 0);

    if (use_raw && cn != -1) {
        PrintAndLogEx(FAILED, "Can't specify both Raw and Card id at the same time");
        return PM3_EINVARG;
    }

    if (cn != -1) {
        uint32_t scrambled;
        nexwatch_scamble(SCRAMBLE, &cn, &scrambled);
        num_to_bytes(scrambled, 4, raw + 5);
    }

    if (mode != -1) {
        if (mode > 15) {
            mode = 1;
        }
        mode &= 0x0F;
        raw[9] |= (mode << 4);
    }

    uint8_t magic = 0xBE;
    if (use_nexkey)
        magic = 0x88;

    if (use_quadrakey)
        magic = 0xBE;

    if (use_unk)
        magic = 0x86;

    if (use_raw == false) {
        uint8_t parity = nexwatch_parity(raw + 5) & 0xF;
        raw[9] |= parity;
        raw[10] |= nexwatch_checksum(magic, cn, parity);
    }

    uint8_t bs[96];
    memset(bs, 0, sizeof(bs));

    // hex to bits.  (3 * 32 == 96)
    for (size_t i = 0; i < 3; i++) {
        uint32_t tmp = bytes_to_num(raw + (i * sizeof(uint32_t)), sizeof(uint32_t));
        num_to_bytebits(tmp, sizeof(uint32_t) * 8, bs + (i * sizeof(uint32_t) * 8));
    }

    PrintAndLogEx(SUCCESS, "Simulating NexWatch - raw " _YELLOW_("%s"), sprint_hex_inrow(raw, sizeof(raw)));

    lf_psksim_t *payload = calloc(1, sizeof(lf_psksim_t) + sizeof(bs));
    payload->carrier = 2;
    payload->invert = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

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

static command_t CommandTable[] = {
    {"help",   CmdHelp,           AlwaysAvailable, "This help"},
    {"demod",  CmdNexWatchDemod,  AlwaysAvailable, "demodulate a NexWatch tag (nexkey, quadrakey) from the GraphBuffer"},
    {"reader", CmdNexWatchReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",  CmdNexWatchClone,  IfPm3Lf,         "clone NexWatch tag to T55x7"},
    {"sim",    CmdNexWatchSim,    IfPm3Lf,         "simulate NexWatch tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFNEXWATCH(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int detectNexWatch(uint8_t *dest, size_t *size, bool *invert) {

    uint8_t preamble[28]   = {0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    // sanity check.
    if (*size < 96) return -1;

    size_t startIdx = 0;

    if (!preambleSearch(DemodBuffer, preamble, sizeof(preamble), size, &startIdx)) {
        // if didn't find preamble try again inverting
        uint8_t preamble_i[28] = {1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        if (!preambleSearch(DemodBuffer, preamble_i, sizeof(preamble_i), size, &startIdx)) return -4;
        *invert ^= 1;
    }

    // size tests?
    return (int) startIdx;
}
