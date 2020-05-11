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
#include <inttypes.h>       // PRIu
#include <string.h>
#include <ctype.h>          // tolower
#include <stdlib.h>         // free, alloc

#include "commonutil.h"     // ARRAYLEN
#include "cmdparser.h"      // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"        // preamblesearch
#include "cmdlf.h"
#include "lfdemod.h"
#include "protocols.h"      // t55xx defines
#include "cmdlft55xx.h"     // clone..

typedef enum {
    SCRAMBLE,
    DESCRAMBLE
} NexWatchScramble_t;

static int CmdHelp(const char *Cmd);

static int usage_lf_nexwatch_clone(void) {
    PrintAndLogEx(NORMAL, "clone a Nexwatch tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "You can use raw hex values or create a credential based on id, mode");
    PrintAndLogEx(NORMAL, "and type of credential (Nexkey/Quadrakey)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf nexwatch clone [h] [b <raw hex>] [c <id>] [m <mode>] [n|q]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             : this help");
    PrintAndLogEx(NORMAL, "      r <raw hex>   : raw hex data. 12 bytes max");
    PrintAndLogEx(NORMAL, "      c <id>        : card id (decimal)");
    PrintAndLogEx(NORMAL, "      m <mode>      : mode (decimal) (0-15, defaults to 1)");
    PrintAndLogEx(NORMAL, "      n             : Nexkey credential");
    PrintAndLogEx(NORMAL, "      q             : Quadrakey credential");    
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf nexwatch clone r 5600000000213C9F8F150C");
    PrintAndLogEx(NORMAL, "       lf nexwatch clone c 521512301 m 1 n       -- Nexkey credential");
    PrintAndLogEx(NORMAL, "       lf nexwatch clone c 521512301 m 1 q       -- Quadrakey credential");
    return PM3_SUCCESS;
}

static int usage_lf_nexwatch_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of Nexwatch card");
    PrintAndLogEx(NORMAL, "You can use raw hex values or create a credential based on id, mode");
    PrintAndLogEx(NORMAL, "and type of credential (Nexkey/Quadrakey)");  
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf nexwatch sim [h] <r raw hex> [c <id>] [m <mode>] [n|q]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h            : this help");
    PrintAndLogEx(NORMAL, "      r <raw hex>  : raw hex data. 16 bytes max");
    PrintAndLogEx(NORMAL, "      c <id>        : card id (decimal)");
    PrintAndLogEx(NORMAL, "      m <mode>      : mode (decimal) (0-15, defaults to 1)");
    PrintAndLogEx(NORMAL, "      n             : Nexkey credential");
    PrintAndLogEx(NORMAL, "      q             : Quadrakey credential"); 
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf nexwatch sim r 5600000000213C9F8F150C");
    PrintAndLogEx(NORMAL, "       lf nexwatch sim c 521512301 m 1 n       -- Nexkey credential");
    PrintAndLogEx(NORMAL, "       lf nexwatch sim c 521512301 m 1 q       -- Quadrakey credential");
    return PM3_SUCCESS;
}

// scramble parity (1234) -> (4231)
static uint8_t nexwatch_parity_swap(uint8_t parity) {
    uint8_t a = (((parity >> 3 ) & 1) );
    a |= (((parity >> 1 ) & 1) << 1);
    a |= (((parity >> 2 ) & 1) << 2);
    a |=  ((parity & 1) << 3);
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
/// @param magic =  0xBE  Quadrakey,  0x88 Nexkey
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

    switch(action) {
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
        default: break;
    }
    return PM3_SUCCESS;
}

int demodNexWatch(void) {
    if (PSKDemod("", false) != PM3_SUCCESS) {
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
        char desc[10];
        uint8_t chk;
    } nexwatch_magic_t;
    nexwatch_magic_t items[] = { {0xBE, "Quadrakey", 0}, {0x88, "Nexkey", 0} };

    uint8_t m_idx; 
    for ( m_idx = 0; m_idx < ARRAYLEN(items); m_idx++) {
        
        items[m_idx].chk = nexwatch_checksum(items[m_idx].magic, cn, calc_parity);
        if (items[m_idx].chk == chk) {
            break;
        }
    }

    // output
    PrintAndLogEx(SUCCESS, " NexWatch raw id : " _YELLOW_("0x%"PRIx32) , rawid);

    if (m_idx < 3) {
        PrintAndLogEx(SUCCESS, "     fingerprint : " _GREEN_("%s"),  items[m_idx].desc);        
    }
    PrintAndLogEx(SUCCESS, "        88bit id : " _YELLOW_("%"PRIu32) " ("  _YELLOW_("0x%"PRIx32)")", cn, cn);
    PrintAndLogEx(SUCCESS, "            mode : %x", mode);  
    if ( parity == calc_parity) {
        PrintAndLogEx(SUCCESS, "          parity : %s (0x%X)", _GREEN_("ok"), parity);
    } else {
        PrintAndLogEx(WARNING, "          parity : %s (0x%X != 0x%X)", _RED_("fail"), parity, calc_parity);        
    }
    if (m_idx < 3) {
        PrintAndLogEx(SUCCESS, "        checksum : %s (0x%02X)",  _GREEN_("ok"), chk);
    } else {
        PrintAndLogEx(WARNING, "        checksum : %s (0x%02X != 0x%02X)", _RED_("fail"), chk, items[m_idx].chk);
    }

    PrintAndLogEx(INFO, " raw : " _YELLOW_("%"PRIX32"%"PRIX32"%"PRIX32), raw1, raw2, raw3);
    return PM3_SUCCESS;
}

static int CmdNexWatchDemod(const char *Cmd) {
    (void)Cmd;
    return demodNexWatch();
}

//by marshmellow
//see ASKDemod for what args are accepted
static int CmdNexWatchRead(const char *Cmd) {
    lf_read(false, 20000);
    return CmdNexWatchDemod(Cmd);
}

static int CmdNexWatchClone(const char *Cmd) {

    // 56000000 00213C9F 8F150C00
    uint32_t blocks[4];
    bool use_raw = false;
    bool errors = false;
    uint8_t cmdp = 0;
    int datalen = 0;
    uint8_t magic = 0xBE;
    uint32_t cn = 0;
    uint8_t rawhex[16] = {0x56, 0};
                
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_nexwatch_clone();
            case 'r': {
                int res = param_gethex_to_eol(Cmd, cmdp + 1, rawhex, sizeof(rawhex), &datalen);
                if (res != 0)
                    errors = true;

                use_raw = true;
                cmdp += 2;
                break;
            }
            case 'c': {
                cn = param_get32ex(Cmd, cmdp + 1, 0, 10);
                uint32_t scrambled;
                nexwatch_scamble(SCRAMBLE, &cn, &scrambled);
                num_to_bytes(scrambled, 4, rawhex + 5);
                cmdp += 2;
                break;
            }
            case 'm': {
                uint8_t mode = param_get8ex(Cmd, cmdp + 1, 1, 10);
                mode &= 0x0F;
                rawhex[9] |= (mode << 4);
                cmdp += 2;
                break;
            }
            case 'n': {
                magic = 0x88;
                cmdp++;
                break;
            }
            case 'q': {
                magic = 0xBE;
                cmdp++;
                break;
            }            
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || cmdp == 0) return usage_lf_nexwatch_clone();

    //Nexwatch - compat mode, PSK, data rate 40, 3 data blocks
    blocks[0] = T55x7_MODULATION_PSK1 | T55x7_BITRATE_RF_32 | 3 << T55x7_MAXBLOCK_SHIFT;
    
    if (use_raw == false) {
        uint8_t parity = nexwatch_parity(rawhex + 5) & 0xF;
        rawhex[9] |= parity;
        rawhex[10] |= nexwatch_checksum(magic, cn, parity);
    }
    
    for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
        blocks[i] = bytes_to_num(rawhex + ((i - 1) * 4), sizeof(uint32_t));
    }

    PrintAndLogEx(INFO, "Preparing to clone NexWatch to T55x7 with raw hex");
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf nexwatch read`") " to verify");
    return res;
}

static int CmdNexWatchSim(const char *Cmd) {

    uint8_t cmdp = 0;
    bool errors = false;
    bool use_raw = false;
    uint8_t rawhex[12] = {0x56, 0};
    int rawlen = sizeof(rawhex);
    uint8_t magic = 0xBE;
    uint32_t cn = 0;
    
    uint8_t bs[128];
    memset(bs, 0, sizeof(bs));

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_nexwatch_clone();
            case 'r': {
                int res = param_gethex_to_eol(Cmd, cmdp + 1, rawhex, sizeof(rawhex), &rawlen);
                if (res != 0)
                    errors = true;

                use_raw = true;
                cmdp += 2;
                break;
            }
            case 'c': {
                cn = param_get32ex(Cmd, cmdp + 1, 0, 10);
                uint32_t scrambled;
                nexwatch_scamble(SCRAMBLE, &cn, &scrambled);
                num_to_bytes(scrambled, 4, rawhex + 5);
                cmdp += 2;
                break;
            }
            case 'm': {
                uint8_t mode = param_get8ex(Cmd, cmdp + 1, 1, 10);
                mode &= 0x0F;
                rawhex[9] |= (mode << 4);
                cmdp += 2;
                break;
            }
            case 'n': {
                magic = 0x88;
                cmdp++;
                break;
            }
            case 'q': {
                magic = 0xBE;
                cmdp++;
                break;
            }  
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || cmdp == 0) return usage_lf_nexwatch_sim();

    if (use_raw == false) {
        uint8_t parity = nexwatch_parity(rawhex + 5) & 0xF;
        rawhex[9] |= parity;
        rawhex[10] |= nexwatch_checksum(magic, cn, parity);
    }

    // hex to bits.
    uint32_t rawblocks[3];
    for (size_t i = 0; i < ARRAYLEN(rawblocks); i++) {
        rawblocks[i] = bytes_to_num(rawhex + (i * sizeof(uint32_t)), sizeof(uint32_t));
        num_to_bytebits(rawblocks[i], sizeof(uint32_t) * 8, bs + (i * sizeof(uint32_t) * 8));
    }

    PrintAndLogEx(SUCCESS, "Simulating NexWatch - raw: %s", sprint_hex_inrow(rawhex, rawlen));

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
    {"help",  CmdHelp,           AlwaysAvailable, "This help"},
    {"demod", CmdNexWatchDemod,  AlwaysAvailable, "Demodulate a NexWatch tag (nexkey, quadrakey) from the GraphBuffer"},
    {"read",  CmdNexWatchRead,   IfPm3Lf,         "Attempt to Read and Extract tag data from the antenna"},
    {"clone", CmdNexWatchClone,  IfPm3Lf,         "clone NexWatch tag to T55x7"},
    {"sim",   CmdNexWatchSim,    IfPm3Lf,         "simulate NexWatch tag"},
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
