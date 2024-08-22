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
// Low frequency Hitag support
//-----------------------------------------------------------------------------
#include "cmdlfhitag.h"
#include <ctype.h>
#include "cmdparser.h"  // command_t
#include "comms.h"
#include "cmdtrace.h"
#include "commonutil.h"
#include "hitag.h"
#include "fileutils.h"  // savefile
#include "protocols.h"  // defines
#include "cliparser.h"
#include "crc.h"
#include "graph.h"      // MAX_GRAPH_TRACE_LEN
#include "lfdemod.h"
#include "cmddata.h"    // setDemodBuff
#include "pm3_cmd.h"    // return codes
#include "hitag2/hitag2_crypto.h"
#include "util_posix.h"             // msclock

static int CmdHelp(const char *Cmd);

static const char *getHitagTypeStr(uint32_t uid) {
    //uid s/n        ********
    uint8_t type = (uid >> 4) & 0xF;
    switch (type) {
        case 1:
            return "PCF 7936";
        case 2:
            return "PCF 7946";
        case 3:
            return "PCF 7947";
        case 4:
            return "PCF 7942/44";
        case 5:
            return "PCF 7943";
        case 6:
            return "PCF 7941";
        case 7:
            return "PCF 7952";
        case 9:
            return "PCF 7945";
        default:
            return "";
    }
}

uint8_t hitag1_CRC_check(uint8_t *d, uint32_t nbit) {
    if (nbit < 9) {
        return 2;
    }
    return (CRC8Hitag1Bits(d, nbit) == 0);
}


/*
static size_t nbytes(size_t nbits) {
    return (nbits / 8) + ((nbits % 8) > 0);
}
*/

static int CmdLFHitagList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "lf hitag", "hitag2");
    /*
    uint8_t *got = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    if (!got) {
        PrintAndLogEx(WARNING, "Cannot allocate memory for trace");
        return PM3_EMALLOC;
    }

    // Query for the actual size of the trace
    PacketResponseNG resp;
    if (!GetFromDevice(BIG_BUF, got, PM3_CMD_DATA_SIZE, 0, NULL, 0, &resp, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        free(got);
        return PM3_ETIMEOUT;
    }

    uint16_t traceLen = resp.arg[2];
    if (traceLen > PM3_CMD_DATA_SIZE) {
        uint8_t *p = realloc(got, traceLen);
        if (p == NULL) {
            PrintAndLogEx(WARNING, "Cannot allocate memory for trace");
            free(got);
            return PM3_EMALLOC;
        }
        got = p;
        if (!GetFromDevice(BIG_BUF, got, traceLen, 0, NULL, 0, NULL, 2500, false)) {
            PrintAndLogEx(WARNING, "command execution time out");
            free(got);
            return PM3_ETIMEOUT;
        }
    }

    PrintAndLogEx(NORMAL, "recorded activity (TraceLen = %d bytes):");
    PrintAndLogEx(NORMAL, " ETU     :nbits: who bytes");
    PrintAndLogEx(NORMAL, "---------+-----+----+-----------");

    int i = 0;
    int prev = -1;
    int len = strlen(Cmd);

    char filename[FILE_PATH_SIZE]  = { 0x00 };
    FILE *f = NULL;

    if (len > FILE_PATH_SIZE) len = FILE_PATH_SIZE;

    memcpy(filename, Cmd, len);

    if (strlen(filename) > 0) {
        f = fopen(filename, "wb");
        if (!f) {
            PrintAndLogEx(ERR, "Error: Could not open file [%s]", filename);
            return PM3_EFILE;
        }
    }

    for (;;) {

        if (i >= traceLen) { break; }

        bool isResponse;
        int timestamp = *((uint32_t *)(got + i));
        if (timestamp & 0x80000000) {
            timestamp &= 0x7fffffff;
            isResponse = 1;
        } else {
            isResponse = 0;
        }

        int parityBits = *((uint32_t *)(got + i + 4));
        // 4 bytes of additional information...
        // maximum of 32 additional parity bit information
        //
        // TODO:
        // at each quarter bit period we can send power level (16 levels)
        // or each half bit period in 256 levels.

        int bits = got[i + 8];
        int len = nbytes(got[i + 8]);

        if (len > 100) {
            break;
        }
        if (i + len > traceLen) { break;}

        uint8_t *frame = (got + i + 9);

        // Break and stick with current result if buffer was not completely full
        if (frame[0] == 0x44 && frame[1] == 0x44 && frame[3] == 0x44) { break; }

        char line[1000] = "";
        int j;
        for (j = 0; j < len; j++) {

            int offset = j * 4;
            //if((parityBits >> (len - j - 1)) & 0x01) {
            if (isResponse && (oddparity8(frame[j]) != ((parityBits >> (len - j - 1)) & 0x01))) {
                snprintf(line + offset, sizeof(line) - offset, "%02x!  ", frame[j]);
            } else {
                snprintf(line + offset, sizeof(line) - offset, "%02x   ", frame[j]);
            }
        }

        PrintAndLogEx(NORMAL, " +%7d:  %3d: %s %s",
                      (prev < 0 ? 0 : (timestamp - prev)),
                      bits,
                      (isResponse ? "TAG" : "   "),
                      line);

        if (f) {
            fprintf(f, " +%7d:  %3d: %s %s\n",
                    (prev < 0 ? 0 : (timestamp - prev)),
                    bits,
                    (isResponse ? "TAG" : "   "),
                    line);
        }

        prev = timestamp;
        i += (len + 9);
    }

    if (f) {
        fclose(f);
        PrintAndLogEx(NORMAL, "Recorded activity successfully written to file: %s", filename);
    }

    free(got);
    return PM3_SUCCES;
    */
}

static void print_hitag2_paxton(const uint8_t *data) {

    // if the pwd isn't..
    if (memcmp(data + 4, "\xBD\xF5\xE8\x46", 4)) {
        return;
    }

    uint64_t num = 0;
    uint64_t paxton_id = 0;
    uint16_t skip = 48;
    uint64_t mask = 0xF80000000000;

    uint64_t bytes = bytes_to_num(data + 16, 6);

    for (int j = 0; j < 8; j++) {

        num = bytes & mask;
        skip -= 5;
        mask >>= 5;

        uint8_t digit = (num >> skip & 0xF);
        paxton_id = (paxton_id * 10) + digit;

        if (j == 5) {
            skip -= 2;
            mask >>= 2;
        }
    }

    /*
    const uint8_t isocard = 0x06;
    const uint8_t fob = 0x03;
    const uint8_t iso_magstripe = 0x02;
    */

// [=]  4/0x04 | 39 04 21 1C | 9.!.  | RW  | User
// [=]  5/0x05 | AC 3F 00 06 | .?..  | RW  | User

    char formfactor[16];
    switch (data[23]) {
        case 0x06: {
            strcat(formfactor, "isocard");
            break;
        }
        case 0x03: {
            strcat(formfactor, "fob");
            break;
        }
        case 0x02: {
            strcat(formfactor, "iso magstripe");
            break;
        }
        default: {
            snprintf(formfactor, sizeof(formfactor), "unk: %02x", data[23]);
            break;
        }
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Possible de-scramble patterns") " -------------");
    PrintAndLogEx(SUCCESS, "Paxton id... %" PRIu64 " | 0x%" PRIx64 "  ( %s )", paxton_id, paxton_id, formfactor);
    PrintAndLogEx(INFO, "");
}

static void print_hitag2_configuration(uint32_t uid, uint8_t config) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(SUCCESS, "UID...... " _GREEN_("%08X"), uid);
    PrintAndLogEx(SUCCESS, "TYPE..... " _GREEN_("%s"), getHitagTypeStr(uid));

    char msg[100];
    memset(msg, 0, sizeof(msg));

    uint8_t bits[8 + 1] = {0};
    num_to_bytebits(config, 8, bits);
    const char *bs = sprint_bytebits_bin(bits, 8);

    //configuration byte
//    PrintAndLogEx(SUCCESS, "");
    PrintAndLogEx(SUCCESS, "Config... " _YELLOW_("0x%02X"), config);
    PrintAndLogEx(SUCCESS, "  %s", bs);
    PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 0, 4, "RFU"));

    if (config & 0x8) {
        PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_YELLOW, bs, 8, 4, 1, "Crypto mode"));
    } else  {
        PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 4, 1, "Password mode"));
    }

    // version
    uint8_t foo = ((config & 0x6) >> 1);
    switch (foo) {
        case 0:
            PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 5, 2, "Public mode B, Coding: biphase"));
            break;
        case 1:
            PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 5, 2, "Public mode A, Coding: manchester"));
            break;
        case 2:
            PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 5, 2, "Public mode C, Coding: biphase"));
            break;
        case 3:
            PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 5, 2, "Hitag 2"));
            break;
    }

    // encoding
    if (config & 0x01) {
        PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 7, 1, "Biphase"));
    } else {
        PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 7, 1, "Manchester"));
    }
    PrintAndLogEx(NORMAL, "");
}

const char *annotation[] = {
    "UID", "Pwd", "Key/Pwd", "Config",
    "User", "User", "User", "User",
    "User", "User", "User", "User"
};

static void print_hitag2_blocks(uint8_t *d, uint16_t n) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "----------------------------------------------");
    PrintAndLogEx(INFO, " #      | data        | ascii | lck | Info");
    PrintAndLogEx(INFO, "--------+-------------+-------+-----+---------");

    uint8_t config = d[HITAG2_CONFIG_OFFSET];
    uint8_t blocks = (n / HITAG_BLOCK_SIZE);

    for (uint8_t i = 0; i < blocks; ++i) {

        char lckstr[20] = {0};
        sprintf(lckstr, "  ");

        switch (i) {
            case  0:
                sprintf(lckstr, "%s", _RED_("L "));
                break;
            case  1:
                if (config & 0x80) {
                    sprintf(lckstr, "%s", _RED_("L "));
                } else  {
                    sprintf(lckstr, "%s", _GREEN_("RW"));
                }
                break;
            case  2:
                if (config & 0x80) {
                    if (config & 0x8) {
                        sprintf(lckstr, "%s", _RED_("L "));
                    } else {
                        sprintf(lckstr, "%s", _RED_("R "));
                    }
                } else  {
                    sprintf(lckstr, "%s", _GREEN_("RW"));
                }
                break;
            case  3:
                // OTP Page 3.
                if (config & 0x40) {
                    sprintf(lckstr, "%s", _RED_("R "));
                    //. Configuration byte and password tag " _RED_("FIXED / IRREVERSIBLE"));
                } else  {
                    sprintf(lckstr, "%s", _GREEN_("RW"));
                }
                break;
            case  4:
            case  5:
                if (config & 0x20) {
                    sprintf(lckstr, "%s", _RED_("R "));
                } else  {
                    sprintf(lckstr, "%s", _GREEN_("RW"));
                }
                break;
            case  6:
            case  7:
                if (config & 0x10) {
                    sprintf(lckstr, "%s", _RED_("R "));
                } else  {
                    sprintf(lckstr, "%s", _GREEN_("RW"));
                }
                break;
            default:
                break;
        }

        PrintAndLogEx(INFO, "%2d/0x%02X | %s| %s  | %s  | %s"
                      , i
                      , i
                      , sprint_hex(d + (i * HITAG_BLOCK_SIZE), HITAG_BLOCK_SIZE)
                      , sprint_ascii(d + (i * HITAG_BLOCK_SIZE), HITAG_BLOCK_SIZE)
                      , lckstr
                      , annotation[i]
                     );
    }
    PrintAndLogEx(INFO, "--------+-------------+-------+-----+---------");
    PrintAndLogEx(INFO, " "_RED_("L") " = Locked, "_GREEN_("RW") " = Read Write, R = Read Only");
    PrintAndLogEx(INFO, " FI = Fixed / Irreversible");
    PrintAndLogEx(INFO, "----------------------------------------------");
}

// Annotate HITAG protocol
void annotateHitag1(char *exp, size_t size, const uint8_t *cmd, uint8_t cmdsize, bool is_response) {
}

static struct {
    enum {
        STATE_HALT,
        STATE_START_AUTH,
        STATE_AUTH,
        STATE_START_ENCRYPTED,
        STATE_ENCRYPTED,
    } state;
    uint32_t uid;
    uint64_t cipher_state;
    uint8_t plainlen;
    uint8_t plain[30];
    bool found_key;
    uint64_t key;
} _ht2state;

void annotateHitag2_init(void) {
    _ht2state.state = STATE_HALT;
    _ht2state.uid = 0;
    _ht2state.cipher_state = 0;
    _ht2state.plainlen = 0;
    memset(_ht2state.plain, 0, sizeof(_ht2state.plain));
}

static void rev_msb_array(uint8_t *d, uint8_t n) {
    for (uint8_t i = 0 ; i < n ; i++) {
        d[i] = reflect8(d[i]);
    }
}

// param nrar must be 8 bytes
static bool ht2_check_cryptokeys(const uint64_t *keys, const uint32_t keycount, const uint8_t *nrar) {

    if (keys == NULL || keycount == 0 || nrar == NULL) {
        return false;
    }

    uint32_t iv = REV32((nrar[3] << 24) + (nrar[2] << 16) + (nrar[1] << 8) + nrar[0]);
    uint32_t ar = (nrar[4] << 24) + (nrar[5] << 16) + (nrar[6] << 8) + nrar[7];

    bool found = false;
    for (uint32_t i = 0; i < keycount; i++) {

        uint64_t key = keys[i];
        key = BSWAP_48(key);
        key = REV64(key);

        hitag_state_t hs2;
        ht2_hitag2_init_ex(&hs2, key, _ht2state.uid, iv);

        uint32_t tbits = ht2_hitag2_nstep(&hs2, 32);
        if ((ar ^ tbits) == 0xFFFFFFFF) {
            _ht2state.found_key = true;
            _ht2state.key = key;
            found = true;
            break;
        }
    }
    return found;
}

static int ht2_check_dictionary(uint32_t key_count, uint8_t *keys,  uint8_t keylen, uint32_t *found_idx) {

    lf_hitag_data_t packet;
    memset(&packet, 0, sizeof(packet));

    uint8_t *pkeys = keys;

    while (key_count--) {

        if (keylen == 4) {
            packet.cmd = RHT2F_PASSWORD;
            memcpy(packet.pwd, pkeys, keylen);
        } else {
            packet.cmd = RHT2F_CRYPTO;
            memcpy(packet.key, pkeys, keylen);
        }

        pkeys += keylen;

        clearCommandBuffer();
        SendCommandNG(CMD_LF_HITAG_READER, (uint8_t *)&packet, sizeof(packet));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_LF_HITAG_READER, &resp, 2000) == false) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            return PM3_ETIMEOUT;
        }

        if (resp.status != PM3_SUCCESS) {
            *found_idx = *found_idx + 1;
            continue;
        }
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}


bool hitag2_get_plain(uint8_t *plain,  uint8_t *plen) {
    if (_ht2state.state == STATE_ENCRYPTED || _ht2state.state == STATE_START_ENCRYPTED) {
        if (_ht2state.found_key) {
            *plen = _ht2state.plainlen;
            memcpy(plain, _ht2state.plain, _ht2state.plainlen);
            return true;
        }
    }
    return false;
}

static uint8_t hitag2_get_page(const char *bs) {
    if ((memcmp(bs + 2, "000", 3) == 0) && (memcmp(bs + 2 + 3 + 2, "111", 3) == 0)) {
        return 0;
    }
    if ((memcmp(bs + 2, "001", 3) == 0) && (memcmp(bs + 2 + 3 + 2, "110", 3) == 0)) {
        return 1;
    }
    if ((memcmp(bs + 2, "010", 3) == 0) && (memcmp(bs + 2 + 3 + 2, "101", 3) == 0)) {
        return 2;
    }
    if ((memcmp(bs + 2, "011", 3) == 0) && (memcmp(bs + 2 + 3 + 2, "100", 3) == 0)) {
        return 3;
    }
    if ((memcmp(bs + 2, "100", 3) == 0) && (memcmp(bs + 2 + 3 + 2, "011", 3) == 0)) {
        return 4;
    }
    if ((memcmp(bs + 2, "101", 3) == 0) && (memcmp(bs + 2 + 3 + 2, "010", 3) == 0)) {
        return 5;
    }
    if ((memcmp(bs + 2, "110", 3) == 0) && (memcmp(bs + 2 + 3 + 2, "001", 3) == 0)) {
        return 6;
    }
    if ((memcmp(bs + 2, "111", 3) == 0) && (memcmp(bs + 2 + 3 + 2, "000", 3) == 0)) {
        return 7;
    }
    return 255;
}

void hitag2_annotate_plain(char *exp, size_t size, const uint8_t *cmd, uint8_t cmdsize, uint8_t bits) {

    if (cmdsize == 0) {
        return;
    }

    char *binstr = (char *)calloc((cmdsize * 8) + 1, sizeof(uint8_t));
    if (binstr == NULL) {
        return;
    }

    bytes_2_binstr(binstr, cmd, cmdsize);

    size_t bn = strlen(binstr);
    if (bits) {
        if (cmdsize == 1) {
            bn = bits;
        } else if (cmdsize > 1) {
            bn = ((cmdsize - 1) * 8) + bits;
        }
    }

    switch (bn) {
        case 5: {
            snprintf(exp, size, " ");
            break;
        }
        case 10: {
            if (memcmp(binstr, HITAG2_HALT, 2) == 0) {
                snprintf(exp, size, " ");
                break;
            }

            uint8_t page = hitag2_get_page(binstr);

            if (memcmp(binstr, HITAG2_READ_PAGE, 2) == 0) {
                snprintf(exp, size, "READ PAGE (" _MAGENTA_("%u") ")", page);
                break;
            }

            if (memcmp(binstr, HITAG2_READ_PAGE_INVERTED, 2) == 0) {
                snprintf(exp, size, "READ PAGE INV (" _MAGENTA_("%u") ")", page);
                break;
            }

            if (memcmp(binstr, HITAG2_WRITE_PAGE, 2) == 0) {
                snprintf(exp, size, "WRITE PAGE (" _MAGENTA_("%u") ")", page);
                break;
            }
            break;
        }
        case 32: {       // password or data
            snprintf(exp, size, " ");
            break;
        }
        case 64: {       // crypto handshake
            snprintf(exp, size, " ");
            break;
        }
        default: {
            snprintf(exp, size, " ");
            break;
        }
    }
    free(binstr);
}

void annotateHitag2(char *exp, size_t size, const uint8_t *cmd, uint8_t cmdsize, uint8_t bits, bool is_response, const uint64_t *keys, uint32_t keycount, bool isdecrypted) {

    if (cmdsize == 0) {
        return;
    }

    char *binstr = (char *)calloc((cmdsize * 8) + 1, sizeof(uint8_t));
    if (binstr == NULL) {
        return;
    }

    bytes_2_binstr(binstr, cmd, cmdsize);

    size_t bn = strlen(binstr);
    if (bits) {
        if (cmdsize == 1) {
            bn = bits;
        } else if (cmdsize > 1) {
            bn = ((cmdsize - 1) * 8) + bits;
        }
    }

    memcpy(_ht2state.plain, cmd, cmdsize);
    _ht2state.plainlen = cmdsize;

    if (_ht2state.state == STATE_ENCRYPTED || _ht2state.state == STATE_START_ENCRYPTED) {

        if (_ht2state.found_key && isdecrypted == false) {
            ht2_hitag2_cipher_transcrypt(&_ht2state.cipher_state, _ht2state.plain, bn / 8, bn % 8);
        }
    }

    // 11000  AUTH  only one with 5 bits.  cmdsize 1
    switch (bn) {
        case 5: {
            annotateHitag2_init();

            if (memcmp(binstr, HITAG2_START_AUTH, 5) == 0) {
                snprintf(exp, size, "START AUTH");
                _ht2state.state = STATE_START_AUTH;
            } else {
                snprintf(exp, size, "?");
            }
            break;
        }
        case 10: {

            if (isdecrypted == false && _ht2state.state == STATE_ENCRYPTED) {
                snprintf(exp, size, "ENC CMD");
                break;
            }

            if (memcmp(binstr, HITAG2_HALT, 2) == 0) {
                snprintf(exp, size, "HALT");
                _ht2state.state = STATE_HALT;
                break;
            }

            uint8_t page = hitag2_get_page(binstr);

            if (memcmp(binstr, HITAG2_READ_PAGE, 2) == 0) {
                snprintf(exp, size, "READ PAGE (" _MAGENTA_("%u") ")", page);
                break;
            }

            if (memcmp(binstr, HITAG2_READ_PAGE_INVERTED, 2) == 0) {
                snprintf(exp, size, "READ PAGE INV (" _MAGENTA_("%u") ")", page);
                break;
            }

            if (memcmp(binstr, HITAG2_WRITE_PAGE, 2) == 0) {
                snprintf(exp, size, "WRITE PAGE (" _MAGENTA_("%u") ")", page);
                break;
            }
            break;
        }

        case 32: {       // password or data
            if (_ht2state.state == STATE_START_AUTH) {
                if (is_response) {
                    snprintf(exp, size, "UID");
                    uint8_t uid[4];
                    memcpy(uid, cmd, 4);
                    rev_msb_array(uid, 4);
                    _ht2state.uid = MemLeToUint4byte(uid);
                } else  {
                    snprintf(exp, size, "PWD: " _GREEN_("0x%02X%02X%02X%02X"), cmd[0], cmd[1], cmd[2], cmd[3]);
                    _ht2state.state = STATE_AUTH;
                }
                break;
            }

            if (_ht2state.state == STATE_AUTH) {
                snprintf(exp, size, "DATA");
                break;
            }

            if (_ht2state.state == STATE_START_ENCRYPTED) {
                snprintf(exp, size, "At");
                _ht2state.state = STATE_ENCRYPTED;
                break;
            }

            if (isdecrypted == false && _ht2state.state == STATE_ENCRYPTED) {
                snprintf(exp, size, "ENC DATA");
            }
            break;
        }

        case 64: {       // crypto handshake

            if (_ht2state.state == STATE_START_AUTH) {
                _ht2state.state = STATE_START_ENCRYPTED;

                // need to be called with filename...
                if (ht2_check_cryptokeys(keys, keycount, cmd)) {

                    _ht2state.cipher_state = ht2_hitag2_init(
                                                 _ht2state.key,
                                                 _ht2state.uid,
                                                 REV32((cmd[3] << 24) + (cmd[2] << 16) + (cmd[1] << 8) + cmd[0])
                                             );
                    ht2_hitag2_cipher_transcrypt(&_ht2state.cipher_state, _ht2state.plain + 4, 4, 0);

                    uint64_t key = REV64(_ht2state.key);
                    key = BSWAP_48(key);
                    snprintf(exp, size, "Nr Ar " _WHITE_("( ")  _GREEN_("%012" PRIx64)  " )", key);

                } else {
                    snprintf(exp, size, "AUTH: Nr Ar");
                }
            } else {
                snprintf(exp, size, "AUTH: Nr Ar");
            }
            break;
        }
        default: {
            snprintf(exp, size, "?");
            _ht2state.state = STATE_HALT;
            break;
        }
    }

    free(binstr);
}

void annotateHitagS(char *exp, size_t size, const uint8_t *cmd, uint8_t cmdsize, bool is_response) {
}

static const char *identify_transponder_hitag2(uint32_t uid) {

    switch (uid) {
        case 0x53505910:
            return "IMMO Key emulator";
            break;
        case 0x5accc811:
        case 0x5accc821:
        case 0x5accc831:
        case 0x5accc841:
        case 0x5accc851:
        case 0x5accc861:
        case 0x5accc871:
        case 0x5accc881:
        case 0x5accc891:
        case 0x5accc8B1:
            return "CN3 Tango Key emulator";
    }
    return "";
}

static bool getHitag2Uid(uint32_t *uid) {

    lf_hitag_data_t packet;
    memset(&packet, 0, sizeof(packet));
    packet.cmd = RHT2F_UID_ONLY;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAG_READER, (uint8_t *) &packet, sizeof(packet));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_HITAG_READER, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return false;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - failed getting UID");
        return false;
    }

    if (uid) {
        *uid = bytes_to_num(resp.data.asBytes, HITAG_UID_SIZE);
    }
    return true;
}

static int CmdLFHitagInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag info",
                  "Hitag 2 tag information",
                  "lf hitag info"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // read UID
    uint32_t uid = 0;
    if (getHitag2Uid(&uid) == false) {
        return PM3_ESOFT;
    }
    // how to determine Hitag types?
    // need auth / pwd to get it.
    // we could try the default key/pwd and print if successful
    // read block3,  get configuration byte.

    // common configurations.
    print_hitag2_configuration(uid, 0x06);   // pwd mode enabled / AM
    // print_hitag2_configuration(uid,  0x0E);  // crypto mode enabled / AM
    // print_hitag2_configuration(uid,  0x02);
    // print_hitag2_configuration(uid,  0x00);
    // print_hitag2_configuration(uid,  0x04);

    PrintAndLogEx(INFO, "--- " _CYAN_("Fingerprint"));
    const char *s = identify_transponder_hitag2(uid);
    if (strlen(s)) {
        PrintAndLogEx(SUCCESS, "Found... " _GREEN_("%s"), s);
    } else {
        PrintAndLogEx(INFO, _RED_("n/a"));
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdLFHitagReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag reader",
                  "Act as a Hitag 2 reader.  Look for Hitag 2 tags until Enter or the pm3 button is pressed\n",
                  "lf hitag reader\n"
                  "lf hitag reader -@   -> Continuous mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    do {
        // read UID
        uint32_t uid = 0;
        if (getHitag2Uid(&uid)) {
            PrintAndLogEx(SUCCESS, "UID.... " _GREEN_("%08X"), uid);
        }
    } while (cm && kbd_enter_pressed() == false);

    return PM3_SUCCESS;
}

static int CmdLFHitagRd(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag read",
                  "Read Hitag memory. It support Hitag S and Hitag 2\n\n"
                  "  Password mode:\n"
                  "    - default key 4D494B52 (MIKR)\n\n"
                  "  Crypto mode: \n"
                  "    - key format ISK high + ISK low\n"
                  "    - default key 4F4E4D494B52 (ONMIKR)\n"
                  ,
                  "  lf hitag read --hts                         -> Hitag S, plain mode\n"
                  "  lf hitag read --hts --nrar 0102030411223344 -> Hitag S, challenge mode\n"
                  "  lf hitag read --hts --crypto                -> Hitag S, crypto mode, def key\n"
                  "  lf hitag read --hts -k 4F4E4D494B52         -> Hitag S, crypto mode\n\n"
                  "  lf hitag read --ht2 --pwd                   -> Hitag 2, pwd mode, def key\n"
                  "  lf hitag read --ht2 -k 4D494B52             -> Hitag 2, pwd mode\n"
                  "  lf hitag read --ht2 --nrar 0102030411223344 -> Hitag 2, challenge mode\n"
                  "  lf hitag read --ht2 --crypto                -> Hitag 2, crypto mode, def key\n"
                  "  lf hitag read --ht2 -k 4F4E4D494B52         -> Hitag 2, crypto mode\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s", "hts", "Hitag S"),
        arg_lit0("2", "ht2", "Hitag 2"),
        arg_lit0(NULL, "pwd", "password mode"),
        arg_str0(NULL, "nrar", "<hex>", "nonce / answer writer, 8 hex bytes"),
        arg_lit0(NULL, "crypto", "crypto mode"),
        arg_str0("k", "key", "<hex>", "key, 4 or 6 hex bytes"),
// currently pm3 fw reads all the memory anyway
//        arg_int1("p", "page", "<dec>", "page address to write to"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool use_ht1 = false; // not yet implemented
    bool use_hts = arg_get_lit(ctx, 1);
    bool use_ht2 = arg_get_lit(ctx, 2);
    bool use_htm = false; // not yet implemented

    bool use_plain = false;
    bool use_pwd = arg_get_lit(ctx, 3);
    uint8_t nrar[8];
    int nalen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 4), nrar, sizeof(nrar), &nalen);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    bool use_nrar = nalen > 0;
    bool use_crypto = arg_get_lit(ctx, 5);

    uint8_t key[6];
    int keylen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 6), key, sizeof(key), &keylen);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
//    uint32_t page = arg_get_u32_def(ctx, 6, 0);

    CLIParserFree(ctx);

    // sanity checks
    if ((use_ht1 + use_ht2 + use_hts + use_htm) > 1) {
        PrintAndLogEx(ERR, "error, specify only one Hitag type");
        return PM3_EINVARG;
    }
    if ((use_ht1 + use_ht2 + use_hts + use_htm) == 0) {
        PrintAndLogEx(ERR, "error, specify one Hitag type");
        return PM3_EINVARG;
    }

    if (keylen != 0 && keylen != 4 && keylen != 6) {
        PrintAndLogEx(WARNING, "Wrong KEY len expected 0, 4 or 6, got %d", keylen);
        return PM3_EINVARG;
    }

    if (nalen != 0 && nalen != 8) {
        PrintAndLogEx(WARNING, "Wrong NR/AR len expected 0 or 8, got %d", nalen);
        return PM3_EINVARG;
    }

    // complete options
    if (keylen == 4) {
        use_pwd = true;
    }
    if (keylen == 6) {
        use_crypto = true;
    }
    if ((keylen == 0) && use_pwd) {
        memcpy(key, "MIKR", 4);
        keylen = 4;
    }
    if ((keylen == 0) && use_crypto) {
        memcpy(key, "ONMIKR", 6);
        keylen = 6;
    }

    // check coherence
    uint8_t foo = (use_plain + use_pwd + use_nrar + use_crypto);
    if (foo > 1) {
        PrintAndLogEx(WARNING, "Specify only one authentication mode");
        return PM3_EINVARG;
    } else if (foo == 0) {
        if (use_hts) {
            use_plain = true;
        } else {
            PrintAndLogEx(WARNING, "Specify one authentication mode");
            return PM3_EINVARG;
        }
    }

    if (use_hts && use_pwd) { // not sure for the other types...
        PrintAndLogEx(WARNING, "Chosen Hitag type does not have Password mode");
        return PM3_EINVARG;
    }

    if (use_ht2 && use_plain) { // not sure for the other types...
        PrintAndLogEx(WARNING, "Chosen Hitag type does not have Plain mode");
        return PM3_EINVARG;
    }

    lf_hitag_data_t packet;
    memset(&packet, 0, sizeof(packet));

    int pm3cmd;
    if (use_hts) {
        // plain mode?
        pm3cmd = CMD_LF_HITAGS_READ;
    } else if (use_hts && use_nrar) {
        pm3cmd = CMD_LF_HITAGS_READ;
        packet.cmd = RHTSF_CHALLENGE;
        memcpy(packet.NrAr, nrar, sizeof(packet.NrAr));

    } else if (use_hts && use_crypto) {
        pm3cmd = CMD_LF_HITAGS_READ;
        packet.cmd = RHTSF_KEY;
        memcpy(packet.key, key, sizeof(packet.key));

    } else if (use_ht2 && use_pwd) {
        pm3cmd = CMD_LF_HITAG_READER;
        packet.cmd = RHT2F_PASSWORD;
        memcpy(packet.pwd, key, sizeof(packet.pwd));

    } else if (use_ht2 && use_nrar) {
        pm3cmd = CMD_LF_HITAG_READER;
        packet.cmd = RHT2F_AUTHENTICATE;
        memcpy(packet.NrAr, nrar, sizeof(packet.NrAr));
    } else if (use_ht2 && use_crypto) {

        pm3cmd = CMD_LF_HITAG_READER;
        packet.cmd = RHT2F_CRYPTO;
        memcpy(packet.key, key, sizeof(packet.key));
    } else {
        PrintAndLogEx(WARNING, "Sorry, not yet implemented");
        return PM3_ENOTIMPL;
    }

    clearCommandBuffer();
    SendCommandNG(pm3cmd, (uint8_t *)&packet, sizeof(packet));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(pm3cmd, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - hitag failed");
        return PM3_ESOFT;
    }

    if (use_nrar) {
        return PM3_SUCCESS;
    }

    uint8_t *data = resp.data.asBytes;
    uint32_t uid = bytes_to_num(data, HITAG_UID_SIZE);
    print_hitag2_configuration(uid, data[HITAG_BLOCK_SIZE * 3]);

    if (use_ht2) {
        print_hitag2_blocks(data, HITAG2_MAX_BYTE_SIZE);
        print_hitag2_paxton(data);
    } else {
        print_hex_break(data, HITAG_MAX_BYTE_SIZE, HITAG_BLOCK_SIZE);
    }
    return PM3_SUCCESS;
}

static int CmdLFHitagSCheckChallenges(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag cc",
                  "Check challenges, load a file with saved hitag crypto challenges and test them all.\n"
                  "The file should be 8 * 60 bytes long, the file extension defaults to " _YELLOW_("`.cc`") " ",
                  "lf hitag cc -f my_hitag_challenges"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "filename to load ( w/o ext )"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    uint8_t *data = NULL;
    size_t datalen = 0;
    int res = loadFile_safe(filename, ".cc", (void **)&data, &datalen);
    if (res == PM3_SUCCESS) {

        if (datalen % 8) {
            PrintAndLogEx(ERR, "Error, file length mismatch. Expected multiple of 8, got " _RED_("%zu"), datalen);
            free(data);
            return PM3_EINVARG;
        }
        if (datalen != (8 * 60)) {
            PrintAndLogEx(ERR, "Error, file length mismatch.  Expected 480, got " _RED_("%zu"), datalen);
            free(data);
            return PM3_EINVARG;
        }

        clearCommandBuffer();
        SendCommandNG(CMD_LF_HITAGS_TEST_TRACES, data, datalen);
    }
    if (data) {
        free(data);
    }
    return PM3_SUCCESS;
}

static int CmdLFHitag2CheckChallenges(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag ta",
                  "Test recorded authentications (replay?)",
                  "lf hitag ta"
                 );
    CLIParserFree(ctx);

    lf_hitag_data_t packet;
    memset(&packet, 0, sizeof(lf_hitag_data_t));
    packet.cmd = RHT2F_TEST_AUTH_ATTEMPTS;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAG_READER, (uint8_t *)&packet, sizeof(packet));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_HITAG_READER, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - hitag failed");
        return PM3_ESOFT;
    }

    // FIXME: doegox: not sure what this fct does and what it returns...
    return PM3_SUCCESS;
}

static int CmdLFHitagWriter(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag wrbl",
                  "Write a page in Hitag memory. It support HitagS and Hitag 2\n"
                  "  Password mode:\n"
                  "    - default key 4D494B52 (MIKR)\n\n"
                  "  Crypto mode: \n"
                  "    - key format ISK high + ISK low\n"
                  "    - default key 4F4E4D494B52 (ONMIKR)\n"
                  ,
                  "  lf hitag wrbl --hts -p 6 -d 01020304                         -> HitagS, plain mode\n"
                  "  lf hitag wrbl --hts -p 6 -d 01020304 --nrar 0102030411223344 -> HitagS, challenge mode\n"
                  "  lf hitag wrbl --hts -p 6 -d 01020304 --crypto                -> HitagS, crypto mode, def key\n"
                  "  lf hitag wrbl --hts -p 6 -d 01020304 -k 4F4E4D494B52         -> HitagS, crypto mode\n\n"
                  "  lf hitag wrbl --ht2 -p 6 -d 01020304 --pwd                   -> Hitag 2, pwd mode, def key\n"
                  "  lf hitag wrbl --ht2 -p 6 -d 01020304 -k 4D494B52             -> Hitag 2, pwd mode\n"
                  "  lf hitag wrbl --ht2 -p 6 -d 01020304 --nrar 0102030411223344 -> Hitag 2, challenge mode\n"
                  "  lf hitag wrbl --ht2 -p 6 -d 01020304 --crypto                -> Hitag 2, crypto mode, def key\n"
                  "  lf hitag wrbl --ht2 -p 6 -d 01020304 -k 4F4E4D494B52         -> Hitag 2, crypto mode\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s", "hts", "Hitag S"),
        arg_lit0("2", "ht2", "Hitag 2"),
        arg_lit0(NULL, "pwd", "password mode"),
        arg_str0(NULL, "nrar", "<hex>", "nonce / answer writer, 8 hex bytes"),
        arg_lit0(NULL, "crypto", "crypto mode"),
        arg_str0("k", "key", "<hex>", "key, 4 or 6 hex bytes"),
        arg_int1("p", "page", "<dec>", "page address to write to"),
        arg_str1("d", "data", "<hex>", "data, 4 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool use_ht1 = false; // not yet implemented
    bool use_hts = arg_get_lit(ctx, 1);
    bool use_ht2 = arg_get_lit(ctx, 2);
    bool use_htm = false; // not yet implemented

    bool use_plain = false;
    bool use_pwd = arg_get_lit(ctx, 3);
    uint8_t nrar[8];
    int nalen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 4), nrar, sizeof(nrar), &nalen);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    bool use_nrar = nalen > 0;
    bool use_crypto = arg_get_lit(ctx, 5);

    uint8_t key[6];
    int keylen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 6), key, sizeof(key), &keylen);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int page = arg_get_int_def(ctx, 7, 0);

    uint8_t data[4];
    int dlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 8), data, sizeof(data), &dlen);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    // sanity checks
    if ((use_ht1 + use_ht2 + use_hts + use_htm) > 1) {
        PrintAndLogEx(ERR, "error, specify only one Hitag type");
        return PM3_EINVARG;
    }
    if ((use_ht1 + use_ht2 + use_hts + use_htm) == 0) {
        PrintAndLogEx(ERR, "error, specify one Hitag type");
        return PM3_EINVARG;
    }

    if (keylen != 0 && keylen != 4 && keylen != 6) {
        PrintAndLogEx(WARNING, "Wrong KEY len expected 0, 4 or 6, got %d", keylen);
        return PM3_EINVARG;
    }

    if (dlen != sizeof(data)) {
        PrintAndLogEx(WARNING, "Wrong DATA len expected 4, got %d", dlen);
        return PM3_EINVARG;
    }

    if (nalen != 0 && nalen != 8) {
        PrintAndLogEx(WARNING, "Wrong NR/AR len expected 0 or 8, got %d", nalen);
        return PM3_EINVARG;
    }

    // complete options
    if (keylen == 4) {
        use_pwd = true;
    }
    if (keylen == 6) {
        use_crypto = true;
    }
    if ((keylen == 0) && use_pwd) {
        memcpy(key, "MIKR", 4);
        keylen = 4;
    }
    if ((keylen == 0) && use_crypto) {
        memcpy(key, "ONMIKR", 6);
        keylen = 6;
    }

    // check coherence
    uint8_t foo = (use_plain + use_pwd + use_nrar + use_crypto);
    if (foo > 1) {
        PrintAndLogEx(WARNING, "Specify only one authentication mode");
        return PM3_EINVARG;
    } else if (foo == 0) {
        if (use_hts) {
            use_plain = true;
        } else {
            PrintAndLogEx(WARNING, "Specify one authentication mode");
            return PM3_EINVARG;
        }
    }

    if (use_hts && use_pwd) { // not sure for the other types...
        PrintAndLogEx(WARNING, "Chosen Hitag type does not have Password mode");
        return PM3_EINVARG;
    }

    if (use_ht2 && use_plain) { // not sure for the other types...
        PrintAndLogEx(WARNING, "Chosen Hitag type does not have Plain mode");
        return PM3_EINVARG;
    }

    lf_hitag_data_t packet;
    memset(&packet, 0, sizeof(packet));

    if (use_hts && use_plain) {
        packet.cmd = WHTSF_PLAIN;
        packet.page = page;
        memcpy(packet.data, data, sizeof(data));

        PrintAndLogEx(INFO, "Write to " _YELLOW_("Hitag S") " in Plain mode");

    } else if (use_hts && use_nrar) {
        packet.cmd = WHTSF_CHALLENGE;
        memcpy(packet.NrAr, nrar, sizeof(packet.NrAr));
        memcpy(packet.data, data, sizeof(data));
        // iceman:  No page in Hitag S ?
        PrintAndLogEx(INFO, "Authenticating to " _YELLOW_("Hitag S") " in Challenge mode");

    } else if (use_hts && use_crypto) {
        packet.cmd = WHTSF_KEY;
        memcpy(packet.key, key, sizeof(packet.key));
        memcpy(packet.data, data, sizeof(data));
        // iceman:  No page in Hitag S ?
        PrintAndLogEx(INFO, "Authenticating to " _YELLOW_("Hitag S") " in Crypto mode");

    } else if (use_ht2 && use_pwd) {
        packet.cmd = WHT2F_PASSWORD;
        packet.page = page;
        memcpy(packet.pwd, key, sizeof(packet.pwd));
        memcpy(packet.data, data, sizeof(data));
        PrintAndLogEx(INFO, "Authenticating to " _YELLOW_("Hitag 2") " in Password mode");

    } else if (use_ht2 && use_crypto) {
        packet.cmd = WHT2F_CRYPTO;
        packet.page = page;
        memcpy(packet.key, key, sizeof(packet.key));
        memcpy(packet.data, data, sizeof(data));
        PrintAndLogEx(INFO, "Authenticating to " _YELLOW_("Hitag 2") " in Crypto mode");

    } else {
        PrintAndLogEx(WARNING, "Sorry, not yet implemented");
        return PM3_ENOTIMPL;
    }

    clearCommandBuffer();

    if (use_ht2) {
        SendCommandNG(CMD_LF_HITAG2_WRITE, (uint8_t *)&packet, sizeof(packet));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_LF_HITAG2_WRITE, &resp, 4000) == false) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            return PM3_ETIMEOUT;
        }

        if (resp.status == PM3_ETEAROFF) {
            PrintAndLogEx(INFO, "Writing tear off triggered");
            return PM3_SUCCESS;
        }

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Write ( " _RED_("fail") " )");
            return resp.status;
        }

    } else {

        SendCommandNG(CMD_LF_HITAGS_WRITE, (uint8_t *)&packet, sizeof(packet));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_LF_HITAGS_WRITE, &resp, 4000) == false) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            return PM3_ETIMEOUT;
        }

        if (resp.status == PM3_ETEAROFF) {
            PrintAndLogEx(INFO, "Writing tear off triggered");
            return PM3_SUCCESS;
        }

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Write ( " _RED_("fail") " )");
            return resp.status;
        }
    }

    PrintAndLogEx(SUCCESS, "Write ( " _GREEN_("ok") " )");
    return PM3_SUCCESS;
}

static int CmdLFHitag2Dump(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag dump",
                  "Read all Hitag 2 card memory and save to file\n"
                  "Crypto mode key format: ISK high + ISK low,  4F4E4D494B52 (ONMIKR)\n"
                  "Password mode, default key 4D494B52 (MIKR)\n",
                  "lf hitag dump --pwd                -> use def pwd\n"
                  "lf hitag dump -k 4D494B52          -> pwd mode\n"
                  "lf hitag dump --crypto             -> use def crypto\n"
                  "lf hitag dump -k 4F4E4D494B52      -> crypto mode\n"
                  "lf hitag dump --nrar 0102030411223344\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "pwd", "password mode"),
        arg_str0(NULL, "nrar", "<hex>", "nonce / answer reader, 8 hex bytes"),
        arg_lit0(NULL, "crypto", "crypto mode"),
        arg_str0("k", "key", "<hex>", "key, 4 or 6 hex bytes"),
        arg_str0("f", "file", "<fn>", "specify file name"),
        arg_lit0(NULL, "ns", "no save to file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool use_ht1 = false; // not yet implemented
    bool use_hts = false; // not yet implemented
    bool use_ht2 = true;
    bool use_htm = false; // not yet implemented

    bool use_plain = false;
    bool use_pwd = arg_get_lit(ctx, 1);
    uint8_t nrar[8];
    int nalen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), nrar, sizeof(nrar), &nalen);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    bool use_nrar = nalen > 0;
    bool use_crypto = arg_get_lit(ctx, 3);

    uint8_t key[HITAG_NRAR_SIZE];
    int keylen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 4), key, sizeof(key), &keylen);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool nosave = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    // sanity checks
    if ((use_ht1 + use_ht2 + use_hts + use_htm) > 1) {
        PrintAndLogEx(ERR, "error, specify only one Hitag type");
        return PM3_EINVARG;
    }
    if ((use_ht1 + use_ht2 + use_hts + use_htm) == 0) {
        PrintAndLogEx(ERR, "error, specify one Hitag type");
        return PM3_EINVARG;
    }

    if (keylen != 0 &&
            keylen != HITAG_PASSWORD_SIZE &&
            keylen != HITAG_CRYPTOKEY_SIZE &&
            keylen != HITAG_NRAR_SIZE) {
        PrintAndLogEx(WARNING, "Wrong KEY len expected (0,4,6,8) got %d", keylen);
        return PM3_EINVARG;
    }

    // complete options
    if (keylen == HITAG_PASSWORD_SIZE) {
        use_pwd = true;
    }
    if (keylen == HITAG_CRYPTOKEY_SIZE) {
        use_crypto = true;
    }
    if (keylen == HITAG_NRAR_SIZE) {
        use_nrar = true;
        memcpy(nrar, key, sizeof(nrar));
    }

    // Set default key / pwd
    if ((keylen == 0) && use_pwd) {
        memcpy(key, "MIKR", HITAG_PASSWORD_SIZE);
        keylen = HITAG_PASSWORD_SIZE;
    }
    if ((keylen == 0) && use_crypto) {
        memcpy(key, "ONMIKR", HITAG_CRYPTOKEY_SIZE);
        keylen = HITAG_CRYPTOKEY_SIZE;
    }

    // check coherence
    uint8_t foo = (use_plain + use_pwd + use_nrar + use_crypto);
    if (foo > 1) {
        PrintAndLogEx(WARNING, "Specify only one authentication mode");
        return PM3_EINVARG;
    } else if (foo == 0) {
        if (use_hts) {
            use_plain = true;
        } else {
            PrintAndLogEx(WARNING, "Specify one authentication mode");
            return PM3_EINVARG;
        }
    }

    if (use_hts && use_pwd) { // not sure for the other types...
        PrintAndLogEx(WARNING, "Chosen Hitag type does not have Password mode");
        return PM3_EINVARG;
    }

    if (use_ht2 && use_plain) { // not sure for the other types...
        PrintAndLogEx(WARNING, "Chosen Hitag type does not have Plain mode");
        return PM3_EINVARG;
    }

    uint32_t uid = 0;

    PacketResponseNG resp;
    uint8_t *data = NULL;

    lf_hitag_data_t packet;
    memset(&packet, 0, sizeof(packet));

    if (use_ht2 && use_pwd) {
        packet.cmd = RHT2F_PASSWORD;
        memcpy(packet.pwd, key, sizeof(packet.pwd));
        PrintAndLogEx(INFO, "Authenticating to " _YELLOW_("Hitag 2") " in Password mode");

    } else if (use_ht2 && use_crypto) {
        packet.cmd = RHT2F_CRYPTO;
        memcpy(packet.key, key, sizeof(packet.key));
        PrintAndLogEx(INFO, "Authenticating to " _YELLOW_("Hitag 2") " in Crypto mode");

    } else if (use_ht2 && use_nrar) {


        memcpy(packet.NrAr, nrar, sizeof(packet.NrAr));

        PrintAndLogEx(INFO, _YELLOW_("Hitag 2") " - Challenge mode (NrAr)");

        uint64_t t1 = msclock();

        clearCommandBuffer();
        SendCommandNG(CMD_LF_HITAG2_CRACK, (uint8_t *) &packet, sizeof(packet));

        // loop
        uint8_t attempt = 30;
        do {

            PrintAndLogEx(INPLACE, "Attack 1 running...");
            fflush(stdout);

            if (WaitForResponseTimeout(CMD_LF_HITAG2_CRACK, &resp, 1000) == false) {
                attempt--;
                continue;
            }

            lf_hitag_crack_response_t *payload = (lf_hitag_crack_response_t *)resp.data.asBytes;

            if (resp.status == PM3_SUCCESS) {
                PrintAndLogEx(NORMAL, " ( %s )", _GREEN_("ok"));
                data = payload->data;

                t1 = msclock() - t1;
                PrintAndLogEx(SUCCESS, "\ntime " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);
                goto out;
            }

            // error codes
            switch (payload->status) {
                case -1: {
                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(FAILED, "Couldn't select tag!");
                    return PM3_ESOFT;
                }
                case -2: {
                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(FAILED, "Cannot find a valid encrypted command!");
                    return PM3_ESOFT;
                }
                case -3: {
                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(FAILED, "Cannot find encrypted 'read page0' command!");
                    return PM3_ESOFT;
                }
                case -4: {
                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(FAILED, "Partial data extraction!");
                    continue;
                }
            }

        } while (attempt);

        if (attempt == 0) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            return PM3_ESOFT;
        }

        t1 = msclock() - t1;
        PrintAndLogEx(SUCCESS, "\ntime " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);

        goto out;

    } else {
        PrintAndLogEx(WARNING, "Sorry, not yet implemented");
        return PM3_ENOTIMPL;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAG_READER, (uint8_t *) &packet, sizeof(packet));

    if (WaitForResponseTimeout(CMD_LF_HITAG_READER, &resp, 5000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - hitag failed");
        return resp.status;
    }

    data = resp.data.asBytes;

out:


    // block3, 1 byte
    uid = bytes_to_num(data, HITAG_UID_SIZE);

    if (use_ht2) {
        print_hitag2_configuration(uid, data[HITAG_BLOCK_SIZE * 3]);
        print_hitag2_blocks(data, HITAG2_MAX_BYTE_SIZE);
        print_hitag2_paxton(data);
    } else {
        PrintAndLogEx(INFO, "No memory printing available");
    }

    if (nosave) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "Called with no save option");
        PrintAndLogEx(NORMAL, "");
        return PM3_SUCCESS;
    }

    if (fnlen < 1) {
        char *fptr = filename;
        fptr += snprintf(filename, sizeof(filename), "lf-hitag-");
        FillFileNameByUID(fptr, data, "-dump", HITAG_UID_SIZE);
    }

    pm3_save_dump(filename, data, HITAG2_MAX_BYTE_SIZE, jsfHitag);
    return PM3_SUCCESS;
}

static int CmdLFHitagView(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag view",
                  "Print a HITAG dump file (bin/eml/json)",
                  "lf hitag view -f lf-hitag-01020304-dump.bin"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, HITAG2_MAX_BYTE_SIZE);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (bytes_read < HITAG2_MAX_BYTE_SIZE) {
        PrintAndLogEx(ERR, "Error, dump file is too small");
        free(dump);
        return PM3_ESOFT;
    }

    if (verbose) {
        // block3, 1 byte
        uint8_t config = dump[HITAG2_CONFIG_OFFSET];
        uint32_t uid = bytes_to_num(dump, HITAG_UID_SIZE);
        print_hitag2_configuration(uid, config);
        print_hitag2_paxton(dump);
    }
    print_hitag2_blocks(dump, HITAG2_MAX_BYTE_SIZE);
    free(dump);
    return PM3_SUCCESS;
}

static int CmdLFHitagEload(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag eload",
                  "Loads hitag tag dump into emulator memory on device",
                  "lf hitag eload -2 -f lf-hitag-11223344-dump.bin\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify dump filename"),
        arg_lit0("1", "ht1", "Card type Hitag 1"),
        arg_lit0("2", "ht2", "Card type Hitag 2"),
        arg_lit0("s", "hts", "Card type Hitag S"),
        arg_lit0("m", "htm", "Card type Hitag \xce\xbc"), // μ
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool use_ht1 = arg_get_lit(ctx, 2);
    bool use_ht2 = arg_get_lit(ctx, 3);
    bool use_hts = arg_get_lit(ctx, 4);
    bool use_htm = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if ((use_ht1 + use_ht2 + use_hts + use_htm) > 1) {
        PrintAndLogEx(ERR, "error, specify only one Hitag type");
        return PM3_EINVARG;
    }
    if ((use_ht1 + use_ht2 + use_hts + use_htm) == 0) {
        PrintAndLogEx(ERR, "error, specify one Hitag type");
        return PM3_EINVARG;
    }

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = (4 * 64);
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, (4 * 64));
    if (res != PM3_SUCCESS) {
        return res;
    }

    // check dump len..
    if (bytes_read == HITAG2_MAX_BYTE_SIZE || bytes_read == 4 * 64) {

        lf_hitag_t *payload =  calloc(1, sizeof(lf_hitag_t) + bytes_read);

        if (use_ht1)
            payload->type = 1;
        if (use_ht2)
            payload->type = 2;
        if (use_hts)
            payload->type = 3;
        if (use_htm)
            payload->type = 4;

        payload->len = bytes_read;
        memcpy(payload->data, dump, bytes_read);

        clearCommandBuffer();
        SendCommandNG(CMD_LF_HITAG_ELOAD, (uint8_t *)payload, 3 + bytes_read);
        free(payload);
    } else {
        PrintAndLogEx(ERR, "error, wrong dump file size. got %zu", bytes_read);
    }

    free(dump);
    return PM3_SUCCESS;
}

static int CmdLFHitagEview(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag eview",
                  "It displays emulator memory",
                  "lf hitag eview\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    int bytes = HITAG2_MAX_BYTE_SIZE;

    // reserve memory
    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "Downloading " _YELLOW_("%u") " bytes from emulator memory...", bytes);
    if (GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return PM3_ETIMEOUT;
    }

    if (verbose) {
        // block3, 1 byte
        uint8_t config = dump[HITAG2_CONFIG_OFFSET];
        uint32_t uid = bytes_to_num(dump, HITAG_UID_SIZE);
        print_hitag2_configuration(uid, config);
        print_hitag2_paxton(dump);
    }
    print_hitag2_blocks(dump, HITAG2_MAX_BYTE_SIZE);
    free(dump);
    return PM3_SUCCESS;
}

static int CmdLFHitagSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag sim",
                  "Simulate Hitag transponder\n"
                  "You need to `lf hitag eload` first",
                  "lf hitag sim -2"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("1", "ht1", "simulate Hitag 1"),
        arg_lit0("2", "ht2", "simulate Hitag 2"),
        arg_lit0("s", "hts", "simulate Hitag S"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool use_ht1 = arg_get_lit(ctx, 1);
    bool use_ht2 = arg_get_lit(ctx, 2);
    bool use_hts = arg_get_lit(ctx, 3);
    bool use_htm = false; // not implemented yet
    CLIParserFree(ctx);

    if ((use_ht1 + use_ht2 + use_hts + use_htm) > 1) {
        PrintAndLogEx(ERR, "error, specify only one Hitag type");
        return PM3_EINVARG;
    }
    if ((use_ht1 + use_ht2 + use_hts + use_htm) == 0) {
        PrintAndLogEx(ERR, "error, specify one Hitag type");
        return PM3_EINVARG;
    }

    uint16_t cmd = CMD_LF_HITAG_SIMULATE;
//    if (use_ht1)
//        cmd = CMD_LF_HITAG1_SIMULATE;

    if (use_hts)
        cmd = CMD_LF_HITAGS_SIMULATE;

    clearCommandBuffer();
    SendCommandMIX(cmd, 0, 0, 0, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdLFHitagSniff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag sniff",
                  "Sniff the communication between reader and tag.\n"
                  "Use `lf hitag list` to view collected data.",
                  " lf hitag sniff"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " to abort sniffing");

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAG_SNIFF, NULL, 0);
    WaitForResponse(CMD_LF_HITAG_SNIFF, &resp);
    PrintAndLogEx(INFO, "Done!");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("lf hitag list")"` to view captured tracelog");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("trace save -h") "` to save tracelog for later analysing");
    return PM3_SUCCESS;
}

/*
static int CmdLFHitag2PWMDemod(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag pwmdemod",
                  "Demodulate the data in the GraphBuffer and output binary\n",
                  "lf hitag pwmdemod"
                  "lf hitag pwmdemod -t 65              --> specify first wave index\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("t", "start", "<dec>", "first wave index"),
        arg_int0(NULL, "zero", "<dec>", "Zero pulse length"),
        arg_int0(NULL, "one", "<dec>", "One pulse length"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t start_idx = (uint32_t)arg_get_int_def(ctx, 1, 0);
    uint8_t fclow = (uint8_t)arg_get_int_def(ctx, 2, 20);
    uint8_t fchigh = (uint8_t)arg_get_int_def(ctx, 3, 29);
    CLIParserFree(ctx);

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(INFO, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    size_t size = getFromGraphBuffer(bits);

    PrintAndLogEx(DEBUG, "DEBUG: (Hitag2PWM) #samples from graphbuff... %zu", size);

    if (size < 255) {
        PrintAndLogEx(INFO, "too few samples in buffer");
        free(bits);
        return PM3_ESOFT;
    }

    // TODO autodetect
    size = HitagPWMDemod(bits, size, &fchigh, &fclow, &start_idx, g_DemodBitRangeBuffer);
    if (size == 0) {
        PrintAndLogEx(FAILED, "No wave detected");
        free(bits);
        return PM3_ESOFT;
    }

    PrintAndLogEx(DEBUG, "DEBUG: start_idx... %u size... %zu", start_idx, size);

    setDemodBuffBitRange(bits, size, 0, g_DemodBitRangeBuffer);
    setClockGrid(32, start_idx);

    uint32_t total = 0;
    for (size_t i = 0; i < size; i++) {
        total += g_DemodBitRangeBuffer[i];
        PrintAndLogEx(DEBUG, "%d", g_DemodBitRangeBuffer[i]);
    }
    PrintAndLogEx(DEBUG, "Total... %d", total);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("HITAG/PWM") " ---------------------------");
    printDemodBuff(0, false, false, false);
    printDemodBuff(0, false, false, true);
    free(bits);
    return PM3_SUCCESS;
}
*/

static int CmdLFHitag2Chk(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag chk",
                  "Run dictionary key or password recovery against Hitag card.",
                  "lf hitag chk\n               -> checks for both pwd / crypto keys"
                  "lf hitag chk --crypto        -> use def dictionary\n"
                  "lf hitag chk --pwd -f my.dic -> pwd mode, custom dictionary"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "specify dictionary filename"),
        arg_lit0(NULL, "pwd", "password mode"),
        arg_lit0(NULL, "crypto", "crypto mode"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool use_pwd = arg_get_lit(ctx, 2);
    bool use_crypto = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (use_pwd + use_crypto > 1) {
        PrintAndLogEx(WARNING, "Only specify one mode");
        return PM3_EINVARG;
    }

    // no filename -> use default = ht2_default.dic
    if (fnlen == 0) {
        snprintf(filename, sizeof(filename), HITAG_DICTIONARY);
    }

    uint8_t keylen = 4;
    if (use_crypto) {
        keylen = 6;
    }

    uint64_t t1 = msclock();

    // just loop twice at max. Starting with 4 or 6.
    for (; keylen < 7; keylen += 2) {
        // load keys
        uint8_t *keys = NULL;
        uint32_t key_count = 0;
        int res = loadFileDICTIONARY_safe(filename, (void **)&keys, keylen, &key_count);
        if (res != PM3_SUCCESS || key_count == 0 || keys == NULL) {
            PrintAndLogEx(WARNING, "no keys found in file");
            if (keys != NULL) {
                free(keys);
            }
            return res;
        }

        // Main loop
        uint32_t found_idx = 0;
        int status = ht2_check_dictionary(key_count, keys, keylen, &found_idx);

        if (status == PM3_SUCCESS) {

            PrintAndLogEx(NORMAL, "");
            if (keylen == 6) {
                PrintAndLogEx(SUCCESS, "found valid key [ " _GREEN_("%s") " ]", sprint_hex_inrow(keys + (found_idx * keylen), keylen));
            } else {
                PrintAndLogEx(SUCCESS, "found valid password [ " _GREEN_("%s") " ]", sprint_hex_inrow(keys + (found_idx * keylen), keylen));
            }
            free(keys);
            break;
        }
        free(keys);
    }

    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "\ntime in check " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);
    return PM3_SUCCESS;
}

static int CmdLFHitag2Lookup(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag lookup",
                  "This command take sniffed trace data and try to recovery a Hitag 2 crypto key.\n"
                  " You can either\n"
                  " - verify that NR/AR matches a known crypto key\n"
                  " - verify if NR/AR matches a known 6 byte crypto key in a dictionary",
                  "lf hitag lookup --uid 11223344 --nr 73AA5A62 --ar EAB8529C -k 010203040506 -> check key\n"
                  "lf hitag lookup --uid 11223344 --nr 73AA5A62 --ar EAB8529C                 -> use def dictionary\n"
                  "lf hitag lookup --uid 11223344 --nr 73AA5A62 --ar EAB8529C -f my.dic       -> use custom dictionary\n"
                  "lf hitag lookup --uid 11223344 --nrar 73AA5A62EAB8529C"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "specify dictionary filename"),
        arg_str0("k", "key", "<hex>", "specify known cryptokey as 6 bytes"),
        arg_str1("u", "uid", "<hex>", "specify UID as 4 hex bytes"),
        arg_str0(NULL, "nr", "<hex>", "specify nonce as 4 hex bytes"),
        arg_str0(NULL, "ar", "<hex>", "specify answer as 4 hex bytes"),
        arg_str0(NULL, "nrar", "<hex>", "specify nonce / answer as 8 hex bytes"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int inkeylen = 0;
    uint8_t inkey[6] = {0};
    CLIGetHexWithReturn(ctx, 2, inkey, &inkeylen);

    int ulen = 0;
    uint8_t uidarr[4] = {0};
    CLIGetHexWithReturn(ctx, 3, uidarr, &ulen);

    int nlen = 0;
    uint8_t narr[4] = {0};
    CLIGetHexWithReturn(ctx, 4, narr, &nlen);

    int alen = 0;
    uint8_t aarr[4] = {0};
    CLIGetHexWithReturn(ctx, 5, aarr, &alen);

    int nalen = 0;
    uint8_t nrar[8] = {0};
    CLIGetHexWithReturn(ctx, 6, nrar, &nalen);

    CLIParserFree(ctx);

    // sanity checks
    if (inkeylen && inkeylen != 6) {
        PrintAndLogEx(INFO, "Key wrong length. expected 6, got %i", inkeylen);
        return PM3_EINVARG;
    }

    if (ulen && ulen != 4) {
        PrintAndLogEx(INFO, "UID wrong length. expected 4, got %i", ulen);
        return PM3_EINVARG;
    }

    if (nlen && nlen != 4) {
        PrintAndLogEx(INFO, "Nr wrong length. expected 4, got %i", nlen);
        return PM3_EINVARG;
    }

    if (alen && alen != 4) {
        PrintAndLogEx(INFO, "Ar wrong length. expected 4, got %i", alen);
        return PM3_EINVARG;
    }

    if (nalen && nalen != 8) {
        PrintAndLogEx(INFO, "NrAr wrong length. expected 8, got %i", nalen);
        return PM3_EINVARG;
    }

    // Iceman note:
    //  - key, uid and Nr1  is alway dentoed as LSB/LE order
    //  - Ar1  is NOT.   It is in BE/MSB everywhere.
    //  - At1  is NOT.   It is in BE/MSB everywhere.
    //  - crypto stream generated is in BE/MSB order  in Pm3 code.
    //  - crypto state is in ?
    //  - lfsr state is in ?
    //
    //  Different implementations handles internally the state either in MSB or LSB.
    //  Something to keep an eye for when looking at code.
    //
    // Termology:
    //  cs / hstate.shiftregister / crypto state   = same
    //  lsfr  = some implementations mixes cs and lsfr into one and only use the state.  Some differentiate between them.
    //          usually the key recovery functions under /tools/hitag2crack
    //  IV / Nonce Reader 1 / Nr1  = same  (clear text),   always 00 00 00 00 in PM3 code when acting as reader.
    //  Answer Reader 1 / Ar1  = encrypted and BE/MSB,  +32, the clear text is always FF FF FF FF.
    //  Answer Tag 1  / At1    = encrypted and BE/MSB,  +32,

    /*
    When initializer the crypto engine

    1. UID: 11223344
    2. KEY: FFFF143624FF
    3. NONCE / IV: 00 00 00 00
    3. NONCE / IV: 3B 6F 08 4D

    now you have a CS / Shiftregister / state  = crypto stream?

    Ar1 - first encrypted   crypto stream ^ 0xFFFFFFFF
    4. Ar1:   96 7A 6F 2A  ^ FF FF FF FF  == 69 85 90 D5

    */
    rev_msb_array(inkey, sizeof(inkey));
    rev_msb_array(uidarr, sizeof(uidarr));
    rev_msb_array(narr, sizeof(narr));
    rev_msb_array(nrar, 4);


    // Little Endian
    uint64_t knownkey = MemLeToUint6byte(inkey);
    uint32_t uid = MemLeToUint4byte(uidarr);

    uint32_t nr;
    // Big Endian
    uint32_t ar;

    if (nlen && alen) {
        nr = MemLeToUint4byte(narr);
        ar = MemBeToUint4byte(aarr);
    } else if (nalen) {
        nr = MemLeToUint4byte(nrar);
        ar = MemBeToUint4byte(nrar + 4);
    } else {
        PrintAndLogEx(INFO, "No nr or ar was supplied");
        return PM3_EINVARG;
    }

    uint32_t iv = nr;


    if (inkeylen) {

        PrintAndLogEx(DEBUG, "UID... %08" PRIx32, uid);
        PrintAndLogEx(DEBUG, "IV.... %08" PRIx32, iv);
        PrintAndLogEx(DEBUG, "Key... %012" PRIx64, knownkey);

        //  initialize state
        hitag_state_t hstate;
        ht2_hitag2_init_ex(&hstate, knownkey, uid, iv);

        // get 32 bits of crypto stream.
        uint32_t cbits = ht2_hitag2_nstep(&hstate, 32);
        bool isok = (ar == (cbits ^ 0xFFFFFFFF));

        PrintAndLogEx(DEBUG, "state.shiftreg...... %012" PRIx64, hstate.shiftreg);
        PrintAndLogEx(DEBUG, "state.lfsr.......... %012" PRIx64, hstate.lfsr);
        PrintAndLogEx(DEBUG, "c bits.............. %08x", cbits);
        PrintAndLogEx(DEBUG, "c-bits ^ FFFFFFFF... %08x", cbits ^ 0xFFFFFFFF);
        PrintAndLogEx(DEBUG, "Ar.................. %08" PRIx32 "  ( %s )", ar, (isok) ? _GREEN_("ok") : _RED_("fail"));

        PrintAndLogEx(INFO, "Nr/Ar match key ( %s )", (isok) ? _GREEN_("ok") : _RED_("fail"));
        PrintAndLogEx(NORMAL, "");
        return PM3_SUCCESS;
    }

    if (fnlen == 0) {
        snprintf(filename, sizeof(filename), HITAG_DICTIONARY);
    }

    // load keys
    uint8_t *keys = NULL;
    uint32_t key_count = 0;
    int res = loadFileDICTIONARY_safe(filename, (void **)&keys, HITAG_CRYPTOKEY_SIZE, &key_count);
    if (res != PM3_SUCCESS || key_count == 0 || keys == NULL) {
        PrintAndLogEx(WARNING, "no keys found in file");
        if (keys != NULL) {
            free(keys);
        }
        return res;
    }

    bool found = false;
    for (uint32_t i = 0; i < key_count; i++) {

        uint8_t *pkey = keys + (i * HITAG_CRYPTOKEY_SIZE);
        uint64_t mykey = MemLeToUint6byte(pkey);
        mykey = REV64(mykey);

        hitag_state_t hs2;
        ht2_hitag2_init_ex(&hs2, mykey, uid, iv);

        uint32_t tbits = ht2_hitag2_nstep(&hs2, 32);
        if ((ar ^ tbits) == 0xFFFFFFFF) {
            PrintAndLogEx(SUCCESS, "Found valid key [ " _GREEN_("%s")" ]", sprint_hex_inrow(pkey, HITAG_CRYPTOKEY_SIZE));
            found = true;
            break;
        }

        if (g_debugMode) {
            PrintAndLogEx(DEBUG, " tbits... %08" PRIx32 " Known ar... %08" PRIx32, tbits, ar);
            PrintAndLogEx(DEBUG, " 0xFFFFFFFF ^ tbits... %08" PRIx32, tbits ^ 0xFFFFFFFF);
            PrintAndLogEx(DEBUG, " 0xFFFFFFFF ^ ar...... %08" PRIx32, ar ^ 0xFFFFFFFF);
            PrintAndLogEx(DEBUG, " tbits ^ ar........... %08" PRIx32 " ( 0xFFFFFFFF )",  ar ^ tbits);
        }
    }

    free(keys);

    if (found == false) {
        PrintAndLogEx(WARNING, "check failed");
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdLFHitag2Crack2(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag crack2",
                  "This command tries to recover 2048 bits of Hitag 2 crypto stream data.\n",
                  "lf hitag crack2 --nrar 73AA5A62EAB8529C"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "nrar", "<hex>", "specify nonce / answer as 8 hex bytes"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int nalen = 0;
    uint8_t nrar[8] = {0};
    CLIGetHexWithReturn(ctx, 1, nrar, &nalen);
    CLIParserFree(ctx);

    // sanity checks
    if (nalen && nalen != 8) {
        PrintAndLogEx(INFO, "NrAr wrong length. expected 8, got %i", nalen);
        return PM3_EINVARG;
    }

    lf_hitag_data_t packet;
    memset(&packet, 0, sizeof(packet));
    memcpy(packet.NrAr, nrar, sizeof(packet.NrAr));

    PrintAndLogEx(INFO, _YELLOW_("Hitag 2") " - Nonce replay and length extension attack ( Crack2 )");

    uint64_t t1 = msclock();

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAG2_CRACK_2, (uint8_t *) &packet, sizeof(packet));

    // loop
    uint8_t attempt = 50;
    do {

//        PrintAndLogEx(INPLACE, "Attack 2 running...");
//        fflush(stdout);

        if (WaitForResponseTimeout(CMD_LF_HITAG2_CRACK_2, &resp, 1000) == false) {
            attempt--;
            continue;
        }

        if (resp.status == PM3_SUCCESS) {

            PrintAndLogEx(SUCCESS, "--------------------- " _CYAN_("Recovered Keystream") " ----------------------");
            lf_hitag_crack_response_t *payload = (lf_hitag_crack_response_t *)resp.data.asBytes;

            for (int i = 0; i < 256; i += 32) {
                PrintAndLogEx(SUCCESS, "%s", sprint_hex_inrow(payload->data + i, 32));
            }
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS, "Nonce replay and length extension attack ( %s )", _GREEN_("ok"));
            PrintAndLogEx(HINT, "try running `tools/hitag2crack/crack2/ht2crack2search <FILE_with_above_bytes>");
            break;
        } else {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(FAILED, "Nonce replay and length extension attack ( %s )", _RED_("fail"));
            break;
        }

    } while (attempt);

    if (attempt == 0) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ESOFT;
    }

    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "\ntime " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);
    return PM3_SUCCESS;
}

/* Test code

   Test data and below information about it comes from
     http://www.mikrocontroller.net/attachment/102194/hitag2.c
     Written by "I.C. Wiener 2006-2007"

   "MIKRON"         =  O  N  M  I  K  R
    Key             = 4F 4E 4D 49 4B 52 - Secret 48-bit key
    Serial          = 49 43 57 69       - Serial number of the tag, transmitted in clear
    Random          = 65 6E 45 72       - Random IV, transmitted in clear
    ~28~DC~80~31    = D7 23 7F CE       - Authenticator value = inverted first 4 bytes of the keystream

   The code below must print out "D7 23 7F CE 8C D0 37 A9 57 49 C1 E6 48 00 8A B6".
   The inverse of the first 4 bytes is sent to the tag to authenticate.
   The rest is encrypted by XORing it with the subsequent keystream.
*/
static uint64_t hitag2_benchtest_gen32(void) {
    const uint64_t key = 0x4ad292b272f2;
    const uint32_t serial = 0x96eac292;
    const uint32_t initvec = 0x4ea276a6;
    hitag_state_t state;

    // init crypto
    ht2_hitag2_init_ex(&state, key, serial, initvec);

    // benchmark: generation of 32 bit stream (excludes initialisation)
    uint64_t t1 = usclock();

    (void) ht2_hitag2_nstep(&state, 32);

    t1 = usclock() - t1;
    return t1;
}

static uint64_t hitag2_benchtest(uint32_t count) {

    const uint64_t key = 0x4ad292b272f2;
    const uint32_t serial = 0x96eac292;
    const uint32_t initvec = 0x4ea276a6;

    hitag_state_t state;

    // start timer
    uint64_t t1 = usclock();

    // benchmark: initialise crypto & generate 32 bit authentication
    // adding i stops gcc optimizer moving init function call out of loop
    for (uint32_t i = 0; i < count; i++) {
        ht2_hitag2_init_ex(&state, key, serial, initvec + i);
        (void) ht2_hitag2_nstep(&state, 32);
    }

    t1 = usclock() - t1;
    return t1;
}

static uint64_t hitag2_verify_crypto_test(void) {

    uint8_t expected[16] = { 0xD7, 0x23, 0x7F, 0xCE, 0x8C, 0xD0, 0x37, 0xA9, 0x57, 0x49, 0xC1, 0xE6, 0x48, 0x00, 0x8A, 0xB6 };
    // key = 0x4ad292b272f2  after each byte has its bit order reversed
    // uid = 0x96eac292      ditto
    // initvec = 0x4ea276a6  ditto
    const uint64_t key = REV64(0x524B494D4E4FUL);
    const uint32_t uid = REV32(0x69574349);
    const uint32_t iv = REV32(0x72456E65);

    PrintAndLogEx(DEBUG, "UID... %08" PRIx32, uid);
    PrintAndLogEx(DEBUG, "IV.... %08" PRIx32, iv);
    PrintAndLogEx(DEBUG, "Key... %012" PRIx64, key);

    // initialise
    hitag_state_t state;
    ht2_hitag2_init_ex(&state, key, uid, iv);
    PrintAndLogEx(DEBUG, "hs shiftreg... %012" PRIx64, state.shiftreg);

    for (uint32_t i = 0; i < 16; i++) {
        // get 8 bits of keystream
        uint8_t x = (uint8_t) ht2_hitag2_nstep(&state, 8);
        uint8_t y = expected[i];

        PrintAndLogEx(DEBUG, "%02X (%02X)", x, y);
        if (x != y) {
            return 0;
        }
    }
    return 1;
}

static uint64_t hitag2_verify_crypto_test_round(void) {

    uint8_t expected[16] = { 0xD7, 0x23, 0x7F, 0xCE, 0x8C, 0xD0, 0x37, 0xA9, 0x57, 0x49, 0xC1, 0xE6, 0x48, 0x00, 0x8A, 0xB6 };
    const uint64_t key = REV64(0x524B494D4E4FUL);
    const uint32_t uid = REV32(0x69574349);
    const uint32_t iv = REV32(0x72456E65);

    PrintAndLogEx(DEBUG, "UID... %08" PRIx32, uid);
    PrintAndLogEx(DEBUG, "IV.... %08" PRIx32, iv);
    PrintAndLogEx(DEBUG, "Key... %012" PRIx64, key);

    // initialise
    uint64_t cs = ht2_hitag2_init(key, uid, iv);
    PrintAndLogEx(DEBUG, "hs shiftreg... %012" PRIx64, cs);

    for (uint32_t i = 0; i < 16; i++) {
        // get 8 bits of keystream
        uint8_t x = (uint8_t) ht2_hitag2_byte(&cs);
        uint8_t y = expected[i];

        PrintAndLogEx(DEBUG, "%02X (%02X)", x, y);
        if (x != y) {
            return 0;
        }
    }
    return 1;
}

static int CmdLFHitag2Selftest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag test",
                  "Perform self tests of Hitag crypto engine",
                  "lf hitag test\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "======== " _CYAN_("Hitag 2 crypto test") " ============================");
    uint64_t test = hitag2_verify_crypto_test();
    PrintAndLogEx(INFO, "Crypto self test ( %s )", test ? _GREEN_("ok") : _RED_("fail"));

    test |= hitag2_verify_crypto_test_round();
    PrintAndLogEx(INFO, "Crypto self test ROUND ( %s )", test ? _GREEN_("ok") : _RED_("fail"));

    test |= hitag2_benchtest(1);
    PrintAndLogEx(INFO, "Hitag 2 crypto, init + gen 32 bits ( us %" PRIu64 " )", test);

    test |= hitag2_benchtest_gen32();
    PrintAndLogEx(INFO, "Hitag 2 crypto, gen new 32 bits only ( us: %" PRIu64 " )", test);

    test |= hitag2_benchtest(1000);
    PrintAndLogEx(INFO, "Hitag 2 crypto, init + gen 32 bits, x1000 ( us: %" PRIu64 " )", test);

    PrintAndLogEx(INFO, "--------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "Tests ( %s )", (test) ? _GREEN_("ok") : _RED_("fail"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,                    AlwaysAvailable, "This help"},
    {"list",        CmdLFHitagList,             AlwaysAvailable, "List Hitag trace history"},
    {"-----------", CmdHelp,                    IfPm3Hitag,      "------------------------ " _CYAN_("General") " ------------------------"},
    {"info",        CmdLFHitagInfo,             IfPm3Hitag,      "Hitag 2 tag information"},
    {"reader",      CmdLFHitagReader,           IfPm3Hitag,      "Act like a Hitag 2 reader"},
    {"test",        CmdLFHitag2Selftest,        AlwaysAvailable, "Perform self tests"},
    {"-----------", CmdHelp,                    IfPm3Hitag,      "----------------------- " _CYAN_("Operations") " -----------------------"},
//    {"demod",       CmdLFHitag2PWMDemod,        IfPm3Hitag,      "PWM Hitag 2 reader message demodulation"},
    {"dump",        CmdLFHitag2Dump,            IfPm3Hitag,      "Dump Hitag 2 tag"},
    {"read",        CmdLFHitagRd,               IfPm3Hitag,      "Read Hitag memory"},
    {"sniff",       CmdLFHitagSniff,            IfPm3Hitag,      "Eavesdrop Hitag communication"},
    {"view",        CmdLFHitagView,             AlwaysAvailable, "Display content from tag dump file"},
    {"wrbl",        CmdLFHitagWriter,           IfPm3Hitag,      "Write a block (page) in Hitag memory"},
    {"-----------", CmdHelp,                    IfPm3Hitag,      "----------------------- " _CYAN_("Simulation") " -----------------------"},
    {"eload",       CmdLFHitagEload,            IfPm3Hitag,      "Upload file into emulator memory"},
//    {"esave",       CmdLFHitagESave,            IfPm3Hitag,      "Save emulator memory to file"},
    {"eview",       CmdLFHitagEview,            IfPm3Hitag,      "View emulator memory"},
    {"sim",         CmdLFHitagSim,              IfPm3Hitag,      "Simulate Hitag transponder"},
    {"-----------", CmdHelp,                    IfPm3Hitag,      "----------------------- " _CYAN_("Recovery") " -----------------------"},
    {"cc",          CmdLFHitagSCheckChallenges, IfPm3Hitag,      "Hitag S: test all provided challenges"},
    {"crack2",      CmdLFHitag2Crack2,          IfPm3Hitag,      "Recover 2048bits of crypto stream"},
    {"chk",         CmdLFHitag2Chk,             IfPm3Hitag,      "Check keys"},
    {"lookup",      CmdLFHitag2Lookup,          AlwaysAvailable, "Uses authentication trace to check for key in dictionary file"},
    {"ta",          CmdLFHitag2CheckChallenges, IfPm3Hitag,      "Hitag 2: test all recorded authentications"},
    { NULL, NULL, 0, NULL }
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFHitag(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int readHitagUid(void) {
    uint32_t uid = 0;
    if (getHitag2Uid(&uid) == false) {
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "UID.... " _GREEN_("%08X"), uid);
    PrintAndLogEx(SUCCESS, "TYPE... " _GREEN_("%s"), getHitagTypeStr(uid));
    return PM3_SUCCESS;
}

