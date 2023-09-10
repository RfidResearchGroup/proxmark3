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
// Low frequency EM4x05 commands
//-----------------------------------------------------------------------------

#include "cmdlfem4x05.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>

#include "util_posix.h"  // msclock
#include "fileutils.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "commonutil.h"
#include "common.h"
#include "util_posix.h"
#include "protocols.h"
#include "ui.h"
#include "proxgui.h"
#include "graph.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"
#include "generator.h"
#include "cliparser.h"
#include "cmdhw.h"
#include "util.h"

//////////////// 4205 / 4305 commands

#define EM_PREAMBLE_LEN 8

static int CmdHelp(const char *Cmd);

// 1 = EM4x69
// 2 = EM4x05
static em_tech_type_t em_get_card_type(uint32_t config) {
    uint8_t t = (config >> 1) & 0xF;
    switch (t) {
        case 4:
            return EM_4469;
        case 8:
            return EM_4205;
        case 9:
            return EM_4305;
        case 12:
            return EM_4369;
    }
    return EM_UNKNOWN;
}

static const char *em_get_card_str(uint32_t config) {
    switch (em_get_card_type(config)) {
        case EM_4305:
            return "EM4305";
        case EM_4469:
            return "EM4469";
        case EM_4205:
            return "EM4205";
        case EM_4369:
            return "EM4369";
        case EM_UNKNOWN:
            break;
    }
    return "Unknown";
}

// even parity COLUMN
static bool em4x05_col_parity_test(const uint8_t *bs, size_t size, uint8_t rows, uint8_t cols, uint8_t pType) {
    if (rows * cols > size) return false;
    uint8_t colP = 0;

    for (uint8_t c = 0; c < cols - 1; c++) {
        for (uint8_t r = 0; r < rows; r++) {
            colP ^= bs[(r * cols) + c];
        }
        if (colP != pType) return false;
        colP = 0;
    }
    return true;
}

// download samples from device and copy to Graphbuffer
static bool em4x05_download_samples(void) {

    // 8 bit preamble + 32 bit word response (max clock (128) * 40bits = 5120 samples)
    uint8_t got[6000];
    if (!GetFromDevice(BIG_BUF, got, sizeof(got), 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "(em_download_samples) command execution time out");
        return false;
    }

    setGraphBuf(got, sizeof(got));
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(got, sizeof(got));
    RepaintGraphWindow();
    if (getSignalProperties()->isnoise) {
        PrintAndLogEx(DEBUG, "No tag found - signal looks like noise");
        return false;
    }
    return true;
}

// em_demod
static int doPreambleSearch(size_t *startIdx) {

    // sanity check
    if (g_DemodBufferLen < EM_PREAMBLE_LEN) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM4305 DemodBuffer too small");
        return PM3_ESOFT;
    }

    // set size to 11 to only test first 3 positions for the preamble
    // do not set it too long else an error preamble followed by 010 could be seen as success.
    size_t size = (11 > g_DemodBufferLen) ? g_DemodBufferLen : 11;
    *startIdx = 0;

    // skip first two 0 bits as they might have been missed in the demod
    uint8_t preamble[EM_PREAMBLE_LEN] = {0, 0, 0, 0, 1, 0, 1, 0};
    if (!preambleSearchEx(g_DemodBuffer, preamble, EM_PREAMBLE_LEN, &size, startIdx, true)) {

        uint8_t errpreamble[EM_PREAMBLE_LEN] = {0, 0, 0, 0, 0, 0, 0, 1};
        if (!preambleSearchEx(g_DemodBuffer, errpreamble, EM_PREAMBLE_LEN, &size, startIdx, true)) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - EM4305 preamble not found :: %zu", *startIdx);
            return PM3_ESOFT;
        }
        return PM3_EFAILED; // Error preamble found

    }
    return PM3_SUCCESS;
}

static bool detectFSK(void) {
    // detect fsk clock
    if (GetFskClock("", false) == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM: FSK clock failed");
        return false;
    }
    // demod
    int ans = FSKrawDemod(0, 0, 0, 0, false);
    if (ans != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM: FSK Demod failed");
        return false;
    }
    return true;
}
// PSK clocks should be easy to detect ( but difficult to demod a non-repeating pattern... )
static bool detectPSK(void) {
    int ans = GetPskClock("", false);
    if (ans <= 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM: PSK clock failed");
        return false;
    }
    //demod
    //try psk1 -- 0 0 6 (six errors?!?)
    ans = PSKDemod(0, 0, 6, false);
    if (ans != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM: PSK1 Demod failed");
        return false;
    }

    // In order to hit the INVERT,  we need to demod here
    if (g_DemodBufferLen < 11) {
        PrintAndLogEx(INFO, " demod buff len less than PREAMBLE lEN");
    }

    size_t size = (11 > g_DemodBufferLen) ? g_DemodBufferLen : 11;
    size_t startIdx = 0;
    uint8_t preamble[EM_PREAMBLE_LEN] = {0, 0, 0, 0, 1, 0, 1, 0};
    if (!preambleSearchEx(g_DemodBuffer, preamble, EM_PREAMBLE_LEN, &size, &startIdx, true)) {

        //try psk1 inverted
        ans = PSKDemod(0, 1, 6, false);
        if (ans != PM3_SUCCESS) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - EM: PSK1 inverted Demod failed");
            return false;
        }

        if (!preambleSearchEx(g_DemodBuffer, preamble, EM_PREAMBLE_LEN, &size, &startIdx, true)) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - EM: PSK1 inverted Demod failed 2");
            return false;
        }
    }

    // either PSK1 or PSK1 inverted is ok from here.
    // lets check PSK2 later.
    return true;
}
// try manchester - NOTE: ST only applies to T55x7 tags.
static bool detectASK_MAN(void) {
    bool stcheck = false;
    if (ASKDemod_ext(0, 0, 50, 0, false, false, false, 1, &stcheck) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM: ASK/Manchester Demod failed");
        return false;
    }
    return true;
}

static bool detectASK_BI(void) {
    int ans = ASKbiphaseDemod(0, 0, 1, 50, false);
    if (ans != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM: ASK/biphase normal demod failed");

        ans = ASKbiphaseDemod(0, 1, 1, 50, false);
        if (ans != PM3_SUCCESS) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - EM: ASK/biphase inverted demod failed");
            return false;
        }
    }
    return true;
}
static bool detectNRZ(void) {
    int ans = NRZrawDemod(0, 0, 1, false);
    if (ans != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM: NRZ normal demod failed");

        ans = NRZrawDemod(0, 1, 1, false);
        if (ans != PM3_SUCCESS) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - EM: NRZ inverted demod failed");
            return false;
        }
    }

    return true;
}

// param: idx - start index in demoded data.
static int em4x05_setdemod_buffer(uint32_t *word, size_t idx) {

    //test for even parity bits.
    uint8_t parity[45] = {0};
    memcpy(parity, g_DemodBuffer, 45);
    if (!em4x05_col_parity_test(g_DemodBuffer + idx + EM_PREAMBLE_LEN, 45, 5, 9, 0)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - End Parity check failed");
        return PM3_ESOFT;
    }

    // test for even parity bits and remove them. (leave out the end row of parities so 36 bits)
    if (!removeParity(g_DemodBuffer, idx + EM_PREAMBLE_LEN, 9, 0, 36)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM, failed removing parity");
        return PM3_ESOFT;
    }
    setDemodBuff(g_DemodBuffer, 32, 0);
    *word = bytebits_to_byteLSBF(g_DemodBuffer, 32);
    return PM3_SUCCESS;
}

// FSK, PSK, ASK/MANCHESTER, ASK/BIPHASE, ASK/DIPHASE, NRZ
// should cover 90% of known used configs
// the rest will need to be manually demoded for now...
static int em4x05_demod_resp(uint32_t *word, bool onlyPreamble) {
    *word = 0;
    int res;
    size_t idx = 0;
    bool found_err = false;
    do {
        if (detectASK_MAN()) {
            res = doPreambleSearch(&idx);
            if (res == PM3_SUCCESS)
                break;
            if (res == PM3_EFAILED)
                // go on, maybe it's false positive and another modulation will work
                found_err = true;
        }
        if (detectASK_BI()) {
            res = doPreambleSearch(&idx);
            if (res == PM3_SUCCESS)
                break;
            if (res == PM3_EFAILED)
                found_err = true;
        }
        if (detectNRZ()) {
            res = doPreambleSearch(&idx);
            if (res == PM3_SUCCESS)
                break;
            if (res == PM3_EFAILED)
                found_err = true;
        }
        if (detectFSK()) {
            res = doPreambleSearch(&idx);
            if (res == PM3_SUCCESS)
                break;
            if (res == PM3_EFAILED)
                found_err = true;
        }
        if (detectPSK()) {
            res = doPreambleSearch(&idx);
            if (res == PM3_SUCCESS)
                break;

            if (res == PM3_EFAILED)
                found_err = true;

            psk1TOpsk2(g_DemodBuffer, g_DemodBufferLen);
            res = doPreambleSearch(&idx);
            if (res == PM3_SUCCESS)
                break;

            if (res == PM3_EFAILED)
                found_err = true;
        }

        if (found_err)
            return PM3_EFAILED;

        return PM3_ESOFT;
    } while (0);

    if (onlyPreamble)
        return PM3_SUCCESS;

    res = em4x05_setdemod_buffer(word, idx);
    if (res == PM3_SUCCESS)
        return res;

    if (found_err)
        return PM3_EFAILED;
    return res;
}


//////////////// 4205 / 4305 commands

static bool em4x05_verify_write(uint8_t addr, uint32_t pwd, bool use_pwd, uint32_t data) {
    uint32_t r = 0;
    int res = em4x05_read_word_ext(addr, pwd, use_pwd, &r);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "%08x == %08x", r, data);
        return (r == data);
    }
    return false;
}

int em4x05_clone_tag(uint32_t *blockdata, uint8_t numblocks, uint32_t pwd, bool use_pwd) {

    if (blockdata == NULL)
        return PM3_EINVARG;

    if (numblocks < 1 || numblocks > 8)
        return PM3_EINVARG;

    // fast push mode
    g_conn.block_after_ACK = true;
    int res = 0;
    for (int8_t i = 0; i < numblocks; i++) {

        // Disable fast mode on last packet
        if (i == numblocks - 1) {
            g_conn.block_after_ACK = false;
        }

        if (i != 0) {
            blockdata[i] = reflect(blockdata[i], 32);
        }

        res = em4x05_write_word_ext(4 + i, pwd, use_pwd, blockdata[i]);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "(em4x05_clone_tag) Time out writing to tag");
            return res;
        }
    }

    res = 0;
    for (int8_t i = 0; i < numblocks; i++) {
        if (em4x05_verify_write(4 + i, use_pwd, pwd, blockdata[i]) == false) {
            res++;
        }
    }

    if (res == 0)
        PrintAndLogEx(SUCCESS, "Data written and verified");

    return PM3_SUCCESS;
}

static int em4x05_login_ext(uint32_t pwd) {

    struct {
        uint32_t password;
    } PACKED payload;

    payload.password = pwd;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X_LOGIN, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X_LOGIN, &resp, 10000)) {
        PrintAndLogEx(WARNING, "(em4x05_login_ext) timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (em4x05_download_samples() == false) {
        return PM3_ESOFT;
    }
    uint32_t word;
    return em4x05_demod_resp(&word, true);
}

int em4x05_read_word_ext(uint8_t addr, uint32_t pwd, bool use_pwd, uint32_t *word) {

    struct {
        uint32_t password;
        uint8_t address;
        uint8_t usepwd;
    } PACKED payload;

    payload.password = pwd;
    payload.address = addr;
    payload.usepwd = use_pwd;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X_READWORD, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X_READWORD, &resp, 10000)) {
        PrintAndLogEx(WARNING, "(em4x05_read_word_ext) timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (em4x05_download_samples() == false) {
        return PM3_ESOFT;
    }
    return em4x05_demod_resp(word, false);
}

int em4x05_write_word_ext(uint8_t addr, uint32_t pwd, bool use_pwd, uint32_t data) {
    struct {
        uint32_t password;
        uint32_t data;
        uint8_t address;
        uint8_t usepwd;
    } PACKED payload;

    payload.password = pwd;
    payload.data = data;
    payload.address = addr;
    payload.usepwd = use_pwd;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X_WRITEWORD, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X_WRITEWORD, &resp, 2000)) {
        PrintAndLogEx(ERR, "Error occurred, device did not respond during write operation.");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

static int em4x05_protect(uint32_t pwd, bool use_pwd, uint32_t data) {
    struct {
        uint32_t password;
        uint32_t data;
        uint8_t usepwd;
    } PACKED payload;

    payload.password = pwd;
    payload.data = data;
    payload.usepwd = use_pwd;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X_PROTECTWORD, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X_PROTECTWORD, &resp, 2000)) {
        PrintAndLogEx(ERR, "Error occurred, device did not respond during write operation.");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

int CmdEM4x05Demod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x05 demod",
                  "Try to find EM 4x05 preamble, if found decode / descramble data",
                  "lf em 4x05 demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    uint32_t dummy = 0;
    return em4x05_demod_resp(&dummy, false);
}

int CmdEM4x05Dump(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x05 dump",
                  "Dump EM4x05/EM4x69.  Tag must be on antenna.",
                  "lf em 4x05 dump\n"
                  "lf em 4x05 dump -p 11223344\n"
                  "lf em 4x05 dump -f myfile -p 11223344"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("p", "pwd", "<hex>", "password (00000000)"),
        arg_str0("f", "file", "<fn>", "override filename prefix (optional).  Default is based on UID"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint64_t inputpwd = arg_get_u64_hexstr_def(ctx, 1, 0xFFFFFFFFFFFFFFFF);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    uint8_t addr = 0;
    uint32_t pwd = 0;
    bool usePwd = false;
    if (inputpwd != 0xFFFFFFFFFFFFFFFF) {

        if (inputpwd & 0xFFFFFFFF00000000) {
            PrintAndLogEx(FAILED, "Pwd too large");
            return PM3_EINVARG;
        }

        usePwd = true;
        pwd = (inputpwd & 0xFFFFFFFF);
    }

    uint32_t block0 = 0;
    // read word 0 (chip info)
    // block 0 can be read even without a password.
    if (em4x05_isblock0(&block0) == false)
        return PM3_ESOFT;

    uint8_t bytes[4] = {0};
    uint32_t data[16];

    int success = PM3_SUCCESS;
    uint32_t lock_bits = 0x00; // no blocks locked
    bool gotLockBits = false;
    uint32_t word = 0;

    const char *info[] = {"Info/User", "UID", "Password", "User", "Config", "User", "User", "User", "User", "User", "User", "User", "User", "User", "Lock", "Lock"};
    const char *info4x69 [] = {"Info", "UID", "Password", "Lock", "Config", "User", "User", "User", "User", "User", "User", "User", "User", "User", "User", "User"};

    // EM4305 vs EM4469
    em_tech_type_t card_type = em_get_card_type(block0);

    PrintAndLogEx(INFO, "Found a " _GREEN_("%s") " tag", em_get_card_str(block0));

    if (usePwd) {
        // Test first if the password is correct
        int status = em4x05_login_ext(pwd);
        if (status == PM3_SUCCESS) {
            PrintAndLogEx(INFO, "password is " _GREEN_("correct"));
        } else if (status == PM3_EFAILED) {
            PrintAndLogEx(WARNING, "password is " _RED_("incorrect") ", will try without password");
            usePwd = false;
        } else if (status != PM3_EFAILED) {
            PrintAndLogEx(WARNING, "Login attempt: no answer from tag");
            return status;
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Addr | data     | ascii |lck| info");
    PrintAndLogEx(INFO, "-----+----------+-------+---+-----");

    if (card_type == EM_4205 || card_type == EM_4305 || card_type == EM_UNKNOWN) {
        bool lockInPW2 = false;
        // To flag any blocks locked we need to read blocks 14 and 15 first
        // don't swap endian until we get block lock flags.
        int status14 = em4x05_read_word_ext(EM4305_PROT1_BLOCK, pwd, usePwd, &word);
        if (status14 == PM3_SUCCESS) {
            if ((word & 0x00008000) != 0x00) {
                lock_bits = word;
                gotLockBits = true;
            }
            data[EM4305_PROT1_BLOCK] = word;
        } else {
            success = PM3_ESOFT; // If any error ensure fail is set so not to save invalid data
        }
        int status15 = em4x05_read_word_ext(EM4305_PROT2_BLOCK, pwd, usePwd, &word);
        if (status15 == PM3_SUCCESS) {
            if ((word & 0x00008000) != 0x00) { // assume block 15 is the current lock block
                lock_bits = word;
                gotLockBits = true;
                lockInPW2 = true;
            }
            data[EM4305_PROT2_BLOCK] = word;
        } else {
            success = PM3_ESOFT; // If any error ensure fail is set so not to save invalid data
        }
        uint32_t lockbit;
        // Now read blocks 0 - 13 as we have 14 and 15
        for (; addr < 14; addr++) {
            lockbit = (lock_bits >> addr) & 1;
            if (addr == 2) {
                if (usePwd) {
                    data[addr] = BSWAP_32(pwd);
                    num_to_bytes(pwd, 4, bytes);
                    PrintAndLogEx(INFO, "  %02u | %08X | %s  | %s | %s", addr, pwd, sprint_ascii(bytes, 4), gotLockBits ? (lockbit ? _RED_("x") : " ") : _YELLOW_("?"), info[addr]);
                } else {
                    data[addr] = 0x00; // Unknown password, but not used to set to zeros
                    PrintAndLogEx(INFO, "  %02u |          |       |   | %-10s " _YELLOW_("write only"), addr, info[addr]);
                }
            } else {
                // success &= em4x05_read_word_ext(addr, pwd, usePwd, &word);
                int status = em4x05_read_word_ext(addr, pwd, usePwd, &word); // Get status for single read
                if (status != PM3_SUCCESS)
                    success = PM3_ESOFT; // If any error ensure fail is set so not to save invalid data
                data[addr] = BSWAP_32(word);
                if (status == PM3_SUCCESS) {
                    num_to_bytes(word, 4, bytes);
                    PrintAndLogEx(INFO, "  %02u | %08X | %s  | %s | %s", addr, word, sprint_ascii(bytes, 4), gotLockBits ? (lockbit ? _RED_("x") : " ") : _YELLOW_("?"), info[addr]);
                } else
                    PrintAndLogEx(INFO, "  %02u |          |       |   | %-10s %s", addr, info[addr], status == PM3_EFAILED ? _RED_("read denied") : _RED_("read failed"));
            }
        }
        // Print blocks 14 and 15
        // Both lock bits are protected with bit idx 14 (special case)
        addr = 14;
        if (status14 == PM3_SUCCESS) {
            lockbit = (lock_bits >> addr) & 1;
            PrintAndLogEx(INFO, "  %02u | %08X | %s  | %s | %-10s %s", addr, data[addr], sprint_ascii(bytes, 4), gotLockBits ? (lockbit ? _RED_("x") : " ") : _YELLOW_("?"), info[addr], lockInPW2 ? "" : _GREEN_("active"));
        } else {
            PrintAndLogEx(INFO, "  %02u |          |       |   | %-10s %s", addr, info[addr], status14 == PM3_EFAILED ? _RED_("read denied") : _RED_("read failed"));
        }
        addr = 15;
        if (status15 == PM3_SUCCESS) {
            lockbit = (lock_bits >> 14) & 1; // beware lock bit of word15 is pr14
            PrintAndLogEx(INFO, "  %02u | %08X | %s  | %s | %-10s %s", addr, data[addr], sprint_ascii(bytes, 4), gotLockBits ? (lockbit ? _RED_("x") : " ") : _YELLOW_("?"), info[addr], lockInPW2 ? _GREEN_("active") : "");
        } else {
            PrintAndLogEx(INFO, "  %02u |          |       |   | %-10s %s", addr, info[addr], status15 == PM3_EFAILED ? _RED_("read denied") : _RED_("read failed"));
        }
        // Update endian for files
        data[14] = BSWAP_32(data[14]);
        data[15] = BSWAP_32(data[15]);

    } else if (card_type == EM_4369 || card_type == EM_4469) {

        // To flag any blocks locked we need to read block 3 first
        // don't swap endian until we get block lock flags.
        int status14 = em4x05_read_word_ext(EM4469_PROT_BLOCK, pwd, usePwd, &word);
        if (status14 == PM3_SUCCESS) {
            lock_bits = word;
            gotLockBits = true;
            data[EM4469_PROT_BLOCK] = word;
        } else {
            success = PM3_ESOFT; // If any error ensure fail is set so not to save invalid data
        }

        for (; addr < 16; addr++) {
            uint32_t lockbit = (lock_bits >> (addr * 2)) & 3;
            if (addr == 2) {
                if (usePwd) {
                    data[addr] = BSWAP_32(pwd);
                    num_to_bytes(pwd, 4, bytes);
                    PrintAndLogEx(INFO, "  %02u | %08X | %s  | %s | %s", addr, pwd, sprint_ascii(bytes, 4), gotLockBits ? (lockbit ? _RED_("x") : " ") : _YELLOW_("?"), info4x69[addr]);
                } else {
                    data[addr] = 0x00; // Unknown password, but not used to set to zeros
                    PrintAndLogEx(INFO, "  %02u |          |       |   | %-10s " _YELLOW_("write only"), addr, info4x69[addr]);
                }
            } else {

                int status = em4x05_read_word_ext(addr, pwd, usePwd, &word);
                if (status != PM3_SUCCESS) {
                    success = PM3_ESOFT; // If any error ensure fail is set so not to save invalid data
                }

                data[addr] = BSWAP_32(word);
                if (status == PM3_SUCCESS) {
                    num_to_bytes(word, 4, bytes);
                    PrintAndLogEx(INFO, "  %02u | %08X | %s  | %s | %s", addr, word, sprint_ascii(bytes, 4), gotLockBits ? (lockbit ? _RED_("x") : " ") : _YELLOW_("?"), info4x69[addr]);
                } else {
                    PrintAndLogEx(INFO, "  %02u |          |       |   | %-10s %s", addr, info4x69[addr], status == PM3_EFAILED ? _RED_("read denied") : _RED_("read failed"));
                }
            }
        }

    } else {
    }

    // all ok save dump to file
    if (success == PM3_SUCCESS) {

        if (strcmp(filename, "") == 0) {

            if (card_type == EM_4369) {
                snprintf(filename, sizeof(filename), "lf-4369-%08X-dump", BSWAP_32(data[1]));
            } else if (card_type == EM_4469) {
                snprintf(filename, sizeof(filename), "lf-4469-%08X-dump", BSWAP_32(data[1]));
            } else {
                snprintf(filename, sizeof(filename), "lf-4x05-%08X-dump", BSWAP_32(data[1]));
            }

        }
        PrintAndLogEx(NORMAL, "");
        if (card_type == EM_4369 || card_type == EM_4469)
            pm3_save_dump(filename, (uint8_t *)data, sizeof(data), jsfEM4x69, 4);
        else
            pm3_save_dump(filename, (uint8_t *)data, sizeof(data), jsfEM4x05, 4);
    }
    PrintAndLogEx(NORMAL, "");
    return success;
}

int CmdEM4x05Read(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x05 read",
                  "Read EM4x05/EM4x69. Tag must be on antenna.",
                  "lf em 4x05 read -a 1\n"
                  "lf em 4x05 read --addr 1 --pwd 11223344"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int1("a", "addr", "<dec>", "memory address to read. (0-15)"),
        arg_str0("p", "pwd", "<hex>", "optional - password, 4 bytes hex"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint8_t addr = (uint8_t)arg_get_int_def(ctx, 1, 50);
    uint64_t inputpwd = arg_get_u64_hexstr_def(ctx, 2, 0xFFFFFFFFFFFFFFFF);
    CLIParserFree(ctx);

    uint32_t pwd = 0;
    bool use_pwd = false;

    if (addr > 15) {
        PrintAndLogEx(ERR, "Address must be between 0 and 15");
        return PM3_EINVARG;
    }

    if (inputpwd == 0xFFFFFFFFFFFFFFFF) {
        PrintAndLogEx(INFO, "Reading address %02u", addr);
    } else {
        pwd = (inputpwd & 0xFFFFFFFF);
        use_pwd = true;
        PrintAndLogEx(INFO, "Reading address %02u using password %08X", addr, pwd);
    }

    uint32_t word = 0;
    int status = em4x05_read_word_ext(addr, pwd, use_pwd, &word);
    if (status == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Address %02d | %08X - %s", addr, word, (addr > 13) ? "Lock" : "");
    else if (status == PM3_EFAILED)
        PrintAndLogEx(ERR, "Tag denied Read operation");
    else
        PrintAndLogEx(WARNING, "No answer from tag");
    return status;
}

int CmdEM4x05Write(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x05 write",
                  "Write EM4x05/EM4x69. Tag must be on antenna.",
                  "lf em 4x05 write -a 1 -d deadc0de\n"
                  "lf em 4x05 write --addr 1 --pwd 11223344 --data deadc0de\n"
                  "lf em 4x05 write --po --pwd 11223344 --data deadc0de\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("a", "addr", "<dec>", "memory address to write to. (0-13)"),
        arg_str1("d", "data", "<hex>", "data to write (4 hex bytes)"),
        arg_str0("p", "pwd", "<hex>", "password (4 hex bytes)"),
        arg_lit0(NULL, "po", "protect operation"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint8_t addr = (uint8_t)arg_get_int_def(ctx, 1, 50);
    uint32_t data = 0;
    int res = arg_get_u32_hexstr_def(ctx, 2, 0, &data);
    if (res == 2) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Data must be 4 hex bytes");
        return PM3_EINVARG;
    } else if (res == 0) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Data must be 4 hex bytes");
        return PM3_EINVARG;
    }

    bool use_pwd = false;
    uint32_t pwd = 0;
    res = arg_get_u32_hexstr_def_nlen(ctx, 3, 0, &pwd, 4, true);
    if (res == 2) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Password must be 4 hex bytes");
        return PM3_EINVARG;
    } else if (res == 3) {
        use_pwd = false;
    } else if (res == 1) {
        use_pwd = true;
    }

    bool protect_operation = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if ((addr > 13) && (protect_operation == false)) {
        PrintAndLogEx(WARNING, "Address must be between 0 and 13");
        return PM3_EINVARG;
    }

    if (use_pwd) {
        if (protect_operation)
            PrintAndLogEx(INFO, "Writing protection words data %08X using password %08X", data, pwd);
        else
            PrintAndLogEx(INFO, "Writing address %d data %08X using password %08X", addr, data, pwd);
    } else {
        if (protect_operation)
            PrintAndLogEx(INFO, "Writing protection words data %08X", data);
        else
            PrintAndLogEx(INFO, "Writing address %d data %08X", addr, data);
    }

    res = PM3_SUCCESS;
    // set Protect Words
    if (protect_operation) {
        res = em4x05_protect(pwd, use_pwd, data);
        if (res != PM3_SUCCESS) {
            return res;
        }
    } else {
        res = em4x05_write_word_ext(addr, pwd, use_pwd, data);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }

    if (em4x05_download_samples() == false)
        return PM3_ENODATA;

    uint32_t dummy = 0;
    int status = em4x05_demod_resp(&dummy, true);
    if (status == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Data written and verified");
    else if (status == PM3_EFAILED)
        PrintAndLogEx(ERR, "Tag denied %s operation", protect_operation ? "Protect" : "Write");
    else
        PrintAndLogEx(DEBUG, "No answer from tag");

    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf em 4x05 read`") " to verify");
    return status;
}

int CmdEM4x05Wipe(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x05 wipe",
                  "Wipe EM4x05/EM4x69. Tag must be on antenna.",
                  "lf em 4x05 wipe --4305 -p 11223344  -> wipe EM 4305 w pwd\n"
                  "lf em 4x05 wipe --4205              -> wipe EM 4205\n"
                  "lf em 4x05 wipe --4369              -> wipe EM 4369"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "4205", "target chip type EM 4205"),
        arg_lit0(NULL, "4305", "target chip type EM 4305 (default)"),
        arg_lit0(NULL, "4369", "target chip type EM 4369"),
        arg_lit0(NULL, "4469", "target chip type EM 4469"),
        arg_str0("p", "pwd", "<hex>", "optional - password, 4 bytes hex"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool target_4205 = arg_get_lit(ctx, 1);
    bool target_4305 = arg_get_lit(ctx, 2);
    bool target_4369 = arg_get_lit(ctx, 3);
    bool target_4469 = arg_get_lit(ctx, 4);
    uint64_t inputpwd = arg_get_u64_hexstr_def(ctx, 5, 0xFFFFFFFFFFFFFFFF);
    CLIParserFree(ctx);

    uint8_t foo = target_4205 + target_4305 + target_4369 + target_4469;

    if (foo > 1) {
        PrintAndLogEx(ERR, "Can't target multiple chip types at the same time");
        return PM3_EINVARG;
    }

    uint8_t addr = 0;
    uint32_t chip_info  = 0x00040072; // Chip info/User Block normal 4305 Chip Type
    uint32_t chip_UID   = 0x614739AE; // UID normally readonly, but just in case
    uint32_t block_data = 0x00000000; // UserBlock/Password (set to 0x00000000 for a wiped card1
    uint32_t config     = 0x0001805F; // Default config (no password)

    if (target_4205) {
        chip_info  = 0x00040070;
    }
    if (target_4369) {
        chip_info  = 0x00020078;  // found on HID Prox
    }
    if (target_4469) {
//        chip_info  = 0x00020078;  // need to get a normal 4469 chip info block
    }

    bool use_pwd = false;
    uint32_t pwd = 0;
    if (inputpwd != 0xFFFFFFFFFFFFFFFF) {
        pwd = (inputpwd & 0xFFFFFFFF);
        use_pwd = true;
    }
    // block 0 : User Data or Chip Info
    int res = em4x05_write_word_ext(0, pwd, use_pwd, chip_info);
    if (res != PM3_SUCCESS) {
        return res;
    }

    // block 1 : UID - this should be read only for EM4205 and EM4305 not sure about others
    res = em4x05_write_word_ext(1, pwd, use_pwd, chip_UID);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(INFO, "UID block write failed");
    }

    // block 2 : password
    res = em4x05_write_word_ext(2, pwd, use_pwd, block_data);
    if (res != PM3_SUCCESS) {
        return res;
    }

    // Password should now have changed, so use new password
    pwd = block_data;
    // block 3 : user data
    res = em4x05_write_word_ext(3, pwd, use_pwd, block_data);
    if (res != PM3_SUCCESS) {
        return res;
    }

    // block 4 : config
    res = em4x05_write_word_ext(4, pwd, use_pwd, config);
    if (res != PM3_SUCCESS) {
        return res;
    }

    // Remainder of user/data blocks
    for (addr = 5; addr < 14; addr++) {// Clear user data blocks
        res = em4x05_write_word_ext(addr, pwd, use_pwd, block_data);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }
    return PM3_SUCCESS;
}

static const char *printEM4x05_known(uint32_t word) {

    switch (word) {
//        case EM4305_DEFAULT_CONFIG_BLOCK:
        case EM4305_PRESCO_CONFIG_BLOCK: {
            return "EM4305 DEFAULT / PRESCO";
        }
//        case EM4305_PAXTON_CONFIG_BLOCK:
        case EM4305_EM_UNIQUE_CONFIG_BLOCK: {
            return "EM UNIQUE / PAXTON";
        }
        case EM4305_VISA2000_CONFIG_BLOCK: {
            return "VISA2000";
        }
        case EM4305_VIKING_CONFIG_BLOCK: {
            return "VIKING";
        }
        case EM4305_NORALSY_CONFIG_BLOCK: {
            return "NORALSY";
        }
        case EM4305_SECURAKEY_CONFIG_BLOCK: {
            return "SECURAKEY";
        }
//        case EM4305_HID_26_CONFIG_BLOCK:
//        case EM4305_PARADOX_CONFIG_BLOCK:
        case EM4305_AWID_CONFIG_BLOCK: {
            return "HID26 / PARADOX / AWID";
        }
        case EM4305_PYRAMID_CONFIG_BLOCK: {
            return "PYRAMID";
        }
        case EM4305_IOPROX_CONFIG_BLOCK: {
            return "IOPROX";
        }
//        case EM4305_KERI_CONFIG_BLOCK:
        case EM4305_INDALA_64_CONFIG_BLOCK: {
            return "INDALA 64 / KERI";
        }
        case EM4305_INDALA_224_CONFIG_BLOCK: {
            return "INDALA 224";
        }
        case EM4305_MOTOROLA_CONFIG_BLOCK: {
            return "MOTOROLA";
        }
        case EM4305_NEXWATCH_CONFIG_BLOCK: {
            return "NEXWATCH";
        }
//        case EM4305_NEDAP_64_CONFIG_BLOCK:
        case EM4305_JABLOTRON_CONFIG_BLOCK: {
            return "JABLOTRON / NEDAP 64";
        }
        case EM4305_GUARDPROXII_CONFIG_BLOCK: {
            return "GUARD PROXII";
        }
        case EM4305_NEDAP_128_CONFIG_BLOCK: {
            return "NEDAP 128";
        }
        case EM4305_PAC_CONFIG_BLOCK: {
            return "PAC/Stanley";
        }
        case EM4305_VERICHIP_CONFIG_BLOCK: {
            return "VERICHIP";
        }
    }
    return "";
}

static void printEM4x05config(em_tech_type_t card_type, uint32_t wordData) {
    uint16_t datarate = (((wordData & 0x3F) + 1) * 2);
    uint8_t encoder = ((wordData >> 6) & 0xF);
    char enc[14];
    memset(enc, 0, sizeof(enc));

    uint8_t PSKcf = (wordData >> 10) & 0x3;
    char cf[10];
    memset(cf, 0, sizeof(cf));
    uint8_t delay = (wordData >> 12) & 0x3;
    char cdelay[33];
    memset(cdelay, 0, sizeof(cdelay));
    uint8_t numblks = EM4x05_GET_NUM_BLOCKS(wordData);
    uint8_t LWR = numblks + 5 - 1; //last word read
    switch (encoder) {
        case 0:
            snprintf(enc, sizeof(enc), "NRZ");
            break;
        case 1:
            snprintf(enc, sizeof(enc), "Manchester");
            break;
        case 2:
            snprintf(enc, sizeof(enc), "Biphase");
            break;
        case 3:
            snprintf(enc, sizeof(enc), "Miller");
            break;
        case 4:
            snprintf(enc, sizeof(enc), "PSK1");
            break;
        case 5:
            snprintf(enc, sizeof(enc), "PSK2");
            break;
        case 6:
            snprintf(enc, sizeof(enc), "PSK3");
            break;
        case 7:
            snprintf(enc, sizeof(enc), "Unknown");
            break;
        case 8:
            snprintf(enc, sizeof(enc), "FSK1");
            break;
        case 9:
            snprintf(enc, sizeof(enc), "FSK2");
            break;
        default:
            snprintf(enc, sizeof(enc), "Unknown");
            break;
    }

    switch (PSKcf) {
        case 0:
            snprintf(cf, sizeof(cf), "RF/2");
            break;
        case 1:
            snprintf(cf, sizeof(cf), "RF/8");
            break;
        case 2:
            snprintf(cf, sizeof(cf), "RF/4");
            break;
        case 3:
            snprintf(cf, sizeof(cf), "unknown");
            break;
    }

    switch (delay) {
        case 0:
            snprintf(cdelay, sizeof(cdelay), "no delay");
            break;
        case 1:
            snprintf(cdelay, sizeof(cdelay), "BP/8 or 1/8th bit period delay");
            break;
        case 2:
            snprintf(cdelay, sizeof(cdelay), "BP/4 or 1/4th bit period delay");
            break;
        case 3:
            snprintf(cdelay, sizeof(cdelay), "no delay");
            break;
    }
    uint8_t readLogin = (wordData & EM4x05_READ_LOGIN_REQ) >> 18;
    uint8_t readHKL = (wordData & EM4x05_READ_HK_LOGIN_REQ) >> 19;
    uint8_t writeLogin = (wordData & EM4x05_WRITE_LOGIN_REQ) >> 20;
    uint8_t writeHKL = (wordData & EM4x05_WRITE_HK_LOGIN_REQ) >> 21;
    uint8_t raw = (wordData & EM4x05_READ_AFTER_WRITE) >> 22;
    uint8_t disable = (wordData & EM4x05_DISABLE_ALLOWED) >> 23;
    uint8_t rtf = (wordData & EM4x05_READER_TALK_FIRST) >> 24;
    uint8_t invert = (wordData & EM4x05_INVERT) >> 25;
    uint8_t pigeon = (wordData & EM4x05_PIGEON) >> 26;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Config Information") " ------------------------");
    PrintAndLogEx(INFO, "ConfigWord: %08X  ( " _YELLOW_("%s") " )", wordData, printEM4x05_known(wordData));

    PrintAndLogEx(INFO, " Data Rate:  %02u | "_YELLOW_("RF/%u"), wordData & 0x3F, datarate);
    PrintAndLogEx(INFO, "   Encoder:   %u | " _YELLOW_("%s"), encoder, enc);
    if (card_type == EM_4369 || card_type == EM_4469) {
        PrintAndLogEx(INFO, "    PSK CF:   %u | %s", PSKcf, cf);
    } else if (PSKcf != 0) {
        PrintAndLogEx(INFO, "co10..c011:   %u | %s", PSKcf, _RED_("Not used, must be set to logic 0"));
    }
    if (card_type == EM_4305) {
        PrintAndLogEx(INFO, "     Delay:   %u | %s", delay, cdelay);
    } else if (delay != 0) {
        PrintAndLogEx(INFO, "co12..c013:   %u | %s", delay, _RED_("Not used, must be set to logic 0"));
    }
    PrintAndLogEx(INFO, " LastWordR:  %02u | Address of last word for default read - meaning %u blocks are output", LWR, numblks);
    PrintAndLogEx(INFO, " ReadLogin:   %u | Read login is %s", readLogin, readLogin ? _YELLOW_("required") :  _GREEN_("not required"));
    if (card_type == EM_4369 || card_type == EM_4469) {
        PrintAndLogEx(INFO, "   ReadHKL:   %u | Read housekeeping words (3,4) login is %s", readHKL, readHKL ? _YELLOW_("required") : _GREEN_("not required"));
    } else if (readHKL != 0) {
        PrintAndLogEx(INFO, "      c019:   %u | %s", readHKL, _RED_("Not used, must be set to logic 0"));
    }
    PrintAndLogEx(INFO, "WriteLogin:   %u | Write login is %s", writeLogin, writeLogin ? _YELLOW_("required") :  _GREEN_("not required"));
    if (card_type == EM_4369 || card_type == EM_4469) {
        PrintAndLogEx(INFO, "  WriteHKL:   %u | Write housekeeping words (2,3,4) login is %s", writeHKL, writeHKL ? _YELLOW_("required") :  _GREEN_("not Required"));
    } else if (writeHKL != 0) {
        PrintAndLogEx(INFO, "      c021:   %u | %s", writeHKL, _RED_("Not used, must be set to logic 0"));
    }
    if (card_type == EM_4369 || card_type == EM_4469) {
        PrintAndLogEx(INFO, "    R.A.W.:   %u | Read after write is %s", raw, raw ? "on" : "off");
    } else if (raw != 0) {
        PrintAndLogEx(INFO, "      c022:   %u | %s", raw, _RED_("Not used, must be set to logic 0"));
    }
    PrintAndLogEx(INFO, "   Disable:   %u | Disable command is %s", disable, disable ? "accepted" : "not accepted");
    PrintAndLogEx(INFO, "    R.T.F.:   %u | Reader talk first is %s", rtf, rtf ? _YELLOW_("enabled") : "disabled");
    if (card_type == EM_4369) {
        PrintAndLogEx(INFO, "    Invert:   %u | Invert data? %s", invert, invert ? _YELLOW_("yes") : "no");
    } else if (invert != 0) {
        PrintAndLogEx(INFO, "      c025:   %u | %s", invert, _RED_("Not used, must be set to logic 0"));
    }
    if (card_type == EM_4305) {
        PrintAndLogEx(INFO, "    Pigeon:   %u | Pigeon mode is %s", pigeon, pigeon ? _YELLOW_("enabled") : "disabled");
    } else if (pigeon != 0) {
        PrintAndLogEx(INFO, "      c026:   %u | %s", pigeon, _RED_("Not used, must be set to logic 0"));
    }
}

static void printEM4x05info(uint32_t block0, uint32_t serial) {

    uint8_t chipType = (block0 >> 1) & 0xF;
    uint8_t cap = (block0 >> 5) & 3;
    uint16_t custCode = (block0 >> 9) & 0x2FF;

    /* bits
    //  0,   rfu
    //  1,2,3,4  chip type
    //  5,6  resonant cap
    //  7,8, rfu
    //  9 - 18 customer code
    //  19,  rfu

       98765432109876543210
       001000000000
    // 00100000000001111000
                   xxx----
    //                1100
    //             011
    // 00100000000
    */

    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");

    PrintAndLogEx(SUCCESS, "    Block0: " _GREEN_("%08x"), block0);
    PrintAndLogEx(SUCCESS, " Chip Type:   %3u | " _YELLOW_("%s"), chipType, em_get_card_str(block0));

    switch (cap) {
        case 3:
            PrintAndLogEx(SUCCESS, "  Cap Type:   %3u | 330pF", cap);
            break;
        case 2:
            PrintAndLogEx(SUCCESS, "  Cap Type:   %3u | %spF", cap, (chipType == 4) ? "75" : "210");
            break;
        case 1:
            PrintAndLogEx(SUCCESS, "  Cap Type:   %3u | 250pF", cap);
            break;
        case 0:
            PrintAndLogEx(SUCCESS, "  Cap Type:   %3u | no resonant capacitor", cap);
            break;
        default:
            PrintAndLogEx(SUCCESS, "  Cap Type:   %3u | unknown", cap);
            break;
    }

    PrintAndLogEx(SUCCESS, " Cust Code: 0x%x | %s", custCode, (custCode == 0x200) ? "Default" : "Unknown");
    if (serial != 0)
        PrintAndLogEx(SUCCESS, "  Serial #: " _YELLOW_("%08X"), serial);
}

static void printEM4x05ProtectionBits(uint32_t word, uint8_t addr) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Protection") " --------------------------------");
    PrintAndLogEx(INFO, "ProtectionWord: %08X (Word %i)", word, addr);
    for (uint8_t i = 0; i < 15; i++) {
        PrintAndLogEx(INFO, "      Word:  %02u | %s", i, ((1 << i) & word) ? _RED_("write Locked") : "unlocked");
        if (i == 14)
            PrintAndLogEx(INFO, "      Word:  %02u | %s", i + 1, ((1 << i) & word) ? _RED_("write locked") : "unlocked");
    }
}

//quick test for EM4x05/EM4x69 tag
bool em4x05_isblock0(uint32_t *word) {
    return (em4x05_read_word_ext(0, 0, false, word) == PM3_SUCCESS);
}

int CmdEM4x05Info(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x05 info",
                  "Tag information EM4205/4305/4469//4569 tags. Tag must be on antenna.",
                  "lf em 4x05 info\n"
                  "lf em 4x05 info -p 11223344"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("p", "pwd", "<hex>", "optional - password, 4 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint64_t inputpwd = arg_get_u64_hexstr_def(ctx, 1, 0xFFFFFFFFFFFFFFFF);
    CLIParserFree(ctx);

    bool use_pwd = false;
    uint32_t pwd = 0;
    if (inputpwd != 0xFFFFFFFFFFFFFFFF) {
        pwd = inputpwd & 0xFFFFFFFF;
        use_pwd = true;
    }

    uint32_t word = 0, block0 = 0, serial = 0;

    // read word 0 (chip info)
    // block 0 can be read even without a password.
    if (em4x05_isblock0(&block0) == false)
        return PM3_ESOFT;

    // based on Block0 ,  decide type.
    em_tech_type_t card_type = em_get_card_type(block0);

    // read word 1 (serial #) doesn't need pwd
    // continue if failed, .. non blocking fail.
    int res = em4x05_read_word_ext(EM_SERIAL_BLOCK, 0, false, &serial);
    (void)res;

    printEM4x05info(block0, serial);

    // read word 4 (config block)
    // needs password if one is set
    if (em4x05_read_word_ext(EM_CONFIG_BLOCK, pwd, use_pwd, &word) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "(CmdEM4x05Info) failed to read CONFIG BLOCK");
        return PM3_ESOFT;
    }

    printEM4x05config(card_type, word);

    // if 4469 read EM4469_PROT_BLOCK
    // if 4305 read 14,15
    if (card_type == EM_4205 || card_type == EM_4305) {

        // read word 14 and 15 to see which is being used for the protection bits
        if (em4x05_read_word_ext(EM4305_PROT1_BLOCK, pwd, use_pwd, &word) != PM3_SUCCESS) {
            return PM3_ESOFT;
        }

        if (word & 0x8000) {
            printEM4x05ProtectionBits(word, EM4305_PROT1_BLOCK);
            return PM3_SUCCESS;
        } else { // if status bit says this is not the used protection word
            if (em4x05_read_word_ext(EM4305_PROT2_BLOCK, pwd, use_pwd, &word) != PM3_SUCCESS)
                return PM3_ESOFT;
            if (word & 0x8000) {
                printEM4x05ProtectionBits(word, EM4305_PROT2_BLOCK);
                return PM3_SUCCESS;
            }
        }
    } else if (card_type == EM_4369 || card_type == EM_4469) {
        // read word 3 to see which is being used for the protection bits
        if (em4x05_read_word_ext(EM4469_PROT_BLOCK, pwd, use_pwd, &word) != PM3_SUCCESS) {
            return PM3_ESOFT;
        }
        printEM4x05ProtectionBits(word, EM4469_PROT_BLOCK);
    }

    //something went wrong
    return PM3_ESOFT;
}

static bool is_cancelled(void) {
    if (kbd_enter_pressed()) {
        PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
        return true;
    }
    return false;
}
// load a default pwd file.
int CmdEM4x05Chk(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x05 chk",
                  "This command uses a dictionary attack against EM4205/4305/4469/4569",
                  "lf em 4x05 chk\n"
                  "lf em 4x05 chk -e 000022B8            -> check password 000022B8\n"
                  "lf em 4x05 chk -f t55xx_default_pwds  -> use T55xx default dictionary"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "loads a default keys dictionary file <*.dic>"),
        arg_str0("e", "em", "<EM4100>", "try the calculated password from some cloners based on EM4100 ID"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    uint64_t card_id = 0;
    int res = arg_get_u64_hexstr_def_nlen(ctx, 2, 0, &card_id, 5, true);
    if (res == 2) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "EM4100 ID must be 5 hex bytes");
        return PM3_EINVARG;
    }
    if (res == 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    if (strlen(filename) == 0) {
        snprintf(filename, sizeof(filename), "t55xx_default_pwds");
    }
    PrintAndLogEx(NORMAL, "");

    bool found = false;
    uint64_t t1 = msclock();

    // White cloner password based on EM4100 ID
    if (card_id > 0) {

        uint32_t pwd = lf_t55xx_white_pwdgen(card_id & 0xFFFFFFFF);
        PrintAndLogEx(INFO, "testing %08"PRIX32" generated ", pwd);

        int status = em4x05_login_ext(pwd);
        if (status == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "found valid password [ " _GREEN_("%08"PRIX32) " ]", pwd);
            found = true;
        } else if (status != PM3_EFAILED) {
            PrintAndLogEx(WARNING, "no answer from tag");
        }
    }

    // Loop dictionary
    uint8_t *keyBlock = NULL;
    if (found == false) {

        uint32_t keycount = 0;

        res = loadFileDICTIONARY_safe(filename, (void **) &keyBlock, 4, &keycount);
        if (res != PM3_SUCCESS || keycount == 0 || keyBlock == NULL) {
            PrintAndLogEx(WARNING, "no keys found in file");
            if (keyBlock != NULL)
                free(keyBlock);

            return PM3_ESOFT;
        }

        PrintAndLogEx(INFO, "press " _GREEN_("<Enter>") " to exit");

        for (uint32_t c = 0; c < keycount; ++c) {

            if (!g_session.pm3_present) {
                PrintAndLogEx(WARNING, "device offline\n");
                free(keyBlock);
                return PM3_ENODATA;
            }

            if (is_cancelled()) {
                free(keyBlock);
                return PM3_EOPABORTED;
            }

            uint32_t curr_password = bytes_to_num(keyBlock + 4 * c, 4);

            PrintAndLogEx(INFO, "testing %08"PRIX32, curr_password);

            int status = em4x05_login_ext(curr_password);
            if (status == PM3_SUCCESS) {
                PrintAndLogEx(SUCCESS, "found valid password [ " _GREEN_("%08"PRIX32) " ]", curr_password);
                found = true;
                break;
            } else if (status != PM3_EFAILED) {
                PrintAndLogEx(WARNING, "no answer from tag");
            }
        }
    }

    if (found == false)
        PrintAndLogEx(WARNING, "check pwd failed");

    free(keyBlock);

    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "\ntime in check pwd " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);
    return PM3_SUCCESS;
}

int CmdEM4x05Brute(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x05 brute",
                  "This command tries to bruteforce the password of a EM4205/4305/4469/4569\n"
                  "The loop is running on device side,  press Proxmark3 button to abort\n",
                  "Note: if you get many false positives, change position on the antenna"
                  "lf em 4x05 brute\n"
                  "lf em 4x05 brute -n 1            -> stop after first candidate found\n"
                  "lf em 4x05 brute -s 000022AA     -> start at 000022AA"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("s", "start", "<hex>", "Start bruteforce enumeration from this password value"),
        arg_u64_0("n", NULL, "<dec>", "Stop after having found n candidates. Default: 0 (infinite)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t start_pwd = 0;
    int res = arg_get_u32_hexstr_def(ctx, 1, 0, &start_pwd);
    if (res != 1) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "check `start_pwd` parameter");
        return PM3_EINVARG;
    }

    uint32_t n = arg_get_u32_def(ctx, 2, 0);
    CLIParserFree(ctx);

    PrintAndLogEx(NORMAL, "");

    struct {
        uint32_t start_pwd;
        uint32_t n;
    } PACKED payload;

    payload.start_pwd = start_pwd;
    payload.n = n;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X_BF, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_EM4X_BF, &resp, 1000) == false) {
        PrintAndLogEx(WARNING, "(EM4x05 Bruteforce) timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }
    PrintAndLogEx(INFO, "Bruteforce is running on device side, press button to interrupt");
    return PM3_SUCCESS;
}

typedef struct {
    uint16_t cnt;
    uint32_t value;
} em4x05_unlock_item_t;

static int unlock_write_protect(bool use_pwd, uint32_t pwd, uint32_t data, bool verbose) {

    struct {
        uint32_t password;
        uint32_t data;
        uint8_t usepwd;
    } PACKED payload;

    payload.password = pwd;
    payload.data = data;
    payload.usepwd = use_pwd;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X_PROTECTWORD, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_EM4X_PROTECTWORD, &resp, 2000) == false) {
        PrintAndLogEx(ERR, "Error occurred, device did not respond during write operation.");
        return PM3_ETIMEOUT;
    }

    if (em4x05_download_samples() == false)
        return PM3_ENODATA;

    uint32_t dummy = 0;
    int status = em4x05_demod_resp(&dummy, true);
    if (status == PM3_SUCCESS && verbose)
        PrintAndLogEx(SUCCESS, "Data written and verified");
    else if (status == PM3_EFAILED)
        PrintAndLogEx(ERR, "Tag denied PROTECT operation");
    else
        PrintAndLogEx(DEBUG, "No answer from tag");

    return status;
}
static int unlock_reset(bool use_pwd, uint32_t pwd, uint32_t data, bool verbose) {
    if (verbose)
        PrintAndLogEx(INFO, "resetting the " _RED_("active") " lock block");

    return unlock_write_protect(use_pwd, pwd, data, false);
}
static void unlock_add_item(em4x05_unlock_item_t *array, uint8_t len, uint32_t value) {

    uint8_t i = 0;
    for (; i < len; i++) {
        if (array[i].value == value) {
            array[i].cnt++;
            break;
        }
        if (array[i].cnt == 0) {
            array[i].cnt++;
            array[i].value = value;
            break;
        }
    }
}

int CmdEM4x05Unlock(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x05 unlock",
                  "execute tear off against EM4205/4305/4469/4569",
                  "lf em 4x05 unlock\n"
                  "lf em 4x05 unlock -s 4100 -e 4100       -> lock on and autotune at 4100us\n"
                  "lf em 4x05 unlock -n 10 -s 3000 -e 4400 -> scan delays 3000us -> 4400us"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("n", NULL, NULL, "steps to skip"),
        arg_int0("s", "start", "<us>", "start scan from delay (us)"),
        arg_int0("e", "end", "<us>", "end scan at delay (us)"),
        arg_str0("p", "pwd", "<hex>", "password (def 00000000)"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    double n = (double)arg_get_int_def(ctx, 1, 0);
    double start = (double)arg_get_int_def(ctx, 2, 2000);
    double end = (double)arg_get_int_def(ctx, 3, 6000);
    uint64_t inputpwd = arg_get_u64_hexstr_def(ctx, 4, 0xFFFFFFFFFFFFFFFF);
    bool verbose = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (start > end) {
        PrintAndLogEx(FAILED, "start delay can\'t be larger than end delay %.0lf vs %.0lf", start, end);
        return PM3_EINVARG;
    }

    if (g_session.pm3_present == false) {
        PrintAndLogEx(WARNING, "device offline\n");
        return PM3_ENODATA;
    }

    bool use_pwd = false;
    uint32_t pwd = 0;
    if (inputpwd != 0xFFFFFFFFFFFFFFFF) {
        use_pwd = true;
        pwd = inputpwd & 0xFFFFFFFF;
    }

    uint32_t search_value = 0;
    uint32_t write_value = 0;
    //
    // initial phase
    //
    // read word 14
    uint32_t init_14 = 0;
    int res = em4x05_read_word_ext(14, pwd, use_pwd, &init_14);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "failed to read word 14\n");
        return PM3_ENODATA;
    }


    // read 15
    uint32_t init_15 = 0;
    res = em4x05_read_word_ext(15, pwd, use_pwd, &init_15);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "failed to read word 15\n");
        return PM3_ENODATA;
    }

#define ACTIVE_MASK 0x00008000
    if ((init_15 & ACTIVE_MASK) == ACTIVE_MASK) {
        search_value = init_15;
    } else {
        search_value = init_14;
    }

    if (search_value == ACTIVE_MASK) {
        PrintAndLogEx(SUCCESS, "Tag already fully unlocked, nothing to do");
        return PM3_SUCCESS;
    }

    bool my_auto = false;
    if (n == 0) {
        my_auto = true;
        n = (end - start) / 2;
    }

    // fix at one specific delay
    if (start == end) {
        n = 0;
    }

    PrintAndLogEx(INFO, "--------------- " _CYAN_("EM4x05 tear-off : target PROTECT") " -----------------------\n");

    PrintAndLogEx(INFO, "initial prot 14&15 [ " _GREEN_("%08X") ", " _GREEN_("%08X")  " ]", init_14, init_15);

    if (use_pwd) {
        PrintAndLogEx(INFO, "   target password [ " _GREEN_("%08X") " ]", pwd);
    }
    if (my_auto) {
        PrintAndLogEx(INFO, "    automatic mode [ " _GREEN_("enabled") " ]");
    }

    PrintAndLogEx(INFO, "   target stepping [ " _GREEN_("%.0lf") " ]", n);
    PrintAndLogEx(INFO, "target delay range [ " _GREEN_("%.0lf") " ... " _GREEN_("%.0lf") " ]", start, end);
    PrintAndLogEx(INFO, "      search value [ " _GREEN_("%08X") " ]", search_value);
    PrintAndLogEx(INFO, "       write value [ " _GREEN_("%08X") " ]", write_value);

    PrintAndLogEx(INFO, "----------------------------------------------------------------------------\n");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "press " _GREEN_("<Enter>'") " to exit");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--------------- " _CYAN_("start") " -----------------------\n");

    int exit_code = PM3_SUCCESS;
    uint32_t word14 = 0, word15 = 0;
    uint32_t word14b = 0, word15b = 0;
    uint32_t tries = 0;
    uint32_t soon = 0;
    uint32_t late = 0;

    em4x05_unlock_item_t flipped[64] = {{0, 0}};

    //
    // main loop
    //
    bool success = false;
    uint64_t t1 = msclock();
    while (start <= end) {

        if (my_auto && n < 1) {
            PrintAndLogEx(INFO, "Reached n < 1                       => " _YELLOW_("disabling automatic mode"));
            end = start;
            my_auto = false;
            n = 0;
        }

        if (my_auto == false) {
            start += n;
        }

        if (tries >= 5 && n == 0 && soon != late) {

            if (soon > late) {
                start++;
                end++;
                PrintAndLogEx(INFO, "Tried %d times, soon:%i late:%i        => " _CYAN_("adjust +1 us >> %.0lf us"), tries, soon, late, start);
            } else {
                start--;
                end--;
                PrintAndLogEx(INFO, "Tried %d times, soon:%i late:%i        => " _CYAN_("adjust -1 us >> %.0lf us"), tries, soon, late, start);
            }
            tries = 0;
            soon = 0;
            late = 0;
        }

        if (is_cancelled()) {
            exit_code = PM3_EOPABORTED;
            break;
        }

        // set tear off trigger
        clearCommandBuffer();
        tearoff_params_t params = {
            .delay_us = start,
            .on = true,
            .off = false
        };
        res = handle_tearoff(&params, verbose);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "failed to configure tear off");
            return PM3_ESOFT;
        }

        // write
        // don't check the return value. As a tear-off occurred, the write failed.
        unlock_write_protect(use_pwd, pwd, write_value, verbose);

        // read after trigger
        res = em4x05_read_word_ext(14, pwd, use_pwd, &word14);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "failed to read 14");
            return PM3_ESOFT;
        }

        // read after trigger
        res = em4x05_read_word_ext(15, pwd, use_pwd, &word15);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "failed to read 15");
            return PM3_ESOFT;
        }

        if (verbose)
            PrintAndLogEx(INFO, "ref:%08X   14:%08X   15:%08X ", search_value, word14, word15);

        if (word14 == search_value && word15 == 0) {
            PrintAndLogEx(INFO, "Status: Nothing happened            => " _GREEN_("tearing too soon"));

            if (my_auto) {
                start += n;
                PrintAndLogEx(INFO, "                                    => " _CYAN_("adjust +%.0lf us >> %.0lf us"), n, start);
                n = (int)(n / 2);
            } else {
                soon++;
            }
        } else {

            if (word15 == search_value) {

                if (word14 == 0) {
                    PrintAndLogEx(INFO, "Status: Protect succeeded           => " _GREEN_("tearing too late"));
                } else {
                    if (word14 == search_value) {
                        PrintAndLogEx(INFO, "Status: 15 ok, 14 not yet erased    => " _GREEN_("tearing too late"));
                    } else {
                        PrintAndLogEx(INFO, "Status: 15 ok, 14 partially erased  => " _GREEN_("tearing too late"));
                    }
                }

                unlock_reset(use_pwd, pwd, write_value, verbose);

                // read after reset
                res = em4x05_read_word_ext(14, pwd, use_pwd, &word14b);
                if (res != PM3_SUCCESS) {
                    PrintAndLogEx(WARNING, "failed to read 14");
                    return PM3_ESOFT;
                }

                if (word14b == 0) {

                    unlock_reset(use_pwd, pwd, write_value, verbose);

                    res = em4x05_read_word_ext(14, pwd, use_pwd, &word14b);
                    if (res != PM3_SUCCESS) {
                        PrintAndLogEx(WARNING, "failed to read 14");
                        return PM3_ESOFT;
                    }
                }

                if (word14b != search_value) {

                    res = em4x05_read_word_ext(15, pwd, use_pwd, &word15b);
                    if (res == PM3_SUCCESS) {
                        PrintAndLogEx(INFO, "Status: new definitive value!       => " _RED_("SUCCESS:") " 14: " _CYAN_("%08X") "  15: %08X", word14b, word15b);
                        success = true;
                        break;
                    } else {
                        PrintAndLogEx(WARNING, "failed to read 15");
                        return PM3_ESOFT;
                    }
                }
                if (my_auto) {
                    end = start;
                    start -= n;
                    PrintAndLogEx(INFO, "                                    => " _CYAN_("adjust -%.0lf us >> %.0lf us"), n, start);
                    n = (int)(n / 2);
                } else {
                    late++;
                }

            } else {

                if ((word15 & ACTIVE_MASK) == ACTIVE_MASK) {

                    PrintAndLogEx(INFO, "Status: 15 bitflipped and active    => " _RED_("SUCCESS?:  ") "14: %08X  15: " _CYAN_("%08X"), word14, word15);
                    PrintAndLogEx(INFO, "Committing results...");

                    unlock_reset(use_pwd, pwd, write_value, verbose);

                    // read after reset
                    res = em4x05_read_word_ext(14, pwd, use_pwd, &word14b);
                    if (res != PM3_SUCCESS) {
                        PrintAndLogEx(WARNING, "failed to read 14");
                        return PM3_ESOFT;
                    }

                    res = em4x05_read_word_ext(15, pwd, use_pwd, &word15b);
                    if (res != PM3_SUCCESS) {
                        PrintAndLogEx(WARNING, "failed to read 15");
                        return PM3_ESOFT;
                    }

                    if (verbose)
                        PrintAndLogEx(INFO, "ref:%08x   14:%08X   15:%08X", search_value, word14b, word15b);

                    if ((word14b & ACTIVE_MASK) == ACTIVE_MASK) {

                        if (word14b == word15) {
                            PrintAndLogEx(INFO, "Status: confirmed                   => " _GREEN_("SUCCESS:   ") "14: " _GREEN_("%08X") "  15: %08X", word14b, word15b);

                            unlock_add_item(flipped, 64, word14b);
                            success = true;
                            break;
                        }

                        if (word14b != search_value) {
                            PrintAndLogEx(INFO, "Status: new definitive value!       => " _RED_("SUCCESS:   ") "14: " _CYAN_("%08X") "  15: %08X", word14b, word15b);

                            unlock_add_item(flipped, 64, word14b);
                            success = true;
                            break;
                        }

                        PrintAndLogEx(INFO, "Status: failed to commit bitflip        => " _RED_("FAIL:      ") "14: %08X  15: %08X", word14b, word15b);
                    }
                    if (my_auto) {
                        n = 0;
                        end = start;
                    } else {
                        tries = 0;
                        soon = 0;
                        late = 0;
                    }
                } else {
                    PrintAndLogEx(INFO, "Status: 15 bitflipped but inactive      => " _YELLOW_("PROMISING: ") "14: %08X  15: " _CYAN_("%08X"), word14, word15);

                    unlock_add_item(flipped, 64, word15);

                    soon ++;
                }
            }
        }

        if (my_auto == false) {
            tries++;
        }
    }

    PrintAndLogEx(INFO, "----------------------------- " _CYAN_("exit") " ----------------------------------\n");
    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "\ntime in unlock " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);
    if (success) {
        uint32_t bitflips = search_value ^ word14b;
        PrintAndLogEx(INFO, "Old protection word => " _YELLOW_("%08X"), search_value);
        char bitstring[9] = {0};
        for (int i = 0; i < 8; i++) {
            bitstring[i] = (bitflips & (0xFU << ((7 - i) * 4))) ? 'x' : '.';
        }
        // compute number of bits flipped
        PrintAndLogEx(INFO, "Bitflips: %2u events => %s", bitcount32(bitflips), bitstring);
        PrintAndLogEx(INFO, "New protection word => " _CYAN_("%08X") "\n", word14b);
        PrintAndLogEx(INFO, "Try " _YELLOW_("`lf em 4x05 dump`"));
    }

    if (verbose) {
        PrintAndLogEx(NORMAL, "Stats:");
        PrintAndLogEx(INFO, " idx | value    | cnt | flipped bits");
        PrintAndLogEx(INFO, "-----+----------+-----+------");
        for (uint8_t i = 0; i < 64; i++) {
            if (flipped[i].cnt == 0)
                break;

            PrintAndLogEx(INFO, " %3u | %08X | %3u | %u", i, flipped[i].value, flipped[i].cnt, bitcount32(search_value ^ flipped[i].value));
        }
    }
    PrintAndLogEx(NORMAL, "");
    return exit_code;
}

static size_t em4x05_Sniff_GetNextBitStart(size_t idx, size_t sc, const int *data, size_t *pulsesamples) {
    while ((idx < sc) && (data[idx] <= 10)) // find a going high
        idx++;

    while ((idx < sc) && (data[idx] > -10)) // find going low  may need to add something here it SHOULD be a small clk around 0, but white seems to extend a bit.
        idx++;

    (*pulsesamples) = 0;
    while ((idx < sc) && ((data[idx + 1] - data[idx]) < 10)) { // find "sharp rise"
        (*pulsesamples)++;
        idx++;
    }

    return idx;
}

static uint32_t em4x05_Sniff_GetBlock(const char *bits, bool fwd) {
    uint32_t value = 0;
    uint8_t idx;
    bool parityerror = false;
    uint8_t parity;

    parity = 0;
    for (idx = 0; idx < 8; idx++) {
        value <<= 1;
        value += (bits[idx] - '0');
        parity += (bits[idx] - '0');
    }
    parity = parity % 2;
    if (parity != (bits[8] - '0'))
        parityerror = true;

    parity = 0;
    for (idx = 9; idx < 17; idx++) {
        value <<= 1;
        value += (bits[idx] - '0');
        parity += (bits[idx] - '0');
    }
    parity = parity % 2;
    if (parity != (bits[17] - '0'))
        parityerror = true;

    parity = 0;
    for (idx = 18; idx < 26; idx++) {
        value <<= 1;
        value += (bits[idx] - '0');
        parity += (bits[idx] - '0');
    }
    parity = parity % 2;
    if (parity != (bits[26] - '0'))
        parityerror = true;

    parity = 0;
    for (idx = 27; idx < 35; idx++) {
        value <<= 1;
        value += (bits[idx] - '0');
        parity += (bits[idx] - '0');
    }
    parity = parity % 2;
    if (parity != (bits[35] - '0'))
        parityerror = true;

    if (parityerror)
        PrintAndLogEx(ERR, "parity error : ");

    if (!fwd) {
        uint32_t t1 = value;
        value = 0;
        for (idx = 0; idx < 32; idx++)
            value |= (((t1 >> idx) & 1) << (31 - idx));
    }
    return value;
}

int CmdEM4x05Sniff(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x05 sniff",
                  "Sniff EM4x05 commands sent from a programmer",
                  "lf em 4x05 sniff     --> sniff via lf sniff\n"
                  "lf em 4x05 sniff -1  --> sniff from data loaded into the buffer\n"
                  "lf em 4x05 sniff -r  --> reverse the bit order when showing block data"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("1", "buf", "Use the data in the buffer"),
        arg_lit0("r", "rev", "Reverse the bit order for data blocks"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool sampleData = (arg_get_lit(ctx, 1) == false);
    bool fwd = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    const char *cmdText;
    char dataText[100];
    char blkAddr[4];
    int i;
    int ZeroWidth;    // 32-42 "1" is 32
    int CycleWidth;
    size_t pulseSamples;

    // setup and sample data from Proxmark
    // if not directed to existing sample/graphbuffer
    if (sampleData) {
        if (IfPm3Lf() == false) {
            PrintAndLogEx(WARNING, "Only offline mode is available");
            return PM3_EINVARG;
        }
        CmdLFSniff("");
    }

    // Headings
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, _CYAN_("EM4x05 command detection"));
    PrintAndLogEx(SUCCESS, "offset | Command     |   Data   | blk | raw");
    PrintAndLogEx(SUCCESS, "-------+-------------+----------+-----+------------------------------------------------------------");

    smartbuf bits = { 0 };
    bits.ptr = malloc(EM4X05_BITS_BUFSIZE);
    bits.size = EM4X05_BITS_BUFSIZE;
    bits.idx = 0;
    size_t idx = 0;
    // loop though sample buffer
    while (idx < g_GraphTraceLen) {
        bool haveData = false;
        bool pwd = false;

        idx = em4x05_Sniff_GetNextBitStart(idx, g_GraphTraceLen, g_GraphBuffer, &pulseSamples);
        size_t pktOffset = idx;
        if (pulseSamples >= 10)  { // Should be 18 so a bit less to allow for processing

            // Use first bit to get "0" bit samples as a reference
            ZeroWidth = idx;
            idx = em4x05_Sniff_GetNextBitStart(idx, g_GraphTraceLen, g_GraphBuffer, &pulseSamples);
            ZeroWidth = idx - ZeroWidth;

            if (ZeroWidth <= 50) {
                pktOffset -= ZeroWidth;
                memset(bits.ptr, 0, bits.size);
                bits.idx = 0;

                bool eop = false;
                while ((idx < g_GraphTraceLen) && !eop) {
                    CycleWidth = idx;
                    idx = em4x05_Sniff_GetNextBitStart(idx, g_GraphTraceLen, g_GraphBuffer, &pulseSamples);

                    CycleWidth = idx - CycleWidth;
                    if ((CycleWidth > 300) || (CycleWidth < (ZeroWidth - 5))) { // to long or too short
                        eop = true;
                        sb_append_char(&bits, '0');   // Append last zero from the last bit find
                        cmdText = "";

                        // EM4305 command lengths
                        // Login        0011 <pwd>          => 4 +     45 => 49
                        // Write Word   0101 <adr> <data>   => 4 + 7 + 45 => 56
                        // Read Word    1001 <adr>          => 4 + 7      => 11
                        // Protect      1100       <data>   => 4 +     45 => 49
                        // Disable      1010       <data>   => 4 +     45 => 49
                        // -> disable 1010 11111111 0 11111111 0 11111111 0 11111111 0 00000000 0

                        // Check to see if we got the leading 0
                        if (((strncmp(bits.ptr, "00011", 5) == 0) && (bits.idx == 50)) ||
                                ((strncmp(bits.ptr, "00101", 5) == 0) && (bits.idx == 57)) ||
                                ((strncmp(bits.ptr, "01001", 5) == 0) && (bits.idx == 12)) ||
                                ((strncmp(bits.ptr, "01100", 5) == 0) && (bits.idx == 50)) ||
                                ((strncmp(bits.ptr, "01010", 5) == 0) && (bits.idx == 50))) {
                            memmove(bits.ptr, &bits.ptr[1], bits.idx - 1);
                            bits.idx--;
                            PrintAndLogEx(INFO, "Trim leading 0");
                        }
                        sb_append_char(&bits, 0);
                        bits.idx--;

                        // logon
                        if ((strncmp(bits.ptr, "0011", 4) == 0) && (bits.idx == 49)) {
                            haveData = true;
                            pwd = true;
                            cmdText = "Logon";
                            strncpy(blkAddr, "   ",  sizeof(blkAddr));
                            uint32_t tmpValue = em4x05_Sniff_GetBlock(&bits.ptr[4], fwd);
                            snprintf(dataText, sizeof(dataText), "%08X", tmpValue);
                        }

                        // write
                        if ((strncmp(bits.ptr, "0101", 4) == 0) && (bits.idx == 56)) {
                            haveData = true;
                            cmdText = "Write";
                            uint32_t tmpValue = (bits.ptr[4] - '0') + ((bits.ptr[5] - '0') << 1) + ((bits.ptr[6] - '0') << 2)  + ((bits.ptr[7] - '0') << 3);
                            snprintf(blkAddr, sizeof(blkAddr), "%u", tmpValue);
                            if (tmpValue == 2) {
                                pwd = true;
                            }
                            tmpValue = em4x05_Sniff_GetBlock(&bits.ptr[11], fwd);
                            snprintf(dataText, sizeof(dataText), "%08X", tmpValue);
                        }

                        // read
                        if ((strncmp(bits.ptr, "1001", 4) == 0) && (bits.idx == 11)) {
                            haveData = true;
                            pwd = false;
                            cmdText = "Read";
                            uint32_t tmpValue = (bits.ptr[4] - '0') + ((bits.ptr[5] - '0') << 1) + ((bits.ptr[6] - '0') << 2)  + ((bits.ptr[7] - '0') << 3);
                            snprintf(blkAddr, sizeof(blkAddr), "%u", tmpValue);
                            strncpy(dataText, " ", sizeof(dataText));
                        }

                        // protect
                        if ((strncmp(bits.ptr, "1100", 4) == 0) && (bits.idx == 49)) {
                            haveData = true;
                            pwd = false;
                            cmdText = "Protect";
                            strncpy(blkAddr, " ",  sizeof(blkAddr));
                            uint32_t tmpValue = em4x05_Sniff_GetBlock(&bits.ptr[11], fwd);
                            snprintf(dataText, sizeof(dataText), "%08X", tmpValue);
                        }

                        // disable
                        if ((strncmp(bits.ptr, "1010", 4) == 0) && (bits.idx == 49)) {
                            haveData = true;
                            pwd = false;
                            cmdText = "Disable";
                            strncpy(blkAddr, " ",  sizeof(blkAddr));
                            uint32_t tmpValue = em4x05_Sniff_GetBlock(&bits.ptr[11], fwd);
                            snprintf(dataText, sizeof(dataText), "%08X", tmpValue);
                        }

                        //  bits[bitidx] = 0;
                    } else {
                        i = (CycleWidth - ZeroWidth) / 28;
                        sb_append_char(&bits, '0');
                        for (int ii = 0; ii < i; ii++) {
                            sb_append_char(&bits, '1');
                        }
                    }
                }
            }
        }
        idx++;

        // Print results
        if (haveData) { //&& (minWidth > 1) && (maxWidth > minWidth)){
            if (pwd)
                PrintAndLogEx(SUCCESS, "%6zu | %-10s  | " _YELLOW_("%8s")" | " _YELLOW_("%3s")" | %s", pktOffset, cmdText, dataText, blkAddr, bits.ptr);
            else
                PrintAndLogEx(SUCCESS, "%6zu | %-10s  | " _GREEN_("%8s")" | " _GREEN_("%3s")" | %s", pktOffset, cmdText, dataText, blkAddr, bits.ptr);
        }
    }
    free(bits.ptr);
    bits.ptr = NULL;

    // footer
    PrintAndLogEx(SUCCESS, "---------------------------------------------------------------------------------------------------");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,              AlwaysAvailable, "This help"},
    {"brute",  CmdEM4x05Brute,       IfPm3Lf,         "Bruteforce password"},
    {"chk",    CmdEM4x05Chk,         IfPm3Lf,         "Check passwords from dictionary"},
    {"demod",  CmdEM4x05Demod,       AlwaysAvailable, "Demodulate a EM4x05/EM4x69 tag from the GraphBuffer"},
    {"dump",   CmdEM4x05Dump,        IfPm3Lf,         "Dump EM4x05/EM4x69 tag"},
    {"info",   CmdEM4x05Info,        IfPm3Lf,         "Tag information"},
    {"read",   CmdEM4x05Read,        IfPm3Lf,         "Read word data from EM4x05/EM4x69"},
    {"sniff",  CmdEM4x05Sniff,       AlwaysAvailable, "Attempt to recover em4x05 commands from sample buffer"},
    {"unlock", CmdEM4x05Unlock,      IfPm3Lf,         "Execute tear off against EM4x05/EM4x69"},
    {"wipe",   CmdEM4x05Wipe,        IfPm3Lf,         "Wipe EM4x05/EM4x69 tag"},
    {"write",  CmdEM4x05Write,       IfPm3Lf,         "Write word data to EM4x05/EM4x69"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFEM4X05(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
