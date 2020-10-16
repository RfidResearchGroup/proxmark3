//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x commands
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

//////////////// 4205 / 4305 commands
static int usage_lf_em4x05_dump(void) {
    PrintAndLogEx(NORMAL, "Dump EM4x05/EM4x69.  Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x05_dump [h] [f <filename prefix>] <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h                     - this help");
    PrintAndLogEx(NORMAL, "       f <filename prefix>   - overide filename prefix (optional).  Default is based on UID");
    PrintAndLogEx(NORMAL, "       pwd                   - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x05_dump");
    PrintAndLogEx(NORMAL, "      lf em 4x05_dump 11223344");
    PrintAndLogEx(NORMAL, "      lf em 4x05_dump f card1 11223344");
    return PM3_SUCCESS;
}
static int usage_lf_em4x05_wipe(void) {
    PrintAndLogEx(NORMAL, "Wipe EM4x05/EM4x69.  Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x05_wipe [h] <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h     - this help");
    PrintAndLogEx(NORMAL, "       c     - chip type : 0 em4205");
    PrintAndLogEx(NORMAL, "                           1 em4305 (default)");
    PrintAndLogEx(NORMAL, "       pwd   - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x05_wipe");
    PrintAndLogEx(NORMAL, "      lf em 4x05_wipe 11223344");
    return PM3_SUCCESS;
}
static int usage_lf_em4x05_read(void) {
    PrintAndLogEx(NORMAL, "Read EM4x05/EM4x69.  Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x05_read [h] <address> <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       address   - memory address to read. (0-15)");
    PrintAndLogEx(NORMAL, "       pwd       - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x05_read 1");
    PrintAndLogEx(NORMAL, "      lf em 4x05_read 1 11223344");
    return PM3_SUCCESS;
}
static int usage_lf_em4x05_write(void) {
    PrintAndLogEx(NORMAL, "Write EM4x05/4x69.  Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x05_write [h] <address> <data> <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       address   - memory address to write to. (0-13, 99 for Protection Words)");
    PrintAndLogEx(NORMAL, "       data      - data to write (hex)");
    PrintAndLogEx(NORMAL, "       pwd       - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x05_write 1 deadc0de");
    PrintAndLogEx(NORMAL, "      lf em 4x05_write 1 deadc0de 11223344");
    return PM3_SUCCESS;
}
static int usage_lf_em4x05_info(void) {
    PrintAndLogEx(NORMAL, "Tag information EM4205/4305/4469//4569 tags.  Tag must be on antenna.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x05_info [h] <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       pwd       - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x05_info");
    PrintAndLogEx(NORMAL, "      lf em 4x05_info deadc0de");
    return PM3_SUCCESS;
}

// even parity COLUMN
static bool EM_ColParityTest(uint8_t *bs, size_t size, uint8_t rows, uint8_t cols, uint8_t pType) {
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

#define EM_PREAMBLE_LEN 6
// download samples from device and copy to Graphbuffer
static bool downloadSamplesEM(void) {

    // 8 bit preamble + 32 bit word response (max clock (128) * 40bits = 5120 samples)
    uint8_t got[6000];
    if (!GetFromDevice(BIG_BUF, got, sizeof(got), 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "(downloadSamplesEM) command execution time out");
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
    if (DemodBufferLen < EM_PREAMBLE_LEN) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM4305 demodbuffer too small");
        return PM3_ESOFT;
    }

    // set size to 9 to only test first 3 positions for the preamble
    // do not set it too long else an error preamble followed by 010 could be seen as success.
    size_t size = (9 > DemodBufferLen) ? DemodBufferLen : 9;
    *startIdx = 0;
    // skip first two 0 bits as they might have been missed in the demod
    uint8_t preamble[EM_PREAMBLE_LEN] = {0, 0, 1, 0, 1, 0};

    if (!preambleSearchEx(DemodBuffer, preamble, EM_PREAMBLE_LEN, &size, startIdx, true)) {
        uint8_t errpreamble[EM_PREAMBLE_LEN] = {0, 0, 0, 0, 0, 1};
        if (!preambleSearchEx(DemodBuffer, errpreamble, EM_PREAMBLE_LEN, &size, startIdx, true)) {
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

        //try psk1 inverted
        ans = PSKDemod(0, 1, 6, false);
        if (ans != PM3_SUCCESS) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - EM: PSK1 inverted Demod failed");
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
static int setDemodBufferEM(uint32_t *word, size_t idx) {

    //test for even parity bits.
    uint8_t parity[45] = {0};
    memcpy(parity, DemodBuffer, 45);
    if (!EM_ColParityTest(DemodBuffer + idx + EM_PREAMBLE_LEN, 45, 5, 9, 0)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - End Parity check failed");
        return PM3_ESOFT;
    }

    // test for even parity bits and remove them. (leave out the end row of parities so 36 bits)
    if (!removeParity(DemodBuffer, idx + EM_PREAMBLE_LEN, 9, 0, 36)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM, failed removing parity");
        return PM3_ESOFT;
    }
    setDemodBuff(DemodBuffer, 32, 0);
    *word = bytebits_to_byteLSBF(DemodBuffer, 32);
    return PM3_SUCCESS;
}

// FSK, PSK, ASK/MANCHESTER, ASK/BIPHASE, ASK/DIPHASE, NRZ
// should cover 90% of known used configs
// the rest will need to be manually demoded for now...
static int demodEM4x05resp(uint32_t *word, bool onlyPreamble) {
    size_t idx = 0;
    *word = 0;
    bool found_err = false;
    int res = PM3_SUCCESS;
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

            psk1TOpsk2(DemodBuffer, DemodBufferLen);
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
    res = setDemodBufferEM(word, idx);
    if (res == PM3_SUCCESS)
        return res;
    if (found_err)
        return PM3_EFAILED;
    return res;
}

//////////////// 4205 / 4305 commands

int EM4x05ReadWord_ext(uint8_t addr, uint32_t pwd, bool usePwd, uint32_t *word) {

    struct {
        uint32_t password;
        uint8_t address;
        uint8_t usepwd;
    } PACKED payload;

    payload.password = pwd;
    payload.address = addr;
    payload.usepwd = usePwd;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X_READWORD, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X_READWORD, &resp, 10000)) {
        PrintAndLogEx(WARNING, "(EM4x05ReadWord_ext) timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (downloadSamplesEM() == false) {
        return PM3_ESOFT;
    }
    return demodEM4x05resp(word, false);
}

int CmdEM4x05Demod(const char *Cmd) {
//    uint8_t ctmp = tolower(param_getchar(Cmd, 0));
//   if (ctmp == 'h') return usage_lf_em4x05_demod();
    uint32_t dummy = 0;
    return demodEM4x05resp(&dummy, false);
}

int CmdEM4x05Dump(const char *Cmd) {
    uint8_t addr = 0;
    uint32_t pwd = 0;
    bool usePwd = false;
    bool needReadPwd = true;
    uint8_t cmdp = 0;
    uint8_t bytes[4] = {0};
    uint32_t data[16];
    char preferredName[FILE_PATH_SIZE] = {0};
    char optchk[10];

    while (param_getchar(Cmd, cmdp) != 0x00) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_em4x05_dump();
                break;
            case 'f':   // since f could match in password, lets confirm it is 1 character only for an option
                param_getstr(Cmd, cmdp, optchk, sizeof(optchk));
                if (strlen(optchk) == 1) { // Have a single character f so filename no password
                    param_getstr(Cmd, cmdp + 1, preferredName, FILE_PATH_SIZE);
                    cmdp += 2;
                    break;
                } // if not a single 'f' dont break and flow onto default as should be password

            default :   // for backwards-compatibility options should be > 'f' else assume its the hex password`
                // for now use default input of 1 as invalid (unlikely 1 will be a valid password...)
                pwd = param_get32ex(Cmd, cmdp, 1, 16);
                if (pwd != 1)
                    usePwd = true;
                cmdp++;
        };
    }

    int success = PM3_SUCCESS;
    int status, status14, status15;
    uint32_t lock_bits = 0x00; // no blocks locked
    bool gotLockBits = false;
    bool lockInPW2 = false;
    uint32_t word = 0;
    const char *info[] = {"Info/User", "UID", "Password", "User", "Config", "User", "User", "User", "User", "User", "User", "User", "User", "User", "Lock", "Lock"};

    if (usePwd) {
        // Test first if a password is required
        status = EM4x05ReadWord_ext(14, pwd, false, &word);
        if (status == PM3_SUCCESS) {
            PrintAndLogEx(INFO, "Note that password doesn't seem to be needed");
            needReadPwd = false;
        }
    }
    PrintAndLogEx(NORMAL, "Addr | data     | ascii |lck| info");
    PrintAndLogEx(NORMAL, "-----+----------+-------+---+-----");

    // To flag any blocks locked we need to read blocks 14 and 15 first
    // dont swap endin until we get block lock flags.
    status14 = EM4x05ReadWord_ext(14, pwd, usePwd, &word);
    if (status14 == PM3_SUCCESS) {
        if (!usePwd)
            needReadPwd = false;
        if ((word & 0x00008000) != 0x00) {
            lock_bits = word;
            gotLockBits = true;
        }
        data[14] = word;
    } else {
        success = PM3_ESOFT; // If any error ensure fail is set so not to save invalid data
    }
    status15 = EM4x05ReadWord_ext(15, pwd, usePwd, &word);
    if (status15 == PM3_SUCCESS) {
        if ((word & 0x00008000) != 0x00) { // assume block 15 is the current lock block
            lock_bits = word;
            gotLockBits = true;
            lockInPW2 = true;
        }
        data[15] = word;
    } else {
        success = PM3_ESOFT; // If any error ensure fail is set so not to save invalid data
    }
    uint32_t lockbit;
    // Now read blocks 0 - 13 as we have 14 and 15
    for (; addr < 14; addr++) {
        lockbit = (lock_bits >> addr) & 1;
        if (addr == 2) {
            if (usePwd) {
                if ((needReadPwd) && (success != PM3_ESOFT)) {
                    data[addr] = BSWAP_32(pwd);
                    num_to_bytes(pwd, 4, bytes);
                    PrintAndLogEx(NORMAL, "  %02u | %08X | %s  | %s | %s", addr, pwd, sprint_ascii(bytes, 4), gotLockBits ? (lockbit ? _RED_("x") : " ") : _YELLOW_("?"), info[addr]);
                } else {
                    // The pwd is not needed for Login so we're not sure what's the actual content of that block
                    PrintAndLogEx(NORMAL, "  %02u |          |       |   | %-10s " _YELLOW_("write only"), addr, info[addr]);
                }
            } else {
                data[addr] = 0x00; // Unknown password, but not used to set to zeros
                PrintAndLogEx(NORMAL, "  %02u |          |       |   | %-10s " _YELLOW_("write only"), addr, info[addr]);
            }
        } else {
            // success &= EM4x05ReadWord_ext(addr, pwd, usePwd, &word);
            status = EM4x05ReadWord_ext(addr, pwd, usePwd, &word); // Get status for single read
            if (status != PM3_SUCCESS)
                success = PM3_ESOFT; // If any error ensure fail is set so not to save invalid data
            data[addr] = BSWAP_32(word);
            if (status == PM3_SUCCESS) {
                num_to_bytes(word, 4, bytes);
                PrintAndLogEx(NORMAL, "  %02u | %08X | %s  | %s | %s", addr, word, sprint_ascii(bytes, 4), gotLockBits ? (lockbit ? _RED_("x") : " ") : _YELLOW_("?"), info[addr]);
            } else
                PrintAndLogEx(NORMAL, "  %02u |          |       |   | %-10s %s", addr, info[addr], status == PM3_EFAILED ? _RED_("read denied") : _RED_("read failed"));
        }
    }
    // Print blocks 14 and 15
    // Both lock bits are protected with bit idx 14 (special case)
    addr = 14;
    if (status14 == PM3_SUCCESS) {
        lockbit = (lock_bits >> addr) & 1;
        PrintAndLogEx(NORMAL, "  %02u | %08X | %s  | %s | %-10s %s", addr, data[addr], sprint_ascii(bytes, 4), gotLockBits ? (lockbit ? _RED_("x") : " ") : _YELLOW_("?"), info[addr], lockInPW2 ? "" : _GREEN_("active"));
    } else {
        PrintAndLogEx(NORMAL, "  %02u |          |       |   | %-10s %s", addr, info[addr], status14 == PM3_EFAILED ? _RED_("read denied") : _RED_("read failed"));
    }
    addr = 15;
    if (status15 == PM3_SUCCESS) {
        lockbit = (lock_bits >> 14) & 1; // beware lock bit of word15 is pr14
        PrintAndLogEx(NORMAL, "  %02u | %08X | %s  | %s | %-10s %s", addr, data[addr], sprint_ascii(bytes, 4), gotLockBits ? (lockbit ? _RED_("x") : " ") : _YELLOW_("?"), info[addr], lockInPW2 ? _GREEN_("active") : "");
    } else {
        PrintAndLogEx(NORMAL, "  %02u |          |       |   | %-10s %s", addr, info[addr], status15 == PM3_EFAILED ? _RED_("read denied") : _RED_("read failed"));
    }
    // Update endian for files
    data[14] = BSWAP_32(data[14]);
    data[15] = BSWAP_32(data[15]);

    if (success == PM3_SUCCESS) { // all ok save dump to file
        // saveFileEML will add .eml extension to filename
        // saveFile (binary) passes in the .bin extension.
        if (strcmp(preferredName, "") == 0) // Set default filename, if not set by user
            sprintf(preferredName, "lf-4x05-%08X-dump", BSWAP_32(data[1]));

        saveFileEML(preferredName, (uint8_t *)data, 16 * sizeof(uint32_t), sizeof(uint32_t));
        saveFile(preferredName, ".bin", data, sizeof(data));
    }

    return success;
}

int CmdEM4x05Read(const char *Cmd) {
    uint8_t addr;
    uint32_t pwd;
    bool usePwd = false;

    uint8_t ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || ctmp == 'h') return usage_lf_em4x05_read();

    addr = param_get8ex(Cmd, 0, 50, 10);
    pwd =  param_get32ex(Cmd, 1, 0xFFFFFFFF, 16);

    if (addr > 15) {
        PrintAndLogEx(WARNING, "Address must be between 0 and 15");
        return PM3_ESOFT;
    }
    if (pwd == 0xFFFFFFFF) {
        PrintAndLogEx(INFO, "Reading address %02u", addr);
    } else {
        usePwd = true;
        PrintAndLogEx(INFO, "Reading address %02u using password %08X", addr, pwd);
    }

    uint32_t word = 0;
    int status = EM4x05ReadWord_ext(addr, pwd, usePwd, &word);
    if (status == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Address %02d | %08X - %s", addr, word, (addr > 13) ? "Lock" : "");
    else if (status == PM3_EFAILED)
        PrintAndLogEx(ERR, "Tag denied Read operation");
    else
        PrintAndLogEx(WARNING, "No answer from tag");
    return status;
}

int CmdEM4x05Write(const char *Cmd) {
    uint8_t ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || ctmp == 'h') return usage_lf_em4x05_write();

    bool usePwd = false;
    uint8_t addr;
    uint32_t data, pwd;

    addr = param_get8ex(Cmd, 0, 50, 10);
    data = param_get32ex(Cmd, 1, 0, 16);
    pwd =  param_get32ex(Cmd, 2, 0xFFFFFFFF, 16);
    bool protectOperation = addr == 99; // will do better with cliparser...

    if ((addr > 13) && (!protectOperation)) {
        PrintAndLogEx(WARNING, "Address must be between 0 and 13");
        return PM3_EINVARG;
    }
    if (pwd == 0xFFFFFFFF) {
        if (protectOperation)
            PrintAndLogEx(INFO, "Writing protection words data %08X", data);
        else
            PrintAndLogEx(INFO, "Writing address %d data %08X", addr, data);
    } else {
        usePwd = true;
        if (protectOperation)
            PrintAndLogEx(INFO, "Writing protection words data %08X using password %08X", data, pwd);
        else
            PrintAndLogEx(INFO, "Writing address %d data %08X using password %08X", addr, data, pwd);
    }

    if (protectOperation) { // set Protect Words
        struct {
            uint32_t password;
            uint32_t data;
            uint8_t usepwd;
        } PACKED payload;

        payload.password = pwd;
        payload.data = data;
        payload.usepwd = usePwd;

        clearCommandBuffer();
        SendCommandNG(CMD_LF_EM4X_PROTECTWORD, (uint8_t *)&payload, sizeof(payload));
        PacketResponseNG resp;
        if (!WaitForResponseTimeout(CMD_LF_EM4X_PROTECTWORD, &resp, 2000)) {
            PrintAndLogEx(ERR, "Error occurred, device did not respond during write operation.");
            return PM3_ETIMEOUT;
        }
    } else {
        struct {
            uint32_t password;
            uint32_t data;
            uint8_t address;
            uint8_t usepwd;
        } PACKED payload;

        payload.password = pwd;
        payload.data = data;
        payload.address = addr;
        payload.usepwd = usePwd;

        clearCommandBuffer();
        SendCommandNG(CMD_LF_EM4X_WRITEWORD, (uint8_t *)&payload, sizeof(payload));
        PacketResponseNG resp;
        if (!WaitForResponseTimeout(CMD_LF_EM4X_WRITEWORD, &resp, 2000)) {
            PrintAndLogEx(ERR, "Error occurred, device did not respond during write operation.");
            return PM3_ETIMEOUT;
        }
    }
    if (!downloadSamplesEM())
        return PM3_ENODATA;

    uint32_t dummy = 0;
    int status = demodEM4x05resp(&dummy, true);
    if (status == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Success writing to tag");
    else if (status == PM3_EFAILED)
        PrintAndLogEx(ERR, "Tag denied %s operation", protectOperation ? "Protect" : "Write");
    else
        PrintAndLogEx(DEBUG, "No answer from tag");

    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf em 4x05_read`") " to verify");
    return status;
}

int CmdEM4x05Wipe(const char *Cmd) {
    uint8_t addr = 0;
    uint32_t pwd = 0;
    uint8_t cmdp = 0;
    uint8_t  chipType  = 1; // em4305
    uint32_t chipInfo  = 0x00040072; // Chip info/User Block normal 4305 Chip Type
    uint32_t chipUID   = 0x614739AE; // UID normally readonly, but just in case
    uint32_t blockData = 0x00000000; // UserBlock/Password (set to 0x00000000 for a wiped card1
    uint32_t config    = 0x0001805F; // Default config (no password)
    int success = PM3_SUCCESS;
    char cmdStr [100];
    char optchk[10];

    while (param_getchar(Cmd, cmdp) != 0x00) {
        // check if cmd is a 1 byte option
        param_getstr(Cmd, cmdp, optchk, sizeof(optchk));
        if (strlen(optchk) == 1) { // Have a single character so option not part of password
            switch (tolower(param_getchar(Cmd, cmdp))) {
                case 'c':   // chip type
                    if (param_getchar(Cmd, cmdp) != 0x00)
                        chipType = param_get8ex(Cmd, cmdp + 1, 0, 10);
                    cmdp += 2;
                    break;
                case 'h':   // return usage_lf_em4x05_wipe();
                default :   // Unknown or 'h' send help
                    return usage_lf_em4x05_wipe();
                    break;
            };
        } else { // Not a single character so assume password
            pwd = param_get32ex(Cmd, cmdp, 1, 16);
            cmdp++;
        }
    }

    switch (chipType) {
        case 0  : // em4205
            chipInfo  = 0x00040070;
            config    = 0x0001805F;
            break;
        case 1  : // em4305
            chipInfo  = 0x00040072;
            config    = 0x0001805F;
            break;
        default : // Type 0/Default : EM4305
            chipInfo  = 0x00040072;
            config    = 0x0001805F;
    }

    // block 0 : User Data or Chip Info
    sprintf(cmdStr, "%d %08X %08X", 0, chipInfo, pwd);
    CmdEM4x05Write(cmdStr);
    // block 1 : UID - this should be read only for EM4205 and EM4305 not sure about others
    sprintf(cmdStr, "%d %08X %08X", 1, chipUID, pwd);
    CmdEM4x05Write(cmdStr);
    // block 2 : password
    sprintf(cmdStr, "%d %08X %08X", 2, blockData, pwd);
    CmdEM4x05Write(cmdStr);
    pwd = blockData; // Password should now have changed, so use new password
    // block 3 : user data
    sprintf(cmdStr, "%d %08X %08X", 3, blockData, pwd);
    CmdEM4x05Write(cmdStr);
    // block 4 : config
    sprintf(cmdStr, "%d %08X %08X", 4, config, pwd);
    CmdEM4x05Write(cmdStr);

    // Remainder of user/data blocks
    for (addr = 5; addr < 14; addr++) {// Clear user data blocks
        sprintf(cmdStr, "%d %08X %08X", addr, blockData, pwd);
        CmdEM4x05Write(cmdStr);
    }

    return success;
}

static void printEM4x05config(uint32_t wordData) {
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
    uint8_t pigeon = (wordData & (1 << 26)) >> 26;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Config Information") " ---------------------------");
    PrintAndLogEx(INFO, "ConfigWord: %08X (Word 4)", wordData);
    PrintAndLogEx(INFO, " Data Rate:  %02u | "_YELLOW_("RF/%u"), wordData & 0x3F, datarate);
    PrintAndLogEx(INFO, "   Encoder:   %u | " _YELLOW_("%s"), encoder, enc);
    PrintAndLogEx(INFO, "    PSK CF:   %u | %s", PSKcf, cf);
    PrintAndLogEx(INFO, "     Delay:   %u | %s", delay, cdelay);
    PrintAndLogEx(INFO, " LastWordR:  %02u | Address of last word for default read - meaning %u blocks are output", LWR, numblks);
    PrintAndLogEx(INFO, " ReadLogin:   %u | Read login is %s", readLogin, readLogin ? _YELLOW_("required") :  _GREEN_("not required"));
    PrintAndLogEx(INFO, "   ReadHKL:   %u | Read housekeeping words login is %s", readHKL, readHKL ? _YELLOW_("required") : _GREEN_("not required"));
    PrintAndLogEx(INFO, "WriteLogin:   %u | Write login is %s", writeLogin, writeLogin ? _YELLOW_("required") :  _GREEN_("not required"));
    PrintAndLogEx(INFO, "  WriteHKL:   %u | Write housekeeping words login is %s", writeHKL, writeHKL ? _YELLOW_("required") :  _GREEN_("not Required"));
    PrintAndLogEx(INFO, "    R.A.W.:   %u | Read after write is %s", raw, raw ? "on" : "off");
    PrintAndLogEx(INFO, "   Disable:   %u | Disable command is %s", disable, disable ? "accepted" : "not accepted");
    PrintAndLogEx(INFO, "    R.T.F.:   %u | Reader talk first is %s", rtf, rtf ? _YELLOW_("enabled") : "disabled");
    PrintAndLogEx(INFO, "    Pigeon:   %u | Pigeon mode is %s", pigeon, pigeon ? _YELLOW_("enabled") : "disabled");
}

static void printEM4x05info(uint32_t block0, uint32_t serial) {

    uint8_t chipType = (block0 >> 1) & 0xF;
    uint8_t cap = (block0 >> 5) & 3;
    uint16_t custCode = (block0 >> 9) & 0x2FF;    

    PrintAndLogEx(INFO, "   block0: %X", block0);
    PrintAndLogEx(INFO, " chiptype: %X", chipType);
    PrintAndLogEx(INFO, "capacitor: %X", cap);
    PrintAndLogEx(INFO, " custcode: %X", custCode);
    
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

    char ctstr[50];
    snprintf(ctstr, sizeof(ctstr), " Chip Type:   %u | ", chipType);
    switch (chipType) {
        case 9:
            snprintf(ctstr + strlen(ctstr), sizeof(ctstr) - strlen(ctstr), _YELLOW_("%s"), "EM4305");
            break;
        case 4:
            snprintf(ctstr + strlen(ctstr), sizeof(ctstr) - strlen(ctstr), _YELLOW_("%s"), "EM4469");
            break;
        case 8:
            snprintf(ctstr + strlen(ctstr), sizeof(ctstr) - strlen(ctstr), _YELLOW_("%s"), "EM4205");
            break;
        //add more here when known
        default:
            snprintf(ctstr + strlen(ctstr), sizeof(ctstr) - strlen(ctstr), _YELLOW_("%s"), "Unknown");
            break;
    }
    PrintAndLogEx(SUCCESS, "%s", ctstr);

    switch (cap) {
        case 3:
            PrintAndLogEx(SUCCESS, "  Cap Type:   %u | 330pF", cap);
            break;
        case 2:
            PrintAndLogEx(SUCCESS, "  Cap Type:   %u | %spF", cap, (chipType == 2) ? "75" : "210");
            break;
        case 1:
            PrintAndLogEx(SUCCESS, "  Cap Type:   %u | 250pF", cap);
            break;
        case 0:
            PrintAndLogEx(SUCCESS, "  Cap Type:   %u | no resonant capacitor", cap);
            break;
        default:
            PrintAndLogEx(SUCCESS, "  Cap Type:   %u | unknown", cap);
            break;
    }

    PrintAndLogEx(SUCCESS, " Cust Code: %03u | %s", custCode, (custCode == 0x200) ? "Default" : "Unknown");
    if (serial != 0)
        PrintAndLogEx(SUCCESS, "  Serial #: " _YELLOW_("%08X"), serial);
}

static void printEM4x05ProtectionBits(uint32_t word, uint8_t addr) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Protection") " ---------------------------");
    PrintAndLogEx(INFO, "ProtectionWord: %08X (Word %i)", word, addr);
    for (uint8_t i = 0; i < 15; i++) {
        PrintAndLogEx(INFO, "      Word:  %02u | %s", i, ((1 << i) & word) ? _RED_("write Locked") : "unlocked");
        if (i == 14)
            PrintAndLogEx(INFO, "      Word:  %02u | %s", i + 1, ((1 << i) & word) ? _RED_("write locked") : "unlocked");
    }
}

//quick test for EM4x05/EM4x69 tag
bool EM4x05IsBlock0(uint32_t *word) {
    return (EM4x05ReadWord_ext(0, 0, false, word) == PM3_SUCCESS);
}

int CmdEM4x05Info(const char *Cmd) {
#define EM_SERIAL_BLOCK 1
#define EM_CONFIG_BLOCK 4
#define EM_PROT1_BLOCK 14
#define EM_PROT2_BLOCK 15
    uint32_t pwd;
    uint32_t word = 0, block0 = 0, serial = 0;
    bool usePwd = false;
    uint8_t ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return usage_lf_em4x05_info();

    // for now use default input of 1 as invalid (unlikely 1 will be a valid password...)
    pwd = param_get32ex(Cmd, 0, 0xFFFFFFFF, 16);

    if (pwd != 0xFFFFFFFF)
        usePwd = true;

    // read word 0 (chip info)
    // block 0 can be read even without a password.
    if (EM4x05IsBlock0(&block0) == false)
        return PM3_ESOFT;

    // read word 1 (serial #) doesn't need pwd
    // continue if failed, .. non blocking fail.
    EM4x05ReadWord_ext(EM_SERIAL_BLOCK, 0, false, &serial);
    printEM4x05info(block0, serial);

    // read word 4 (config block)
    // needs password if one is set
    if (EM4x05ReadWord_ext(EM_CONFIG_BLOCK, pwd, usePwd, &word) != PM3_SUCCESS)
        return PM3_ESOFT;

    printEM4x05config(word);

    // read word 14 and 15 to see which is being used for the protection bits
    if (EM4x05ReadWord_ext(EM_PROT1_BLOCK, pwd, usePwd, &word) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }
    if (word & 0x8000) {
        printEM4x05ProtectionBits(word, EM_PROT1_BLOCK);
        return PM3_SUCCESS;
    } else { // if status bit says this is not the used protection word
        if (EM4x05ReadWord_ext(EM_PROT2_BLOCK, pwd, usePwd, &word) != PM3_SUCCESS)
            return PM3_ESOFT;
        if (word & 0x8000) {
            printEM4x05ProtectionBits(word, EM_PROT2_BLOCK);
            return PM3_SUCCESS;
        }
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
    CLIParserInit(&ctx, "lf em 4x05_chk",
                  "This command uses a dictionary attack against EM4205/4305/4469/4569",
                  "lf em 4x05_chk\n"
                  "lf em 4x05_chk -e 0x00000022B8        -> remember to use 0x for hex\n"
                  "lf em 4x05_chk -f t55xx_default_pwds  -> use T55xx default dictionary"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("f", "file", "<*.dic>", "loads a default keys dictionary file <*.dic>"),
        arg_u64_0("e", "em", "<EM4100>", "try the calculated password from some cloners based on EM4100 ID"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    uint64_t card_id = arg_get_u64_def(ctx, 2, 0);
    CLIParserFree(ctx);

    if (strlen(filename) == 0) {
        snprintf(filename, sizeof(filename), "t55xx_default_pwds");
    }
    PrintAndLogEx(NORMAL, "");
    
    uint8_t addr = 4;
    uint32_t word = 0;
    bool found = false;
    uint64_t t1 = msclock();
    
    // White cloner password based on EM4100 ID
    if ( card_id > 0 ) {

        uint32_t pwd = lf_t55xx_white_pwdgen(card_id & 0xFFFFFFFF);
        PrintAndLogEx(INFO, "testing %08"PRIX32" generated ", pwd);

        int status = EM4x05ReadWord_ext(addr, pwd, true, &word);
        if (status == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "found valid password [ " _GREEN_("%08"PRIX32) " ]", pwd);
            found = true;
        }
    }

    // Loop dictionary
    uint8_t *keyBlock = NULL;
    if (found == false) {

        PrintAndLogEx(INFO, "press " _YELLOW_("'enter'") " to cancel the command");

        word = 0;
        uint32_t keycount = 0;

        int res = loadFileDICTIONARY_safe(filename, (void **) &keyBlock, 4, &keycount);
        if (res != PM3_SUCCESS || keycount == 0 || keyBlock == NULL) {
            PrintAndLogEx(WARNING, "no keys found in file");
            if (keyBlock != NULL)
                free(keyBlock);

            return PM3_ESOFT;
        }

        for (uint32_t c = 0; c < keycount; ++c) {

            if (!session.pm3_present) {
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

            int status = EM4x05ReadWord_ext(addr, curr_password, 1, &word);
            if (status == PM3_SUCCESS) {
                PrintAndLogEx(SUCCESS, "found valid password [ " _GREEN_("%08"PRIX32) " ]", curr_password);
                found = true;
                break;
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

    if (!downloadSamplesEM())
        return PM3_ENODATA;

    uint32_t dummy = 0;
    int status = demodEM4x05resp(&dummy, true);
    if (status == PM3_SUCCESS && verbose)
        PrintAndLogEx(SUCCESS, "Success writing to tag");
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
        if ( array[i].value == value ) {
            array[i].cnt++;
            break;
        }
        if ( array[i].cnt == 0 ) {
            array[i].cnt++;
            array[i].value = value;
            break;
        }
    }
}

int CmdEM4x05Unlock(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x05_unlock",
                  "execute tear off against EM4205/4305/4469/4569",
                  "lf em 4x05_unlock\n"
                  "lf em 4x05_unlock -s 4100 -e 4100       -> lock on and autotune at 4100us\n"
                  "lf em 4x05_unlock -n 10 -s 3000 -e 4400 -> scan delays 3000us -> 4400us"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("n", NULL, NULL, "steps to skip"),
        arg_int0("s", "start", "<us>", "start scan from delay (us)"),
        arg_int0("e", "end", "<us>", "end scan at delay (us)"),
        arg_u64_0("p", "pwd", "", "password (0x00000000)"),        
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end        
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    double n = (double)arg_get_int_def(ctx, 1, 0);
    double start = (double)arg_get_int_def(ctx, 2, 2000);
    double end = (double)arg_get_int_def(ctx, 3, 6000);
    uint64_t inputpwd = arg_get_u64_def(ctx, 4, 0xFFFFFFFFFFFFFFFF);
    bool verbose = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if ( start > end ) {
        PrintAndLogEx(FAILED, "start delay can\'t be larger than end delay %.0lf vs %.0lf", start, end);
        return PM3_EINVARG;
    }

    if (session.pm3_present == false) {
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
    // inital phase 
    //
    // read word 14
    uint32_t init_14 = 0;
    int res = EM4x05ReadWord_ext(14, pwd, use_pwd, &init_14);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "failed to read word 14\n");
        return PM3_ENODATA;        
    }

        
    // read 15 
    uint32_t init_15 = 0;
    res = EM4x05ReadWord_ext(15, pwd, use_pwd, &init_15);
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
    PrintAndLogEx(INFO, "press " _YELLOW_("'enter'") " to cancel the command");
    PrintAndLogEx(NORMAL, "");    
    PrintAndLogEx(INFO, "--------------- " _CYAN_("start") " -----------------------\n");
    
    int exit_code = PM3_SUCCESS;
    uint32_t word14 = 0, word15 = 0;
    uint32_t word14b = 0, word15b = 0;
    uint32_t tries = 0;
    uint32_t soon = 0;
    uint32_t late = 0;

    em4x05_unlock_item_t flipped[64]; 

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
                PrintAndLogEx(INFO, "Tried %d times, soon:%i late:%i        => " _CYAN_("adjust +1 us >> %.0lf us"), tries, soon, late, start);
                start++;
                end++;
            } else {
                PrintAndLogEx(INFO, "Tried %d times, soon:%i late:%i        => " _CYAN_("adjust -1 us >> %.0lf us"), tries, soon, late, start);
                start--;
                end--;
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
        if ( res != PM3_SUCCESS ) {
            PrintAndLogEx(WARNING, "failed to configure tear off");
            return PM3_ESOFT;
        }

        // write
        res = unlock_write_protect(use_pwd, pwd, write_value, verbose);
        
        // read after trigger
        res = EM4x05ReadWord_ext(14, pwd, use_pwd, &word14);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "failed to read 14");
            return PM3_ESOFT;
        }

        // read after trigger
        res = EM4x05ReadWord_ext(15, pwd, use_pwd, &word15);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "failed to read 15");
            return PM3_ESOFT;
        }

        if (verbose)
            PrintAndLogEx(INFO, "ref:%08X   14:%08X   15:%08X ", search_value, word14, word15);
        
        if ( word14 == search_value && word15 == 0) {
            PrintAndLogEx(INFO, "Status: Nothing happened            => " _GREEN_("tearing too soon"));
            
            if (my_auto) {
                start += n;
                PrintAndLogEx(INFO, "                                    => " _CYAN_("adjust +%.0lf us >> %.0lf us"), n, start);
                n /= 2;
            } else {
                soon++;
            }
        } else {
            
            if (word15 == search_value) {
                
                if (word14 == 0) {
                    PrintAndLogEx(INFO, "Status: Protect succeeded           => " _GREEN_("tearing too late"));
                } else {
                    if ( word14 == search_value) {
                        PrintAndLogEx(INFO, "Status: 15 ok, 14 not yet erased    => " _GREEN_("tearing too late"));
                    } else {
                        PrintAndLogEx(INFO, "Status: 15 ok, 14 partially erased  => " _GREEN_("tearing too late"));
                    }                    
                }

                unlock_reset(use_pwd, pwd, write_value, verbose);

                // read after reset
                res = EM4x05ReadWord_ext(14, pwd, use_pwd, &word14b);
                if (res != PM3_SUCCESS) {
                    PrintAndLogEx(WARNING, "failed to read 14");
                    return PM3_ESOFT;
                }

                if (word14b == 0) {

                    unlock_reset(use_pwd, pwd, write_value, verbose);                    

                    res = EM4x05ReadWord_ext(14, pwd, use_pwd, &word14b);
                    if (res != PM3_SUCCESS) {
                        PrintAndLogEx(WARNING, "failed to read 14");
                        return PM3_ESOFT;
                    }
                }
                
                if (word14b != search_value) {

                    res = EM4x05ReadWord_ext(15, pwd, use_pwd, &word15b);
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
                    n /= 2;
                } else {
                    late++;
                }

            } else {
                
                if (( word15 & ACTIVE_MASK) == ACTIVE_MASK) {
                    
                    PrintAndLogEx(INFO, "Status: 15 bitflipped and active    => " _RED_("SUCCESS?:  ") "14: %08X  15: " _CYAN_("%08X"), word14, word15);
                    PrintAndLogEx(INFO, "Committing results...");

                    unlock_reset(use_pwd, pwd, write_value, verbose);    
                    
                    // read after reset
                    res = EM4x05ReadWord_ext(14, pwd, use_pwd, &word14b);
                    if ( res != PM3_SUCCESS ) {
                        PrintAndLogEx(WARNING, "failed to read 14");
                        return PM3_ESOFT;
                    }

                    res = EM4x05ReadWord_ext(15, pwd, use_pwd, &word15b);
                    if ( res != PM3_SUCCESS ) {
                        PrintAndLogEx(WARNING, "failed to read 15");
                        return PM3_ESOFT;
                    }
                    
                    if (verbose)
                        PrintAndLogEx(INFO, "ref:%08x   14:%08X   15:%08X", search_value, word14b, word15b);
                    
                    if ((word14b & ACTIVE_MASK) == ACTIVE_MASK) {
                        
                        if (word14b == word15) {
                            PrintAndLogEx(INFO, "Status: confirmed                   => " _RED_("SUCCESS:   ") "14: " _CYAN_("%08X") "  15: %08X", word14b, word15b);

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
        for (int i=0; i < 8; i++) {
            bitstring[i] = bitflips & (0xF << ((7-i) * 4)) ? 'x' : '.';
        }
        // compute number of bits flipped

        PrintAndLogEx(INFO, "Bitflips: %2u events => %s", bitcount32(bitflips), bitstring);
        PrintAndLogEx(INFO, "New protection word => " _CYAN_("%08X") "\n", word14b);

   
        PrintAndLogEx(INFO, "Try " _YELLOW_("`lf em 4x05_dump`"));
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
