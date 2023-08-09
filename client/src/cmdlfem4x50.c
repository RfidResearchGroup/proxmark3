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
// Low frequency EM4x50 commands
//-----------------------------------------------------------------------------

#include "cliparser.h"
#include "cmdlfem4x50.h"
#include <ctype.h>
#include <math.h>
#include "cmdparser.h"    // command_t
#include "util_posix.h"  // msclock
#include "fileutils.h"
#include "commonutil.h"
#include "pmflash.h"
#include "cmdflashmemspiffs.h"
#include "em4x50.h"

static int CmdHelp(const char *Cmd);

static void prepare_result(const uint8_t *data, int fwr, int lwr, em4x50_word_t *words) {

    // restructure received result in "em4x50_word_t" structure
    for (int i = fwr; i <= lwr; i++) {
        for (int j = 0; j < 4; j++) {
            words[i].byte[j] = data[i * 4 + (3 - j)];
        }
    }
}

static void print_result(const em4x50_word_t *words, int fwr, int lwr) {

    // print available information for given word from fwr to lwr, i.e.
    // bit table + summary lines with hex notation of word (msb + lsb)

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "  # | word (msb)  | word (lsb)  | desc");
    PrintAndLogEx(INFO, "----+-------------+-------------+--------------------");

    for (int i = fwr; i <= lwr; i++) {

        const char *s;
        switch (i) {
            case EM4X50_DEVICE_PASSWORD:
                s = _YELLOW_("password, write only");
                break;
            case EM4X50_PROTECTION:
                s = _YELLOW_("protection cfg (locked)");
                break;
            case EM4X50_CONTROL:
                s = _YELLOW_("control cfg (locked)");
                break;
            case EM4X50_DEVICE_SERIAL:
                s = _YELLOW_("device serial number (read only)");
                break;
            case EM4X50_DEVICE_ID:
                s = _YELLOW_("device identification (read only)");
                break;
            default:
                s = "user data";
                break;
        }

        char r[30] = {0};
        for (int j = 3; j >= 0; j--) {
            int offset = strlen(r);
            snprintf(r + offset, sizeof(r) - offset, "%02x ", reflect8(words[i].byte[j]));
        }

        PrintAndLogEx(INFO, " %2i | " _GREEN_("%s") "| %s| %s",
                      i,
                      sprint_hex(words[i].byte, 4),
                      r,
                      s
                     );
    }
    PrintAndLogEx(INFO, "----+-------------+-------------+--------------------");
}

static void print_info_result(uint8_t *data, bool verbose) {

    // display all information of info result in structured format
    em4x50_word_t words[EM4X50_NO_WORDS];
    prepare_result(data, 0, EM4X50_NO_WORDS - 1, words);

    bool bpwc = words[EM4X50_CONTROL].byte[CONFIG_BLOCK] & PASSWORD_CHECK;
    bool braw = words[EM4X50_CONTROL].byte[CONFIG_BLOCK] & READ_AFTER_WRITE;

    int fwr = reflect8(words[EM4X50_CONTROL].byte[FIRST_WORD_READ]);
    int lwr = reflect8(words[EM4X50_CONTROL].byte[LAST_WORD_READ]);
    int fwrp = reflect8(words[EM4X50_PROTECTION].byte[FIRST_WORD_READ_PROTECTED]);
    int lwrp = reflect8(words[EM4X50_PROTECTION].byte[LAST_WORD_READ_PROTECTED]);
    int fwwi = reflect8(words[EM4X50_PROTECTION].byte[FIRST_WORD_WRITE_INHIBITED]);
    int lwwi = reflect8(words[EM4X50_PROTECTION].byte[LAST_WORD_WRITE_INHIBITED]);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");

    // data section
    if (verbose) {
        print_result(words, 0, EM4X50_NO_WORDS - 1);
    } else {
        print_result(words, EM4X50_DEVICE_SERIAL, EM4X50_DEVICE_ID);
    }

    // configuration section
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---- " _CYAN_("Configuration") " ----");

    PrintAndLogEx(INFO, "first word read.... " _YELLOW_("%i"), fwr);
    PrintAndLogEx(INFO, "last word read..... " _YELLOW_("%i"), lwr);
    PrintAndLogEx(INFO, "password check..... %s", (bpwc) ? _RED_("on") : _GREEN_("off"));
    PrintAndLogEx(INFO, "read after write... %s", (braw) ? "on" : "off");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--------- " _CYAN_("Protection") " ------------");
    PrintAndLogEx(INFO, "first word read protected.... %i", fwrp);
    PrintAndLogEx(INFO, "last word read protected..... %i", lwrp);
    PrintAndLogEx(INFO, "first word write inhibited... %i", fwwi);
    PrintAndLogEx(INFO, "last word write inhibited.... %i", lwwi);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "zero values may indicate read protection");
    PrintAndLogEx(NORMAL, "");
}

static int em4x50_load_file(const char *filename, uint8_t *data, size_t data_len, size_t *bytes_read) {

    // read dump file
    uint8_t *dump = NULL;
    *bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&dump, bytes_read, DUMP_FILESIZE);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (*bytes_read != DUMP_FILESIZE) {
        free(dump);
        return PM3_EFILE;
    }

    // sanity check, valid em4x50 data?
    uint32_t serial = bytes_to_num(dump + 4 * EM4X50_DEVICE_SERIAL, 4);
    uint32_t device_id = bytes_to_num(dump + 4 * EM4X50_DEVICE_ID, 4);
    if (serial == device_id) {
        PrintAndLogEx(WARNING, "No valid EM4x50 data in file %s", filename);
        free(dump);
        return PM3_ENODATA;
    }

    memcpy(data, dump, *bytes_read);
    free(dump);
    return PM3_SUCCESS;
}

static void em4x50_seteml(uint8_t *src, uint32_t offset, uint32_t numofbytes) {

    PrintAndLogEx(INFO, "uploading to emulator memory");
    PrintAndLogEx(INFO, "." NOLF);
    // fast push mode
    g_conn.block_after_ACK = true;
    for (size_t i = offset; i < numofbytes; i += PM3_CMD_DATA_SIZE) {

        size_t len = MIN((numofbytes - i), PM3_CMD_DATA_SIZE);
        if (len == numofbytes - i) {
            // Disable fast mode on last packet
            g_conn.block_after_ACK = false;
        }
        clearCommandBuffer();
        SendCommandOLD(CMD_LF_EM4X50_ESET, i, len, 0, src + i, len);
        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "uploaded " _YELLOW_("%d") " bytes to emulator memory", numofbytes);
}

int CmdEM4x50ELoad(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 eload",
                  "Loads EM4x50 tag dump (bin/eml/json) into emulator memory on device",
                  "lf em 4x50 eload -f mydump.bin\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "dump filename (bin/eml/json)"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    // read data from dump file; file type has to be "bin", "eml" or "json"
    size_t bytes_read = 0;
    uint8_t data[DUMP_FILESIZE] = {0x0};

    if (em4x50_load_file(filename, data, DUMP_FILESIZE, &bytes_read) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Read error");
        return PM3_EFILE;
    }

    // upload to emulator memory
    em4x50_seteml(data, 0, DUMP_FILESIZE);
    PrintAndLogEx(HINT, "You are ready to simulate. See " _YELLOW_("`lf em 4x50 sim -h`"));
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

int CmdEM4x50ESave(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 esave",
                  "Saves bin/eml/json dump file of emulator memory.",
                  "lf em 4x50 esave                    -> use UID as filename\n"
                  "lf em 4x50 esave -f mydump\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "specifiy filename"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    // download emulator memory
    PrintAndLogEx(SUCCESS, "Reading emulator memory...");
    uint8_t data[DUMP_FILESIZE] = {0x0};
    if (GetFromDevice(BIG_BUF_EML, data, DUMP_FILESIZE, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        return PM3_ETIMEOUT;
    }

    // valid em4x50 data?
    uint32_t serial = bytes_to_num(data + 4 * EM4X50_DEVICE_SERIAL, 4);
    uint32_t device_id = bytes_to_num(data + 4 * EM4X50_DEVICE_ID, 4);
    if (serial == device_id) {
        PrintAndLogEx(WARNING, "No valid em4x50 data in flash memory.");
        return PM3_ENODATA;
    }

    // user supplied filename?
    if (fnlen == 0) {
        PrintAndLogEx(INFO, "Using UID as filename");
        char *fptr = filename;
        fptr += snprintf(fptr, sizeof(filename), "lf-4x50-");
        FillFileNameByUID(fptr, (uint8_t *)&data[4 * EM4X50_DEVICE_ID], "-dump", 4);
    }

    pm3_save_dump(filename, data, DUMP_FILESIZE, jsfEM4x50, 4);
    return PM3_SUCCESS;
}

int CmdEM4x50EView(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 eview",
                  "Displays em4x50 content of emulator memory.",
                  "lf em 4x50 eview\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // download emulator memory
    PrintAndLogEx(SUCCESS, "Reading emulator memory...");
    uint8_t data[DUMP_FILESIZE] = {0x0};
    if (GetFromDevice(BIG_BUF_EML, data, DUMP_FILESIZE, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        return PM3_ETIMEOUT;
    }

    // valid em4x50 data?
    uint32_t serial = bytes_to_num(data + 4 * EM4X50_DEVICE_SERIAL, 4);
    uint32_t device_id = bytes_to_num(data + 4 * EM4X50_DEVICE_ID, 4);
    if (serial == device_id) {
        PrintAndLogEx(WARNING, "No valid em4x50 data in emulator memory.");
        return PM3_ENODATA;
    }

    em4x50_word_t words[EM4X50_NO_WORDS];
    for (int i = 0; i < EM4X50_NO_WORDS; i++) {
        memcpy(words[i].byte, data + i * 4, 4);
    }
    print_result(words, 0, EM4X50_NO_WORDS - 1);
    PrintAndLogEx(NORMAL, "");

    return PM3_SUCCESS;
}

int CmdEM4x50Login(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 login",
                  "Login into EM4x50 tag.",
                  "lf em 4x50 login -p 12345678    -> login with password 12345678\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "passsword", "<hex>", "password, 4 bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int pwd_len = 0;
    uint8_t pwd[4] = {0x0};
    CLIGetHexWithReturn(ctx, 1, pwd, &pwd_len);
    CLIParserFree(ctx);

    if (pwd_len != 4) {
        PrintAndLogEx(FAILED, "password length must be 4 bytes");
        return PM3_EINVARG;
    }

    uint32_t password = BYTES2UINT32_BE(pwd);

    // start
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_LF_EM4X50_LOGIN, (uint8_t *)&password, sizeof(password));
    WaitForResponse(CMD_LF_EM4X50_LOGIN, &resp);

    // print response
    if (resp.status == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Login ( " _GREEN_("ok") " )");
    else
        PrintAndLogEx(FAILED, "Login ( " _RED_("failed") " )");

    return resp.status;
}

int CmdEM4x50Brute(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 brute",
                  "Tries to bruteforce the password of a EM4x50 card.\n"
                  "Function can be stopped by pressing pm3 button.\n",

                  "lf em 4x50 brute --mode range --begin 12330000 --end 12340000 -> tries pwds from 0x12330000 to 0x12340000\n"
                  "lf em 4x50 brute --mode charset --digits --uppercase -> tries all combinations of ASCII codes for digits and uppercase letters\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "mode", "<str>", "Bruteforce mode (range|charset)"),
        arg_str0(NULL, "begin", "<hex>",   "Range mode - start of the key range"),
        arg_str0(NULL, "end", "<hex>",   "Range mode - end of the key range"),
        arg_lit0(NULL, "digits",  "Charset mode - include ASCII codes for digits"),
        arg_lit0(NULL, "uppercase",  "Charset mode - include ASCII codes for uppercase letters"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    em4x50_data_t etd;
    memset(&etd, 0, sizeof(etd));

    int mode_len = 64;
    char mode[64];
    CLIGetStrWithReturn(ctx, 1, (uint8_t *) mode, &mode_len);
    PrintAndLogEx(INFO, "Chosen mode: %s", mode);

    if (strcmp(mode, "range") == 0) {
        etd.bruteforce_mode = BRUTEFORCE_MODE_RANGE;
    } else if (strcmp(mode, "charset") == 0) {
        etd.bruteforce_mode = BRUTEFORCE_MODE_CHARSET;
    } else {
        PrintAndLogEx(FAILED, "Unknown bruteforce mode: %s", mode);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (etd.bruteforce_mode == BRUTEFORCE_MODE_RANGE) {
        int begin_len = 0;
        uint8_t begin[4] = {0x0};
        CLIGetHexWithReturn(ctx, 2, begin, &begin_len);

        int end_len = 0;
        uint8_t end[4] = {0x0};
        CLIGetHexWithReturn(ctx, 3, end, &end_len);

        if (begin_len != 4) {
            PrintAndLogEx(FAILED, "'begin' parameter must be 4 bytes");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }

        if (end_len != 4) {
            PrintAndLogEx(FAILED, "'end' parameter must be 4 bytes");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }

        etd.password1 = BYTES2UINT32_BE(begin);
        etd.password2 = BYTES2UINT32_BE(end);
    } else if (etd.bruteforce_mode == BRUTEFORCE_MODE_CHARSET) {
        bool enable_digits = arg_get_lit(ctx, 4);
        bool enable_uppercase = arg_get_lit(ctx, 5);

        if (enable_digits)
            etd.bruteforce_charset |= CHARSET_DIGITS;
        if (enable_uppercase)
            etd.bruteforce_charset |= CHARSET_UPPERCASE;

        if (etd.bruteforce_charset == 0) {
            PrintAndLogEx(FAILED, "Please enable at least one charset when using charset bruteforce mode.");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }

        PrintAndLogEx(INFO, "Enabled charsets: %s%s",
                      enable_digits ? "digits " : "",
                      enable_uppercase ? "uppercase " : "");

    }

    CLIParserFree(ctx);

    // 27 passwords/second (empirical value)
    const int speed = 27;
    int no_iter = 0;

    if (etd.bruteforce_mode == BRUTEFORCE_MODE_RANGE) {
        no_iter = etd.password2 - etd.password1 + 1;
        PrintAndLogEx(INFO, "Trying " _YELLOW_("%i") " passwords in range [0x%08x, 0x%08x]"
                      , no_iter
                      , etd.password1
                      , etd.password2
                     );
    } else if (etd.bruteforce_mode == BRUTEFORCE_MODE_CHARSET) {
        unsigned int digits = 0;

        if (etd.bruteforce_charset & CHARSET_DIGITS)
            digits += CHARSET_DIGITS_SIZE;

        if (etd.bruteforce_charset & CHARSET_UPPERCASE)
            digits += CHARSET_UPPERCASE_SIZE;

        no_iter = pow(digits, 4);
    }

    // print some information
    int dur_s = no_iter / speed;
    int dur_h = dur_s / 3600;
    int dur_m = (dur_s - dur_h * 3600) / 60;

    dur_s -= dur_h * 3600 + dur_m * 60;

    PrintAndLogEx(INFO, "Estimated duration: %ih %im %is", dur_h, dur_m, dur_s);

    // start
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_LF_EM4X50_BRUTE, (uint8_t *)&etd, sizeof(etd));
    WaitForResponse(CMD_LF_EM4X50_BRUTE, &resp);

    // print response
    if (resp.status == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "found valid password [ " _GREEN_("%08"PRIX32) " ]", resp.data.asDwords[0]);
    else
        PrintAndLogEx(WARNING, "brute pwd failed");

    return PM3_SUCCESS;
}

// upload passwords from given dictionary to device and start check;
// if no filename is given dictionary "t55xx_default_pwds.dic" is used
int CmdEM4x50Chk(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 chk",
                  "Run dictionary key recovery against EM4x50 card.",
                  "lf em 4x50 chk             -> uses T55xx default dictionary\n"
                  "lf em 4x50 chk -f my.dic"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "specify dictionary filename"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    if (IfPm3Flash() == false) {
        PrintAndLogEx(WARNING, "no flash memory available");
        return PM3_EFLASH;
    }

    // no filename -> default = t55xx_default_pwds
    if (strlen(filename) == 0) {
        snprintf(filename, sizeof(filename), "t55xx_default_pwds");
        PrintAndLogEx(INFO, "treating file as T55xx keys");
    }

    // load keys
    uint8_t *keys = NULL;
    uint32_t key_count = 0;
    int res = loadFileDICTIONARY_safe(filename, (void **)&keys, 4, &key_count);
    if (res != PM3_SUCCESS || key_count == 0) {
        free(keys);
        return res;
    }

    uint8_t *pkeys = keys;

    uint64_t t1 = msclock();

    PrintAndLogEx(INFO, "You can cancel this operation by pressing the pm3 button");

    // block with 2000 bytes -> 500 keys
    uint8_t destfn[32] = "em4x50_chk.bin";
    PacketResponseNG resp;
    int bytes_remaining = key_count * 4;
    int status = PM3_EFAILED;

    while (bytes_remaining > 0) {

        PrintAndLogEx(INPLACE, "Remaining keys: %i ", bytes_remaining / 4);

        // upload to flash.
        size_t n = MIN(bytes_remaining, 2000);
        res = flashmem_spiffs_load((char *)destfn, keys, n);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "SPIFFS upload failed");
            return res;
        }

        clearCommandBuffer();
        SendCommandNG(CMD_LF_EM4X50_CHK, destfn, sizeof(destfn));
        WaitForResponseTimeoutW(CMD_LF_EM4X50_CHK,  &resp, -1, false);

        status = resp.status;
        if ((status == PM3_SUCCESS) || (status == PM3_EOPABORTED))
            break;

        bytes_remaining -= n;
        keys += n;
    }

    free(pkeys);
    PrintAndLogEx(NORMAL, "");

    if (status == PM3_SUCCESS) {
        uint32_t pwd = BYTES2UINT32(resp.data.asBytes);
        PrintAndLogEx(SUCCESS, "found valid password [ " _GREEN_("%08"PRIX32) " ]", pwd);
    } else {
        PrintAndLogEx(FAILED, "No key found");
    }

    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "\ntime in check pwd " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);
    return PM3_SUCCESS;
}

//quick test for EM4x50 tag
bool detect_4x50_block(void) {
    em4x50_data_t etd = {
        .pwd_given = false,
        .addr_given = true,
        .addresses = (EM4X50_DEVICE_SERIAL << 8) | EM4X50_DEVICE_SERIAL,
    };
    em4x50_word_t words[EM4X50_NO_WORDS];
    return (em4x50_read(&etd, words) == PM3_SUCCESS);
}

int read_em4x50_uid(void) {
    em4x50_data_t etd = {
        .pwd_given = false,
        .addr_given = true,
        .addresses = (EM4X50_DEVICE_SERIAL << 8) | EM4X50_DEVICE_SERIAL,
    };
    em4x50_word_t words[EM4X50_NO_WORDS];
    int res = em4x50_read(&etd, words);
    if (res == PM3_SUCCESS)
        PrintAndLogEx(INFO, " Serial: " _GREEN_("%s"), sprint_hex(words[EM4X50_DEVICE_SERIAL].byte, 4));
    return res;
}

// envoke reading
// - with given address (option b) (and optional password if address is
//   read protected) -> selective read mode
int em4x50_read(em4x50_data_t *etd, em4x50_word_t *out) {

    em4x50_data_t edata = { .pwd_given = false, .addr_given = false };

    if (etd != NULL) {
        edata = *etd;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_READ, (uint8_t *)&edata, sizeof(edata));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_READ, &resp, TIMEOUT_CMD)) {
        PrintAndLogEx(WARNING, "(em4x50) timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS)
        return PM3_ESOFT;

    uint8_t *data = resp.data.asBytes;
    em4x50_word_t words[EM4X50_NO_WORDS] = {0};
    prepare_result(data, etd->addresses & 0xFF, (etd->addresses >> 8) & 0xFF, words);

    if (out != NULL)
        memcpy(out, &words, sizeof(em4x50_word_t) * EM4X50_NO_WORDS);

    print_result(words, etd->addresses & 0xFF, (etd->addresses >> 8) & 0xFF);

    return PM3_SUCCESS;
}

int CmdEM4x50Read(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 rdbl",
                  "Reads single EM4x50 block/word.",
                  "lf em 4x50 rdbl -b 3\n"
                  "lf em 4x50 rdbl -b 32 -p 12345678   -> reads block 32 with pwd 0x12345678\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int1("b", "block", "<dec>", "block/word address"),
        arg_str0("p", "pwd", "<hex>", "password, 4 hex bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int addr = arg_get_int_def(ctx, 1, 0);
    int pwd_len = 0;
    uint8_t pwd[4] = {0x0};
    CLIGetHexWithReturn(ctx, 2, pwd, &pwd_len);
    CLIParserFree(ctx);

    if (addr <= 0 || addr >= EM4X50_NO_WORDS) {
        return PM3_EINVARG;
    }

    em4x50_data_t etd;

    // init
    memset(&etd, 0x00, sizeof(em4x50_data_t));
    etd.pwd_given = false;
    etd.addresses = (addr << 8) | addr;
    etd.addr_given = true;

    if (pwd_len) {
        if (pwd_len != 4) {
            PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwd_len);
            return PM3_EINVARG;
        } else {
            etd.password1 = BYTES2UINT32_BE(pwd);
            etd.pwd_given = true;
        }
    }

    return em4x50_read(&etd, NULL);
}

// envoke reading of a EM4x50 tag which has to be on the antenna because
// decoding is done by the device (not on client side)
int CmdEM4x50Info(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 info",
                  "Tag information EM4x50.",
                  "lf em 4x50 info\n"
                  "lf em 4x50 info -v           -> show data section\n"
                  "lf em 4x50 info -p 12345678  -> uses pwd 0x12345678\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("p", "pwd", "<hex>", "password, 4 hex bytes, lsb"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int pwd_len = 0;
    uint8_t pwd[4] = {0x0};
    CLIGetHexWithReturn(ctx, 1, pwd, &pwd_len);
    bool verb = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    em4x50_data_t etd = {.pwd_given = false};
    if (pwd_len) {
        if (pwd_len != 4) {
            PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwd_len);
            return PM3_EINVARG;
        } else {
            etd.password1 = BYTES2UINT32_BE(pwd);
            etd.pwd_given = true;
        }
    }

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_INFO, (uint8_t *)&etd, sizeof(etd));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_INFO, &resp, TIMEOUT_CMD)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS)
        print_info_result(resp.data.asBytes, verb);
    else
        PrintAndLogEx(FAILED, "Reading tag " _RED_("failed"));

    return resp.status;
}

int CmdEM4x50Reader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 reader",
                  "Shows standard read data of EM4x50 tag.",
                  "lf em 4x50 reader\n"
                  "lf em 4x50 reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    // start
    do {

        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_LF_EM4X50_READER, 0, 0);
        WaitForResponseTimeoutW(CMD_LF_EM4X50_READER,  &resp, -1, false);

        // iceman,  misuse of return status code.
        int now = resp.status;

        if (now > 0) {

            em4x50_word_t words[EM4X50_NO_WORDS];
            prepare_result(resp.data.asBytes, 0, now - 1, words);

            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, " word (msb)  | word (lsb)  ");
            PrintAndLogEx(INFO, "-------------+-------------");

            for (int i = 0; i < now; i++) {

                char r[30];
                memset(r, 0, sizeof(r));
                for (int j = 3; j >= 0; j--) {
                    int offset = strlen(r);
                    snprintf(r + offset, sizeof(r) - offset, "%02x ", reflect8(words[i].byte[j]));
                }

                PrintAndLogEx(INFO, _GREEN_(" %s") "| %s", sprint_hex(words[i].byte, 4), r);
            }

            PrintAndLogEx(INFO, "-------------+-------------");
        }
    } while (cm && !kbd_enter_pressed());

    return PM3_SUCCESS;
}

int CmdEM4x50Dump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 dump",
                  "Reads all blocks/words from EM4x50 tag and saves dump in bin/eml/json format",
                  "lf em 4x50 dump\n"
                  "lf em 4x50 dump -f mydump\n"
                  "lf em 4x50 dump -p 12345678\n"
                  "lf em 4x50 dump -f mydump -p 12345678"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "specify dump filename (bin/eml/json)"),
        arg_str0("p", "pwd", "<hex>", "password, 4 hex bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int fnLen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnLen);

    int pwd_len = 0;
    uint8_t pwd[4] = {0x0};
    CLIGetHexWithReturn(ctx, 2, pwd, &pwd_len);
    CLIParserFree(ctx);

    em4x50_data_t etd = {.pwd_given = false};

    if (pwd_len) {
        if (pwd_len != 4) {
            PrintAndLogEx(FAILED, "password length must be 4 bytes");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        } else {
            etd.password1 = BYTES2UINT32_BE(pwd);
            etd.pwd_given = true;
        }
    }

    PrintAndLogEx(INFO, "Reading EM4x50 tag");
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_INFO, (uint8_t *)&etd, sizeof(etd));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_INFO, &resp, TIMEOUT_CMD)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Reading tag " _RED_("failed"));
        return PM3_ESOFT;
    }

    // structured format
    em4x50_word_t words[EM4X50_NO_WORDS];
    prepare_result(resp.data.asBytes, 0, EM4X50_NO_WORDS - 1, words);

    // result output
    PrintAndLogEx(INFO, _YELLOW_("EM4x50 data:"));
    print_result(words, 0, EM4X50_NO_WORDS - 1);

    // user supplied filename?
    if (fnLen == 0) {
        PrintAndLogEx(INFO, "Using UID as filename");
        char *fptr = filename + snprintf(filename, sizeof(filename), "lf-4x50-");
        FillFileNameByUID(fptr, words[EM4X50_DEVICE_ID].byte, "-dump", 4);
    }

    uint8_t data[DUMP_FILESIZE] = {0};
    for (int i = 0; i < EM4X50_NO_WORDS; i++) {
        memcpy(data + (i * 4), words[i].byte, 4);
    }

    pm3_save_dump(filename, data, sizeof(data), jsfEM4x50, 4);
    return PM3_SUCCESS;
}

// envoke writing a single word (32 bit) to a EM4x50 tag
int CmdEM4x50Write(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 wrbl",
                  "Writes single block/word to EM4x50 tag.",
                  "lf em 4x50 wrbl -b 3 -d 4f22e7ff \n"
                  "lf em 4x50 wrbl -b 3 -d 4f22e7ff -p 12345678\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int1("b", "block", "<dec>", "block/word address, dec"),
        arg_str1("d", "data", "<hex>", "data, 4 bytes, lsb"),
        arg_str0("p", "pwd", "<hex>", "password, 4 bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int addr = arg_get_int_def(ctx, 1, 0);

    int word_len = 0;
    uint8_t word[4] = {0x0};
    CLIGetHexWithReturn(ctx, 2, word, &word_len);

    int pwd_len = 0;
    uint8_t pwd[4] = {0x0};
    CLIGetHexWithReturn(ctx, 3, pwd, &pwd_len);
    CLIParserFree(ctx);

    if (addr <= 0 || addr >= EM4X50_NO_WORDS) {
        PrintAndLogEx(FAILED, "address has to be within range [0, 31]");
        return PM3_EINVARG;
    }

    if (word_len != 4) {
        PrintAndLogEx(FAILED, "word/data length must be 4 bytes instead of %d", word_len);
        return PM3_EINVARG;
    }

    em4x50_data_t etd = {.pwd_given = false};
    if (pwd_len) {
        if (pwd_len != 4) {
            PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwd_len);
            return PM3_EINVARG;
        } else {
            etd.password1 = BYTES2UINT32_BE(pwd);
            etd.pwd_given = true;
        }
    }

    etd.addresses = (addr << 8) | addr;
    etd.addr_given = true;
    etd.word = BYTES2UINT32_BE(word);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_WRITE, (uint8_t *)&etd, sizeof(etd));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_WRITE, &resp, TIMEOUT_CMD)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    int status = resp.status;
    if (status == PM3_ETEAROFF)
        return status;

    if (status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Writing " _RED_("failed"));
        return PM3_ESOFT;
    }

    // display result of writing operation in structured format
    uint8_t *data = resp.data.asBytes;
    em4x50_word_t words[EM4X50_NO_WORDS];

    prepare_result(data, addr, addr, words);
    print_result(words, addr, addr);
    PrintAndLogEx(SUCCESS, "Successfully wrote to tag");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("lf em 4x50 rdbl -a %u") "` - to read your data", addr);

    return PM3_SUCCESS;
}

// envokes changing the password of EM4x50 tag
int CmdEM4x50WritePwd(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 wrpwd",
                  "Writes EM4x50 password.",
                  "lf em 4x50 wrpwd -p 4f22e7ff -n 12345678"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "pwd", "<hex>", "password, 4 hex bytes, lsb"),
        arg_str1("n", "new", "<hex>", "new password, 4 hex bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int pwd_len = 0;
    uint8_t pwd[4] = {0x0};
    CLIGetHexWithReturn(ctx, 1, pwd, &pwd_len);

    int npwd_len = 0;
    uint8_t npwd[4] = {0x0};
    CLIGetHexWithReturn(ctx, 2, npwd, &npwd_len);

    CLIParserFree(ctx);

    em4x50_data_t etd;
    if (pwd_len != 4) {
        PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwd_len);
        return PM3_EINVARG;
    } else {
        etd.password1 = BYTES2UINT32_BE(pwd);
    }

    if (npwd_len != 4) {
        PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", npwd_len);
        return PM3_EINVARG;
    } else {
        etd.password2 = BYTES2UINT32_BE(npwd);
    }

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_WRITEPWD, (uint8_t *)&etd, sizeof(etd));

    if (!WaitForResponseTimeout(CMD_LF_EM4X50_WRITEPWD, &resp, TIMEOUT_CMD)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_ETEAROFF)
        return PM3_SUCCESS;

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Writing password ( " _RED_("fail") " )");
        return PM3_EFAILED;
    }

    PrintAndLogEx(SUCCESS, "Writing new password %s ( %s )"
                  , sprint_hex_inrow(npwd, sizeof(npwd))
                  , _GREEN_("ok")
                 );
    return PM3_SUCCESS;
}

// fills EM4x50 tag with zeros including password
int CmdEM4x50Wipe(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 wipe",
                  "Wipes EM4x50 tag by filling it with zeros, including the new password\n"
                  "Must give a password.",
                  "lf em 4x50 wipe -p 12345678"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "passsword", "<hex>", "password, 4 bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int pwd_len = 0;
    uint8_t pwd[4] = {0x0};
    CLIGetHexWithReturn(ctx, 1, pwd, &pwd_len);
    CLIParserFree(ctx);

    if (pwd_len != 4) {
        PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwd_len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    em4x50_data_t etd = {.pwd_given = false, .word = 0x0, .password2 = 0x0};

    etd.password1 = BYTES2UINT32_BE(pwd);
    etd.pwd_given = true;

    // clear password
    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_WRITEPWD, (uint8_t *)&etd, sizeof(etd));
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_WRITEPWD, &resp, TIMEOUT_CMD)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Resetting password to 00000000 ( " _GREEN_("ok") " )");
    } else {
        PrintAndLogEx(FAILED, "Resetting password ( " _RED_("failed") " )");
        return PM3_ESOFT;
    }

    // from now on new password 0x0
    etd.password1 = 0x0;

    // clear data (words 1 to 31)
    for (int i = 1; i < EM4X50_DEVICE_SERIAL; i++) {

        // no login necessary for blocks 3 to 31
        etd.pwd_given = (i <= EM4X50_CONTROL);

        PrintAndLogEx(INPLACE, "Wiping block %i", i);

        etd.addresses = i << 8 | i;
        clearCommandBuffer();
        SendCommandNG(CMD_LF_EM4X50_WRITE, (uint8_t *)&etd, sizeof(etd));
        if (!WaitForResponseTimeout(CMD_LF_EM4X50_WRITE, &resp, TIMEOUT_CMD)) {
            PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
            return PM3_ETIMEOUT;
        }

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(FAILED, "Wiping data " _RED_("failed"));
            return PM3_ESOFT;
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Done");
    return PM3_SUCCESS;
}

int CmdEM4x50Restore(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 restore",
                  "Restores data from dumpfile (bin/eml/json) onto a EM4x50 tag.\n"
                  "if used with -u,  the filetemplate `lf-4x50-UID-dump.bin` is used as filename",
                  "lf em 4x50 restore -u 1b5aff5c           -> uses lf-4x50-1B5AFF5C-dump.bin\n"
                  "lf em 4x50 restore -f mydump.eml\n"
                  "lf em 4x50 restore -u 1b5aff5c -p 12345678\n"
                  "lf em 4x50 restore -f mydump.eml -p 12345678\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid", "<hex>", "uid, 4 hex bytes, msb"),
        arg_str0("f", "file", "<fn>", "specify dump filename (bin/eml/json)"),
        arg_str0("p", "pwd", "<hex>", "password, 4 hex bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int uidLen = 0;
    uint8_t uid[4] = {0x0};
    CLIGetHexWithReturn(ctx, 1, uid, &uidLen);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int pwd_len = 0;
    uint8_t pwd[4] = {0x0};
    CLIGetHexWithReturn(ctx, 3, pwd, &pwd_len);
    CLIParserFree(ctx);

    if ((uidLen && fnlen) || (!uidLen && !fnlen)) {
        PrintAndLogEx(FAILED, "either use option 'u' or option 'f'");
        return PM3_EINVARG;
    }

    int startblock = EM4X50_CONTROL + 1;
    em4x50_data_t etd = {.pwd_given = false};

    if (pwd_len) {
        if (pwd_len != 4) {
            PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwd_len);
            return PM3_EINVARG;
        } else {
            etd.password1 = BYTES2UINT32_BE(pwd);
            etd.pwd_given = true;
            // if password is available protection and control word can be restored
            startblock = EM4X50_PROTECTION;
        }
    }

    if (uidLen) {
        PrintAndLogEx(INFO, "Using UID as filename");
        char *fptr = filename + snprintf(filename, sizeof(filename), "lf-4x50-");
        FillFileNameByUID(fptr, uid, "-dump", 4);
    }

    PrintAndLogEx(INFO, "Restoring " _YELLOW_("%s")" to card", filename);

    // read data from dump file; file type has to be "bin", "eml" or "json"
    uint8_t data[DUMP_FILESIZE] = {0x0};
    size_t bytes_read = 0;
    if (em4x50_load_file(filename, data, DUMP_FILESIZE, &bytes_read) != PM3_SUCCESS)
        return PM3_EFILE;

    for (int i = startblock; i < EM4X50_DEVICE_SERIAL; i++) {

        PrintAndLogEx(INPLACE, "Restoring block %i", i);

        etd.addresses = i << 8 | i;
        etd.word = reflect32(BYTES2UINT32_BE((data + 4 * i)));

        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_LF_EM4X50_WRITE, (uint8_t *)&etd, sizeof(etd));
        if (!WaitForResponseTimeout(CMD_LF_EM4X50_WRITE, &resp, TIMEOUT_CMD)) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
            return PM3_ETIMEOUT;
        }

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(FAILED, "Restoring data " _RED_("failed"));
            return PM3_ESOFT;
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Done");
    return PM3_SUCCESS;
}

int CmdEM4x50Sim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50 sim",
                  "Simulates a EM4x50 tag\n"
                  "First upload to device using `lf em 4x50 eload`",
                  "lf em 4x50 sim\n"
                  "lf em 4x50 sim -p 27182818   -> uses password for eload data"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("p", "passsword", "<hex>", "password, 4 bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int pwd_len = 0;
    uint8_t pwd[4] = {0};
    CLIGetHexWithReturn(ctx, 1, pwd, &pwd_len);
    CLIParserFree(ctx);

    uint32_t password = 0;
    if (pwd_len) {
        if (pwd_len != 4) {
            PrintAndLogEx(FAILED, "password length must be 4 bytes, got %d", pwd_len);
            return PM3_EINVARG;
        } else {
            password = BYTES2UINT32_BE(pwd);
        }
    }

    int status = PM3_EFAILED;
    PrintAndLogEx(INFO, "Starting simulating");

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_SIM, (uint8_t *)&password, sizeof(password));

    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " or pm3-button to abort simulation");

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

    bool keypress;
    do {
        keypress = kbd_enter_pressed();

        if (WaitForResponseTimeout(CMD_LF_EM4X50_SIM, &resp, 1500)) {
            status = resp.status;
            break;
        }

    } while (keypress == false);

    if (keypress) {
        SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
        status = PM3_EOPABORTED;
    }

    if ((status == PM3_SUCCESS) || (status == PM3_EOPABORTED))
        PrintAndLogEx(INFO, "Done!");
    else
        PrintAndLogEx(FAILED, "No valid EM4x50 data in memory");

    return resp.status;
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,              AlwaysAvailable, "This help"},
    {"-----------", CmdHelp,         AlwaysAvailable, "--------------------- " _CYAN_("operations") " ---------------------"},
    {"brute",   CmdEM4x50Brute,      IfPm3EM4x50,     "Bruteforce attack to find password"},
    {"chk",     CmdEM4x50Chk,        IfPm3EM4x50,     "Check passwords from dictionary"},
    {"dump",    CmdEM4x50Dump,       IfPm3EM4x50,     "Dump EM4x50 tag"},
    {"info",    CmdEM4x50Info,       IfPm3EM4x50,     "Tag information"},
    {"login",   CmdEM4x50Login,      IfPm3EM4x50,     "Login into EM4x50 tag"},
    {"rdbl",    CmdEM4x50Read,       IfPm3EM4x50,     "Read EM4x50 word data"},
    {"reader",  CmdEM4x50Reader,     IfPm3EM4x50,     "Show standard read mode data"},
    {"restore", CmdEM4x50Restore,    IfPm3EM4x50,     "Restore EM4x50 dump to tag"},
    {"wrbl",    CmdEM4x50Write,      IfPm3EM4x50,     "Write EM4x50 word data"},
    {"wrpwd",   CmdEM4x50WritePwd,   IfPm3EM4x50,     "Change EM4x50 password"},
    {"wipe",    CmdEM4x50Wipe,       IfPm3EM4x50,     "Wipe EM4x50 tag"},
    {"-----------", CmdHelp,         AlwaysAvailable, "--------------------- " _CYAN_("simulation") " ---------------------"},
    {"eload",  CmdEM4x50ELoad,       IfPm3EM4x50,     "Upload EM4x50 dump to emulator memory"},
    {"esave",  CmdEM4x50ESave,       IfPm3EM4x50,     "Save emulator memory to file"},
    {"eview",  CmdEM4x50EView,       IfPm3EM4x50,     "View EM4x50 content in emulator memory"},
    {"sim",    CmdEM4x50Sim,         IfPm3EM4x50,     "Simulate EM4x50 tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFEM4X50(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

