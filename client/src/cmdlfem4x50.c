//-----------------------------------------------------------------------------
// Copyright (C) 2020 tharexde
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x50 commands
//-----------------------------------------------------------------------------

#include "cliparser.h"
#include "cmdlfem4x50.h"
#include "fileutils.h"
#include "commonutil.h"
#include "pmflash.h"

#define CARD_MEMORY_SIZE    4096

#define BYTES2UINT32(x) ((x[0] << 24) | (x[1] << 16) | (x[2] << 8) | (x[3]))

//==============================================================================
// output functions
//==============================================================================

static void prepare_result(const uint8_t *data, int fwr, int lwr, em4x50_word_t *words) {

    // restructure received result in "em4x50_word_t" structure

    for (int i = fwr; i <= lwr; i++)
        for (int j = 0; j < 4; j++)
            words[i].byte[j] = data[i * 4 + (3 - j)];
}

static void print_result(const em4x50_word_t *words, int fwr, int lwr) {

    // print available information for given word from fwr to lwr, i.e.
    // bit table + summary lines with hex notation of word (msb + lsb)

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "  # | word (msb)  | word (lsb)  | desc");
    PrintAndLogEx(INFO, "----+-------------+-------------+--------------------");

    for (int i = fwr; i <= lwr; i++) {

        char s[50] = {0};
        switch (i) {
            case EM4X50_DEVICE_PASSWORD:
                sprintf(s, _YELLOW_("password, write only"));
                break;
            case EM4X50_PROTECTION:
                sprintf(s, _YELLOW_("protection cfg (locked)"));
                break;
            case EM4X50_CONTROL:
                sprintf(s, _YELLOW_("control cfg (locked)"));
                break;
            case EM4X50_DEVICE_SERIAL:
                sprintf(s, _YELLOW_("device serial number (read only)"));
                break;
            case EM4X50_DEVICE_ID:
                sprintf(s, _YELLOW_("device identification (read only)"));
                break;
            default:
                sprintf(s, "user data");
                break;
        }

        char r[30] = {0};
        for (int j = 3; j >= 0; j--) {
            sprintf(r + strlen(r), "%02x ", reflect8(words[i].byte[j]));
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

static void print_info_result(uint8_t *data) {

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
    PrintAndLogEx(INFO, "-------------------------------------------------------------");

    // data section
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, _YELLOW_("EM4x50 data:"));
    print_result(words, 0, EM4X50_NO_WORDS - 1);

    // configuration section
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---- " _CYAN_("Configuration") " ----");

    PrintAndLogEx(INFO, "first word read  %3i", fwr);
    PrintAndLogEx(INFO, "last word read   %3i", lwr);
    PrintAndLogEx(INFO, "password check   %3s", (bpwc) ? _RED_("on") : _GREEN_("off"));
    PrintAndLogEx(INFO, "read after write %3s", (braw) ? "on" : "off");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--------- " _CYAN_("Protection") " ---------");
    PrintAndLogEx(INFO, "first word read protected  %3i", fwrp);
    PrintAndLogEx(INFO, "last word read protected   %3i", lwrp);
    PrintAndLogEx(INFO, "first word write inhibited %3i", fwwi);
    PrintAndLogEx(INFO, "last word write inhibited  %3i", lwwi);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "zero values may indicate read protection");
    PrintAndLogEx(NORMAL, "");
}

//==============================================================================
// file/memory functions
//==============================================================================

static int em4x50_load_file(const char *filename, uint8_t *data, size_t data_len, size_t *bytes_read) {

    // read data from dump file; file type is derived from file name extension

    int res = 0;
    uint32_t serial = 0x0, device_id = 0x0;
     
    if (str_endswith(filename, ".eml"))
        res = loadFileEML(filename, data, bytes_read) != PM3_SUCCESS;
    else if (str_endswith(filename, ".json"))
        res = loadFileJSON(filename, data, data_len, bytes_read, NULL);
    else
        res = loadFile(filename, ".bin", data, data_len, bytes_read);

    if ((res != PM3_SUCCESS) && (*bytes_read != DUMP_FILESIZE))
        return PM3_EFILE;

    // valid em4x50 data?
    serial = bytes_to_num(data + 4 * EM4X50_DEVICE_SERIAL, 4);
    device_id = bytes_to_num(data + 4 * EM4X50_DEVICE_ID, 4);
    if (serial == device_id) {
        PrintAndLogEx(WARNING, "No valid em4x50 data in file %s.", filename);
        return PM3_ENODATA;
    }

    return PM3_SUCCESS;
}

static void em4x50_seteml(uint8_t *src, uint32_t offset, uint32_t numofbytes) {
    // fast push mode
    conn.block_after_ACK = true;
    for (size_t i = offset; i < numofbytes; i += PM3_CMD_DATA_SIZE) {

        size_t len = MIN((numofbytes - i), PM3_CMD_DATA_SIZE);
        if (len == numofbytes - i) {
            // Disable fast mode on last packet
            conn.block_after_ACK = false;
        }
        clearCommandBuffer();
        SendCommandOLD(CMD_LF_EM4X50_ESET, i, len, 0, src + i, len);
    }
}

static int em4x50_wipe_flash(int page) {
    
    int isok = 0;
    
    clearCommandBuffer();
    SendCommandMIX(CMD_FLASHMEM_WIPE, page, false, 0, NULL, 0);
    PacketResponseNG resp;
    
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 8000)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }
    
    isok = resp.oldarg[0] & 0xFF;
    if (!isok) {
        PrintAndLogEx(WARNING, "Flash error");
        return PM3_EFLASH;
    }
    
    return PM3_SUCCESS;
}

static int em4x50_write_flash(uint8_t *data, int offset, size_t datalen) {
    
    int isok = 0;
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining = datalen;
    uint32_t bytes_in_packet = 0;
    PacketResponseNG resp;

    // wipe
    em4x50_wipe_flash(0);
    em4x50_wipe_flash(1);
    em4x50_wipe_flash(2);

    // fast push mode
    conn.block_after_ACK = true;

    while (bytes_remaining > 0) {
        bytes_in_packet = MIN(FLASH_MEM_BLOCK_SIZE, bytes_remaining);

        clearCommandBuffer();
        SendCommandOLD(CMD_FLASHMEM_WRITE, offset + bytes_sent, bytes_in_packet, 0, data + bytes_sent, bytes_in_packet);

        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;

        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000) == false) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            conn.block_after_ACK = false;
            return PM3_ETIMEOUT;
        }

        isok = resp.oldarg[0] & 0xFF;
        if (!isok) {
            conn.block_after_ACK = false;
            PrintAndLogEx(FAILED, "Flash write fail [offset %u]", bytes_sent);
            return PM3_EFLASH;
        }
    }

    conn.block_after_ACK = false;
    
    return PM3_SUCCESS;
}

int CmdEM4x50ELoad(const char *Cmd) {

    int slen = 0;
    size_t bytes_read = 0;
    char filename[FILE_PATH_SIZE] = {0};
    uint8_t data[DUMP_FILESIZE] = {0x0};

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_eload",
                  "Loads EM4x50 tag dump into emulator memory on device.",
                  "lf em 4x50_eload -f mydump.bin -> uploads bin file ./mydump.bin\n"
                  "lf em 4x50_eload -f mydump.eml -> uploads eml file ./mydump.eml\n"
                  "lf em 4x50_eload -f mydump.json -> uploads json file ./mydump.json\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "filename", "<filename>", "dump filename"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &slen);
    CLIParserFree(ctx);

    // read data from dump file; file type has to be "bin", "eml" or "json"
    if (em4x50_load_file(filename, data, DUMP_FILESIZE, &bytes_read) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Read error");
        return PM3_EFILE;
    }

    // upload to emulator memory
    PrintAndLogEx(INFO, "Uploading dump " _YELLOW_("%s") " to emulator memory", filename);
    em4x50_seteml(data, 0, DUMP_FILESIZE);
    
    PrintAndLogEx(INFO, "Done");
    return PM3_SUCCESS;
}

int CmdEM4x50ESave(const char *Cmd) {

    int slen = 0;
    uint32_t serial = 0x0, device_id = 0x0;
    char filename[FILE_PATH_SIZE] = {0};
    char *fptr = filename;
    uint8_t data[DUMP_FILESIZE] = {0x0};

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_esave",
                  "Saves bin/eml/json dump file of emulator memory.",
                  "lf em 4x50_esave -> use UID as filename\n"
                  "lf em 4x50_esave -f mydump.bin -> saves to bin file ./mydump.bin\n"
                  "lf em 4x50_esave -f mydump.eml -> saves to eml file ./mydump.eml\n"
                  "lf em 4x50_esave -f mydump.json -> saves to json file ./mydump.json\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "filename", "<filename>", "data filename"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &slen);
    CLIParserFree(ctx);

    // download emulator memory
    PrintAndLogEx(SUCCESS, "Reading emulator memory...");
    if (!GetFromDevice(BIG_BUF_EML, data, DUMP_FILESIZE, 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(data);
        return PM3_ETIMEOUT;
    }
    
    // valid em4x50 data?
    serial = bytes_to_num(data + 4 * EM4X50_DEVICE_SERIAL, 4);
    device_id = bytes_to_num(data + 4 * EM4X50_DEVICE_ID, 4);
    if (serial == device_id) {
        PrintAndLogEx(WARNING, "No valid em4x50 data in flash memory.");
        return PM3_ENODATA;
    }
    
    // user supplied filename?
    if (slen == 0) {
        PrintAndLogEx(INFO, "Using UID as filename");
        fptr += snprintf(fptr, sizeof(filename), "lf-4x50-");
        FillFileNameByUID(fptr, (uint8_t *)&data[4 * EM4X50_DEVICE_ID], "-dump", 4);
    }

    saveFile(filename, ".bin", data, DUMP_FILESIZE);
    saveFileEML(filename, data, DUMP_FILESIZE, 4);
    saveFileJSON(filename, jsfEM4x50, data, DUMP_FILESIZE, NULL);
    return PM3_SUCCESS;
}

//==============================================================================
// login functions
//==============================================================================

int CmdEM4x50Login(const char *Cmd) {

    int pwdLen = 0;
    uint8_t pwd[4] = {0x0};
    uint32_t password = 0x0;
    PacketResponseNG resp;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_login",
                  "Login into EM4x50 tag.",
                  "lf em 4x50_login -p 12345678 -< login with password 12345678\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "passsword", "<password>", "password, hex, 4 bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    
    CLIGetHexWithReturn(ctx, 1, pwd, &pwdLen);
    if (pwdLen != 4) {
        PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwdLen);
        return PM3_EINVARG;
    } else {
        password = BYTES2UINT32(pwd);
    }

    CLIParserFree(ctx);

    // start
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_LOGIN, (uint8_t *)&password, sizeof(password));
    WaitForResponse(CMD_LF_EM4X50_LOGIN, &resp);

    // print response
    if (resp.status == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Login " _GREEN_("ok"));
    else
        PrintAndLogEx(FAILED, "Login " _RED_("failed"));

    return resp.status;
}

int CmdEM4x50Brute(const char *Cmd) {

    const int speed = 27;   // 27 passwords/second (empirical value)
    int no_iter = 0, dur_h = 0, dur_m = 0, dur_s = 0;

    int pwd1Len = 0, pwd2Len = 0;
    uint8_t pwd1[4] = {0x0}, pwd2[4] = {0x0};
    em4x50_data_t etd;
    PacketResponseNG resp;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_brute",
                  "Tries to bruteforce the password of a EM4x50. Function can be stopped by pressing pm3 button.",
                  "lf em 4x50_brute -f 12330000 -l 12340000 -> tries passwords from 0x12330000 to 0x1234000000\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "fp", "<password>", "first password (start), hex, 4 bytes, lsb"),
        arg_str1("l", "lp", "<password>", "last password (stop), hex, 4 bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    
    CLIGetHexWithReturn(ctx, 1, pwd1, &pwd1Len);
    CLIGetHexWithReturn(ctx, 2, pwd2, &pwd2Len);

    if (pwd1Len != 4) {
        PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwd1Len);
        return PM3_EINVARG;
    } else if (pwd2Len != 4) {
            PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwd2Len);
            return PM3_EINVARG;
    } else {
        etd.password1 = BYTES2UINT32(pwd1);
        etd.password2 = BYTES2UINT32(pwd2);
    }

    CLIParserFree(ctx);

    // print some information
    no_iter = etd.password2 - etd.password1 + 1;
    dur_s = no_iter / speed;
    dur_h = dur_s / 3600;
    dur_m = (dur_s - dur_h * 3600) / 60;
    dur_s -= dur_h * 3600 + dur_m * 60;
    PrintAndLogEx(INFO, "Trying %i passwords in range [0x%08x, 0x%08x]",
                  no_iter, etd.password1, etd.password2);
    PrintAndLogEx(INFO, "Estimated duration: %ih%im%is", dur_h, dur_m, dur_s);

    // start
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_BRUTE, (uint8_t *)&etd, sizeof(etd));
    WaitForResponse(CMD_LF_EM4X50_BRUTE, &resp);

    // print response
    if ((bool)resp.status)
        PrintAndLogEx(SUCCESS, "Password " _GREEN_("found") ": 0x%08x", resp.data.asDwords[0]);
    else
        PrintAndLogEx(FAILED, "Password: " _RED_("not found"));

    return PM3_SUCCESS;
}

int CmdEM4x50Chk(const char *Cmd) {

    // upload passwords from given dictionary to flash memory and
    // start password check;
    // if no filename is given dictionary "t55xx_default_pwds.dic" is used
    
    int status = PM3_EFAILED;
    int res = 0, slen = 0;
    int keys_remain = 0;
    int block_count = 1;
    size_t datalen = 0;
    uint8_t data[FLASH_MEM_MAX_SIZE] = {0x0};
    uint8_t *keys = data;
    uint32_t key_count = 0, offset = 0;
    char filename[FILE_PATH_SIZE] = {0};
    PacketResponseNG resp;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_chk",
                  "Dictionary attack against EM4x50.",
                  "lf em 4x50_chk -> uses T55xx default dictionary\n"
                  "lf em 4x50_chk -f my.dic -> uses dictionary ./my.dic\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "filename", "<filename>", "dictionary filename"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &slen);
    CLIParserFree(ctx);
    
    // no filename -> default = t55xx_default_pwds
    if (strlen(filename) == 0) {
        snprintf(filename, sizeof(filename), "t55xx_default_pwds");
        offset = DEFAULT_T55XX_KEYS_OFFSET;
        PrintAndLogEx(INFO, "treating file as T55xx keys");
    }
    
    res = loadFileDICTIONARY(filename, data + 2, &datalen, 4, &key_count);
    if (res || !key_count)
        return PM3_EFILE;
    
    PrintAndLogEx(INFO, "You can cancel this operation by pressing the pm3 button");
    
    if (datalen > CARD_MEMORY_SIZE) {
        
        // we have to use more than one block of passwords
        block_count = (4 * key_count) / CARD_MEMORY_SIZE;
        keys_remain = key_count - block_count * CARD_MEMORY_SIZE / 4;
        
        if (keys_remain != 0)
            block_count++;
        
        // adjust pwd_size_available and pwd_count
        datalen = CARD_MEMORY_SIZE;
        key_count = datalen / 4;

        PrintAndLogEx(INFO, "Keys subdivided into %i blocks", block_count);
    }
    
    for (int n = 0; n < block_count; n++) {

        // adjust parameters if more than 1 block
        if (n != 0) {

            keys += datalen;

            // final run with remaining passwords
            if (n == block_count - 1) {
                key_count = keys_remain;
                datalen = 4 * keys_remain;
            }
        }
        
        keys[0] = (key_count >> 0) & 0xFF;
        keys[1] = (key_count >> 8) & 0xFF;

        PrintAndLogEx(INPLACE, "Checking block #%i (%i keys)", n + 1, key_count);

        // send to device
        res = em4x50_write_flash(keys, offset, datalen + 2);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "Error uploading to flash.");
            return res;
        }

        clearCommandBuffer();
        SendCommandNG(CMD_LF_EM4X50_CHK, (uint8_t *)&offset, sizeof(offset));
        WaitForResponseTimeoutW(CMD_LF_EM4X50_CHK,  &resp, -1, false);
        
        status = resp.status;
        if ((status == PM3_SUCCESS) || (status == PM3_EOPABORTED))
            break;
    }

    // print response
    if (status == PM3_SUCCESS) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, "Key " _GREEN_("found: %02x %02x %02x %02x"),
                      resp.data.asBytes[3],
                      resp.data.asBytes[2],
                      resp.data.asBytes[1],
                      resp.data.asBytes[0]
                      );
    } else {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(FAILED, "No key found");
    }

    PrintAndLogEx(INFO, "Done");
    return PM3_SUCCESS;
}

//==============================================================================
// reset functions
//==============================================================================

int CmdEM4x50Reset(const char *Cmd) {

    PacketResponseNG resp;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_reset",
                  "Reseta EM4x50 tag.",
                  "lf em 4x50_reset\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // start
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_RESET, 0, 0);
    WaitForResponse(CMD_LF_EM4X50_RESET, &resp);

    // print response
    if (resp.status == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Reset " _GREEN_("ok"));
    else
        PrintAndLogEx(FAILED, "Reset " _RED_("failed"));

    return resp.status;
}

//==============================================================================
// read functions
//==============================================================================

//quick test for EM4x50 tag
bool detect_4x50_block(void) {
    em4x50_data_t etd = {
        .pwd_given = false,
        .addr_given = true,
        .addresses = (EM4X50_DEVICE_ID << 8) | EM4X50_DEVICE_ID,
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

int em4x50_read(em4x50_data_t *etd, em4x50_word_t *out) {

    // envoke reading
    // - with given address (option b) (and optional password if address is
    //   read protected) -> selective read mode

    em4x50_data_t edata = { .pwd_given = false, .addr_given = false };

    if (etd != NULL) {
        edata = *etd;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_READ, (uint8_t *)&edata, sizeof(edata));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_READ, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "(em4x50) timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS)
        return PM3_ESOFT;

    uint8_t *data = resp.data.asBytes;
    em4x50_word_t words[EM4X50_NO_WORDS];
    prepare_result(data, etd->addresses & 0xFF, (etd->addresses >> 8) & 0xFF, words);

    if (out != NULL)
        memcpy(out, &words, sizeof(em4x50_word_t) * EM4X50_NO_WORDS);

    print_result(words, etd->addresses & 0xFF, (etd->addresses >> 8) & 0xFF);

    return PM3_SUCCESS;
}

int CmdEM4x50Read(const char *Cmd) {

    int pwdLen = 0;
    int addr = 0;
    uint8_t pwd[4] = {0x0};
    em4x50_data_t etd;

    // init
    memset(&etd, 0x00, sizeof(em4x50_data_t));
    etd.addr_given = false;
    etd.pwd_given = false;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_read",
                  "Reads single EM4x50 block/word.",
                  "lf em 4x50_read -b 3 -> reads block 3\n"
                  "lf em 4x50_read -b 32 -p 12345678 -> reads block 32 with password 0x12345678\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int1("b", "block", "<address>", "block/word address, dec"),
        arg_str0("p", "passsword", "<password>", "password, hex, 4 bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    
    addr = arg_get_int_def(ctx, 1, 0);
    CLIGetHexWithReturn(ctx, 2, pwd, &pwdLen);
    
    if (addr <= 0 || addr >= EM4X50_NO_WORDS) {
        return PM3_EINVARG;
    } else {
        etd.addresses = (addr << 8) | addr;
        etd.addr_given = true;
    }

    if (pwdLen) {
        if (pwdLen != 4) {
            PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwdLen);
            return PM3_EINVARG;
        } else {
            etd.password1 = BYTES2UINT32(pwd);
            etd.pwd_given = true;
        }
    }

    CLIParserFree(ctx);

    return em4x50_read(&etd, NULL);
}

int CmdEM4x50Info(const char *Cmd) {

    // envoke reading of a EM4x50 tag which has to be on the antenna because
    // decoding is done by the device (not on client side)

    int pwdLen = 0;
    int status = 0;
    uint8_t pwd[4] = {0x0};
    em4x50_data_t etd = {.pwd_given = false};
    
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_info",
                  "Tag information EM4x50.",
                  "lf em 4x50_info\n"
                  "lf em 4x50_info -p 12345678 -> uses password 0x12345678\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("p", "passsword", "<password>", "password, hex, 4 bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    
    CLIGetHexWithReturn(ctx, 1, pwd, &pwdLen);
    
    if (pwdLen) {
        if (pwdLen != 4) {
            PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwdLen);
            return PM3_EINVARG;
        } else {
            etd.password1 = BYTES2UINT32(pwd);
            etd.pwd_given = true;
        }
    }

    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_INFO, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_INFO, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    status = resp.status;

    if (status == PM3_SUCCESS)
        print_info_result(resp.data.asBytes);
    else
        PrintAndLogEx(FAILED, "Reading tag " _RED_("failed"));

    return status;
}

int CmdEM4x50Reader(const char *Cmd) {

    int now = 0;
    PacketResponseNG resp;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_reader",
                  "Shows standard read data of EM4x50 tag.",
                  "lf em 4x50_reader\n"
                  "lf em 4x50_reader -@   -> continuous reader mode"
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

        clearCommandBuffer();
        SendCommandNG(CMD_LF_EM4X50_READER, 0, 0);
        WaitForResponseTimeoutW(CMD_LF_EM4X50_READER,  &resp, -1, false);

        now = resp.status;
        
        // print response
        if (now > 0) {

            em4x50_word_t words[EM4X50_NO_WORDS];
            prepare_result(resp.data.asBytes, 0, now - 1, words);

            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, " word (msb)  | word (lsb)  ");
            PrintAndLogEx(INFO, "-------------+-------------");

            for (int i = 0; i < now; i++) {

                char r[30] = {0};
                for (int j = 3; j >= 0; j--)
                    sprintf(r + strlen(r), "%02x ", reflect8(words[i].byte[j]));

                PrintAndLogEx(INFO, _GREEN_(" %s") "| %s",
                              sprint_hex(words[i].byte, 4),
                              r
                              );
            }
            
            PrintAndLogEx(INFO, "-------------+-------------");
        }
    } while (cm && !kbd_enter_pressed());

    return PM3_SUCCESS;
}

int CmdEM4x50Dump(const char *Cmd) {

    int fnLen = 0, pwdLen = 0, status = 0;
    uint8_t pwd[4] = {0x0};
    char filename[FILE_PATH_SIZE] = {0};
    char *fptr = filename;
    em4x50_data_t etd = {.pwd_given = false};
    uint8_t data[DUMP_FILESIZE] = {0};

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_dump",
                  "Reads all blocks/words from EM4x50 tag and saves dump in bin/eml/json format.",
                  "lf em 4x50_dump -> saves dump in lf-4x50-<UID>-dump.bin/eml/json\n"
                  "lf em 4x50_dump -f mydump.eml -> saves dump in mydump.eml\n"
                  "lf em 4x50_dump -p 12345678\n"
                  "lf em 4x50_dump -f mydump.eml -p 12345678\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "filename", "<filename>", "dump filename (bin/eml/json)"),
        arg_str0("p", "passsword", "<password>", "password, hex, 4 bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    
    CLIParamStrToBuf(arg_get_str(ctx, 1),
                     (uint8_t *)filename,
                     FILE_PATH_SIZE,
                     &fnLen
                     );
    CLIGetHexWithReturn(ctx, 2, pwd, &pwdLen);
        
    if (pwdLen) {
        if (pwdLen != 4) {
            PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwdLen);
            return PM3_EINVARG;
        } else {
            etd.password1 = BYTES2UINT32(pwd);
            etd.pwd_given = true;
        }
    }
    
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Reading EM4x50 tag");
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_INFO, (uint8_t *)&etd, sizeof(etd));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_INFO, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    status = resp.status;
    if (status != PM3_SUCCESS) {
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
        fptr += sprintf(fptr, "lf-4x50-");
        FillFileNameByUID(fptr, words[EM4X50_DEVICE_ID].byte, "-dump", 4);
    }

    for (int i = 0; i < EM4X50_NO_WORDS; i++)
        memcpy(data + (i * 4), words[i].byte, 4);

    // saveFileEML will add .eml extension to filename
    // saveFile (binary) passes in the .bin extension.
    // saveFileJSON adds .json extension
    saveFileEML(filename, data, sizeof(data), 4);
    saveFile(filename, ".bin", data, sizeof(data));
    saveFileJSON(filename, jsfEM4x50, data, sizeof(data), NULL);

    return PM3_SUCCESS;
}

//==============================================================================
// write functions
//==============================================================================

int CmdEM4x50Write(const char *Cmd) {

    // envoke writing a single word (32 bit) to a EM4x50 tag

    int wordLen = 0, pwdLen = 0, addr = 0;
    int status = 0;
    uint8_t word[4] = {0x0};
    uint8_t pwd[4] = {0x0};
    em4x50_data_t etd = {.pwd_given = false};
    
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_write",
                  "Writes single block/word to EM4x50 tag.",
                  "lf em 4x50_write -b 3 -d 4f22e7ff -> writes 0x4f22e7ff to block 3\n"
                  "lf em 4x50_write -b 3 -d 4f22e7ff -p 12345678\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int1("b", "block", "<address>", "block/word address, dec"),
        arg_str1("d", "data", "<data>", "data, hex, 4 bytes, lsb"),
        arg_str0("p", "passsword", "<password>", "password, hex, 4 bytes, lsb"),
        arg_param_end
    };
    
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    
    addr = arg_get_int_def(ctx, 1, 0);
    CLIGetHexWithReturn(ctx, 2, word, &wordLen);
    CLIGetHexWithReturn(ctx, 3, pwd, &pwdLen);
    
    if (addr <= 0 || addr >= EM4X50_NO_WORDS) {
        PrintAndLogEx(FAILED, "address has to be within range [0, 31]");
        return PM3_EINVARG;
    } else {
        etd.addresses = (addr << 8) | addr;
        etd.addr_given = true;
    }
    if (wordLen != 4) {
        PrintAndLogEx(FAILED, "word/data length must be 4 bytes instead of %d", wordLen);
        return PM3_EINVARG;
    } else {
        etd.word = BYTES2UINT32(word);
    }
    if (pwdLen) {
        if (pwdLen != 4) {
            PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwdLen);
            return PM3_EINVARG;
        } else {
            etd.password1 = BYTES2UINT32(pwd);
            etd.pwd_given = true;
        }
    }

    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_WRITE, (uint8_t *)&etd, sizeof(etd));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_WRITE, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    status = resp.status;
    if (status == PM3_ETEAROFF)
        return PM3_SUCCESS;

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
    PrintAndLogEx(HINT, "Try `" _YELLOW_("lf em 4x50_read a %u") "` - to read your data", addr);

    return PM3_SUCCESS;
}

int CmdEM4x50WritePwd(const char *Cmd) {

    // envokes changing the password of EM4x50 tag

    int status = PM3_EFAILED;
    int pwdLen = 0, npwdLen = 0;
    uint8_t pwd[4] = {0x0}, npwd[4] = {0x0};
    PacketResponseNG resp;
    em4x50_data_t etd;
    
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_writepwd",
                  "Writes EM4x50 password.",
                  "lf em 4x50_writepwd -p 4f22e7ff -n 12345678 -> replaces password 0x4f22e7ff with 0x12345678\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "pwd", "<password>", "password, hex, 4 bytes, lsb"),
        arg_str1("n", "newpwd", "<password>", "new password, hex, 4 bytes, lsb"),
        arg_param_end
    };
    
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    
    CLIGetHexWithReturn(ctx, 1, pwd, &pwdLen);
    CLIGetHexWithReturn(ctx, 2, npwd, &npwdLen);
    
    if (pwdLen != 4) {
        PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwdLen);
        return PM3_EINVARG;
    } else {
        etd.password1 = BYTES2UINT32(pwd);
    }
    if (npwdLen != 4) {
        PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", npwdLen);
        return PM3_EINVARG;
    } else {
        etd.password2 = BYTES2UINT32(npwd);
    }

    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_WRITEPWD, (uint8_t *)&etd, sizeof(etd));

    if (!WaitForResponseTimeout(CMD_LF_EM4X50_WRITEPWD, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    status = resp.status;

    if (status == PM3_ETEAROFF)
        return PM3_SUCCESS;

    // print response
    if (status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Writing password " _RED_("failed"));
        return PM3_EFAILED;
    }

    PrintAndLogEx(SUCCESS, "Writing new password " _GREEN_("ok"));

    return PM3_SUCCESS;
}

int CmdEM4x50Wipe(const char *Cmd) {

    // fills EM4x50 tag with zeros including password

    bool isOK = false;
    int pwdLen = 0;
    uint8_t pwd[4] = {0x0};
    em4x50_data_t etd = {.pwd_given = false, .word = 0x0, .password2 = 0x0};
    PacketResponseNG resp;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_wipe",
                  "Wipes EM4x50 tag.",
                  "lf em 4x50_wipe -p 12345678 -> wipes tag with password 0x12345678\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "passsword", "<password>", "password, hex, 4 bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    
    CLIGetHexWithReturn(ctx, 1, pwd, &pwdLen);
    if (pwdLen != 4) {
        PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwdLen);
        return PM3_EINVARG;
    } else {
        etd.password1 = BYTES2UINT32(pwd);
        etd.pwd_given = true;
    }

    CLIParserFree(ctx);
    
    // clear password
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_WRITEPWD, (uint8_t *)&etd, sizeof(etd));
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_WRITEPWD, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Resetting password " _GREEN_("ok"));
    } else {
        PrintAndLogEx(FAILED, "Resetting password " _RED_("failed"));
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
        if (!WaitForResponseTimeout(CMD_LF_EM4X50_WRITE, &resp, TIMEOUT)) {
            PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
            return PM3_ETIMEOUT;
        }

        isOK = resp.status;
        if (isOK != PM3_SUCCESS) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(FAILED, "Wiping data " _RED_("failed"));
            return PM3_ESOFT;
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Wiping data " _GREEN_("ok"));
    
    PrintAndLogEx(INFO, "Done");

    return PM3_SUCCESS;
}

int CmdEM4x50Restore(const char *Cmd) {

    int uidLen = 0, fnLen = 0, pwdLen = 0, status = 0;
    uint8_t pwd[4] = {0x0}, uid[4] = {0x0};
    uint8_t data[DUMP_FILESIZE] = {0x0};
    size_t bytes_read = 0;
    char filename[FILE_PATH_SIZE] = {0};
    char *fptr = filename;
    em4x50_data_t etd = {.pwd_given = false};
    PacketResponseNG resp;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_restore",
                  "Restores data from dumpfile onto a Em4x50 tag.",
                  "lf em 4x50_restore -u 1b5aff5c -> uses lf-4x50-1B5AFF5C-dump.bin\n"
                  "lf em 4x50_restore -f mydump.eml -> uses mydump.eml\n"
                  "lf em 4x50_restore -u 1b5aff5c -p 12345678 -> \n"
                  "lf em 4x50_restore -f mydump.eml -p 12345678 -> \n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid", "<uid>", "uid, hex, 4 bytes, msb, restore from lf-4x50-<uid>-dump.bin"),
        arg_str0("f", "filename", "<filename>", "dump filename (bin/eml/json)"),
        arg_str0("p", "passsword", "<password>", "password, hex, 4 bytes, lsb"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    
    CLIGetHexWithReturn(ctx, 1, uid, &uidLen);
    CLIParamStrToBuf(arg_get_str(ctx, 2),
                     (uint8_t *)filename,
                     FILE_PATH_SIZE,
                     &fnLen
                     );
    CLIGetHexWithReturn(ctx, 3, pwd, &pwdLen);
    
    if ((uidLen && fnLen) || (!uidLen && !fnLen)) {
        PrintAndLogEx(FAILED, "either use option 'u' or option 'f'");
        return PM3_EINVARG;
    }
    
    if (uidLen) {
        PrintAndLogEx(INFO, "Using UID as filename");
        fptr += sprintf(fptr, "lf-4x50-");
        FillFileNameByUID(fptr, uid, "-dump", 4);
    }
    
    if (pwdLen) {
        if (pwdLen != 4) {
            PrintAndLogEx(FAILED, "password length must be 4 bytes instead of %d", pwdLen);
            return PM3_EINVARG;
        } else {
            etd.password1 = BYTES2UINT32(pwd);
            etd.pwd_given = true;
        }
    }

    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Restoring " _YELLOW_("%s")" to card", filename);

    // read data from dump file; file type has to be "bin", "eml" or "json"
    if (em4x50_load_file(filename, data, DUMP_FILESIZE, &bytes_read) != PM3_SUCCESS)
        return PM3_EFILE;

    // upload to flash memory
    status = em4x50_write_flash(data, 0, bytes_read);
    if (status != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Error uploading to flash.");
        return status;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_RESTORE, (uint8_t *)&etd, sizeof(etd));
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_RESTORE, &resp, 2 * TIMEOUT)) {
        PrintAndLogEx(FAILED, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    status = resp.status;
    if (status == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Restore " _GREEN_("ok"));
    else
        PrintAndLogEx(FAILED, "Restore " _RED_("failed"));

    return status;
}

//==============================================================================
// simulate functions
//==============================================================================

int CmdEM4x50Sim(const char *Cmd) {

    int slen = 0, res = 0;
    size_t bytes_read = 0;
    uint8_t data[DUMP_FILESIZE] = {0x0};
    char filename[FILE_PATH_SIZE] = {0};
    PacketResponseNG resp;
     
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x50_sim",
                  "Simulates a EM4x50 tag",
                  "lf em 4x50_sim -> simulates EM4x50 data in flash memory.\n"
                  "lf em 4x50_sim -f mydump.eml -> simulates content of file ./mydump\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "filename", "<filename>", "dump filename, bin/eml/json"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &slen);
    CLIParserFree(ctx);
    
    // read data from dump file; file type has to be "bin", "eml" or "json"
    if (slen != 0) {

        // load file content
        if (em4x50_load_file(filename, data, DUMP_FILESIZE, &bytes_read) != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Read error");
            return PM3_EFILE;
        }

        if (bytes_read * 8 > FLASH_MEM_MAX_SIZE) {
            PrintAndLogEx(FAILED, "Filesize is larger than available memory");
            return PM3_EOVFLOW;
        }

        PrintAndLogEx(INFO, "Uploading dump " _YELLOW_("%s") " to flash memory", filename);

        if (res != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Error wiping flash.");
            return res;
        }

        // upload to device
        res = em4x50_write_flash(data, 0, bytes_read);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Error uploading to flash.");
            return res;
        }
    }

    PrintAndLogEx(INFO, "Simulating data in " _YELLOW_("%s"), filename);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_SIM, 0, 0);
    WaitForResponse(CMD_LF_EM4X50_SIM, &resp);
    
    if (resp.status == PM3_SUCCESS)
        PrintAndLogEx(INFO, "Done");
    else
        PrintAndLogEx(FAILED, "No valid em4x50 data in flash memory.");

    return resp.status;
}
