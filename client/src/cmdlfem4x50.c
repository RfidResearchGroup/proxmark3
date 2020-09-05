//-----------------------------------------------------------------------------
// Copyright (C) 2020 tharexde
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x50 commands
//-----------------------------------------------------------------------------

#include "cmdlfem4x50.h"
#include <ctype.h>
#include "fileutils.h"
#include "comms.h"
#include "commonutil.h"
#include "em4x50.h"

static int usage_lf_em4x50_info(void) {
    PrintAndLogEx(NORMAL, "Read all information of EM4x50. Tag nust be on antenna.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_info [h] [v] [p <pwd>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       v         - verbose output");
    PrintAndLogEx(NORMAL, "       p <pwd>   - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_info"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_info p fa225de1"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_info v p fa225de1"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_write(void) {
    PrintAndLogEx(NORMAL, "Write EM4x50 word. Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_write [h] [a <address>] [w <data>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       a <addr>  - memory address to write to (dec)");
    PrintAndLogEx(NORMAL, "       w <word>  - word to write (hex)");
    PrintAndLogEx(NORMAL, "       p <pwd>   - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_write a 3 w deadc0de"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_write_password(void) {
    PrintAndLogEx(NORMAL, "Write EM4x50 password. Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_write_password [h] [p <pwd>] [n <pwd>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       p <pwd>   - password (hex)");
    PrintAndLogEx(NORMAL, "       n <pwd>   - new password (hex)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_write_password p 11223344 n 01020304"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_read(void) {
    PrintAndLogEx(NORMAL, "Read EM4x50 word(s). Tag must be on antenna.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_read [h] [a <address>] [p <pwd>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       a <addr>  - memory address to read (dec) (optional)");
    PrintAndLogEx(NORMAL, "       p <pwd>   - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_read"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_read a 2 p 00000000"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_dump(void) {
    PrintAndLogEx(NORMAL, "Dump EM4x50 tag.  Tag must be on antenna.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_dump [h] [f <filename prefix>] [p <pwd>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h                     - this help");
    PrintAndLogEx(NORMAL, "       f <filename prefix>   - overide filename prefix (optional).  Default is based on UID");
    PrintAndLogEx(NORMAL, "       p <pwd>               - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_dump"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_dump p 11223344"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_dump f card_nnn p 11223344"));
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_wipe(void) {
    PrintAndLogEx(NORMAL, "Wipe data from EM4x50 tag. Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_wipe [h] [p <pwd>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       p <pwd>   - password (hex)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_wwipe p 11223344"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static void prepare_result(const uint8_t *byte, int fwr, int lwr, em4x50_word_t *words) {

    // restructure received result in "em4x50_word_t" structure and check all
    // parities including stop bit; result of each check is stored in structure

    int p = 0, c[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    for (int i = fwr; i <= lwr; i++) {

        words[i].stopparity = true;
        words[i].parity = true;

        for (int j = 0; j < 8; j++)
            c[j] = 0;

        for (int j = 0; j < 4; j++) {
            words[i].byte[j] = byte[i * 7 + j];
            words[i].row_parity[j] = (byte[i * 7 + 4] >> (3 - j)) & 1;

            // collect parities
            p = 0;

            for (int k = 0; k < 8; k++) {

                // row parity
                p ^= (words[i].byte[j] >> k) & 1;

                // column parity
                c[k] ^= (words[i].byte[j] >> (7 - k)) & 1;
            }

            // check row parities
            words[i].rparity[j] = (words[i].row_parity[j] == p) ? true : false;

            if (!words[i].rparity[j])
                words[i].parity = false;
        }

        // check column parities
        words[i].col_parity = byte[i * 7 + 5];

        for (int j = 0; j < 8; j++) {
            words[i].cparity[j] = (((words[i].col_parity >> (7 - j)) & 1) == c[j]) ? true : false;

            if (!words[i].cparity[j])
                words[i].parity = false;
        }

        // check stop bit
        words[i].stopbit = byte[i * 7 + 6] & 1;

        if (words[i].stopbit == 1)
            words[i].stopparity = false;
    }
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

//quick test for EM4x50 tag
bool detect_4x50_block(void) {
    em4x50_data_t etd = {
        .pwd_given = false,
        .addr_given = true,
        .address = EM4X50_DEVICE_ID,
    };
    em4x50_word_t words[EM4X50_NO_WORDS];
    return (em4x50_read(&etd, words, false) == PM3_SUCCESS);
}

int read_em4x50_uid(void) {
    em4x50_data_t etd = {
        .pwd_given = false,
        .addr_given = true,
        .address = EM4X50_DEVICE_SERIAL,
    };
    em4x50_word_t words[EM4X50_NO_WORDS];
    int res = em4x50_read(&etd, words, false);
    if (res == PM3_SUCCESS)
        PrintAndLogEx(INFO, " Serial: " _GREEN_("%s"), sprint_hex(words[EM4X50_DEVICE_SERIAL].byte, 4));
    return res;
}

int CmdEM4x50Info(const char *Cmd) {

    // envoke reading of a EM4x50 tag which has to be on the antenna because
    // decoding is done by the device (not on client side)

    bool errors = false, verbose = false;
    uint8_t cmdp = 0;
    em4x50_data_t etd;
    etd.pwd_given = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {

            case 'h':
                return usage_lf_em4x50_info();

            case 'p':
                if (param_gethex(Cmd, cmdp + 1, etd.password, 8)) {
                    PrintAndLogEx(FAILED, "\n  password has to be 8 hex symbols\n");
                    return PM3_EINVARG;
                }
                etd.pwd_given = true;
                cmdp += 2;
                break;

            case 'v':
                verbose = true;
                cmdp += 1;
                break;

            default:
                PrintAndLogEx(WARNING, "  Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    // validation
    if (errors)
        return usage_lf_em4x50_info();

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_INFO, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    bool success = (resp.status & STATUS_SUCCESS) >> 1;
    if (success) {
        print_info_result(resp.data.asBytes, verbose);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "reading tag " _RED_("failed"));
    return PM3_ESOFT;
}

int CmdEM4x50Write(const char *Cmd) {

    // envoke writing a single word (32 bit) to a EM4x50 tag

    em4x50_data_t etd = { .pwd_given = false };

    bool errors = false, bword = false, baddr = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {

        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h': {
                return usage_lf_em4x50_write();
            }
            case 'p': {
                if (param_gethex(Cmd, cmdp + 1, etd.password, 8)) {
                    PrintAndLogEx(FAILED, "\n  password has to be 8 hex symbols\n");
                    return PM3_EINVARG;
                }
                etd.pwd_given = true;
                cmdp += 2;
                break;
            }
            case 'w': {
                if (param_gethex(Cmd, cmdp + 1, etd.word, 8)) {
                    PrintAndLogEx(FAILED, "\n  word has to be 8 hex symbols\n");
                    return PM3_EINVARG;
                }
                bword = true;
                cmdp += 2;
                break;
            }
            case 'a': {
                param_getdec(Cmd, cmdp + 1, &etd.address);

                // validation
                if (etd.address < 1 || etd.address > 31) {
                    PrintAndLogEx(FAILED, "\n  error, address has to be in range [1-31]\n");
                    return PM3_EINVARG;
                }
                baddr = true;
                cmdp += 2;
                break;
            }
            default: {
                PrintAndLogEx(WARNING, "\n  Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
            }
        }
    }

    if (errors || !bword || !baddr)
        return usage_lf_em4x50_write();

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_WRITE, (uint8_t *)&etd, sizeof(etd));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    bool isOK = (resp.status & STATUS_SUCCESS) >> 1;
    if (isOK == false) {
        PrintAndLogEx(FAILED, "writing " _RED_("failed"));
        return PM3_ESOFT;
    }

    if (etd.pwd_given) {
        bool login = resp.status & STATUS_LOGIN;
        if (login == false) {
            PrintAndLogEx(FAILED, "login failed");
            return PM3_ESOFT;
        }
        PrintAndLogEx(SUCCESS, "login with password " _YELLOW_("%s"), sprint_hex_inrow(etd.password, 4));
    }

    // display result of writing operation in structured format
    uint8_t *data = resp.data.asBytes;
    em4x50_word_t words[EM4X50_NO_WORDS];

    prepare_result(data, etd.address, etd.address, words);
    print_result(words, etd.address, etd.address);
    PrintAndLogEx(SUCCESS, "Successfully wrote to tag");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("lf em 4x50_read a %u") "` - to read your data", etd.address);
    return PM3_SUCCESS;
}

static void print_write_password_result(PacketResponseNG *resp, const em4x50_data_t *etd) {

    // display result of password changing operation

    char string[NO_CHARS_MAX] = {0}, pstring[NO_CHARS_MAX] = {0};

    sprintf(pstring, "\n  writing new password " _GREEN_("ok"));
    strcat(string, pstring);

    PrintAndLogEx(NORMAL, "%s\n", string);
}

int CmdEM4x50WritePassword(const char *Cmd) {

    // envokes changing the password of EM4x50 tag

    bool errors = false, bpwd = false, bnpwd = false, success = false;
    uint8_t cmdp = 0;
    em4x50_data_t etd;
    PacketResponseNG resp;

    // init
    etd.pwd_given = false;
    etd.newpwd_given = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {

        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_em4x50_write_password();

            case 'p':
                if (param_gethex(Cmd, cmdp + 1, etd.password, 8)) {
                    PrintAndLogEx(FAILED, "\n  password has to be 8 hex symbols\n");
                    return PM3_EINVARG;
                }
                bpwd = true;
                etd.pwd_given = true;
                cmdp += 2;
                break;

            case 'n':
                if (param_gethex(Cmd, cmdp + 1, etd.new_password, 8)) {
                    PrintAndLogEx(FAILED, "\n  password has to be 8 hex symbols\n");
                    return PM3_EINVARG;
                }
                bnpwd = true;
                etd.newpwd_given = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "\n  Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || !bpwd || !bnpwd)
        return usage_lf_em4x50_write_password();

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_WRITE_PASSWORD, (uint8_t *)&etd, sizeof(etd));

    if (!WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }
    success = (bool)resp.status;

    // get, prepare and print response
    if (success)
        print_write_password_result(&resp, &etd);
    else
        PrintAndLogEx(NORMAL, "\nwriting password " _RED_("failed") "\n");

    return (success) ? PM3_SUCCESS : PM3_ESOFT;
}

int em4x50_read(em4x50_data_t *etd, em4x50_word_t *out, bool verbose) {

    // envoke reading
    // - without option -> standard read mode
    // - with given address (option a) (and optional password if address is
    //   read protected) -> selective read mode

    em4x50_data_t edata = { .pwd_given = false, .addr_given = false };

    if (etd != NULL) {
        edata = *etd;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_READ, (uint8_t *)&edata, sizeof(edata));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "(em4x50) timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    bool isOK = (resp.status & STATUS_SUCCESS) >> 1;
    if (isOK == false) {
        if (verbose)
            PrintAndLogEx(FAILED, "reading " _RED_("failed"));

        return PM3_ESOFT;
    }

    if (edata.pwd_given) {
        bool login = resp.status & STATUS_LOGIN;
        if (login == false) {
            PrintAndLogEx(FAILED, "login failed");
            return PM3_ESOFT;
        }
        PrintAndLogEx(SUCCESS, "login with password " _YELLOW_("%s"), sprint_hex_inrow(etd->password, 4));
    }

    uint8_t *data = resp.data.asBytes;
    em4x50_word_t words[EM4X50_NO_WORDS];
    if (edata.addr_given) {
        prepare_result(data, etd->address, etd->address, words);
    } else {
        int now = (resp.status & STATUS_NO_WORDS) >> 2;
        prepare_result(data, 0, now - 1, words);
    }

    if (out != NULL) {
        memcpy(out, &words, sizeof(em4x50_word_t) * EM4X50_NO_WORDS);
    }

    print_result(words, etd->address, etd->address);
    return PM3_SUCCESS;
}

int CmdEM4x50Read(const char *Cmd) {

    em4x50_data_t etd;
    etd.pwd_given = false;
    etd.addr_given = false;
    etd.newpwd_given = false;

    bool errors = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {

        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h': {
                return usage_lf_em4x50_read();
            }
            case 'a': {
                param_getdec(Cmd, cmdp + 1, &etd.address);

                // validation
                if (etd.address <= 0 || etd.address >= EM4X50_NO_WORDS) {
                    PrintAndLogEx(FAILED, "\n  error, address has to be in range [1-33]\n");
                    return PM3_EINVARG;
                }
                etd.addr_given = true;
                cmdp += 2;
                break;
            }
            case 'p': {
                if (param_gethex(Cmd, cmdp + 1, etd.password, 8)) {
                    PrintAndLogEx(FAILED, "\n  password has to be 8 hex symbols\n");
                    return PM3_EINVARG;
                }
                etd.pwd_given = true;
                cmdp += 2;
                break;
            }
            default: {
                PrintAndLogEx(WARNING, "\n  Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
            }
        }
    }

    if (errors || strlen(Cmd) == 0 || etd.addr_given == false)
        return usage_lf_em4x50_read();

    return em4x50_read(&etd, NULL, true);
}

int CmdEM4x50Dump(const char *Cmd) {

    em4x50_data_t etd;
    etd.pwd_given = false;
    etd.addr_given = false;
    etd.newpwd_given = false;

    char filename[FILE_PATH_SIZE] = {0x00};
    char *fptr = filename;

    bool errors = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_em4x50_dump();
                break;
            case 'f':
                param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                cmdp += 2;
                break;
            case 'p': {
                if (param_gethex(Cmd, cmdp + 1, etd.password, 8)) {
                    PrintAndLogEx(FAILED, "\n  password has to be 8 hex symbols\n");
                    return PM3_EINVARG;
                }
                etd.pwd_given = true;
                cmdp += 2;
                break;
            }
            default:
                PrintAndLogEx(WARNING, "  Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        };
    }

    // validation
    if (errors)
        return usage_lf_em4x50_dump();

    PrintAndLogEx(INFO, "reading EM4x50 tag");
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_INFO, (uint8_t *)&etd, sizeof(etd));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    bool success = (resp.status & STATUS_SUCCESS) >> 1;
    if (success == false) {
        PrintAndLogEx(FAILED, "reading tag " _RED_("failed"));
        return PM3_ESOFT;
    }

    // structured format
    em4x50_word_t words[EM4X50_NO_WORDS];
    prepare_result(resp.data.asBytes, 0, EM4X50_NO_WORDS - 1, words);

    PrintAndLogEx(INFO, _YELLOW_("EM4x50 data:"));
    print_result(words, 0, EM4X50_NO_WORDS - 1);

    // user supplied filename?
    if (strlen(filename) == 0) {
        PrintAndLogEx(INFO, "Using UID as filename");
        fptr += sprintf(fptr, "lf-4x50-");
        FillFileNameByUID(fptr, words[EM4X50_DEVICE_SERIAL].byte, "-dump", 4);
    }

    uint8_t data[EM4X50_NO_WORDS * 4] = {0};
    for (int i = 0; i < EM4X50_NO_WORDS; i++) {
        memcpy(data + (i * 4), words[i].byte, 4);
    }

    // saveFileEML will add .eml extension to filename
    // saveFile (binary) passes in the .bin extension.
    saveFileEML(filename, data, sizeof(data), 4);
    saveFile(filename, ".bin", data, sizeof(data));
    //saveFileJSON...
    return PM3_SUCCESS;
}

int CmdEM4x50Wipe(const char *Cmd) {

    // fills EM4x50 tag with zeros including password

    bool errors = false, bpwd = false;
    uint8_t cmdp = 0;
    em4x50_data_t etd;
    PacketResponseNG resp;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {

        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_em4x50_wipe();

            case 'p':
                if (param_gethex(Cmd, cmdp + 1, etd.password, 8)) {
                    PrintAndLogEx(FAILED, "\npassword has to be 8 hex symbols\n");
                    return PM3_EINVARG;
                }
                bpwd = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "\nUnknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || !bpwd)
        return usage_lf_em4x50_wipe();

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_WIPE, (uint8_t *)&etd, sizeof(etd));

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2 * TIMEOUT)) {
        PrintAndLogEx(WARNING, "\ntimeout while waiting for reply.\n");
        return PM3_ETIMEOUT;
    }

    // print response
    bool isOK = resp.status;
    if (isOK) {
        PrintAndLogEx(SUCCESS, "\nwiping data " _GREEN_("ok") "\n");
    } else {
        PrintAndLogEx(FAILED, "\nwiping data " _RED_("failed") "\n");
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}
