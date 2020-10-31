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
#include "util.h"
#include "commonutil.h"
#include "cmdparser.h"
#include "em4x50.h"

static int usage_lf_em4x50_info(void) {
    PrintAndLogEx(NORMAL, "Read all information of EM4x50. Tag must be on antenna.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_info [h] [p <pwd>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       p <pwd>   - password (hex, lsb)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_info"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_info p fa225de1"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_write(void) {
    PrintAndLogEx(NORMAL, "Write EM4x50 word. Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_write [h] b <block> d <data> [p <pwd>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       b <block> - block address to write to (dec)");
    PrintAndLogEx(NORMAL, "       d <data>  - word to write (hex, lsb)");
    PrintAndLogEx(NORMAL, "       p <pwd>   - password (hex, lsb)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_write b 3 d deadc0de"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_write_password(void) {
    PrintAndLogEx(NORMAL, "Write EM4x50 password. Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_write_password [h] p <pwd> n <pwd>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       p <pwd>   - password (hex, lsb)");
    PrintAndLogEx(NORMAL, "       n <pwd>   - new password (hex, lsb)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_write_password p 11223344 n 01020304"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_read(void) {
    PrintAndLogEx(NORMAL, "Read EM4x50 word(s). Tag must be on antenna.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_read [h] b <block> [p <pwd>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       b <block> - block address to read (dec)");
    PrintAndLogEx(NORMAL, "       p <pwd>   - password (hex, lsb)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_read b 32"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_read b 2 p 00000000"));
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
    PrintAndLogEx(NORMAL, "       p <pwd>               - password (hex, lsb)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_dump"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_dump p 11223344"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_dump f card_nnn p 11223344"));
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_wipe(void) {
    PrintAndLogEx(NORMAL, "Wipe data from EM4x50 tag. Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_wipe [h] p <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       p <pwd>   - password (hex, lsb)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_wipe p 11223344"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_brute(void) {
    PrintAndLogEx(NORMAL, "Guess password of EM4x50 tag. Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_brute [h] f <pwd> l <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       f <pwd>   - start password (hex, lsb)");
    PrintAndLogEx(NORMAL, "       l <pwd>   - stop password (hex, lsb)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_brute f 11200000 l 11300000"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_login(void) {
    PrintAndLogEx(NORMAL, "Login into EM4x50 tag. Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_login [h] p <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       p <pwd>   - password (hex, lsb)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_login p 11200000"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_reset(void) {
    PrintAndLogEx(NORMAL, "Reset EM4x50 tag. Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_reset [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_reset"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_watch(void) {
    PrintAndLogEx(NORMAL, "Watch for EM4x50 tag. Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_watch [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_watch"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_restore(void) {
    PrintAndLogEx(NORMAL, "Restore EM4x50 dump to tag. Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_restore [h] [u <UID>] [f <filename>] [p <pwd>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             - this help");
    PrintAndLogEx(NORMAL, "       u <UID>       - uid, try to restore from lf-4x50-<UID>-dump.bin");
    PrintAndLogEx(NORMAL, "       f <filename>  - data filename <filename.bin/eml/json>");
    PrintAndLogEx(NORMAL, "       p <pwd>       - password (hex, lsb)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_restore h"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_restore f em4x50dump.bin"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_restore f em4x50dump.eml p 12345678"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_restore f em4x50dump.json p 00000001"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_sim(void) {
    PrintAndLogEx(NORMAL, "Simulate dump of EM4x50 tag in emulatoe memory. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_sim [h] [f <filename>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             - this help");
    PrintAndLogEx(NORMAL, "       f <filename>  - dump filename (bin/eml/json) for emulator memory upload");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_sim h"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_sim"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_sim f em4x50dump.json"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_stdread(void) {
    PrintAndLogEx(NORMAL, "Show standard read mode data of EM4x50 tag. Tag must be on antenna.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_std_read [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_std_read"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_eload(void) {
    PrintAndLogEx(NORMAL, "Load dump file into emulator memory.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_eload [h] f <filename>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             - this help");
    PrintAndLogEx(NORMAL, "       f <filename>  - dump filename <filename.bin/eml/json>");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_eload f em4x50dump.bin"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_lf_em4x50_esave(void) {
    PrintAndLogEx(NORMAL, "Save emulator memory to file.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_esave [h] [f <filename>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             - this help");
    PrintAndLogEx(NORMAL, "       f <filename>  - dump filename <filename.bin/eml/json>");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_esave"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 4x50_esave f em4x50dump.bin"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int loadFileEM4x50(const char *filename, uint8_t *data, size_t data_len) {

    // read data from dump file; file type is derived from file name extension

    int res = 0;
    size_t bytes_read = 0;
     
    if (str_endswith(filename, ".eml"))
        res = loadFileEML(filename, data, &bytes_read) != PM3_SUCCESS;
    else if (str_endswith(filename, ".json"))
        res = loadFileJSON(filename, data, data_len, &bytes_read, NULL);
    else
        res = loadFile(filename, ".bin", data, data_len, &bytes_read);

    if ((res != PM3_SUCCESS) && (bytes_read != DUMP_FILESIZE))
        return PM3_EFILE;

    return PM3_SUCCESS;
}

static void em4x50_seteml(uint8_t *src, uint32_t offset, uint32_t nobytes) {

    // fast push mode
    conn.block_after_ACK = true;

    for (size_t i = offset; i < nobytes; i += PM3_CMD_DATA_SIZE) {

        size_t len = MIN((nobytes - i), PM3_CMD_DATA_SIZE);
        if (len == nobytes - i) {
            // Disable fast mode on last packet
            conn.block_after_ACK = false;
        }

        clearCommandBuffer();
        SendCommandOLD(CMD_LF_EM4X50_ESET, i, len, 0, src + i, len);
    }
}

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
                etd.password1 = param_get32ex(Cmd, cmdp + 1, 0, 16);
                etd.pwd_given = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
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
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_INFO, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    bool success = (resp.status & STATUS_SUCCESS) >> 1;
    if (success) {
        print_info_result(resp.data.asBytes, verbose);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "Reading tag " _RED_("failed"));
    return PM3_ESOFT;
}

int CmdEM4x50Write(const char *Cmd) {

    // envoke writing a single word (32 bit) to a EM4x50 tag

    em4x50_data_t etd = { .pwd_given = false };

    bool errors = false, bword = false, baddr = false;
    uint8_t address = 0x0;
    uint8_t cmdp = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {

        switch (tolower(param_getchar(Cmd, cmdp))) {

            case 'h':
                return usage_lf_em4x50_write();

            case 'p':
                etd.password1 = param_get32ex(Cmd, cmdp + 1, 0, 16);
                etd.pwd_given = true;
                cmdp += 2;
                break;

            case 'd':
                etd.word = param_get32ex(Cmd, cmdp + 1, 0, 16);
                bword = true;
                cmdp += 2;
                break;

            case 'b':
                param_getdec(Cmd, cmdp + 1, &address);

                // validation
                if (address < 1 || address > 31) {
                    PrintAndLogEx(FAILED, "Error, address has to be in range [1-31]");
                    return PM3_EINVARG;
                }
                etd.addresses = address;    // lwr
                etd.addresses <<= 8;
                etd.addresses |= address;   // fwr
                baddr = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || !bword || !baddr)
        return usage_lf_em4x50_write();

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_WRITE, (uint8_t *)&etd, sizeof(etd));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_WRITE, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_ETEAROFF)
        return PM3_SUCCESS;

    bool isOK = (resp.status & STATUS_SUCCESS) >> 1;
    if (isOK == false) {
        PrintAndLogEx(FAILED, "Writing " _RED_("failed"));
        return PM3_ESOFT;
    }

    if (etd.pwd_given) {
        bool login = resp.status & STATUS_LOGIN;
        if (login == false) {
            PrintAndLogEx(FAILED, "Login failed");
            return PM3_ESOFT;
        }
        PrintAndLogEx(SUCCESS, "Login with password " _YELLOW_("%08x"), etd.password1);
    }

    // display result of writing operation in structured format
    uint8_t *data = resp.data.asBytes;
    em4x50_word_t words[EM4X50_NO_WORDS];

    prepare_result(data, address, address, words);
    print_result(words, address, address);
    PrintAndLogEx(SUCCESS, "Successfully wrote to tag");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("lf em 4x50_read a %u") "` - to read your data", address);
    return PM3_SUCCESS;
}

int CmdEM4x50WritePassword(const char *Cmd) {

    // envokes changing the password of EM4x50 tag

    bool errors = false, bpwd = false, bnpwd = false, success = false;
    uint8_t cmdp = 0;
    em4x50_data_t etd;
    PacketResponseNG resp;

    // init
    etd.pwd_given = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {

        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_em4x50_write_password();

            case 'p':
                etd.password1 = param_get32ex(Cmd, cmdp + 1, 0, 16);
                etd.pwd_given = true;
                bpwd = true;
                cmdp += 2;
                break;

            case 'n':
                etd.password2 = param_get32ex(Cmd, cmdp + 1, 0, 16);
                bnpwd = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || !bpwd || !bnpwd)
        return usage_lf_em4x50_write_password();

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_WRITE_PASSWORD, (uint8_t *)&etd, sizeof(etd));

    if (!WaitForResponseTimeout(CMD_LF_EM4X50_WRITE_PASSWORD, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_ETEAROFF)
        return PM3_SUCCESS;

    success = (bool)resp.status;

    // print response
    if (success)
        PrintAndLogEx(SUCCESS, "Writing new password " _GREEN_("ok"));
    else
        PrintAndLogEx(FAILED, "Writing password " _RED_("failed"));

    return (success) ? PM3_SUCCESS : PM3_ESOFT;
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

    bool isOK = (resp.status & STATUS_SUCCESS) >> 1;
    if (isOK == false)
        return PM3_ESOFT;

    if (edata.pwd_given) {
        bool login = resp.status & STATUS_LOGIN;
        if (login == false) {
            PrintAndLogEx(FAILED, "Login failed");
            return PM3_ESOFT;
        }
        PrintAndLogEx(SUCCESS, "Login with password " _YELLOW_("%08x"), etd->password1);
    }

    uint8_t *data = resp.data.asBytes;
    em4x50_word_t words[EM4X50_NO_WORDS];
    prepare_result(data, etd->addresses & 0xFF, (etd->addresses >> 8) & 0xFF, words);

    if (out != NULL) {
        memcpy(out, &words, sizeof(em4x50_word_t) * EM4X50_NO_WORDS);
    }

    print_result(words, etd->addresses & 0xFF, (etd->addresses >> 8) & 0xFF);

    return PM3_SUCCESS;
}

int CmdEM4x50Read(const char *Cmd) {

    uint8_t address = 0x0;
    em4x50_data_t etd;
    memset(&etd, 0x00, sizeof(em4x50_data_t));

    etd.pwd_given = false;
    etd.addr_given = false;

    bool errors = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {

        switch (tolower(param_getchar(Cmd, cmdp))) {

            case 'h':
                return usage_lf_em4x50_read();

            case 'b': {
                param_getdec(Cmd, cmdp + 1, &address);
                // lsb: byte 1 = fwr, byte 2 = lwr, byte 3 = 0x0, byte 4 = 0x0
                etd.addresses = (address << 8) | address;

                // validation
                if (address <= 0 || address >= EM4X50_NO_WORDS) {
                    PrintAndLogEx(FAILED, "Error, address has to be in range [1-33]");
                    return PM3_EINVARG;
                }
                etd.addr_given = true;
                cmdp += 2;
                break;
            }
            case 'p':
                etd.password1 = param_get32ex(Cmd, cmdp + 1, 0, 16);
                etd.pwd_given = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || strlen(Cmd) == 0 || etd.addr_given == false)
        return usage_lf_em4x50_read();

    return em4x50_read(&etd, NULL);
}

int CmdEM4x50Dump(const char *Cmd) {

    em4x50_data_t etd;
    etd.pwd_given = false;
    etd.addr_given = false;

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

            case 'p':
                etd.password1 = param_get32ex(Cmd, cmdp + 1, 0, 16);
                etd.pwd_given = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        };
    }

    // validation
    if (errors)
        return usage_lf_em4x50_dump();

    PrintAndLogEx(INFO, "Reading EM4x50 tag");
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_INFO, (uint8_t *)&etd, sizeof(etd));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_INFO, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    bool success = (resp.status & STATUS_SUCCESS) >> 1;
    if (success == false) {
        PrintAndLogEx(FAILED, "Reading tag " _RED_("failed"));
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
        FillFileNameByUID(fptr, words[EM4X50_DEVICE_ID].byte, "-dump", 4);
    }

    uint8_t data[EM4X50_NO_WORDS * 4] = {0};
    for (int i = 0; i < EM4X50_NO_WORDS; i++) {
        memcpy(data + (i * 4), words[i].byte, 4);
    }

    // saveFileEML will add .eml extension to filename
    // saveFile (binary) passes in the .bin extension.
    // saveFileJSON adds .json extension
    saveFileEML(filename, data, sizeof(data), 4);
    saveFile(filename, ".bin", data, sizeof(data));
    saveFileJSON(filename, jsfEM4x50, data, sizeof(data), NULL);

    return PM3_SUCCESS;
}

int CmdEM4x50Wipe(const char *Cmd) {

    // fills EM4x50 tag with zeros including password

    bool errors = false, pwd_given = false;
    uint8_t cmdp = 0;
    uint32_t password = 0x0;
    PacketResponseNG resp;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {

        switch (tolower(param_getchar(Cmd, cmdp))) {
 
            case 'h':
                return usage_lf_em4x50_wipe();

            case 'p':
                password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                pwd_given = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || !pwd_given)
        return usage_lf_em4x50_wipe();

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_WIPE, (uint8_t *)&password, sizeof(password));
    WaitForResponse(CMD_LF_EM4X50_WIPE, &resp);
    
    // print response
    bool isOK = resp.status;
    if (isOK) {
        PrintAndLogEx(SUCCESS, "Wiping data " _GREEN_("ok"));
    } else {
        PrintAndLogEx(FAILED, "Wiping data " _RED_("failed"));
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

int CmdEM4x50Brute(const char *Cmd) {

    bool startpwd = false, stoppwd = false, errors = false;
    const int speed = 27;   // 27 passwords/second (empirical value)
    int no_iter = 0, dur_h = 0, dur_m = 0, dur_s = 0;
    uint8_t cmdp = 0;
    em4x50_data_t etd;
    PacketResponseNG resp;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {

        switch (tolower(param_getchar(Cmd, cmdp))) {

            case 'h':
                return usage_lf_em4x50_brute();

            case 'f':
                etd.password1 = param_get32ex(Cmd, cmdp + 1, 0, 16);
                startpwd = true;
                cmdp += 2;
                break;

            case 'l':
                etd.password2 = param_get32ex(Cmd, cmdp + 1, 0, 16);
                stoppwd = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    
    if (errors || !startpwd || !stoppwd)
        return usage_lf_em4x50_brute();

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

int CmdEM4x50Login(const char *Cmd) {

    bool errors = false, pwd_given = false;
    uint8_t cmdp = 0;
    uint32_t password = 0x0;
    PacketResponseNG resp;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {

        switch (tolower(param_getchar(Cmd, cmdp))) {

            case 'h':
                return usage_lf_em4x50_login();

            case 'p':
                password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                pwd_given = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    
    if (errors || !pwd_given)
        return usage_lf_em4x50_login();

    // start
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_LOGIN, (uint8_t *)&password, sizeof(password));
    WaitForResponse(CMD_LF_EM4X50_LOGIN, &resp);

    // print response
    if ((bool)resp.status)
        PrintAndLogEx(SUCCESS, "Login " _GREEN_("ok"));
    else
        PrintAndLogEx(FAILED, "Login " _RED_("failed"));

    return PM3_SUCCESS;
}

int CmdEM4x50Reset(const char *Cmd) {

    bool errors = false;
    uint8_t cmdp = 0;
    PacketResponseNG resp;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {

        switch (tolower(param_getchar(Cmd, cmdp))) {

            case 'h':
                return usage_lf_em4x50_reset();

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    
    if (errors)
        return usage_lf_em4x50_reset();

    // start
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_RESET, 0, 0);
    WaitForResponse(CMD_LF_EM4X50_RESET, &resp);

    // print response
    if ((bool)resp.status)
        PrintAndLogEx(SUCCESS, "Reset " _GREEN_("ok"));
    else
        PrintAndLogEx(FAILED, "Reset " _RED_("failed"));

    return PM3_SUCCESS;
}

int CmdEM4x50Watch(const char *Cmd) {

    // continously envoke reading of a EM4x50 tag

    bool errors = false;
    uint8_t cmdp = 0;
    PacketResponseNG resp;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {

            case 'h':
                return usage_lf_em4x50_watch();

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    // validation
    if (errors)
        return usage_lf_em4x50_watch();

    PrintAndLogEx(SUCCESS, "Watching for EM4x50 cards - place tag on antenna");
    
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_WATCH, 0, 0);
    WaitForResponse(CMD_LF_EM4X50_WATCH, &resp);

    PrintAndLogEx(INFO, "Done");

    return PM3_SUCCESS;
}

int CmdEM4x50Restore(const char *Cmd) {

    size_t fn_len = 0;
    char filename[FILE_PATH_SIZE] = {0};
    char szTemp[FILE_PATH_SIZE - 20] = {0x00};
    em4x50_data_t etd;
    uint8_t *data = calloc(DUMP_FILESIZE, sizeof(uint8_t));

    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    etd.pwd_given = false;

    bool errors = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {

            case 'h':
                return usage_lf_em4x50_restore();
                break;

            case 'u':
                param_getstr(Cmd, cmdp + 1, szTemp, FILE_PATH_SIZE - 20);
                if (filename[0] == 0x00)
                    snprintf(filename, FILE_PATH_SIZE, "./lf-4x50-%s-dump.bin", szTemp);
                cmdp += 2;
                break;

            case 'f':
                fn_len = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                if (fn_len == 0)
                    errors = true;
                cmdp += 2;
                break;

            case 'p':
                etd.password1 = param_get32ex(Cmd, cmdp + 1, 0, 16);
                etd.pwd_given = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        };
    }

    // validation
    if (errors)
        return usage_lf_em4x50_restore();

    PrintAndLogEx(INFO, "Restoring " _YELLOW_("%s")" to card", filename);

    // read data from dump file; file type has to be "bin", "eml" or "json"
    if (loadFileEM4x50(filename, data, DUMP_FILESIZE) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Read error");
        return PM3_EFILE;
    }

    em4x50_seteml(data, 0, DUMP_FILESIZE);
    free(data);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_RESTORE, (uint8_t *)&etd, sizeof(etd));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_RESTORE, &resp, 2 * TIMEOUT)) {
        PrintAndLogEx(FAILED, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_ETEAROFF)
        return PM3_SUCCESS;

    bool isOK = (resp.status & STATUS_SUCCESS) >> 1;
    if (isOK == false) {
        PrintAndLogEx(FAILED, "Restore " _RED_("failed"));
        return PM3_ESOFT;
    }

    if (etd.pwd_given) {
        bool login = resp.status & STATUS_LOGIN;
        if (login == false) {
            PrintAndLogEx(FAILED, "Login failed");
            return PM3_ESOFT;
        }
        PrintAndLogEx(SUCCESS, "Login with password " _YELLOW_("%08x"), etd.password1);
    }
    PrintAndLogEx(SUCCESS, "Restore " _GREEN_("ok"));
    PrintAndLogEx(INFO, "Finished restoring");

    return PM3_SUCCESS;
}

int CmdEM4x50Sim(const char *Cmd) {

    bool errors = false, fn_given = false;
    size_t fn_len = 0;
    uint8_t cmdp = 0;
    char filename[FILE_PATH_SIZE] = {0};
    uint8_t *data = calloc(DUMP_FILESIZE, sizeof(uint8_t));

    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {

            case 'h':
                return usage_lf_em4x50_sim();
                break;

            case 'f':
                fn_len = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                if (fn_len != 0)
                    fn_given = true;
                else
                    errors = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        };
    }

    // validations
    if (errors)
        return usage_lf_em4x50_sim();
    
    // read data from dump file; file type has to be "bin", "eml" or "json"
    if (fn_given) {
        if (loadFileEM4x50(filename, data, DUMP_FILESIZE) != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Read error");
            return PM3_EFILE;
        }

        PrintAndLogEx(INFO, "Uploading dump " _YELLOW_("%s") " to emulator memory", filename);

        em4x50_seteml(data, 0, DUMP_FILESIZE);
        free(data);
    }

    PrintAndLogEx(INFO, "Simulating data in emulator memory " _YELLOW_("%s"), filename);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_SIM, 0, 0);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_EM4X50_SIM, &resp);
    
    if (resp.status == PM3_ETEAROFF)
        return PM3_SUCCESS;

    PrintAndLogEx(INFO, "Done");

    return PM3_SUCCESS;
}

int CmdEM4x50StdRead(const char *Cmd) {

    bool errors = false;
    uint8_t cmdp = 0;
    int now = 0;
    PacketResponseNG resp;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {

        switch (tolower(param_getchar(Cmd, cmdp))) {

            case 'h':
                return usage_lf_em4x50_stdread();

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    
    if (errors)
        return usage_lf_em4x50_stdread();

    // start
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_STDREAD, 0, 0);
    if (!WaitForResponseTimeout(CMD_LF_EM4X50_STDREAD, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    now = resp.status;
    
    // print response
    if (now > 0) {

        em4x50_word_t words[EM4X50_NO_WORDS];
        
        prepare_result(resp.data.asBytes, 0, now - 1, words);

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "  # | word (msb)  | word (lsb)  ");
        PrintAndLogEx(INFO, "----+-------------+-------------");

        for (int i = 0; i < now; i++) {

            char r[30] = {0};
            for (int j = 3; j >= 0; j--)
                sprintf(r + strlen(r), "%02x ", reflect8(words[i].byte[j]));

            PrintAndLogEx(INFO, " %2i | " _GREEN_("%s") "| %s",
                          i,
                          sprint_hex(words[i].byte, 4),
                          r
                          );
        }
        
        PrintAndLogEx(INFO, "----+-------------+-------------");
        PrintAndLogEx(SUCCESS, "Standard read " _GREEN_("ok"));

    } else {
        PrintAndLogEx(FAILED, "Standard read " _RED_("failed"));
    }

    return PM3_SUCCESS;
}

int CmdEM4x50ELoad(const char *Cmd) {

    bool errors = false, fn_given = false;
    size_t nobytes = DUMP_FILESIZE, fn_len = 0;
    uint8_t cmdp = 0;
    char filename[FILE_PATH_SIZE] = {0};
    uint8_t *data = calloc(nobytes, sizeof(uint8_t));

    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {

            case 'h':
                return usage_lf_em4x50_eload();
                break;

            case 'f':
                fn_len = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                if (fn_len != 0)
                    fn_given = true;
                else
                    errors = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        };
    }

    // validations
    if (errors || (fn_given == false))
        return usage_lf_em4x50_eload();
    
    // read data from dump file; file type has to be "bin", "eml" or "json"
    if (loadFileEM4x50(filename, data, DUMP_FILESIZE) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Read error");
        return PM3_EFILE;
    }

    PrintAndLogEx(INFO, "Uploading dump " _YELLOW_("%s") " to emulator memory", filename);
    em4x50_seteml(data, 0, nobytes);
    
    free(data);
    PrintAndLogEx(SUCCESS, "Done");
    return PM3_SUCCESS;
}

int CmdEM4x50ESave(const char *Cmd) {

    bool errors = false;
    size_t nobytes = DUMP_FILESIZE, fn_len = 0;
    uint8_t cmdp = 0;
    char filename[FILE_PATH_SIZE] = {0};
    char *fptr = filename;
    uint8_t *data = calloc(nobytes, sizeof(uint8_t));

    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {

            case 'h':
                return usage_lf_em4x50_esave();
                break;

            case 'f':
                fn_len = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                if (fn_len == 0)
                    errors = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        };
    }

    // validations
    if (errors)
        return usage_lf_em4x50_esave();
    
    // download emulator memory
    PrintAndLogEx(SUCCESS, "Reading emulator memory...");
    if (!GetFromDevice(BIG_BUF_EML, data, nobytes, 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(data);
        return PM3_ETIMEOUT;
    }
    
    // user supplied filename?
    if (fn_len == 0) {
        PrintAndLogEx(INFO, "Using UID as filename");
        fptr += snprintf(fptr, sizeof(filename), "lf-4x50-");
        FillFileNameByUID(fptr, (uint8_t *)&data[4 * EM4X50_DEVICE_ID], "-dump", 4);
    }

    PrintAndLogEx(INFO, "Uploading dump " _YELLOW_("%s") " to emulator memory", filename);
    em4x50_seteml(data, 0, nobytes);
    
    saveFile(filename, ".bin", data, nobytes);
    saveFileEML(filename, data, nobytes, 4);
    saveFileJSON(filename, jsfEM4x50, data, nobytes, NULL);
    return PM3_SUCCESS;
}
