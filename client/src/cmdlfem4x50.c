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

#define EM4X50_NO_WORDS             34

// special words
#define EM4X50_DEVICE_PASSWORD      0
#define EM4X50_PROTECTION           1
#define EM4X50_CONTROL        2
#define EM4X50_DEVICE_SERIAL        32
#define EM4X50_DEVICE_ID            33

// control word (word = 4 bytes)
#define FIRST_WORD_READ             0       // first byte
#define LAST_WORD_READ              1       // second byte
#define CONFIG_BLOCK                2       // third byte
#define PASSWORD_CHECK              0x80    // first bit in third byte
#define READ_AFTER_WRITE            0x40    // second bit in third byte

// protection word
#define FIRST_WORD_READ_PROTECTED   0       // first byte
#define LAST_WORD_READ_PROTECTED    1       // second byte
#define FIRST_WORD_WRITE_INHIBITED  2       // third byte
#define LAST_WORD_WRITE_INHIBITED   3       // fourth byte

// misc
#define STATUS_SUCCESS              0x2
#define STATUS_LOGIN                0x1
#define NO_CHARS_MAX                400

int usage_lf_em4x50_info(void) {
    PrintAndLogEx(NORMAL, "Read all information of EM4x50. Tag nust be on antenna.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_info [h] [v] [p <pwd>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       v         - verbose output");
    PrintAndLogEx(NORMAL, "       p <pwd>   - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x50_info");
    PrintAndLogEx(NORMAL, "      lf em 4x50_info p fa225de1\n");
    PrintAndLogEx(NORMAL, "      lf em 4x50_info v p fa225de1\n");
    return PM3_SUCCESS;
}
int usage_lf_em4x50_write(void) {
    PrintAndLogEx(NORMAL, "Write EM4x50 word. Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_write [h] a <address> w <data>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       a <addr>  - memory address to write to (dec)");
    PrintAndLogEx(NORMAL, "       w <word>  - word to write (hex)");
    PrintAndLogEx(NORMAL, "       p <pwd>   - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x50_write a 3 w deadc0de");
    return PM3_SUCCESS;
}
int usage_lf_em4x50_write_password(void) {
    PrintAndLogEx(NORMAL, "Write EM4x50 password. Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_write_password [h] p <pwd> n <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       p <pwd>   - password (hex)");
    PrintAndLogEx(NORMAL, "       n <pwd>   - new password (hex)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x50_write_password p 11223344 n 01020304");
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
            words[i].byte[j] = byte[i*7+j];
            words[i].row_parity[j] = (byte[i*7+4] >> (3-j)) & 1;
            
            // collect parities
            p = 0;

            for (int k = 0; k < 8; k++) {
               
                // row parity
                p ^= (words[i].byte[j] >> k) & 1;
                
                // column parity
                c[k] ^= (words[i].byte[j] >> (7-k)) & 1;
            }
            
            // check row parities
            words[i].rparity[j] = (words[i].row_parity[j] == p) ? true : false;

            if (!words[i].rparity[j])
                words[i].parity = false;
        }
        
        // check column parities
        words[i].col_parity = byte[i*7+5] ;
        
        for (int j = 0; j < 8; j++) {
            words[i].cparity[j] = (((words[i].col_parity >> (7-j)) & 1) == c[j]) ? true : false;

            if (!words[i].cparity[j])
                words[i].parity = false;
        }

        // check stop bit
        words[i].stopbit = byte[i*7+6] & 1;
        
        if (words[i].stopbit == 1)
            words[i].stopparity = false;
        
    }
}

static void print_bit_table(const em4x50_word_t word) {
    
    // generate output in table form for each word including parities, stop
    // bit, result of parity checks and hex notation of each row in msb/lsb
    // notation
    // individual parity errors will be highlighted in red
        
    int bit = 0;
    char string[NO_CHARS_MAX] = {0}, pstring[NO_CHARS_MAX] = {0};

    // print binary data
    for (int j = 0; j < 4; j++) {
        
        strcat(string, "  ");

        // lsb notation
        for (int k = 0; k < 8; k++) {
            sprintf(pstring, "%i", (word.byte[j] >> (7-k)) & 1);
            strcat(string, pstring);
        }

        strcat(string, " | ");

        // binary row parities + hex bytes of word
        sprintf(pstring, (word.rparity[j]) ? "%i" : _RED_("%i"), word.row_parity[j]);
        strcat(string, pstring);
        
        if (j == 0)
            sprintf(pstring, "  msb: 0x%02x  lsb: 0x%02x", word.byte[j], reflect8(word.byte[j]));
        else
            sprintf(pstring, "       0x%02x       0x%02x", word.byte[j], reflect8(word.byte[j]));
        
        strcat(string, pstring);
        PrintAndLogEx(NORMAL,string);

        string[0] = '\0';
    }

    strcat(string, "  ------------  --------------------\n  ");

    // binary column parities
    for (int k = 0; k < 8; k++) {
        
        bit = (word.col_parity >> (7-k)) & 1;
        
        // if column parity is false -> highlight bit in red
        sprintf(pstring, (word.cparity[k]) ? "%i" : _RED_("%i"), bit);
        strcat(string, pstring);
    }

    // binary stop bit
    strcat(string, " | ");
    sprintf(pstring, (word.stopparity) ? "%i" : _RED_("%i"), word.stopbit);
    strcat(pstring, "  parities ");
    strcat(string, pstring);
    
    // parities passed/failed
    sprintf(pstring, (word.parity) ? _GREEN_("ok") : _RED_("failed"));
    strcat(string, pstring);

    PrintAndLogEx(NORMAL,string);
   
    string[0] = '\0';
}

static void print_result(const em4x50_word_t *words,  int fwr,  int lwr) {
    
    // print available information for given word from fwr to lwr, i.e.
    // bit table + summary lines with hex notation of word (msb + lsb)
    
    char string[NO_CHARS_MAX] = {0}, pstring[NO_CHARS_MAX] = {0};

    for (int i = fwr; i <= lwr; i++) {

        // blank line before each bit table
        PrintAndLogEx(NORMAL, "");

        // print bit table
        print_bit_table(words[i]);
         
        // final result
        sprintf(pstring, "\n  word[%i] msb: " _GREEN_("0x"), i);
        strcat(string, pstring);

        for (int j = 0; j < 4; j++) {
            sprintf(pstring, _GREEN_("%02x"), words[i].byte[j]);
            strcat(string, pstring);
        }
        
        sprintf(pstring, "\n  word[%i] lsb: 0x", i);
        strcat(string, pstring);

        for (int j = 0; j < 4; j++) {
            sprintf(pstring, "%02x", reflect8(words[i].byte[3-j]));
            strcat(string, pstring);
        }
        
        PrintAndLogEx(NORMAL,string);

        string[0] = '\0';
    }
}

static void print_info_result(PacketResponseNG *resp, const em4x50_data_t *etd, bool bverbose) {

    // display all information of info result in structured format

    uint8_t *data = resp->data.asBytes;
    em4x50_word_t words[EM4X50_NO_WORDS];
    char pstring[NO_CHARS_MAX] = {0}, string[NO_CHARS_MAX] = {0};

    bool bpwd_given = etd->pwd_given;
    bool bsuccess = resp->status & STATUS_SUCCESS;
    bool blogin = resp->status & STATUS_LOGIN;

    prepare_result(data, 0, EM4X50_NO_WORDS - 1, words);

    bool bpwc = words[EM4X50_CONTROL].byte[CONFIG_BLOCK] & PASSWORD_CHECK;
    bool braw = words[EM4X50_CONTROL].byte[CONFIG_BLOCK] & READ_AFTER_WRITE;
    int fwr = reflect8(words[EM4X50_CONTROL].byte[FIRST_WORD_READ]);
    int lwr = reflect8(words[EM4X50_CONTROL].byte[LAST_WORD_READ]);
    int fwrp = reflect8(words[EM4X50_PROTECTION].byte[FIRST_WORD_READ_PROTECTED]);
    int lwrp = reflect8(words[EM4X50_PROTECTION].byte[LAST_WORD_READ_PROTECTED]);
    int fwwi = reflect8(words[EM4X50_PROTECTION].byte[FIRST_WORD_WRITE_INHIBITED]);
    int lwwi = reflect8(words[EM4X50_PROTECTION].byte[LAST_WORD_WRITE_INHIBITED]);
    
    // data section
    PrintAndLogEx(NORMAL, _YELLOW_("\n  em4x50 data:"));

    if (bverbose) {

        // detailed data section
        print_result(words, 0, EM4X50_NO_WORDS - 1);
        
    } else {

        // condensed data section
        for (int i = 0; i < EM4X50_NO_WORDS; i++) {
     
            sprintf(pstring, "  word[%2i]:  ", i);
            strcat(string, pstring);

            for (int j = 0; j < 4; j++) {
                sprintf(pstring, "%02x", words[i].byte[j]);
                strcat(string, pstring);
            }
            
            switch(i) {
                case EM4X50_DEVICE_PASSWORD:
                    sprintf(pstring, _YELLOW_("  password, write only"));
                    break;
                case EM4X50_PROTECTION:
                    sprintf(pstring, _YELLOW_("  protection word, write inhibited"));
                    break;
                case EM4X50_CONTROL:
                    sprintf(pstring, _YELLOW_("  control word, write inhibited"));
                    break;
                case EM4X50_DEVICE_SERIAL:
                    sprintf(pstring, _YELLOW_("  device serial number, read only"));
                    break;
                case EM4X50_DEVICE_ID:
                    sprintf(pstring, _YELLOW_("  device identification, read only"));
                    break;
                default:
                    sprintf(pstring, "  user data");
                    break;
            }

            strcat(string, pstring);
            PrintAndLogEx(NORMAL,"%s", string);
            string[0] = '\0';
        }
    }
    
    // configuration section
    PrintAndLogEx(NORMAL, _YELLOW_("\n  em4x50 configuration"));
    PrintAndLogEx(NORMAL,"  control:                 |  protection:");

    sprintf(pstring, "    first word read:  %3i  |", fwr);
    strcat(string, pstring);
    sprintf(pstring, "    first word read protected:  %3i", fwrp);
    strcat(string, pstring);
    PrintAndLogEx(NORMAL,"%s", string);
    string[0] = '\0';

    sprintf(pstring, "    last word read:   %3i  |", lwr);
    strcat(string, pstring);
    sprintf(pstring, "    last word read protected:   %3i", lwrp);
    strcat(string, pstring);
    PrintAndLogEx(NORMAL,"%s", string);
    string[0] = '\0';

    sprintf(pstring, "    password check:   %3s  |", (bpwc) ? "on" : "off");
    strcat(string, pstring);
    sprintf(pstring, "    first word write inhibited: %3i", fwwi);
    strcat(string, pstring);
    PrintAndLogEx(NORMAL,"%s", string);
    string[0] = '\0';

    sprintf(pstring, "    read after write: %3s  |", (braw) ? "on" : "off");
    strcat(string, pstring);
    sprintf(pstring, "    last word write inhibited:  %3i", lwwi);
    strcat(string, pstring);
    PrintAndLogEx(NORMAL,"%s", string);
    string[0] = '\0';

    PrintAndLogEx(NORMAL, "\n  zero values may indicate read protection!");
    
    // status line
    sprintf(pstring, "  reading ");
    strcat(string, pstring);

    if (!bsuccess) {
        
        sprintf(pstring, _RED_("failed"));
        strcat(string, pstring);

    } else {
            
        sprintf(pstring, _GREEN_("ok "));
        strcat(string, pstring);

        if (blogin) {

            if (bpwd_given) {

                sprintf(pstring, "(login with password 0x%02x%02x%02x%02x)",
                                    etd->password[0], etd->password[1],
                                    etd->password[2], etd->password[3]);
                strcat(string, pstring);
            
            } else {

                sprintf(pstring, "(login with default password 0x00000000)");
                strcat(string, pstring);

            }

        } else {

            if (bpwd_given) {

                sprintf(pstring, "(login failed)");
                strcat(string, pstring);
            
            } else {

                sprintf(pstring, "(no login)");
                strcat(string, pstring);

            }
        }

    }

    PrintAndLogEx(NORMAL,"%s\n", string);
}

int CmdEM4x50Info(const char *Cmd) {

    // envoke reading of a EM4x50 tag which has to be on the antenna because
    // decoding is done by the device (not on client side)

    bool errors = false, verbose = false, success = false;
    uint8_t cmdp = 0;
    em4x50_data_t etd;
    PacketResponseNG resp;

    // init
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

    // call info command
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_INFO, (uint8_t *)&etd, sizeof(etd));


    // get result
    if (!WaitForResponse(CMD_ACK, &resp)) {
        PrintAndLogEx(WARNING, "  timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }
    
    // print result
    print_info_result(&resp, &etd, verbose);
    
    success = resp.status & STATUS_SUCCESS;
    return (success) ? PM3_SUCCESS : PM3_ESOFT;
}

static void print_write_result(PacketResponseNG *resp, const em4x50_data_t *etd) {
    
    // display result of writing operation in structured format

    bool pwd_given = etd->pwd_given;
    bool success = resp->status & STATUS_SUCCESS;
    bool login = resp->status & STATUS_LOGIN;
    uint8_t *data = resp->data.asBytes;
    char string[NO_CHARS_MAX] = {0}, pstring[NO_CHARS_MAX] = {0};
    em4x50_word_t word;

    if (!success) {
        
        sprintf(pstring, "\n  writing " _RED_("failed"));
        strcat(string, pstring);

    } else {
            
        prepare_result(data, etd->address, etd->address, &word);
        print_result(&word, etd->address, etd->address);

        sprintf(pstring, "\n  writing " _GREEN_("ok "));
        strcat(string, pstring);

        if (pwd_given) {

            if (login) {
                sprintf(pstring, "(login with password 0x%02x%02x%02x%02x)",
                                    etd->password[0], etd->password[1],
                                    etd->password[2], etd->password[3]);
                strcat(string, pstring);
            } else {
                sprintf(pstring, "(login failed)");
                strcat(string, pstring);
            }

        } else {
            sprintf(pstring, "(no login)");
            strcat(string, pstring);
        }
    }

    PrintAndLogEx(NORMAL,"%s\n", string);
}

int CmdEM4x50Write(const char *Cmd) {

    // envoke writing a single word (32 bit) to a EM4x50 tag

    bool errors = false, bword = false, baddr = false, success = false;
    uint8_t cmdp = 0;
    em4x50_data_t etd;
    PacketResponseNG resp;

    // init
    etd.pwd_given = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {

        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_em4x50_write();

            case 'p':
                if (param_gethex(Cmd, cmdp + 1, etd.password, 8)) {
                     PrintAndLogEx(FAILED, "\n  password has to be 8 hex symbols\n");
                     return PM3_EINVARG;
                 }
                etd.pwd_given = true;
                cmdp += 2;
                break;

            case 'w':
                if (param_gethex(Cmd, cmdp + 1, etd.word, 8)) {
                     PrintAndLogEx(FAILED, "\n  word has to be 8 hex symbols\n");
                     return PM3_EINVARG;
                }
                bword = true;
                cmdp += 2;
                break;

            case 'a':
                param_getdec(Cmd, cmdp + 1, &etd.address);

                // validation
                if (etd.address < 1 || etd.address > 31) {
                    PrintAndLogEx(FAILED, "\n  error, address has to be in range [1-31]\n");
                    return PM3_EINVARG;
                }
                baddr = true;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "\n  Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || !bword || !baddr)
         return usage_lf_em4x50_write();

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X50_WRITE, (uint8_t *)&etd, sizeof(etd));


    if (!WaitForResponse(CMD_ACK, &resp)) {
        PrintAndLogEx(WARNING, "\n  timeout while waiting for reply.\n");
        return PM3_ETIMEOUT;
    }
    
    // get, prepare and print response
    print_write_result(&resp, &etd);
    
    success = resp.status & STATUS_SUCCESS;
    return (success) ? PM3_SUCCESS : PM3_ESOFT;
}

static void print_write_password_result(PacketResponseNG *resp, const em4x50_data_t *etd) {
    
    // display result of password changing operation

    bool success = resp->status;
    char string[NO_CHARS_MAX] = {0}, pstring[NO_CHARS_MAX] = {0};

    if (!success) {
        
        sprintf(pstring, "\n  writing new password " _RED_("failed"));
        strcat(string, pstring);

    } else {
        
        sprintf(pstring, "\n  writing new password " _GREEN_("ok"));
        strcat(string, pstring);
    }

    PrintAndLogEx(NORMAL,"%s\n", string);
}

int CmdEM4x50WritePassword(const char *Cmd) {

    // envokes changing the password of EM4x50 tag

    bool errors = false, bpwd = false, bnpwd = false;
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

    if (!WaitForResponse(CMD_ACK, &resp)) {
        PrintAndLogEx(WARNING, "\n  timeout while waiting for reply.\n");
        return PM3_ETIMEOUT;
    }
    
    // get, prepare and print response
    print_write_password_result(&resp, &etd);
    
    return ((bool)resp.status) ? PM3_SUCCESS : PM3_ESOFT;
}
