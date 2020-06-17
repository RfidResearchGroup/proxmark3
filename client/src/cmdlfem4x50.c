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
#include "em4x50.h"

#define EM4x50_FCT_STDREAD  0
#define EM4x50_FCT_LOGIN    1
#define EM4x50_FCT_WRITE    2

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

static uint8_t msb2lsb(uint8_t byte) {

    // convert given byte (msb) into lsb format
    
    uint8_t tmp = 0;
    
    for (int i = 0; i < 8; i++)
        tmp |= ((byte >> (7-i)) & 1) << i;
    
    return tmp;
}

static bool check_bit_in_byte(uint8_t pos, uint8_t byte) {
    
    // return true if bit at position <pos> is "1"
    
    return (((byte >> pos) & 1) == 1) ? true : false;
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
    char string[400] = {0};
    char pstring[100] = {0};

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
            sprintf(pstring, "  msb: 0x%02x  lsb: 0x%02x", word.byte[j], msb2lsb(word.byte[j]));
        else
            sprintf(pstring, "       0x%02x       0x%02x", word.byte[j], msb2lsb(word.byte[j]));
        
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
    sprintf(pstring, (word.parity) ? _GREEN_("passed") : _RED_("failed"));
    strcat(string, pstring);

    PrintAndLogEx(NORMAL,string);
   
    string[0] = '\0';
}

static void print_result(const em4x50_word_t *words,  int fwr,  int lwr) {
    
    // print available information for given word from fwr to lwr, i.e.
    // bit table + summary lines with hex notation of word (msb + lsb)
    
    char string[400] = {0};
    char pstring[100] = {0};

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
        
        sprintf(pstring, "\n  word[%i] lsb: " _GREEN_("0x"), i);
        strcat(string, pstring);

        for (int j = 0; j < 4; j++) {
            sprintf(pstring, _GREEN_("%02x"), msb2lsb(words[i].byte[3-j]));
            strcat(string, pstring);
        }
        
        PrintAndLogEx(NORMAL,string);

        string[0] = '\0';
    }
}

static void print_info_result(PacketResponseNG *resp, const em4x50_data_t *etd, bool bverbose) {

    // display all information info result in structured format
    
    bool bpwd_given = etd->pwd_given;
    bool bsuccess = (bool)resp->oldarg[0];
    bool blogin = (bool)resp->oldarg[1];
    bool bpwc, braw;
    int fwr, lwr, fwrp, lwrp, fwwi, lwwi;
    uint8_t *data = resp->data.asBytes;
    em4x50_word_t words[34];
    char pstring[100] = {0};
    char string[200] = {0};

    prepare_result(data, 0, 33, words);

    bpwc = check_bit_in_byte(7, words[2].byte[2]);   // password check
    braw = check_bit_in_byte(6, words[2].byte[2]);   // read after write
    fwr = msb2lsb(words[2].byte[0]);    // first word read
    lwr = msb2lsb(words[2].byte[1]);    // last word read
    fwrp = msb2lsb(words[1].byte[0]);   // first word read protected
    lwrp = msb2lsb(words[1].byte[1]);   // last word read protected
    fwwi = msb2lsb(words[1].byte[2]);   // first word write inhibited
    lwwi = msb2lsb(words[1].byte[3]);   // last word write inhibited
    
    // data section
    PrintAndLogEx(NORMAL, _YELLOW_("\n  em4x50 data:"));

    if (bverbose) {

        // detailed data section
        print_result(words, 0, 33);
        
    } else {

        // condensed data section
        for (int i = 0; i <= 33; i++) {
     
            sprintf(pstring, "  word[%2i]:  ", i);
            strcat(string, pstring);

            for (int j = 0; j < 4; j++) {
                sprintf(pstring, "%02x", words[i].byte[j]);
                strcat(string, pstring);
            }
            
            switch(i) {
                case 0:
                    sprintf(pstring, _YELLOW_("  password, write only"));
                    break;
                case 1:
                    sprintf(pstring, _YELLOW_("  protection word, write inhibited"));
                    break;
                case 2:
                    sprintf(pstring, _YELLOW_("  control word, write inhibited"));
                    break;
                case 32:
                    sprintf(pstring, _YELLOW_("  device serial number, read only"));
                    break;
                case 33:
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
            
        sprintf(pstring, _GREEN_("successful "));
        strcat(string, pstring);

        if (blogin) {

            if (bpwd_given) {

                sprintf(pstring, "(login with 0x%02x%02x%02x%02x)",
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

    bool errors = false, verbose = false;
    char password[20] = {0x00}, tmpbuff[3];
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
                param_getstr(Cmd, cmdp + 1, password, sizeof(password));
                
                // validation
                if (strlen(password) != 8) {
    
                    PrintAndLogEx(WARNING, "\n  error, password has to be 4 bytes\n");
                    errors = true;
                    break;
                }
                
                // prepare given password
                etd.pwd_given = true;
                for (int i = 0; i < 4; i++)
                    sscanf(strncpy(tmpbuff, password+2*i, 2), "%2hhx", &etd.password[i]);
                    
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
     if (errors) {
         return usage_lf_em4x50_info();
    }

    // call info command
    clearCommandBuffer();
    SendCommandMIX(CMD_LF_EM4X50_INFO, 0, 0, 0, &etd, sizeof(etd));

    // get result
    if (!WaitForResponse(CMD_ACK, &resp)) {
        PrintAndLogEx(WARNING, "  timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }
    
    // prepare result
    print_info_result(&resp, &etd, verbose);

    return ((bool)resp.oldarg[0]) ? PM3_SUCCESS : PM3_ESOFT;
}

static void print_write_result(PacketResponseNG *resp, const em4x50_data_t *etd) {
    
    // display result of writing operation in structured format

    bool pwd_given = etd->pwd_given;
    bool success = (bool)resp->oldarg[0];
    bool login = (bool)resp->oldarg[1];
    uint8_t *data = resp->data.asBytes;
    char string[400] = {0};
    char pstring[100] = {0};
    em4x50_word_t word[1];

    if (!success) {
        
        sprintf(pstring, "\n  writing " _RED_("failed"));
        strcat(string, pstring);

    } else {
            
        prepare_result(data, etd->address, etd->address, &word[0]);
        print_result(word, etd->address, etd->address);

        sprintf(pstring, "\n  writing " _GREEN_("successful "));
        strcat(string, pstring);

        if (pwd_given) {

            if (login) {
                sprintf(pstring, "(login with 0x%02x%02x%02x%02x)",
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

    bool errors = false, baddress = false, bword = false;
    char password[20] = {0x00}, word[20] = {0x00}, tmpbuff[3];
    int address = 0;
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
                param_getstr(Cmd, cmdp + 1, password, sizeof(password));
              
                // validation
                if (strlen(password) != 8) {
                    PrintAndLogEx(WARNING, "\n  error, password has to be 4 bytes\n");
                    errors = true;
                    break;
                }
              
                // prepare given password
                etd.pwd_given = true;
                for (int i = 0; i < 4; i++)
                    sscanf(strncpy(tmpbuff, password+2*i, 2), "%2hhx", &etd.password[i]);
                  
                cmdp += 2;
                break;

            case 'w':
                param_getstr(Cmd, cmdp + 1, word, sizeof(word));
              
                // validation
                if (strlen(word) != 8) {
                    PrintAndLogEx(WARNING, "\n  error, word has to be 4 bytes\n");
                    errors = true;
                    break;
                } else {
                    bword = true;
                }
              
                // prepare given word
                for (int i = 0; i < 4; i++)
                    sscanf(strncpy(tmpbuff, word+2*i, 2), "%2hhx", &etd.word[i]);
                  
                cmdp += 2;
                break;

            case 'a':
                param_getstr(Cmd, cmdp + 1, tmpbuff, sizeof(address));
                address = atoi(tmpbuff);
                
                // validation
                if (address < 1 || address > 31) {
                    PrintAndLogEx(WARNING, "\n  error, address has to be in range [1-31]\n");
                    errors = true;
                    break;
                } else {
                    baddress = true;
                }

                etd.address = address;

                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "\n  Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || !baddress || !bword)
         return usage_lf_em4x50_write();

    clearCommandBuffer();
    SendCommandMIX(CMD_LF_EM4X50_WRITE, 0, 0, 0, &etd, sizeof(etd));

    if (!WaitForResponse(CMD_ACK, &resp)) {
        PrintAndLogEx(WARNING, "\n  timeout while waiting for reply.\n");
        return PM3_ETIMEOUT;
    }
    
    // get, prepare and print response
    print_write_result(&resp, &etd);
    
    return ((bool)resp.oldarg[0]) ? PM3_SUCCESS : PM3_ESOFT;
}

static void print_write_password_result(PacketResponseNG *resp, const em4x50_data_t *etd) {
    
    // display result of password changing operation

    bool success = (bool)resp->oldarg[0];
    char string[400] = {0};
    char pstring[100] = {0};

    if (!success) {
        
        sprintf(pstring, "\n  writing new password " _RED_("failed"));
        strcat(string, pstring);

    } else {
        
        sprintf(pstring, "\n  writing new password " _GREEN_("successful"));
        strcat(string, pstring);
    }

    PrintAndLogEx(NORMAL,"%s\n", string);
}

int CmdEM4x50WritePassword(const char *Cmd) {

    // envokes changing the password of EM4x50 tag

    bool errors = false, bpwd = false, bnewpwd = false;
    char password[20] = {0x00}, new_password[20] = {0x00}, tmpbuff[3];
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
                param_getstr(Cmd, cmdp + 1, password, sizeof(password));
              
                // validation
                if (strlen(password) != 8) {
                    PrintAndLogEx(WARNING, "\n  error, passwords has to be 4 bytes\n");
                    errors = true;
                    break;
                } else {
                    bpwd = true;
                }
              
                // prepare given password
                etd.pwd_given = true;
                for (int i = 0; i < 4; i++)
                    sscanf(strncpy(tmpbuff, password+2*i, 2), "%2hhx", &etd.password[i]);
                  
                cmdp += 2;
                break;

            case 'n':
                param_getstr(Cmd, cmdp + 1, new_password, sizeof(new_password));
              
                // validation
                if (strlen(new_password) != 8) {
                    PrintAndLogEx(WARNING, "\n  error, passwords have to be 4 bytes\n");
                    errors = true;
                    break;
                } else {
                    bnewpwd = true;
                }
              
                // prepare given password
                etd.newpwd_given = true;
                for (int i = 0; i < 4; i++)
                    sscanf(strncpy(tmpbuff, new_password+2*i, 2), "%2hhx", &etd.new_password[i]);
                  
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "\n  Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || !bpwd || !bnewpwd)
         return usage_lf_em4x50_write_password();

    clearCommandBuffer();
    SendCommandMIX(CMD_LF_EM4X50_WRITE_PASSWORD, 0, 0, 0, &etd, sizeof(etd));

    if (!WaitForResponse(CMD_ACK, &resp)) {
        PrintAndLogEx(WARNING, "\n  timeout while waiting for reply.\n");
        return PM3_ETIMEOUT;
    }
    
    // get, prepare and print response
    print_write_password_result(&resp, &etd);
    
    return ((bool)resp.oldarg[0]) ? PM3_SUCCESS : PM3_ESOFT;
}
