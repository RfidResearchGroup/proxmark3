//-----------------------------------------------------------------------------
// Copyright (C) 2012 Roel Verdult
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Hitag support
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proxmark3.h"
#include "ui.h"
#include "cmdparser.h"
#include "common.h"
#include "util.h"
#include "parity.h"
#include "hitag.h"
#include "util_posix.h"
#include "comms.h"
#include "cmddata.h"
#include "loclass/fileutils.h"  // savefile

static int CmdHelp(const char *Cmd);

size_t nbytes(size_t nbits) {
    return (nbits / 8) + ((nbits % 8) > 0);
}
int usage_hitag_sniff(void) {
    PrintAndLogEx(NORMAL, "Sniff traffic between Hitag reader and tag. Use " _YELLOW_("`lf hitag list`")" to view collected data.");
    PrintAndLogEx(NORMAL, "Usage:   lf hitag sniff [h] ");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             This help");
//    PrintAndLogEx(NORMAL, "       p <pwd>       Password");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         lf hitag sniff");
    return 0;
}
int usage_hitag_sim(void) {
    PrintAndLogEx(NORMAL, "Simulate " _YELLOW_("Hitag2 / HitagS")" transponder");
    PrintAndLogEx(NORMAL, "Usage:   lf hitag sim [h] [2|s] e|j|b <filename w/o extension>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             This help");
    PrintAndLogEx(NORMAL, "       [2|s]         2 = hitag2,  s = hitagS");
    PrintAndLogEx(NORMAL, "       e <filename>  Load data from EML file");
    PrintAndLogEx(NORMAL, "       j <filename>  Load data from JSON file");
    PrintAndLogEx(NORMAL, "       b <filename>  Load data from BIN file");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         lf hitag sim 2 b lf-hitag-dump");
    return 0;
}
int usage_hitag_info(void) {
    PrintAndLogEx(NORMAL, "Usage:   lf hitag info [h] p <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h          This help");
    PrintAndLogEx(NORMAL, "       p <pwd>    password");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         lf hitag info");
    return 0;
}
int usage_hitag_dump(void) {
    PrintAndLogEx(NORMAL, "Usage:   lf hitag dump [h] p <pwd> f <name>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h          This help");
//    PrintAndLogEx(NORMAL, "       p <pwd>    password");
//    PrintAndLogEx(NORMAL, "       f <name>   data filename, if no <name> given, UID will be used as filename");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         lf hitag dump f mydump");
    PrintAndLogEx(NORMAL, "         lf hitag dump p 4D494B52 f mydump");
    return 0;
}
int usage_hitag_reader(void) {
    PrintAndLogEx(NORMAL, "Hitag reader functions");
    PrintAndLogEx(NORMAL, "Usage: lf hitag reader [h] <reader function #>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h               This help");
    PrintAndLogEx(NORMAL, "   HitagS (0*)");
    PrintAndLogEx(NORMAL, "      01 <nr> <ar>     Challenge, read all pages from a Hitag S tag");
    PrintAndLogEx(NORMAL, "      02 <key>         Set to 0 if no authentication is needed. Read all pages from a Hitag S tag");
    PrintAndLogEx(NORMAL, "   Hitag1 (1*)");
    PrintAndLogEx(NORMAL, "   Hitag2 (2*)");
    PrintAndLogEx(NORMAL, "      21 <password>    Password mode");
    PrintAndLogEx(NORMAL, "      22 <nr> <ar>     Authentication");
    PrintAndLogEx(NORMAL, "      23 <key>         Authentication, key is in format: ISK high + ISK low");
    PrintAndLogEx(NORMAL, "      25               Test recorded authentications");
    PrintAndLogEx(NORMAL, "      26               Just read UID");
    return 0;
}
int usage_hitag_writer(void) {
    PrintAndLogEx(NORMAL, "Hitag writer functions");
    PrintAndLogEx(NORMAL, "Usage: lf hitag write [h] <reader function #>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h          This help");
    PrintAndLogEx(NORMAL, "   HitagS (0*)");
    PrintAndLogEx(NORMAL, "      03 <nr,ar> (Challenge) <page> <byte0...byte3> write page on a Hitag S tag");
    PrintAndLogEx(NORMAL, "      04 <key> (set to 0 if no authentication is needed) <page> <byte0...byte3> write page on a Hitag S tag");
    PrintAndLogEx(NORMAL, "   Hitag1 (1*)");
    PrintAndLogEx(NORMAL, "   Hitag2 (2*)");
    PrintAndLogEx(NORMAL, "      24  <key> (set to 0 if no authentication is needed) <page> <byte0...byte3> write page on a Hitag2 tag");
    return 0;
}
int usage_hitag_checkchallenges(void) {
    PrintAndLogEx(NORMAL, "Check challenges, load a file with save hitag crypto challenges and test them all.");
    PrintAndLogEx(NORMAL, "The file should be 8 * 60 bytes long,  the file extension defaults to " _YELLOW_("`.cc`"));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:   lf hitag cc [h] f <filename w/o extension>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h              This help");
    PrintAndLogEx(NORMAL, "       f <filename>   Load data from BIN file");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         lf hitag cc f lf-hitag-challenges");
    return 0;
}

int CmdLFHitagList(const char *Cmd) {
    CmdTraceList("hitag");
    return 0;

    /*
    uint8_t *got = calloc(USB_CMD_DATA_SIZE, sizeof(uint8_t));
    if (!got) {
        PrintAndLogEx(WARNING, "Cannot allocate memory for trace");
        return 2;
    }

    // Query for the actual size of the trace
    UsbCommand response;
    if (!GetFromDevice(BIG_BUF, got, USB_CMD_DATA_SIZE, 0, &response, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        free(got);
        return 2;
    }

    uint16_t traceLen = response.arg[2];
    if (traceLen > USB_CMD_DATA_SIZE) {
        uint8_t *p = realloc(got, traceLen);
        if (p == NULL) {
            PrintAndLogEx(WARNING, "Cannot allocate memory for trace");
            free(got);
            return 2;
        }
        got = p;
        if (!GetFromDevice(BIG_BUF, got, traceLen, 0, NULL, 2500, false)) {
            PrintAndLogEx(WARNING, "command execution time out");
            free(got);
            return 2;
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
            PrintAndLogEx(WARNING, "Error: Could not open file [%s]", filename);
            return 1;
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

            //if((parityBits >> (len - j - 1)) & 0x01) {
            if (isResponse && (oddparity8(frame[j]) != ((parityBits >> (len - j - 1)) & 0x01))) {
                sprintf(line + (j * 4), "%02x!  ", frame[j]);
            } else {
                sprintf(line + (j * 4), "%02x   ", frame[j]);
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
        PrintAndLogEx(NORMAL, "Recorded activity succesfully written to file: %s", filename);
    }

    free(got);
    return 0;
    */
}

int CmdLFHitagSniff(const char *Cmd) {

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return usage_hitag_sniff();

    UsbCommand c = {CMD_SNIFF_HITAG, {0, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

int CmdLFHitagSim(const char *Cmd) {

    bool errors = false;
    bool tag_mem_supplied = false;
    uint8_t cmdp = 0;
    size_t maxdatalen = 48;
    uint8_t *data = calloc(4 * 64, sizeof(uint8_t));
    size_t datalen = 0;
    int res = 0;
    char filename[FILE_PATH_SIZE] = { 0x00 };

    UsbCommand c = {CMD_SIMULATE_HITAG, {0, 0, 0}};

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                free(data);
                return usage_hitag_sim();
            case '2':
                maxdatalen = 48;
                cmdp++;
                break;
            case 's':
                c.cmd = CMD_SIMULATE_HITAG_S;
                maxdatalen = 4 * 64;
                cmdp++;
                break;
            case 'e':
                param_getstr(Cmd, cmdp + 1, filename, sizeof(filename));
                res = loadFileEML(filename, "eml", data, &datalen);
                if (res > 0 || datalen != maxdatalen) {
                    PrintAndLogDevice(FAILED, "error, bytes read mismatch file size");
                    errors = true;
                    break;
                }
                tag_mem_supplied = true;
                cmdp += 2;
                break;
            case 'j':
                param_getstr(Cmd, cmdp + 1, filename, sizeof(filename));
                res = loadFileJSON(filename, "json", data, maxdatalen, &datalen);
                if (res > 0) {
                    errors = true;
                    break;
                }
                tag_mem_supplied = true;
                cmdp += 2;
                break;
            case 'b':
                param_getstr(Cmd, cmdp + 1, filename, sizeof(filename));
                res = loadFile(filename, "bin", data, maxdatalen, &datalen);
                if (res > 0) {
                    errors = true;
                    break;
                }
                tag_mem_supplied = true;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors || cmdp == 0) {
        free(data);
        return usage_hitag_sim();
    }

    c.arg[0] = (uint32_t)tag_mem_supplied;
    if (tag_mem_supplied) {
        memcpy(c.d.asBytes, data, datalen);
    }
    clearCommandBuffer();
    SendCommand(&c);

    free(data);
    return 0;
}

static void printHitagConfiguration(uint8_t config) {
    
    char msg[100];
    memset(msg, 0, sizeof(msg));

    char bits[9];
    char *bs = bits;
    for (uint8_t i = 0 ; i < 8 ; i++) {
        snprintf(bs, sizeof(bits) - i, "%1d", (config >> (7 - i)) & 1);
        bs++;
    }

    PrintAndLogEx(INFO, "\n\nHitag2 tag information ");
    PrintAndLogEx(INFO, "------------------------------------");
    
    //configuration byte
    PrintAndLogEx(SUCCESS, "Config byte : 0x%02X [ %s ]", config, bits);    
    
    // encoding
    strcat(msg, "Encoding    : ");
    if (config & 0x1) {
        strcat(msg + strlen(msg), _YELLOW_("Biphase"));
    } else {
        strcat(msg + strlen(msg), _YELLOW_("Manchester"));
    }
    PrintAndLogEx(SUCCESS, "%s", msg);
    memset(msg, 0, sizeof(msg));

    // version
    strcat(msg, "Coding in HITAG 2 operation: %s");
    uint8_t foo = (config & 0x6) >> 1;
    switch (foo) {
        case 0:
            PrintAndLogEx(SUCCESS, "Version     : public mode B, Coding: biphase");
            PrintAndLogEx(SUCCESS, msg, (config & 0x1) ? "biphase" : "manchester");
            break;
        case 1:
            PrintAndLogEx(SUCCESS, "Version     : public mode A, Coding: manchester");
            PrintAndLogEx(SUCCESS, msg, (config & 0x1) ? "biphase" : "manchester");
            break;
        case 2:
            PrintAndLogEx(SUCCESS, "Version     : public mode C, Coding: biphase");
            PrintAndLogEx(SUCCESS, msg, (config & 0x1) ? "biphase" : "manchester");
            break;
        case 3:
            PrintAndLogEx(SUCCESS, "Version     : Hitag2");
            PrintAndLogEx(SUCCESS, msg, (config & 0x1) ? "biphase" : "manchester");
            break;
    }
    memset(msg, 0, sizeof(msg));

    // mode
    strcat(msg, "Tag is in   : ");
    if (config & 0x8) {
        strcat(msg + strlen(msg), _YELLOW_("Crypto mode"));
    } else  {
        strcat(msg + strlen(msg), _YELLOW_("Password mode"));
    }
    PrintAndLogEx(SUCCESS, "%s", msg);
    memset(msg, 0, sizeof(msg));

    // page access
    strcat(msg, "Page 6,7    : ");
    if (config & 0x10) {
        strcat(msg + strlen(msg), "read only");
    } else  {
        strcat(msg + strlen(msg), _GREEN_("read write"));
    }
    PrintAndLogEx(SUCCESS, "%s", msg);
    memset(msg, 0, sizeof(msg));

    // page access
    strcat(msg, "Page 4,5    : ");    
    if (config & 0x20) {
        strcat(msg + strlen(msg), "read only");
    } else  {
        strcat(msg + strlen(msg), _GREEN_("read write"));
    }
    PrintAndLogEx(SUCCESS, "%s", msg);
    memset(msg, 0, sizeof(msg));

    // OTP
    strcat(msg, "Page 3      : ");
    if (config & 0x40) {
        strcat(msg + strlen(msg), "read only. Configuration byte and password tag " _RED_("FIXED / IRREVERSIBLE"));
    } else  {
        strcat(msg + strlen(msg), _GREEN_("read write"));
    }
    PrintAndLogEx(SUCCESS, "%s", msg);
    memset(msg, 0, sizeof(msg));

    // OTP
    if (config & 0x80) {
        strcat(msg, "Page 1      : " _RED_("locked") "\n");

        strcat(msg + strlen(msg), "Page 2      : ");
        if (config & 0x8) {
            strcat(msg + strlen(msg), _RED_("locked"));
        } else {
            strcat(msg + strlen(msg), "read only");
        }
    } else  {
        strcat(msg, "Page 1,2    : " _GREEN_("read write"));
    }
    PrintAndLogEx(SUCCESS, "%s", msg);
    PrintAndLogEx(INFO, "------------------------------------");
}

static bool getHitagUid(uint32_t *uid) {

    UsbCommand c = {CMD_READER_HITAG, {RHT2F_UID_ONLY, 0, 0} };
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return false;
    }

    if (resp.arg[0] == false) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - failed getting UID");
        return false;
    }

    if ( uid )
        *uid = bytes_to_num(resp.d.asBytes, 4);
   
    return true;
}

int CmdLFHitagInfo(const char *Cmd) {
    PrintAndLogEx(INFO, "Hitag2 tag information ");
    PrintAndLogEx(INFO, "To be done!");
    PrintAndLogEx(INFO, "------------------------------------");

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return usage_hitag_info();
    
    // pwd or key

    // read UID
    uint32_t uid = 0;
    if ( getHitagUid( &uid ) == false ) 
        return 1;
    
    PrintAndLogEx(SUCCESS, "UID: %08X", uid);
    
    // how to detemine Hitag types?
    
    // read block3,  get configuration byte.

    // common configurations.
    printHitagConfiguration(0x06);
    //printHitagConfiguration( 0x0E );
    //printHitagConfiguration( 0x02 );
    //printHitagConfiguration( 0x00 );
    //printHitagConfiguration( 0x04 );
    return 0;
}

// TODO: iceman 
// Hitag2 reader,  problem is that this command mixes up stuff.  So 26 give uid.  21 etc will also give you a memory dump !?
//
int CmdLFHitagReader(const char *Cmd) {

    UsbCommand c = {CMD_READER_HITAG, {0, 0, 0} };
    hitag_data *htd = (hitag_data *)c.d.asBytes;
    hitag_function htf = param_get32ex(Cmd, 0, 0, 10);

    switch (htf) {
        case RHTSF_CHALLENGE: {
            c.cmd = CMD_READ_HITAG_S;
            num_to_bytes(param_get32ex(Cmd, 1, 0, 16), 4, htd->auth.NrAr);
            num_to_bytes(param_get32ex(Cmd, 2, 0, 16), 4, htd->auth.NrAr + 4);
            break;
        }
        case RHTSF_KEY: {
            c.cmd = CMD_READ_HITAG_S;
            num_to_bytes(param_get64ex(Cmd, 1, 0, 16), 6, htd->crypto.key);
            break;
        }
        case RHT2F_PASSWORD: {
            num_to_bytes(param_get32ex(Cmd, 1, 0, 16), 4, htd->pwd.password);
            break;
        }
        case RHT2F_AUTHENTICATE: {
            num_to_bytes(param_get32ex(Cmd, 1, 0, 16), 4, htd->auth.NrAr);
            num_to_bytes(param_get32ex(Cmd, 2, 0, 16), 4, htd->auth.NrAr + 4);
            break;
        }
        case RHT2F_CRYPTO: {
            num_to_bytes(param_get64ex(Cmd, 1, 0, 16), 6, htd->crypto.key);
            break;
        }
        case RHT2F_TEST_AUTH_ATTEMPTS: {
            // No additional parameters needed
            break;
        }
        case RHT2F_UID_ONLY: {
            // No additional parameters needed
            break;
        }
        default: {
            return usage_hitag_reader();
        }
    }

    c.arg[0] = htf;
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 4000)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return 1;
    }

    if (resp.arg[0] == false) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - hitag failed");
        return 1;
    }

    uint32_t id = bytes_to_num(resp.d.asBytes, 4);

    PrintAndLogEx(SUCCESS, "Valid Hitag2 tag found - UID: %08x", id);
    if (htf != RHT2F_UID_ONLY) {
        
        PrintAndLogEx(SUCCESS, "Dumping tag memory..." );
        uint8_t *data = resp.d.asBytes;

        char filename[FILE_PATH_SIZE];
        char *fnameptr = filename;
        fnameptr += sprintf(fnameptr, "lf-hitag-");
        FillFileNameByUID(fnameptr, data, "-dump", 4);

        saveFile(filename, "bin", data, 48);
        saveFileEML(filename, "eml", data, 48, 4);
        saveFileJSON(filename, "json", jsfHitag, data, 48);
        
        // block3, 1 byte
        printHitagConfiguration(data[4*3] );
    }
    return 0;
}

int CmdLFHitagCheckChallenges(const char *Cmd) {

    UsbCommand c = { CMD_TEST_HITAGS_TRACES, {0, 0, 0}};
    char filename[FILE_PATH_SIZE] = { 0x00 };
    size_t datalen = 0;
    int res = 0;
    bool file_given = false;
    bool errors = false;
    uint8_t cmdp = 0;
    uint8_t *data = calloc(8 * 60, sizeof(uint8_t));

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                free(data);
                return usage_hitag_checkchallenges();
            case 'f':
                param_getstr(Cmd, cmdp + 1, filename, sizeof(filename));
                res = loadFile(filename, "cc", data, 8 * 60, &datalen);
                if (res > 0) {
                    errors = true;
                    break;
                }

                memcpy(c.d.asBytes, data, datalen);
                file_given = true;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors) {
        free(data);
        return usage_hitag_checkchallenges();
    }

    //file with all the challenges to try
    c.arg[0] = (uint32_t)file_given;
    clearCommandBuffer();
    SendCommand(&c);

    free(data);
    return 0;
}

int CmdLFHitagWriter(const char *Cmd) {
    UsbCommand c = { CMD_WR_HITAG_S, {0, 0, 0}};
    hitag_data *htd = (hitag_data *)c.d.asBytes;
    hitag_function htf = param_get32ex(Cmd, 0, 0, 10);

    switch (htf) {
        case WHTSF_CHALLENGE: {
            num_to_bytes(param_get64ex(Cmd, 1, 0, 16), 8, htd->auth.NrAr);
            c.arg[2] = param_get32ex(Cmd, 2, 0, 10);
            num_to_bytes(param_get32ex(Cmd, 3, 0, 16), 4, htd->auth.data);
            break;
        }
        case WHTSF_KEY:
        case WHT2F_CRYPTO: {
            num_to_bytes(param_get64ex(Cmd, 1, 0, 16), 6, htd->crypto.key);
            c.arg[2] = param_get32ex(Cmd, 2, 0, 10);
            num_to_bytes(param_get32ex(Cmd, 3, 0, 16), 4, htd->crypto.data);
            break;
        }
        default: {
            return usage_hitag_writer();
        }
    }

    c.arg[0] = htf;

    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 4000)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return 1;
    }

    if (resp.arg[0] == false) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - hitag write failed");
        return 1;
    }
    return 0;
}

int CmdLFHitagDump(const char *Cmd) {
    PrintAndLogEx(INFO, "Dumping of tag memory");
    PrintAndLogEx(INFO, "To be done!");

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return usage_hitag_dump();
    return 0;
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,                   1, "This help" },
    {"list",     CmdLFHitagList,            0, "List Hitag trace history" },
    {"info",     CmdLFHitagInfo,            1, "Tag information" },
    {"reader",   CmdLFHitagReader,          1, "Act like a Hitag Reader" },
    {"sim",      CmdLFHitagSim,             1, "Simulate Hitag transponder" },
    {"sniff",    CmdLFHitagSniff,           1, "Eavesdrop Hitag communication" },
    {"writer",   CmdLFHitagWriter,          1, "Act like a Hitag Writer" },
    {"cc",       CmdLFHitagCheckChallenges, 1, "Test all challenges" },
    { NULL, NULL, 0, NULL }
};

int CmdLFHitag(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
