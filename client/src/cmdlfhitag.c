//-----------------------------------------------------------------------------
// Copyright (C) 2012 Roel Verdult
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Hitag support
//-----------------------------------------------------------------------------
#include "cmdlfhitag.h"
#include <ctype.h>
#include "cmdparser.h"   // command_t
#include "comms.h"
#include "cmdtrace.h"
#include "commonutil.h"
#include "hitag.h"
#include "fileutils.h"   // savefile
#include "protocols.h"   // defines
#include "cliparser.h"

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

/*
static size_t nbytes(size_t nbits) {
    return (nbits / 8) + ((nbits % 8) > 0);
}

static int usage_hitag_dump(void) {
    PrintAndLogEx(NORMAL, "Usage:   lf hitag dump [h] p <pwd> f <name>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h          This help");
//    PrintAndLogEx(NORMAL, "       p <pwd>    password");
//    PrintAndLogEx(NORMAL, "       f <name>   data filename, if no <name> given, UID will be used as filename");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         lf hitag dump f mydump");
    PrintAndLogEx(NORMAL, "         lf hitag dump p 4D494B52 f mydump");
    return PM3_SUCCESS;
}
*/
static int usage_hitag_writer(void) {
    PrintAndLogEx(NORMAL, "Hitag writer functions");
    PrintAndLogEx(NORMAL, "Usage: lf hitag write [h] <reader function #>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h                                     This help");
    PrintAndLogEx(NORMAL, "   HitagS (0*)");
    PrintAndLogEx(NORMAL, "      03 <nr,ar> <page> <byte0...byte3>      Write page, challenge mode");
    PrintAndLogEx(NORMAL, "      04 <key> <page> <byte0...byte3>        Write page, crypto mode. Set key=0 for no auth");
    PrintAndLogEx(NORMAL, "   Hitag1 (1*)");
    PrintAndLogEx(NORMAL, "      Not implemented");
    PrintAndLogEx(NORMAL, "   Hitag2 (2*)");
    PrintAndLogEx(NORMAL, "      24  <key> <page> <byte0...byte3>       Write page, crypto mode. Key format: ISK high + ISK low.");
    PrintAndLogEx(NORMAL, "                                             Default: 4F4E4D494B52 (\"ONMIKR\"). Set key=0 for no auth");
    PrintAndLogEx(NORMAL, "      27  <password> <page> <byte0...byte3>  Write page, password mode. Default: 4D494B52 (\"MIKR\")");
    return PM3_SUCCESS;
}

static int CmdLFHitagList(const char *Cmd) {
    char args[128] = {0};
    if (strlen(Cmd) == 0) {
        snprintf(args, sizeof(args), "-t hitag2");
    } else {
        strncpy(args, Cmd, sizeof(args) - 1);
    }
    return CmdTraceList(args);


    /*
    uint8_t *got = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    if (!got) {
        PrintAndLogEx(WARNING, "Cannot allocate memory for trace");
        return PM3_EMALLOC;
    }

    // Query for the actual size of the trace
    PacketResponseNG response;
    if (!GetFromDevice(BIG_BUF, got, PM3_CMD_DATA_SIZE, 0, NULL, 0, &response, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        free(got);
        return PM3_ETIMEOUT;
    }

    uint16_t traceLen = response.arg[2];
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
        PrintAndLogEx(NORMAL, "Recorded activity successfully written to file: %s", filename);
    }

    free(got);
    return PM3_SUCCES;
    */
}

static int CmdLFHitagSniff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag sniff",
                  "Sniff traffic between Hitag reader and tag.\n"
                  "Use " _YELLOW_("`lf hitag list`")" to view collected data.",
                  "lf hitag sniff"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAG_SNIFF, NULL, 0);
    PrintAndLogEx(HINT, "HINT: Try " _YELLOW_("`lf hitag list`")" to view collected data");
    return PM3_SUCCESS;
}


// eload ,  to be implemented
static int CmdLFHitagEload(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag eload",
                  "Loads hitag tag dump into emulator memory on device",
                  "lf hitag eload -f lf-hitag-11223344-dump.bin\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<filename>", "filename of dump"),
        arg_lit0("1", NULL, "simulate Hitag1"),
        arg_lit0("2", NULL, "simulate Hitag2"),
        arg_lit0("s", NULL, "simulate HitagS"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool use_ht1 = arg_get_lit(ctx, 2);
    bool use_ht2 = arg_get_lit(ctx, 3);
    bool use_hts = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    uint8_t n = (use_ht1 + use_ht2 + use_hts);
    if (n != 1) {
        PrintAndLogEx(ERR, "error, only specify one Hitag type");
        return PM3_EINVARG;
    }

    DumpFileType_t dftype = getfiletype(filename);
    size_t dumplen = 0;
    uint8_t *dump = NULL;
    int res = 0;
    switch (dftype) {
        case BIN: {
            res = loadFile_safe(filename, ".bin", (void **)&dump, &dumplen);
            break;
        }
        case EML: {
            res = loadFileEML_safe(filename, (void **)&dump, &dumplen);
            break;
        }
        case JSON: {
            dumplen = 4 * 64;
            dump = calloc(dumplen, sizeof(uint8_t));
            if (dump == NULL) {
                PrintAndLogEx(ERR, "error, cannot allocate memory");
                return PM3_EMALLOC;
            }
            res = loadFileJSON(filename, dump, dumplen, &dumplen, NULL);
            break;
        }
        case DICTIONARY: {
            PrintAndLogEx(ERR, "error, only BIN/JSON/EML formats allowed");
            return PM3_EINVARG;
        }
    }

    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "error, something went wrong when loading file");
        free(dump);
        return PM3_EFILE;
    }

    // check dump len..
    if (dumplen == 48 ||  dumplen == 4 * 64) {
        struct {
            uint16_t len;
            uint8_t *data;
        } PACKED payload;
        payload.len = dumplen;
        memcpy(payload.data, dump, dumplen);

        clearCommandBuffer();
        SendCommandNG(CMD_LF_HITAG_ELOAD, (uint8_t *)&payload, 2 + dumplen);
    } else {
        PrintAndLogEx(ERR, "error, wrong dump file size. got %zu", dumplen);
    }

    free(dump);
    return PM3_SUCCESS;
}

static int CmdLFHitagSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag sim",
                  "Simulate Hitag2 / HitagS transponder\n"
                  "You need to `lf hitag eload` first",
                  "lf hitag sim -2"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("1", NULL, "simulate Hitag1"),
        arg_lit0("2", NULL, "simulate Hitag2"),
        arg_lit0("s", NULL, "simulate HitagS"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool use_ht1 = arg_get_lit(ctx, 1);
    bool use_ht2 = arg_get_lit(ctx, 2);
    bool use_hts = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if ((use_ht1 + use_ht2 + use_hts) > 1) {
        PrintAndLogEx(ERR, "error, Only specify one Hitag type");
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
        strcat(msg + strlen(msg), _GREEN_("RW"));
    }
    PrintAndLogEx(SUCCESS, "%s", msg);
    memset(msg, 0, sizeof(msg));

    // page access
    strcat(msg, "Page 4,5    : ");
    if (config & 0x20) {
        strcat(msg + strlen(msg), "read only");
    } else  {
        strcat(msg + strlen(msg), _GREEN_("RW"));
    }
    PrintAndLogEx(SUCCESS, "%s", msg);
    memset(msg, 0, sizeof(msg));

    // OTP
    strcat(msg, "Page 3      : ");
    if (config & 0x40) {
        strcat(msg + strlen(msg), "read only. Configuration byte and password tag " _RED_("FIXED / IRREVERSIBLE"));
    } else  {
        strcat(msg + strlen(msg), _GREEN_("RW"));
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
        strcat(msg, "Page 1,2    : " _GREEN_("RW"));
    }
    PrintAndLogEx(SUCCESS, "%s", msg);
    PrintAndLogEx(INFO, "------------------------------------");
}

static bool getHitagUid(uint32_t *uid) {
    hitag_data htd;
    memset(&htd, 0, sizeof(htd));
    clearCommandBuffer();
    SendCommandMIX(CMD_LF_HITAG_READER, RHT2F_UID_ONLY, 0, 0, &htd, sizeof(htd));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return false;
    }

    if (resp.oldarg[0] == false) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - failed getting UID");
        return false;
    }

    if (uid)
        *uid = bytes_to_num(resp.data.asBytes, 4);

    return true;
}

static int CmdLFHitagInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag info",
                  "Sniff traffic between Hitag reader and tag.",
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
    if (getHitagUid(&uid) == false)
        return PM3_ESOFT;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "     UID: " _GREEN_("%08X"), uid);
    PrintAndLogEx(SUCCESS, "    TYPE: " _GREEN_("%s"), getHitagTypeStr(uid));

    // how to detemine Hitag types?
    // read block3,  get configuration byte.

    // common configurations.
    // printHitagConfiguration(0x06);
    //printHitagConfiguration( 0x0E );
    //printHitagConfiguration( 0x02 );
    //printHitagConfiguration( 0x00 );
    //printHitagConfiguration( 0x04 );
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    return PM3_SUCCESS;
}

// TODO: iceman
// Hitag2 reader,  problem is that this command mixes up stuff.  So 26 give uid.  21 etc will also give you a memory dump !?
//
static int CmdLFHitagReader(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag reader",
                  "Act like a Hitag Reader",
                  "Hitag S\n"
                  "  lf hitag reader --01 --nr 01020304 --ar 11223344\n"
                  "  lf hitag reader --02 -k 4F4E4D494B52\n"
                  "Hitag 2\n"
                  "  lf hitag reader --21 -k 4D494B52\n"
                  "  lf hitag reader --22 --nr 01020304 --ar 11223344\n"
                  "  lf hitag reader --23 -k 4F4E4D494B52\n"
                  "  lf hitag reader --26\n"
                );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "01", "HitagS, read all pages, challenge mode"),
        arg_lit0(NULL, "02", "HitagS, read all pages, crypto mode. Set key=0 for no auth"),
        arg_lit0(NULL, "21", "Hitag2, read all pages, password mode. def 4D494B52 (MIKR)"),
        arg_lit0(NULL, "22", "Hitag2, read all pages, challenge mode"),
        arg_lit0(NULL, "23", "Hitag2, read all pages, crypto mode. Key format: ISK high + ISK low. def 4F4E4D494B52 (ONMIKR)"),
        arg_lit0(NULL, "25", "Hitag2, test recorded authentications (replay?)"),
        arg_lit0(NULL, "26", "Hitag2, read UID"),
        arg_str0("k","key", "<hex>", "4 or 6 hex bytes"),
        arg_str0(NULL,"nr", "<hex>", "nonce reader, 4 hex bytes"),
        arg_str0(NULL,"ar", "<hex>", "answer reader, 4 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    // Hitag S
    bool s01 = arg_get_lit(ctx, 1);
    bool s02 = arg_get_lit(ctx, 2);

    // Hitag 2
    bool h21 = arg_get_lit(ctx, 3);
    bool h22 = arg_get_lit(ctx, 4);
    bool h23 = arg_get_lit(ctx, 5);
    bool h25 = arg_get_lit(ctx, 6);
    bool h26 = arg_get_lit(ctx, 7);

    uint8_t key[6];
    int keylen = 0;
    CLIParamHexToBuf(arg_get_str(ctx, 8), key, sizeof(key), &keylen);

    uint8_t nr[4];
    int nlen = 0;
    CLIParamHexToBuf(arg_get_str(ctx, 9), nr, sizeof(nr), &nlen);

    uint8_t ar[4];
    int alen = 0;
    CLIParamHexToBuf(arg_get_str(ctx, 10), ar, sizeof(ar), &alen);
    CLIParserFree(ctx);


    // sanity checks
    if (keylen != 0 && keylen != 6) {
        PrintAndLogEx(WARNING, "Wrong KEY len expected 0 or 6,  got %d", keylen);
        return PM3_EINVARG;
    }

    if (nlen != 0 && nlen != 4) {
        PrintAndLogEx(WARNING, "Wrong NR len expected 0 or 4,  got %d", nlen);
        return PM3_EINVARG;
    }

    if (alen != 0 && alen != 4) {
        PrintAndLogEx(WARNING, "Wrong AR len expected 0 or 4,  got %d", alen);
        return PM3_EINVARG;
    }

    uint8_t foo = (s01 + s02 + h21 + h22 + h23 + h25 + h26);
    if (foo > 1) {
        PrintAndLogEx(WARNING, "Only specify one HITAG reader call");
        return PM3_EINVARG;
    } else if (foo == 0) {
        PrintAndLogEx(WARNING, "Specify one HITAG reader call");
        return PM3_EINVARG;
    }

    hitag_function htf;
    hitag_data htd;
    uint16_t cmd = CMD_LF_HITAG_READER;
    if (s01) {
        cmd = CMD_LF_HITAGS_READ;
        htf = RHTSF_CHALLENGE;
        memcpy(htd.auth.NrAr, nr, sizeof(nr));
        memcpy(htd.auth.NrAr + 4, ar, sizeof(ar));
    }
    if (s02){
        cmd = CMD_LF_HITAGS_READ;
        htf = RHTSF_KEY;
        memcpy(htd.crypto.key, key, sizeof(key));
    }
    if (h21) {
        htf = RHT2F_PASSWORD;
        memcpy(htd.pwd.password, key, 4);
    }
    if (h22) {
        htf = RHT2F_AUTHENTICATE;
        memcpy(htd.auth.NrAr, nr, sizeof(nr));
        memcpy(htd.auth.NrAr + 4, ar, sizeof(ar));
    }
    if (h23) {
        htf = RHT2F_CRYPTO;
        memcpy(htd.crypto.key, key, sizeof(key));
    }
    if (h25) {
        htf = RHT2F_TEST_AUTH_ATTEMPTS;
    }
    if (h26) {
        htf = RHT2F_UID_ONLY;
    }
    
    clearCommandBuffer();
    SendCommandMIX(cmd, htf, 0, 0, &htd, sizeof(htd));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.oldarg[0] == false) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - hitag failed");
        return PM3_ESOFT;
    }

    uint32_t id = bytes_to_num(resp.data.asBytes, 4);
    uint8_t *data = resp.data.asBytes;
    PrintAndLogEx(SUCCESS, " UID: " _YELLOW_("%08x"), id);

    if (htf != RHT2F_UID_ONLY) {

        // block3, 1 byte
        printHitagConfiguration(data[4 * 3]);
    }
    return PM3_SUCCESS;
}

static int CmdLFHitagCheckChallenges(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag cc",
                  "Check challenges, load a file with saved hitag crypto challenges and test them all.\n"
                  "The file should be 8 * 60 bytes long, the file extension defaults to " _YELLOW_("`.cc`") " ",
                  "lf hitag cc -f my_hitag_challenges"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "filename", "<fn w/o ext>", "filename to load from"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    CLIParserFree(ctx);

    clearCommandBuffer();

    if (fnlen > 0) {
        uint8_t *data = NULL;
        size_t datalen = 0;
        int res = loadFile_safe(filename, ".cc", (void **)&data, &datalen);
        if (res == PM3_SUCCESS) {
            if (datalen == (8 * 60)) {
                SendCommandOLD(CMD_LF_HITAGS_TEST_TRACES, 1, 0, 0, data, datalen);
            } else {
                PrintAndLogEx(ERR, "Error, file length mismatch. Expected %d, got %zu", 8 * 60, datalen);
            }
        }
        if (data) {
            free(data);
        }
    } else {
        SendCommandMIX(CMD_LF_HITAGS_TEST_TRACES, 0, 0, 0, NULL, 0);
    }

    return PM3_SUCCESS;
}

static int CmdLFHitagWriter(const char *Cmd) {
    hitag_data htd;
    hitag_function htf = param_get32ex(Cmd, 0, 0, 10);

    uint32_t arg2 = 0;
    switch (htf) {
        case WHTSF_CHALLENGE: {
            num_to_bytes(param_get64ex(Cmd, 1, 0, 16), 8, htd.auth.NrAr);
            arg2 = param_get32ex(Cmd, 2, 0, 10);
            num_to_bytes(param_get32ex(Cmd, 3, 0, 16), 4, htd.auth.data);
            break;
        }
        case WHTSF_KEY:
        case WHT2F_CRYPTO: {
            num_to_bytes(param_get64ex(Cmd, 1, 0, 16), 6, htd.crypto.key);
            arg2 = param_get32ex(Cmd, 2, 0, 10);
            num_to_bytes(param_get32ex(Cmd, 3, 0, 16), 4, htd.crypto.data);
            break;
        }
        case WHT2F_PASSWORD: {
            num_to_bytes(param_get64ex(Cmd, 1, 0, 16), 4, htd.pwd.password);
            arg2 = param_get32ex(Cmd, 2, 0, 10);
            num_to_bytes(param_get32ex(Cmd, 3, 0, 16), 4, htd.crypto.data);
            break;
        }
        default:
        case RHT1F_PLAIN:
        case RHT1F_AUTHENTICATE:
        case RHTSF_CHALLENGE:
        case RHTSF_KEY:
        case RHT2F_PASSWORD:
        case RHT2F_AUTHENTICATE:
        case RHT2F_CRYPTO:
        case RHT2F_TEST_AUTH_ATTEMPTS:
        case RHT2F_UID_ONLY:
            return usage_hitag_writer();
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_LF_HITAGS_WRITE, htf, 0, arg2, &htd, sizeof(htd));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 4000)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.oldarg[0] == false) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - hitag write failed");
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int CmdLFHitag2Dump(const char *Cmd) {
    PrintAndLogEx(INFO, "Dumping of tag memory");

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return 0; // usage_hitag_dump();

    PacketResponseNG resp;

    PrintAndLogEx(SUCCESS, "Dumping tag memory...");
    uint8_t *data = resp.data.asBytes;

    char filename[FILE_PATH_SIZE];
    char *fnameptr = filename;
    fnameptr += sprintf(fnameptr, "lf-hitag-");
    FillFileNameByUID(fnameptr, data, "-dump", 4);

    saveFile(filename, ".bin", data, 48);
    saveFileEML(filename, data, 48, 4);
    saveFileJSON(filename, jsfHitag, data, 48, NULL);

    return PM3_SUCCESS;
}


// Annotate HITAG protocol
void annotateHitag1(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize, bool is_reader) {
}

void annotateHitag2(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize, bool is_response) {

    // iceman: live decrypt of trace?
    if (is_response) {


        uint8_t cmdbits = (cmd[0] & 0xC0) >> 6;

        if (cmdsize == 1) {
            if (cmdbits == HITAG2_START_AUTH) {
                snprintf(exp, size, "START AUTH");
                return;
            }
            if (cmdbits == HITAG2_HALT) {
                snprintf(exp, size, "HALT");
                return;
            }
        }

        if (cmdsize == 3) {
            if (cmdbits == HITAG2_START_AUTH) {
                // C     1     C   0
                // 1100 0 00 1 1100 000
                uint8_t page = (cmd[0] & 0x38) >> 3;
                uint8_t inv_page = ((cmd[0] & 0x1) << 2) | ((cmd[1] & 0xC0) >> 6);
                snprintf(exp, size, "READ page(%x) %x", page, inv_page);
                return;
            }
            if (cmdbits == HITAG2_WRITE_PAGE) {
                uint8_t page = (cmd[0] & 0x38) >> 3;
                uint8_t inv_page = ((cmd[0] & 0x1) << 2) | ((cmd[1] & 0xC0) >> 6);
                snprintf(exp, size, "WRITE page(%x) %x", page, inv_page);
                return;
            }
        }

        if (cmdsize == 9)  {
            snprintf(exp, size, "Nr Ar Is response");
            return;
        }
    } else {

        if (cmdsize == 9)  {
            snprintf(exp, size, "Nr Ar");
            return;
        }
    }

}


void annotateHitagS(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize, bool is_reader) {
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,               AlwaysAvailable, "This help"},
    {"eload",  CmdLFHitagEload,       IfPm3Hitag,      "Load Hitag dump file into emulator memory"},
    {"list",   CmdLFHitagList,        IfPm3Hitag,      "List Hitag trace history"},
    {"info",   CmdLFHitagInfo,        IfPm3Hitag,      "Tag information"},
    {"reader", CmdLFHitagReader,      IfPm3Hitag,      "Act like a Hitag Reader"},
    {"sim",    CmdLFHitagSim,         IfPm3Hitag,      "Simulate Hitag transponder"},
    {"sniff",  CmdLFHitagSniff,       IfPm3Hitag,      "Eavesdrop Hitag communication"},
    {"writer", CmdLFHitagWriter,      IfPm3Hitag,      "Act like a Hitag Writer"},
    {"dump",   CmdLFHitag2Dump,       IfPm3Hitag,      "Dump Hitag2 tag"},
    {"cc",     CmdLFHitagCheckChallenges, IfPm3Hitag,  "Test all challenges"},
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
    return (CmdLFHitagReader("26") == PM3_SUCCESS);
}
