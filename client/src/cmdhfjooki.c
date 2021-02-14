//-----------------------------------------------------------------------------
// Ultralight Code (c) 2021 Iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE ULTRALIGHT / Jooki commands
//-----------------------------------------------------------------------------
#include "cmdhfjooki.h"
#include <ctype.h>
#include <string.h>       // memset
#include "commonutil.h"   // ARRAYLEN
#include "ui.h"           // PrintAndLog
#include "cmdparser.h"
#include "generator.h"
#include "base64.h"
#include "mifare/ndef.h"  // print decode ndef
#include "mifare/mifarehost.h"  // mfemlsetmem_xt
#include "cliparser.h"
#include "cmdhfmfu.h"
#include "cmdmain.h"
#include "fileutils.h"    // convert_mfu..


static int CmdHelp(const char *Cmd);

typedef struct {
    uint8_t uid[7];
    const char b64[17];
    uint8_t tagtype;
} PACKED jooki_t;

// sample set for selftest.
jooki_t jooks[] = {
    { {0x04, 0xDA, 0xB7, 0x6A, 0xE7, 0x4C, 0x80}, "ruxow8lnn88uyeX+", 0x00},
    { {0x04, 0xf0, 0x22, 0xc2, 0x33, 0x5e, 0x80}, "\0" , 0x00},
    { {0x04, 0x8C, 0xEC, 0xDA, 0xF0, 0x4A, 0x80}, "ONrsVf7jX6IaSNV6", 0x01},
    { {0x04, 0x92, 0xA7, 0x6A, 0xE7, 0x4C, 0x81}, "Hjjpcx/mZwuveTF+", 0x02},
    { {0x04, 0xD0, 0xB0, 0x3A, 0xD3, 0x63, 0x80}, "\0", 0x02},
    { {0x04, 0x96, 0x42, 0xDA, 0xF0, 0x4A, 0x80}, "vEWy0WO9wZNEzEok", 0x03},
    { {0x04, 0x33, 0xb5, 0x62, 0x39, 0x4d, 0x80}, "\0", 0x03},
    { {0x04, 0x17, 0xB7, 0x3A, 0xD3, 0x63, 0x81}, "f0axEma+g2WnLGAm", 0x05},
    { {0x04, 0x84, 0x27, 0x6A, 0xE7, 0x4C, 0x80}, "VZB/OLBwOiM5Mpnp", 0x05},
    { {0x04, 0x28, 0xF4, 0xDA, 0xF0, 0x4A, 0x81}, "7WzlgEzqLgwTnWNy", 0x05},
};

const char *jooks_figures[] = {"Dragon", "Fox", "Ghost", "Knight", "?", "Whale"};
const uint8_t jooki_secret[] = {0x20, 0x20, 0x20, 0x6D, 0x24, 0x0B, 0xEB, 0x94, 0x2C, 0x80, 0x45, 0x16};
const uint8_t NFC_SECRET[] = { 0x03, 0x9c, 0x25, 0x6f, 0xb9, 0x2e, 0xe8, 0x08, 0x09, 0x83, 0xd9, 0x33, 0x56};

#define JOOKI_UID_LEN  7
#define JOOKI_IV_LEN   4
#define JOOKI_B64_LEN (16 + 1)
#define JOOKI_PLAIN_LEN 12

static int jooki_encode(uint8_t *iv, uint8_t tagtype, uint8_t *uid, uint8_t *out) {
    if (out == NULL) {
        PrintAndLogEx(ERR, "(encode jooki) base64ndef param is NULL");
        return PM3_EINVARG;
    }    

    out[0] = 0x00;
    if (iv == NULL || uid == NULL) {
        PrintAndLogEx(ERR, "(encode jooki) iv or uid param is NULL");
        return PM3_EINVARG;
    }

    uint8_t d[JOOKI_PLAIN_LEN] = {iv[0], iv[1],iv[2], iv[3], tagtype, uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6]};
    uint8_t enc[JOOKI_PLAIN_LEN] = {0};
    for (uint8_t i = 0; i < JOOKI_PLAIN_LEN; i++) {

        if (i < 3)
            enc[i] = d[i] ^ NFC_SECRET[i];
        else
            enc[i] = d[i] ^ NFC_SECRET[i] ^ d[i % 3];
    }

    PrintAndLogEx(DEBUG, "encoded result.... %s", sprint_hex(enc, sizeof(enc)));

    size_t b64len = 0;
    uint8_t b64[20];
    memset(b64, 0, 20);
    mbedtls_base64_encode(b64, sizeof(b64), &b64len, (const unsigned char*)enc, sizeof(enc));
    memcpy(out, b64, b64len);
    return PM3_SUCCESS;
}

static int jooki_decode(uint8_t *b64, uint8_t *result) {
    uint8_t ndef[JOOKI_PLAIN_LEN] = {0};
    size_t outputlen = 0;
    mbedtls_base64_decode(ndef, sizeof(ndef), &outputlen, (const unsigned char*)b64, 16);

    PrintAndLogEx(DEBUG, "(decode_jooki) raw encoded... " _GREEN_("%s"), sprint_hex(ndef, sizeof(ndef)));

    for (uint8_t i = 0; i < JOOKI_PLAIN_LEN; i++) {
        if (i < 3)
            result[i] = ndef[i] ^ NFC_SECRET[i];
        else
            result[i] = ndef[i] ^ NFC_SECRET[i] ^ ndef[i % 3] ^ NFC_SECRET[i % 3];
    }
    PrintAndLogEx(DEBUG, "(decode_jooki) plain......... %s", sprint_hex(result, sizeof(ndef)));
    return PM3_SUCCESS;
}

static int jooki_create_ndef(uint8_t *b64ndef, uint8_t *ndefrecord) {
    // sample of url:   https://s.jooki.rocks/s/?s=ONrsVf7jX6IaSNV6
    if (ndefrecord == NULL) {
        PrintAndLogEx(ERR, "(jooki_create_ndef) ndefrecord param is NULL");
        return PM3_EINVARG;
    }
    memcpy(ndefrecord, 
        "\x01\x03\xa0\x0c\x34\x03\x29\xd1"
        "\x01\x25\x55\x04\x73\x2e\x6a\x6f"
        "\x6f\x6b\x69\x2e\x72\x6f\x63\x6b"
        "\x73\x2f\x73\x2f\x3f\x73\x3d", 31);
    memcpy(ndefrecord + 31, b64ndef, 16);
    memcpy(ndefrecord + 47, "\x0a\xFE\x00\x00\x00", 5);
    return PM3_SUCCESS;
}

static void jooki_printEx(uint8_t *b64, uint8_t *iv, uint8_t tt, uint8_t *uid, bool verbose) {
    PrintAndLogEx(INFO, "Encoded URL.. %s ( %s )", sprint_hex(b64, 12), b64);
    PrintAndLogEx(INFO, "Figurine..... %02x - " _GREEN_("%s"), tt, jooks_figures[tt]);
    PrintAndLogEx(INFO, "iv........... %s", sprint_hex(iv, JOOKI_IV_LEN));  
    PrintAndLogEx(INFO, "uid.......... %s", sprint_hex(uid, JOOKI_UID_LEN));  

    uint8_t ndefmsg[52] = {0};
    jooki_create_ndef(b64, ndefmsg);
    PrintAndLogEx(INFO, "NDEF raw..... %s", sprint_hex_inrow(ndefmsg, sizeof(ndefmsg)));

    if (verbose) {
        int res = NDEFRecordsDecodeAndPrint(ndefmsg, sizeof(ndefmsg));
        if (res != PM3_SUCCESS) {
            NDEFDecodeAndPrint(ndefmsg, sizeof(ndefmsg), verbose);
        }
    }
}

static void jooki_print(uint8_t *b64, uint8_t *result, bool verbose) {
    if (b64 == NULL || result == NULL)
        return;

    uint8_t iv[JOOKI_IV_LEN] = {0};
    uint8_t uid[JOOKI_UID_LEN] = {0};
    memcpy(iv, result, sizeof(iv));
    uint8_t tt = result[4];
    memcpy(uid, result + 5, sizeof(uid));

    jooki_printEx(b64, iv, tt, uid, verbose);
}

static int jooki_selftest(void) {
    
    PrintAndLogEx(INFO, "======== " _CYAN_("selftest") " ==========================================="); 
    for (int i = 0; i < ARRAYLEN(jooks); i++) {
        if (strlen(jooks[i].b64) == 0)
            continue;

        uint8_t iv[JOOKI_IV_LEN] = {0};
        uint8_t uid[JOOKI_UID_LEN] = {0};
        uint8_t result[JOOKI_PLAIN_LEN] = {0};
        jooki_decode((uint8_t*)jooks[i].b64, result);

        memcpy(iv, result, 4);
        uint8_t tt = result[4];
        memcpy(uid, result + 5, sizeof(uid));

        bool tt_ok  = (tt == jooks[i].tagtype); 
        bool uid_ok = (memcmp(uid, jooks[i].uid, sizeof(uid)) == 0);

        PrintAndLogEx(INFO, "Encoded URL.. %s ( %s )", sprint_hex((const uint8_t*)jooks[i].b64, 12), jooks[i].b64);
        PrintAndLogEx(INFO, "Figurine..... %02x - " _GREEN_("%s") " ( %s )", tt, jooks_figures[tt], tt_ok ? _GREEN_("ok") : _RED_("fail"));  
        PrintAndLogEx(INFO, "iv........... %s", sprint_hex(iv, sizeof(iv)));  
        PrintAndLogEx(INFO, "uid.......... %s ( %s )", sprint_hex(uid, sizeof(uid)), uid_ok ? _GREEN_("ok") : _RED_("fail"));          

        uint8_t b64[JOOKI_B64_LEN] = {0};
        memset(b64, 0, sizeof(b64));        
        jooki_encode(iv, tt, uid, b64);

        uint8_t ndefmsg[52] = {0};
        jooki_create_ndef(b64, ndefmsg);
        PrintAndLogEx(INFO, "NDEF raw .... %s", sprint_hex(ndefmsg, sizeof(ndefmsg)));
        
        int status = NDEFRecordsDecodeAndPrint(ndefmsg, sizeof(ndefmsg));
        if ( status != PM3_SUCCESS) {
            status = NDEFDecodeAndPrint(ndefmsg, sizeof(ndefmsg), true);
        }
        PrintAndLogEx(INFO, "==================================================================");     
    }
    return PM3_SUCCESS;
}

static int CmdHF14AJookiEncode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf jooki encode",
                  "Encode a Jooki token to base64 NDEF URI format",
                  "hf jooki encode -t            --> selftest\n"
                  "hf jooki encode -r --dragon   --> read uid from tag and use for encoding\n"
                  "hf jooki encode --uid 04010203040506 --dragon"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid",  "<hex>", "uid bytes"),
        arg_lit0("r", NULL, "read uid from tag instead"),
        arg_lit0("t", NULL, "selftest"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "dragon", "tag type"),
        arg_lit0(NULL, "fox", "tag type"),
        arg_lit0(NULL, "ghost", "tag type"),
        arg_lit0(NULL, "knight", "tag type"),
        arg_lit0(NULL, "whale", "tag type"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int ulen = 0;
    uint8_t uid[JOOKI_UID_LEN] = {0x00};
    memset(uid, 0x0, sizeof(uid));
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), uid, sizeof(uid), &ulen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool use_tag = arg_get_lit(ctx, 2);
    bool selftest = arg_get_lit(ctx, 3);
    bool verbose = arg_get_lit(ctx, 4);
    bool tt_dragon = arg_get_lit(ctx, 5);
    bool tt_fox = arg_get_lit(ctx, 6);
    bool tt_ghost = arg_get_lit(ctx, 7);
    bool tt_knight = arg_get_lit(ctx, 8);
    bool tt_whale = arg_get_lit(ctx, 9);
    CLIParserFree(ctx);
    
    if (selftest) {
        return jooki_selftest();
    }

    if ((tt_dragon + tt_fox + tt_ghost + tt_knight + tt_whale) > 1) {
        PrintAndLogEx(ERR, "Select one tag type");
        return PM3_EINVARG;
    }
    uint8_t tt = 0;
    if (tt_fox)
        tt = 1;
    if (tt_ghost)
        tt = 2;
    if (tt_knight)
        tt = 3;
    if (tt_whale)
        tt = 5;
    
    uint8_t iv[JOOKI_IV_LEN] = {0x80, 0x77, 0x51, 1};
    if (use_tag) {
        res = ul_read_uid(uid);
        if (res != PM3_SUCCESS) {
            return res;
        }
    } else {
        if (ulen != JOOKI_UID_LEN) {
            PrintAndLogEx(ERR, "Wrong length of UID, expect %u, got %d", JOOKI_UID_LEN, ulen);
            return PM3_EINVARG;
        }
    }

    uint8_t b64[JOOKI_B64_LEN] = {0};
    memset(b64, 0, sizeof(b64));        
    jooki_encode(iv, tt, uid, b64);  
    jooki_printEx(b64, iv, tt, uid, verbose);
    return PM3_SUCCESS;
}

static int CmdHF14AJookiDecode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf jooki decode",
                  "Decode a base64-encode Jooki token in NDEF URI format",
                  "hf jooki decode -d 7WzlgEzqLgwTnWNy"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<base64>", "base64 url parameter"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int dlen = 16;
    uint8_t b64[JOOKI_B64_LEN] = {0x00};
    memset(b64, 0x0, sizeof(b64));
    CLIGetStrWithReturn(ctx, 1, b64, &dlen);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    uint8_t result[JOOKI_PLAIN_LEN] = {0};
    int res = jooki_decode(b64, result);
    if (res == PM3_SUCCESS) {
        jooki_print(b64, result, verbose);
    }
    return PM3_SUCCESS;
}

static int CmdHF14AJookiSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf jooki sim",
                  "Simulate a Jooki token.  Either `hf mfu eload` before or use `-d` param",
                  "hf jooki sim     --> using eload before\n"
                  "hf jooki sim -d 7WzlgEzqLgwTnWNy"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("d", "data", "<base64>", "base64 url parameter"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int dlen = 16;
    uint8_t b64[JOOKI_B64_LEN] = {0x00};
    memset(b64, 0x0, sizeof(b64));
    CLIGetStrWithReturn(ctx, 1, b64, &dlen);
    CLIParserFree(ctx);

    uint8_t result[JOOKI_PLAIN_LEN] = {0};
    int res = jooki_decode(b64, result);
    if (res != PM3_SUCCESS) {
        return res;
    }

    jooki_print(b64, result, false);

    // copy UID from base64 url parameter
    uint8_t uid[7] = {0};
    memcpy(uid, result + 5, 7);

    // hf mfu sim...
    uint8_t *data = calloc(144, sizeof(uint8_t));

    memcpy(data, uid, 3);
    memcpy(data + (1*4), uid + 3, 4);

    // bbc0
    data[3] = 0x88 ^ data[0] ^ data[1] ^ data[2];

    // bbc1
    data[8] = data[4] ^ data[5] ^ data[6] ^ data[7];

    // copy NDEF magic firs, skip BBC1 
    memcpy(data + (2*4) + 1, "\x48\x00\x00\xE1\x10\x12\x00", 7);

    // copy raw NDEF
    jooki_create_ndef(b64, data + (4 * 4));

    // convert plain or old mfu format to new format
    size_t datalen = 144;
    res = convert_mfu_dump_format(&data, &datalen, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Failed convert on load to new Ultralight/NTAG format");
        free(data);
        return res;
    }

    mfu_dump_t *mfu_dump = (mfu_dump_t *)data;


    memcpy(mfu_dump->version, "\x00\x04\x04\x02\x01\x00\x0F\x03", 8);
    mfu_dump->counter_tearing[2][3] = 0xBD;
    mfu_dump->pages = 0x2c;

    printMFUdumpEx(mfu_dump, mfu_dump->pages + 1, 0);

    // upload to emulator memory
    PrintAndLogEx(INFO, "Uploading to emulator memory");

    PrintAndLogEx(INFO, "." NOLF);
    // fast push mode
    conn.block_after_ACK = true;
    uint8_t blockwidth = 4, counter = 0, blockno = 0;
    while (datalen) {
        if (datalen == blockwidth) {
            // Disable fast mode on last packet
            conn.block_after_ACK = false;
        }

        if (mfEmlSetMem_xt(data + counter, blockno, 1, blockwidth) != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Cant set emul block: %3d", blockno);
            free(data);
            return PM3_ESOFT;
        }
        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);
        blockno++;
        counter += blockwidth;
        datalen -= blockwidth;
    }
    PrintAndLogEx(NORMAL, "\n");

    struct {
        uint8_t tagtype;
        uint8_t flags;
        uint8_t uid[10];
        uint8_t exitAfter;
    } PACKED payload;

    // NTAG,  7 byte UID in eloaded data.
    payload.tagtype = 7;
    payload.flags = FLAG_UID_IN_EMUL;
    payload.exitAfter = 0;
    memcpy(payload.uid, uid, sizeof(uid));

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443A_SIMULATE, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;

    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " or pm3-button to abort simulation");
    for (;;) {
        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, "User aborted");
            break;
        }

        if (WaitForResponseTimeout(CMD_HF_MIFARE_SIMULATE, &resp, 1500) == 0)
            continue;

        if (resp.status != PM3_SUCCESS) 
            break;
    }
    free(data);
    PrintAndLogEx(INFO, "Done");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf 14a list") "` to view trace log" );
    return PM3_SUCCESS;
}

static int CmdHF14AJookiWrite(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf jooki write",
                  "Write a Jooki token to a Ultralight or NTAG tag",
                  "hf jooki write -d  xxxxxxxx   ->  where x is raw NDEF from encode command"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "bytes"),
        arg_str0("p", "pwd", "<hex>", "password for authentication (EV1/NTAG 4 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int dlen = 0;
    uint8_t data[52] = {0x00};
    memset(data, 0x0, sizeof(data));
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), data, sizeof(data), &dlen);
    if (res) {
        CLIParserFree(ctx);
        PrintAndLogEx(FAILED, "Error parsing bytes");
        return PM3_EINVARG;
    }


    int plen = 0;
    uint8_t pwd[4] = {0x00};
    CLIGetHexWithReturn(ctx, 2, pwd, &plen);

    CLIParserFree(ctx);

    if (dlen != 52) {
        PrintAndLogEx(ERR, "Wrong data length. Expected 52 got %d", dlen);
        return PM3_EINVARG;
    }

    bool has_pwd = false;
    if (plen == 4) {
        has_pwd = true;
    }

    // 0 - no authentication
    // 2 - pwd  (4 bytes)
    uint8_t keytype = 0, blockno = 4, i = 0;

    while ((i * 4) < dlen) {

        uint8_t cmddata[8] = {0};
        memcpy(cmddata, data + (i * 4), 4);
        if (has_pwd) {
            memcpy(cmddata + 4, pwd, 4);
            keytype = 2;
        }
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, blockno, keytype, 0, cmddata, sizeof(cmddata));

        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
            uint8_t isOK  = resp.oldarg[0] & 0xff;
            PrintAndLogEx(SUCCESS, "Write block %d ( %s )", blockno, isOK ? _GREEN_("ok") : _RED_("fail"));
        } else {
            PrintAndLogEx(WARNING, "Command execute timeout");
        }

        blockno++;
        i++;
    }

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,             AlwaysAvailable, "This help"},
    {"encode", CmdHF14AJookiEncode,  AlwaysAvailable, "Encode Jooki token"},
    {"decode", CmdHF14AJookiDecode,  AlwaysAvailable, "Decode Jooki token"},
    {"sim",    CmdHF14AJookiSim,     IfPm3Iso14443a,  "Simulate Jooki token"},
    {"write",  CmdHF14AJookiWrite,   IfPm3Iso14443a,  "Write a Jooki token"},

    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHF_Jooki(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
