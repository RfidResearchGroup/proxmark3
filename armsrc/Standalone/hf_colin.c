//-----------------------------------------------------------------------------
// Copyright (C) Colin Brigato, 2016
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
// main code for HF Mifare aka ColinRun by Colin Brigato
//-----------------------------------------------------------------------------

#include "standalone.h" // standalone definitions

#include "hf_colin.h"
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "dbprint.h"
#include "ticks.h"
#include "util.h"
#include "commonutil.h"
#include "BigBuf.h"
#include "iso14443a.h"
#include "mifareutil.h"
#include "mifaresim.h"
#include "vtsend.h"
#include "spiffs.h"
#include "frozen.h"

#define MF1KSZ 1024
#define MF1KSZSIZE 64
#define AUTHENTICATION_TIMEOUT 848
#define HFCOLIN_LASTTAG_SYMLINK "hf_colin/lasttag.bin"
#define HFCOLIN_SCHEMAS_JSON "hf_colin/schemas.json"

/* Example jsonconfig file schemas.json : (array !)
[{
  "name": "UrmetCaptive",
  "trigger": "0x8829da9daf76",
  "keysA": [
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76"
  ],
  "keysB": [
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76",
    "0x8829da9daf76"
  ]
},{
  "name": "Noralsy",
...

]

*/

static uint8_t colin_cjuid[10];
static uint32_t colin_cjcuid;
static iso14a_card_select_t colin_p_card;
static int colin_currline;
static int colin_currfline;
static int colin_curlline;

// TODO : Implement fast read of KEYS like in RFIdea
// also http://ext.delaat.net/rp/2015-2016/p04/report.pdf

// Colin's VIGIKPWN sniff/simulate/clone repeat routine for HF Mifare

static const uint8_t colin_is_hex[] = {
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0,
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0,
    0, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0,
    0, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0,
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0,
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0,
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0,
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0
};

static uint64_t hex2i(const char *s) {
    uint64_t val = 0;
    if (s == NULL || s[0] == 0)
        return 0;
    if (s[1] == 'x')
        s += 2;
    else if (*s == 'x')
        s++;
    while (colin_is_hex[(uint8_t)*s])
        val = (val << 4) | (colin_is_hex[(uint8_t) * (s++)] - 1);
    return val;
}

/*char *noralsy2test =
    "{\"name\":\"noralsy2\",\"trigger\":\"0x414C41524F4E\",\"keysA\":[\"0x414C41524F4E\",\"0x414C41524F4E\","
    "\"0x414C41524F4E\","
    "\"0x414C41524F4E\",\"0x414C41524F4E\",\"0x414C41524F4E\",\"0x414C41524F4E\",\"0x414C41524F4E\","
    "\"0x414C41524F4E\",\"0x414C41524F4E\","
    "\"0x414C41524F4E\",\"0x414C41524F4E\",\"0x414C41524F4E\",\"0x414C41524F4E\",\"0x414C41524F4E\","
    "\"0x414C41524F4E\"],\"keysB\":["
    "\"0x424C41524F4E\",\"0x424C41524F4E\",\"0x424C41524F4E\",\"0x424C41524F4E\",\"0x424C41524F4E\","
    "\"0x424C41524F4E\",\"0x424C41524F4E\","
    "\"0x424C41524F4E\",\"0x424C41524F4E\",\"0x424C41524F4E\",\"0x424C41524F4E\",\"0x424C41524F4E\","
    "\"0x424C41524F4E\",\"0x424C41524F4E\","
    "\"0x424C41524F4E\",\"0x424C41524F4E\"]}";*/

/*char *urmetcaptive2test =
    "{\"name\":\"urmetcaptive2\",\"trigger\":\"0x8829da9daf76\",\"keysA\":[\"0x8829da9daf76\",\"0x8829da9daf76\","
    "\"0x8829da9daf76\","
    "\"0x8829da9daf76\",\"0x8829da9daf76\",\"0x8829da9daf76\",\"0x8829da9daf76\",\"0x8829da9daf76\","
    "\"0x8829da9daf76\",\"0x8829da9daf76\","
    "\"0x8829da9daf76\",\"0x8829da9daf76\",\"0x8829da9daf76\",\"0x8829da9daf76\",\"0x8829da9daf76\","
    "\"0x8829da9daf76\"],\"keysB\":["
    "\"0x8829da9daf76\",\"0x8829da9daf76\",\"0x8829da9daf76\",\"0x8829da9daf76\",\"0x8829da9daf76\","
    "\"0x8829da9daf76\",\"0x8829da9daf76\","
    "\"0x8829da9daf76\",\"0x8829da9daf76\",\"0x8829da9daf76\",\"0x8829da9daf76\",\"0x8829da9daf76\","
    "\"0x8829da9daf76\",\"0x8829da9daf76\","
    "\"0x8829da9daf76\",\"0x8829da9daf76\"]}";*/

typedef struct {
    uint8_t name[32];
    uint64_t trigger;
    uint64_t keysA[16];
    uint64_t keysB[16];
} MFC1KSchema_t;

#define MAX_SCHEMAS 4

static void scan_keys(const char *str, int len, uint64_t *user_data) {
    struct json_token t;
    int i;
    char ks[32];
    for (i = 0; json_scanf_array_elem(str, len, "", i, &t) > 0; i++) {
        sprintf(ks, "%.*s", t.len, t.ptr);
        user_data[i] = hex2i(ks);
    }
}

static MFC1KSchema_t colin_Schemas[MAX_SCHEMAS];

/*MFC1KSchema_t Noralsy = {
    .name = "Noralsy",
    .trigger = 0x414c41524f4e,
    .keysA = {0x414c41524f4e, 0x414c41524f4e, 0x414c41524f4e, 0x414c41524f4e, 0x414c41524f4e, 0x414c41524f4e,
              0x414c41524f4e, 0x414c41524f4e, 0x414c41524f4e, 0x414c41524f4e, 0x414c41524f4e, 0x414c41524f4e,
              0x414c41524f4e, 0x414c41524f4e, 0x414c41524f4e, 0x414c41524f4e},
    .keysB = {0x424c41524f4e, 0x424c41524f4e, 0x424c41524f4e, 0x424c41524f4e, 0x424c41524f4e, 0x424c41524f4e,
              0x424c41524f4e, 0x424c41524f4e, 0x424c41524f4e, 0x424c41524f4e, 0x424c41524f4e, 0x424c41524f4e,
              0x424c41524f4e, 0x424c41524f4e, 0x424c41524f4e, 0x424c41524f4e}};

MFC1KSchema_t InfiHexact = {.name = "Infineon/Hexact",
                          .trigger = 0x484558414354,
                          .keysA = {0x484558414354, 0x484558414354, 0x484558414354, 0x484558414354, 0x484558414354,
                                    0x484558414354, 0x484558414354, 0x484558414354, 0x484558414354, 0x484558414354,
                                    0x484558414354, 0x484558414354, 0x484558414354, 0x484558414354, 0x484558414354,
                                    0x484558414354},
                          .keysB = {0xa22ae129c013, 0x49fae4e3849f, 0x38fcf33072e0, 0x8ad5517b4b18, 0x509359f131b1,
                                    0x6c78928e1317, 0xaa0720018738, 0xa6cac2886412, 0x62d0c424ed8e, 0xe64a986a5d94,
                                    0x8fa1d601d0a2, 0x89347350bd36, 0x66d2b7dc39ef, 0x6bc1e1ae547d, 0x22729a9bd40f}};
*/

/*MFC1KSchema_t UrmetCaptive = {
    .name = "Urmet Captive",
    .trigger = 0x8829da9daf76,
    .keysA = {0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76,
              0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76,
              0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76},
    .keysB = {0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76,
              0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76,
              0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76, 0x8829da9daf76}};
*/

static int colin_total_schemas = 0;

static void add_schema(MFC1KSchema_t *p, MFC1KSchema_t a, int *schemas_counter) {
    if (*schemas_counter < MAX_SCHEMAS) {
        p[*schemas_counter] = a;
        *schemas_counter += 1;
    }
}
/*
static void delete_schema(MFC1KSchema_t *p, int *schemas_counter, int index) {
    if (*schemas_counter > 0 && index < *schemas_counter && index > -1) {
        int last_index = *schemas_counter - 1;
        for (int i = index; i < last_index; i++) {
            p[i] = p[i + 1];
        }
        *schemas_counter -= 1;
    }
}
*/
static void cjSetCursFRight(void) {
    vtsend_cursor_position(NULL, 98, (colin_currfline));
    colin_currfline++;
}

static void cjSetCursRight(void) {
    vtsend_cursor_position(NULL, 59, (colin_currline));
    colin_currline++;
}

static void cjSetCursLeft(void) {
    vtsend_cursor_position(NULL, 0, (colin_curlline));
    colin_curlline++;
}

static void cjTabulize(void) { DbprintfEx(FLAG_RAWPRINT, "\t\t\t"); }

static char *ReadSchemasFromSPIFFS(char *filename) {
    SpinOff(0);

    int changed = rdv40_spiffs_lazy_mount();
    uint32_t size = size_in_spiffs((char *)filename);
    uint8_t *mem = BigBuf_malloc(size);
    rdv40_spiffs_read_as_filetype((char *)filename, (uint8_t *)mem, size, RDV40_SPIFFS_SAFETY_SAFE);

    if (changed) {
        rdv40_spiffs_lazy_unmount();
    }
    SpinOff(0);
    return (char *)mem;
}

static void add_schemas_from_json_in_spiffs(char *filename) {

    char *jsonfile = ReadSchemasFromSPIFFS((char *)filename);

    int i, len = strlen(jsonfile);
    struct json_token t;
    for (i = 0; json_scanf_array_elem(jsonfile, len, "", i, &t) > 0; i++) {
        char *tmpname;
        char *tmptrigger;
        MFC1KSchema_t tmpscheme;
        json_scanf(t.ptr, t.len, "{ name:%Q, trigger:%Q, keysA:%M, keysB:%M}", &tmpname, &tmptrigger, scan_keys,
                   &tmpscheme.keysA, scan_keys, &tmpscheme.keysB);
        memcpy(tmpscheme.name, tmpname, 32);
        tmpscheme.trigger = hex2i(tmptrigger);
        add_schema(colin_Schemas, tmpscheme, &colin_total_schemas);
        DbprintfEx(FLAG_NEWLINE, "Schema loaded : %s", tmpname);
        cjSetCursLeft();
    }
}

static void ReadLastTagFromFlash(void) {
    SpinOff(0);
    LED_A_ON();
    LED_B_ON();
    LED_C_ON();
    LED_D_ON();
    uint16_t len = 1024;
    size_t size = len;

    DbprintfEx(FLAG_NEWLINE, "Button HELD ! Using LAST Known TAG for Simulation...");
    cjSetCursLeft();

    uint8_t *mem = BigBuf_malloc(size);

    // this one will handle filetype (symlink or not) and resolving by itself
    rdv40_spiffs_read_as_filetype((char *)HFCOLIN_LASTTAG_SYMLINK, (uint8_t *)mem, len, RDV40_SPIFFS_SAFETY_SAFE);

    // copy 64blocks (16bytes) starting w block0, to emulator mem.
    emlSetMem_xt(mem, 0, 64, 16);

    DbprintfEx(FLAG_NEWLINE, "[OK] Last tag recovered from FLASHMEM set to emulator");
    cjSetCursLeft();
    SpinOff(0);
    return;
}

void WriteTagToFlash(uint32_t uid, size_t size) {
    SpinOff(0);
    LED_A_ON();
    LED_B_ON();
    LED_C_ON();
    LED_D_ON();

    uint32_t len = size;
    uint8_t data[(size * (16 * 64)) / 1024];

    emlGetMem(data, 0, (size * 64) / 1024);

    char dest[SPIFFS_OBJ_NAME_LEN];
    uint8_t buid[4];
    num_to_bytes(uid, 4, buid);
    sprintf(dest, "hf_colin/mf_%02x%02x%02x%02x.bin", buid[0], buid[1], buid[2], buid[3]);

    // TODO : by using safe function for multiple writes we are both breaking cache mechanisms and making useless and
    // unoptimized mount operations we should manage at out level the mount status before and after the whole
    // standalone mode
    rdv40_spiffs_write((char *)dest, (uint8_t *)data, len, RDV40_SPIFFS_SAFETY_SAFE);
    // lastag will only contain filename/path to last written tag file so we don't loose time or space.
    rdv40_spiffs_make_symlink((char *)dest, (char *)HFCOLIN_LASTTAG_SYMLINK, RDV40_SPIFFS_SAFETY_SAFE);

    DbprintfEx(FLAG_NEWLINE, "[OK] TAG WRITTEN TO FLASH !");
    cjSetCursLeft();
    SpinOff(0);
    return;
}

void ModInfo(void) {
    DbpString("  HF Mifare ultra fast sniff/sim/clone - aka VIGIKPWN (Colin Brigato)");
}

void RunMod(void) {
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    Dbprintf(">>  HF Mifare ultra fast sniff/sim/clone  a.k.a VIGIKPWN Started  <<");

    // turn off all debugging.
    g_dbglevel = DBG_NONE;

    // add_schema(colin_Schemas, Noralsy, &colin_total_schemas);
    // add_schema(colin_Schemas, InfiHexact, &colin_total_schemas);
    // add_schema_from_json_in_spiffs((char *)HFCOLIN_URMETCAPTIVE_JSON);
    // add_schema(colin_Schemas, UrmetCaptive, &colin_total_schemas);

    colin_currline = 20;
    colin_curlline = 20;
    colin_currfline = 24;
    memset(colin_cjuid, 0, sizeof(colin_cjuid));
    colin_cjcuid = 0;
    uint8_t sectorsCnt = (MF1KSZ / MF1KSZSIZE);
    uint64_t key64;    // Defines current key
    uint8_t *keyBlock; // Where the keys will be held in memory.

    /* VIGIK EXPIRED DUMP FOR STUDY
    Sector 0
    121C7F730208040001FA33F5CB2D021D
    44001049164916491649000000000000
    00000000000000000000000000000000
    A0A1A2A3A4A579678800010203040506
    Sector 1
    0F000000000000000000000000000000
    AA0700002102080000740C110600AF13
    000000000000000001740C1108220000
    314B4947495679678800010203040506
    Sector 2
    24E572B923A3D243B402D60CAB576956
    216D6501FC8618B6C426762511AC2DEE
    25BF4CEC3618D0BAB3A6E9210D887746
    314B4947495679678800010203040506
    Sector 3
    0FBC41A5D95398E76A1B2029E8EA9735
    088BA2CE732653D0C1147596AFCF94D7
    77B4D91F0442182273A29DEAF7A2D095
    314B4947495679678800010203040506
    Sector 4
    4CEE715866E508CDBC95C640EC9D1E58
    E800457CF8B079414E1B45DD3E6C9317
    77B4D91F0442182273A29DEAF7A2D095
    314B4947495679678800010203040506
    010203040506  0
    Sector 5-0F
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    FFFFFFFFFFFFFF078069FFFFFFFFFFFF
    KEY A : 1KGIV ;
    ACCBITS : 796788[00]+VALUE
    */

// ----------------------------
//   Set of keys to be used.
//  This should cover ~98% of
//  French VIGIK system @2017
// ----------------------------

    const uint64_t mfKeys[] = {
        0xffffffffffff, // TRANSPORTS
        0x000000000000, // Blankkey
        0x484558414354, // INFINEONON A / 0F SEC B / INTRATONE / HEXACT...
        0x414c41524f4e, // ALARON NORALSY
        0x424c41524f4e, // BLARON NORALSY
        0x4a6352684677, // COMELIT A General Key  / 08 [2] 004
        0x536653644c65, // COMELIT B General Key  / 08 [2] 004
        0x8829da9daf76, // URMET CAPTIV IF A => ALL A/B / BTICINO
        0x314B49474956, // "1KIGIV" VIGIK'S SERVICE BADGE A KEY
        0xa0a1a2a3a4a5, // PUBLIC BLOC0 BTICINO MAD ACCESS
        0x021209197591, // BTCINO UNDETERMINED SPREAKD 0x01->0x13 key
        0x010203040506, // VIGIK's B Derivative
        0xb0b1b2b3b4b5, // NA DERIVATE B # 1
        0xaabbccddeeff, // NA DERIVATE B # 1
        0x4d3a99c351dd, // NA DERIVATE B # 1
        0x1a982c7e459a, // NA DERIVATE B # 1
        0xd3f7d3f7d3f7, // NA DERIVATE B # 1
        0x714c5c886e97, // NA DERIVATE B # 1
        0x587ee5f9350f, // NA DERIVATE B # 1
        0xa0478cc39091, // NA DERIVATE B # 1
        0x533cb6c723f6, // NA DERIVATE B # 1
        0x8fd0a4f256e9, // NA DERIVATE B # 1
        0xa22ae129c013, // INFINEON B 00
        0x49fae4e3849f, // INFINEON B 01
        0x38fcf33072e0, // INFINEON B 02
        0x8ad5517b4b18, // INFINEON B 03
        0x509359f131b1, // INFINEON B 04
        0x6c78928e1317, // INFINEON B 05
        0xaa0720018738, // INFINEON B 06
        0xa6cac2886412, // INFINEON B 07
        0x62d0c424ed8e, // INFINEON B 08
        0xe64a986a5d94, // INFINEON B 09
        0x8fa1d601d0a2, // INFINEON B 0A
        0x89347350bd36, // INFINEON B 0B
        0x66d2b7dc39ef, // INFINEON B 0C
        0x6bc1e1ae547d, // INFINEON B 0D
        0x22729a9bd40f  // INFINEON B 0E
    };

    // Can remember something like that in case of Bigbuf
    keyBlock = BigBuf_malloc(ARRAYLEN(mfKeys) * 6);
    int mfKeysCnt = ARRAYLEN(mfKeys);

    for (int mfKeyCounter = 0; mfKeyCounter < mfKeysCnt; mfKeyCounter++) {
        num_to_bytes(mfKeys[mfKeyCounter], 6, (uint8_t *)(keyBlock + mfKeyCounter * 6));
    }

    // TODO : remember why we actually had need to initialize this array in such specific case
    //   and why not a simple memset abuse to 0xffize the whole space in one go ?
    // uint8_t foundKey[2][40][6]; //= [ {0xff} ]; /* C99 abusal 6.7.8.21
    uint8_t foundKey[2][40][6];
    for (uint16_t i = 0; i < 2; i++) {
        for (uint16_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
            foundKey[i][sectorNo][0] = 0xFF;
            foundKey[i][sectorNo][1] = 0xFF;
            foundKey[i][sectorNo][2] = 0xFF;
            foundKey[i][sectorNo][3] = 0xFF;
            foundKey[i][sectorNo][4] = 0xFF;
            foundKey[i][sectorNo][5] = 0xFF;
        }
    }

    int key = -1;
    bool err = 0;
    bool trapped = 0;
    bool allKeysFound = true;
    uint32_t size = mfKeysCnt;

    // banner:
    vtsend_reset(NULL);
    DbprintfEx(FLAG_NEWLINE, "\r\n%s", clearTerm);
    DbprintfEx(FLAG_NEWLINE, "%s%s%s", _XCYAN_, sub_banner, _XWHITE_);
    DbprintfEx(FLAG_NEWLINE, "%s>>%s C.J.B's MifareFastPwn Started\r\n", _XRED_, _XWHITE_);

    colin_currline = 20;
    colin_curlline = 20;
    colin_currfline = 24;
    cjSetCursLeft();

    add_schemas_from_json_in_spiffs((char *)HFCOLIN_SCHEMAS_JSON);

failtag:

    vtsend_cursor_position_save(NULL);
    vtsend_set_attribute(NULL, 1);
    vtsend_set_attribute(NULL, 5);
    DbprintfEx(FLAG_NEWLINE, "\t\t\t[ Waiting For Tag ]");
    vtsend_set_attribute(NULL, 0);

    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    SpinOff(50);
    LED_A_ON();

    while (!iso14443a_select_card(colin_cjuid, &colin_p_card, &colin_cjcuid, true, 0, true)) {
        WDT_HIT();
        if (BUTTON_HELD(10) == BUTTON_HOLD) {
            WDT_HIT();
            DbprintfEx(FLAG_NEWLINE, "\t\t\t[    READING FLASH   ]");
            ReadLastTagFromFlash();
            goto readysim;
        }
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
        SpinDelay(500);
        LED_A_INV();
    }

    SpinOff(50);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    vtsend_cursor_position_restore(NULL);
    DbprintfEx(FLAG_NEWLINE, "\t\t\t%s[   GOT a Tag !   ]%s", _XGREEN_, _XWHITE_);
    cjSetCursLeft();
    DbprintfEx(FLAG_NEWLINE, "\t\t\t       `---> Breaking keys ---->");
    cjSetCursRight();

    DbprintfEx(FLAG_NEWLINE, "\t%sGOT TAG :%s %08x%s", _XRED_, _XCYAN_, colin_cjcuid, _XWHITE_);

    if (colin_cjcuid == 0) {
        cjSetCursLeft();
        DbprintfEx(FLAG_NEWLINE, "%s>>%s BUG: 0000_CJCUID! Retrying...", _XRED_, _XWHITE_);
        SpinErr(LED_A, 100, 8);
        goto failtag;
    }

    SpinOff(50);
    LED_B_ON();
    cjSetCursRight();
    DbprintfEx(FLAG_NEWLINE, "--------+--------------------+-------");
    cjSetCursRight();
    DbprintfEx(FLAG_NEWLINE, " SECTOR |        KEY         |  A/B  ");
    cjSetCursRight();
    DbprintfEx(FLAG_NEWLINE, "--------+--------------------+-------");

    uint32_t start_time = GetTickCount();
    uint32_t delta_time = 0;

    // ---------------------------------------------------------------------------
    // WE SHOULD FIND A WAY TO GET UID TO AVOID THIS "TESTRUN"
    // --------------------------------------------------------
    // + HERE IS TO BE THOUGHT AS ONLY A KEY SHOULD BE CHECK
    // `-+ THEN WE FILL EMULATOR WITH KEY
    // `-+ WHEN WE FILL EMULATOR CARD WITH A KEY
    // `-+ IF THERE IS ANY FAIL DURING ANY POINT, WE START BACK CHECKING B KEYS
    // `-+ THEN FILL EMULATOR WITH B KEEY
    // `-+ THEN EMULATOR WITH CARD WITH B KEY
    // `-+ IF IT HAS FAILED OF ANY OF SORT THEN WE ARE MARRON LIKE POMALO.
    // ----------------------------------------------------------------------------
    // AN EVEN BETTER IMPLEMENTATION IS TO CHECK EVERY KEY FOR SECTOR 0 KEY A
    // THEN IF FOUND CHECK THE SAME KEY FOR NEXT SECTOR ONLY KEY A
    // THEN IF FAIL CHECK EVERY SECTOR A KEY FOR EVERY OTHER KEY BUT NOT THE BLOCK
    // 0 KEY
    // THEN TRY TO READ B KEYS FROM KNOWN A KEYS
    // IF FAIL, CHECK SECTOR 0 B KEY WITH SECTOR 0 A KEY
    // THEN IF FOUND CHECK EVERY SECTOR FOR SAME B KEY
    // ELSE IF FAIL CHECK EVERY KEY FOR SECTOR 0 KEY B
    // THEN IF FOUND CHECK SAME KEY FOR ONLY NEXT SECTOR KEY B (PROBABLE A KEY IS
    // SAME FOR EVERY SECTOR AND B KEY IS SAME FOR EVERY SECTOR WITH JUST A vs B
    // DERIVATION
    // THEN IF B KEY IS NOT OF THIS SCHEME CHECK EVERY REMAINING B KEYED SECTOR
    // WITH EVERY REMAINING KEYS, BUT DISCARDING ANY DEFAULT TRANSPORT KEYS.
    // -----------------------------------------------------------------------------
    // also we could avoid first UID check for every block

    // then let's expose this optimal case of well known vigik schemes :
    for (uint8_t type = 0; type < 2 && !err && !trapped; type++) {
        for (int sec = 0; sec < sectorsCnt && !err && !trapped; ++sec) {
            key = cjat91_saMifareChkKeys(sec * 4, type, NULL, size, &keyBlock[0], &key64);

            if (key == -1) {
                err = 1;
                allKeysFound = false;
                // used in portable imlementation on microcontroller: it reports back the fail and open the
                // standalone lock reply_ng(CMD_CJB_FSMSTATE_MENU, NULL, 0);
                break;
            } else if (key == -2) {
                err = 1; // Can't select card.
                allKeysFound = false;
                // reply_old(CMD_CJB_FSMSTATE_MENU, 0, 0, 0, 0, 0);
                break;
            } else {
                /*  BRACE YOURSELF : AS LONG AS WE TRAP A KNOWN KEY, WE STOP CHECKING AND ENFORCE KNOWN SCHEMES */
                // uint8_t tosendkey[13];
                char tosendkey[13];
                num_to_bytes(key64, 6, foundKey[type][sec]);
                cjSetCursRight();
                DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %012" PRIx64 " ; TYP: %i", sec, key64, type);
                /*reply_old(CMD_CJB_INFORM_CLIENT_KEY, 12, sec, type, tosendkey, 12);*/

                for (int i = 0; i < colin_total_schemas; i++) {
                    if (key64 == colin_Schemas[i].trigger) {

                        cjSetCursLeft();
                        DbprintfEx(FLAG_NEWLINE, "%s>>>>>>>>>>>>!*STOP*!<<<<<<<<<<<<<<%s", _XRED_, _XWHITE_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "    .TAG SEEMS %sDETERMINISTIC%s.     ", _XGREEN_, _XWHITE_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "%sDetected: %s %s%s", _XORANGE_, _XCYAN_, colin_Schemas[i].name, _XWHITE_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "...%s[%sKey_derivation_schemeTest%s]%s...", _XYELLOW_, _XGREEN_,
                                   _XYELLOW_, _XGREEN_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "%s>>>>>>>>>>>>!*DONE*!<<<<<<<<<<<<<<%s", _XGREEN_, _XWHITE_);

                        uint16_t t = 0;
                        for (uint16_t s = 0; s < sectorsCnt; s++) {
                            num_to_bytes(colin_Schemas[i].keysA[s], 6, foundKey[t][s]);
                            sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][s][0], foundKey[t][s][1],
                                    foundKey[t][s][2], foundKey[t][s][3], foundKey[t][s][4], foundKey[t][s][5]);
                            cjSetCursRight();
                            DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", s, tosendkey, t);
                        }
                        t = 1;
                        for (uint16_t s = 0; s < sectorsCnt; s++) {
                            num_to_bytes(colin_Schemas[i].keysB[s], 6, foundKey[t][s]);
                            sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][s][0], foundKey[t][s][1],
                                    foundKey[t][s][2], foundKey[t][s][3], foundKey[t][s][4], foundKey[t][s][5]);
                            cjSetCursRight();
                            DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", s, tosendkey, t);
                        }
                        trapped = 1;
                        break;
                    }
                }
                /* etc etc for testing schemes quick schemes */
            }
        }
    }

    if (!allKeysFound) {
        cjSetCursLeft();
        cjTabulize();
        DbprintfEx(FLAG_NEWLINE, "%s[ FAIL ]%s\r\n->did not found all the keys :'(", _XRED_, _XWHITE_);
        cjSetCursLeft();
        SpinErr(LED_B, 100, 8);
        SpinOff(100);
        return;
    }

    // Settings keys to emulator
    emlClearMem();
    uint8_t mblock[16];
    for (uint8_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
        emlGetMem(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1);
        for (uint8_t t = 0; t < 2; t++) {
            memcpy(mblock + t * 10, foundKey[t][sectorNo], 6);
        }
        emlSetMem_xt(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1, 16);
    }
    cjSetCursLeft();

    DbprintfEx(FLAG_NEWLINE, "%s>>%s Setting Keys->Emulator MEM...[%sOK%s]", _XYELLOW_, _XWHITE_, _XGREEN_, _XWHITE_);

    // filling TAG to emulator
    int filled;
    cjSetCursLeft();

    DbprintfEx(FLAG_NEWLINE, "%s>>%s Filling Emulator <- from A keys...", _XYELLOW_, _XWHITE_);
    filled = e_MifareECardLoad(sectorsCnt, 0);
    if (filled != PM3_SUCCESS) {
        cjSetCursLeft();

        DbprintfEx(FLAG_NEWLINE, "%s>>%s W_FAILURE ! %sTrying fallback B keys....", _XRED_, _XORANGE_, _XWHITE_);

        // no trace, no dbg
        filled = e_MifareECardLoad(sectorsCnt, 1);
        if (filled != PM3_SUCCESS) {
            cjSetCursLeft();
            DbprintfEx(FLAG_NEWLINE, "FATAL:EML_FALLBACKFILL_B");
            SpinErr(LED_C, 100, 8);
            SpinOff(100);
            return;
        }
    }

    delta_time = GetTickCountDelta(start_time);
    cjSetCursLeft();

    DbprintfEx(FLAG_NEWLINE, "%s>>%s Time for VIGIK break :%s%dms%s", _XGREEN_, _XWHITE_, _XYELLOW_, delta_time,
               _XWHITE_);

    vtsend_cursor_position_save(NULL);
    vtsend_set_attribute(NULL, 1);
    vtsend_set_attribute(NULL, 5);
    cjTabulize();
    DbprintfEx(FLAG_NEWLINE, "[    WRITING FLASH   ]");
    cjSetCursLeft();
    cjSetCursLeft();

    WriteTagToFlash(colin_cjcuid, 1024);

readysim:
    cjSetCursLeft();

    DbprintfEx(FLAG_NEWLINE, "-> We launch Emulation ->");
    cjSetCursLeft();

    DbprintfEx(FLAG_NEWLINE, "%s!> HOLD ON : %s When you'll click, simm will stop", _XRED_, _XWHITE_);
    cjSetCursLeft();

    DbprintfEx(FLAG_NEWLINE,
               "Then %s immediately %s we'll try to %s dump our emulator state%s \r\nin a %s chinese tag%s", _XRED_,
               _XWHITE_, _XYELLOW_, _XWHITE_, _XCYAN_, _XWHITE_);
    cjSetCursLeft();
    cjSetCursLeft();

    cjTabulize();

    DbprintfEx(FLAG_NEWLINE, "[    SIMULATION   ]");
    vtsend_set_attribute(NULL, 0);

    SpinOff(100);
    LED_C_ON();

    /*
    uint16_t flags = 0;
    switch (colin_p_card.uidlen) {
        case 10:
            flags = FLAG_10B_UID_IN_DATA;
            break;
        case 7:
            flags = FLAG_7B_UID_IN_DATA;
            break;
        case 4:
            flags = FLAG_4B_UID_IN_DATA;
            break;
        default:
            flags = FLAG_UID_IN_EMUL;
            break;
    }
    // Use UID, SAK, ATQA from EMUL, if uid not defined
    if ((flags & (FLAG_4B_UID_IN_DATA | FLAG_7B_UID_IN_DATA | FLAG_10B_UID_IN_DATA)) == 0) {
       flags |= FLAG_UID_IN_EMUL;
    }
    flags |= FLAG_MF_1K;
    if ((flags & (FLAG_4B_UID_IN_DATA | FLAG_7B_UID_IN_DATA | FLAG_10B_UID_IN_DATA)) == 0) {
        flags |= FLAG_UID_IN_EMUL;
     }
    flags = 0x10;
    */
    uint16_t flags = FLAG_UID_IN_EMUL;
    DbprintfEx(FLAG_NEWLINE, "\n\n\n\n\n\n\n\nn\n\nn\n\n\nflags: %d (0x%02x)", flags, flags);
    cjSetCursLeft();
    SpinOff(1000);
    Mifare1ksim(flags, 0, colin_cjuid, 0, 0);
    LED_C_OFF();
    SpinOff(50);
    vtsend_cursor_position_restore(NULL);
    DbprintfEx(FLAG_NEWLINE, "[   SIMUL ENDED   ]%s", _XGREEN_, _XWHITE_);
    cjSetCursLeft();

    DbprintfEx(FLAG_NEWLINE, "<- We're out of Emulation");
    // END SIM

    cjSetCursLeft();

    DbprintfEx(FLAG_NEWLINE, "-> Trying a clone !");
    saMifareMakeTag();
    cjSetCursLeft();
    vtsend_cursor_position_restore(NULL);
    DbprintfEx(FLAG_NEWLINE, "%s[ CLONED? ]", _XCYAN_);

    DbprintfEx(FLAG_NEWLINE, "-> End Cloning.");
    WDT_HIT();

    // Debunk...
    cjSetCursLeft();
    cjTabulize();
    vtsend_set_attribute(NULL, 0);
    vtsend_set_attribute(NULL, 7);
    DbprintfEx(FLAG_NEWLINE, "- [ LA FIN ] -\r\n%s`-> You can take shell back :) ...", _XWHITE_);
    cjSetCursLeft();
    vtsend_set_attribute(NULL, 0);
    SpinErr(LED_D, 100, 16);
    SpinDown(75);
    SpinOff(100);
    return;
}

/* Abusive microgain on original MifareECardLoad :
 * - *datain used as error return
 * - tracing is falsed
 */
int e_MifareECardLoad(uint32_t numofsectors, uint8_t keytype) {
    uint8_t numSectors = numofsectors;
    uint8_t keyType = keytype;

    struct Crypto1State mpcs = {0, 0};
    struct Crypto1State *pcs;
    pcs = &mpcs;

    uint8_t dataoutbuf[16];
    uint8_t dataoutbuf2[16];

    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    clear_trace();
    set_tracing(false);

    bool isOK = true;

    if (!iso14443a_select_card(colin_cjuid, &colin_p_card, &colin_cjcuid, true, 0, true)) {
        isOK = false;
    }

    for (uint8_t s = 0; isOK && s < numSectors; s++) {
        uint64_t ui64Key = emlGetKey(s, keyType);
        if (s == 0) {
            if (isOK && mifare_classic_auth(pcs, colin_cjcuid, FirstBlockOfSector(s), keyType, ui64Key, AUTH_FIRST)) {
                break;
            }
        } else {
            if (isOK && mifare_classic_auth(pcs, colin_cjcuid, FirstBlockOfSector(s), keyType, ui64Key, AUTH_NESTED)) {
                isOK = false;
                break;
            }
        }

        for (uint8_t blockNo = 0; isOK && blockNo < NumBlocksPerSector(s); blockNo++) {
            if (isOK && mifare_classic_readblock(pcs, FirstBlockOfSector(s) + blockNo, dataoutbuf)) {
                isOK = false;
                break;
            };
            if (isOK) {
                if (blockNo < NumBlocksPerSector(s) - 1) {
                    emlSetMem_xt(dataoutbuf, FirstBlockOfSector(s) + blockNo, 1, 16);
                } else {
                    // sector trailer, keep the keys, set only the AC
                    emlGetMem(dataoutbuf2, FirstBlockOfSector(s) + blockNo, 1);
                    memcpy(&dataoutbuf2[6], &dataoutbuf[6], 4);
                    emlSetMem_xt(dataoutbuf2, FirstBlockOfSector(s) + blockNo, 1, 16);
                }
            }
        }
    }

    int res = mifare_classic_halt(pcs);
    (void)res;

    crypto1_deinit(pcs);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    return (isOK) ? PM3_SUCCESS : PM3_EUNDEF;
}

/* the chk function is a piwi'ed(tm) check that will try all keys for
a particular sector. also no tracing no dbg */
int cjat91_saMifareChkKeys(uint8_t blockNo, uint8_t keyType, bool clearTrace,
                           uint8_t keyCount, uint8_t *datain, uint64_t *key) {
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    set_tracing(false);

    struct Crypto1State mpcs = {0, 0};
    struct Crypto1State *pcs;
    pcs = &mpcs;

    int retval = -1;

    for (uint8_t i = 0; i < keyCount; i++) {

        /* no need for anticollision. just verify tag is still here */
        // if (!iso14443a_fast_select_card(colin_cjuid, 0)) {
        if (!iso14443a_select_card(colin_cjuid, &colin_p_card, &colin_cjcuid, true, 0, true)) {
            cjSetCursLeft();
            DbprintfEx(FLAG_NEWLINE, "%sFATAL%s : E_MF_LOSTTAG", _XRED_, _XWHITE_);
            break;
        }

        uint64_t ui64Key = bytes_to_num(datain + i * 6, 6);
        if (mifare_classic_auth(pcs, colin_cjcuid, blockNo, keyType, ui64Key, AUTH_FIRST)) {
            uint8_t dummy_answer = 0;
            ReaderTransmit(&dummy_answer, 1, NULL);
            // wait for the card to become ready again
            SpinDelayUs(AUTHENTICATION_TIMEOUT);
            continue;
        }
        *key = ui64Key;
        retval = i;
        break;
    }
    crypto1_deinit(pcs);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    return retval;
}

void saMifareMakeTag(void) {
    uint8_t cfail = 0;
    cjSetCursLeft();
    cjTabulize();
    vtsend_cursor_position_save(NULL);
    vtsend_set_attribute(NULL, 1);
    DbprintfEx(FLAG_NEWLINE, "[ CLONING ]");
    vtsend_set_attribute(NULL, 0);

    cjSetCursFRight();

    DbprintfEx(FLAG_NEWLINE, ">> Write to Special:");
    int flags = 0;
    for (int blockNum = 0; blockNum < 16 * 4; blockNum++) {
        uint8_t mblock[16];
        emlGetMem(mblock, blockNum, 1);
        // switch on field and send magic sequence
        if (blockNum == 0)
            flags = 0x08 + 0x02;

        // just write
        if (blockNum == 1)
            flags = 0;

        // Done. Magic Halt and switch off field.
        if (blockNum == 16 * 4 - 1)
            flags = 0x04 + 0x10;

        if (saMifareCSetBlock(0, flags & 0xFE, blockNum, mblock)) {
            cjSetCursFRight();
            if (colin_currfline > 53) {
                colin_currfline = 54;
            }
            DbprintfEx(FLAG_NEWLINE, "Block :%02x %sOK%s", blockNum, _XGREEN_, _XWHITE_);
            continue;
        } else {
            cjSetCursLeft();
            cjSetCursLeft();
            DbprintfEx(FLAG_NEWLINE, "`--> %sFAIL%s : CHN_FAIL_BLK_%02x_NOK", _XRED_, _XWHITE_, blockNum);
            cjSetCursFRight();
            DbprintfEx(FLAG_NEWLINE, "%s>>>>%s STOP AT %02x", _XRED_, _XWHITE_, blockNum);
            cfail++;
            break;
        }
        cjSetCursFRight();
        DbprintfEx(FLAG_NEWLINE, "%s>>>>>>>> END <<<<<<<<%s", _XYELLOW_, _XWHITE_);
    }

    if (cfail == 0) {
        SpinUp(50);
        SpinUp(50);
        SpinUp(50);
    }
}

// TODO : make this work either for a Gen1a or for a block 0 direct write all transparently
//-----------------------------------------------------------------------------
// Matt's StandAlone mod.
// Work with "magic Chinese" card (email him: ouyangweidaxian@live.cn)
//-----------------------------------------------------------------------------
int saMifareCSetBlock(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain) {
    // params
    uint8_t needWipe = arg0;
    // bit 0 - need get UID
    // bit 1 - need wupC
    // bit 2 - need HALT after sequence
    // bit 3 - need init FPGA and field before sequence
    // bit 4 - need reset FPGA and LED
    uint8_t workFlags = arg1;
    uint8_t blockNo = arg2;

    // card commands
    uint8_t wupC1[] = {0x40};
    uint8_t wupC2[] = {0x43};
    uint8_t wipeC[] = {0x41};

    // variables
    uint8_t isOK = 0;
    uint8_t d_block[18] = {0x00};

    uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE];
    uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE];

    // reset FPGA and LED
    if (workFlags & 0x08) {
        iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
        //  clear_trace();
        set_tracing(FALSE);
    }

    while (true) {
        cjSetCursLeft();

        // get UID from chip
        if (workFlags & 0x01) {
            if (!iso14443a_select_card(colin_cjuid, &colin_p_card, &colin_cjcuid, true, 0, true)) {
                DbprintfEx(FLAG_NEWLINE, "Can't select card");
                break;
            };

            if (mifare_classic_halt(NULL)) {
                DbprintfEx(FLAG_NEWLINE, "Halt error");
                break;
            };
        };

        // reset chip
        if (needWipe) {
            ReaderTransmitBitsPar(wupC1, 7, 0, NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                DbprintfEx(FLAG_NEWLINE, "wupC1 error");
                break;
            };

            ReaderTransmit(wipeC, sizeof(wipeC), NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                DbprintfEx(FLAG_NEWLINE, "wipeC error");
                break;
            };

            if (mifare_classic_halt(NULL)) {
                DbprintfEx(FLAG_NEWLINE, "Halt error");
                break;
            };
        };

        // chaud
        // write block
        if (workFlags & 0x02) {
            ReaderTransmitBitsPar(wupC1, 7, 0, NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                DbprintfEx(FLAG_NEWLINE, "wupC1 error");
                break;
            };

            ReaderTransmit(wupC2, sizeof(wupC2), NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                DbprintfEx(FLAG_NEWLINE, "wupC2 errorv");
                break;
            };
        }

        if ((mifare_sendcmd_short(NULL, CRYPT_NONE, 0xA0, blockNo, receivedAnswer, receivedAnswerPar, NULL) != 1) ||
                (receivedAnswer[0] != 0x0a)) {
            DbprintfEx(FLAG_NEWLINE, "write block send command error");
            break;
        };

        memcpy(d_block, datain, 16);
        AddCrc14A(d_block, 16);
        ReaderTransmit(d_block, sizeof(d_block), NULL);
        if ((ReaderReceive(receivedAnswer, receivedAnswerPar) != 1) || (receivedAnswer[0] != 0x0a)) {
            DbprintfEx(FLAG_NEWLINE, "write block send data error");
            break;
        };

        if (workFlags & 0x04) {
            if (mifare_classic_halt(NULL)) {
                cjSetCursFRight();

                DbprintfEx(FLAG_NEWLINE, "Halt error");
                break;
            };
        }

        isOK = 1;
        break;
    }

    if ((workFlags & 0x10) || (!isOK)) {
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    }

    return isOK;
}
