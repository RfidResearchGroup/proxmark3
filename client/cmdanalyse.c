//-----------------------------------------------------------------------------
// Copyright (C) 2016 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Analyse bytes commands
//-----------------------------------------------------------------------------
#include "cmdanalyse.h"

static int CmdHelp(const char *Cmd);

static int usage_analyse_lcr(void) {
    PrintAndLogEx(NORMAL, "Specifying the bytes of a UID with a known LRC will find the last byte value");
    PrintAndLogEx(NORMAL, "needed to generate that LRC with a rolling XOR. All bytes should be specified in HEX.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  analyse lcr [h] <bytes>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          This help");
    PrintAndLogEx(NORMAL, "           <bytes>    bytes to calc missing XOR in a LCR");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      analyse lcr 04008064BA");
    PrintAndLogEx(NORMAL, "expected output: Target (BA) requires final LRC XOR byte value: 5A");
    return 0;
}
static int usage_analyse_checksum(void) {
    PrintAndLogEx(NORMAL, "The bytes will be added with eachother and than limited with the applied mask");
    PrintAndLogEx(NORMAL, "Finally compute ones' complement of the least significant bytes");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  analyse chksum [h] [v] b <bytes> m <mask>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          This help");
    PrintAndLogEx(NORMAL, "           v          supress header");
    PrintAndLogEx(NORMAL, "           b <bytes>  bytes to calc missing XOR in a LCR");
    PrintAndLogEx(NORMAL, "           m <mask>   bit mask to limit the outpuyt");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      analyse chksum b 137AF00A0A0D m FF");
    PrintAndLogEx(NORMAL, "expected output: 0x61");
    return 0;
}
static int usage_analyse_crc(void) {
    PrintAndLogEx(NORMAL, "A stub method to test different crc implementations inside the PM3 sourcecode. Just because you figured out the poly, doesn't mean you get the desired output");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  analyse crc [h] <bytes>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          This help");
    PrintAndLogEx(NORMAL, "           <bytes>    bytes to calc crc");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      analyse crc 137AF00A0A0D");
    return 0;
}
static int usage_analyse_nuid(void) {
    PrintAndLogEx(NORMAL, "Generate 4byte NUID from 7byte UID");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  analyse hid [h] <bytes>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          This help");
    PrintAndLogEx(NORMAL, "           <bytes>  input bytes (14 hexsymbols)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      analyse nuid 11223344556677");
    return 0;
}
static int usage_analyse_a(void) {
    PrintAndLogEx(NORMAL, "Iceman's personal garbage test command");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  analyse a [h] d <bytes>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          This help");
    PrintAndLogEx(NORMAL, "           d <bytes>  bytes to send to device");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      analyse a d 137AF00A0A0D");
    return 0;
}

static uint8_t calculateLRC(uint8_t *bytes, uint8_t len) {
    uint8_t LRC = 0;
    for (uint8_t i = 0; i < len; i++)
        LRC ^= bytes[i];
    return LRC;
}
/*
static uint16_t matrixadd ( uint8_t* bytes, uint8_t len){
      -----------
 0x9c | 1001 1100
 0x97 | 1001 0111
 0x72 | 0111 0010
 0x5e | 0101 1110
 -----------------
        C32F 9d74

    return 0;
}
*/
/*
static uint16_t shiftadd ( uint8_t* bytes, uint8_t len){
    return 0;
}
*/
static uint16_t calcSumCrumbAdd(uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum += CRUMB(bytes[i], 0);
        sum += CRUMB(bytes[i], 2);
        sum += CRUMB(bytes[i], 4);
        sum += CRUMB(bytes[i], 6);
    }
    sum &= mask;
    return sum;
}
static uint16_t calcSumCrumbAddOnes(uint8_t *bytes, uint8_t len, uint32_t mask) {
    return (~calcSumCrumbAdd(bytes, len, mask) & mask);
}
static uint16_t calcSumNibbleAdd(uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum += NIBBLE_LOW(bytes[i]);
        sum += NIBBLE_HIGH(bytes[i]);
    }
    sum &= mask;
    return sum;
}
static uint16_t calcSumNibbleAddOnes(uint8_t *bytes, uint8_t len, uint32_t mask) {
    return (~calcSumNibbleAdd(bytes, len, mask) & mask);
}
static uint16_t calcSumCrumbXor(uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum ^= CRUMB(bytes[i], 0);
        sum ^= CRUMB(bytes[i], 2);
        sum ^= CRUMB(bytes[i], 4);
        sum ^= CRUMB(bytes[i], 6);
    }
    sum &= mask;
    return sum;
}
static uint16_t calcSumNibbleXor(uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum ^= NIBBLE_LOW(bytes[i]);
        sum ^= NIBBLE_HIGH(bytes[i]);
    }
    sum &= mask;
    return sum;
}
static uint16_t calcSumByteXor(uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum ^= bytes[i];
    }
    sum &= mask;
    return sum;
}
static uint16_t calcSumByteAdd(uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum += bytes[i];
    }
    sum &= mask;
    return sum;
}
// Ones complement
static uint16_t calcSumByteAddOnes(uint8_t *bytes, uint8_t len, uint32_t mask) {
    return (~calcSumByteAdd(bytes, len, mask) & mask);
}

static uint16_t calcSumByteSub(uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum -= bytes[i];
    }
    sum &= mask;
    return sum;
}
static uint16_t calcSumByteSubOnes(uint8_t *bytes, uint8_t len, uint32_t mask) {
    return (~calcSumByteSub(bytes, len, mask) & mask);
}
static uint16_t calcSumNibbleSub(uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum -= NIBBLE_LOW(bytes[i]);
        sum -= NIBBLE_HIGH(bytes[i]);
    }
    sum &= mask;
    return sum;
}
static uint16_t calcSumNibbleSubOnes(uint8_t *bytes, uint8_t len, uint32_t mask) {
    return (~calcSumNibbleSub(bytes, len, mask) & mask);
}

// BSD shift checksum 8bit version
static uint16_t calcBSDchecksum8(uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum = ((sum & 0xFF) >> 1) | ((sum & 0x1) << 7);   // rotate accumulator
        sum += bytes[i];  // add next byte
        sum &= 0xFF;  //
    }
    sum &= mask;
    return sum;
}
// BSD shift checksum 4bit version
static uint16_t calcBSDchecksum4(uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum = ((sum & 0xF) >> 1) | ((sum & 0x1) << 3);   // rotate accumulator
        sum += NIBBLE_HIGH(bytes[i]);  // add high nibble
        sum &= 0xF;  //
        sum = ((sum & 0xF) >> 1) | ((sum & 0x1) << 3);   // rotate accumulator
        sum += NIBBLE_LOW(bytes[i]);  // add low nibble
        sum &= 0xF;  //
    }
    sum &= mask;
    return sum;
}

// measuring LFSR maximum length
static int CmdAnalyseLfsr(const char *Cmd) {

    uint16_t lfsr;  /* Any nonzero start state will work. */
    uint8_t iv = param_get8ex(Cmd, 0, 0, 16);
    uint8_t find = param_get8ex(Cmd, 1, 0, 16);

    PrintAndLogEx(NORMAL, "LEGIC LFSR IV 0x%02X: \n", iv);
    PrintAndLogEx(NORMAL, " bit# | lfsr | ^0x40 |  0x%02X ^ lfsr \n", find);

    for (uint8_t i = 0x01; i < 0x30; i += 1) {
        legic_prng_init(iv);
        legic_prng_forward(i);
        lfsr = legic_prng_get_bits(12);
        PrintAndLogEx(NORMAL, " %02X | %03X | %03X | %03X \n", i, lfsr, 0x40 ^ lfsr, find ^ lfsr);
    }
    return 0;
}
static int CmdAnalyseLCR(const char *Cmd) {
    uint8_t data[50];
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_analyse_lcr();

    int len = 0;
    switch (param_gethex_to_eol(Cmd, 0, data, sizeof(data), &len)) {
        case 1:
            PrintAndLogEx(WARNING, "Invalid HEX value.");
            return 1;
        case 2:
            PrintAndLogEx(WARNING, "Too many bytes.  Max %d bytes", sizeof(data));
            return 1;
        case 3:
            PrintAndLogEx(WARNING, "Hex must have even number of digits.");
            return 1;
    }
    uint8_t finalXor = calculateLRC(data, len);
    PrintAndLogEx(NORMAL, "Target [%02X] requires final LRC XOR byte value: 0x%02X", data[len - 1], finalXor);
    return 0;
}
static int CmdAnalyseCRC(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_analyse_crc();

    int len = strlen(Cmd);
    if (len & 1) return usage_analyse_crc();

    // add 1 for null terminator.
    uint8_t *data = calloc(len + 1,  sizeof(uint8_t));
    if (!data) return 1;

    if (param_gethex(Cmd, 0, data, len)) {
        free(data);
        return usage_analyse_crc();
    }
    len >>= 1;

    PrintAndLogEx(NORMAL, "\nTests with (%d) | %s", len, sprint_hex(data, len));

    // 51  f5  7a  d6
    uint8_t uid[] = {0x51, 0xf5, 0x7a, 0xd6}; //12 34 56
    init_table(CRC_LEGIC);
    uint8_t legic8 = CRC8Legic(uid, sizeof(uid));
    PrintAndLogEx(NORMAL, "Legic 16 | %X (EF6F expected) [legic8 = %02x]", crc16_legic(data, len, legic8), legic8);
    init_table(CRC_FELICA);
    PrintAndLogEx(NORMAL, "FeliCa | %X ", crc16_xmodem(data, len));

    PrintAndLogEx(NORMAL, "\nTests of reflection. Current methods in source code");
    PrintAndLogEx(NORMAL, "   reflect(0x3e23L,3) is %04X == 0x3e26", reflect(0x3e23L, 3));
    PrintAndLogEx(NORMAL, "       reflect8(0x80) is %02X == 0x01", reflect8(0x80));
    PrintAndLogEx(NORMAL, "    reflect16(0x8000) is %04X == 0x0001", reflect16(0xc6c6));

    uint8_t b1, b2;
    // ISO14443 crc B
    compute_crc(CRC_14443_B, data, len, &b1, &b2);
    uint16_t crcBB_1 = b1 << 8 | b2;
    uint16_t bbb = Crc16ex(CRC_14443_B, data, len);
    PrintAndLogEx(NORMAL, "ISO14443 crc B  | %04x == %04x \n", crcBB_1, bbb);


    // Test of CRC16,  '123456789' string.
    //

    PrintAndLogEx(NORMAL, "\n\nStandard test with 31 32 33 34 35 36 37 38 39  '123456789'\n\n");
    uint8_t dataStr[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39 };
    legic8 = CRC8Legic(dataStr, sizeof(dataStr));

    //these below has been tested OK.
    PrintAndLogEx(NORMAL, "Confirmed CRC Implementations");
    PrintAndLogEx(NORMAL, "-------------------------------------\n");
    PrintAndLogEx(NORMAL, "CRC 8 based\n\n");
    PrintAndLogEx(NORMAL, "LEGIC: CRC8 : %X (C6 expected)", legic8);
    PrintAndLogEx(NORMAL, "MAXIM: CRC8 : %X (A1 expected)", CRC8Maxim(dataStr, sizeof(dataStr)));
    PrintAndLogEx(NORMAL, "-------------------------------------\n");
    PrintAndLogEx(NORMAL, "CRC16 based\n\n");

    // input from commandline
    PrintAndLogEx(NORMAL, "CCITT  | %X (29B1 expected)", Crc16ex(CRC_CCITT, dataStr, sizeof(dataStr)));

    uint8_t poll[] = {0xb2, 0x4d, 0x12, 0x01, 0x01, 0x2e, 0x3d, 0x17, 0x26, 0x47, 0x80, 0x95, 0x00, 0xf1, 0x00, 0x00, 0x00, 0x01, 0x43, 0x00, 0xb3, 0x7f};
    PrintAndLogEx(NORMAL, "FeliCa | %04X (B37F expected)", Crc16ex(CRC_FELICA, poll + 2, sizeof(poll) - 4));
    PrintAndLogEx(NORMAL, "FeliCa | %04X (0000 expected)", Crc16ex(CRC_FELICA, poll + 2, sizeof(poll) - 2));

    uint8_t sel_corr[] = { 0x40, 0xe1, 0xe1, 0xff, 0xfe, 0x5f, 0x02, 0x3c, 0x43, 0x01};
    PrintAndLogEx(NORMAL, "iCLASS | %04x (0143 expected)", Crc16ex(CRC_ICLASS, sel_corr, sizeof(sel_corr) - 2));
    PrintAndLogEx(NORMAL, "---------------------------------------------------------------\n\n\n");

    // ISO14443 crc A
    compute_crc(CRC_14443_A, dataStr, sizeof(dataStr), &b1, &b2);
    uint16_t crcAA = b1 << 8 | b2;
    PrintAndLogEx(NORMAL, "ISO14443 crc A  | %04x or %04x (BF05 expected)\n", crcAA, Crc16ex(CRC_14443_A, dataStr, sizeof(dataStr)));

    // ISO14443 crc B
    compute_crc(CRC_14443_B, dataStr, sizeof(dataStr), &b1, &b2);
    uint16_t crcBB = b1 << 8 | b2;
    PrintAndLogEx(NORMAL, "ISO14443 crc B  | %04x or %04x (906E expected)\n", crcBB, Crc16ex(CRC_14443_B, dataStr, sizeof(dataStr)));

    // ISO15693 crc  (x.25)
    compute_crc(CRC_15693, dataStr, sizeof(dataStr), &b1, &b2);
    uint16_t crcCC = b1 << 8 | b2;
    PrintAndLogEx(NORMAL, "ISO15693 crc X25| %04x or %04x (906E expected)\n", crcCC, Crc16ex(CRC_15693, dataStr, sizeof(dataStr)));

    // ICLASS
    compute_crc(CRC_ICLASS, dataStr, sizeof(dataStr), &b1, &b2);
    uint16_t crcDD = b1 << 8 | b2;
    PrintAndLogEx(NORMAL, "ICLASS crc      | %04x or %04x\n", crcDD, Crc16ex(CRC_ICLASS, dataStr, sizeof(dataStr)));

    // FeliCa
    compute_crc(CRC_FELICA, dataStr, sizeof(dataStr), &b1, &b2);
    uint16_t crcEE = b1 << 8 | b2;
    PrintAndLogEx(NORMAL, "FeliCa          | %04x or %04x (31C3 expected)\n", crcEE, Crc16ex(CRC_FELICA, dataStr, sizeof(dataStr)));

    free(data);
    return 0;
}
static int CmdAnalyseCHKSUM(const char *Cmd) {

    uint8_t data[50];
    uint8_t cmdp = 0;
    uint32_t mask = 0xFFFF;
    bool errors = false;
    bool useHeader = false;
    int len = 0;
    memset(data, 0x0, sizeof(data));

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (param_getchar(Cmd, cmdp)) {
            case 'b':
            case 'B':
                param_gethex_ex(Cmd, cmdp + 1, data, &len);
                if (len % 2) errors = true;
                len >>= 1;
                cmdp += 2;
                break;
            case 'm':
            case 'M':
                mask = param_get32ex(Cmd, cmdp + 1, 0, 16);
                cmdp += 2;
                break;
            case 'v':
            case 'V':
                useHeader = true;
                cmdp++;
                break;
            case 'h':
            case 'H':
                return usage_analyse_checksum();
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors || cmdp == 0) return usage_analyse_checksum();

    if (useHeader) {
        PrintAndLogEx(NORMAL, "     add          | sub         | add 1's compl    | sub 1's compl   | xor");
        PrintAndLogEx(NORMAL, "byte nibble crumb | byte nibble | byte nibble cumb | byte nibble     | byte nibble cumb |  BSD       |");
        PrintAndLogEx(NORMAL, "------------------+-------------+------------------+-----------------+--------------------");
    }
    PrintAndLogEx(NORMAL, "0x%X 0x%X   0x%X  | 0x%X 0x%X   | 0x%X 0x%X   0x%X | 0x%X 0x%X       | 0x%X 0x%X   0x%X  | 0x%X  0x%X |\n",
                  calcSumByteAdd(data, len, mask)
                  , calcSumNibbleAdd(data, len, mask)
                  , calcSumCrumbAdd(data, len, mask)
                  , calcSumByteSub(data, len, mask)
                  , calcSumNibbleSub(data, len, mask)
                  , calcSumByteAddOnes(data, len, mask)
                  , calcSumNibbleAddOnes(data, len, mask)
                  , calcSumCrumbAddOnes(data, len, mask)
                  , calcSumByteSubOnes(data, len, mask)
                  , calcSumNibbleSubOnes(data, len, mask)
                  , calcSumByteXor(data, len, mask)
                  , calcSumNibbleXor(data, len, mask)
                  , calcSumCrumbXor(data, len, mask)
                  , calcBSDchecksum8(data, len, mask)
                  , calcBSDchecksum4(data, len, mask)
                 );
    return 0;
}

static int CmdAnalyseDates(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    // look for datestamps in a given array of bytes
    PrintAndLogEx(NORMAL, "To be implemented. Feel free to contribute!");
    return 0;
}
static int CmdAnalyseTEASelfTest(const char *Cmd) {

    uint8_t v[8], v_le[8];
    memset(v, 0x00, sizeof(v));
    memset(v_le, 0x00, sizeof(v_le));
    uint8_t *v_ptr = v_le;

    uint8_t cmdlen = strlen(Cmd);
    cmdlen = (sizeof(v) << 2 < cmdlen) ? sizeof(v) << 2 : cmdlen;

    if (param_gethex(Cmd, 0, v, cmdlen) > 0) {
        PrintAndLogEx(WARNING, "Can't read hex chars, uneven? :: %u", cmdlen);
        return 1;
    }

    SwapEndian64ex(v, 8, 4, v_ptr);

    // ENCRYPTION KEY:
    uint8_t key[16] = {0x55, 0xFE, 0xF6, 0x30, 0x62, 0xBF, 0x0B, 0xC1, 0xC9, 0xB3, 0x7C, 0x34, 0x97, 0x3E, 0x29, 0xFB };
    uint8_t keyle[16];
    uint8_t *key_ptr = keyle;
    SwapEndian64ex(key, sizeof(key), 4, key_ptr);

    PrintAndLogEx(NORMAL, "TEST LE enc| %s", sprint_hex(v_ptr, 8));

    tea_decrypt(v_ptr, key_ptr);
    PrintAndLogEx(NORMAL, "TEST LE dec | %s", sprint_hex_ascii(v_ptr, 8));

    tea_encrypt(v_ptr, key_ptr);
    tea_encrypt(v_ptr, key_ptr);
    PrintAndLogEx(NORMAL, "TEST enc2 | %s", sprint_hex_ascii(v_ptr, 8));

    return 0;
}

/*
static char *pb(uint32_t b) {
    static char buf1[33] = {0};
    static char buf2[33] = {0};
    static char *s;

    if (s != buf1)
        s = buf1;
    else
        s = buf2;

    memset(s, 0, sizeof(buf1));

    uint32_t mask = 0x80000000;
    for (uint8_t i = 0; i < 32; i++) {
        s[i] = (mask & b) ? '1' : '0';
        mask >>= 1;
    }
    return s;
}
*/

static int CmdAnalyseA(const char *Cmd) {

    return usage_analyse_a();
    /*
        PrintAndLogEx(NORMAL, "-- " _BLUE_("its my message") "\n");
        PrintAndLogEx(NORMAL, "-- " _RED_("its my message") "\n");
        PrintAndLogEx(NORMAL, "-- " _YELLOW_("its my message") "\n");
        PrintAndLogEx(NORMAL, "-- " _GREEN_("its my message") "\n");

        //uint8_t syncBit = 99;
        // The start bit is one ore more Sequence Y followed by a Sequence Z (... 11111111 00x11111). We need to distinguish from
        // Sequence X followed by Sequence Y followed by Sequence Z     (111100x1 11111111 00x11111)
        // we therefore look for a ...xx1111 11111111 00x11111xxxxxx... pattern
        // (12 '1's followed by 2 '0's, eventually followed by another '0', followed by 5 '1's)
    # define SYNC_16BIT 0xB24D
        uint32_t shiftReg = param_get32ex(Cmd, 0, 0xb24d, 16);
        uint8_t bt = param_get8ex(Cmd, 1, 0xBB, 16);
        uint8_t byte_offset = 99;
        // reverse byte
        uint8_t rev =  reflect8(bt);
        PrintAndLogEx(NORMAL, "input  %02x | %02x \n", bt, rev);
        // add byte to shift register
        shiftReg = shiftReg << 8 | rev;

        PrintAndLogEx(NORMAL, "shiftreg after %08x | pattern %08x \n", shiftReg, SYNC_16BIT);

        uint8_t n0 = 0, n1 = 0;

        n0 = (rev & (uint8_t)(~(0xFF >> (8 - 4)))) >> 4;
        n1 = (n1 << 4) | (rev & (uint8_t)(~(0xFF << 4)));

        PrintAndLogEx(NORMAL, "rev %02X | %02X %s | %02X %s |\n", rev, n0, pb(n0), n1, pb(n1));
    */
    /*
    hex(0xb24d shr 0) 0xB24D 0b1011001001001101
    hex(0xb24d shr 1) 0x5926
    hex(0xb24d shr 2) 0x2C93
    */

    /*
        for (int i = 0; i < 16; i++) {
            PrintAndLogEx(NORMAL, " (shiftReg >> %d) & 0xFFFF ==  %08x ---", i, ((shiftReg >> i) & 0xFFFF));

            // kolla om SYNC_PATTERN finns.
            if (((shiftReg >> 7) & 0xFFFF) == SYNC_16BIT) byte_offset = 7;
            else if (((shiftReg >> 6) & 0xFFFF) == SYNC_16BIT) byte_offset = 6;
            else if (((shiftReg >> 5) & 0xFFFF) == SYNC_16BIT) byte_offset = 5;
            else if (((shiftReg >> 4) & 0xFFFF) == SYNC_16BIT) byte_offset = 4;
            else if (((shiftReg >> 3) & 0xFFFF) == SYNC_16BIT) byte_offset = 3;
            else if (((shiftReg >> 2) & 0xFFFF) == SYNC_16BIT) byte_offset = 2;
            else if (((shiftReg >> 1) & 0xFFFF) == SYNC_16BIT) byte_offset = 1;
            else if (((shiftReg >> 0) & 0xFFFF) == SYNC_16BIT) byte_offset = 0;

            PrintAndLogEx(NORMAL, "Offset  %u \n", byte_offset);
            if (byte_offset != 99)
                break;

            shiftReg >>= 1;
        }

        uint8_t p1 = (rev & (uint8_t)(~(0xFF << byte_offset)));
        PrintAndLogEx(NORMAL, "Offset  %u  | leftovers  %02x  %s \n", byte_offset, p1, pb(p1));

    */

    /*
    pm3 --> da hex2bin 4db2     0100110110110010
    */
    //return 0;
    /*
        // split byte into two parts.
        uint8_t offset = 3, n0 = 0, n1 = 0;
        rev = 0xB2;
        for (uint8_t m=0; m<8; m++) {
            offset = m;
            n0 = (rev & (uint8_t)(~(0xFF >> (8-offset)))) >> offset;
            n1 = (n1 << offset) | (rev & (uint8_t)(~(0xFF << offset)));

            PrintAndLogEx(NORMAL, "rev %02X | %02X %s | %02X %s |\n", rev, n0, pb(n0), n1, pb(n1) );
            n0 = 0, n1 = 0;
            // PrintAndLogEx(NORMAL, " (0xFF >> offset) == %s |\n", pb( (0xFF >> offset)) );
            //PrintAndLogEx(NORMAL, "~(0xFF >> (8-offset)) == %s |\n", pb(  (uint8_t)(~(0xFF >> (8-offset))) ) );
            //PrintAndLogEx(NORMAL, " rev & xxx == %s\n\n", pb( (rev & (uint8_t)(~(0xFF << offset))) ));
        }
    return 0;
        // from A  -- x bits into B and the rest into C.

        for ( uint8_t i=0; i<8; i++){
            PrintAndLogEx(NORMAL, "%u | %02X %s | %02X %s |\n", i, a, pb(a), b, pb(b) );
            b = a & (a & (0xFF >> (8-i)));
            a >>=1;
        }

        */
//    return 0;

    /*
        // 14443-A
        uint8_t u14_c[] = {0x09, 0x78, 0x00, 0x92, 0x02, 0x54, 0x13, 0x02, 0x04, 0x2d, 0xe8 }; // atqs w crc
        uint8_t u14_w[] = {0x09, 0x78, 0x00, 0x92, 0x02, 0x54, 0x13, 0x02, 0x04, 0x2d, 0xe7 }; // atqs w crc
        PrintAndLogEx(FAILED, "14a check wrong crc      | %s\n", (check_crc(CRC_14443_A, u14_w, sizeof(u14_w))) ? "YES" : "NO");
        PrintAndLogEx(SUCCESS, "14a check correct crc    | %s\n", (check_crc(CRC_14443_A, u14_c, sizeof(u14_c))) ? "YES" : "NO");

        // 14443-B
        uint8_t u14b[] = {0x05, 0x00, 0x08, 0x39, 0x73};
        PrintAndLogEx(NORMAL, "14b check crc            | %s\n", (check_crc(CRC_14443_B, u14b, sizeof(u14b))) ? "YES" : "NO");

        // 15693 test
        uint8_t u15_c[] = {0x05, 0x00, 0x08, 0x39, 0x73}; // correct
        uint8_t u15_w[] = {0x05, 0x00, 0x08, 0x39, 0x72}; // wrong
        PrintAndLogEx(FAILED, "15 check wrong crc       | %s\n", (check_crc(CRC_15693, u15_w, sizeof(u15_w))) ? "YES" : "NO");
        PrintAndLogEx(SUCCESS, "15 check correct crc     | %s\n", (check_crc(CRC_15693, u15_c, sizeof(u15_c))) ? "YES" : "NO");

        // iCLASS test - wrong crc , swapped bytes.
        uint8_t iclass_w[] = { 0x40, 0xe1, 0xe1, 0xff, 0xfe, 0x5f, 0x02, 0x3c, 0x01, 0x43};
        uint8_t iclass_c[] = { 0x40, 0xe1, 0xe1, 0xff, 0xfe, 0x5f, 0x02, 0x3c, 0x43, 0x01};
        PrintAndLogEx(FAILED, "iCLASS check wrong crc   | %s\n", (check_crc(CRC_ICLASS, iclass_w, sizeof(iclass_w))) ? "YES" : "NO");
        PrintAndLogEx(SUCCESS, "iCLASS check correct crc | %s\n", (check_crc(CRC_ICLASS, iclass_c, sizeof(iclass_c))) ? "YES" : "NO");

        // FeliCa test
        uint8_t felica_w[] = {0x12, 0x01, 0x01, 0x2e, 0x3d, 0x17, 0x26, 0x47, 0x80, 0x95, 0x00, 0xf1, 0x00, 0x00, 0x00, 0x01, 0x43, 0x00, 0xb3, 0x7e};
        uint8_t felica_c[] = {0x12, 0x01, 0x01, 0x2e, 0x3d, 0x17, 0x26, 0x47, 0x80, 0x95, 0x00, 0xf1, 0x00, 0x00, 0x00, 0x01, 0x43, 0x00, 0xb3, 0x7f};
        PrintAndLogEx(FAILED, "FeliCa check wrong crc   | %s\n", (check_crc(CRC_FELICA, felica_w, sizeof(felica_w))) ? "YES" : "NO");
        PrintAndLogEx(SUCCESS, "FeliCa check correct crc | %s\n", (check_crc(CRC_FELICA, felica_c, sizeof(felica_c))) ? "YES" : "NO");

        PrintAndLogEx(NORMAL, "\n\n");

        return 0;
        */
    /*
    bool term = !isatty(STDIN_FILENO);
    if (!term) {
        char star[4];
        star[0] = '-';
        star[1] = '\\';
        star[2] = '|';
        star[3] = '/';

        for (uint8_t k=0; k<4; k = (k+1) % 4 ) {
            PrintAndLogEx(NORMAL, "\e[s%c\e[u", star[k]);
            fflush(stdout);
            if (ukbhit()) {
                int gc = getchar(); (void)gc;
                break;
            }
        }
    }
    */

//piwi
// uid(2e086b1a) nt(230736f6) ks(0b0008000804000e) nr(000000000)
// uid(2e086b1a) nt(230736f6) ks(0e0b0e0b090c0d02) nr(000000001)
// uid(2e086b1a) nt(230736f6) ks(0e05060e01080b08) nr(000000002)
//uint64_t d1[] = {0x2e086b1a, 0x230736f6, 0x0000001, 0x0e0b0e0b090c0d02};
//uint64_t d2[] = {0x2e086b1a, 0x230736f6, 0x0000002, 0x0e05060e01080b08};

// uid(17758822) nt(c0c69e59) ks(080105020705040e) nr(00000001)
// uid(17758822) nt(c0c69e59) ks(01070a05050c0705) nr(00000002)
//uint64_t d1[] = {0x17758822, 0xc0c69e59, 0x0000001, 0x080105020705040e};
//uint64_t d2[] = {0x17758822, 0xc0c69e59, 0x0000002, 0x01070a05050c0705};

// uid(6e442129) nt(8f699195) ks(090d0b0305020f02) nr(00000001)
// uid(6e442129) nt(8f699195) ks(03030508030b0c0e) nr(00000002)
// uid(6e442129) nt(8f699195) ks(02010f030c0d050d) nr(00000003)
// uid(6e442129) nt(8f699195) ks(00040f0f0305030e) nr(00000004)
//uint64_t d1[] = {0x6e442129, 0x8f699195, 0x0000001, 0x090d0b0305020f02};
//uint64_t d2[] = {0x6e442129, 0x8f699195, 0x0000004, 0x00040f0f0305030e};

    /*
    uid(3e172b29) nt(039b7bd2) ks(0c0e0f0505080800) nr(00000001)
    uid(3e172b29) nt(039b7bd2) ks(0e06090d03000b0f) nr(00000002)
    */
    /*
        uint64_t *keylistA = NULL, *keylistB = NULL;
        uint32_t keycountA = 0, keycountB = 0;
    //  uint64_t d1[] = {0x3e172b29, 0x039b7bd2, 0x0000001, 0, 0x0c0e0f0505080800};
    //  uint64_t d2[] = {0x3e172b29, 0x039b7bd2, 0x0000002, 0, 0x0e06090d03000b0f};
        uint64_t d1[] = {0x6e442129, 0x8f699195, 0x0000001, 0, 0x090d0b0305020f02};
        uint64_t d2[] = {0x6e442129, 0x8f699195, 0x0000004, 0, 0x00040f0f0305030e};

        keycountA = nonce2key(d1[0], d1[1], d1[2], 0, d1[3], d1[4], &keylistA);
        keycountB = nonce2key(d2[0], d2[1], d2[2], 0, d2[3], d2[4], &keylistB);

        switch (keycountA) {
            case 0:
                PrintAndLogEx(FAILED, "Key test A failed\n");
                break;
            case 1:
                PrintAndLogEx(SUCCESS, "KEY A | %012" PRIX64 " ", keylistA[0]);
                break;
        }
        switch (keycountB) {
            case 0:
                PrintAndLogEx(FAILED, "Key test B failed\n");
                break;
            case 1:
                PrintAndLogEx(SUCCESS, "KEY B | %012" PRIX64 " ", keylistB[0]);
                break;
        }

        free(keylistA);
        free(keylistB);
    */
//  qsort(keylist, keycount, sizeof(*keylist), compare_uint64);
//  keycount = intersection(last_keylist, keylist);

    /*
    uint64_t keys[] = {
        0x7b5b8144a32f, 0x76b46ccc461e, 0x03c3c36ea7a2, 0x171414d31961,
        0xe2bfc7153eea, 0x48023d1d1985, 0xff7e1a410953, 0x49a3110249d3,
        0xe3515546d015, 0x667c2ac86f85, 0x5774a8d5d6a9, 0xe401c2ca602c,
        0x3be7e5020a7e, 0x66dbec3cf90b, 0x4e13f1534605, 0x5c172e1e78c9,
        0xeafe51411fbf, 0xc579f0fcdd8f, 0x2146a0d745c3, 0xab31ca60171a,
        0x3169130a5035, 0xde5e11ea4923, 0x96fe2aeb9924, 0x828b61e6fcba,
        0x8211b0607367, 0xe2936b320f76, 0xaff501e84378, 0x82b31cedb21b,
        0xb725d31d4cd3, 0x3b984145b2f1, 0x3b4adb3e82ba, 0x8779075210fe
    };

    uint64_t keya[] = {
        0x7b5b8144a32f, 0x76b46ccc461e, 0x03c3c36ea7a2, 0x171414d31961,
        0xe2bfc7153eea, 0x48023d1d1985, 0xff7e1a410953, 0x49a3110249d3,
        0xe3515546d015, 0x667c2ac86f85, 0x5774a8d5d6a9, 0xe401c2ca602c,
        0x3be7e5020a7e, 0x66dbec3cf90b, 0x4e13f1534605, 0x5c172e1e78c9
    };
    uint64_t keyb[] = {
        0xeafe51411fbf, 0xc579f0fcdd8f, 0x2146a0d745c3, 0xab31ca60171a,
        0x3169130a5035, 0xde5e11ea4923, 0x96fe2aeb9924, 0x828b61e6fcba,
        0x8211b0607367, 0xe2936b320f76, 0xaff501e84378, 0x82b31cedb21b,
        0xb725d31d4cd3, 0x3b984145b2f1, 0x3b4adb3e82ba, 0x8779075210fe
    };

    */

    /*
    uint64_t xor[] = {
        0x0DEFED88E531, 0x7577AFA2E1BC, 0x14D7D7BDBEC3, 0xF5ABD3C6278B,
        0xAABDFA08276F, 0xB77C275C10D6, 0xB6DD0B434080, 0xAAF2444499C6,
        0x852D7F8EBF90, 0x3108821DB92C, 0xB3756A1FB685, 0xDFE627C86A52,
        0x5D3C093EF375, 0x28C81D6FBF0E, 0x1204DF4D3ECC, 0xB6E97F5F6776,
        0x2F87A1BDC230, 0xE43F502B984C, 0x8A776AB752D9, 0x9A58D96A472F,
        0xEF3702E01916, 0x48A03B01D007, 0x14754B0D659E, 0x009AD1868FDD,
        0x6082DB527C11, 0x4D666ADA4C0E, 0x2D461D05F163, 0x3596CFF0FEC8,
        0x8CBD9258FE22, 0x00D29A7B304B, 0xBC33DC6C9244
    };


    uint64_t xorA[] = {
        0x0DEFED88E531, 0x7577AFA2E1BC, 0x14D7D7BDBEC3, 0xF5ABD3C6278B,
        0xAABDFA08276F, 0xB77C275C10D6, 0xB6DD0B434080, 0xAAF2444499C6,
        0x852D7F8EBF90, 0x3108821DB92C, 0xB3756A1FB685, 0xDFE627C86A52,
        0x5D3C093EF375, 0x28C81D6FBF0E, 0x1204DF4D3ECC
    };
    uint64_t xorB[] = {
        0x2F87A1BDC230, 0xE43F502B984C, 0x8A776AB752D9, 0x9A58D96A472F,
        0xEF3702E01916, 0x48A03B01D007, 0x14754B0D659E, 0x009AD1868FDD,
        0x6082DB527C11, 0x4D666ADA4C0E, 0x2D461D05F163, 0x3596CFF0FEC8,
        0x8CBD9258FE22, 0x00D29A7B304B, 0xBC33DC6C9244
    };
    */
    /*
    // xor key A      | xor key B
    1  | 0DEFED88E531 | 2F87A1BDC230
    2  | 7577AFA2E1BC | E43F502B984C
    3  | 14D7D7BDBEC3 | 8A776AB752D9
    4  | F5ABD3C6278B | 9A58D96A472F
    5  | AABDFA08276F | EF3702E01916
    6  | B77C275C10D6 | 48A03B01D007
    7  | B6DD0B434080 | 14754B0D659E
    8  | AAF2444499C6 | 009AD1868FDD
    9  | 852D7F8EBF90 | 6082DB527C11
    10 | 3108821DB92C | 4D666ADA4C0E
    11 | B3756A1FB685 | 2D461D05F163
    12 | DFE627C86A52 | 3596CFF0FEC8
    13 | 5D3C093EF375 | 8CBD9258FE22
    14 | 28C81D6FBF0E | 00D29A7B304B
    15 | 1204DF4D3ECC | BC33DC6C9244
    */

    // generate xor table :)
    /*
    for (uint8_t i=0; i<31; i++){
        uint64_t a = keys[i] ^ keys[i+1];
        PrintAndLogEx(NORMAL, "%u | %012" PRIX64 " | \n", i, a);
    }
    */

    /*
    uint32_t id = param_get32ex(Cmd, 0, 0x93290142, 16);
    uint8_t uid[6] = {0};
    num_to_bytes(id,4,uid);

    uint8_t key_s0a[] = {
        uid[1] ^ uid[2] ^ uid[3] ^ 0x11,
        uid[1] ^ 0x72,
        uid[2] ^ 0x80,
        (uid[0] + uid[1] + uid[2] + uid[3] ) ^ uid[3] ^ 0x19,
        0xA3,
        0x2F
    };

    PrintAndLogEx(NORMAL, "UID   | %s\n", sprint_hex(uid,4 ));
    PrintAndLogEx(NORMAL, "KEY A | %s\n", sprint_hex(key_s0a, 6));

    // arrays w all keys
    uint64_t foo[32] = {0};

    //A
    foo[0] = bytes_to_num(key_s0a, 6);
    //B
    //foo[16] = 0xcafe71411fbf;
    foo[16] = 0xeafe51411fbf;

    for (uint8_t i=0; i<15; i++){
        foo[i+1] = foo[i] ^ xorA[i];
        foo[i+16+1] = foo[i+16] ^ xorB[i];

    }
    for (uint8_t i=0; i<15; i++){
        uint64_t a = foo[i];
        uint64_t b = foo[i+16];

        PrintAndLogEx(NORMAL, "%02u | %012" PRIX64 " %s | %012" PRIX64 " %s\n",
            i,
            a,
            ( a == keya[i])?"ok":"err",
            b,
            ( b == keyb[i])?"ok":"err"
        );
    }
    */
//    return 0;
}

static void generate4bNUID(uint8_t *uid, uint8_t *nuid) {
    uint16_t crc;
    uint8_t b1, b2;

    compute_crc(CRC_14443_A, uid, 3, &b1, &b2);
    nuid[0] = (b2 & 0xE0) | 0xF;
    nuid[1] = b1;
    crc = b1;
    crc |= b2 << 8;
    crc = crc16_fast(&uid[3], 4, reflect16(crc), true, true);
    nuid[2] = (crc >> 8) & 0xFF ;
    nuid[3] = crc & 0xFF;
}

static int CmdAnalyseNuid(const char *Cmd) {
    uint8_t nuid[4] = {0};
    uint8_t uid[7] = {0};
    int len = 0;
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_analyse_nuid();

    /* src: https://www.nxp.com/docs/en/application-note/AN10927.pdf */
    /* selftest1  UID 040D681AB52281  -> NUID 8F430FEF */
    /* selftest2  UID 04183F09321B85  -> NUID 4F505D7D */
    if (cmdp == 't') {
        uint8_t uid_test1[] = {0x04, 0x0d, 0x68, 0x1a, 0xb5, 0x22, 0x81};
        uint8_t nuid_test1[] = {0x8f, 0x43, 0x0f, 0xef};
        uint8_t uid_test2[] = {0x04, 0x18, 0x3f, 0x09, 0x32, 0x1b, 0x85};
        uint8_t nuid_test2[] = {0x4f, 0x50, 0x5d, 0x7d};
        memcpy(uid, uid_test1, sizeof(uid));
        generate4bNUID(uid, nuid);

        bool test1 = (0 == memcmp(nuid, nuid_test1, sizeof(nuid)));
        PrintAndLogEx(SUCCESS, "Selftest1 %s\n",  test1 ? _GREEN_("OK") : _RED_("Fail"));

        memcpy(uid, uid_test2, sizeof(uid));
        generate4bNUID(uid, nuid);
        bool test2 = (0 == memcmp(nuid, nuid_test2, sizeof(nuid)));
        PrintAndLogEx(SUCCESS, "Selftest2 %s\n", test2 ? _GREEN_("OK") : _RED_("Fail"));
        return 0;
    }

    param_gethex_ex(Cmd, 0, uid, &len);
    if (len % 2  || len != 14) return usage_analyse_nuid();

    generate4bNUID(uid, nuid);

    PrintAndLogEx(NORMAL, "UID  | %s \n", sprint_hex(uid, 7));
    PrintAndLogEx(NORMAL, "NUID | %s \n", sprint_hex(nuid, 4));
    return 0;
}
static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable, "This help"},
    {"lcr",     CmdAnalyseLCR,      AlwaysAvailable, "Generate final byte for XOR LRC"},
    {"crc",     CmdAnalyseCRC,      AlwaysAvailable, "Stub method for CRC evaluations"},
    {"chksum",  CmdAnalyseCHKSUM,   AlwaysAvailable, "Checksum with adding, masking and one's complement"},
    {"dates",   CmdAnalyseDates,    AlwaysAvailable, "Look for datestamps in a given array of bytes"},
    {"tea",     CmdAnalyseTEASelfTest, AlwaysAvailable, "Crypto TEA test"},
    {"lfsr",    CmdAnalyseLfsr,     AlwaysAvailable, "LFSR tests"},
    {"a",       CmdAnalyseA,        AlwaysAvailable, "num bits test"},
    {"nuid",    CmdAnalyseNuid,     AlwaysAvailable, "create NUID from 7byte UID"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return 0;
}

int CmdAnalyse(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
