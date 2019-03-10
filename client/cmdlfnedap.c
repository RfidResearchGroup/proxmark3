//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency NEDAP tag commands
//-----------------------------------------------------------------------------

#include "cmdlfnedap.h"
static int CmdHelp(const char *Cmd);

int usage_lf_nedap_clone(void) {
    PrintAndLogEx(NORMAL, "clone a NEDAP tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf nedap clone [h] <Card-Number>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             : This help");
    PrintAndLogEx(NORMAL, "      <Card Number> : 24-bit value card number");
//  PrintAndLogEx(NORMAL, "      Q5            : optional - clone to Q5 (T5555) instead of T55x7 chip");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf nedap clone 112233");
    return 0;
}

int usage_lf_nedap_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of NEDAP card with specified card number.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf nedap sim [h] <Card-Number>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h               : This help");
    PrintAndLogEx(NORMAL, "      <Card Number>   : 24-bit value card number");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf nedap sim 112233");
    return 0;
}

// find nedap preamble in already demoded data
int detectNedap(uint8_t *dest, size_t *size) {
    //make sure buffer has data
    if (*size < 128) return -3;

    size_t startIdx = 0;
    //uint8_t preamble[] = {1,1,1,1,1,1,1,1,1,0,0,0,1};
    uint8_t preamble[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 0};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -4; //preamble not found
    return (int) startIdx;
}

int GetNedapBits(uint32_t cn, uint8_t *nedapBits) {

    uint8_t pre[128];
    memset(pre, 0x00, sizeof(pre));

    // preamble  1111 1111 10 = 0xFF8
    num_to_bytebits(0xFF8, 12, pre);

    // fixed tagtype code?  0010 1101 = 0x2D
    num_to_bytebits(0x2D, 8, pre + 10);

    // 46 encrypted bits - UNKNOWN ALGO
    //    -- 16 bits checksum. Should be 4x4 checksum,  based on UID and 2 constant values.
    //    -- 30 bits undocumented?
    //num_to_bytebits(cn, 46, pre+18);

    //----from this part, the UID in clear text, with a 1bit ZERO as separator between bytes.
    pre[64] = 0;
    pre[73] = 0;
    pre[82] = 0;
    pre[91] = 0;
    pre[100] = 0;
    pre[109] = 0;
    pre[118] = 0;

    // cardnumber (uid)
    num_to_bytebits((cn >>  0) & 0xFF, 8, pre + 65);
    num_to_bytebits((cn >>  8) & 0xFF, 8, pre + 74);
    num_to_bytebits((cn >> 16) & 0xFF, 8, pre + 83);

    // two ?
    num_to_bytebits(0, 8, pre + 92);
    num_to_bytebits(0, 8, pre + 101);

    // chksum
    num_to_bytebits((0 >> 0) & 0xFF, 8, pre + 110);
    num_to_bytebits((0 >> 8) & 0xFF, 8, pre + 119);


    // add paritybits (bitsource, dest, sourcelen, paritylen, parityType (odd, even,)
    addParity(pre, pre + 64, 64, 8, 1);
    addParity(pre + 64, pre + 64, 64, 8, 1);

    pre[63] = GetParity(DemodBuffer, EVEN, 63);
    pre[127] = GetParity(DemodBuffer + 64, EVEN, 63);

    memcpy(nedapBits, pre, 128);

    // 1111111110001011010000010110100011001001000010110101001101011001000110011010010000000000100001110001001000000001000101011100111
    return 1;
}
/*
 - UID: 001630
 - i: 4071
 - Checksum2 BE21
*/
//GetParity( uint8_t *bits, uint8_t type, int length)

//NEDAP demod - ASK/Biphase (or Diphase),  RF/64 with preamble of 1111111110  (always a 128 bit data stream)
//print NEDAP Prox ID, encoding, encrypted ID,

int CmdLFNedapDemod(const char *Cmd) {
    //raw ask demod no start bit finding just get binary from wave
    if (!ASKbiphaseDemod("0 64 1 0", false)) {
        if (g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: Error - Nedap ASKbiphaseDemod failed");
        return 0;
    }
    size_t size = DemodBufferLen;
    int idx = detectNedap(DemodBuffer, &size);
    if (idx < 0) {
        if (g_debugMode) {
            // if (idx == -5)
            // PrintAndLogEx(DEBUG, "DEBUG: Error - not enough samples");
            // else if (idx == -1)
            // PrintAndLogEx(DEBUG, "DEBUG: Error - only noise found");
            // else if (idx == -2)
            // PrintAndLogEx(DEBUG, "DEBUG: Error - problem during ASK/Biphase demod");
            if (idx == -3)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Nedap Size not correct: %d", size);
            else if (idx == -4)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Nedap preamble not found");
            else
                PrintAndLogEx(DEBUG, "DEBUG: Error - Nedap idx: %d", idx);
        }
        return 0;
    }

    /* Index map                                                      E                                                                              E
     preamble    enc tag type         encrypted uid                   P d    33    d    90    d    04    d    71    d    40    d    45    d    E7    P
     1111111110 00101101000001011010001100100100001011010100110101100 1 0 00110011 0 10010000 0 00000100 0 01110001 0 01000000 0 01000101 0 11100111 1
                                                                             uid2       uid1       uid0         I          I          R           R
     1111111110 00101101000001011010001100100100001011010100110101100 1

     0 00110011
     0 10010000
     0 00000100
     0 01110001
     0 01000000
     0 01000101
     0 11100111
     1

         Tag ID is 049033
         I = Identical on all tags
         R = Random ?
         UID2, UID1, UID0 == card number

    */
    //get raw ID before removing parities
    uint32_t raw[4] = {0, 0, 0, 0};
    raw[0] = bytebits_to_byte(DemodBuffer + idx + 96, 32);
    raw[1] = bytebits_to_byte(DemodBuffer + idx + 64, 32);
    raw[2] = bytebits_to_byte(DemodBuffer + idx + 32, 32);
    raw[3] = bytebits_to_byte(DemodBuffer + idx, 32);
    setDemodBuf(DemodBuffer, 128, idx);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (idx * g_DemodClock));

    uint8_t firstParity = GetParity(DemodBuffer, EVEN, 63);
    if (firstParity != DemodBuffer[63]) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Nedap 1st 64bit parity check failed:  %d|%d ", DemodBuffer[63], firstParity);
        return 0;
    }

    uint8_t secondParity = GetParity(DemodBuffer + 64, EVEN, 63);
    if (secondParity != DemodBuffer[127]) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Nedap 2st 64bit parity check failed:  %d|%d ", DemodBuffer[127], secondParity);
        return 0;
    }

    // ok valid card found!
    uint32_t uid = 0;
    uid =  bytebits_to_byte(DemodBuffer + 65, 8);
    uid |= bytebits_to_byte(DemodBuffer + 74, 8) << 8;
    uid |= bytebits_to_byte(DemodBuffer + 83, 8) << 16;

    uint16_t two = 0;
    two =  bytebits_to_byte(DemodBuffer + 92, 8);
    two |= bytebits_to_byte(DemodBuffer + 101, 8) << 8;

    uint16_t chksum2 = 0;
    chksum2 =  bytebits_to_byte(DemodBuffer + 110, 8);
    chksum2 |= bytebits_to_byte(DemodBuffer + 119, 8) << 8;

    PrintAndLogEx(SUCCESS, "NEDAP ID Found - Raw: %08x%08x%08x%08x", raw[3], raw[2], raw[1], raw[0]);
    PrintAndLogEx(SUCCESS, " - UID: %06X", uid);
    PrintAndLogEx(SUCCESS, " - i: %04X", two);
    PrintAndLogEx(SUCCESS, " - Checksum2 %04X", chksum2);

    if (g_debugMode) {
        PrintAndLogEx(DEBUG, "DEBUG: idx: %d, Len: %d, Printing Demod Buffer:", idx, 128);
        printDemodBuff();
        PrintAndLogEx(DEBUG, "BIN:\n%s", sprint_bin_break(DemodBuffer, 128, 64));
    }

    return 1;
}
/*
configuration
lf t55xx wr b 0 d 00170082

1) uid 049033
lf t55 wr b 1 d FF8B4168
lf t55 wr b 2 d C90B5359
lf t55 wr b 3 d 19A40087
lf t55 wr b 4 d 120115CF

2) uid 001630
lf t55 wr b 1 d FF8B6B20
lf t55 wr b 2 d F19B84A3
lf t55 wr b 3 d 18058007
lf t55 wr b 4 d 1200857C

3) uid 39feff
lf t55xx wr b 1 d ffbfa73e
lf t55xx wr b 2 d 4c0003ff
lf t55xx wr b 3 d ffbfa73e
lf t55xx wr b 4 d 4c0003ff

*/

int CmdLFNedapRead(const char *Cmd) {
    lf_read(true, 12000);
    return CmdLFNedapDemod(Cmd);
}
/*
int CmdLFNedapClone(const char *Cmd) {

    char cmdp = param_getchar(Cmd, 0);
    if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_nedap_clone();

    uint32_t cardnumber=0, cn = 0;
    uint32_t blocks[5];
    uint8_t bits[128];
    memset(bits, 0x00, sizeof(bits));

    if (sscanf(Cmd, "%u", &cn ) != 1) return usage_lf_nedap_clone();

    cardnumber = (cn & 0x00FFFFFF);

    if ( !GetNedapBits(cardnumber, bits)) {
        PrintAndLogEx(WARNING, "Error with tag bitstream generation.");
        return 1;
    }

    ((ASK/DIphase   data rawdemod ab 0 64 1 0
    //NEDAP - compat mode, ASK/DIphase, data rate 64, 4 data blocks
    // DI-pahse (CDP) T55x7_MODULATION_DIPHASE
    blocks[0] = T55x7_MODULATION_DIPHASE | T55x7_BITRATE_RF_64 | 7 << T55x7_MAXBLOCK_SHIFT;

    if (param_getchar(Cmd, 3) == 'Q' || param_getchar(Cmd, 3) == 'q')
        blocks[0] = T5555_MODULATION_BIPHASE | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(64) | 7 <<T5555_MAXBLOCK_SHIFT;

    blocks[1] = bytebits_to_byte(bits, 32);
    blocks[2] = bytebits_to_byte(bits + 32, 32);
    blocks[3] = bytebits_to_byte(bits + 64, 32);
    blocks[4] = bytebits_to_byte(bits + 96, 32);

    PrintAndLogEx(INFO, "Preparing to clone NEDAP to T55x7 with card number: %u", cardnumber);
    print_blocks(blocks, 5);

    UsbCommand resp;
    UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0,0,0}};

    for (uint8_t i = 0; i<5; ++i ) {
        c.arg[0] = blocks[i];
        c.arg[1] = i;
        clearCommandBuffer();
        SendCommand(&c);
        if (!WaitForResponseTimeout(CMD_ACK, &resp, T55XX_WRITE_TIMEOUT)){
            PrintAndLogEx(WARNING, "Error occurred, device did not respond during write operation.");
            return -1;
        }
    }
    return 0;
}
*/

int CmdLFNedapSim(const char *Cmd) {

    uint32_t cardnumber = 0, cn = 0;

    char cmdp = param_getchar(Cmd, 0);
    if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_nedap_sim();

    if (sscanf(Cmd, "%u", &cn) != 1) return usage_lf_nedap_sim();

    cardnumber = (cn & 0x00FFFFFF);

    uint8_t bs[128];
    size_t size = sizeof(bs);
    memset(bs, 0x00, size);

    // NEDAP,  Biphase = 2, clock 64, inverted,  (DIPhase == inverted BIphase
    uint8_t  clk = 64, encoding = 2, separator = 0, invert = 1;
    uint16_t arg1, arg2;
    arg1 = clk << 8 | encoding;
    arg2 = invert << 8 | separator;

    if (!GetNedapBits(cardnumber, bs)) {
        PrintAndLogEx(WARNING, "Error with tag bitstream generation.");
        return 1;
    }

    PrintAndLogEx(SUCCESS, "bin  %s", sprint_bin_break(bs, 128, 32));
    PrintAndLogEx(SUCCESS, "Simulating Nedap - CardNumber: %u", cardnumber);

    UsbCommand c = {CMD_ASK_SIM_TAG, {arg1, arg2, size}};
    memcpy(c.d.asBytes, bs, size);
    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

int CmdLFNedapChk(const char *Cmd) {
    //301600714021BE
    uint8_t data[256] = { 0x30, 0x16, 0x00, 0x71, 0x40, 0x21, 0xBE};
    int len = 0;
    param_gethex_ex(Cmd, 0, data, &len);

    len = (len == 0) ? 5 : len >> 1;

    PrintAndLogEx(SUCCESS, "Input: [%d] %s", len, sprint_hex(data, len));

    //uint8_t last = GetParity(data, EVEN, 62);
    //PrintAndLogEx(NORMAL, "TEST PARITY::  %d | %d ", DemodBuffer[62], last);

    uint8_t cl = 0x1D, ch = 0x1D, carry = 0;
    uint8_t al, bl, temp;

    for (int i = len; i >= 0; --i) {
        al = data[i];
        for (int j = 8; j > 0; --j) {

            bl = al ^ ch;
            //PrintAndLogEx(NORMAL, "BL %02x | CH %02x \n", al, ch);

            carry = (cl & 0x80) ? 1 : 0;
            cl <<= 1;

            temp = (ch & 0x80) ? 1 : 0;
            ch = (ch << 1) | carry;
            carry = temp;

            carry = (al & 0x80) ? 1 : 0;
            al <<= 1;

            carry = (bl & 0x80) ? 1 : 0;
            bl <<= 1;

            if (carry) {
                cl ^= 0x21;
                ch ^= 0x10;
            }
        }
    }

    PrintAndLogEx(SUCCESS, "Nedap checksum: 0x%X", ((ch << 8) | cl));
    return 0;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        1, "this help"},
    {"demod",   CmdLFNedapDemod, 0, "demodulate an Nedap tag from the GraphBuffer"},
    {"read",    CmdLFNedapRead, 0, "attempt to read and extract tag data"},
//  {"clone",   CmdLFNedapClone,0, "<Card Number>  clone nedap tag"},
    {"sim",     CmdLFNedapSim,  0, "simulate nedap tag"},
    {"chk",     CmdLFNedapChk,  1, "calculate Nedap Checksum <uid bytes>"},
    {NULL, NULL, 0, NULL}
};

int CmdLFNedap(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
