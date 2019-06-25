//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency fdx-b tag commands
// Differential Biphase, rf/32, 128 bits (known)
//-----------------------------------------------------------------------------

#include "cmdlffdx.h"

/*
    FDX-B ISO11784/85 demod  (aka animal tag)  BIPHASE, inverted, rf/32,  with preamble of 00000000001 (128bits)
    8 databits + 1 parity (1)
    CIITT 16 checksum
    NATIONAL CODE, ICAR database
    COUNTRY CODE (ISO3166) or http://cms.abvma.ca/uploads/ManufacturersISOsandCountryCodes.pdf
    FLAG (animal/non-animal)

    38 IDbits
    10 country code
    1 extra app bit
    14 reserved bits
    1 animal bit
    16 ccitt CRC chksum over 64bit ID CODE.
    24 appli bits.

    sample: 985121004515220  [ 37FF65B88EF94 ]
*/

static int CmdHelp(const char *Cmd);

static int usage_lf_fdx_clone(void) {
    PrintAndLogEx(NORMAL, "Clone a FDX-B animal tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "Usage: lf fdx clone [h] <country id> <animal id> <Q5>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h            : This help");
    PrintAndLogEx(NORMAL, "      <country id> : Country id");
    PrintAndLogEx(NORMAL, "      <animal id>  : Animal id");
    // has extended data?
    //reserved/rfu
    //is animal tag
    // extended data
    PrintAndLogEx(NORMAL, "      <Q5>        : Specify write to Q5 (t5555 instead of t55x7)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf fdx clone 999 112233");
    return PM3_SUCCESS;
}

static int usage_lf_fdx_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of FDX-B animal tag");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf fdx sim [h] <country id> <animal id>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h            : This help");
    PrintAndLogEx(NORMAL, "      <country id> : Country ID");
    PrintAndLogEx(NORMAL, "      <animal id>  : Animal ID");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf fdx sim 999 112233");
    return PM3_SUCCESS;
}

// clearing the topbit needed for the preambl detection.
static void verify_values(uint32_t countryid, uint64_t animalid) {
    if ((animalid & 0x3FFFFFFFFF) != animalid) {
        animalid &= 0x3FFFFFFFFF;
        PrintAndLogEx(INFO, "Animal ID Truncated to 38bits: %"PRIx64, animalid);
    }
    if ((countryid & 0x3ff) != countryid) {
        countryid &= 0x3ff;
        PrintAndLogEx(INFO, "Country ID Truncated to 10bits: %03d", countryid);
    }
}

// FDX-B ISO11784/85 demod  (aka animal tag)  BIPHASE, inverted, rf/32,  with preamble of 00000000001 (128bits)
// 8 databits + 1 parity (1)
// CIITT 16 chksum
// NATIONAL CODE, ICAR database
// COUNTRY CODE (ISO3166) or http://cms.abvma.ca/uploads/ManufacturersISOsandCountryCodes.pdf
// FLAG (animal/non-animal)
/*
38 IDbits
10 country code
1 extra app bit
14 reserved bits
1 animal bit
16 ccitt CRC chksum over 64bit ID CODE.
24 appli bits.

-- sample: 985121004515220  [ 37FF65B88EF94 ]
*/
/*
static int CmdFDXBdemodBI(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

    int clk = 32;
    int invert = 1, errCnt = 0, offset = 0, maxErr = 100;
    uint8_t bs[MAX_DEMOD_BUF_LEN];
    size_t size = getFromGraphBuf(bs);

    errCnt = askdemod(bs, &size, &clk, &invert, maxErr, 0, 0);
    if (errCnt < 0 || errCnt > maxErr) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - FDXB no data or error found %d, clock: %d", errCnt, clk);
        return PM3_ESOFT;
    }

    errCnt = BiphaseRawDecode(bs, &size, &offset, 1);
    if (errCnt < 0 || errCnt > maxErr) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - FDXB BiphaseRawDecode: %d", errCnt);
        return PM3_ESOFT;
    }

    int preambleIndex = detectFDXB(bs, &size);
    if (preambleIndex < 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - FDXB preamble not found :: %d", preambleIndex);
        return PM3_ESOFT;
    }
    if (size != 128) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - FDXB incorrect data length found");
        return PM3_ESOFT;
    }

    setDemodBuff(bs, 128, preambleIndex);

    // remove marker bits (1's every 9th digit after preamble) (pType = 2)
    size = removeParity(bs, preambleIndex + 11, 9, 2, 117);
    if (size != 104) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - FDXB error removeParity:: %d", size);
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "\nFDX-B / ISO 11784/5 Animal Tag ID Found:");

    //got a good demod
    uint64_t NationalCode = ((uint64_t)(bytebits_to_byteLSBF(bs + 32, 6)) << 32) | bytebits_to_byteLSBF(bs, 32);
    uint32_t countryCode = bytebits_to_byteLSBF(bs + 38, 10);
    uint8_t dataBlockBit = bs[48];
    uint32_t reservedCode = bytebits_to_byteLSBF(bs + 49, 14);
    uint8_t animalBit = bs[63];
    uint32_t crc_16 = bytebits_to_byteLSBF(bs + 64, 16);
    uint32_t extended = bytebits_to_byteLSBF(bs + 80, 24);

    uint64_t rawid = ((uint64_t)bytebits_to_byte(bs, 32) << 32) | bytebits_to_byte(bs + 32, 32);
    uint8_t raw[8];
    num_to_bytes(rawid, 8, raw);

    PrintAndLogEx(SUCCESS, "Raw ID Hex: %s", sprint_hex(raw, 8));

    uint16_t calcCrc = crc16_kermit(raw, 8);
    PrintAndLogEx(SUCCESS, "Animal ID:     %04u-%012" PRIu64, countryCode, NationalCode);
    PrintAndLogEx(SUCCESS, "National Code: %012" PRIu64, NationalCode);
    PrintAndLogEx(SUCCESS, "CountryCode:   %04u", countryCode);

    PrintAndLogEx(SUCCESS, "Reserved/RFU:      %u", reservedCode);
    PrintAndLogEx(SUCCESS, "Animal Tag:        %s", animalBit ? _YELLOW_("True") : "False");
    PrintAndLogEx(SUCCESS, "Has extended data: %s [0x%X]", dataBlockBit ? _YELLOW_("True") : "False", extended);
    PrintAndLogEx(SUCCESS, "CRC:           0x%04X - [%04X] - %s", crc_16, calcCrc, (calcCrc == crc_16) ? _GREEN_("Passed") : _RED_("Fail") );

    if (g_debugMode) {
        PrintAndLogEx(DEBUG, "Start marker %d;   Size %d", preambleIndex, size);
        char *bin = sprint_bin_break(bs, size, 16);
        PrintAndLogEx(DEBUG, "DEBUG BinStream:\n%s", bin);
    }
    return PM3_SUCCESS;
}
*/

//see ASKDemod for what args are accepted
//almost the same demod as cmddata.c/CmdFDXBdemodBI
static int CmdFdxDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

    //Differential Biphase / di-phase (inverted biphase)
    //get binary from ask wave
    if (ASKbiphaseDemod("0 32 1 100", false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - FDX-B ASKbiphaseDemod failed");
        return PM3_ESOFT;
    }
    size_t size = DemodBufferLen;
    int preambleIndex = detectFDXB(DemodBuffer, &size);
    if (preambleIndex < 0) {

        if (preambleIndex == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - FDX-B too few bits found");
        else if (preambleIndex == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - FDX-B preamble not found");
        else if (preambleIndex == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - FDX-B Size not correct: %d", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - FDX-B ans: %d", preambleIndex);
        return PM3_ESOFT;
    }

    // set and leave DemodBuffer intact
    setDemodBuff(DemodBuffer, 128, preambleIndex);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (preambleIndex * g_DemodClock));
    // remove marker bits (1's every 9th digit after preamble) (pType = 2)
    size = removeParity(DemodBuffer, 11, 9, 2, 117);
    if (size != 104) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - FDX-B error removeParity: %d", size);
        return PM3_ESOFT;
    }

    //got a good demod
    uint64_t NationalCode = ((uint64_t)(bytebits_to_byteLSBF(DemodBuffer + 32, 6)) << 32) | bytebits_to_byteLSBF(DemodBuffer, 32);
    uint16_t countryCode = bytebits_to_byteLSBF(DemodBuffer + 38, 10);
    uint8_t dataBlockBit = DemodBuffer[48];
    uint32_t reservedCode = bytebits_to_byteLSBF(DemodBuffer + 49, 14);
    uint8_t animalBit = DemodBuffer[63];
    uint32_t crc_16 = bytebits_to_byteLSBF(DemodBuffer + 64, 16);
    uint32_t extended = bytebits_to_byteLSBF(DemodBuffer + 80, 24);
    uint64_t rawid = (uint64_t)(bytebits_to_byte(DemodBuffer, 32)) << 32 | bytebits_to_byte(DemodBuffer + 32, 32);
    uint8_t raw[8];
    num_to_bytes(rawid, 8, raw);


    uint16_t calcCrc = crc16_kermit(raw, 8);

    PrintAndLogEx(SUCCESS, "\nFDX-B / ISO 11784/5 Animal Tag ID Found:  Raw : %s", sprint_hex(raw, 8));
    PrintAndLogEx(SUCCESS, "Animal ID          %04u-%012" PRIu64, countryCode, NationalCode);
    PrintAndLogEx(SUCCESS, "National Code      %012" PRIu64 " (0x%" PRIx64 ")", NationalCode, NationalCode);
    PrintAndLogEx(SUCCESS, "Country Code       %04u", countryCode);
    PrintAndLogEx(SUCCESS, "Reserved/RFU       %u (0x04%X)", reservedCode,  reservedCode);
    PrintAndLogEx(SUCCESS, "Animal Tag         %s", animalBit ? _YELLOW_("True") : "False");
    PrintAndLogEx(SUCCESS, "Has extended data  %s [0x%X]", dataBlockBit ? _YELLOW_("True") : "False", extended);
    PrintAndLogEx(SUCCESS, "CRC-16             0x%04X - 0x%04X [%s]", crc_16, calcCrc, (calcCrc == crc_16) ? _GREEN_("Ok") : _RED_("Fail"));

    if (g_debugMode) {
        PrintAndLogEx(DEBUG, "Start marker %d;   Size %d", preambleIndex, size);
        char *bin = sprint_bin_break(DemodBuffer, size, 16);
        PrintAndLogEx(DEBUG, "DEBUG bin stream:\n%s", bin);
    }

    // set block 0 for later
    //g_DemodConfig = T55x7_MODULATION_DIPHASE | T55x7_BITRATE_RF_32 | 4 << T55x7_MAXBLOCK_SHIFT;

    return PM3_SUCCESS;
}

static int CmdFdxRead(const char *Cmd) {
    lf_read(true, 10000);
    return CmdFdxDemod(Cmd);
}

static int CmdFdxClone(const char *Cmd) {

    uint32_t countryid = 0;
    uint64_t animalid = 0;
    uint32_t blocks[5] = {T55x7_MODULATION_DIPHASE | T55x7_BITRATE_RF_32 | 4 << T55x7_MAXBLOCK_SHIFT, 0, 0, 0, 0};
    uint8_t bits[128];
    uint8_t *bs = bits;
    memset(bs, 0, sizeof(bits));

    char cmdp = param_getchar(Cmd, 0);
    if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_fdx_clone();

    countryid = param_get32ex(Cmd, 0, 0, 10);
    animalid = param_get64ex(Cmd, 1, 0, 10);

    verify_values(countryid, animalid);

    // getFDXBits(uint64_t national_id, uint16_t country, uint8_t isanimal, uint8_t isextended, uint32_t extended, uint8_t *bits)
    if (getFDXBits(animalid, countryid, 1, 0, 0, bs) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Error with tag bitstream generation.");
        return PM3_ESOFT;
    }

    //Q5
    if (param_getchar(Cmd, 2) == 'Q' || param_getchar(Cmd, 2) == 'q')
        blocks[0] = T5555_MODULATION_BIPHASE | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(32) | 4 << T5555_MAXBLOCK_SHIFT;

    // convert from bit stream to block data
    blocks[1] = bytebits_to_byte(bs, 32);
    blocks[2] = bytebits_to_byte(bs + 32, 32);
    blocks[3] = bytebits_to_byte(bs + 64, 32);
    blocks[4] = bytebits_to_byte(bs + 96, 32);

    PrintAndLogEx(INFO, "Preparing to clone FDX-B to T55x7 with animal ID: %04u-%"PRIu64, countryid, animalid);
    print_blocks(blocks, 5);

    PacketResponseNG resp;

    // fast push mode
    conn.block_after_ACK = true;
    for (int i = 4; i >= 0; --i) {
        if (i == 0) {
            // Disable fast mode on last packet
            conn.block_after_ACK = false;
        }
        clearCommandBuffer();

        t55xx_write_block_t ng;
        ng.data = blocks[i];
        ng.pwd = 0;
        ng.blockno = i;
        ng.flags = 0;

        SendCommandNG(CMD_T55XX_WRITE_BLOCK, (uint8_t *)&ng, sizeof(ng));
        if (!WaitForResponseTimeout(CMD_T55XX_WRITE_BLOCK, &resp, T55XX_WRITE_TIMEOUT)) {
            PrintAndLogEx(WARNING, "Error occurred, device did not respond during write operation.");
            return PM3_ETIMEOUT;
        }
    }
    return PM3_SUCCESS;
}

static int CmdFdxSim(const char *Cmd) {
    uint32_t countryid = 0;
    uint64_t animalid = 0;

    char cmdp = param_getchar(Cmd, 0);
    if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_fdx_sim();

    countryid = param_get32ex(Cmd, 0, 0, 10);
    animalid = param_get64ex(Cmd, 1, 0, 10);

    verify_values(countryid, animalid);

    PrintAndLogEx(SUCCESS, "Simulating FDX-B animal ID: %04u-%"PRIu64, countryid, animalid);

    uint8_t bs[128];
    //getFDXBits(uint64_t national_id, uint16_t country, uint8_t isanimal, uint8_t isextended, uint32_t extended, uint8_t *bits)
    getFDXBits(animalid, countryid, 1, 0, 0, bs);

    // 32, no STT, BIPHASE INVERTED == diphase
    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + sizeof(bs));
    payload->encoding = 2;
    payload->invert = 1;
    payload->separator = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_ASK_SIM_TAG, (uint8_t *)payload,  sizeof(lf_asksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_ASK_SIM_TAG, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,     AlwaysAvailable, "this help"},
    {"demod",   CmdFdxDemod, AlwaysAvailable, "demodulate a FDX-B ISO11784/85 tag from the GraphBuffer"},
    {"read",    CmdFdxRead,  IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",   CmdFdxClone, IfPm3Lf,         "clone animal ID tag to T55x7 (or to q5/T5555)"},
    {"sim",     CmdFdxSim,   IfPm3Lf,         "simulate Animal ID tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFFdx(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// Ask/Biphase Demod then try to locate an ISO 11784/85 ID
// BitStream must contain previously askrawdemod and biphasedemoded data
int detectFDXB(uint8_t *dest, size_t *size) {
    //make sure buffer has enough data
    if (*size < 128 * 2) return -1;
    size_t startIdx = 0;
    uint8_t preamble[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found
    if (*size != 128) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}

int demodFDX(void) {
    return CmdFdxDemod("");
}

int getFDXBits(uint64_t national_id, uint16_t country, uint8_t isanimal, uint8_t isextended, uint32_t extended, uint8_t *bits) {

    // add preamble ten 0x00 and one 0x01
    memset(bits, 0x00, 10);
    bits[10] = 1;

    // 128bits
    // every 9th bit is 0x01, but we can just fill the rest with 0x01 and overwrite
    memset(bits, 0x01, 128);

    // add preamble ten 0x00 and one 0x01
    memset(bits, 0x00, 10);

    // add reserved
    num_to_bytebitsLSBF(0x00, 7, bits + 66);
    num_to_bytebitsLSBF(0x00 >> 7, 7, bits + 74);

    // add animal flag - OK
    bits[65] = isanimal;

    // add extended flag - OK
    bits[81] = isextended;

    // add national code 40bits - OK
    num_to_bytebitsLSBF(national_id >> 0, 8, bits + 11);
    num_to_bytebitsLSBF(national_id >> 8, 8, bits + 20);
    num_to_bytebitsLSBF(national_id >> 16, 8, bits + 29);
    num_to_bytebitsLSBF(national_id >> 24, 8, bits + 38);
    num_to_bytebitsLSBF(national_id >> 32, 6, bits + 47);

    // add country code - OK
    num_to_bytebitsLSBF(country >> 0, 2, bits + 53);
    num_to_bytebitsLSBF(country >> 2, 8, bits + 56);

    // add crc-16 - OK
    uint8_t raw[8];
    for (uint8_t i = 0; i < 8; ++i)
        raw[i] = bytebits_to_byte(bits + 11 + i * 9, 8);

    uint16_t crc = crc16_kermit(raw, 8);
    num_to_bytebitsLSBF(crc >> 0, 8, bits + 83);
    num_to_bytebitsLSBF(crc >> 8, 8, bits + 92);

    // extended data - OK
    num_to_bytebitsLSBF(extended >> 0, 8, bits + 101);
    num_to_bytebitsLSBF(extended >> 8, 8, bits + 110);
    num_to_bytebitsLSBF(extended >> 16, 8, bits + 119);
    return PM3_SUCCESS;
}

