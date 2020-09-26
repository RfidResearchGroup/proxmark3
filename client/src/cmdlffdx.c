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

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>       // tolower

#include "cmdparser.h"    // command_t
#include "comms.h"
#include "commonutil.h"

#include "ui.h"         // PrintAndLog
#include "cmddata.h"
#include "cmdlf.h"      // lf read
#include "crc16.h"      // for checksum crc-16_ccitt
#include "protocols.h"  // for T55xx config register definitions
#include "lfdemod.h"    // parityTest
#include "cmdlft55xx.h" // verifywrite

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
    PrintAndLogEx(NORMAL, "Clone a FDX-B animal tag to a T55x7 or Q5/T5555 tag.");
    PrintAndLogEx(NORMAL, "Usage: lf fdx clone [h] [c <country code>] [a <national code>] [e <extended>] <s> <Q5>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h               : This help");
    PrintAndLogEx(NORMAL, "      c <country>     : (dec) Country code");
    PrintAndLogEx(NORMAL, "      n <national>    : (dec) National code");
    PrintAndLogEx(NORMAL, "      e <extended>    : (hex) Extended data");
    PrintAndLogEx(NORMAL, "      s               : Set animal bit");
    PrintAndLogEx(NORMAL, "      <Q5>            : Specify writing to Q5/T5555 tag");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("       lf fdx clone c 999 n 112233 s"));
    PrintAndLogEx(NORMAL, _YELLOW_("       lf fdx clone c 999 n 112233 e 16a"));
    return PM3_SUCCESS;
}

static int usage_lf_fdx_read(void) {
    PrintAndLogEx(NORMAL, "Read FDX-B animal tag");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf fdx read [h] [@]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h               : This help");
    PrintAndLogEx(NORMAL, "      @               : run continuously until a key is pressed (optional)");
    PrintAndLogEx(NORMAL, "Note that the continuous mode is less verbose");
    return PM3_SUCCESS;
}

static int usage_lf_fdx_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of FDX-B animal tag");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf fdx sim [h] [c <country code>] [n <national code>] [e <extended>] <s> <Q5>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h               : This help");
    PrintAndLogEx(NORMAL, "      c <country>     : (dec) Country code");
    PrintAndLogEx(NORMAL, "      n <national>    : (dec) National code");
    PrintAndLogEx(NORMAL, "      e <extended>    : (hex) Extended data");
    PrintAndLogEx(NORMAL, "      s               : Set animal bit");
    PrintAndLogEx(NORMAL, "      <Q5>            : Specify writing to Q5/T5555 tag");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("       lf fdx sim c 999 n 112233 s"));
    PrintAndLogEx(NORMAL, _YELLOW_("       lf fdx sim c 999 n 112233 e 16a"));
    return PM3_SUCCESS;
}

// clearing the topbit needed for the preambl detection.
static void verify_values(uint64_t *animalid, uint32_t *countryid, uint32_t *extended, uint8_t *is_animal) {
    if ((*animalid & 0x3FFFFFFFFF) != *animalid) {
        *animalid &= 0x3FFFFFFFFF;
        PrintAndLogEx(INFO, "Animal ID truncated to 38bits: " _YELLOW_("%"PRIx64), *animalid);
    }
    if ((*countryid & 0x3FF) != *countryid) {
        *countryid &= 0x3FF;
        PrintAndLogEx(INFO, "Country ID truncated to 10bits:" _YELLOW_("%03d"), *countryid);
    }
    if ((*extended & 0xFFF) != *extended) {
        *extended &= 0xFFF;
        PrintAndLogEx(INFO, "Extended truncated to 24bits: " _YELLOW_("0x%03X"), *extended);
    }

    *is_animal &= 0x01;
}

static inline uint32_t bitcount(uint32_t a) {
#if defined __GNUC__
    return __builtin_popcountl(a);
#else
    a = a - ((a >> 1) & 0x55555555);
    a = (a & 0x33333333) + ((a >> 2) & 0x33333333);
    return (((a + (a >> 4)) & 0x0f0f0f0f) * 0x01010101) >> 24;
#endif
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
int demodFDX(bool verbose) {
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
            PrintAndLogEx(DEBUG, "DEBUG: Error - FDX-B Size not correct: %zu", size);
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
        PrintAndLogEx(DEBUG, "DEBUG: Error - FDX-B error removeParity: %zu", size);
        return PM3_ESOFT;
    }

    //got a good demod
    uint8_t offset;
    uint64_t NationalCode = ((uint64_t)(bytebits_to_byteLSBF(DemodBuffer + 32, 6)) << 32) | bytebits_to_byteLSBF(DemodBuffer, 32);

    offset = 38;
    uint16_t countryCode = bytebits_to_byteLSBF(DemodBuffer + offset, 10);

    offset += 10;
    uint8_t dataBlockBit = DemodBuffer[offset];

    offset++;
    uint32_t reservedCode = bytebits_to_byteLSBF(DemodBuffer + offset, 14);

    offset += 14;
    uint8_t animalBit = DemodBuffer[offset];

    offset++;
    uint16_t crc = bytebits_to_byteLSBF(DemodBuffer + offset, 16);

    offset += 16;
    uint32_t extended = bytebits_to_byteLSBF(DemodBuffer + offset, 24);

    uint64_t rawid = (uint64_t)(bytebits_to_byte(DemodBuffer, 32)) << 32 | bytebits_to_byte(DemodBuffer + 32, 32);
    uint8_t raw[8];
    num_to_bytes(rawid, 8, raw);

    if (!verbose) {
        PROMPT_CLEARLINE;
        PrintAndLogEx(SUCCESS, "Animal ID          " _GREEN_("%04u-%012"PRIu64), countryCode, NationalCode);
        return PM3_SUCCESS;
    }
    PrintAndLogEx(SUCCESS, "FDX-B / ISO 11784/5 Animal");
    PrintAndLogEx(SUCCESS, "Animal ID          " _GREEN_("%04u-%012"PRIu64), countryCode, NationalCode);
    PrintAndLogEx(SUCCESS, "National Code      " _GREEN_("%012" PRIu64) " (0x%" PRIX64 ")", NationalCode, NationalCode);
    PrintAndLogEx(SUCCESS, "Country Code       " _GREEN_("%04u"), countryCode);
    PrintAndLogEx(SUCCESS, "Reserved/RFU       %u (0x%04X)", reservedCode,  reservedCode);
    PrintAndLogEx(SUCCESS, "  Animal bit set?  %s", animalBit ? _YELLOW_("True") : "False");
    PrintAndLogEx(SUCCESS, "      Data block?  %s  [value 0x%X]", dataBlockBit ? _YELLOW_("True") : "False", extended);

    uint8_t c[] = {0, 0};
    compute_crc(CRC_11784, raw, sizeof(raw), &c[0], &c[1]);
    PrintAndLogEx(SUCCESS, "CRC-16             0x%04X (%s)", crc, (crc == (c[1] << 8 | c[0])) ? _GREEN_("ok") : _RED_("fail"));
    // iceman: crc doesn't protect the extended data?
    PrintAndLogEx(SUCCESS, "Raw                " _GREEN_("%s"), sprint_hex(raw, 8));

    if (g_debugMode) {
        PrintAndLogEx(DEBUG, "Start marker %d;   Size %zu", preambleIndex, size);
        char *bin = sprint_bin_break(DemodBuffer, size, 16);
        PrintAndLogEx(DEBUG, "DEBUG bin stream:\n%s", bin);
    }

    uint8_t bt_par = (extended & 0x100) >> 8;
    uint8_t bt_temperature = extended & 0xff;
    uint8_t bt_calc_parity = (bitcount(bt_temperature) & 0x1) ? 0 : 1;
    uint8_t is_bt_temperature = (bt_calc_parity == bt_par) && !(extended & 0xe00) ;

    if (is_bt_temperature) {
        float bt_F = 74 + bt_temperature * 0.2;
        float bt_C = (bt_F - 32) / 1.8;
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, "Bio-Thermo detected");
        PrintAndLogEx(INFO, "   temperature     " _GREEN_("%.1f")" F / " _GREEN_("%.1f") " C", bt_F, bt_C);
    }

    // set block 0 for later
    //g_DemodConfig = T55x7_MODULATION_DIPHASE | T55x7_BITRATE_RF_32 | 4 << T55x7_MAXBLOCK_SHIFT;

    return PM3_SUCCESS;
}

static int CmdFdxDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    return demodFDX(true);
}

static int CmdFdxRead(const char *Cmd) {
    sample_config config;
    memset(&config, 0, sizeof(sample_config));
    int retval = lf_getconfig(&config);
    if (retval != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "failed to get current device LF config");
        return retval;
    }

    bool errors = false;
    bool continuous = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_fdx_read();
            case '@':
                continuous = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors) return usage_lf_fdx_read();
    int16_t tmp_div = config.divisor;
    if (tmp_div != LF_DIVISOR_134) {
        config.divisor = LF_DIVISOR_134;
        config.verbose = false;
        retval = lf_config(&config);
        if (retval != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "failed to change LF configuration");
            return retval;
        }
    }
    if (continuous) {
        PrintAndLogEx(INFO, "Press " _GREEN_("Enter") " to exit");
    }
    int ret = PM3_SUCCESS;
    do {
        retval = lf_read(false, 10000);
        if (retval != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "failed to get LF read from device");
            return retval;
        }
        ret = demodFDX(!continuous); // be verbose only if not in continuous mode
        if (kbd_enter_pressed()) {
            break;
        }
        PrintAndLogEx(INPLACE, "");
    } while (continuous);
    if (tmp_div != LF_DIVISOR_134) {
        config.divisor = tmp_div;
        retval = lf_config(&config);
        if (retval != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "failed to restore LF configuration");
            return retval;
        }
    }
    return ret;
}

static int CmdFdxClone(const char *Cmd) {

    uint32_t country_code = 0, extended = 0;
    uint64_t national_code = 0;
    uint8_t is_animal = 0, cmdp = 0;
    bool errors = false, has_extended = false,  q5 = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_fdx_clone();
            case 'c': {
                country_code = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            }
            case 'n': {
                national_code = param_get64ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            }
            case 'e': {
                extended = param_get32ex(Cmd, cmdp + 1, 0, 16);
                has_extended = true;
                cmdp += 2;
                break;
            }
            case 's': {
                is_animal = 1;
                cmdp++;
                break;
            }
            case 'q': {
                q5 = true;
                cmdp++;
                break;
            }
            default: {
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
            }
        }
    }
    if (errors || strlen(Cmd) == 0) return usage_lf_fdx_clone();

    verify_values(&national_code, &country_code, &extended, &is_animal);

    PrintAndLogEx(INFO, "      Country code %"PRIu32, country_code);
    PrintAndLogEx(INFO, "     National code %"PRIu64, national_code);
    PrintAndLogEx(INFO, "    Set animal bit %c", (is_animal) ? 'Y' : 'N');
    PrintAndLogEx(INFO, "Set data block bit %c", (has_extended) ? 'Y' : 'N');
    PrintAndLogEx(INFO, "     Extended data 0x%"PRIX32, extended);
    PrintAndLogEx(INFO, "               RFU 0");

    uint8_t *bits = calloc(128, sizeof(uint8_t));
    if (getFDXBits(national_code, country_code, is_animal, has_extended, extended, bits) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        free(bits);
        return PM3_ESOFT;
    }

    uint32_t blocks[5] = {T55x7_MODULATION_DIPHASE | T55x7_BITRATE_RF_32 | 4 << T55x7_MAXBLOCK_SHIFT, 0, 0, 0, 0};

    //Q5
    if (q5)
        blocks[0] = T5555_FIXED | T5555_MODULATION_BIPHASE | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(32) | 4 << T5555_MAXBLOCK_SHIFT;

    // convert from bit stream to block data
    blocks[1] = bytebits_to_byte(bits, 32);
    blocks[2] = bytebits_to_byte(bits + 32, 32);
    blocks[3] = bytebits_to_byte(bits + 64, 32);
    blocks[4] = bytebits_to_byte(bits + 96, 32);

    free(bits);

    PrintAndLogEx(INFO, "Preparing to clone FDX-B to " _YELLOW_("%s") " with animal ID: " _GREEN_("%04u-%"PRIu64), (q5) ? "Q5/T5555" : "T55x7", country_code, national_code);
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf fdx read`") " to verify");
    return res;
}

static int CmdFdxSim(const char *Cmd) {

    uint32_t country_code = 0, extended = 0;
    uint64_t national_code = 0;
    uint8_t is_animal = 0, cmdp = 0;
    bool errors = false, has_extended = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_fdx_sim();
            case 'c': {
                country_code = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            }
            case 'n': {
                national_code = param_get64ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            }
            case 'e': {
                extended = param_get32ex(Cmd, cmdp + 1, 0, 10);
                has_extended = true;
                cmdp += 2;
                break;
            }
            case 's': {
                is_animal = 1;
                cmdp++;
                break;
            }
            default: {
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
            }
        }
    }
    if (errors) return usage_lf_fdx_sim();

    verify_values(&national_code, &country_code, &extended, &is_animal);

    PrintAndLogEx(INFO, "      Country code %"PRIu32, country_code);
    PrintAndLogEx(INFO, "     National code %"PRIu64, national_code);
    PrintAndLogEx(INFO, "    Set animal bit %c", (is_animal) ? 'Y' : 'N');
    PrintAndLogEx(INFO, "Set data block bit %c", (has_extended) ? 'Y' : 'N');
    PrintAndLogEx(INFO, "     Extended data 0x%"PRIX32, extended);
    PrintAndLogEx(INFO, "               RFU 0");

    PrintAndLogEx(SUCCESS, "Simulating FDX-B animal ID: " _GREEN_("%04u-%"PRIu64), country_code, national_code);

    uint8_t *bits = calloc(128, sizeof(uint8_t));
    if (getFDXBits(national_code, country_code, is_animal, (extended > 0), extended, bits) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        free(bits);
        return PM3_ESOFT;
    }

    // 32, no STT, BIPHASE INVERTED == diphase
    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + 128);
    payload->encoding = 2;
    payload->invert = 1;
    payload->separator = 0;
    payload->clock = 32;
    memcpy(payload->data, bits, 128);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload,  sizeof(lf_asksim_t) + 128);

    free(bits);
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_ASK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,     AlwaysAvailable, "this help"},
    {"demod",   CmdFdxDemod, AlwaysAvailable, "demodulate a FDX-B ISO11784/85 tag from the GraphBuffer"},
    {"read",    CmdFdxRead,  IfPm3Lf,         "attempt to read at 134kHz and extract tag data"},
    {"clone",   CmdFdxClone, IfPm3Lf,         "clone animal ID tag to T55x7 or Q5/T5555"},
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

int getFDXBits(uint64_t national_code, uint16_t country_code, uint8_t is_animal, uint8_t is_extended, uint32_t extended, uint8_t *bits) {

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
    bits[81] = is_animal;

    // add extended flag - OK
    bits[65] = is_extended;

    // add national code 40bits - OK
    num_to_bytebitsLSBF(national_code >> 0, 8, bits + 11);
    num_to_bytebitsLSBF(national_code >> 8, 8, bits + 20);
    num_to_bytebitsLSBF(national_code >> 16, 8, bits + 29);
    num_to_bytebitsLSBF(national_code >> 24, 8, bits + 38);
    num_to_bytebitsLSBF(national_code >> 32, 6, bits + 47);

    // add country code - OK
    num_to_bytebitsLSBF(country_code >> 0, 2, bits + 53);
    num_to_bytebitsLSBF(country_code >> 2, 8, bits + 56);

    // add crc-16 - OK
    uint8_t raw[8];
    for (uint8_t i = 0; i < 8; ++i)
        raw[i] = bytebits_to_byte(bits + 11 + i * 9, 8);

    init_table(CRC_11784);
    uint16_t crc = crc16_fdx(raw, 8);
    num_to_bytebitsLSBF(crc >> 0, 8, bits + 83);
    num_to_bytebitsLSBF(crc >> 8, 8, bits + 92);

    // extended data - OK
    num_to_bytebitsLSBF(extended >> 0, 8, bits + 101);
    num_to_bytebitsLSBF(extended >> 8, 8, bits + 110);
    num_to_bytebitsLSBF(extended >> 16, 8, bits + 119);

    // 8  16 24 32 40 48 49
    // A8 28 0C 92 EA 6F 00 01
    // A8 28 0C 92 EA 6F 80 00
    return PM3_SUCCESS;
}

