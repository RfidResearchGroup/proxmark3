//-----------------------------------------------------------------------------
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
// Low frequency fdx-b tag commands
// Differential Biphase, rf/32, 128 bits (known)
//-----------------------------------------------------------------------------

#include "cmdlffdxb.h"
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>        // tolower
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "commonutil.h"
#include "ui.h"           // PrintAndLog
#include "cmddata.h"
#include "cmdlf.h"        // lf read
#include "crc16.h"        // for checksum crc-16_ccitt
#include "protocols.h"    // for T55xx config register definitions
#include "lfdemod.h"      // parityTest
#include "cmdlft55xx.h"   // verifywrite
#include "cliparser.h"
#include "cmdlfem4x05.h"  // EM defines

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

static int getFDXBBits(uint64_t national_code, uint16_t country_code, uint8_t is_animal, uint8_t is_extended, uint32_t extended, uint8_t *bits) {

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
    uint16_t crc = crc16_fdxb(raw, 8);
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

// clearing the topbit needed for the preambl detection.
static void verify_values(uint64_t *animalid, uint32_t *countryid, uint32_t *extended) {
    if ((*animalid & 0x3FFFFFFFFF) != *animalid) {
        *animalid &= 0x3FFFFFFFFF;
        PrintAndLogEx(INFO, "Animal ID truncated to 38bits: " _YELLOW_("%"PRIx64), *animalid);
    }
    if ((*countryid & 0x3FF) != *countryid) {
        *countryid &= 0x3FF;
        PrintAndLogEx(INFO, "Country ID truncated to 10bits:" _YELLOW_("%03d"), *countryid);
    }
    if ((*extended & 0xFFFFFF) != *extended) {
        *extended &= 0xFFFFFF;
        PrintAndLogEx(INFO, "Extended truncated to 24bits: " _YELLOW_("0x%03X"), *extended);
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
    PrintAndLogEx(SUCCESS, "CRC:           0x%04X - [%04X] - %s", crc_16, calcCrc, (calcCrc == crc_16) ? _GREEN_("ok") : _RED_("fail") );

    if (g_debugMode) {
        PrintAndLogEx(DEBUG, "Start marker %d;   Size %d", preambleIndex, size);
        char *bin = sprint_bytebits_bin_break(bs, size, 16);
        PrintAndLogEx(DEBUG, "DEBUG BinStream:\n%s", bin);
    }
    return PM3_SUCCESS;
}
*/

// For the country part:
// wget -q -O - "https://en.wikipedia.org/w/index.php?title=List_of_ISO_3166_country_codes&action=raw" | awk '/id=/{match($0, /\[\[([^\]|]*)/, a); name=a[1];getline;getline;getline;getline;getline;match($0, /numeric#([0-9]*)/, a);num=a[1]; if (num != "") {printf "    { %3u, \"%s\" },\n", num, name}}'
// Beware the bottom of the list contains also Manufacturers list
static const fdxbCountryMapping_t fdxbCountryMapping[] = {
    {   4, "Afghanistan" },
    {   8, "Albania" },
    {  12, "Algeria" },
    {  16, "American Samoa" },
    {  20, "Andorra" },
    {  24, "Angola" },
    { 660, "Anguilla" },
    {  10, "Antarctica" },
    {  28, "Antigua and Barbuda" },
    {  32, "Argentina" },
    {  51, "Armenia" },
    { 533, "Aruba" },
    {  40, "Austria" },
    {  31, "Azerbaijan" },
    {  44, "The Bahamas" },
    {  48, "Bahrain" },
    {  50, "Bangladesh" },
    {  52, "Barbados" },
    { 112, "Belarus" },
    {  56, "Belgium" },
    {  84, "Belize" },
    { 204, "Benin" },
    {  60, "Bermuda" },
    {  64, "Bhutan" },
    {  68, "Bolivia" },
    { 535, "Bonaire" },
    {  70, "Bosnia and Herzegovina" },
    {  72, "Botswana" },
    {  74, "Bouvet Island" },
    {  76, "Brazil" },
    {  86, "British Indian Ocean Territory" },
    { 100, "Bulgaria" },
    { 854, "Burkina Faso" },
    { 132, "Cape Verde" },
    { 116, "Cambodia" },
    { 120, "Cameroon" },
    { 124, "Canada" },
    { 140, "Central African Republic" },
    { 148, "Chad" },
    { 152, "Chile" },
    { 156, "China" },
    { 170, "Colombia" },
    { 174, "Comoros" },
    { 180, "Democratic Republic of the Congo" },
    { 178, "Republic of the Congo" },
    { 184, "Cook Islands" },
    { 384, "Ivory Coast" },
    { 191, "Croatia" },
    { 192, "Cuba" },
    { 531, "Curaçao" },
    { 196, "Cyprus" },
    { 203, "Czech Republic" },
    { 262, "Djibouti" },
    { 212, "Dominica" },
    { 214, "Dominican Republic" },
    { 818, "Egypt" },
    { 222, "El Salvador" },
    { 232, "Eritrea" },
    { 233, "Estonia" },
    { 748, "Eswatini" },
    { 231, "Ethiopia" },
    { 238, "Falkland Islands" },
    { 234, "Faroe Islands" },
    { 242, "Fiji" },
    { 246, "Finland" },
    { 250, "France" },
    { 254, "French Guiana" },
    { 258, "French Polynesia" },
    { 260, "French Southern Territories" },
    { 266, "Gabon" },
    { 270, "The Gambia" },
    { 268, "Georgia (country)" },
    { 276, "Germany" },
    { 288, "Ghana" },
    { 292, "Gibraltar" },
    { 304, "Greenland" },
    { 308, "Grenada" },
    { 312, "Guadeloupe" },
    { 316, "Guam" },
    { 320, "Guatemala" },
    { 831, "Bailiwick of Guernsey" },
    { 324, "Guinea" },
    { 624, "Guinea-Bissau" },
    { 328, "Guyana" },
    { 332, "Haiti" },
    { 336, "Holy See" },
    { 340, "Honduras" },
    { 344, "Hong Kong" },
    { 348, "Hungary" },
    { 352, "Iceland" },
    { 356, "India" },
    { 360, "Indonesia" },
    { 364, "Iran (Islamic Republic of)" },
    { 368, "Iraq" },
    { 372, "Republic of Ireland" },
    { 833, "Isle of Man" },
    { 376, "Israel" },
    { 380, "Italy" },
    { 832, "Jersey" },
    { 400, "Jordan" },
    { 398, "Kazakhstan" },
    { 404, "Kenya" },
    { 296, "Kiribati" },
    { 408, "North Korea" },
    { 410, "South Korea" },
    { 414, "Kuwait" },
    { 417, "Kyrgyzstan" },
    { 418, "Laos" },
    { 428, "Latvia" },
    { 422, "Lebanon" },
    { 426, "Lesotho" },
    { 430, "Liberia" },
    { 434, "Libya" },
    { 438, "Liechtenstein" },
    { 440, "Lithuania" },
    { 442, "Luxembourg" },
    { 446, "Macau" },
    { 807, "North Macedonia" },
    { 450, "Madagascar" },
    { 454, "Malawi" },
    { 458, "Malaysia" },
    { 462, "Maldives" },
    { 466, "Mali" },
    { 470, "Malta" },
    { 584, "Marshall Islands" },
    { 474, "Martinique" },
    { 478, "Mauritania" },
    { 480, "Mauritius" },
    { 175, "Mayotte" },
    { 484, "Mexico" },
    { 583, "Federated States of Micronesia" },
    { 498, "Moldova" },
    { 492, "Monaco" },
    { 496, "Mongolia" },
    { 499, "Montenegro" },
    { 500, "Montserrat" },
    { 504, "Morocco" },
    { 508, "Mozambique" },
    { 104, "Myanmar" },
    { 516, "Namibia" },
    { 520, "Nauru" },
    { 524, "Nepal" },
    { 528, "Kingdom of the Netherlands" },
    { 540, "New Caledonia" },
    { 554, "New Zealand" },
    { 558, "Nicaragua" },
    { 562, "Niger" },
    { 566, "Nigeria" },
    { 570, "Niue" },
    { 574, "Norfolk Island" },
    { 578, "Norway" },
    { 512, "Oman" },
    { 586, "Pakistan" },
    { 585, "Palau" },
    { 275, "State of Palestine" },
    { 591, "Panama" },
    { 598, "Papua New Guinea" },
    { 600, "Paraguay" },
    { 608, "Philippines" },
    { 612, "Pitcairn Islands" },
    { 616, "Poland" },
    { 620, "Portugal" },
    { 630, "Puerto Rico" },
    { 634, "Qatar" },
    { 638, "Réunion" },
    { 642, "Romania" },
    { 643, "Russia" },
    { 646, "Rwanda" },
    { 654, "Saint Helena" },
    { 659, "Saint Kitts and Nevis" },
    { 662, "Saint Lucia" },
    { 663, "Collectivity of Saint Martin" },
    { 666, "Saint Pierre and Miquelon" },
    { 670, "Saint Vincent and the Grenadines" },
    { 882, "Samoa" },
    { 674, "San Marino" },
    { 678, "São Tomé and Príncipe" },
    { 682, "Saudi Arabia" },
    { 688, "Serbia" },
    { 690, "Seychelles" },
    { 694, "Sierra Leone" },
    { 702, "Singapore" },
    { 703, "Slovakia" },
    { 705, "Slovenia" },
    {  90, "Solomon Islands" },
    { 706, "Somalia" },
    { 710, "South Africa" },
    { 239, "South Georgia and the South Sandwich Islands" },
    { 724, "Spain" },
    { 144, "Sri Lanka" },
    { 729, "Sudan" },
    { 740, "Suriname" },
    { 744, "Svalbard" },
    { 752, "Sweden" },
    { 756, "Switzerland" },
    { 760, "Syria" },
    { 158, "Taiwan" },
    { 762, "Tajikistan" },
    { 834, "Tanzania" },
    { 764, "Thailand" },
    { 626, "East Timor" },
    { 768, "Togo" },
    { 772, "Tokelau" },
    { 776, "Tonga" },
    { 780, "Trinidad and Tobago" },
    { 788, "Tunisia" },
    { 792, "Turkey" },
    { 795, "Turkmenistan" },
    { 796, "Turks and Caicos Islands" },
    { 798, "Tuvalu" },
    { 800, "Uganda" },
    { 804, "Ukraine" },
    { 784, "United Arab Emirates" },
    { 826, "United Kingdom" },
    { 581, "United States Minor Outlying Islands" },
    { 840, "United States" },
    { 860, "Uzbekistan" },
    { 548, "Vanuatu" },
    { 704, "Vietnam" },
    {  92, "British Virgin Islands" },
    { 850, "United States Virgin Islands" },
    { 732, "Western Sahara" },
    { 887, "Yemen" },
    { 894, "Zambia" },
    { 716, "Zimbabwe" },

    // Manufacturers list:
    { 952, "JECTA" },
    { 953, "Cromasa Identificacion electronica S.A."},
    { 955, "Reseaumatique" },
    { 956, "Trovan Ltd. (ACK Reunite)" },
    { 958, "Pet ID" },
    { 959, "Global ID Technologies" },
    { 961, "Mannings I.A.I.D." },
    { 963, "Korth Eletro Mecanica LTDA" },
    { 965, "4D Technology Co. Ltd" },
    { 966, "PetCode" },
    { 967, "Rfdynamics / M4S ID in Canada" },
    { 968, "AEG / EIDAP in Canada" },
    { 972, "Planet ID" },
    { 975, "Sokymat" },
    { 977, "AVID" },
    { 978, "Ordicam" },
    { 981, "Microfindr, Datamars, Found Animals, Crystal Tag, Banfield, Bayer resQ, Peeva" },
    { 982, "24 Pet Watch (Allflex)" },
    { 985, "HomeAgain (Destron Fearing/Digital Angel)" },
    { 991, "Peeva" },
    { 999, "Test range" },
    { 0,   "N/A" } // must be the last entry
};

static const char *mapFDBX(uint16_t countryCode) {
    uint16_t i = 0;
    while (fdxbCountryMapping[i].code > 0) {
        if (countryCode == fdxbCountryMapping[i].code) {
            return fdxbCountryMapping[i].desc;
        }
        i++;
    }
    return fdxbCountryMapping[i].desc;
}

//see ASKDemod for what args are accepted
//almost the same demod as cmddata.c/CmdFDXBdemodBI
int demodFDXB(bool verbose) {
    //Differential Biphase / di-phase (inverted biphase)
    //get binary from ask wave
    if (ASKbiphaseDemod(0, 32, 1, 100, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - FDX-B ASKbiphaseDemod failed");
        return PM3_ESOFT;
    }
    size_t size = g_DemodBufferLen;
    int preambleIndex = detectFDXB(g_DemodBuffer, &size);
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

    // set and leave g_DemodBuffer intact
    setDemodBuff(g_DemodBuffer, 128, preambleIndex);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (preambleIndex * g_DemodClock));


    // remove marker bits (1's every 9th digit after preamble) (pType = 2)
    size = removeParity(g_DemodBuffer, 11, 9, 2, 117);
    if (size != 104) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - FDX-B error removeParity: %zu", size);
        return PM3_ESOFT;
    }

    //got a good demod
    uint8_t offset;
    // ISO: bits 27..64
    uint64_t NationalCode = ((uint64_t)(bytebits_to_byteLSBF(g_DemodBuffer + 32, 6)) << 32) | bytebits_to_byteLSBF(g_DemodBuffer, 32);

    offset = 38;
    // ISO: bits 17..26
    uint16_t countryCode = bytebits_to_byteLSBF(g_DemodBuffer + offset, 10);

    offset += 10;
    // ISO: bits 16
    uint8_t dataBlockBit = g_DemodBuffer[offset];

    offset++;
    // ISO: bits 15
    uint8_t rudiBit = g_DemodBuffer[offset];

    offset++;
    // ISO: bits 10..14
    uint32_t reservedCode = bytebits_to_byteLSBF(g_DemodBuffer + offset, 5);

    offset += 5;
    // ISO: bits 5..9
    uint32_t userInfo = bytebits_to_byteLSBF(g_DemodBuffer + offset, 5);

    offset += 5;
    // ISO: bits 2..4
    uint32_t replacementNr = bytebits_to_byteLSBF(g_DemodBuffer + offset, 3);

    offset += 3;
    uint8_t animalBit = g_DemodBuffer[offset];

    offset++;
    uint16_t crc = bytebits_to_byteLSBF(g_DemodBuffer + offset, 16);

    offset += 16;
    uint32_t extended = bytebits_to_byteLSBF(g_DemodBuffer + offset, 24);

    uint64_t rawid = (uint64_t)(bytebits_to_byte(g_DemodBuffer, 32)) << 32 | bytebits_to_byte(g_DemodBuffer + 32, 32);
    uint8_t raw[8];
    num_to_bytes(rawid, 8, raw);

    if (!verbose) {
        PROMPT_CLEARLINE;
        PrintAndLogEx(SUCCESS, "Animal ID          " _GREEN_("%04u-%012"PRIu64), countryCode, NationalCode);
        return PM3_SUCCESS;
    }
    PrintAndLogEx(SUCCESS, "FDX-B / ISO 11784/5 Animal");
    PrintAndLogEx(SUCCESS, "Animal ID          " _GREEN_("%03u-%012"PRIu64), countryCode, NationalCode);
    PrintAndLogEx(SUCCESS, "National Code      " _GREEN_("%012" PRIu64) " (0x%" PRIX64 ")", NationalCode, NationalCode);
    PrintAndLogEx(SUCCESS, "Country Code       " _GREEN_("%03u") " - %s", countryCode, mapFDBX(countryCode));
    PrintAndLogEx(SUCCESS, "Reserved/RFU       %u (0x%04X)", reservedCode,  reservedCode);
    PrintAndLogEx(SUCCESS, "  Animal bit set?  %s", animalBit ? _YELLOW_("True") : "False");
    PrintAndLogEx(SUCCESS, "      Data block?  %s  [value 0x%X]", dataBlockBit ? _YELLOW_("True") : "False", extended);
    PrintAndLogEx(SUCCESS, "        RUDI bit?  %s", rudiBit ? _YELLOW_("True") " (advanced transponder)" : "False");
    PrintAndLogEx(SUCCESS, "       User Info?  %u %s", userInfo, userInfo == 0 ? "(RFU)" : "");
    PrintAndLogEx(SUCCESS, "  Replacement No?  %u %s", replacementNr, replacementNr == 0 ? "(RFU)" : "");

    uint8_t c[] = {0, 0};
    compute_crc(CRC_11784, raw, sizeof(raw), &c[0], &c[1]);
    PrintAndLogEx(SUCCESS, "CRC-16             0x%04X ( %s )", crc, (crc == (c[1] << 8 | c[0])) ? _GREEN_("ok") : _RED_("fail"));
    // iceman: crc doesn't protect the extended data?
    PrintAndLogEx(SUCCESS, "Raw                " _GREEN_("%s"), sprint_hex(raw, 8));

    if (g_debugMode) {
        PrintAndLogEx(DEBUG, "Start marker %d;   Size %zu", preambleIndex, size);
        char *bin = sprint_bytebits_bin_break(g_DemodBuffer, size, 16);
        PrintAndLogEx(DEBUG, "DEBUG bin stream:\n%s", bin);
    }

    uint8_t bt_par = (extended & 0x100) >> 8;
    uint8_t bt_temperature = extended & 0xff;
    uint8_t bt_calc_parity = (bitcount32(bt_temperature) & 0x1) ? 0 : 1;
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

static int CmdFdxBDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf fdxb demod",
                  "Try to find FDX-B preamble, if found decode / descramble data",
                  "lf fdxb demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodFDXB(true);
}

static int CmdFdxBReader(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf fdxb reader",
                  "read a FDX-B animal tag\n"
                  "Note that the continuous mode is less verbose",
                  "lf fdxb reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    sample_config config;
    memset(&config, 0, sizeof(sample_config));
    int res = lf_getconfig(&config);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "failed to get current device LF config");
        return res;
    }

    config.verbose = false;

    int16_t curr_div = config.divisor;
    int16_t old_div = curr_div;

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    int ret = PM3_SUCCESS;
    do {

        if (curr_div == LF_DIVISOR_125) {
            config.divisor = LF_DIVISOR_134;
            res = lf_config(&config);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "failed to change to 134 KHz LF configuration");
                return res;
            }
        } else {
            config.divisor = LF_DIVISOR_125;
            res = lf_config(&config);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "failed to change to 125 KHz LF configuration");
                return res;
            }
        }
        curr_div = config.divisor;

        lf_read(false, 10000);
        ret = demodFDXB(!cm); // be verbose only if not in continuous mode

    } while (cm && !kbd_enter_pressed());


    if (old_div != curr_div) {
        config.divisor = old_div;
        res = lf_config(&config);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "failed to restore LF configuration");
            return res;
        }
    }
    return ret;
}

static int CmdFdxBClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf fdxb clone",
                  "clone a FDX-B tag to a T55x7, Q5/T5555 or EM4305/4469 tag.",
                  "lf fdxb clone --country 999 --national 1337 --animal        -> encode for T55x7 tag, with animal bit\n"
                  "lf fdxb clone --country 999 --national 1337 --extended 016A -> encode for T55x7 tag, with extended data\n"
                  "lf fdxb clone --country 999 --national 1337 --q5            -> encode for Q5/T5555 tag\n"
                  "lf fdxb clone --country 999 --national 1337 --em            -> encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1("c", "country", "<dec>", "country code"),
        arg_u64_1("n", "national", "<dec>", "national code"),
        arg_str0(NULL, "extended", "<hex>", "extended data"),
        arg_lit0("a", "animal", "optional - set animal bit"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint32_t country_code = arg_get_u32_def(ctx, 1, 0);
    uint64_t national_code = arg_get_u64_def(ctx, 2, 0);

    int extended_len = 0;
    uint8_t edata[3] = {0};
    CLIGetHexWithReturn(ctx, 3, edata, &extended_len);

    bool is_animal = arg_get_lit(ctx, 4);
    bool q5 = arg_get_lit(ctx, 5);
    bool em = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    uint32_t extended = 0;
    bool has_extended = false;
    if (extended_len) {
        extended = bytes_to_num(edata, extended_len);
        has_extended = true;
    }

    verify_values(&national_code, &country_code, &extended);

    PrintAndLogEx(INFO, "Country code........ %"PRIu32, country_code);
    PrintAndLogEx(INFO, "National code....... %"PRIu64, national_code);
    PrintAndLogEx(INFO, "Set animal bit...... %c", (is_animal) ? 'Y' : 'N');
    PrintAndLogEx(INFO, "Set data block bit.. %c", (has_extended) ? 'Y' : 'N');
    PrintAndLogEx(INFO, "Extended data....... 0x%"PRIX32, extended);
    PrintAndLogEx(INFO, "RFU................. 0");

    uint8_t *bs = calloc(128, sizeof(uint8_t));
    if (getFDXBBits(national_code, country_code, is_animal, has_extended, extended, bs) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        free(bs);
        return PM3_ESOFT;
    }

    uint32_t blocks[5] = {T55x7_MODULATION_DIPHASE | T55x7_BITRATE_RF_32 | 4 << T55x7_MAXBLOCK_SHIFT, 0, 0, 0, 0};
    char cardtype[16] = {"T55x7"};

    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_BIPHASE | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(32) | 4 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        blocks[0] = EM4305_FDXB_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    // convert from bit stream to block data
    blocks[1] = bytebits_to_byte(bs, 32);
    blocks[2] = bytebits_to_byte(bs + 32, 32);
    blocks[3] = bytebits_to_byte(bs + 64, 32);
    blocks[4] = bytebits_to_byte(bs + 96, 32);

    free(bs);

    PrintAndLogEx(INFO, "Preparing to clone FDX-B to " _YELLOW_("%s") " with animal ID: " _GREEN_("%04u-%"PRIu64)
                  , cardtype
                  , country_code
                  , national_code
                 );
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf fdxb reader`") " to verify");
    return res;
}

static int CmdFdxBSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf fdxb sim",
                  "Enables simulation of  FDX-B animal tag.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf fdxb sim --country 999 --national 1337 --animal\n"
                  "lf fdxb sim --country 999 --national 1337 --extended 016A\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1("c", "country", "<dec>", "country code"),
        arg_u64_1("n", "national", "<dec>", "national code"),
        arg_str0(NULL, "extended", "<hex>", "extended data"),
        arg_lit0("a", "animal", "optional - set animal bit"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint32_t country_code = arg_get_u32_def(ctx, 1, 0);
    uint64_t national_code = arg_get_u64_def(ctx, 2, 0);
    int extended_len = 0;
    uint8_t edata[3] = {0};
    CLIGetHexWithReturn(ctx, 3, edata, &extended_len);

    bool is_animal = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    uint32_t extended = 0;
    bool has_extended = false;
    if (extended_len) {
        extended = bytes_to_num(edata, extended_len);
        has_extended = true;
    }

    verify_values(&national_code, &country_code, &extended);

    PrintAndLogEx(INFO, "Country code........ %"PRIu32, country_code);
    PrintAndLogEx(INFO, "National code....... %"PRIu64, national_code);
    PrintAndLogEx(INFO, "Set animal bit...... %c", (is_animal) ? 'Y' : 'N');
    PrintAndLogEx(INFO, "Set data block bit.. %c", (has_extended) ? 'Y' : 'N');
    PrintAndLogEx(INFO, "Extended data....... 0x%"PRIX16, extended);
    PrintAndLogEx(INFO, "RFU................. 0");

    PrintAndLogEx(SUCCESS, "Simulating FDX-B animal ID: " _YELLOW_("%04u-%"PRIu64), country_code, national_code);

    uint8_t *bs = calloc(128, sizeof(uint8_t));
    if (getFDXBBits(national_code, country_code, is_animal, (extended > 0), extended, bs) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        free(bs);
        return PM3_ESOFT;
    }

    // 32, no STT, BIPHASE INVERTED == diphase
    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + 128);
    payload->encoding = 2;
    payload->invert = 1;
    payload->separator = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, 128);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload,  sizeof(lf_asksim_t) + 128);

    free(bs);
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_ASK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,      AlwaysAvailable, "this help"},
    {"demod",   CmdFdxBDemod,  AlwaysAvailable, "demodulate a FDX-B ISO11784/85 tag from the GraphBuffer"},
    {"reader",  CmdFdxBReader, IfPm3Lf,         "attempt to read at 134kHz and extract tag data"},
    {"clone",   CmdFdxBClone,  IfPm3Lf,         "clone animal ID tag to T55x7 or Q5/T5555"},
    {"sim",     CmdFdxBSim,    IfPm3Lf,         "simulate Animal ID tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFFdxB(const char *Cmd) {
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
    if (*size < 128) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}
