//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Legic commands
//-----------------------------------------------------------------------------
#include "cmdhflegic.h"

static int CmdHelp(const char *Cmd);

#define MAX_LENGTH 1024

static int usage_legic_calccrc(void) {
    PrintAndLogEx(NORMAL, "Calculates the legic crc8/crc16 on the given data.");
    PrintAndLogEx(NORMAL, "There must be an even number of hexsymbols as input.");
    PrintAndLogEx(NORMAL, "Usage:  hf legic crc [h] d <data> u <uidcrc> c <8|16>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             : this help");
    PrintAndLogEx(NORMAL, "      d <data>      : (hex symbols) bytes to calculate crc over");
    PrintAndLogEx(NORMAL, "      u <uidcrc>    : MCC hexbyte");
    PrintAndLogEx(NORMAL, "      c <8|16>      : Crc type");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf legic crc d deadbeef1122");
    PrintAndLogEx(NORMAL, "      hf legic crc d deadbeef1122 u 9A c 16");
    return 0;
}
static int usage_legic_rdmem(void) {
    PrintAndLogEx(NORMAL, "Read data from a legic tag.");
    PrintAndLogEx(NORMAL, "Usage:  hf legic rdmem [h] <offset> <length> <IV>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             : this help");
    PrintAndLogEx(NORMAL, "      <offset>      : (hex) offset in data array to start download from");
    PrintAndLogEx(NORMAL, "      <length>      : (hex) number of bytes to read");
    PrintAndLogEx(NORMAL, "      <IV>          : (hex) (optional) Initialization vector to use. Must be odd and 7bits max");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf legic rdmem 0 16        - reads from byte[0] 0x16 bytes(system header)");
    PrintAndLogEx(NORMAL, "      hf legic rdmem 0 4 55      - reads from byte[0] 0x4 bytes with IV 0x55");
    PrintAndLogEx(NORMAL, "      hf legic rdmem 0 100 55    - reads 0x100 bytes with IV 0x55");
    return 0;
}
static int usage_legic_sim(void) {
    PrintAndLogEx(NORMAL, "Simulates a LEGIC Prime tag. MIM22, MIM256, MIM1024 types can be emulated");
    PrintAndLogEx(NORMAL, "Use ELOAD/ESAVE to upload a dump into emulator memory");
    PrintAndLogEx(NORMAL, "Usage:  hf legic sim [h] <tagtype>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             : this help");
    PrintAndLogEx(NORMAL, "      <tagtype>     : 0 = MIM22");
    PrintAndLogEx(NORMAL, "                    : 1 = MIM256 (default)");
    PrintAndLogEx(NORMAL, "                    : 2 = MIM1024");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf legic sim 2");
    return 0;
}
static int usage_legic_write(void) {
    PrintAndLogEx(NORMAL, "Write data to a LEGIC Prime tag. It autodetects tagsize to make sure size");
    PrintAndLogEx(NORMAL, "Usage:  hf legic write [h] o <offset> d <data (hex symbols)>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             : this help");
    PrintAndLogEx(NORMAL, "      o <offset>    : (hex) offset in data array to start writing");
    //PrintAndLogEx(NORMAL, "  <IV>          : (optional) Initialization vector to use (ODD and 7bits)");
    PrintAndLogEx(NORMAL, "      d <data>      : (hex symbols) bytes to write ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf legic write o 10 d 11223344    - Write 0x11223344 starting from offset 0x10");
    return 0;
}
static int usage_legic_reader(void) {
    PrintAndLogEx(NORMAL, "Read UID and type information from a legic tag.");
    PrintAndLogEx(NORMAL, "Usage:  hf legic reader [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             : this help");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf legic reader");
    return 0;
}
static int usage_legic_info(void) {
    PrintAndLogEx(NORMAL, "Reads information from a legic prime tag.");
    PrintAndLogEx(NORMAL, "Shows systemarea, user areas etc");
    PrintAndLogEx(NORMAL, "Usage:  hf legic info [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             : this help");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf legic info");
    return 0;
}
static int usage_legic_dump(void) {
    PrintAndLogEx(NORMAL, "Reads all pages from LEGIC Prime MIM22, MIM256, MIM1024");
    PrintAndLogEx(NORMAL, "and saves binary dump into the file `filename.bin` or `cardUID.bin`");
    PrintAndLogEx(NORMAL, "It autodetects card type.\n");
    PrintAndLogEx(NORMAL, "Usage:  hf legic dump [h] o <filename w/o .bin>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             : this help");
    PrintAndLogEx(NORMAL, "      o <filename>  : filename w/o '.bin' to dump bytes");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf legic dump");
    PrintAndLogEx(NORMAL, "      hf legic dump o myfile");
    return 0;
}
static int usage_legic_restore(void) {
    PrintAndLogEx(NORMAL, "Reads binary file and it autodetects card type and verifies that the file has the same size");
    PrintAndLogEx(NORMAL, "Then write the data back to card. All bytes except the first 7bytes [UID(4) MCC(1) DCF(2)]\n");
    PrintAndLogEx(NORMAL, "Usage:   hf legic restore [h] i <filename w/o .bin>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             : this help");
    PrintAndLogEx(NORMAL, "      i <filename>  : filename w/o '.bin' to restore bytes on to card from");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf legic restore i myfile");
    return 0;
}
static int usage_legic_eload(void) {
    PrintAndLogEx(NORMAL, "It loads binary dump from the file `filename.bin`");
    PrintAndLogEx(NORMAL, "Usage:  hf legic eload [h] [card memory] <file name w/o `.bin`>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             : this help");
    PrintAndLogEx(NORMAL, "      [card memory] : 0 = MIM22");
    PrintAndLogEx(NORMAL, "                    : 1 = MIM256 (default)");
    PrintAndLogEx(NORMAL, "                    : 2 = MIM1024");
    PrintAndLogEx(NORMAL, "      <filename>    : filename w/o .bin to load");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf legic eload 2 myfile");
    return 0;
}
static int usage_legic_esave(void) {
    PrintAndLogEx(NORMAL, "It saves binary dump into the file `filename.bin` or `cardID.bin`");
    PrintAndLogEx(NORMAL, " Usage:  hf legic esave [h] [card memory] [file name w/o `.bin`]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             : this help");
    PrintAndLogEx(NORMAL, "      [card memory] : 0 = MIM22");
    PrintAndLogEx(NORMAL, "                    : 1 = MIM256 (default)");
    PrintAndLogEx(NORMAL, "                    : 2 = MIM1024");
    PrintAndLogEx(NORMAL, "      <filename>    : filename w/o .bin to load");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf legic esave 2 myfile");
    return 0;
}
static int usage_legic_wipe(void) {
    PrintAndLogEx(NORMAL, "Fills a legic tag memory with zeros. From byte7 and to the end.");
    PrintAndLogEx(NORMAL, " Usage:  hf legic wipe [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             : this help");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf legic wipe");
    return 0;
}
/*
 *  Output BigBuf and deobfuscate LEGIC RF tag data.
 *  This is based on information given in the talk held
 *  by Henryk Ploetz and Karsten Nohl at 26c3
 */
static int CmdLegicInfo(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_legic_info();

    int i = 0, k = 0, segmentNum = 0, segment_len = 0, segment_flag = 0;
    int crc = 0, wrp = 0, wrc = 0;
    uint8_t stamp_len = 0;
    uint16_t datalen = 0;
    char token_type[6] = {0, 0, 0, 0, 0, 0};
    int dcf = 0;
    int bIsSegmented = 0;

    // tagtype
    legic_card_select_t card;
    if (legic_get_type(&card)) {
        PrintAndLogEx(WARNING, "Failed to identify tagtype");
        return 1;
    }

    PrintAndLogEx(SUCCESS, "Reading full tag memory of %d bytes...", card.cardsize);

    // allocate receiver buffer
    uint8_t *data = calloc(card.cardsize, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Cannot allocate memory");
        return 2;
    }

    int status = legic_read_mem(0, card.cardsize, 0x55, data, &datalen);
    if (status > 0) {
        PrintAndLogEx(WARNING, "Failed reading memory");
        free(data);
        return 3;
    }

    // Output CDF System area (9 bytes) plus remaining header area (12 bytes)
    crc = data[4];
    uint32_t calc_crc =  CRC8Legic(data, 4);

    PrintAndLogEx(NORMAL, _YELLOW_("CDF: System Area"));
    PrintAndLogEx(NORMAL, "------------------------------------------------------");
    PrintAndLogEx(NORMAL, "MCD: %02x, MSN: %02x %02x %02x, MCC: %02x %s",
                  data[0],
                  data[1],
                  data[2],
                  data[3],
                  data[4],
                  (calc_crc == crc) ? _GREEN_("OK") : _RED_("Fail")
                 );

    // MCD = Manufacturer ID (should be list meaning something?)

    token_type[0] = 0;
    dcf = ((int)data[6] << 8) | (int)data[5];

    // New unwritten media?
    if (dcf == 0xFFFF) {

        PrintAndLogEx(NORMAL, "DCF: %d (%02x %02x), Token Type=NM (New Media)",
                      dcf,
                      data[5],
                      data[6]
                     );

    } else if (dcf > 60000) { // Master token?

        int fl = 0;

        if (data[6] == 0xec) {
            strncpy(token_type, "XAM", sizeof(token_type) - 1);
            fl = 1;
            stamp_len = 0x0c - (data[5] >> 4);
        } else {
            switch (data[5] & 0x7f) {
                case 0x00 ... 0x2f:
                    strncpy(token_type, "IAM", sizeof(token_type) - 1);
                    fl = (0x2f - (data[5] & 0x7f)) + 1;
                    break;
                case 0x30 ... 0x6f:
                    strncpy(token_type, "SAM", sizeof(token_type) - 1);
                    fl = (0x6f - (data[5] & 0x7f)) + 1;
                    break;
                case 0x70 ... 0x7f:
                    strncpy(token_type, "GAM", sizeof(token_type) - 1);
                    fl = (0x7f - (data[5] & 0x7f)) + 1;
                    break;
            }

            stamp_len = 0xfc - data[6];
        }

        PrintAndLogEx(NORMAL, "DCF: %d (%02x %02x), Token Type=" _YELLOW_("%s") " (OLE=%01u), OL=%02u, FL=%02u",
                      dcf,
                      data[5],
                      data[6],
                      token_type,
                      (data[5] & 0x80) >> 7,
                      stamp_len,
                      fl
                     );

    } else { // Is IM(-S) type of card...

        if (data[7] == 0x9F && data[8] == 0xFF) {
            bIsSegmented = 1;
            strncpy(token_type, "IM-S", sizeof(token_type) - 1);
        } else {
            strncpy(token_type, "IM", sizeof(token_type) - 1);
        }

        PrintAndLogEx(NORMAL, "DCF: %d (%02x %02x), Token Type = %s (OLE = %01u)",
                      dcf,
                      data[5],
                      data[6],
                      token_type,
                      (data[5] & 0x80) >> 7
                     );
    }

    // Makes no sence to show this on blank media...
    if (dcf != 0xFFFF) {

        if (bIsSegmented) {
            PrintAndLogEx(NORMAL, "WRP = %02u, WRC = %01u, RD = %01u, SSC = %02X",
                          data[7] & 0x0f,
                          (data[7] & 0x70) >> 4,
                          (data[7] & 0x80) >> 7,
                          data[8]
                         );
        }

        // Header area is only available on IM-S cards, on master tokens this data is the master token data itself
        if (bIsSegmented || dcf > 60000) {
            if (dcf > 60000) {
                PrintAndLogEx(NORMAL, "Master token data");
                PrintAndLogEx(NORMAL, "%s", sprint_hex(data + 8, 14));
            } else {
                PrintAndLogEx(NORMAL, "Remaining Header Area");
                PrintAndLogEx(NORMAL, "%s", sprint_hex(data + 9, 13));
            }
        }
    }
    PrintAndLogEx(NORMAL, "------------------------------------------------------");

    uint8_t segCrcBytes[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t segCalcCRC = 0;
    uint32_t segCRC = 0;

    // Not Data card?
    if (dcf > 60000)
        goto out;

    PrintAndLogEx(NORMAL, _YELLOW_("\nADF: User Area"));
    PrintAndLogEx(NORMAL, "------------------------------------------------------");

    if (bIsSegmented) {

        // Data start point on segmented cards
        i = 22;

        // decode segments
        for (segmentNum = 1; segmentNum < 128; segmentNum++) {
            segment_len = ((data[i + 1] ^ crc) & 0x0f) * 256 + (data[i] ^ crc);
            segment_flag = ((data[i + 1] ^ crc) & 0xf0) >> 4;
            wrp = (data[i + 2] ^ crc);
            wrc = ((data[i + 3] ^ crc) & 0x70) >> 4;

            bool hasWRC = (wrc > 0);
            bool hasWRP = (wrp > wrc);
            int wrp_len = (wrp - wrc);
            int remain_seg_payload_len = (segment_len - wrp - 5);

            // validate segment-crc
            segCrcBytes[0] = data[0];         //uid0
            segCrcBytes[1] = data[1];         //uid1
            segCrcBytes[2] = data[2];         //uid2
            segCrcBytes[3] = data[3];         //uid3
            segCrcBytes[4] = (data[i] ^ crc); //hdr0
            segCrcBytes[5] = (data[i + 1] ^ crc); //hdr1
            segCrcBytes[6] = (data[i + 2] ^ crc); //hdr2
            segCrcBytes[7] = (data[i + 3] ^ crc); //hdr3

            segCalcCRC = CRC8Legic(segCrcBytes, 8);
            segCRC = data[i + 4] ^ crc;

            PrintAndLogEx(NORMAL, "Segment     | %02u ", segmentNum);
            PrintAndLogEx(NORMAL, "raw header  | 0x%02X 0x%02X 0x%02X 0x%02X",
                          data[i] ^ crc,
                          data[i + 1] ^ crc,
                          data[i + 2] ^ crc,
                          data[i + 3] ^ crc
                         );
            PrintAndLogEx(NORMAL, "Segment len | %u,  Flag: 0x%X (valid:%01u, last:%01u)",
                          segment_len,
                          segment_flag,
                          (segment_flag & 0x4) >> 2,
                          (segment_flag & 0x8) >> 3
                         );
            PrintAndLogEx(NORMAL, "            | WRP: %02u, WRC: %02u, RD: %01u, CRC: 0x%02X (%s)",
                          wrp,
                          wrc,
                          ((data[i + 3] ^ crc) & 0x80) >> 7,
                          segCRC,
                          (segCRC == segCalcCRC) ? _GREEN_("OK") : _RED_("Fail")
                         );

            i += 5;

            if (hasWRC) {
                PrintAndLogEx(NORMAL, "\nWRC protected area:   (I %d | K %d| WRC %d)", i, k, wrc);
                PrintAndLogEx(NORMAL, "\nrow  | data");
                PrintAndLogEx(NORMAL, "-----+------------------------------------------------");

                for (k = i; k < (i + wrc); ++k)
                    data[k] ^= crc;

                print_hex_break(data + i, wrc, 16);
                PrintAndLogEx(NORMAL, "-----+------------------------------------------------\n");
                i += wrc;
            }

            if (hasWRP) {
                PrintAndLogEx(NORMAL, "Remaining write protected area:  (I %d | K %d | WRC %d | WRP %d  WRP_LEN %d)", i, k, wrc, wrp, wrp_len);
                PrintAndLogEx(NORMAL, "\nrow  | data");
                PrintAndLogEx(NORMAL, "-----+------------------------------------------------");

                for (k = i; k < (i + wrp_len); ++k)
                    data[k] ^= crc;

                print_hex_break(data + i, wrp_len, 16);
                PrintAndLogEx(NORMAL, "-----+------------------------------------------------\n");
                i += wrp_len;

                // does this one work? (Answer: Only if KGH/BGH is used with BCD encoded card number! So maybe this will show just garbage...)
                if (wrp_len == 8) {
                    PrintAndLogEx(NORMAL, "Card ID: " _YELLOW_("%2X%02X%02X"),
                                  data[i - 4] ^ crc,
                                  data[i - 3] ^ crc,
                                  data[i - 2] ^ crc
                                 );
                }
            }
            if (remain_seg_payload_len > 0) {
                PrintAndLogEx(NORMAL, "Remaining segment payload:  (I %d | K %d | Remain LEN %d)", i, k, remain_seg_payload_len);
                PrintAndLogEx(NORMAL, "\nrow  | data");
                PrintAndLogEx(NORMAL, "-----+------------------------------------------------");

                for (k = i; k < (i + remain_seg_payload_len); ++k)
                    data[k] ^= crc;

                print_hex_break(data + i, remain_seg_payload_len, 16);
                PrintAndLogEx(NORMAL, "-----+------------------------------------------------\n");
                i += remain_seg_payload_len;
            }
            // end with last segment
            if (segment_flag & 0x8)
                goto out;

        } // end for loop

    } else {

        // Data start point on unsegmented cards
        i = 8;

        wrp = data[7] & 0x0F;
        wrc = (data[7] & 0x70) >> 4;

        bool hasWRC = (wrc > 0);
        bool hasWRP = (wrp > wrc);
        int wrp_len = (wrp - wrc);
        int remain_seg_payload_len = (card.cardsize - 22 - wrp);

        PrintAndLogEx(NORMAL, "Unsegmented card - WRP: %02u, WRC: %02u, RD: %01u",
                      wrp,
                      wrc,
                      (data[7] & 0x80) >> 7
                     );

        if (hasWRC) {
            PrintAndLogEx(NORMAL, "WRC protected area:   (I %d | WRC %d)", i, wrc);
            PrintAndLogEx(NORMAL, "\nrow  | data");
            PrintAndLogEx(NORMAL, "-----+------------------------------------------------");
            print_hex_break(data + i, wrc, 16);
            PrintAndLogEx(NORMAL, "-----+------------------------------------------------\n");
            i += wrc;
        }

        if (hasWRP) {
            PrintAndLogEx(NORMAL, "Remaining write protected area:  (I %d | WRC %d | WRP %d | WRP_LEN %d)", i, wrc, wrp, wrp_len);
            PrintAndLogEx(NORMAL, "\nrow  | data");
            PrintAndLogEx(NORMAL, "-----+------------------------------------------------");
            print_hex_break(data + i, wrp_len, 16);
            PrintAndLogEx(NORMAL, "-----+------------------------------------------------\n");
            i += wrp_len;

            // Q: does this one work?
            // A: Only if KGH/BGH is used with BCD encoded card number. Maybe this will show just garbage
            if (wrp_len == 8) {
                PrintAndLogEx(NORMAL, "Card ID: " _YELLOW_("%2X%02X%02X"),
                              data[i - 4],
                              data[i - 3],
                              data[i - 2]
                             );
            }
        }

        if (remain_seg_payload_len > 0) {
            PrintAndLogEx(NORMAL, "Remaining segment payload:  (I %d | Remain LEN %d)", i, remain_seg_payload_len);
            PrintAndLogEx(NORMAL, "\nrow  | data");
            PrintAndLogEx(NORMAL, "-----+------------------------------------------------");
            print_hex_break(data + i, remain_seg_payload_len, 16);
            PrintAndLogEx(NORMAL, "-----+------------------------------------------------\n");
        }
    }

out:
    free(data);
    return 0;
}

// params:
// offset in data memory
// number of bytes to read
static int CmdLegicRdmem(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_legic_rdmem();

    uint32_t offset = 0, len = 0, iv = 1;
    uint16_t datalen = 0;
    sscanf(Cmd, "%x %x %x", &offset, &len, &iv);

    // sanity checks
    if (len + offset >= MAX_LENGTH) {
        PrintAndLogEx(WARNING, "Out-of-bounds, Cardsize = %d, [offset+len = %d ]", MAX_LENGTH, len + offset);
        return -1;
    }

    PrintAndLogEx(SUCCESS, "Reading %d bytes, from offset %d", len, offset);

    // allocate receiver buffer
    uint8_t *data = calloc(len, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Cannot allocate memory");
        return -2;
    }

    int status = legic_read_mem(offset, len, iv, data, &datalen);
    if (status == 0) {
        PrintAndLogEx(NORMAL, "\n ##  |  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F");
        PrintAndLogEx(NORMAL, "-----+------------------------------------------------------------------------------------------------");
        print_hex_break(data, datalen, 32);
    }
    free(data);
    return status;
}

static int CmdLegicRfSim(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_legic_sim();

    uint64_t id = 1;
    sscanf(Cmd, " %" SCNi64, &id);
    clearCommandBuffer();
    SendCommandMIX(CMD_SIMULATE_TAG_LEGIC_RF, id, 0, 0, NULL, 0);
    return 0;
}

static int CmdLegicRfWrite(const char *Cmd) {

    uint8_t *data = NULL;
    uint8_t cmdp = 0;
    bool errors = false;
    int len = 0, bg, en;
    uint32_t offset = 0, IV = 0x55;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'd':
                // peek at length of the input string so we can
                // figure out how many elements to malloc in "data"
                bg = en = 0;
                if (param_getptr(Cmd, &bg, &en, cmdp + 1)) {
                    errors = true;
                    break;
                }
                len = (en - bg + 1);

                // check that user entered even number of characters
                // for hex data string
                if (len & 1) {
                    errors = true;
                    break;
                }

                // limit number of bytes to write. This is not a 'restore' command.
                if ((len >> 1) > 100) {
                    PrintAndLogEx(WARNING, "Max bound on 100bytes to write a one time.");
                    PrintAndLogEx(WARNING, "Use the 'hf legic restore' command if you want to write the whole tag at once");
                    errors = true;
                }

                // it's possible for user to accidentally enter "b" parameter
                // more than once - we have to clean previous malloc
                if (data)
                    free(data);

                data = calloc(len >> 1, sizeof(uint8_t));
                if (data == NULL) {
                    PrintAndLogEx(WARNING, "Can't allocate memory. exiting");
                    errors = true;
                    break;
                }

                if (param_gethex(Cmd, cmdp + 1, data, len)) {
                    errors = true;
                    break;
                }

                len >>= 1;
                cmdp += 2;
                break;
            case 'o':
                offset = param_get32ex(Cmd, cmdp + 1, 4, 16);
                cmdp += 2;
                break;
            case 'h':
                errors = true;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors || cmdp == 0) {
        if (data)
            free(data);
        return usage_legic_write();
    }

    // tagtype
    legic_card_select_t card;
    if (legic_get_type(&card)) {
        PrintAndLogEx(WARNING, "Failed to identify tagtype");
        return -1;
    }

    legic_print_type(card.cardsize, 0);

    // OUT-OF-BOUNDS checks
    // UID 4+1 bytes can't be written to.
    if (offset < 5) {
        PrintAndLogEx(WARNING, "Out-of-bounds, bytes 0-1-2-3-4 can't be written to. Offset = %d", offset);
        return -2;
    }

    if (len + offset >= card.cardsize) {
        PrintAndLogEx(WARNING, "Out-of-bounds, Cardsize = %d, [offset+len = %d ]", card.cardsize, len + offset);
        return -2;
    }

    if (offset == 5 || offset == 6) {
        PrintAndLogEx(NORMAL, "############# DANGER ################");
        PrintAndLogEx(NORMAL, "# changing the DCF is irreversible  #");
        PrintAndLogEx(NORMAL, "#####################################");
        char *answer = readline("do you really want to continue? y(es) n(o) : ");
        bool overwrite = (answer[0] == 'y' || answer[0] == 'Y');
        if (!overwrite) {
            PrintAndLogEx(NORMAL, "command cancelled");
            return 0;
        }
    }

    legic_chk_iv(&IV);

    PrintAndLogEx(SUCCESS, "Writing to tag");

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandOLD(CMD_WRITER_LEGIC_RF, offset, len, IV, data, len);


    uint8_t timeout = 0;
    while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        ++timeout;
        printf(".");
        fflush(stdout);
        if (timeout > 7) {
            PrintAndLogEx(WARNING, "\ncommand execution time out");
            return 1;
        }
    }
    PrintAndLogEx(NORMAL, "\n");

    uint8_t isOK = resp.oldarg[0] & 0xFF;
    if (!isOK) {
        PrintAndLogEx(WARNING, "Failed writing tag");
        return 1;
    }

    return 0;
}

static int CmdLegicCalcCrc(const char *Cmd) {

    uint8_t *data = NULL;
    uint8_t cmdp = 0, uidcrc = 0, type = 0;
    bool errors = false;
    int len = 0;
    int bg, en;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'd':
                // peek at length of the input string so we can
                // figure out how many elements to malloc in "data"
                bg = en = 0;
                if (param_getptr(Cmd, &bg, &en, cmdp + 1)) {
                    errors = true;
                    break;
                }
                len = (en - bg + 1);

                // check that user entered even number of characters
                // for hex data string
                if (len & 1) {
                    errors = true;
                    break;
                }

                // it's possible for user to accidentally enter "b" parameter
                // more than once - we have to clean previous malloc
                if (data) free(data);
                data = calloc(len >> 1,  sizeof(uint8_t));
                if (data == NULL) {
                    PrintAndLogEx(WARNING, "Can't allocate memory. exiting");
                    errors = true;
                    break;
                }

                if (param_gethex(Cmd, cmdp + 1, data, len)) {
                    errors = true;
                    break;
                }

                len >>= 1;
                cmdp += 2;
                break;
            case 'u':
                uidcrc = param_get8ex(Cmd, cmdp + 1, 0, 16);
                cmdp += 2;
                break;
            case 'c':
                type = param_get8ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            case 'h':
                errors = true;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors || cmdp == 0) {
        if (data) free(data);
        return usage_legic_calccrc();
    }

    switch (type) {
        case 16:
            init_table(CRC_LEGIC);
            PrintAndLogEx(SUCCESS, "Legic crc16: %X", crc16_legic(data, len, uidcrc));
            break;
        default:
            PrintAndLogEx(SUCCESS, "Legic crc8: %X",  CRC8Legic(data, len));
            break;
    }

    if (data) free(data);
    return 0;
}

int legic_read_mem(uint32_t offset, uint32_t len, uint32_t iv, uint8_t *out, uint16_t *outlen) {

    legic_chk_iv(&iv);

    clearCommandBuffer();
    SendCommandMIX(CMD_READER_LEGIC_RF, offset, len, iv, NULL, 0);
    PacketResponseNG resp;

    uint8_t timeout = 0;
    while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        ++timeout;
        printf(".");
        fflush(stdout);
        if (timeout > 7) {
            PrintAndLogEx(WARNING, "\ncommand execution time out");
            return 1;
        }
    }
    PrintAndLogEx(NORMAL, "\n");

    uint8_t isOK = resp.oldarg[0] & 0xFF;
    *outlen = resp.oldarg[1];
    if (!isOK) {
        PrintAndLogEx(WARNING, "Failed reading tag");
        return 2;
    }

    if (*outlen != len)
        PrintAndLogEx(WARNING, "Fail, only managed to read %u bytes", *outlen);

    // copy data from device
    if (!GetFromDevice(BIG_BUF_EML, out, *outlen, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        return 4;
    }
    return 0;
}

int legic_print_type(uint32_t tagtype, uint8_t spaces) {
    char spc[11] = "          ";
    spc[10] = 0x00;
    char *spacer = spc + (10 - spaces);

    if (tagtype == 22)
        PrintAndLogEx(SUCCESS, "%sTYPE : MIM%d card (outdated)", spacer, tagtype);
    else if (tagtype == 256)
        PrintAndLogEx(SUCCESS, "%sTYPE : MIM%d card (234 bytes)", spacer, tagtype);
    else if (tagtype == 1024)
        PrintAndLogEx(SUCCESS, "%sTYPE : MIM%d card (1002 bytes)", spacer, tagtype);
    else
        PrintAndLogEx(INFO, "%sTYPE : Unknown %06x", spacer, tagtype);
    return 0;
}
int legic_get_type(legic_card_select_t *card) {

    if (card == NULL) return 1;

    clearCommandBuffer();
    SendCommandNG(CMD_LEGIC_INFO, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500))
        return 2;

    uint8_t isOK = resp.oldarg[0] & 0xFF;
    if (!isOK)
        return 3;

    memcpy(card, (legic_card_select_t *)resp.data.asBytes, sizeof(legic_card_select_t));
    return 0;
}
void legic_chk_iv(uint32_t *iv) {
    if ((*iv & 0x7F) != *iv) {
        *iv &= 0x7F;
        PrintAndLogEx(INFO, "Truncating IV to 7bits, %u", *iv);
    }
    // IV must be odd
    if ((*iv & 1) == 0) {
        *iv |= 0x01;
        PrintAndLogEx(INFO, "LSB of IV must be SET %u", *iv);
    }
}
void legic_seteml(uint8_t *src, uint32_t offset, uint32_t numofbytes) {
    // fast push mode
    conn.block_after_ACK = true;
    for (size_t i = offset; i < numofbytes; i += PM3_CMD_DATA_SIZE) {

        size_t len = MIN((numofbytes - i), PM3_CMD_DATA_SIZE);
        if (len == numofbytes - i) {
            // Disable fast mode on last packet
            conn.block_after_ACK = false;
        }
        clearCommandBuffer();
        SendCommandOLD(CMD_LEGIC_ESET, i, len, 0, src + i, len);
    }
}

static int CmdLegicReader(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_legic_reader();

    return readLegicUid(true);
}

static int CmdLegicDump(const char *Cmd) {

    FILE *f;
    char filename[FILE_PATH_SIZE] = {0x00};
    char *fnameptr = filename;
    size_t fileNlen = 0;
    bool errors = false;
    uint16_t dumplen;
    uint8_t cmdp = 0;

    memset(filename, 0, sizeof(filename));

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_legic_dump();
            case 'o':
                fileNlen = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                if (!fileNlen)
                    errors = true;
                if (fileNlen > FILE_PATH_SIZE - 5)
                    fileNlen = FILE_PATH_SIZE - 5;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors) return usage_legic_dump();

    // tagtype
    legic_card_select_t card;
    if (legic_get_type(&card)) {
        PrintAndLogEx(WARNING, "Failed to identify tagtype");
        return -1;
    }
    dumplen = card.cardsize;

    legic_print_type(dumplen, 0);
    PrintAndLogEx(SUCCESS, "Reading tag memory %d b...", dumplen);

    clearCommandBuffer();
    SendCommandMIX(CMD_READER_LEGIC_RF, 0x00, dumplen, 0x55, NULL, 0);
    PacketResponseNG resp;

    uint8_t timeout = 0;
    while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        ++timeout;
        printf(".");
        fflush(stdout);
        if (timeout > 7) {
            PrintAndLogEx(WARNING, "\ncommand execution time out");
            return 1;
        }
    }
    PrintAndLogEx(NORMAL, "\n");

    uint8_t isOK = resp.oldarg[0] & 0xFF;
    if (!isOK) {
        PrintAndLogEx(WARNING, "Failed dumping tag data");
        return 2;
    }

    uint16_t readlen = resp.oldarg[1];
    uint8_t *data = calloc(readlen, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return 3;
    }

    if (readlen != dumplen)
        PrintAndLogEx(WARNING, "Fail, only managed to read 0x%02X bytes of 0x%02X", readlen, dumplen);

    // copy data from device
    if (!GetFromDevice(BIG_BUF_EML, data, readlen, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(data);
        return 4;
    }

    // user supplied filename?
    if (fileNlen < 1)
        sprintf(fnameptr, "%02X%02X%02X%02X.bin", data[0], data[1], data[2], data[3]);
    else
        sprintf(fnameptr + fileNlen, ".bin");

    f = fopen(filename, "wb");
    if (!f) {
        PrintAndLogEx(WARNING, "Could not create file name %s", filename);
        if (data)
            free(data);
        return PM3_EFILE;
    }
    fwrite(data, 1, readlen, f);
    fflush(f);
    fclose(f);
    free(data);
    PrintAndLogEx(SUCCESS, "Wrote %d bytes to %s", readlen, filename);
    return PM3_SUCCESS;
}

static int CmdLegicRestore(const char *Cmd) {

    FILE *f;
    char filename[FILE_PATH_SIZE] = {0x00};
    char *fnameptr = filename;
    size_t fileNlen = 0;
    bool errors = false;
    uint16_t numofbytes;
    uint8_t cmdp = 0;

    memset(filename, 0, sizeof(filename));

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                errors = true;
                break;
            case 'i':
                fileNlen = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                if (!fileNlen)
                    errors = true;

                if (fileNlen > FILE_PATH_SIZE - 5)
                    fileNlen = FILE_PATH_SIZE - 5;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors || cmdp == 0) return usage_legic_restore();

    // tagtype
    legic_card_select_t card;
    if (legic_get_type(&card)) {
        PrintAndLogEx(WARNING, "Failed to identify tagtype");
        return 1;
    }
    numofbytes = card.cardsize;

    // set up buffer
    uint8_t *data = calloc(numofbytes, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return 2;
    }

    legic_print_type(numofbytes, 0);

    // set up file
    fnameptr += fileNlen;
    sprintf(fnameptr, ".bin");

    f = fopen(filename, "rb");
    if (!f) {
        PrintAndLogEx(WARNING, "File %s not found or locked", filename);
        free(data);
        return PM3_EFILE;
    }

    // verify size of dumpfile is the same as card.
    fseek(f, 0, SEEK_END); // seek to end of file
    size_t filesize = ftell(f); // get current file pointer
    fseek(f, 0, SEEK_SET); // seek back to beginning of file

    if (filesize != numofbytes) {
        PrintAndLogEx(WARNING, "Fail, filesize and cardsize is not equal. [%u != %u]", filesize, numofbytes);
        free(data);
        fclose(f);
        return 4;
    }

    // load file
    size_t bytes_read = fread(data, 1, numofbytes, f);
    fclose(f);

    if (bytes_read == 0) {
        PrintAndLogEx(WARNING, "File reading error");
        free(data);
        return 2;
    }

    PrintAndLogEx(SUCCESS, "Restoring to card");

    // fast push mode
    conn.block_after_ACK = true;

    // transfer to device
    PacketResponseNG resp;
    for (size_t i = 7; i < numofbytes; i += PM3_CMD_DATA_SIZE) {

        size_t len = MIN((numofbytes - i), PM3_CMD_DATA_SIZE);
        if (len == numofbytes - i) {
            // Disable fast mode on last packet
            conn.block_after_ACK = false;
        }
        clearCommandBuffer();
        SendCommandOLD(CMD_WRITER_LEGIC_RF, i, len, 0x55, data + i, len);

        uint8_t timeout = 0;
        while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
            ++timeout;
            printf(".");
            fflush(stdout);
            if (timeout > 7) {
                PrintAndLogEx(WARNING, "\ncommand execution time out");
                free(data);
                return 1;
            }
        }
        PrintAndLogEx(NORMAL, "\n");

        uint8_t isOK = resp.oldarg[0] & 0xFF;
        if (!isOK) {
            PrintAndLogEx(WARNING, "Failed writing tag [msg = %u]", resp.oldarg[1] & 0xFF);
            free(data);
            return 1;
        }
        PrintAndLogEx(SUCCESS, "Wrote chunk [offset %d | len %d | total %d", i, len, i + len);
    }

    free(data);
    PrintAndLogEx(SUCCESS, "\nWrote %d bytes to card from file %s", numofbytes, filename);
    return PM3_SUCCESS;
}

static int CmdLegicELoad(const char *Cmd) {
    FILE *f;
    char filename[FILE_PATH_SIZE];
    char *fnameptr = filename;
    int len, numofbytes;
    int nameParamNo = 1;

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h' || cmdp == 0x00)
        return usage_legic_eload();

    switch (cmdp) {
        case '0' :
            numofbytes = 22;
            break;
        case '1' :
        case '\0':
            numofbytes = 256;
            break;
        case '2' :
            numofbytes = 1024;
            break;
        default  :
            numofbytes = 256;
            nameParamNo = 0;
            break;
    }

    // set up buffer
    uint8_t *data = calloc(numofbytes, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return 3;
    }

    // set up file
    len = param_getstr(Cmd, nameParamNo, filename, FILE_PATH_SIZE);
    if (len > FILE_PATH_SIZE - 5)
        len = FILE_PATH_SIZE - 5;
    fnameptr += len;
    sprintf(fnameptr, ".bin");

    // open file
    f = fopen(filename, "rb");
    if (!f) {
        PrintAndLogEx(WARNING, "File %s not found or locked", filename);
        free(data);
        return PM3_EFILE;
    }

    // load file
    size_t bytes_read = fread(data, 1, numofbytes, f);
    if (bytes_read == 0) {
        PrintAndLogEx(WARNING, "File reading error");
        free(data);
        fclose(f);
        f = NULL;
        return 2;
    }
    fclose(f);
    f = NULL;

    // transfer to device
    legic_seteml(data, 0, numofbytes);

    free(data);
    PrintAndLogEx(SUCCESS, "\nLoaded %d bytes from file: %s  to emulator memory", numofbytes, filename);
    return PM3_SUCCESS;
}

static int CmdLegicESave(const char *Cmd) {

    char filename[FILE_PATH_SIZE];
    char *fnameptr = filename;
    int fileNlen, numofbytes, nameParamNo = 1;

    memset(filename, 0, sizeof(filename));

    char cmdp = tolower(param_getchar(Cmd, 0));

    if (cmdp == 'h' || cmdp == 0x00)
        return usage_legic_esave();

    switch (cmdp) {
        case '0' :
            numofbytes = 22;
            break;
        case '1' :
        case '\0':
            numofbytes = 256;
            break;
        case '2' :
            numofbytes = 1024;
            break;
        default  :
            numofbytes = 256;
            nameParamNo = 0;
            break;
    }

    fileNlen = param_getstr(Cmd, nameParamNo, filename, FILE_PATH_SIZE);

    if (fileNlen > FILE_PATH_SIZE - 5)
        fileNlen = FILE_PATH_SIZE - 5;

    // set up buffer
    uint8_t *data = calloc(numofbytes, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return 3;
    }

    // download emulator memory
    PrintAndLogEx(SUCCESS, "Reading emulator memory...");
    if (!GetFromDevice(BIG_BUF_EML, data, numofbytes, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(data);
        return 4;
    }
    // user supplied filename?
    if (fileNlen < 1)
        sprintf(fnameptr, "%02X%02X%02X%02X.bin", data[0], data[1], data[2], data[3]);
    else
        sprintf(fnameptr + fileNlen, ".bin");

    saveFileEML(filename, data, numofbytes, 8);
    saveFile(filename, ".bin", data, numofbytes);
    return 0;
}

static int CmdLegicWipe(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));

    if (cmdp == 'h') return usage_legic_wipe();

    // tagtype
    legic_card_select_t card;
    if (legic_get_type(&card)) {
        PrintAndLogEx(WARNING, "Failed to identify tagtype");
        return 1;
    }

    // set up buffer
    uint8_t *data = calloc(card.cardsize, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return 2;
    }

    legic_print_type(card.cardsize, 0);

    PrintAndLogEx(SUCCESS, "Erasing");
    // fast push mode
    conn.block_after_ACK = true;

    // transfer to device
    PacketResponseNG resp;
    for (size_t i = 7; i < card.cardsize; i += PM3_CMD_DATA_SIZE) {

        printf(".");
        fflush(stdout);
        size_t len = MIN((card.cardsize - i), PM3_CMD_DATA_SIZE);
        if (len == card.cardsize - i) {
            // Disable fast mode on last packet
            conn.block_after_ACK = false;
        }
        clearCommandBuffer();
        SendCommandOLD(CMD_WRITER_LEGIC_RF, i, len, 0x55, data + i, len);

        uint8_t timeout = 0;
        while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
            ++timeout;
            printf(".");
            fflush(stdout);
            if (timeout > 7) {
                PrintAndLogEx(WARNING, "\ncommand execution time out");
                free(data);
                return 3;
            }
        }
        PrintAndLogEx(NORMAL, "\n");

        uint8_t isOK = resp.oldarg[0] & 0xFF;
        if (!isOK) {
            PrintAndLogEx(WARNING, "Failed writing tag [msg = %u]", resp.oldarg[1] & 0xFF);
            free(data);
            return 4;
        }
    }
    PrintAndLogEx(SUCCESS, "ok\n");
    free(data);
    return 0;
}

static int CmdLegicList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdTraceList("legic");
    return 0;
}

static command_t CommandTable[] =  {
    {"help",    CmdHelp,          AlwaysAvailable, "This help"},
    {"reader",  CmdLegicReader,   IfPm3Legicrf,    "LEGIC Prime Reader UID and tag info"},
    {"info",    CmdLegicInfo,     IfPm3Legicrf,    "Display deobfuscated and decoded LEGIC Prime tag data"},
    {"dump",    CmdLegicDump,     IfPm3Legicrf,    "Dump LEGIC Prime tag to binary file"},
    {"restore", CmdLegicRestore,  IfPm3Legicrf,    "Restore a dump file onto a LEGIC Prime tag"},
    {"rdmem",   CmdLegicRdmem,    IfPm3Legicrf,    "Read bytes from a LEGIC Prime tag"},
    {"sim",     CmdLegicRfSim,    IfPm3Legicrf,    "Start tag simulator"},
    {"write",   CmdLegicRfWrite,  IfPm3Legicrf,    "Write data to a LEGIC Prime tag"},
    {"crc",     CmdLegicCalcCrc,  AlwaysAvailable, "Calculate Legic CRC over given bytes"},
    {"eload",   CmdLegicELoad,    IfPm3Legicrf,    "Load binary dump to emulator memory"},
    {"esave",   CmdLegicESave,    IfPm3Legicrf,    "Save emulator memory to binary file"},
    {"list",    CmdLegicList,     AlwaysAvailable,    "List LEGIC history"},
    {"wipe",    CmdLegicWipe,     IfPm3Legicrf,    "Wipe a LEGIC Prime tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return 0;
}

int CmdHFLegic(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int readLegicUid(bool verbose) {

    legic_card_select_t card;
    switch (legic_get_type(&card)) {
        case 1:
            return 2;
        case 2:
            if (verbose) PrintAndLogEx(WARNING, "command execution time out");
            return 1;
        case 3:
            if (verbose) PrintAndLogEx(WARNING, "legic card select failed");
            return 2;
        default:
            break;
    }
    PrintAndLogEx(SUCCESS, " UID : %s", sprint_hex(card.uid, sizeof(card.uid)));
    legic_print_type(card.cardsize, 0);
    return 0;
}
