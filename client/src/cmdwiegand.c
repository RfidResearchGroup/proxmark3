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
// Wiegand commands
//-----------------------------------------------------------------------------
#include "cmdwiegand.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "cmdparser.h"          // command_t
#include "cliparser.h"
#include "comms.h"
#include "pm3_cmd.h"
#include "protocols.h"
#include "parity.h"             // oddparity
#include "cmdhflist.h"          // annotations
#include "commonutil.h"         // ARRAYLEN
#include "wiegand_formats.h"
#include "wiegand_formatutils.h"
#include "util.h"

static int CmdHelp(const char *Cmd);

#define PACS_EXTRA_LONG_FORMAT  18     // 144 bits
#define PACS_LONG_FORMAT        13     // 96 bits + 1 byte pad
#define PACS_FORMAT             6      // 44 bits
#define PACS_MAX_WIEGAND_BITS   96
#define WIEGAND_MAX_ENCODED_BITS (PACS_MAX_WIEGAND_BITS + 8)

static int wiegand_print_new_pacs_verbose(const wiegand_message_t *packed, const uint8_t *pacs, size_t pacs_len) {
    char binstr[PACS_MAX_WIEGAND_BITS + 1] = {0};
    char rawbin[WIEGAND_MAX_ENCODED_BITS + 1] = {0};
    uint8_t raw[(WIEGAND_MAX_ENCODED_BITS + 7) / 8] = {0};
    size_t raw_len = 0;

    if (wiegand_message_to_binstr(packed, binstr, sizeof(binstr)) == false) {
        PrintAndLogEx(ERR, "Failed to render Wiegand payload");
        return PM3_EINVARG;
    }
    rawbin[0] = '1';
    memcpy(rawbin + 1, binstr, packed->Length);
    binstr_2_bytes(raw, &raw_len, rawbin);
    bytes_2_binstr(rawbin, raw, raw_len);

    PrintAndLogEx(INFO, "----------------------- " _CYAN_("PACS Encoding") " ------------------------");
    PrintAndLogEx(SUCCESS, "New PACS......... " _GREEN_("0x %s"), sprint_hex_inrow(pacs, pacs_len));
    PrintAndLogEx(INFO, "With Sentinel.... " _GREEN_("0b %s") " (%zu-bit)", rawbin, strlen(rawbin));
    PrintAndLogEx(SUCCESS, "Wiegand --raw.... " _YELLOW_("0x %s"), sprint_hex_inrow(raw, raw_len));
    PrintAndLogEx(INFO, "Without Sentinel. " _GREEN_("0b %s") " (%zu-bit)", binstr, strlen(binstr));
    return PM3_SUCCESS;
}

static int wiegand_encode_new_pacs(const wiegand_message_t *packed, bool verbose) {

    if (packed->Length == 0) {
        PrintAndLogEx(ERR, "Empty Wiegand input");
        return PM3_EINVARG;
    }

    if (packed->Length > PACS_MAX_WIEGAND_BITS) {
        PrintAndLogEx(ERR, "New PACS encoding supports up to %u Wiegand bits", PACS_MAX_WIEGAND_BITS);
        return PM3_EINVARG;
    }

    uint8_t padded_bits = (uint8_t)(((packed->Length + 7) / 8) * 8);
    uint8_t pad = padded_bits - packed->Length;

    char binstr[PACS_MAX_WIEGAND_BITS + 1] = {0};
    if (wiegand_message_to_binstr(packed, binstr, sizeof(binstr)) == false) {
        PrintAndLogEx(ERR, "Failed to render Wiegand payload");
        return PM3_EINVARG;
    }
    memset(binstr + packed->Length, '0', pad);
    binstr[padded_bits] = '\0';

    size_t pacs_len = 0;
    uint8_t pacs[PACS_LONG_FORMAT] = {0};
    binstr_2_bytes(pacs + 1, &pacs_len, binstr);
    pacs[0] = pad;

    PrintAndLogEx(SUCCESS, "New PACS......... " _GREEN_("0x %s"), sprint_hex_inrow(pacs, pacs_len + 1));
    if (verbose) {
        PrintAndLogEx(NORMAL, "");
        return wiegand_print_new_pacs_verbose(packed, pacs, pacs_len + 1);
    }
    return PM3_SUCCESS;
}

static int wiegand_new_pacs(const uint8_t *padded_pacs, uint8_t plen) {
    return HIDDumpPACSBits(padded_pacs, plen, false);
}

static int wiegand_print_raw_from_bin(const uint8_t *binarr, int blen) {
    uint8_t out[(WIEGAND_MAX_ENCODED_BITS + 7) / 8] = {0};
    char binstr[WIEGAND_MAX_ENCODED_BITS + 1] = {0};

    binstr[0] = '1';
    for (int i = 0; i < blen; i++) {
        binstr[i + 1] = binarr[i] ? '1' : '0';
    }

    size_t out_len = 0;
    binstr_2_bytes(out, &out_len, binstr);
    PrintAndLogEx(SUCCESS, "Wiegand raw.... " _YELLOW_("%s"), sprint_hex_inrow(out, out_len));
    return PM3_SUCCESS;
}

static int wiegand_encode_new_pacs_from_bin(const uint8_t *binarr, int blen, bool verbose) {
    wiegand_message_t packed;
    memset(&packed, 0, sizeof(packed));
    packed.Length = blen;

    for (int i = 0; i < blen; i++) {
        if (set_bit_by_position(&packed, binarr[i], i) == false) {
            PrintAndLogEx(ERR, "Binary string must be less than or equal to %u bits", PACS_MAX_WIEGAND_BITS);
            return PM3_EINVARG;
        }
    }

    return wiegand_encode_new_pacs(&packed, verbose);
}
int CmdWiegandList(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "wiegand info",
                  "List available wiegand formats",
                  "wiegand list"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    HIDListFormats();
    return PM3_SUCCESS;
}

int CmdWiegandEncode(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "wiegand encode",
                  "Encode wiegand formatted number to raw hex",
                  "wiegand encode --fc 101 --cn 1337               ->  show all formats\n"
                  "wiegand encode -w H10301 --fc 101 --cn 1337     ->  H10301 format\n"
                  "wiegand encode --bin 1                          ->  raw wiegand hex with sentinel\n"
                  "wiegand encode -w H10301 --fc 123 --cn 4567 --new -> new ASN.1 encoded format"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("b", "bin", "<bin>", "binary string to be encoded"),
        arg_u64_0(NULL, "fc", "<dec>", "facility number"),
        arg_u64_0(NULL, "cn", "<dec>", "card number"),
        arg_u64_0(NULL, "issue", "<dec>", "issue level"),
        arg_u64_0(NULL, "oem", "<dec>", "OEM code"),
        arg_str0("w", "wiegand", "<format>", "see `wiegand list` for available formats"),
        arg_lit0("n", "new", "encode to new ASN.1 encoded format"),
        arg_lit0(NULL, "pre", "add HID ProxII preamble to wiegand output"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    wiegand_card_t data;
    memset(&data, 0, sizeof(wiegand_card_t));

    uint8_t binarr[PACS_MAX_WIEGAND_BITS] = {0};
    int blen = 0;
    int res = CLIParamBinToBuf(arg_get_str(ctx, 1), binarr, ARRAYLEN(binarr), &blen);

    data.FacilityCode = arg_get_u32_def(ctx, 2, 0);
    data.CardNumber = arg_get_u64_def(ctx, 3, 0);
    data.IssueLevel = arg_get_u32_def(ctx, 4, 0);
    data.OEM = arg_get_u32_def(ctx, 5, 0);

    int len = 0;
    char format[16] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)format, sizeof(format), &len);

    bool new_pacs = arg_get_lit(ctx, 7);
    bool preamble = arg_get_lit(ctx, 8);
    bool verbose = arg_get_lit(ctx, 9);
    CLIParserFree(ctx);

    if (res) {
        PrintAndLogEx(FAILED, "Error parsing binary string");
        return PM3_EINVARG;
    }

    if (new_pacs && preamble) {
        PrintAndLogEx(ERR, "`--new` and `--pre` can't be combined");
        return PM3_EINVARG;
    }

    if (blen && (len || data.FacilityCode || data.CardNumber || data.IssueLevel || data.OEM || preamble)) {
        PrintAndLogEx(ERR, "`--bin` can't be combined with format, field, or preamble options");
        return PM3_EINVARG;
    }

    if (blen == 0 && len == 0 && data.CardNumber == 0 && data.FacilityCode == 0 && data.IssueLevel == 0 && data.OEM == 0) {
        PrintAndLogEx(ERR, "Must provide either card data, a specific format, or `--bin`");
        return PM3_EINVARG;
    }

    int idx = -1;
    if (len) {
        idx = HIDFindCardFormat(format);
        if (idx == -1) {
            PrintAndLogEx(WARNING, "Unknown format: %s", format);
            return PM3_EINVARG;
        }
    }

    if (new_pacs && idx == -1 && blen == 0) {
        PrintAndLogEx(ERR, "`--new` requires either `--bin` or a specific wiegand format");
        return PM3_EINVARG;
    }

    if (blen) {
        if (new_pacs) {
            return wiegand_encode_new_pacs_from_bin(binarr, blen, verbose);
        }
        return wiegand_print_raw_from_bin(binarr, blen);
    } else if (idx != -1) {
        wiegand_message_t packed;
        memset(&packed, 0, sizeof(wiegand_message_t));
        if (HIDPack(idx, &data, &packed, preamble) == false) {
            PrintAndLogEx(WARNING, "The card data could not be encoded in the selected format.");
            return PM3_ESOFT;
        }
        if (new_pacs) {
            return wiegand_encode_new_pacs(&packed, verbose);
        }
        print_wiegand_code(&packed);
    } else {
        // try all formats and print only the ones that work.
        HIDPackTryAll(&data, preamble);
    }
    return PM3_SUCCESS;
}

int CmdWiegandDecode(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "wiegand decode",
                  "Decode raw hex or binary to wiegand format",
                  "wiegand decode --raw 2006F623AE\n"
                  "wiegand decode --new 06BD88EB80   -> 4..13 bytes, new ASN.1 encoded format "
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw hex to be decoded"),
        arg_str0("b", "bin", "<bin>", "binary string to be decoded"),
        arg_str0("n", "new", "<hex>", "new ASN.1 encoded data as raw hex to be decoded"),
        arg_lit0("f", "force", "skip preabmle checking, brute force all possible lengths for raw hex input"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int hlen = 0;
    char hex[40] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)hex, sizeof(hex), &hlen);

    int blen = 0;
    uint8_t binarr[WIEGAND_MAX_ENCODED_BITS] = {0x00};
    int res = CLIParamBinToBuf(arg_get_str(ctx, 2), binarr, sizeof(binarr), &blen);

    int plen = 0;
    uint8_t phex[PACS_LONG_FORMAT] = {0};
    res = CLIParamHexToBuf(arg_get_str(ctx, 3), phex, sizeof(phex), &plen);

    bool no_preamble = arg_get_lit(ctx, 4);

    CLIParserFree(ctx);

    if (res) {
        PrintAndLogEx(FAILED, "Error parsing binary string");
        return PM3_EINVARG;
    }

    uint32_t top = 0, mid = 0, bot = 0;

    if (hlen) {
        if ((hlen * 4) > PACS_MAX_WIEGAND_BITS) {
            PrintAndLogEx(ERR, "Raw hex decode supports up to %u Wiegand bits", PACS_MAX_WIEGAND_BITS);
            return PM3_EINVARG;
        }
        res = hexstring_to_u96(&top, &mid, &bot, hex);
        if (res != hlen) {
            PrintAndLogEx(ERR, "Hex string contains none hex chars");
            return PM3_EINVARG;
        }

        if (no_preamble) {
            // Pass the input hex length through so decode_wiegand() brute-forces
            // the possible bit lengths instead of assuming a preamble-encoded value.
            blen = -hlen;
        }
    } else if (blen) {
        if (blen > PACS_MAX_WIEGAND_BITS) {
            PrintAndLogEx(ERR, "Binary decode supports up to %u Wiegand bits", PACS_MAX_WIEGAND_BITS);
            return PM3_EINVARG;
        }
        int n = binarray_to_u96(&top, &mid, &bot, binarr, blen);
        if (n != blen) {
            PrintAndLogEx(ERR, "Binary string contains none <0|1> chars");
            return PM3_EINVARG;
        }
        PrintAndLogEx(INFO, "#bits... %d", blen);

    } else if (plen) {

        return wiegand_new_pacs(phex, plen);

    } else {
        PrintAndLogEx(ERR, "Empty input");
        return PM3_EINVARG;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------------------- " _CYAN_("Wiegand") " ---------------------------");

    decode_wiegand(top, mid, bot, blen);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,           AlwaysAvailable, "This help"},
    {"list",    CmdWiegandList,    AlwaysAvailable, "List available wiegand formats"},
    {"encode",  CmdWiegandEncode,  AlwaysAvailable, "Encode to wiegand raw hex (currently for HID Prox)"},
    {"decode",  CmdWiegandDecode,  AlwaysAvailable, "Convert raw hex to decoded wiegand format (currently for HID Prox)"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdWiegand(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
