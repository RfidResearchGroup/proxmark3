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
// High frequency ALIRO commands
//-----------------------------------------------------------------------------

#include "cmdhfaliro.h"

#include <inttypes.h>
#include <string.h>
#include "cliparser.h"
#include "cmdparser.h"
#include "comms.h"
#include "cmdtrace.h"
#include "emv/tlv.h"
#include "iso7816/apduinfo.h"
#include "iso7816/iso7816core.h"
#include "protocols.h"
#include "ui.h"
#include "util.h"
#include "commonutil.h"

static const uint8_t ALIRO_EXPEDITED_AID[] = {
    0xA0, 0x00, 0x00, 0x09, 0x09, 0xAC, 0xCE, 0x55, 0x01
};

typedef struct {
    uint16_t type;
    const char *name;
} aliro_application_type_t;

static const aliro_application_type_t aliro_application_type_map[] = {
    {0x0000, "CSA application"},
};

static int CmdHelp(const char *Cmd);

static const char *get_aliro_application_type_name(uint16_t type) {
    for (size_t i = 0; i < ARRAYLEN(aliro_application_type_map); ++i) {
        if (aliro_application_type_map[i].type == type) {
            return aliro_application_type_map[i].name;
        }
    }
    return NULL;
}

static void parse_extended_length_info(const uint8_t *buf, size_t len,
                                       bool *has_max_command, uint32_t *max_command,
                                       bool *has_max_response, uint32_t *max_response) {
    const uint8_t *cursor = buf;
    size_t left = len;
    size_t integer_index = 0;

    while (left > 0) {
        struct tlv tlv = {0};
        if (tlv_parse_tl(&cursor, &left, &tlv) == false || tlv.len > left) {
            PrintAndLogEx(WARNING, "Malformed tag 7F66 value");
            return;
        }

        const uint8_t *value = cursor;

        if (tlv.tag == 0x02) {
            const uint8_t *trimmed = value;
            size_t trimmed_len = tlv.len;
            while (trimmed_len > 4 && *trimmed == 0x00) {
                ++trimmed;
                --trimmed_len;
            }

            if (trimmed_len > 0 && trimmed_len <= 4) {
                uint32_t parsed = (uint32_t)bytes_to_num(trimmed, trimmed_len);
                if (integer_index == 0) {
                    *has_max_command = true;
                    *max_command = parsed;
                } else if (integer_index == 1) {
                    *has_max_response = true;
                    *max_response = parsed;
                }
                ++integer_index;
            } else {
                PrintAndLogEx(WARNING, "Could not parse INTEGER from tag 7F66");
            }
        }

        cursor += tlv.len;
        left -= tlv.len;
    }
}

static int print_aliro_select_response(const uint8_t *buf, size_t len) {
    const uint8_t *top_cursor = buf;
    size_t top_left = len;
    bool have_fci = false;
    const uint8_t *fci_value = NULL;
    size_t fci_len = 0;

    while (top_left > 0) {
        struct tlv tlv = {0};
        if (tlv_parse_tl(&top_cursor, &top_left, &tlv) == false || tlv.len > top_left) {
            PrintAndLogEx(ERR, "Malformed SELECT response");
            return PM3_ECARDEXCHANGE;
        }

        if (tlv.tag == 0x6F) {
            have_fci = true;
            fci_value = top_cursor;
            fci_len = tlv.len;
            break;
        }

        top_cursor += tlv.len;
        top_left -= tlv.len;
    }

    if (have_fci == false) {
        PrintAndLogEx(ERR, "SELECT response does not contain FCI template (tag 6F)");
        return PM3_ECARDEXCHANGE;
    }

    uint8_t versions[64] = {0};
    size_t versions_len = 0;
    bool have_versions = false;
    uint8_t fci_aid[APDU_AID_LEN] = {0};
    size_t fci_aid_len = 0;
    bool have_fci_aid = false;
    bool have_type = false;
    uint16_t application_type = 0;
    bool has_max_command = false;
    uint32_t max_command = 0;
    bool has_max_response = false;
    uint32_t max_response = 0;
    bool have_proprietary_template = false;

    const uint8_t *fci_cursor = fci_value;
    size_t fci_left = fci_len;
    while (fci_left > 0) {
        struct tlv tlv = {0};
        if (tlv_parse_tl(&fci_cursor, &fci_left, &tlv) == false || tlv.len > fci_left) {
            PrintAndLogEx(ERR, "Malformed FCI template");
            return PM3_ECARDEXCHANGE;
        }

        const uint8_t *value = fci_cursor;
        if (tlv.tag == 0x84) {
            have_fci_aid = true;
            fci_aid_len = tlv.len;
            if (fci_aid_len > sizeof(fci_aid)) {
                fci_aid_len = sizeof(fci_aid);
                PrintAndLogEx(WARNING, "Returned FCI AID too long, truncating output");
            }
            memcpy(fci_aid, value, fci_aid_len);
        } else if (tlv.tag == 0xA5) {
            have_proprietary_template = true;

            const uint8_t *a5_cursor = value;
            size_t a5_left = tlv.len;
            while (a5_left > 0) {
                struct tlv field = {0};
                if (tlv_parse_tl(&a5_cursor, &a5_left, &field) == false || field.len > a5_left) {
                    PrintAndLogEx(ERR, "Malformed proprietary information template");
                    return PM3_ECARDEXCHANGE;
                }

                const uint8_t *field_value = a5_cursor;
                switch (field.tag) {
                    case 0x80:
                        if (field.len == 2) {
                            application_type = (uint16_t)((field_value[0] << 8) | field_value[1]);
                            have_type = true;
                        } else {
                            PrintAndLogEx(WARNING, "Unexpected application type size: %zu", field.len);
                        }
                        break;
                    case 0x5C:
                        have_versions = true;
                        versions_len = field.len;
                        if (versions_len > sizeof(versions)) {
                            versions_len = sizeof(versions);
                            PrintAndLogEx(WARNING, "Supported protocol versions list too long, truncating output");
                        }
                        memcpy(versions, field_value, versions_len);
                        break;
                    case 0x7F66:
                        parse_extended_length_info(field_value, field.len,
                                                   &has_max_command, &max_command,
                                                   &has_max_response, &max_response);
                        break;
                    default:
                        break;
                }

                a5_cursor += field.len;
                a5_left -= field.len;
            }
        }

        fci_cursor += tlv.len;
        fci_left -= tlv.len;
    }

    if (have_proprietary_template == false) {
        PrintAndLogEx(ERR, "SELECT response does not contain proprietary information (tag A5)");
        return PM3_ECARDEXCHANGE;
    }

    if (have_fci_aid) {
        PrintAndLogEx(INFO, "AID....................... %s", sprint_hex_inrow(fci_aid, fci_aid_len));
    } else {
        PrintAndLogEx(INFO, "AID....................... not present");
    }

    if (have_versions && versions_len >= 2) {
        PrintAndLogEx(INFO, "Supported protocol versions:");
        size_t pairs = versions_len / 2;
        for (size_t i = 0; i < pairs; ++i) {
            uint8_t major = versions[(i * 2)];
            uint8_t minor = versions[(i * 2) + 1];
            PrintAndLogEx(INFO, "  %zu) %u.%u (0x%02X%02X)", i + 1, major, minor, major, minor);
        }

        if ((versions_len % 2) != 0) {
            PrintAndLogEx(WARNING, "Trailing protocol version byte ignored: %02X", versions[versions_len - 1]);
        }
    } else {
        PrintAndLogEx(INFO, "Supported protocol versions: not present");
    }

    if (have_type) {
        const char *type_name = get_aliro_application_type_name(application_type);
        if (type_name != NULL) {
            PrintAndLogEx(INFO, "Application type.......... " _YELLOW_("%s") " (0x%04X)", type_name, application_type);
        } else {
            PrintAndLogEx(INFO, "Application type.......... " _YELLOW_("Unknown") " (0x%04X)", application_type);
        }
    } else {
        PrintAndLogEx(INFO, "Application type.......... not present");
    }

    if (has_max_command || has_max_response) {
        if (has_max_command) {
            PrintAndLogEx(INFO, "Maximum command APDU...... %" PRIu32 " bytes", max_command);
        }
        if (has_max_response) {
            PrintAndLogEx(INFO, "Maximum response APDU..... %" PRIu32 " bytes", max_response);
        }
    } else {
        PrintAndLogEx(INFO, "Maximum APDU sizes........ not provided");
    }

    return PM3_SUCCESS;
}

static int info_aliro(void) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    int res = Iso7816Select(CC_CONTACTLESS, true, false,
                            (uint8_t *)ALIRO_EXPEDITED_AID, sizeof(ALIRO_EXPEDITED_AID),
                            buf, sizeof(buf), &len, &sw);
    DropField();

    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "APDU exchange error");
        return res;
    }

    if (sw != ISO7816_OK) {
        if (sw) {
            PrintAndLogEx(INFO, "Aliro applet not found. APDU response: %04x - %s",
                          sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        } else {
            PrintAndLogEx(ERR, "APDU exchange error. Card returns 0x0000");
        }
        return PM3_SUCCESS;
    }

    return print_aliro_select_response(buf, len);
}

static int CmdHFAliroInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf aliro info",
                  "Select ALIRO applet and print capabilities.",
                  "hf aliro info\n"
                  "hf aliro info -a");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool apdu_logging = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    SetAPDULogging(apdu_logging);
    return info_aliro();
}

static int CmdHFAliroList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf aliro", "7816");
}

static command_t CommandTable[] = {
    {"-----------", CmdHelp,        AlwaysAvailable, "----------------------- " _CYAN_("General") " -----------------------"},
    {"help",        CmdHelp,        AlwaysAvailable, "This help"},
    {"list",        CmdHFAliroList, AlwaysAvailable, "List ISO 14443A/7816 history"},
    {"-----------", CmdHelp,        IfPm3Iso14443a,  "--------------------- " _CYAN_("Operations") " ----------------------"},
    {"info",        CmdHFAliroInfo, IfPm3Iso14443a,  "Tag information"},
    {NULL, NULL, NULL, NULL}
};

int CmdHFAliro(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}
