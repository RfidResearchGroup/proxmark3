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
// Command parser
//-----------------------------------------------------------------------------

#include "cmdparser.h"

#include <stdio.h>
#include <string.h>

#include "ui.h"
#include "comms.h"
#include "util_posix.h" // msleep


#define MAX_PM3_INPUT_ARGS_LENGTH    4096

bool AlwaysAvailable(void) {
    return true;
}

bool IfPm3Present(void) {
    if (g_session.help_dump_mode)
        return false;
    return g_session.pm3_present;
}

bool IfPm3Rdv4Fw(void) {
    if (IfPm3Present() == false)
        return false;
    return (g_pm3_capabilities.is_rdv4);
}

bool IfPm3Flash(void) {
    if (IfPm3Present() == false)
        return false;
    if (g_pm3_capabilities.compiled_with_flash == false)
        return false;
    return g_pm3_capabilities.hw_available_flash;
}

bool IfPm3Smartcard(void) {
    if (IfPm3Present() == false)
        return false;
    if (g_pm3_capabilities.compiled_with_smartcard == false)
        return false;
    return g_pm3_capabilities.hw_available_smartcard;
}

bool IfPm3FpcUsart(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_fpc_usart;
}

bool IfPm3FpcUsartHost(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_fpc_usart_host;
}

bool IfPm3FpcUsartHostFromUsb(void) {
    // true if FPC USART Host support and if talking from USB-CDC interface
    if (IfPm3Present() == false)
        return false;
    if (g_pm3_capabilities.compiled_with_fpc_usart_host == false)
        return false;
    return !g_conn.send_via_fpc_usart;
}

bool IfPm3FpcUsartDevFromUsb(void) {
    // true if FPC USART developer support and if talking from USB-CDC interface
    if (IfPm3Present() == false)
        return false;
    if (g_pm3_capabilities.compiled_with_fpc_usart_dev == false)
        return false;

    return !g_conn.send_via_fpc_usart;
}

bool IfPm3FpcUsartFromUsb(void) {
    // true if FPC USART Host or developer support and if talking from USB-CDC interface
    return IfPm3FpcUsartHostFromUsb() || IfPm3FpcUsartDevFromUsb();
}

bool IfPm3Lf(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_lf;
}

bool IfPm3Hitag(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_hitag;
}

bool IfPm3EM4x50(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_em4x50;
}

bool IfPm3EM4x70(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_em4x70;
}

bool IfPm3Hfsniff(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_hfsniff;
}

bool IfPm3Hfplot(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_hfplot;
}

bool IfPm3Iso14443a(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_iso14443a;
}

bool IfPm3Iso14443b(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_iso14443b;
}

bool IfPm3Iso14443(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_iso14443a || g_pm3_capabilities.compiled_with_iso14443b;
}

bool IfPm3Iso15693(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_iso15693;
}

bool IfPm3Felica(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_felica;
}

bool IfPm3Legicrf(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_legicrf;
}

bool IfPm3Iclass(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_iclass;
}

bool IfPm3NfcBarcode(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_nfcbarcode;
}

bool IfPm3Lcd(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_lcd;
}

bool IfPm3Zx8211(void) {
    if (IfPm3Present() == false)
        return false;
    return g_pm3_capabilities.compiled_with_zx8211;
}

void CmdsHelp(const command_t Commands[]) {
    if (Commands[0].Name == NULL) return;
    int i = 0;
    while (Commands[i].Name) {
        if (Commands[i].IsAvailable()) {
            uint8_t old_printAndLog = g_printAndLog;
            g_printAndLog &= PRINTANDLOG_PRINT;
            if (Commands[i].Name[0] == '-' || Commands[i].Name[0] == ' ') {
                PrintAndLogEx(NORMAL, "%-16s %s", Commands[i].Name, Commands[i].Help);
            } else {
                PrintAndLogEx(NORMAL, _GREEN_("%-16s")" %s", Commands[i].Name, Commands[i].Help);
            }
            g_printAndLog = old_printAndLog;
        }
        ++i;
    }
    // empty line needed for the help2json parser
    PrintAndLogEx(NORMAL, "");
}

int CmdsParse(const command_t Commands[], const char *Cmd) {

    if (g_session.client_exe_delay != 0) {
        msleep(g_session.client_exe_delay);
    }

    // Help dump children
    if (strcmp(Cmd, "XX_internal_command_dump_XX") == 0) {
        dumpCommandsRecursive(Commands, 0, false);
        return PM3_SUCCESS;
    }
    // Help dump children with help
    if (strcmp(Cmd, "XX_internal_command_dump_full_XX") == 0) {
        dumpCommandsRecursive(Commands, 0, true);
        return PM3_SUCCESS;
    }
    // Markdown help dump children
    if (strcmp(Cmd, "XX_internal_command_dump_markdown_XX") == 0) {
        dumpCommandsRecursive(Commands, 1, false);
        return PM3_SUCCESS;
    }
    // Markdown help dump children with help
    if (strcmp(Cmd, "XX_internal_command_dump_markdown_help_XX") == 0) {
        dumpCommandsRecursive(Commands, 1, true);
        return PM3_SUCCESS;
    }

    if (strcmp(Cmd, "coffee") == 0) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(NORMAL, "    ((\n     ))\n" _YELLOW_("  .______.\n  |      |]\n  \\      /\n   `----´\n\n"));
        return PM3_SUCCESS;
    }

    if (strcmp(Cmd, "star") == 0) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(NORMAL, "  \\o       o/");
        PrintAndLogEx(NORMAL, "   v\\     /v");
        PrintAndLogEx(NORMAL, "    <\\   />");
        PrintAndLogEx(NORMAL, "     |\\o/|");
        PrintAndLogEx(NORMAL, " _\\__o | o__/");
        PrintAndLogEx(NORMAL, "     |/ \\|");
        PrintAndLogEx(NORMAL, "    o/   \\o");
        PrintAndLogEx(NORMAL, "   /v     v\\");
        PrintAndLogEx(NORMAL, "  />       <\\");
        PrintAndLogEx(NORMAL, "");
        return PM3_SUCCESS;
    }


    char cmd_name[128] = {0};
    memset(cmd_name, 0, sizeof(cmd_name));

    int len = 0;
    // %n == receives an integer of value equal to the number of chars read so far.
    // len = max 127
    sscanf(Cmd, "%127s%n", cmd_name, &len);

    str_lower(cmd_name);

    // Comment
    if (cmd_name[0] == '#')
        return PM3_SUCCESS;

    // find args, check for -h / --help
    int tmplen = len;
    while (Cmd[tmplen] == ' ') {
        ++tmplen;
    }

    bool request_help = (strcmp(Cmd + tmplen, "-h") == 0) || (strcmp(Cmd + tmplen, "--help") == 0);

    int i = 0;
    while (Commands[i].Name) {
        if (0 == strcmp(Commands[i].Name, cmd_name)) {
            if ((Commands[i].Help[0] == '{') ||  // always allow parsing categories
                    request_help ||              // always allow requesting help
                    Commands[i].IsAvailable()) {
                break;
            } else {
                PrintAndLogEx(WARNING, "This command is " _YELLOW_("not available") " in this mode");
                return PM3_ENOTIMPL;
            }
        }
        ++i;
    }

    /* try to find exactly one prefix-match */
    if (!Commands[i].Name) {
        int last_match = 0;
        int matches = 0;

        for (i = 0; Commands[i].Name; i++) {
            if (!strncmp(Commands[i].Name, cmd_name, strlen(cmd_name)) && Commands[i].IsAvailable()) {
                last_match = i;
                matches++;
            }
        }
        if (matches == 1) {
            i = last_match;
        }
    }

    if (Commands[i].Name) {
        while (Cmd[len] == ' ') {
            ++len;
        }
        return Commands[i].Parse(Cmd + len);
    } else {
        // show help for selected hierarchy or if command not recognised
        CmdsHelp(Commands);
    }

    return PM3_SUCCESS;
}

static char pparent[MAX_PM3_INPUT_ARGS_LENGTH] = {0};
static char *parent = pparent;

void dumpCommandsRecursive(const command_t cmds[], int markdown, bool full_help) {
    if (cmds[0].Name == NULL) return;

    int i = 0;
    int w_cmd = 25;
    int w_off = 8;
    // First, dump all single commands, which are not a container for
    // other commands
    if (markdown) {
        PrintAndLogEx(NORMAL, "|%-*s|%-*s|%s", w_cmd, "command", w_off, "offline", "description");
        PrintAndLogEx(NORMAL, "|%-*s|%-*s|%s", w_cmd, "-------", w_off, "-------", "-----------");
    } else if (! full_help) {
        PrintAndLogEx(NORMAL, "%-*s|%-*s|%s", w_cmd, "command", w_off, "offline", "description");
        PrintAndLogEx(NORMAL, "%-*s|%-*s|%s", w_cmd, "-------", w_off, "-------", "-----------");
    }

    while (cmds[i].Name) {

        if ((cmds[i].Name[0] == '-' || strlen(cmds[i].Name) == 0) && ++i) continue;
        if (cmds[i].Help[0] == '{' && ++i) continue;

        const char *cmd_offline = "N";

        if (cmds[i].IsAvailable()) {
            cmd_offline = "Y";
        }

        if (markdown) {
            PrintAndLogEx(NORMAL, "|`%s%-*s`|%-*s|`%s`", parent, w_cmd - (int)strlen(parent) - 2, cmds[i].Name, w_off, cmd_offline, cmds[i].Help);
        } else if (full_help) {
            PrintAndLogEx(NORMAL, "---------------------------------------------------------------------------------------");
            PrintAndLogEx(NORMAL, _RED_("%s%-*s\n") "available offline: %s", parent, w_cmd - (int)strlen(parent), cmds[i].Name, cmds[i].IsAvailable() ? _GREEN_("yes") : _RED_("no"));
            cmds[i].Parse("--help");
        } else {
            PrintAndLogEx(NORMAL, "%s%-*s|%-*s|%s", parent, w_cmd - (int)strlen(parent), cmds[i].Name, w_off, cmd_offline, cmds[i].Help);
        }
        ++i;
    }
    PrintAndLogEx(NORMAL, "\n");
    i = 0;

    // Then, print the categories. These will go into subsections with their own tables
    while (cmds[i].Name) {

        if ((cmds[i].Name[0] == '-' || strlen(cmds[i].Name) == 0) && ++i) continue;
        if (cmds[i].Help[0] != '{' && ++i)  continue;

        if (full_help) {
            PrintAndLogEx(NORMAL, "=======================================================================================");
            PrintAndLogEx(NORMAL, _RED_("%s%s\n\n ")_CYAN_("%s\n"), parent, cmds[i].Name, cmds[i].Help);
        } else {
            PrintAndLogEx(NORMAL, "### %s%s\n\n %s\n", parent, cmds[i].Name, cmds[i].Help);
        }

        char currentparent[MAX_PM3_INPUT_ARGS_LENGTH] = {0};
        snprintf(currentparent, sizeof currentparent, "%s%s ", parent, cmds[i].Name);

        char *old_parent = parent;
        parent = currentparent;
        // This is what causes the recursion, since commands Parse-implementation
        // in turn calls the CmdsParse above.
        if (markdown) {
            cmds[i].Parse("XX_internal_command_dump_markdown_XX");
        } else if (full_help) {
            cmds[i].Parse("XX_internal_command_dump_full_XX");
        } else {
            cmds[i].Parse("XX_internal_command_dump_XX");
        }

        parent = old_parent;
        ++i;
    }
}
