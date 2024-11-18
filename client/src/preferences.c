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
// Preferences Functions
//-----------------------------------------------------------------------------
// Notes
//      To add a new setting
//      Add the new setting to the session_arg_t; in ui.h
//      Add the default value for the setting in the settings_load page below
//      Update the preferences_load_callback to load your setting into the structure
//      Update the preferences_save_callback to ensure your setting gets saved when needed.
//      use the preference as needed : g_session.<preference name>
//      Can use (g_session.preferences_loaded) to check if json settings file was used
//-----------------------------------------------------------------------------

#include "preferences.h"
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include "proxmark3.h"
#include "comms.h"
#include "emv/emvjson.h"
#include "cmdparser.h"
#include "cliparser.h"
#include "uart/uart.h" // uart_reconfigure_timeouts

static int CmdHelp(const char *Cmd);
static int setCmdHelp(const char *Cmd);

static char *prefGetFilename(void) {
    char *path;

    if (searchHomeFilePath(&path, NULL, preferencesFilename, false) == PM3_SUCCESS)
        return path;
    else
        return str_dup(preferencesFilename);
}

int preferences_load(void) {

    // Set all defaults
    g_session.client_debug_level = cdbOFF;
    //  g_session.device_debug_level = ddbOFF;
    g_session.timeout = uart_get_timeouts();

    g_session.window_changed = false;
    g_session.plot.x = 10;
    g_session.plot.y = 30;
    g_session.plot.h = 400;
    g_session.plot.w = 800;
    g_session.overlay.x = g_session.plot.x;
    g_session.overlay.y = 60 + g_session.plot.y + g_session.plot.h;
    g_session.overlay.h = 200;
    g_session.overlay.w = g_session.plot.w;
    g_session.overlay_sliders = true;
    g_session.show_hints = true;
    g_session.dense_output = false;

    g_session.bar_mode = STYLE_VALUE;
    setDefaultPath(spDefault, "");
    setDefaultPath(spDump, "");
    setDefaultPath(spTrace, "");

    // default save path
    if (get_my_user_directory() != NULL) // should return path to .proxmark3 folder
        setDefaultPath(spDefault, get_my_user_directory());
    else
        setDefaultPath(spDefault, ".");

    // default dump path
    if (get_my_user_directory() != NULL) // should return path to .proxmark3 folder
        setDefaultPath(spDump, get_my_user_directory());
    else
        setDefaultPath(spDump, ".");

    // default dump path
    if (get_my_user_directory() != NULL) // should return path to .proxmark3 folder
        setDefaultPath(spTrace, get_my_user_directory());
    else
        setDefaultPath(spTrace, ".");

    if (g_session.incognito) {
        PrintAndLogEx(INFO, "No preferences file will be loaded");
        return PM3_SUCCESS;
    }

    // loadFileJson wants these, so pass in place holder values, though not used
    // in settings load;
    uint8_t dummyData = 0x00;
    size_t dummyDL = 0x00;

    // to better control json cant find file error msg.
    char *fn = prefGetFilename();
    if (fileExists(fn)) {
        if (loadFileJSON(fn, &dummyData, sizeof(dummyData), &dummyDL, &preferences_load_callback) == PM3_SUCCESS) {
            g_session.preferences_loaded = true;
        }
    }
    free(fn);
    // Note, if g_session.settings_loaded == false then the settings_save
    // will be called in main () to save settings as set in defaults and main() checks.

    return PM3_SUCCESS;
}

// Save all settings from memory (struct) to file
int preferences_save(void) {
    // Note sure if backup has value ?
    if (g_session.incognito) {
        PrintAndLogEx(INFO, "No preferences file will be saved");
        return PM3_SUCCESS;
    }
    PrintAndLogEx(DEBUG, "Saving preferences...");

    char *fn = prefGetFilename();
    int fn_len = strlen(fn) + 5; // .bak\0

    // [FILENAME_MAX+sizeof(preferencesFilename)+10]
    char *backupFilename = (char *)calloc(fn_len, sizeof(uint8_t));
    if (backupFilename == NULL) {
        PrintAndLogEx(ERR, "failed to allocate memory");
        free(fn);
        return PM3_EMALLOC;
    }
    snprintf(backupFilename, fn_len, "%s.bak", fn);

    // remove old backup file
    if (fileExists(backupFilename)) {
        if (remove(backupFilename) != 0) {
            PrintAndLogEx(FAILED, "Error - could not delete old settings backup file \"%s\"", backupFilename);
            free(fn);
            free(backupFilename);
            return PM3_ESOFT;
        }
    }

    // rename file to backup file
    if (fileExists(fn)) {
        if (rename(fn, backupFilename) != 0) {
            PrintAndLogEx(FAILED, "Error - could not backup settings file \"%s\" to \"%s\"", fn, backupFilename);
            free(fn);
            free(backupFilename);
            return PM3_ESOFT;
        }
    }

    uint8_t dummyData = 0x00;
    size_t dummyDL = 0x01;

    if (saveFileJSONex(fn, jsfCustom, &dummyData, dummyDL, true, &preferences_save_callback, spItemCount) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error saving preferences to \"%s\"", fn);
    }

    free(fn);
    free(backupFilename);
    return PM3_SUCCESS;
}

// Dump all settings from memory (struct) to console in JSON
int preferences_dump(void) {
    uint8_t dummyData = 0x00;
    size_t dummyDL = 0x01;
    char *s = sprintJSON(jsfCustom, &dummyData, dummyDL, true, &preferences_save_callback);
    PrintAndLogEx(NORMAL, "%s", s);
    free(s);
    return PM3_SUCCESS;
}

void preferences_save_callback(json_t *root) {

    JsonSaveStr(root, "FileType", "settings");

    // Emoji
    switch (g_session.emoji_mode) {
        case EMO_ALIAS:
            JsonSaveStr(root, "show.emoji", "alias");
            break;
        case EMO_EMOJI:
            JsonSaveStr(root, "show.emoji", "emoji");
            break;
        case EMO_ALTTEXT:
            JsonSaveStr(root, "show.emoji", "alttext");
            break;
        case EMO_NONE:
            JsonSaveStr(root, "show.emoji", "none");
            break;
        default:
            JsonSaveStr(root, "show.emoji", "ALIAS");
    }

    JsonSaveBoolean(root, "show.hints", g_session.show_hints);

    JsonSaveBoolean(root, "output.dense", g_session.dense_output);

    JsonSaveBoolean(root, "os.supports.colors", g_session.supports_colors);

    JsonSaveStr(root, "file.default.savepath", g_session.defaultPaths[spDefault]);
    JsonSaveStr(root, "file.default.dumppath", g_session.defaultPaths[spDump]);
    JsonSaveStr(root, "file.default.tracepath", g_session.defaultPaths[spTrace]);

    // Plot window
    JsonSaveInt(root, "window.plot.xpos", g_session.plot.x);
    JsonSaveInt(root, "window.plot.ypos", g_session.plot.y);
    JsonSaveInt(root, "window.plot.hsize", g_session.plot.h);
    JsonSaveInt(root, "window.plot.wsize", g_session.plot.w);

    // Overlay/Slider window
    JsonSaveInt(root, "window.overlay.xpos", g_session.overlay.x);
    JsonSaveInt(root, "window.overlay.ypos", g_session.overlay.y);
    JsonSaveInt(root, "window.overlay.hsize", g_session.overlay.h);
    JsonSaveInt(root, "window.overlay.wsize", g_session.overlay.w);
    JsonSaveBoolean(root, "window.overlay.sliders", g_session.overlay_sliders);

    // Log level, convert to text
    switch (g_session.client_debug_level) {
        case cdbOFF:
            JsonSaveStr(root, "client.debug.level", "off");
            break;
        case cdbSIMPLE:
            JsonSaveStr(root, "client.debug.level", "simple");
            break;
        case cdbFULL:
            JsonSaveStr(root, "client.debug.level", "full");
            break;
        default:
            JsonSaveStr(root, "logging.level", "NORMAL");
    }

    switch (g_session.bar_mode) {
        case STYLE_BAR:
            JsonSaveStr(root, "show.bar.mode", "bar");
            break;
        case STYLE_MIXED:
            JsonSaveStr(root, "show.bar.mode", "mixed");
            break;
        case STYLE_VALUE:
            JsonSaveStr(root, "show.bar.mode", "value");
            break;
        default:
            JsonSaveStr(root, "show.bar.mode", "value");
    }
    /*
        switch (g_session.device_debug_level) {
            case ddbOFF:
                JsonSaveStr(root, "device.debug.level", "off");
                break;
            case ddbERROR:
                JsonSaveStr(root, "device.debug.level", "error");
                break;
            case ddbINFO:
                JsonSaveStr(root, "device.debug.level", "info");
                break;
            case ddbDEBUG:
                JsonSaveStr(root, "device.debug.level", "debug");
                break;
            case ddbEXTENDED:
                JsonSaveStr(root, "device.debug.level", "extended");
                break;
            default:
                JsonSaveStr(root, "logging.level", "NORMAL");
        }
    */
    JsonSaveInt(root, "client.exe.delay", g_session.client_exe_delay);
    JsonSaveInt(root, "client.timeout", g_session.timeout);
}
void preferences_load_callback(json_t *root) {
    json_error_t up_error = {0};
    int b1;
    int i1;
    const char *s1;
    char tempStr [500]; // to use str_lower() since json unpack uses const char *

    // Logging Level
    if (json_unpack_ex(root, &up_error, 0, "{s:s}", "client.debug.level", &s1) == 0) {
        strncpy(tempStr, s1, sizeof(tempStr) - 1);
        str_lower(tempStr);
        if (strncmp(tempStr, "off", 3) == 0) g_session.client_debug_level = cdbOFF;
        if (strncmp(tempStr, "simple", 6) == 0) g_session.client_debug_level = cdbSIMPLE;
        if (strncmp(tempStr, "full", 4) == 0) g_session.client_debug_level = cdbFULL;

        if (g_session.client_debug_level == cdbOFF) {
            SetAPDULogging(false);
        } else {
            SetAPDULogging(true);
        }
    }

    // default save path
    if (json_unpack_ex(root, &up_error, 0, "{s:s}", "file.default.savepath", &s1) == 0)
        setDefaultPath(spDefault, s1);

    // default dump path
    if (json_unpack_ex(root, &up_error, 0, "{s:s}", "file.default.dumppath", &s1) == 0)
        setDefaultPath(spDump, s1);

    // default trace path
    if (json_unpack_ex(root, &up_error, 0, "{s:s}", "file.default.tracepath", &s1) == 0)
        setDefaultPath(spTrace, s1);

    // window plot
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.plot.xpos", &i1) == 0)
        g_session.plot.x = i1;
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.plot.ypos", &i1) == 0)
        g_session.plot.y = i1;
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.plot.hsize", &i1) == 0)
        g_session.plot.h = i1;
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.plot.wsize", &i1) == 0)
        g_session.plot.w = i1;

    // overlay/slider plot
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.overlay.xpos", &i1) == 0)
        g_session.overlay.x = i1;
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.overlay.ypos", &i1) == 0)
        g_session.overlay.y = i1;
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.overlay.hsize", &i1) == 0)
        g_session.overlay.h = i1;
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.overlay.wsize", &i1) == 0)
        g_session.overlay.w = i1;
    if (json_unpack_ex(root, &up_error, 0, "{s:b}", "window.overlay.sliders", &b1) == 0)
        g_session.overlay_sliders = (bool)b1;

    // show options
    if (json_unpack_ex(root, &up_error, 0, "{s:s}", "show.emoji", &s1) == 0) {
        strncpy(tempStr, s1, sizeof(tempStr) - 1);
        str_lower(tempStr);
        if (strncmp(tempStr, "alias", 5) == 0) g_session.emoji_mode = EMO_ALIAS;
        if (strncmp(tempStr, "emoji", 5) == 0) g_session.emoji_mode = EMO_EMOJI;
        if (strncmp(tempStr, "alttext", 7) == 0) g_session.emoji_mode = EMO_ALTTEXT;
        if (strncmp(tempStr, "none", 4) == 0) g_session.emoji_mode = EMO_NONE;
    }

    if (json_unpack_ex(root, &up_error, 0, "{s:b}", "show.hints", &b1) == 0)
        g_session.show_hints = (bool)b1;

    if (json_unpack_ex(root, &up_error, 0, "{s:b}", "output.dense", &b1) == 0)
        g_session.dense_output = (bool)b1;

    if (json_unpack_ex(root, &up_error, 0, "{s:b}", "os.supports.colors", &b1) == 0)
        g_session.supports_colors = (bool)b1;

    // bar mode
    if (json_unpack_ex(root, &up_error, 0, "{s:s}", "show.bar.mode", &s1) == 0) {
        strncpy(tempStr, s1, sizeof(tempStr) - 1);
        str_lower(tempStr);
        if (strncmp(tempStr, "bar", 5) == 0) g_session.bar_mode = STYLE_BAR;
        if (strncmp(tempStr, "mixed", 5) == 0) g_session.bar_mode = STYLE_MIXED;
        if (strncmp(tempStr, "value", 7) == 0) g_session.bar_mode = STYLE_VALUE;
    }

    /*
        // Logging Level
        if (json_unpack_ex(root, &up_error, 0, "{s:s}", "device.debug.level", &s1) == 0) {
            strncpy(tempStr, s1, sizeof(tempStr) - 1);
            str_lower(tempStr);
            if (strncmp(tempStr, "off", 3) == 0) g_session.device_debug_level = ddbOFF;
            if (strncmp(tempStr, "error", 5) == 0) g_session.device_debug_level = ddbERROR;
            if (strncmp(tempStr, "info", 4) == 0) g_session.device_debug_level = ddbINFO;
            if (strncmp(tempStr, "debug", 5) == 0) g_session.device_debug_level = ddbDEBUG;
            if (strncmp(tempStr, "extended", 8) == 0) g_session.device_debug_level = ddbEXTENDED;
        }
    */
    // client command execution delay
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "client.exe.delay", &i1) == 0)
        g_session.client_exe_delay = i1;

    // client command timeout
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "client.timeout", &i1) == 0)
        g_session.timeout = i1;
}

// Help Functions

// Preference Processing Functions
// typedef enum preferenceId {prefNONE,prefHELP,prefEMOJI,prefCOLOR,prefPLOT,prefOVERLAY,prefHINTS,prefCLIENTDEBUG} preferenceId_t;
typedef enum prefShowOpt {prefShowNone, prefShowOLD, prefShowNEW, prefShowOff, prefShowUnknown} prefShowOpt_t;

static const char *pref_show_status_msg(prefShowOpt_t opt) {
    switch (opt) {
        case prefShowOLD:
            return "( " _CYAN_("old") " )";
        case prefShowNEW:
            return "( " _GREEN_("new") " )";
        case prefShowNone:
        case prefShowOff:
        case prefShowUnknown:
        default:
            return "";

    }
}

static const char *pref_show_value(prefShowOpt_t opt, const char *msg) {

    static char s[128] = {0};
    switch (opt) {
        case prefShowOLD:
            sprintf(s, _CYAN_("%s"), msg);
            return s;

        case prefShowNEW:
            sprintf(s, _GREEN_("%s"), msg);
            return s;
        case prefShowNone:
            if ((strncmp(msg, "off", 3) == 0) || (strncmp(msg, "normal", 6) == 0)) {
                sprintf(s, _WHITE_("%s"), msg);
            } else {
                sprintf(s, _GREEN_("%s"), msg);
            }
            return s;

        case prefShowOff:
            sprintf(s, _WHITE_("%s"), msg);
            return s;

        case prefShowUnknown:
            sprintf(s, _RED_("%s"), msg);
            return s;

        default:
            return "";
    }
}


static void showEmojiState(prefShowOpt_t opt) {

    switch (g_session.emoji_mode) {
        case EMO_ALIAS:
            PrintAndLogEx(INFO, "   %s emoji................... %s", pref_show_status_msg(opt), pref_show_value(opt, "alias"));
            break;
        case EMO_EMOJI:
            PrintAndLogEx(INFO, "   %s emoji................... %s", pref_show_status_msg(opt), pref_show_value(opt, "emoji"));
            break;
        case EMO_ALTTEXT:
            PrintAndLogEx(INFO, "   %s emoji................... %s", pref_show_status_msg(opt), pref_show_value(opt, "alttext"));
            break;
        case EMO_NONE:
            PrintAndLogEx(INFO, "   %s emoji................... %s", pref_show_status_msg(opt), pref_show_value(opt, "none"));
            break;
        default:
            PrintAndLogEx(INFO, "   %s emoji................... %s", pref_show_status_msg(opt), pref_show_value(prefShowUnknown, "unknown"));
    }
}

static void showColorState(prefShowOpt_t opt) {
    PrintAndLogEx(INFO, "   %s color................... %s "
                  , pref_show_status_msg(opt)
                  , (g_session.supports_colors) ? pref_show_value(opt, "ansi") : pref_show_value(opt, "off")
                 );
}

static void showClientDebugState(prefShowOpt_t opt) {

    switch (g_session.client_debug_level) {
        case cdbOFF:
            PrintAndLogEx(INFO, "   %s client debug............ %s", pref_show_status_msg(opt), pref_show_value(opt, "off"));
            break;
        case cdbSIMPLE:
            PrintAndLogEx(INFO, "   %s client debug............ %s", pref_show_status_msg(opt), pref_show_value(opt, "simple"));
            break;
        case cdbFULL:
            PrintAndLogEx(INFO, "   %s client debug............ %s", pref_show_status_msg(opt), pref_show_value(opt, "full"));
            break;
        default:
            PrintAndLogEx(INFO, "   %s client debug............ %s", pref_show_status_msg(opt), pref_show_value(prefShowUnknown, "unknown"));
    }
}
/*
static void showDeviceDebugState(prefShowOpt_t opt) {
    switch (g_session.device_debug_level) {
        case ddbOFF:
            PrintAndLogEx(INFO, "   %s device debug........... "_WHITE_("off"), prefShowMsg(opt));
            break;
        case ddbERROR:
            PrintAndLogEx(INFO, "   %s device debug........... "_GREEN_("error"), prefShowMsg(opt));
            break;
        case ddbINFO:
            PrintAndLogEx(INFO, "   %s device debug........... "_GREEN_("info"), prefShowMsg(opt));
            break;
        case ddbDEBUG:
            PrintAndLogEx(INFO, "   %s device debug........... "_GREEN_("debug"), prefShowMsg(opt));
            break;
        case ddbEXTENDED:
            PrintAndLogEx(INFO, "   %s device debug........... "_GREEN_("extended"), prefShowMsg(opt));
            break;
        default:
            PrintAndLogEx(INFO, "   %s device debug........... "_RED_("unknown"), prefShowMsg(opt));
    }
}
*/

static void showSavePathState(savePaths_t path_index, prefShowOpt_t opt) {

    char s[50];
    switch (path_index) {
        case spDefault:
            strcpy(s, "default save path.......");
            break;
        case spDump:
            strcpy(s, "dump save path..........");
            break;
        case spTrace:
            strcpy(s, "trace save path.........");
            break;
        case spItemCount:
        default:
            strcpy(s, _RED_("unknown")" save path.......");
    }

    if (path_index < spItemCount) {
        if ((g_session.defaultPaths[path_index] == NULL) || (strcmp(g_session.defaultPaths[path_index], "") == 0)) {
            PrintAndLogEx(INFO, "   %s %s "_WHITE_("not set"),
                          pref_show_status_msg(opt),
                          s
                         );
        } else {
            PrintAndLogEx(INFO, "   %s %s "_GREEN_("%s"),
                          pref_show_status_msg(opt),
                          s,
                          g_session.defaultPaths[path_index]
                         );
        }
    }
}

static void showPlotPosState(void) {
    PrintAndLogEx(INFO, "    plot window............. X "_GREEN_("%4d")" Y "_GREEN_("%4d")" H "_GREEN_("%4d")" W "_GREEN_("%4d"),
                  g_session.plot.x,
                  g_session.plot.y,
                  g_session.plot.h,
                  g_session.plot.w
                 );
}

static void showOverlayPosState(void) {
    PrintAndLogEx(INFO, "    slider/overlay window... X "_GREEN_("%4d")" Y "_GREEN_("%4d")" H "_GREEN_("%4d")" W "_GREEN_("%4d"),
                  g_session.overlay.x,
                  g_session.overlay.y,
                  g_session.overlay.h,
                  g_session.overlay.w
                 );
}

static void showHintsState(prefShowOpt_t opt) {
    PrintAndLogEx(INFO, "   %s hints................... %s"
                  , pref_show_status_msg(opt)
                  , (g_session.show_hints) ? pref_show_value(opt, "on") : pref_show_value(opt, "off")
                 );
}

static void showPlotSliderState(prefShowOpt_t opt) {
    PrintAndLogEx(INFO, "   %s show plot sliders....... %s"
                  , pref_show_status_msg(opt)
                  , (g_session.overlay_sliders) ? pref_show_value(opt, "on") : pref_show_value(opt, "off")
                 );
}

static void showBarModeState(prefShowOpt_t opt) {

    switch (g_session.bar_mode) {
        case STYLE_BAR:
            PrintAndLogEx(INFO, "   %s barmode................. %s", pref_show_status_msg(opt), pref_show_value(opt, "bar"));
            break;
        case STYLE_MIXED:
            PrintAndLogEx(INFO, "   %s barmode................. %s", pref_show_status_msg(opt), pref_show_value(opt, "mixed"));
            break;
        case STYLE_VALUE:
            PrintAndLogEx(INFO, "   %s barmode................. %s", pref_show_status_msg(opt), pref_show_value(opt, "value"));
            break;
        default:
            PrintAndLogEx(INFO, "   %s barmode................. %s", pref_show_status_msg(opt), pref_show_value(prefShowUnknown, "unknown"));
    }
}

static void showOutputState(prefShowOpt_t opt) {
    PrintAndLogEx(INFO, "   %s output.................. %s"
                  , pref_show_status_msg(opt)
                  , (g_session.dense_output) ? pref_show_value(opt, "dense") : pref_show_value(opt, "normal")
                 );
}

static void showClientExeDelayState(void) {
    PrintAndLogEx(INFO, "    cmd execution delay..... "_GREEN_("%u"), g_session.client_exe_delay);
}

static void showClientTimeoutState(void) {
    PrintAndLogEx(INFO, "    communication timeout... " _GREEN_("%u") " ms", g_session.timeout);
}

static int setCmdEmoji(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs set emoji ",
                  "Set persistent preference of using emojis in the client",
                  "prefs set emoji --alias"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "alias", "show alias for emoji"),
        arg_lit0(NULL, "emoji", "show emoji"),
        arg_lit0(NULL, "alttext", "show alt text for emoji"),
        arg_lit0(NULL, "none", "don't show emoji or text"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool show_a = arg_get_lit(ctx, 1);
    bool show_e = arg_get_lit(ctx, 2);
    bool show_alt = arg_get_lit(ctx, 3);
    bool show_none = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if ((show_a + show_e + show_alt + show_none) > 1) {
        PrintAndLogEx(FAILED, "Can only set one option");
        return PM3_EINVARG;
    }

    emojiMode_t new_value = g_session.emoji_mode;

    if (show_a) {
        new_value = EMO_ALIAS;
    }
    if (show_e) {
        new_value = EMO_EMOJI;
    }
    if (show_alt) {
        new_value = EMO_ALTTEXT;
    }
    if (show_none) {
        new_value = EMO_NONE;
    }

    if (g_session.emoji_mode != new_value) {// changed
        showEmojiState(prefShowOLD);
        g_session.emoji_mode = new_value;
        showEmojiState(prefShowNEW);
        preferences_save();
    } else {
        showEmojiState(prefShowNone);
    }

    return PM3_SUCCESS;
}

static int setCmdColor(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs set color ",
                  "Set persistent preference of using colors in the client",
                  "prefs set color --ansi"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "ansi", "use ANSI colors"),
        arg_lit0(NULL, "off", "don't use colors"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool use_c = arg_get_lit(ctx, 1);
    bool use_n = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if ((use_c + use_n) > 1) {
        PrintAndLogEx(FAILED, "Can only set one option");
        return PM3_EINVARG;
    }

    bool new_value = g_session.supports_colors;
    if (use_c) {
        new_value = true;
    }

    if (use_n) {
        new_value = false;
    }

    if (g_session.supports_colors != new_value) {
        showColorState(prefShowOLD);
        g_session.supports_colors = new_value;
        showColorState(prefShowNEW);
        preferences_save();
    } else {
        showColorState(prefShowNone);
    }

    return PM3_SUCCESS;
}

static int setCmdDebug(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs set client.debug ",
                  "Set persistent preference of using clientside debug level",
                  "prefs set client.debug --simple"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "off", "no debug messages"),
        arg_lit0(NULL, "simple", "simple debug messages"),
        arg_lit0(NULL, "full", "full debug messages"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool use_off = arg_get_lit(ctx, 1);
    bool use_simple = arg_get_lit(ctx, 2);
    bool use_full = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if ((use_off + use_simple + use_full) > 1) {
        PrintAndLogEx(FAILED, "Can only set one option");
        return PM3_EINVARG;
    }

    clientdebugLevel_t new_value = g_session.client_debug_level;

    if (use_off) {
        new_value = cdbOFF;
    }

    if (use_simple) {
        new_value = cdbSIMPLE;
    }

    if (use_full) {
        new_value = cdbFULL;
    }

    if (g_session.client_debug_level != new_value) {
        showClientDebugState(prefShowOLD);
        g_session.client_debug_level = new_value;
        g_debugMode = new_value;

        if (new_value == cdbOFF) {
            SetAPDULogging(false);
        } else {
            SetAPDULogging(true);
        }

        showClientDebugState(prefShowNEW);
        preferences_save();
    } else {
        showClientDebugState(prefShowNone);
    }

    return PM3_SUCCESS;
}
/*
static int setCmdDeviceDebug (const char *Cmd)
{
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs set devicedebug ",
                  "Set persistent preference of device side debug level",
                  "prefs set devicedebug --on"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "off", "no debug messages"),
        arg_lit0(NULL, "error", "error messages"),
        arg_lit0(NULL, "info", "info messages"),
        arg_lit0(NULL, "dbg", "debug messages"),
        arg_lit0(NULL, "ext", "extended debug messages"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool use_off = arg_get_lit(ctx, 1);
    bool use_err = arg_get_lit(ctx, 2);
    bool use_info = arg_get_lit(ctx, 3);
    bool use_dbg = arg_get_lit(ctx, 4);
    bool use_ext = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if ( (use_off + use_err + use_info + use_dbg + use_ext) > 1) {
        PrintAndLogEx(FAILED, "Can only set one option");
        return PM3_EINVARG;
    }

    devicedebugLevel_t new_value = g_session.device_debug_level;

    if (use_off) {
        new_value = ddbOFF;
    }
    if (use_err) {
        new_value = ddbERROR;
    }
    if (use_info) {
        new_value = ddbINFO;
    }
    if (use_dbg) {
        new_value = ddbDEBUG;
    }
    if (use_ext) {
        new_value = ddbEXTENDED;
    }

    if (g_session.device_debug_level != new_value) {// changed
        showDeviceDebugState (prefShowOLD);
        g_session.device_debug_level = new_value;
        showDeviceDebugState (prefShowNEW);
        preferences_save();
    } else {
        showDeviceDebugState (prefShowNone);
    }

    if (g_session.pm3_present) {
        PrintAndLogEx (INFO,"setting device debug loglevel");
        SendCommandNG(CMD_SET_DBGMODE, &g_session.device_debug_level, 1);
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_SET_DBGMODE, &resp, 2000) == false)
            PrintAndLogEx (WARNING,"failed to set device debug loglevel");
    }
    return PM3_SUCCESS;
}
*/

int getDeviceDebugLevel(uint8_t *debug_level) {
    if (!g_session.pm3_present)
        return PM3_EFAILED;

    clearCommandBuffer();
    SendCommandNG(CMD_GET_DBGMODE, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_GET_DBGMODE, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "Failed to get current device debug level");
        return PM3_ETIMEOUT;
    }

    if (debug_level)
        *debug_level = resp.data.asBytes[0];

    return PM3_SUCCESS;
}

int setDeviceDebugLevel(uint8_t debug_level, bool verbose) {
    if (!g_session.pm3_present) {
        return PM3_EFAILED;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "setting device debug loglevel to %u", debug_level);
    }

    uint8_t cdata[] = {debug_level, verbose};
    clearCommandBuffer();
    SendCommandNG(CMD_SET_DBGMODE, cdata, sizeof(cdata));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SET_DBGMODE, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "failed to set device debug loglevel");
        return PM3_EFAILED;
    }
    return PM3_SUCCESS;
}

static int setCmdOutput(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs set output",
                  "Set dump output style to condense consecutive repeated data",
                  "prefs set output --normal --> sets the output style to normal\n"
                  "prefs set output --dense  --> sets the output style to dense"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "normal", "normal output"),
        arg_lit0(NULL, "dense", "dense output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool use_off = arg_get_lit(ctx, 1);
    bool use_on = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if ((use_off + use_on) > 1) {
        PrintAndLogEx(FAILED, "Can only set one option");
        return PM3_EINVARG;
    }

    bool new_value = g_session.dense_output;
    if (use_off) {
        new_value = false;
    }
    if (use_on) {
        new_value = true;
    }

    if (g_session.dense_output != new_value) {
        showOutputState(prefShowOLD);
        g_session.dense_output = new_value;
        showOutputState(prefShowNEW);
        preferences_save();
    } else {
        showOutputState(prefShowNone);
    }

    return PM3_SUCCESS;
}

static int setCmdExeDelay(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs set client.delay",
                  "Set persistent preference of delay before executing a command in the client",
                  "prefs set client.delay --ms 0     --> unsets any delay\n"
                  "prefs set client.delay --ms 1000  --> sets 1000ms delay"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "ms", "<ms>", "delay in micro seconds"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint16_t new_value = (uint16_t)arg_get_int_def(ctx, 1, 0);
    CLIParserFree(ctx);

    if (g_session.client_exe_delay != new_value) {
        showClientExeDelayState();
        g_session.client_exe_delay = new_value;
        showClientExeDelayState();
        preferences_save();
    } else {
        showClientExeDelayState();
    }
    return PM3_SUCCESS;
}

static int setClientTimeout(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs set client.timeout",
                  "Set persistent preference of client communication timeout",
                  "prefs set client.timeout --ms 0     --> unsets any timeout\n"
                  "prefs set client.timeout -m 20      --> Set the timeout to 20ms\n"
                  "prefs set client.timeout --ms 500   --> Set the timeout to 500ms\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("m", "ms", "<ms>", "timeout in micro seconds"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t new_value = (uint32_t)arg_get_int_def(ctx, 1, 0);
    CLIParserFree(ctx);

    // UART_USB_CLIENT_RX_TIMEOUT_MS is considered as the minimum required timeout.
    if (new_value < UART_USB_CLIENT_RX_TIMEOUT_MS) {
        PrintAndLogEx(WARNING, "Timeout less than %u ms might cause errors.", UART_USB_CLIENT_RX_TIMEOUT_MS);
    } else if (new_value > 5000) {
        PrintAndLogEx(WARNING, "Timeout greater than 5000 ms makes the client unresponsive.");
    }

    if (g_session.timeout != new_value) {
        showClientTimeoutState();
        g_session.timeout = new_value;
        uart_reconfigure_timeouts(new_value);
        showClientTimeoutState();
        preferences_save();
    } else {
        showClientTimeoutState();
    }
    return PM3_SUCCESS;
}


static int setCmdHint(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs set hints",
                  "Set persistent preference of showing hint messages in the client",
                  "prefs set hints --on"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "off", "hide hints"),
        arg_lit0(NULL, "on", "show hints"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool use_off = arg_get_lit(ctx, 1);
    bool use_on = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if ((use_off + use_on) > 1) {
        PrintAndLogEx(FAILED, "Can only set one option");
        return PM3_EINVARG;
    }

    bool new_value = g_session.show_hints;
    if (use_off) {
        new_value = false;
    }
    if (use_on) {
        new_value = true;
    }

    if (g_session.show_hints != new_value) {
        showHintsState(prefShowOLD);
        g_session.show_hints = new_value;
        showHintsState(prefShowNEW);
        preferences_save();
    } else {
        showHintsState(prefShowNone);
    }

    return PM3_SUCCESS;
}

static int setCmdPlotSliders(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs set plotsliders",
                  "Set persistent preference of showing the plotslider control in the client",
                  "prefs set plotsliders --on"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "off", "hide plot slider controls"),
        arg_lit0(NULL, "on", "show plot slider controls"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool use_off = arg_get_lit(ctx, 1);
    bool use_on = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if ((use_off + use_on) > 1) {
        PrintAndLogEx(FAILED, "Can only set one option");
        return PM3_EINVARG;
    }

    bool new_value = g_session.overlay_sliders;
    if (use_off) {
        new_value = false;
    }
    if (use_on) {
        new_value = true;
    }

    if (g_session.overlay_sliders != new_value) {
        showPlotSliderState(prefShowOLD);
        g_session.overlay_sliders = new_value;
        showPlotSliderState(prefShowNEW);
        preferences_save();
    } else {
        showPlotSliderState(prefShowNone);
    }
    return PM3_SUCCESS;
}

static int setCmdSavePaths(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs set savepaths",
                  "Set persistent preference of file paths in the client",
                  "prefs set savepaths --dump /home/mydumpfolder      -> all dump files will be saved into this folder\n"
                  "prefs set savepaths --def /home/myfolder -c    -> create if needed, all files will be saved into this folder"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("c", "create", "create directory if it does not exist"),
        arg_str0(NULL, "def", "<path>", "default path"),
        arg_str0(NULL, "dump", "<path>", "dump file path"),
        arg_str0(NULL, "trace", "<path>", "trace path"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool create_dir = arg_get_lit(ctx, 1);

    int deflen = 0;
    char def_path[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)def_path, FILE_PATH_SIZE, &deflen);

    int dulen = 0;
    char dump_path[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)dump_path, FILE_PATH_SIZE, &dulen);

    int tlen = 0;
    char trace_path[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)trace_path, FILE_PATH_SIZE, &tlen);
    CLIParserFree(ctx);

    if (deflen == 0 && dulen == 0 && tlen == 0) {
        PrintAndLogEx(FAILED, "Must give at least one path");
        return PM3_EINVARG;
    }

    savePaths_t path_item = spItemCount;
    char *path = NULL;
    if (deflen) {
        path_item = spDefault;
        path = def_path;
    }
    if (dulen) {
        path_item = spDump;
        path = dump_path;
    }
    if (tlen) {
        path_item = spTrace;
        path = trace_path;
    }

    // remove trailing slash.
    size_t nplen = strlen(path);
    if ((path[nplen - 1] == '/') || (path[nplen - 1] == '\\')) {
        path[nplen - 1] = 0x00;
    }

    // Check path
    if (fileExists(path) == false && create_dir == false) {
        PrintAndLogEx(ERR, "path does not exist... "_RED_("%s"), path);
    }

    // do we need to create it
    //    if (!fileExists(newValue))
    //        create_path (newValue); //mkdir (newValue,0x777);

    if (path_item < spItemCount) {
        if (strcmp(path, g_session.defaultPaths[path_item]) != 0) {
            showSavePathState(path_item, prefShowOLD);
            setDefaultPath(path_item, path);
            showSavePathState(path_item, prefShowNEW);
            preferences_save();
        } else {
            showSavePathState(path_item, prefShowNone);
        }
    }

    return PM3_SUCCESS;
}

static int setCmdBarMode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs set barmode",
                  "Set persistent preference of HF/LF tune command styled output in the client",
                  "prefs set barmode --mix"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "bar", "measured values as bar only"),
        arg_lit0(NULL, "mix", "measured values as numbers and bar"),
        arg_lit0(NULL, "val", "measured values only"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool show_bar = arg_get_lit(ctx, 1);
    bool show_mix = arg_get_lit(ctx, 2);
    bool show_val = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if ((show_bar + show_mix + show_val) > 1) {
        PrintAndLogEx(FAILED, "Can only set one option");
        return PM3_EINVARG;
    }

    barMode_t new_value = g_session.bar_mode;
    if (show_bar) {
        new_value = STYLE_BAR;
    }
    if (show_mix) {
        new_value = STYLE_MIXED;
    }
    if (show_val) {
        new_value = STYLE_VALUE;
    }

    if (g_session.bar_mode != new_value) {
        showBarModeState(prefShowOLD);
        g_session.bar_mode = new_value;
        showBarModeState(prefShowNEW);
        preferences_save();
    } else {
        showBarModeState(prefShowNone);
    }
    return PM3_SUCCESS;
}

static int getCmdEmoji(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs get emoji",
                  "Get preference of using emojis in the client",
                  "prefs get emoji"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    showEmojiState(prefShowNone);
    return PM3_SUCCESS;
}

static int getCmdHint(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs get hints",
                  "Get preference of showing hint messages in the client",
                  "prefs get hints"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    showHintsState(prefShowNone);
    return PM3_SUCCESS;
}

static int getCmdColor(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs get color",
                  "Get preference of using colors in the client",
                  "prefs get color"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    showColorState(prefShowNone);
    return PM3_SUCCESS;
}

static int getCmdDebug(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs get client.debug",
                  "Get preference of using clientside debug level",
                  "prefs get client.debug"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    showClientDebugState(prefShowNone);
    return PM3_SUCCESS;
}

static int getCmdOutput(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs get output",
                  "Get preference of dump output style",
                  "prefs get output"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    showOutputState(prefShowNone);
    return PM3_SUCCESS;
}

static int getCmdPlotSlider(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs get plotsliders",
                  "Get preference of showing the plotslider control in the client",
                  "prefs get plotsliders"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    showPlotSliderState(prefShowNone);
    return PM3_SUCCESS;
}

static int getCmdBarMode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs get barmode",
                  "Get preference of HF/LF tune command styled output in the client",
                  "prefs get barmode"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    showBarModeState(prefShowNone);
    return PM3_SUCCESS;
}

static int getCmdSavePaths(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs get savepaths",
                  "Get preference of file paths in the client",
                  "prefs get savepaths"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    showSavePathState(spDefault, prefShowNone);
    showSavePathState(spDump, prefShowNone);
    showSavePathState(spTrace, prefShowNone);
    return PM3_SUCCESS;
}

static int getCmdExeDelay(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs get client.delay",
                  "Get preference of delay time before execution of a command in the client",
                  "prefs get client.delay"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    showClientExeDelayState();
    return PM3_SUCCESS;
}

static int getClientTimeout(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs get client.timeout",
                  "Get preference of delay time before execution of a command in the client",
                  "prefs get client.timeout"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    showClientTimeoutState();
    return PM3_SUCCESS;
}

static command_t CommandTableGet[] = {
    {"barmode",          getCmdBarMode,       AlwaysAvailable, "Get bar mode preference"},
    {"client.debug",     getCmdDebug,         AlwaysAvailable, "Get client debug level preference"},
    {"client.delay",     getCmdExeDelay,      AlwaysAvailable, "Get client execution delay preference"},
    {"client.timeout",   getClientTimeout,    AlwaysAvailable, "Get client execution delay preference"},
    {"color",            getCmdColor,         AlwaysAvailable, "Get color support preference"},
    {"savepaths",        getCmdSavePaths,     AlwaysAvailable, "Get file folder  "},
    //  {"devicedebug",      getCmdDeviceDebug,   AlwaysAvailable, "Get device debug level"},
    {"emoji",            getCmdEmoji,         AlwaysAvailable, "Get emoji display preference"},
    {"hints",            getCmdHint,          AlwaysAvailable, "Get hint display preference"},
    {"output",           getCmdOutput,        AlwaysAvailable, "Get dump output style preference"},
    {"plotsliders",      getCmdPlotSlider,    AlwaysAvailable, "Get plot slider display preference"},
    {NULL, NULL, NULL, NULL}
};

static command_t CommandTableSet[] = {
    {"help",             setCmdHelp,          AlwaysAvailable, "This help"},
    {"barmode",          setCmdBarMode,       AlwaysAvailable, "Set bar mode"},
    {"client.debug",     setCmdDebug,         AlwaysAvailable, "Set client debug level"},
    {"client.delay",     setCmdExeDelay,      AlwaysAvailable, "Set client execution delay"},
    {"client.timeout",   setClientTimeout,    AlwaysAvailable, "Set client communication timeout"},

    {"color",            setCmdColor,         AlwaysAvailable, "Set color support"},
    {"emoji",            setCmdEmoji,         AlwaysAvailable, "Set emoji display"},
    {"hints",            setCmdHint,          AlwaysAvailable, "Set hint display"},
    {"savepaths",        setCmdSavePaths,     AlwaysAvailable, "... to be adjusted next ... "},
    //  {"devicedebug",      setCmdDeviceDebug,   AlwaysAvailable, "Set device debug level"},
    {"output",           setCmdOutput,        AlwaysAvailable, "Set dump output style"},
    {"plotsliders",      setCmdPlotSliders,   AlwaysAvailable, "Set plot slider display"},
    {NULL, NULL, NULL, NULL}
};

static int setCmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTableSet);
    return PM3_SUCCESS;
}

static int CmdPrefGet(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTableGet, Cmd);
}

static int CmdPrefSet(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTableSet, Cmd);
}

static int CmdPrefShow(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "prefs show",
                  "Show all persistent preferences",
                  "prefs show"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("j", "json", "Dump prefs as JSON"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool json_dump = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (json_dump) {
        preferences_dump();
        return PM3_SUCCESS;
    }
    if (g_session.preferences_loaded) {
        char *fn = prefGetFilename();
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "Using "_YELLOW_("%s"), fn);
        free(fn);
    } else {
        PrintAndLogEx(WARNING, "Preferences file not loaded");
    }

    PrintAndLogEx(INFO, "Current settings");
    showEmojiState(prefShowNone);
    showHintsState(prefShowNone);
    showColorState(prefShowNone);
    showPlotPosState();
    showOverlayPosState();
    showSavePathState(spDefault, prefShowNone);
    showSavePathState(spDump, prefShowNone);
    showSavePathState(spTrace, prefShowNone);
    showClientDebugState(prefShowNone);
    showPlotSliderState(prefShowNone);
//    showDeviceDebugState(prefShowNone);
    showBarModeState(prefShowNone);
    showClientExeDelayState();
    showOutputState(prefShowNone);
    showClientTimeoutState();

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
/*
static int CmdPrefSave (const char *Cmd) {
    preferences_save();
    return PM3_SUCCESS;
}
*/
static command_t CommandTable[] = {
    {"help",         CmdHelp,            AlwaysAvailable, "This help"},
    {"get",          CmdPrefGet,         AlwaysAvailable, "{ Get a preference }"},
    {"set",          CmdPrefSet,         AlwaysAvailable, "{ Set a preference }"},
    {"show",         CmdPrefShow,        AlwaysAvailable, "Show all preferences"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdPreferences(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
