//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Preferences Functions
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Notes
//      To add a new setting
//      Add the new setting to the session_arg_t; in ui.h
//      Add the default value for the setting in the settings_load page below
//      Update the preferences_load_callback to load your setting into the stucture
//      Update the preferences_save_callback to enusre your setting gets saved when needed.
//      use the preference as needed : session.<preference name>
//      Can use (session.preferences_loaded) to check if json settings file was used
//-----------------------------------------------------------------------------

#include "preferences.h"
#include "comms.h"
#include "emv/emvjson.h"
#include <string.h>
#include "cmdparser.h"
#include <ctype.h>
#include <dirent.h>
#include <proxmark3.h>

static int CmdHelp(const char *Cmd);
static int setCmdHelp(const char *Cmd);

static char *prefGetFilename(void) {
    char *path;

    if (searchHomeFilePath(&path, NULL, preferencesFilename, false) == PM3_SUCCESS)
        return path;
    else
        return strdup(preferencesFilename);
}

int preferences_load(void) {

    // Set all defaults
    session.client_debug_level = cdbOFF;
    //  session.device_debug_level = ddbOFF;
    session.window_changed = false;
    session.plot.x = 10;
    session.plot.y = 30;
    session.plot.h = 400;
    session.plot.w = 800;
    session.overlay.x = session.plot.x;
    session.overlay.y = 60 + session.plot.y + session.plot.h;
    session.overlay.h = 200;
    session.overlay.w = session.plot.w;
    session.overlay_sliders = true;
    session.show_hints = false;

//    setDefaultPath (spDefault, "");
//    setDefaultPath (spDump, "");
//    setDefaultPath (spTrace, "");

    /*
        // default save path
        if (get_my_user_directory() != NULL) // should return path to .proxmark3 folder
            setDefaultPath (spDefault, get_my_user_directory());
        else
            setDefaultPath (spDefault, ".");

        // default dump path
        if (get_my_user_directory() != NULL) // should return path to .proxmark3 folder
            setDefaultPath (spDump, get_my_user_directory());
        else
            setDefaultPath (spDump, ".");

        // default dump path
        if (get_my_user_directory() != NULL) // should return path to .proxmark3 folder
            setDefaultPath (spTrace, get_my_user_directory());
        else
            setDefaultPath (spTrace, ".");
    */

    // loadFileJson wants these, so pass in place holder values, though not used
    // in settings load;
    uint8_t dummyData = 0x00;
    size_t dummyDL = 0x00;

    // to better control json cant find file error msg.
    char *fn = prefGetFilename();
    if (fileExists(fn)) {
        if (loadFileJSON(fn, &dummyData, sizeof(dummyData), &dummyDL, &preferences_load_callback) == PM3_SUCCESS) {
            session.preferences_loaded = true;
        }
    }
    free(fn);
    // Note, if session.settings_loaded == false then the settings_save
    // will be called in main () to save settings as set in defaults and main() checks.

    return PM3_SUCCESS;
}

// Save all settings from memory (struct) to file
int preferences_save(void) {
    // Note sure if backup has value ?

    PrintAndLogEx(INFO, "Saving preferences...");

    char *fn = prefGetFilename();
    int fnLen = strlen(fn) + 5; // .bak\0

    // [FILENAME_MAX+sizeof(preferencesFilename)+10]
    char *backupFilename = (char *)calloc(fnLen, sizeof(uint8_t));
    if (backupFilename == NULL) {
        PrintAndLogEx(ERR, "failed to allocate memory");
        free(fn);
        return PM3_EMALLOC;
    }
    snprintf(backupFilename, fnLen, "%s.bak", fn);

    if (fileExists(backupFilename)) {
        if (remove(backupFilename) != 0) {
            PrintAndLogEx(FAILED, "Error - could not delete old settings backup file \"%s\"", backupFilename);
            free(fn);
            free(backupFilename);
            return PM3_ESOFT;
        }
    }

    if (fileExists(fn)) {
        if (rename(fn, backupFilename) != 0) {
            PrintAndLogEx(FAILED, "Error - could not backup settings file \"%s\" to \"%s\"", fn, backupFilename);
            free(fn);
            free(backupFilename);
            return PM3_ESOFT;
        }
    }

    uint8_t dummyData = 0x00;
    size_t dummyDL = 0x00;

    if (saveFileJSON(fn, jsfCustom, &dummyData, dummyDL, &preferences_save_callback) != PM3_SUCCESS)
        PrintAndLogEx(ERR, "Error saving preferences to \"%s\"", fn);

    free(fn);
    free(backupFilename);
    return PM3_SUCCESS;
}

void preferences_save_callback(json_t *root) {

    JsonSaveStr(root, "FileType", "settings");

    // Emoji
    switch (session.emoji_mode) {
        case ALIAS:
            JsonSaveStr(root, "show.emoji", "alias");
            break;
        case EMOJI:
            JsonSaveStr(root, "show.emoji", "emoji");
            break;
        case ALTTEXT:
            JsonSaveStr(root, "show.emoji", "alttext");
            break;
        case ERASE:
            JsonSaveStr(root, "show.emoji", "erase");
            break;
        default:
            JsonSaveStr(root, "show.emoji", "ALIAS");
    }

    JsonSaveBoolean(root, "show.hints", session.show_hints);

    JsonSaveBoolean(root, "os.supports.colors", session.supports_colors);

//   JsonSaveStr(root, "file.default.savepath", session.defaultPaths[spDefault]);
//   JsonSaveStr(root, "file.default.dumppath", session.defaultPaths[spDump]);
//   JsonSaveStr(root, "file.default.tracepath", session.defaultPaths[spTrace]);

    // Plot window
    JsonSaveInt(root, "window.plot.xpos", session.plot.x);
    JsonSaveInt(root, "window.plot.ypos", session.plot.y);
    JsonSaveInt(root, "window.plot.hsize", session.plot.h);
    JsonSaveInt(root, "window.plot.wsize", session.plot.w);

    // Overlay/Slider window
    JsonSaveInt(root, "window.overlay.xpos", session.overlay.x);
    JsonSaveInt(root, "window.overlay.ypos", session.overlay.y);
    JsonSaveInt(root, "window.overlay.hsize", session.overlay.h);
    JsonSaveInt(root, "window.overlay.wsize", session.overlay.w);
    JsonSaveBoolean(root, "window.overlay.sliders", session.overlay_sliders);

    // Log level, convert to text
    switch (session.client_debug_level) {
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
    /*
        switch (session.device_debug_level) {
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
}

void preferences_load_callback(json_t *root) {
    json_error_t up_error = {0};
    bool b1;
    int i1;
    const char *s1;
    char tempStr [500]; // to use str_lower() since json unpack uses const char *

    // Logging Level
    if (json_unpack_ex(root, &up_error, 0, "{s:s}", "client.debug.level", &s1) == 0) {
        strncpy(tempStr, s1, sizeof(tempStr) - 1);
        str_lower(tempStr);
        if (strncmp(tempStr, "off", 3) == 0) session.client_debug_level = cdbOFF;
        if (strncmp(tempStr, "simple", 6) == 0) session.client_debug_level = cdbSIMPLE;
        if (strncmp(tempStr, "full", 4) == 0) session.client_debug_level = cdbFULL;
    }
    /*
        // default save path
        if (json_unpack_ex(root, &up_error, 0, "{s:s}", "file.default.savepath", &s1) == 0)
            setDefaultPath (spDefault,s1);

        // default dump path
        if (json_unpack_ex(root, &up_error, 0, "{s:s}", "file.default.dumppath", &s1) == 0)
            setDefaultPath (spDump,s1);

        // default trace path
        if (json_unpack_ex(root, &up_error, 0, "{s:s}", "file.default.tracepath", &s1) == 0)
            setDefaultPath (spTrace,s1);
    */
    // window plot
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.plot.xpos", &i1) == 0)
        session.plot.x = i1;
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.plot.ypos", &i1) == 0)
        session.plot.y = i1;
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.plot.hsize", &i1) == 0)
        session.plot.h = i1;
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.plot.wsize", &i1) == 0)
        session.plot.w = i1;

    // overlay/slider plot
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.overlay.xpos", &i1) == 0)
        session.overlay.x = i1;
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.overlay.ypos", &i1) == 0)
        session.overlay.y = i1;
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.overlay.hsize", &i1) == 0)
        session.overlay.h = i1;
    if (json_unpack_ex(root, &up_error, 0, "{s:i}", "window.overlay.wsize", &i1) == 0)
        session.overlay.w = i1;
    if (json_unpack_ex(root, &up_error, 0, "{s:b}", "window.overlay.sliders", &b1) == 0)
        session.overlay_sliders = b1;

    // show options
    if (json_unpack_ex(root, &up_error, 0, "{s:s}", "show.emoji", &s1) == 0) {
        strncpy(tempStr, s1, sizeof(tempStr) - 1);
        str_lower(tempStr);
        if (strncmp(tempStr, "alias", 5) == 0) session.emoji_mode = ALIAS;
        if (strncmp(tempStr, "emoji", 5) == 0) session.emoji_mode = EMOJI;
        if (strncmp(tempStr, "alttext", 7) == 0) session.emoji_mode = ALTTEXT;
        if (strncmp(tempStr, "erase", 5) == 0) session.emoji_mode = ERASE;
    }

    if (json_unpack_ex(root, &up_error, 0, "{s:b}", "show.hints", &b1) == 0)
        session.show_hints = b1;

    if (json_unpack_ex(root, &up_error, 0, "{s:b}", "os.supports.colors", &b1) == 0)
        session.supports_colors = b1;
    /*
        // Logging Level
        if (json_unpack_ex(root, &up_error, 0, "{s:s}", "device.debug.level", &s1) == 0) {
            strncpy(tempStr, s1, sizeof(tempStr) - 1);
            str_lower(tempStr);
            if (strncmp(tempStr, "off", 3) == 0) session.device_debug_level = ddbOFF;
            if (strncmp(tempStr, "error", 5) == 0) session.device_debug_level = ddbERROR;
            if (strncmp(tempStr, "info", 4) == 0) session.device_debug_level = ddbINFO;
            if (strncmp(tempStr, "debug", 5) == 0) session.device_debug_level = ddbDEBUG;
            if (strncmp(tempStr, "extended", 8) == 0) session.device_debug_level = ddbEXTENDED;
        }
    */
}

// Help Functions

static int usage_set_emoji(void) {
    PrintAndLogEx(NORMAL, "Usage: pref set emoji <alias | emoji | alttext | erase>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     "_GREEN_("help")"        - This help");
    PrintAndLogEx(NORMAL, "     "_GREEN_("alias")"       - Show alias for emoji");
    PrintAndLogEx(NORMAL, "     "_GREEN_("emoji")"       - Show amoji");
    PrintAndLogEx(NORMAL, "     "_GREEN_("alttext")"     - Show alt text for emoji");
    PrintAndLogEx(NORMAL, "     "_GREEN_("erase")"       - Dont show emoji or text");
    return PM3_SUCCESS;
}

static int usage_set_color(void) {
    PrintAndLogEx(NORMAL, "Usage: pref set color <off | ansi>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     "_GREEN_("help")"        - This help");
    PrintAndLogEx(NORMAL, "     "_GREEN_("off")"         - Dont use colors");
    PrintAndLogEx(NORMAL, "     "_GREEN_("ansi")"        - Use ANSI colors");
    return PM3_SUCCESS;
}

static int usage_set_debug(void) {
    PrintAndLogEx(NORMAL, "Usage: pref set clientdebug <off | simple | full>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     "_GREEN_("help")"        - This help");
    PrintAndLogEx(NORMAL, "     "_GREEN_("off")"         - no debug messages");
    PrintAndLogEx(NORMAL, "     "_GREEN_("simple")"      - simple debug messages");
    PrintAndLogEx(NORMAL, "     "_GREEN_("full")"        - full debug messages");
    return PM3_SUCCESS;
}
/*
static int usage_set_devicedebug(void) {
    PrintAndLogEx(NORMAL, "Usage: pref set devicedebug <off | error | info | debug | extended>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     "_GREEN_("help")"        - This help");
    PrintAndLogEx(NORMAL, "     "_GREEN_("off")"         - no debug messages");
    PrintAndLogEx(NORMAL, "     "_GREEN_("error")"       - error messages");
    PrintAndLogEx(NORMAL, "     "_GREEN_("info")"        - info messages");
    PrintAndLogEx(NORMAL, "     "_GREEN_("debug")"       - debug messages");
    PrintAndLogEx(NORMAL, "     "_GREEN_("extended")"    - extended debug messages");

    return PM3_SUCCESS;
}
*/
static int usage_set_hints(void) {
    PrintAndLogEx(NORMAL, "Usage: pref set hints <off | on>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     "_GREEN_("help")"        - This help");
    PrintAndLogEx(NORMAL, "     "_GREEN_("off")"         - Dont display hints");
    PrintAndLogEx(NORMAL, "     "_GREEN_("on")"          - Display hints");
    return PM3_SUCCESS;
}

static int usage_set_plotsliders(void) {
    PrintAndLogEx(NORMAL, "Usage: pref set plotsliders <on | off>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     "_GREEN_("help")"        - This help");
    PrintAndLogEx(NORMAL, "     "_GREEN_("on")"          - show plot slider controls");
    PrintAndLogEx(NORMAL, "     "_GREEN_("off")"         - hide plot slider controls");
    return PM3_SUCCESS;
}

/*
static int usage_set_savePaths(void) {
    PrintAndLogEx(NORMAL, "Usage: pref set savepaths [help] [create] [default <path>] [dump <path>] [trace <path>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     "_GREEN_("help")"        - This help");
    PrintAndLogEx(NORMAL, "     "_GREEN_("create")"      - Create directory if it does not exist");
    PrintAndLogEx(NORMAL, "     "_GREEN_("default")"     - Deafult path");
    PrintAndLogEx(NORMAL, "     "_GREEN_("dump")"        - Dump path");
    PrintAndLogEx(NORMAL, "     "_GREEN_("trace")"       - Trace help");

    return PM3_SUCCESS;
}
*/
// Preference Processing Functions
// typedef enum preferenceId {prefNONE,prefHELP,prefEMOJI,prefCOLOR,prefPLOT,prefOVERLAY,prefHINTS,prefCLIENTDEBUG} preferenceId_t;
typedef enum prefShowOpt {prefShowNone, prefShowOLD, prefShowNEW} prefShowOpt_t;

static const char *prefShowMsg(prefShowOpt_t Opt) {
    switch (Opt) {
        case prefShowOLD:
            return _YELLOW_("[old]");
        case prefShowNEW:
            return _GREEN_("[new]");
        case prefShowNone:
            return "";
    }

    return "";
}

static void showEmojiState(prefShowOpt_t opt) {

    switch (session.emoji_mode) {
        case ALIAS:
            PrintAndLogEx(INFO, "   %s emoji.................. "_GREEN_("alias"), prefShowMsg(opt));
            break;
        case EMOJI:
            PrintAndLogEx(INFO, "   %s emoji.................. "_GREEN_("emoji"), prefShowMsg(opt));
            break;
        case ALTTEXT:
            PrintAndLogEx(INFO, "   %s emoji.................. "_GREEN_("alttext"), prefShowMsg(opt));
            break;
        case ERASE:
            PrintAndLogEx(INFO, "   %s emoji.................. "_GREEN_("erase"), prefShowMsg(opt));
            break;
        default:
            PrintAndLogEx(INFO, "   %s emoji.................. "_RED_("unknown"), prefShowMsg(opt));
    }
}

static void showColorState(prefShowOpt_t opt) {

    if (session.supports_colors)
        PrintAndLogEx(INFO, "   %s color.................. "_GREEN_("ansi"), prefShowMsg(opt));
    else
        PrintAndLogEx(INFO, "   %s color.................. "_WHITE_("off"), prefShowMsg(opt));
}

static void showClientDebugState(prefShowOpt_t opt) {

    switch (session.client_debug_level) {
        case cdbOFF:
            PrintAndLogEx(INFO, "   %s client debug........... "_WHITE_("off"), prefShowMsg(opt));
            break;
        case cdbSIMPLE:
            PrintAndLogEx(INFO, "   %s client debug........... "_GREEN_("simple"), prefShowMsg(opt));
            break;
        case cdbFULL:
            PrintAndLogEx(INFO, "   %s client debug........... "_GREEN_("full"), prefShowMsg(opt));
            break;
        default:
            PrintAndLogEx(INFO, "   %s client debug........... "_RED_("unknown"), prefShowMsg(opt));
    }
}
/*
static void showDeviceDebugState(prefShowOpt_t opt) {
    switch (session.device_debug_level) {
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
/*
static void showSavePathState(savePaths_t pathIndex, prefShowOpt_t opt) {

    char tempStr[50];

    switch (pathIndex) {
        case spDefault:
            strcpy (tempStr,"default save path......");
            break;
        case spDump:
            strcpy (tempStr,"dump save path.........");
            break;
        case spTrace:
            strcpy (tempStr,"trace save path........");
            break;
        default:
            strcpy (tempStr,_RED_("unknown")" save path......");
    }
    if ((session.defaultPaths[pathIndex] == NULL) || (strcmp(session.defaultPaths[pathIndex],"") == 0))
        PrintAndLogEx(INFO, "   %s %s "_WHITE_("not set"), prefShowMsg(opt),tempStr);
    else
        PrintAndLogEx(INFO, "   %s %s "_GREEN_("%s"), prefShowMsg(opt), tempStr, session.defaultPaths[pathIndex]);
}

static void showPlotPosState(void) {
    PrintAndLogEx(INFO, "    Plot window............ X "_GREEN_("%4d")" Y "_GREEN_("%4d")" H "_GREEN_("%4d")" W "_GREEN_("%4d"),
                  session.plot.x, session.plot.y, session.plot.h, session.plot.w);
}

static void showOverlayPosState(void) {
    PrintAndLogEx(INFO, "    Slider/Overlay window.. X "_GREEN_("%4d")" Y "_GREEN_("%4d")" H "_GREEN_("%4d")" W "_GREEN_("%4d"),
                  session.overlay.x, session.overlay.y, session.overlay.h, session.overlay.w);
}
*/

static void showHintsState(prefShowOpt_t opt) {
    if (session.show_hints)
        PrintAndLogEx(INFO, "   %s hints.................. "_GREEN_("on"), prefShowMsg(opt));
    else
        PrintAndLogEx(INFO, "   %s hints.................. "_WHITE_("off"), prefShowMsg(opt));
}

static void showPlotSliderState(prefShowOpt_t opt) {
    if (session.overlay_sliders)
        PrintAndLogEx(INFO, "   %s show plot sliders...... "_GREEN_("on"), prefShowMsg(opt));
    else
        PrintAndLogEx(INFO, "   %s show plot sliders...... "_WHITE_("off"), prefShowMsg(opt));
}


static int setCmdEmoji(const char *Cmd) {
    uint8_t cmdp = 0;
    bool errors = false;
    bool validValue = false;
    char strOpt[50];
    emojiMode_t newValue = session.emoji_mode;

    if (param_getchar(Cmd, cmdp) == 0x00)
        return usage_set_emoji();

    while ((param_getchar(Cmd, cmdp) != 0x00) && !errors) {

        if (param_getstr(Cmd, cmdp++, strOpt, sizeof(strOpt)) != 0) {
            str_lower(strOpt); // convert to lowercase

            if (strncmp(strOpt, "help", 4) == 0)
                return usage_set_emoji();
            if (strncmp(strOpt, "alias", 5) == 0) {
                validValue = true;
                newValue = ALIAS;
            }
            if (strncmp(strOpt, "emoji", 5) == 0) {
                validValue = true;
                newValue = EMOJI;
            }
            if (strncmp(strOpt, "alttext", 7) == 0) {
                validValue = true;
                newValue = ALTTEXT;
            }
            if (strncmp(strOpt, "erase", 5) == 0) {
                validValue = true;
                newValue = ERASE;
            }

            if (validValue) {
                if (session.emoji_mode != newValue) {// changed
                    showEmojiState(prefShowOLD);
                    session.emoji_mode = newValue;
                    showEmojiState(prefShowNEW);
                    preferences_save();
                } else {
                    PrintAndLogEx(INFO, "nothing changed");
                    showEmojiState(prefShowNone);
                }
            } else {
                PrintAndLogEx(ERR, "invalid option");
                return usage_set_emoji();
            }
        }
    }

    return PM3_SUCCESS;
}

static int setCmdColor(const char *Cmd) {
    uint8_t cmdp = 0;
    bool errors = false;
    bool validValue = false;
    char strOpt[50];
    bool newValue = session.supports_colors;

    if (param_getchar(Cmd, cmdp) == 0x00)
        return usage_set_color();

    while ((param_getchar(Cmd, cmdp) != 0x00) && !errors) {

        if (param_getstr(Cmd, cmdp++, strOpt, sizeof(strOpt)) != 0) {
            str_lower(strOpt); // convert to lowercase

            if (strncmp(strOpt, "help", 4) == 0)
                return usage_set_color();
            if (strncmp(strOpt, "off", 3) == 0) {
                validValue = true;
                newValue = false;
            }
            if (strncmp(strOpt, "ansi", 4) == 0) {
                validValue = true;
                newValue = true;
            }

            if (validValue) {
                if (session.supports_colors != newValue) {// changed
                    showColorState(prefShowOLD);
                    session.supports_colors = newValue;
                    showColorState(prefShowNEW);
                    preferences_save();
                } else {
                    PrintAndLogEx(INFO, "nothing changed");
                    showColorState(prefShowNone);
                }
            } else {
                PrintAndLogEx(ERR, "invalid option");
                return usage_set_color();
            }
        }
    }

    return PM3_SUCCESS;
}

static int setCmdDebug(const char *Cmd) {
    uint8_t cmdp = 0;
    bool errors = false;
    bool validValue = false;
    char strOpt[50];
    clientdebugLevel_t newValue = session.client_debug_level;

    if (param_getchar(Cmd, cmdp) == 0x00)
        return usage_set_debug();

    while ((param_getchar(Cmd, cmdp) != 0x00) && !errors) {

        if (param_getstr(Cmd, cmdp++, strOpt, sizeof(strOpt)) != 0) {
            str_lower(strOpt); // convert to lowercase

            if (strncmp(strOpt, "help", 4) == 0)
                return usage_set_debug();
            if (strncmp(strOpt, "off", 3) == 0) {
                validValue = true;
                newValue = cdbOFF;
            }
            if (strncmp(strOpt, "simple", 6) == 0) {
                validValue = true;
                newValue = cdbSIMPLE;
            }
            if (strncmp(strOpt, "full", 4) == 0) {
                validValue = true;
                newValue = cdbFULL;
            }

            if (validValue) {
                if (session.client_debug_level != newValue) {// changed
                    showClientDebugState(prefShowOLD);
                    session.client_debug_level = newValue;
                    g_debugMode = newValue;
                    showClientDebugState(prefShowNEW);
                    preferences_save();
                } else {
                    PrintAndLogEx(INFO, "nothing changed");
                    showClientDebugState(prefShowNone);
                }
            } else {
                PrintAndLogEx(ERR, "invalid option");
                return usage_set_debug();
            }
        }
    }

    return PM3_SUCCESS;
}
/*
static int setCmdDeviceDebug (const char *Cmd)
{
    uint8_t cmdp = 0;
    bool errors = false;
    bool validValue = false;
    char strOpt[50];
    devicedebugLevel_t newValue = session.device_debug_level;

    if (param_getchar(Cmd, cmdp) == 0x00)
        return usage_set_devicedebug ();

    while ((param_getchar(Cmd, cmdp) != 0x00) && !errors) {

        if (param_getstr(Cmd, cmdp++, strOpt, sizeof(strOpt)) != 0) {
            str_lower(strOpt); // convert to lowercase

            if (strncmp (strOpt,"help",4) == 0)
                return usage_set_devicedebug();
            if (strncmp (strOpt,"off",3) == 0) {
                validValue = true;
                newValue = ddbOFF;
            }
            if (strncmp (strOpt,"error",5) == 0) {
                validValue = true;
                newValue = ddbERROR;
            }
            if (strncmp (strOpt,"info",4) == 0) {
                validValue = true;
                newValue = ddbINFO;
            }
            if (strncmp (strOpt,"debug",5) == 0) {
                validValue = true;
                newValue = ddbDEBUG;
            }
            if (strncmp (strOpt,"extended",8) == 0) {
                validValue = true;
                newValue = ddbEXTENDED;
            }

            if (validValue) {
                if (session.device_debug_level != newValue) {// changed
                    showDeviceDebugState (prefShowOLD);
                    session.device_debug_level = newValue;
                    showDeviceDebugState (prefShowNEW);
                    preferences_save ();
                } else {
                    PrintAndLogEx(INFO,"nothing changed");
                    showDeviceDebugState (prefShowNone);
                }
                if (session.pm3_present) {
                    PrintAndLogEx (INFO,"setting device debug loglevel");
                    SendCommandNG(CMD_SET_DBGMODE, &session.device_debug_level, 1);
                    PacketResponseNG resp;
                    if (WaitForResponseTimeout(CMD_SET_DBGMODE, &resp, 2000) == false)
                        PrintAndLogEx (INFO,"failed to set device debug loglevel");
                }
            } else {
                PrintAndLogEx(ERR,"invalid option");
                return usage_set_devicedebug();
            }
        }
    }

    return PM3_SUCCESS;
}
*/
static int setCmdHint(const char *Cmd) {
    uint8_t cmdp = 0;
    bool errors = false;
    bool validValue = false;
    char strOpt[50];
    bool newValue = session.show_hints;

    if (param_getchar(Cmd, cmdp) == 0x00)
        return usage_set_hints();

    while ((param_getchar(Cmd, cmdp) != 0x00) && !errors) {

        if (param_getstr(Cmd, cmdp++, strOpt, sizeof(strOpt)) != 0) {
            str_lower(strOpt); // convert to lowercase

            if (strncmp(strOpt, "help", 4) == 0)
                return usage_set_hints();
            if (strncmp(strOpt, "off", 3) == 0) {
                validValue = true;
                newValue = false;
            }
            if (strncmp(strOpt, "on", 2) == 0) {
                validValue = true;
                newValue = true;
            }

            if (validValue) {
                if (session.show_hints != newValue) {// changed
                    showHintsState(prefShowOLD);
                    session.show_hints = newValue;
                    showHintsState(prefShowNEW);
                    preferences_save();
                } else {
                    PrintAndLogEx(INFO, "nothing changed");
                    showHintsState(prefShowNone);
                }
            } else {
                PrintAndLogEx(ERR, "invalid option");
                return usage_set_hints();
            }
        }
    }

    return PM3_SUCCESS;
}
static int setCmdPlotSliders(const char *Cmd) {
    uint8_t cmdp = 0;
    bool errors = false;
    bool validValue = false;
    char strOpt[50];
    bool newValue = session.overlay_sliders;

    if (param_getchar(Cmd, cmdp) == 0x00)
        return usage_set_plotsliders();

    while ((param_getchar(Cmd, cmdp) != 0x00) && !errors) {

        if (param_getstr(Cmd, cmdp++, strOpt, sizeof(strOpt)) != 0) {
            str_lower(strOpt); // convert to lowercase

            if (strncmp(strOpt, "help", 4) == 0)
                return usage_set_plotsliders();
            if (strncmp(strOpt, "off", 3) == 0) {
                validValue = true;
                newValue = false;
            }
            if (strncmp(strOpt, "on", 2) == 0) {
                validValue = true;
                newValue = true;
            }

            if (validValue) {
                if (session.overlay_sliders != newValue) {// changed
                    showPlotSliderState(prefShowOLD);
                    session.overlay_sliders = newValue;
                    showPlotSliderState(prefShowNEW);
                    preferences_save();
                } else {
                    PrintAndLogEx(INFO, "nothing changed");
                    showPlotSliderState(prefShowNone);
                }
            } else {
                PrintAndLogEx(ERR, "invalid option");
                return usage_set_plotsliders();
            }
        }
    }

    return PM3_SUCCESS;
}

/*
static int setCmdSavePaths (const char *Cmd) {
    uint8_t cmdp = 0;
    bool errors = false;
    // bool validValue = false;
    char *strOpt = NULL;
    int  optLen = 0;
    char *newValue = NULL;
    bool createDir = false;
    savePaths_t pathItem = spItemCount;


    if (param_getchar(Cmd, cmdp) == 0x00)
        return usage_set_savePaths();

    while ((param_getchar(Cmd, cmdp) != 0x00) && !errors) {

        optLen = param_getlength(Cmd, cmdp)+1;
        strOpt = (char *)realloc(strOpt,optLen+1);//, sizeof(uint8_t));

        if (param_getstr(Cmd, cmdp++, strOpt, optLen) != 0) {
            str_lower(strOpt); // convert to lowercase

            if (strncmp(strOpt, "help", 4) == 0)
                return usage_set_savePaths();

            if (strncmp(strOpt, "create", 6) == 0) {
                // check if 2 more options.
                if (param_getlength(Cmd, cmdp+1) == 0) // should have min 2 more options
                    return usage_set_savePaths();
                createDir = true;
            } else {
                if ((strncmp(strOpt, "default", 7) == 0) ||
                    (strncmp(strOpt, "dump", 4) == 0) ||
                    (strncmp(strOpt, "trace", 5) == 0)) {

                    // Get Path
                    optLen = param_getlength(Cmd, cmdp) + 1;
                    newValue = (char *)realloc(newValue, optLen+1);
                    if (param_getstr(Cmd, cmdp++, newValue, optLen) == 0) {
                        PrintAndLogEx(INFO, "missing %s path",strOpt);
                        return usage_set_savePaths();
                    }
                    // remove trailing slash.
                    if ((newValue[strlen(newValue)-1] == '/') || (newValue[strlen(newValue)-1] == '\\'))
                        newValue[strlen(newValue)-1] = 0x00;

                    // Check path
                    if (!fileExists(newValue) && !createDir) {
                        PrintAndLogEx(ERR,"path does not exist... "_RED_("%s"),newValue);
                    } else {
                        // do we need to create it
                    //    if (!fileExists(newValue))
                    //        create_path (newValue); //mkdir (newValue,0x777);

                        pathItem = spItemCount;
                        if (strncmp(strOpt, "default", 7) == 0) pathItem = spDefault;
                        if (strncmp(strOpt, "dump", 4) == 0) pathItem = spDump;
                        if (strncmp(strOpt, "trace", 5) == 0) pathItem = spTrace;

                        if (pathItem < spItemCount) {
                            if (strcmp(newValue, session.defaultPaths[pathItem]) != 0) {
                                showSavePathState(pathItem, prefShowOLD);
                                setDefaultPath (pathItem, newValue);
                                showSavePathState(pathItem, prefShowNEW);
                                preferences_save();
                            } else {
                                PrintAndLogEx(INFO, "nothing changed");
                                showSavePathState(pathItem, prefShowNone);
                            }
                        }
                    }
                } else {
                    return usage_set_savePaths();
                }
            }
        }
    }

    // clean up
    if (strOpt != NULL) free (strOpt);
    if (newValue != NULL) free (newValue);

    return PM3_SUCCESS;
}

static int getCmdHelp(const char *Cmd) {
    return PM3_SUCCESS;
}
*/

static int getCmdEmoji(const char *Cmd) {
    showEmojiState(prefShowNone);
    return PM3_SUCCESS;
}

static int getCmdHint(const char *Cmd) {
    showHintsState(prefShowNone);
    return PM3_SUCCESS;
}

static int getCmdColor(const char *Cmd) {
    showColorState(prefShowNone);
    return PM3_SUCCESS;
}

static int getCmdDebug(const char *Cmd) {
    showClientDebugState(prefShowNone);
    return PM3_SUCCESS;
}

static int getCmdPlotSlider(const char *Cmd) {
    showPlotSliderState(prefShowNone);
    return PM3_SUCCESS;
}

static command_t getCommandTable[] = {
//     {"help",             getCmdHelp,          AlwaysAvailable, "This help"},
    {"emoji",            getCmdEmoji,         AlwaysAvailable, "Get emoji display preference"},
    {"hints",            getCmdHint,          AlwaysAvailable, "Get hint display preference"},
    {"color",            getCmdColor,         AlwaysAvailable, "Get color support preference"},
    //  {"defaultsavepaths", getCmdSavePaths,     AlwaysAvailable, "... to be adjusted next ... "},
    {"clientdebug",      getCmdDebug,         AlwaysAvailable, "Get client debug level preference"},
    {"plotsliders",      getCmdPlotSlider,    AlwaysAvailable, "Get plot slider display preference"},
    //  {"devicedebug",      getCmdDeviceDebug,   AlwaysAvailable, "Get device debug level"},
    {NULL, NULL, NULL, NULL}
};

static command_t setCommandTable[] = {
    {"help",             setCmdHelp,          AlwaysAvailable, "This help"},
    {"emoji",            setCmdEmoji,         AlwaysAvailable, "Set emoji display"},
    {"hints",            setCmdHint,          AlwaysAvailable, "Set hint display"},
    {"color",            setCmdColor,         AlwaysAvailable, "Set color support"},
    //  {"defaultsavepaths", setCmdSavePaths,     AlwaysAvailable, "... to be adjusted next ... "},
    {"clientdebug",      setCmdDebug,         AlwaysAvailable, "Set client debug level"},
    {"plotsliders",setCmdPlotSliders,         AlwaysAvailable, "Set plot slider display"},
    //  {"devicedebug",      setCmdDeviceDebug,   AlwaysAvailable, "Set device debug level"},
    {NULL, NULL, NULL, NULL}
};

static int setCmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(setCommandTable);
    return PM3_SUCCESS;
}

static int CmdPrefGet(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(getCommandTable, Cmd);
}

static int CmdPrefSet(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(setCommandTable, Cmd);
}

static int CmdPrefShow(const char *Cmd) {

    if (session.preferences_loaded) {
        char *fn = prefGetFilename();
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "Using "_YELLOW_("%s"), fn);
        free(fn);
    } else {
        PrintAndLogEx(ERR, "Preferences not loaded");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Current settings");
    showEmojiState(prefShowNone);
    showHintsState(prefShowNone);
    showColorState(prefShowNone);
    // showPlotPosState ();
    // showOverlayPosState ();
    //  showSavePathState(spDefault, prefShowNone);
    //  showSavePathState(spDump, prefShowNone);
    //  showSavePathState(spTrace, prefShowNone);
    showClientDebugState(prefShowNone);
    showPlotSliderState(prefShowNone);
//    showDeviceDebugState(prefShowNone);
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
    {"get",          CmdPrefGet,         AlwaysAvailable, "Get a preference"},
    {"set",          CmdPrefSet,         AlwaysAvailable, "Set a preference"},
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
