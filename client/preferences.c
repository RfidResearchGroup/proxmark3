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
#include <unistd.h>

//#include "proxgui.h"
//extern void SetWindowsPosition (void);
static int CmdHelp(const char *Cmd);
static int setCmdHelp(const char *Cmd);

// Load all settings into memory (struct)
static char* prefGetFilename (void) {
    /*
    static char Buffer[FILENAME_MAX+sizeof(preferencesFilename)+2] = {0};
    char PATH[FILENAME_MAX] = {0};
    
    getcwd(PATH, sizeof(PATH));
#ifdef _WIN32
    snprintf (Buffer,sizeof(Buffer)-1,"%s\\%s",PATH,preferencesFilename);
#else
    snprintf (Buffer,sizeof(Buffer)-1,"%s/%s",PATH,preferencesFilename);
#endif    

    return Buffer;
    */
    return preferencesFilename;
}

int preferences_load (void) {

    // Set all defaults
    session.client_debug_level = OFF;
    session.window_changed = false;
    session.window_plot_xpos = 10;
    session.window_plot_ypos = 30;
    session.window_plot_hsize = 400;
    session.window_plot_wsize = 800;
    session.window_overlay_xpos = session.window_plot_xpos;
    session.window_overlay_ypos = 60+session.window_plot_ypos + session.window_plot_hsize;
    session.window_overlay_hsize = 200;
    session.window_overlay_wsize = session.window_plot_wsize;
    session.emoji_mode = ALIAS;
    session.show_hints = false;
    session.supports_colors = false;
    
    
    // loadFileJson wants these, so pass in place holder values, though not used
    // in settings load;
    uint8_t dummyData = 0x00;
    size_t dummyDL = 0x00;
    
    if (loadFileJSON(prefGetFilename(), &dummyData, sizeof(dummyData), &dummyDL) == PM3_SUCCESS) {
        session.preferences_loaded = true;
    }
    // Note, if session.settings_loaded == false then the settings_save 
    // will be called in main () to save settings as set in defaults and main() checks.

   return PM3_SUCCESS;
}

// Save all settings from memory (struct) to file
int preferences_save (void) {
    // Note sure if backup has value ?

    char backupFilename[FILENAME_MAX+sizeof(preferencesFilename)+10] = {0};

    PrintAndLogEx(INFO,"Saving preferences ...");
    snprintf (backupFilename,sizeof(backupFilename)-1,"%s.bak",prefGetFilename());

    if (fileExists (backupFilename)) {
        if (remove (backupFilename) != 0) { 
            PrintAndLogEx (FAILED, "Error - could not delete old settings backup file \"%s\"",backupFilename);
            return PM3_ESOFT;
        }
    }

    if (fileExists (prefGetFilename())) {
        if (rename (prefGetFilename(),backupFilename) != 0) {
            PrintAndLogEx (FAILED, "Error - could not backup settings file \"%s\" to \"%s\"",prefGetFilename(),backupFilename);
            return PM3_ESOFT;   
        }
    }

    uint8_t dummyData = 0x00;
    size_t dummyDL = 0x00;

    if (saveFileJSON(prefGetFilename(), jsfSettings, &dummyData, dummyDL) != PM3_SUCCESS)
        PrintAndLogEx (ERR, "Error saving preferences to \"%s\"",prefGetFilename());

    return PM3_SUCCESS;
}

void preferences_save_callback (json_t *root) {

    JsonSaveStr (root,"FileType","settings");

    // Log level, convert to text
    switch (session.client_debug_level) {
        case OFF: JsonSaveStr (root,"client.debug.level","off"); break;
        case SIMPLE: JsonSaveStr (root,"client.debug.level","simple"); break;
        case FULL: JsonSaveStr (root,"client.debug.level","full"); break;
        default:
            JsonSaveStr (root,"logging.level","NORMAL");
    }

    // Plot window
    JsonSaveInt (root,"window.plot.xpos",session.window_plot_xpos);
    JsonSaveInt (root,"window.plot.ypos",session.window_plot_ypos);
    JsonSaveInt (root,"window.plot.hsize",session.window_plot_hsize);
    JsonSaveInt (root,"window.plot.wsize",session.window_plot_wsize);

    // Overlay/Slider window
    JsonSaveInt (root,"window.overlay.xpos",session.window_overlay_xpos);
    JsonSaveInt (root,"window.overlay.ypos",session.window_overlay_ypos);
    JsonSaveInt (root,"window.overlay.hsize",session.window_overlay_hsize);
    JsonSaveInt (root,"window.overlay.wsize",session.window_overlay_wsize);

    // Emoji
    switch (session.emoji_mode) {
        case ALIAS: JsonSaveStr (root,"show.emoji","alias"); break;
        case EMOJI: JsonSaveStr (root,"show.emoji","emoji"); break;
        case ALTTEXT: JsonSaveStr (root,"show.emoji","alttext"); break;
        case ERASE: JsonSaveStr (root,"show.emoji","erase"); break;
        default:
            JsonSaveStr (root,"show.emoji","ALIAS");
    }

    JsonSaveBoolean (root,"show.hints",session.show_hints);

    JsonSaveBoolean (root,"os.supports.colors",session.supports_colors);
}

void preferences_load_callback (json_t *root) {
    json_error_t up_error = {0};
    bool b1;
    int i1;
    const char *s1;
    char tempStr [500]; // to use str_lower() since json unpack uses const char *

    // Logging Level
    if (json_unpack_ex(root,&up_error, 0, "{s:s}","client.debug.level",&s1) == 0) {
        strncpy (tempStr,s1,sizeof(tempStr)-1);
        str_lower (tempStr);
        if (strncmp (tempStr,"off",3) == 0) session.client_debug_level = OFF;
        if (strncmp (tempStr,"simple",6) == 0) session.client_debug_level = SIMPLE;
        if (strncmp (tempStr,"full",4) == 0) session.client_debug_level = FULL;
    }

    // window plot
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.plot.xpos",&i1) == 0) 
        session.window_plot_xpos = i1;
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.plot.ypos",&i1) == 0) 
        session.window_plot_ypos = i1;
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.plot.hsize",&i1) == 0) 
        session.window_plot_hsize = i1;
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.plot.wsize",&i1) == 0) 
        session.window_plot_wsize = i1;

    // overlay/slider plot
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.overlay.xpos",&i1) == 0) 
        session.window_overlay_xpos = i1;
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.overlay.ypos",&i1) == 0) 
        session.window_overlay_ypos = i1;
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.overlay.hsize",&i1) == 0) 
        session.window_overlay_hsize = i1;
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.overlay.wsize",&i1) == 0) 
        session.window_overlay_wsize = i1;

    // show options
    if (json_unpack_ex(root,&up_error, 0, "{s:s}","show.emoji",&s1) == 0) {
        strncpy (tempStr,s1,sizeof(tempStr)-1);
        str_lower (tempStr);
        if (strncmp (tempStr,"alias",5) == 0) session.emoji_mode = ALIAS;
        if (strncmp (tempStr,"emoji",5) == 0) session.emoji_mode = EMOJI;
        if (strncmp (tempStr,"alttext",7) == 0) session.emoji_mode = ALTTEXT;
        if (strncmp (tempStr,"erase",5) == 0) session.emoji_mode = ERASE;
    }

    if (json_unpack_ex(root,&up_error, 0, "{s:b}","show.hints",&b1) == 0) 
        session.show_hints = b1;

    if (json_unpack_ex(root,&up_error, 0, "{s:b}","os.supports.colors",&b1) == 0) 
        session.supports_colors = b1;

}

// Help Functions

static int usage_set_emoji() {
    PrintAndLogEx(NORMAL, "Usage: pref set emoji <alias | emoji | alttext | erase>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     "_GREEN_("help")"        - This help");
    PrintAndLogEx(NORMAL, "     "_GREEN_("alias")"       - Show alias for emoji");
    PrintAndLogEx(NORMAL, "     "_GREEN_("emoji")"       - Show amoji");
    PrintAndLogEx(NORMAL, "     "_GREEN_("alttext")"     - Show alt text for emoji");
    PrintAndLogEx(NORMAL, "     "_GREEN_("erase")"       - Dont show emoji or text");

    return PM3_SUCCESS;
}

static int usage_set_color() {
    PrintAndLogEx(NORMAL, "Usage: pref set color <off | ansi>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     "_GREEN_("help")"        - This help");
    PrintAndLogEx(NORMAL, "     "_GREEN_("off")"         - Dont use colors");
    PrintAndLogEx(NORMAL, "     "_GREEN_("ansi")"        - Use ANSI colors");

    return PM3_SUCCESS;
}

static int usage_set_debug() {
    PrintAndLogEx(NORMAL, "Usage: pref set debug <off | simple | full>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     "_GREEN_("help")"        - This help");
    PrintAndLogEx(NORMAL, "     "_GREEN_("off")"         - no debug messages");
    PrintAndLogEx(NORMAL, "     "_GREEN_("simple")"      - simple debug messages");
    PrintAndLogEx(NORMAL, "     "_GREEN_("full")"        - full debug messages");

    return PM3_SUCCESS;
}
static int usage_set_hints() {
    PrintAndLogEx(NORMAL, "Usage: pref set hints <off | on>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     "_GREEN_("help")"        - This help");
    PrintAndLogEx(NORMAL, "     "_GREEN_("off")"         - Dont display hints");
    PrintAndLogEx(NORMAL, "     "_GREEN_("on")"          - Display hints");

    return PM3_SUCCESS;
}

// Preference Processing Functions
typedef enum preferenceId {prefNONE,prefHELP,prefEMOJI,prefCOLOR,prefPLOT,prefOVERLAY,prefHINTS,prefCLIENTDEBUG} preferenceId_t;
typedef enum prefShowOpt  {prefShowNone,prefShowOLD,prefShowNEW} prefShowOpt_t;

const char *prefShowMsg (prefShowOpt_t Opt)
{
    switch (Opt) {
        case prefShowOLD:  return _YELLOW_("[old]"); //strncpy(Msg,"Before ",sizeof(Msg)-1); break;
        case prefShowNEW: return _GREEN_("[new]"); // strncpy(Msg,"After  ",sizeof(Msg)-1); break;
        case prefShowNone: return "";
    }
    
    return "";
}

void showEmojiState (prefShowOpt_t Opt) {

    switch (session.emoji_mode) {
        case ALIAS: PrintAndLogEx(NORMAL, "   %s emoji.................. "_GREEN_("alias"),prefShowMsg (Opt));
            break;
        case EMOJI: PrintAndLogEx(NORMAL, "   %s emoji.................. "_GREEN_("emoji"),prefShowMsg (Opt));
            break;
        case ALTTEXT: PrintAndLogEx(NORMAL, "   %s emoji.................. "_GREEN_("alttext"),prefShowMsg (Opt));
            break;
        case ERASE: PrintAndLogEx(NORMAL, "   %s emoji.................. "_GREEN_("erase"),prefShowMsg (Opt));
            break;
        default:
            PrintAndLogEx(NORMAL, "   %s emoji.................. "_RED_("unknown"),prefShowMsg(Opt));
    }
}

void showColorState (prefShowOpt_t Opt) {

    if (session.supports_colors)
        PrintAndLogEx(NORMAL, "   %s color.................. "_GREEN_("ansi"),prefShowMsg(Opt));
    else
        PrintAndLogEx(NORMAL, "   %s color.................. "_GREEN_("off"),prefShowMsg(Opt));
}

void showClientDebugState (prefShowOpt_t Opt) {
    
    switch (session.client_debug_level) {
        case OFF: PrintAndLogEx (NORMAL,"   %s client debug........... "_GREEN_("off"),prefShowMsg(Opt));
                break;
        case SIMPLE: PrintAndLogEx (NORMAL,"   %s client debug........... "_GREEN_("simple"),prefShowMsg(Opt));
                break;
        case FULL: PrintAndLogEx (NORMAL,"   %s client debug........... "_GREEN_("full"),prefShowMsg(Opt));
                break;
        default:
            PrintAndLogEx(NORMAL, "   %s client debug........... "_RED_("unknown"),prefShowMsg(Opt));
    }
}

void showPlotPosState (void){
    PrintAndLogEx (NORMAL,"    Plot window............ X "_GREEN_("%4d")" Y "_GREEN_("%4d")" H "_GREEN_("%4d")" W "_GREEN_("%4d"),
        session.window_plot_xpos,session.window_plot_ypos,session.window_plot_hsize,session.window_plot_wsize);
}

void showOverlayPosState (void){
    PrintAndLogEx (NORMAL,"    Slider/Overlay window.. X "_GREEN_("%4d")" Y "_GREEN_("%4d")" H "_GREEN_("%4d")" W "_GREEN_("%4d"),
        session.window_overlay_xpos,session.window_overlay_ypos,session.window_overlay_hsize,session.window_overlay_wsize);
}

void showHintsState (prefShowOpt_t Opt){
    if (session.show_hints)
        PrintAndLogEx (NORMAL,"   %s Hints.................. "_GREEN_("on"),prefShowMsg(Opt));
    else
        PrintAndLogEx (NORMAL,"   %s Hints.................. "_GREEN_("off"),prefShowMsg(Opt));
}

static int setCmdEmoji (const char *Cmd) {
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

            if (strncmp (strOpt,"help",4) == 0)
                return usage_set_emoji();
            if (strncmp (strOpt,"alias",5) == 0) {
                validValue = true;
                newValue = ALIAS;
            }
            if (strncmp (strOpt,"emoji",5) == 0) {
                validValue = true;
                newValue = EMOJI;
            }
            if (strncmp (strOpt,"alttext",7) == 0) {
                validValue = true;
                newValue = ALTTEXT;
            }
            if (strncmp (strOpt,"erase",5) == 0) {
                validValue = true;
                newValue = ERASE;
            }

            if (validValue) {
                if (session.emoji_mode != newValue) {// changed 
                    showEmojiState (prefShowOLD);
                    session.emoji_mode = newValue;
                    showEmojiState (prefShowNEW);
                    preferences_save ();
                } else {
                    PrintAndLogEx(INFO,"nothing changed");
                    showEmojiState (prefShowNone);
                }
            } else {
                PrintAndLogEx(ERR,"invalid option");
                return usage_set_emoji();
            }
        }
    }

    return PM3_SUCCESS;
}

static int setCmdColor (const char *Cmd)
{
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

            if (strncmp (strOpt,"help",4) == 0) 
                return usage_set_color();
            if (strncmp (strOpt,"off",3) == 0) {
                validValue = true;
                newValue = false; 
            }
            if (strncmp (strOpt,"ansi",4) == 0) {
                validValue = true;
                newValue = true;
            }

            if (validValue) {
                if (session.supports_colors != newValue) {// changed 
                    showColorState (prefShowOLD);
                    session.supports_colors = newValue;
                    showColorState (prefShowNEW);
                    preferences_save ();
                } else {
                    PrintAndLogEx(INFO,"nothing changed");
                    showColorState (prefShowNone);
                }
            } else {
                PrintAndLogEx(ERR,"invalid option");
                return usage_set_color();
            }
        }
    }

    return PM3_SUCCESS;
}

static int setCmdDebug (const char *Cmd)
{
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

            if (strncmp (strOpt,"help",4) == 0) 
                return usage_set_debug();
            if (strncmp (strOpt,"off",3) == 0) {
                validValue = true;
                newValue = OFF;
            }                
            if (strncmp (strOpt,"simple",6) == 0) {
                validValue = true;
                newValue = SIMPLE;
            }
            if (strncmp (strOpt,"full",4) == 0) {
                validValue = true;
                newValue = FULL;
            }

            if (validValue) {
                if (session.client_debug_level != newValue) {// changed 
                    showClientDebugState (prefShowOLD);
                    session.client_debug_level = newValue;
                    g_debugMode = newValue;
                    showClientDebugState (prefShowNEW);
                    preferences_save ();
                } else {
                    PrintAndLogEx(INFO,"nothing changed");
                    showClientDebugState (prefShowNone);
                }
            } else {
                PrintAndLogEx(ERR,"invalid option");
                return usage_set_debug();
            }
        }
    }

    return PM3_SUCCESS;
}

static int setCmdHint (const char *Cmd)
{
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

            if (strncmp (strOpt,"help",4) == 0) 
                return usage_set_hints();
            if (strncmp (strOpt,"off",3) == 0) {
                validValue = true;
                newValue = false; 
            }
            if (strncmp (strOpt,"on",2) == 0) {
                validValue = true;
                newValue = true;
            }

            if (validValue) {
                if (session.show_hints != newValue) {// changed 
                    showHintsState (prefShowOLD);
                    session.show_hints = newValue;
                    showHintsState (prefShowNEW);
                    preferences_save ();
                } else {
                    PrintAndLogEx(INFO,"nothing changed");
                    showHintsState (prefShowNone);
                }
            } else {
                PrintAndLogEx(ERR,"invalid option");
                return usage_set_hints();
            }
        }
    }

    return PM3_SUCCESS;
}

static command_t setCommandTable[] = {
    {"help",         setCmdHelp,         AlwaysAvailable, "This help"},
    {"emoji",        setCmdEmoji,        AlwaysAvailable, "Set emoji display"},
    {"color",        setCmdColor,        AlwaysAvailable, "Set color support"},
    {"debug",        setCmdDebug,        AlwaysAvailable, "Set client debug level"},
    {"hints",        setCmdHint,         AlwaysAvailable, "Set hint display"},
    {NULL, NULL, NULL, NULL}
};


static int setCmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(setCommandTable);

    return PM3_SUCCESS;
}

int CmdPrefSet (const char *Cmd)
{
    clearCommandBuffer();

    return CmdsParse(setCommandTable, Cmd);   
}

static int CmdPrefShow (const char *Cmd) {

    PrintAndLogEx(NORMAL,"");
    PrintAndLogEx(NORMAL,_BLUE_("Preferences"));
    
    if (!session. preferences_loaded) {
        PrintAndLogEx (ERR,"Preferneces not loaded");
        return PM3_ESOFT;
    }

    showEmojiState (prefShowNone);
    showColorState (prefShowNone);
   // showPlotPosState ();
   // showOverlayPosState ();
    showClientDebugState(prefShowNone);
    showHintsState (prefShowNone);

    PrintAndLogEx(NORMAL,"");

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
    {"set",          CmdPrefSet,         AlwaysAvailable, "Set a preference"},
    {"show",         CmdPrefShow,        AlwaysAvailable, "Show preferences"},
//    {"save",         CmdPrefSave, AlwaysAvailable, "Save preferences now"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);

    return PM3_SUCCESS;
}

int CmdPreferences (const char *Cmd)
{
    clearCommandBuffer();

    return CmdsParse(CommandTable, Cmd);   
}