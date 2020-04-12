/*****************************************************************************
 * WARNING
 *
 * THIS CODE IS CREATED FOR EXPERIMENTATION AND EDUCATIONAL USE ONLY.
 *
 * USAGE OF THIS CODE IN OTHER WAYS MAY INFRINGE UPON THE INTELLECTUAL
 * PROPERTY OF OTHER PARTIES, SUCH AS INSIDE SECURE AND HID GLOBAL,
 * AND MAY EXPOSE YOU TO AN INFRINGEMENT ACTION FROM THOSE PARTIES.
 *
 * THIS CODE SHOULD NEVER BE USED TO INFRINGE PATENTS OR INTELLECTUAL PROPERTY RIGHTS.
 *
 *****************************************************************************
 *
 * This file is part of loclass. It is a reconstructon of the cipher engine
 * used in iClass, and RFID techology.
 *
 * The implementation is based on the work performed by
 * Flavio D. Garcia, Gerhard de Koning Gans, Roel Verdult and
 * Milosch Meriac in the paper "Dismantling IClass".
 *
 * Copyright (C) 2014 Martin Holst Swende
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, or, at your option, any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with loclass.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 ****************************************************************************/

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

static int CmdHelp(const char *Cmd);

// Load all settings into memory (struct)
int preferences_load (void) {

    // Set all defaults
    session.client_debug_level = OFF;
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
    
    if (loadFileJSON(preferencesFilename, &dummyData, sizeof(dummyData), &dummyDL) == PM3_SUCCESS) {
        session.preferences_loaded = true;
    }
    // Note, if session.settings_loaded == false then the settings_save 
    // will be called in main () to save settings as set in defaults and main() checks.

   return PM3_SUCCESS;
}

// Save all settings from memory (struct) to file
int preferences_save (void) {
    // Note sure if backup has value ?
    char backupFilename[500];

    snprintf (backupFilename,sizeof(backupFilename),"%s.bak",preferencesFilename);

    if (fileExists (backupFilename)) {
        if (remove (backupFilename) != 0) { 
            PrintAndLogEx (FAILED, "Error - could not delete old settings backup file \"%s\"",backupFilename);
            return PM3_ESOFT;
        }
    }

    if (fileExists (preferencesFilename)) {
        if (rename (preferencesFilename,backupFilename) != 0) {
            PrintAndLogEx (FAILED, "Error - could not backup settings file \"%s\" to \"%s\"",preferencesFilename,backupFilename);
            return PM3_ESOFT;   
        }
    }

    uint8_t dummyData = 0x00;
    size_t dummyDL = 0x00;

    if (saveFileJSON(preferencesFilename, jsfSettings, &dummyData, dummyDL) != PM3_SUCCESS)
        PrintAndLogEx (ERR, "Error saving preferences to \"%s\"",preferencesFilename);

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
static int usage_pref_set() {
    PrintAndLogEx(NORMAL, "Usage: pref set [(h)elp] [(e)moji ...] [(c)olor ...] [(hi)nts ...] [debug ...]");
    PrintAndLogEx(NORMAL, "                [(p)lot ...] [(o)verlay ...]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     help                                             - This help");
    PrintAndLogEx(NORMAL, "     emoji <(ali)as | (em)oji | (alt)text | (er)ase>  - Set the level of emoji support");
    PrintAndLogEx(NORMAL, "                                                          alias : show alias");
    PrintAndLogEx(NORMAL, "                                                          emoji : show emoji");
    PrintAndLogEx(NORMAL, "                                                          alttext : show alternative text");
    PrintAndLogEx(NORMAL, "                                                          erase : dont show any emoji");

    PrintAndLogEx(NORMAL, "     color <(o)ff|(a)nsi>                             - Color support level");
    PrintAndLogEx(NORMAL, "                                                          off : dont use color");
    PrintAndLogEx(NORMAL, "                                                          ansi : use ansi color (linux, mac, windows terminal)");

    PrintAndLogEx(NORMAL, "     hints <(of)f | on>                               - Show hints on/off");

    PrintAndLogEx(NORMAL, "     debug <(o)ff | (s)imple | (f)ull>                - Client debug level");
    PrintAndLogEx(NORMAL, "                                                          off : no debug output");
    PrintAndLogEx(NORMAL, "                                                          simple : information level debug");
    PrintAndLogEx(NORMAL, "                                                          full : full debug information");

    PrintAndLogEx(NORMAL, "     plot [x <val>] [y <val>] [h <val>] [w <val>]     - Position the plot window");
    PrintAndLogEx(NORMAL, "     overlay [x <val>] [y <val>] [h <val>] [w <val>]  - Position the overlay/slider window");

    return PM3_SUCCESS;
}

static int usage_pref_show() {
    PrintAndLogEx(NORMAL, "Usage: pref show [help] [emoji|color]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     help                - This help");
    PrintAndLogEx(NORMAL, "     emoji               - show current settings for emoji");
    PrintAndLogEx(NORMAL, "     color               - show current settings for color");

    return PM3_SUCCESS;
}

// Preference Processing Functions
typedef enum preferenceId {prefNONE,prefHELP,prefEMOJI,prefCOLOR,prefPLOT,prefOVERLAY,prefHINTS,prefCLIENTDEBUG} preferenceId_t;

// Enumerate text to ID
preferenceId_t prefGetID (char* cmdOpt)
{
    str_lower (cmdOpt);

    if (strncmp (cmdOpt,"hi",2) == 0) return prefHINTS;
    if (strncmp (cmdOpt,"h",1) == 0) return prefHELP;
    if (strncmp (cmdOpt,"e",1) == 0) return prefEMOJI;
    if (strncmp (cmdOpt,"c",1) == 0) return prefCOLOR;
    if (strncmp (cmdOpt,"p",1) == 0) return prefPLOT;
    if (strncmp (cmdOpt,"o",1) == 0) return prefOVERLAY;
    if (strncmp (cmdOpt,"d",1) == 0) return prefCLIENTDEBUG;

    return NONE;
}

void showEmojiState (void) {
    switch (session.emoji_mode) {
        case ALIAS: PrintAndLogEx(NORMAL, "    emoji.................. "_GREEN_("show alias"));
            break;
        case EMOJI: PrintAndLogEx(NORMAL, "    emoji.................. "_GREEN_("show emoji"));
            break;
        case ALTTEXT: PrintAndLogEx(NORMAL, "    emoji.................. "_GREEN_("show alt text"));
            break;
        case ERASE: PrintAndLogEx(NORMAL, "    emoji.................. "_GREEN_("dont show emoji"));
            break;
        default:
            PrintAndLogEx(NORMAL, "    emoji.................. "_RED_("unknown"));
    }
}

void showColorState (void) {
/*
    switch (session.supports_colors) {
        case false: PrintAndLogEx(NORMAL, "Color : "_GREEN_("off"));
            break;
        case true: PrintAndLogEx(NORMAL, "Color : "_GREEN_("ansi"));
            break;
        default:
            PrintAndLogEx(NORMAL, "Color support set to : "_RED_("unknown"));
    }
*/
    // this will change to 1 of a set from bool
    if (session.supports_colors)
        PrintAndLogEx(NORMAL, "    color.................. "_GREEN_("ansi"));
    else
        PrintAndLogEx(NORMAL, "    color.................. "_GREEN_("off"));
}

void showClientDebugState (void) {
    switch (session.client_debug_level) {
        case OFF: PrintAndLogEx (NORMAL,"    client debug........... "_GREEN_("off"));
                break;
        case SIMPLE: PrintAndLogEx (NORMAL,"    client debug........... "_GREEN_("simple"));
                break;
        case FULL: PrintAndLogEx (NORMAL,"    client debug........... "_GREEN_("full"));
                break;
        default:
            PrintAndLogEx(NORMAL, "    client debug........... "_RED_("unknown"));
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

void showHintsState (void){
    if (session.show_hints)
        PrintAndLogEx (NORMAL,"    Hints.................. "_GREEN_("on"));
    else
        PrintAndLogEx (NORMAL,"    Hints.................. "_GREEN_("off"));
}

static int CmdPrefShow (const char *Cmd) {
    uint8_t cmdp = 0;
    preferenceId_t CmdPref;
    bool errors = false;
    char strOpt[50];
    
    PrintAndLogEx(NORMAL,"");
    PrintAndLogEx(NORMAL,_BLUE_("Preferences"));
    
    if (!session. preferences_loaded) {
        PrintAndLogEx (ERR,"Preferneces not loaded");
        return PM3_ESOFT;
    }

    if (param_getchar(Cmd, cmdp) == 0x00) { // No options - Show all
        showEmojiState ();
        showColorState ();
        showPlotPosState ();
        showOverlayPosState ();
        showClientDebugState();
        showHintsState ();
    }
    else {
        
        while ((param_getchar(Cmd, cmdp) != 0x00) && !errors) {

            if (param_getstr(Cmd, cmdp, strOpt, sizeof(strOpt)) != 0) {
                CmdPref = prefGetID(strOpt);
            }
            else 
                CmdPref = prefNONE;

            switch (CmdPref) {
                case prefHELP:
                    return usage_pref_show();
                case prefEMOJI: 
                    showEmojiState ();
                    break;
                case prefCOLOR: // color
                    showColorState ();
                    break;
                case prefPLOT: 
                    showPlotPosState ();
                    break;
                case prefOVERLAY: 
                    showOverlayPosState ();
                    break;
                case prefCLIENTDEBUG:
                    showClientDebugState();
                    break;
                case prefHINTS:
                    showHintsState();
                    break;
                case prefNONE:
                    PrintAndLogEx (ERR,"Invalid option supplied");
                    errors = true;
                    break;
                    // errors
            }
            cmdp ++;
        }
    }
    PrintAndLogEx(NORMAL,"");
    return PM3_SUCCESS;
}

static int CmdPrefSet (const char *Cmd)
{
    uint8_t cmdp = 0;
    preferenceId_t CmdPref;
    bool errors = false;
    // char charOpt;
    char strOpt[50];
    int x,y,h,w;

    if (param_getchar(Cmd, cmdp) == 0x00) 
        return usage_pref_set();

    while ((param_getchar(Cmd, cmdp) != 0x00) && !errors) {

        if (param_getstr(Cmd, cmdp, strOpt, sizeof(strOpt)) != 0) {
            CmdPref = prefGetID(strOpt);
        }
        else
            CmdPref = prefNONE;
        
        switch (CmdPref) {
            case prefHELP:
                return usage_pref_set();
            case prefEMOJI: 
                showEmojiState ();
                cmdp++;
                if (param_getstr(Cmd, cmdp, strOpt, sizeof(strOpt)) != 0) {
                    str_lower(strOpt);
                    if (strncmp (strOpt,"ali",3) == 0) { session.emoji_mode = ALIAS; showEmojiState (); break; }
                    if (strncmp (strOpt,"em",2) == 0)  { session.emoji_mode = EMOJI; showEmojiState (); break; }
                    if (strncmp (strOpt,"alt",3) == 0) { session.emoji_mode = ALTTEXT; showEmojiState (); break; }
                    if (strncmp (strOpt,"er",2) == 0)  { session.emoji_mode = ERASE; showEmojiState (); break; }
                    // if we get this far, then an error in the mode
                    PrintAndLogEx(ERR,"Invalid emoji option");
                    errors = true;
                }
                else
                    errors = true;
                break;
            case prefCOLOR: // color
                showColorState ();
                cmdp++;
                if (param_getstr(Cmd, cmdp, strOpt, sizeof(strOpt)) != 0) {
                    str_lower(strOpt);
                    if (strncmp(strOpt,"a",1) == 0) { session.supports_colors = true; showColorState (); break; }
                    if (strncmp(strOpt,"o",1) == 0) { session.supports_colors = false; showColorState (); break; }
                    // if we get this far, then an error in the mode
                    PrintAndLogEx(ERR,"Invalid color option");
                    errors = true;
                }
                else    
                    errors = true;
                break;
            case prefPLOT: 
                showPlotPosState ();
                cmdp++;
                x = y = h = w = -99999; // Some invalid value
                for (int i = 0; i < 4; i++) { // upto 4 values X, Y, H, WARNING
                    if (param_getchar(Cmd, cmdp) != 0){
                        switch (tolower(param_getchar(Cmd, cmdp++))) {
                            case 'x': x = param_get32ex(Cmd,cmdp++,-99999,10); break; 
                            case 'y': y = param_get32ex(Cmd,cmdp++,-99999,10); break; 
                            case 'h': h = param_get32ex(Cmd,cmdp++,-99999,10); break; 
                            case 'w': w = param_get32ex(Cmd,cmdp++,-99999,10); break; 
                            default:
                                errors = true;
                        }
                    }
                }
                if (x != -99999) session.window_plot_xpos = x; 
                if (y != -99999) session.window_plot_ypos = y; 
                if (h != -99999) session.window_plot_hsize = h; 
                if (w != -99999) session.window_plot_wsize = w; 
                // Need to work out how to change live....
                // calling data plot seems to work
                
                showPlotPosState ();
                break;
            case prefOVERLAY: 
                showOverlayPosState ();
                cmdp++;
                x = y = h = w = -99999; // Some invalid value
                for (int i = 0; i < 4; i++) { // upto 4 values X, Y, H, WARNING
                    if (param_getchar(Cmd, cmdp) != 0){
                        switch (tolower(param_getchar(Cmd, cmdp++))) {
                            case 'x': x = param_get32ex(Cmd,cmdp++,-99999,10); break; 
                            case 'y': y = param_get32ex(Cmd,cmdp++,-99999,10); break; 
                            case 'h': h = param_get32ex(Cmd,cmdp++,-99999,10); break; 
                            case 'w': w = param_get32ex(Cmd,cmdp++,-99999,10); break; 
                            default:
                                errors = true;
                        }
                    }
                }
                if (x != -99999) session.window_overlay_xpos = x; 
                if (y != -99999) session.window_overlay_ypos = y; 
                if (h != -99999) session.window_overlay_hsize = h; 
                if (w != -99999) session.window_overlay_wsize = w; 
                showOverlayPosState ();
                // Need to work out how to change live....
                break;
            case prefCLIENTDEBUG:
                showClientDebugState();
                cmdp++;
                if (param_getstr(Cmd, cmdp, strOpt, sizeof(strOpt)) != 0) {
                    str_lower(strOpt);
                    if (strncmp(strOpt,"o",1) == 0) { session.client_debug_level = OFF; g_debugMode = OFF; showClientDebugState(); break; }
                    if (strncmp(strOpt,"s",1) == 0) { session.client_debug_level = SIMPLE; g_debugMode = SIMPLE; showClientDebugState(); break; }
                    if (strncmp(strOpt,"f",1) == 0) { session.client_debug_level = FULL; g_debugMode = FULL; showClientDebugState(); break; }
                    // if we get this far, then an error in the mode
                    PrintAndLogEx(ERR,"Invalid client debug option");
                    errors = true;
                }
                else    
                    errors = true;
                break;
            case prefHINTS:
                showHintsState ();
                cmdp++;
                if (param_getstr(Cmd, cmdp, strOpt, sizeof(strOpt)) != 0) {
                    str_lower(strOpt);
                    if (strncmp(strOpt,"on",2) == 0) { session.show_hints = true; showHintsState (); break; }
                    if (strncmp(strOpt,"of",2) == 0) { session.show_hints = false; showHintsState (); break; }
                    // if we get this far, then an error in the mode
                    PrintAndLogEx(ERR,"Invalid hint option");
                    errors = true;
                }
                else    
                    errors = true;
                break;
            case prefNONE:
                PrintAndLogEx (ERR,"Invalid option supplied");
                errors = true;
                break;
        }
        cmdp ++;
    }
    preferences_save();
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",         CmdHelp,            AlwaysAvailable, "This help"},
    {"set",          CmdPrefSet,         AlwaysAvailable, "Set a preference"},
    {"show",         CmdPrefShow,        AlwaysAvailable, "Show (a preference)"},
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