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
// Settings Functions
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Notes
//      To add a new setting
//      Add the new setting to the session_arg_t; in ui.h
//      Add the default value for the setting in the settings_load page below
//      Update the  settings_load_callback to load your setting into the stucture
//      Update the  settings_save_callback to enusre your setting gets saved when needed.
//      use the setting as needed : session.<setting name>
//      Can use (session.settings_loaded) to check if json settings file was used 
//-----------------------------------------------------------------------------

#include "settings.h"
#include "comms.h"
#include "emv/emvjson.h"
#include <string.h>

// Load all settings into memory (struct)
int settings_load (void) {

    // Set all defaults
    session.client_debug_level = OFF;
    session.window_plot_xpos = 10;
    session.window_plot_ypos = 30;
    session.window_plot_hsize = 400;
    session.window_plot_wsize = 800;
    session.window_overlay_xpos = session.window_plot_xpos;
    session.window_overlay_ypos = 20+session.window_plot_ypos + session.window_plot_hsize;
    session.window_overlay_hsize = 200;
    session.window_overlay_wsize = session.window_plot_wsize;
    session.emoji_mode = ALIAS;
    session.show_hints = false;
    session.supports_colors = false;
    
    // loadFileJson wants these, so pass in place holder values, though not used
    // in settings load;
    uint8_t dummyData = 0x00;
    size_t dummyDL = 0x00;
    
    if (loadFileJSON(settingsFilename, &dummyData, sizeof(dummyData), &dummyDL) == PM3_SUCCESS) {
        session.settings_loaded = true;
    }
    // Note, if session.settings_loaded == false then the settings_save 
    // will be called in main () to save settings as set in defaults and main() checks.

   return PM3_SUCCESS;
}

// Save all settings from memory (struct) to file
int settings_save (void) {
    // Note sure if backup has value ?
    char backupFilename[500];

    snprintf (backupFilename,sizeof(backupFilename),"%s.bak",settingsFilename);

    if (fileExists (backupFilename)) {
        if (remove (backupFilename) != 0) { 
            PrintAndLogEx (FAILED, "Error - could not delete old settings backup file \"%s\"",backupFilename);
            return PM3_ESOFT;
        }
    }

    if (fileExists (settingsFilename)) {
        if (rename (settingsFilename,backupFilename) != 0) {
            PrintAndLogEx (FAILED, "Error - could not backup settings file \"%s\" to \"%s\"",settingsFilename,backupFilename);
            return PM3_ESOFT;   
        }
    }

    uint8_t dummyData = 0x00;
    size_t dummyDL = 0x00;

    if (saveFileJSON(settingsFilename, jsfSettings, &dummyData, dummyDL) == PM3_SUCCESS)
        PrintAndLogEx (NORMAL, "settings have been saved to \"%s\"",settingsFilename);

    return PM3_SUCCESS;
}

void settings_save_callback (json_t *root) {

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

void settings_load_callback (json_t *root) {
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
