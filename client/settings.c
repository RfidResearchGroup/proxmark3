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
//      Update the  settings_save_callback to enusre your setting gets saved (not used yet)
//      Include "settingdata.h" (if needed) in the source file where you wish to use the setting
//      use the setting as needed : mySettings.<setting name>
//      Should use if (mySettings.loaded) { use settings } 
//-----------------------------------------------------------------------------

#include "settings.h"
#include "comms.h"
#include "emv/emvjson.h"
#include <string.h>

// Load all settings into memory (struct)
int settings_load (void) {

    // Set all defaults
//    mySettings.os_windows_usecolor = false;
//    mySettings.os_windows_useansicolor = false;
    session.logging_level = NORMAL;
    session.window_plot_xpos = 10;
    session.window_plot_ypos = 30;
    session.window_plot_hsize = 400;
    session.window_plot_wsize = 800;
//    mySettings.window_xpos = 10;
//    mySettings.window_ypos = 210;
//    mySettings.window_hsize = 300;
//    mySettings.window_wsize = 500;
//    mySettings.show_emoji = ALIAS;
    session.emoji_mode = ALIAS;
    session.show_hints = false;
    
    // loadFileJson wants these, so pass in place holder values, though not used
    // in settings load;
    uint8_t dummyData = 0x00;
    size_t dummyDL = 0x00;
    
    if (loadFileJSON(settingsFilename, &dummyData, sizeof(dummyData), &dummyDL) == PM3_SUCCESS) {
        session.settings_loaded = true;
    }
    else // Save default/create settings.json file
        settings_save ();

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
//    JsonSaveBoolean (root,"os.windows.useColor",mySettings.os_windows_usecolor);
//    JsonSaveBoolean (root,"os.windows.useAnsiColor",mySettings.os_windows_useansicolor);
    // Log level, convert to text
    // JsonSaveInt (root,"window.logging.level",mySettings.logging_level);
    switch (session.logging_level) {
        case NORMAL: JsonSaveStr (root,"logging.level","normal"); break;
        case SUCCESS: JsonSaveStr (root,"logging.level","success"); break;
        case INFO: JsonSaveStr (root,"logging.level","info"); break;
        case FAILED: JsonSaveStr (root,"logging.level","failed"); break;
        case WARNING: JsonSaveStr (root,"logging.level","warning"); break;
        case ERR: JsonSaveStr (root,"logging.level","err"); break;
        case DEBUG: JsonSaveStr (root,"logging.level","debug"); break;
        case INPLACE: JsonSaveStr (root,"logging.level","inplace"); break;
        case HINT: JsonSaveStr (root,"logging.level","hint"); break;
        default:
            JsonSaveStr (root,"logging.level","NORMAL");
    }

    // Plot window
    JsonSaveInt (root,"window.plot.xpos",session.window_plot_xpos);
    JsonSaveInt (root,"window.plot.ypos",session.window_plot_ypos);
    JsonSaveInt (root,"window.plot.hsize",session.window_plot_hsize);
    JsonSaveInt (root,"window.plot.wsize",session.window_plot_wsize);
//    JsonSaveInt (root,"window.xpos",mySettings.window_xpos);
//    JsonSaveInt (root,"window.ypos",mySettings.window_ypos);
//    JsonSaveInt (root,"window.hsize",mySettings.window_hsize);
//    JsonSaveInt (root,"window.wsize",mySettings.window_wsize);

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
}

void settings_load_callback (json_t *root) {
    json_error_t up_error = {0};
    bool b1;
    int i1;
    const char *s1;
    
    // Left for example of a string json read
//  if (json_unpack_ex(root, &up_error , 0, "{s:s}","version",&s1) == 0)
//      strncpy (mySettings.version,s1,sizeof (mySettings.version) - 1);
/*
    // os.windows...
    if (json_unpack_ex(root,&up_error, 0, "{s:b}","os.windows.useColor",&b1) == 0) 
        mySettings.os_windows_usecolor = b1;
    if (json_unpack_ex(root,&up_error, 0, "{s:b}","os.windows.useAnsiColor",&b1) == 0) 
        mySettings.os_windows_useansicolor = b1;
*/
    // Logging Level
//    typedef enum logLevel {NORMAL, SUCCESS, INFO, FAILED, WARNING, ERR, DEBUG, INPLACE, HINT} logLevel_t;
    if (json_unpack_ex(root,&up_error, 0, "{s:s}","logging.level",&s1) == 0) {        
        if (strncasecmp (s1,"NORMAL",7) == 0) session.logging_level = NORMAL;
        if (strncasecmp (s1,"SUCCESS",8) == 0) session.logging_level = SUCCESS;
        if (strncasecmp (s1,"INFO",4) == 0) session.logging_level = INFO;
        if (strncasecmp (s1,"FAILED",6) == 0) session.logging_level = FAILED;
        if (strncasecmp (s1,"WARNING",7) == 0) session.logging_level = WARNING;
        if (strncasecmp (s1,"ERR",3) == 0) session.logging_level = ERR;
        if (strncasecmp (s1,"DEBUG",5) == 0) session.logging_level = DEBUG;
        if (strncasecmp (s1,"INPLACE",7) == 0) session.logging_level = INPLACE;
        if (strncasecmp (s1,"HINT",7) == 0) session.logging_level = HINT;
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
/*
    // window...
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.xpos",&i1) == 0) 
        mySettings.window_xpos = i1;
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.ypos",&i1) == 0) 
        mySettings.window_ypos = i1;
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.hsize",&i1) == 0) 
        mySettings.window_hsize = i1;
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.wsize",&i1) == 0) 
        mySettings.window_wsize = i1;

*/
    // show options
    // typedef enum emojiMode {ALIAS, EMOJI, ALTTEXT, ERASE} emojiMode_t;
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","show.emoji",&s1) == 0) {
        if (strncasecmp (s1,"ALIAS",5) == 0) session.emoji_mode = ALIAS;
        if (strncasecmp (s1,"EMOJI",5) == 0) session.emoji_mode = EMOJI;
        if (strncasecmp (s1,"ALTTEXT",7) == 0) session.emoji_mode = ALTTEXT;
        if (strncasecmp (s1,"ERASE",5) == 0) session.emoji_mode = ERASE;
    }
    if (json_unpack_ex(root,&up_error, 0, "{s:b}","show.hints",&b1) == 0) 
        session.show_hints = b1;

}
