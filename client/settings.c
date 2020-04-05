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

#include "settings.h"
#include "comms.h"
#include "emv/emvjson.h"

// settings_t mySettings; 

// Load all settings into memory (struct)
void settingsLoad (void)
{
    // loadFileJson wants these, so pass in place holder values, though not used
    // in settings load;
    uint8_t dummyData = 0x00;
    size_t dummyDL = 0x00;
    
    // clear all settings
    memset (&mySettings,0x00,sizeof(mySettings));
    
    if (loadFileJSON(settingsFilename, &dummyData, sizeof(dummyData), &dummyDL) == PM3_SUCCESS) {
        printf ("==> Settings Loaded\n");
        mySettings.loaded = true;
    }
        
    
    // Test results
    /*
        bool os_windows_usecolor;
        bool os_windows_useansicolor;
        int  window_xpos;
        int  window_ypos;
        int  window_hsize;
        int  window_wsize;
    */
    printf (" Settings Version : [%s]\n",mySettings.version);
    printf (" os_windows_usecolor (bool) : [%d]\n",mySettings.os_windows_usecolor);
    printf (" os_windows_useAnsicolor (bool) : [%d]\n",mySettings.os_windows_useansicolor);
    printf (" window_xpos (int)  : [%d]\n",mySettings.window_xpos);
    printf (" window_ypos (int)  : [%d]\n",mySettings.window_ypos);
    printf (" window_hsize (int) : [%d]\n",mySettings.window_hsize);
    printf (" window_wsize (int) : [%d]\n",mySettings.window_wsize);

}

// Save all settings from memory (struct) to file
int settingsSave (void)
{
    // Note sure if backup has value ?
    char backupFilename[500];
    // if (mySettings.loaded)

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
    
    // int saveFileJSON(const char *preferredName, JSONFileType ftype, uint8_t *data, size_t datalen);

    if (saveFileJSON(settingsFilename, jsfSettings, &dummyData, dummyDL) == PM3_SUCCESS)
        PrintAndLogEx (NORMAL, "settings have been saved to \"%s\"",settingsFilename);
    
    return PM3_SUCCESS;
}

void JsonSaveSettingsCallback (json_t *root)
{
      //      extern settings_t mySettings;
        
            printf ("==> Save Settings\n");
            //JsonSaveStr(root, "FileType", "settings");
            //JsonSaveStr (root,"Test1.Test2","test settings");
            /*
             "version": "1.0 Nov 2019",
    "os.windows.usecolor": true,
    "os.windows.useAnsiColor": true,
    "window.xpos": 10,
    "window.ypos": 10,
    "window.hsize": 300,
    "window.wsize": 600
            */
            JsonSaveStr     (root,"FileType","settings");
            JsonSaveStr     (root,"version","1.0 Nov 2019");//mySettings.version);
            JsonSaveBoolean (root,"os.windows.useColor",mySettings.os_windows_usecolor);
            JsonSaveBoolean (root,"os.windows.useAnsiColor",mySettings.os_windows_useansicolor);
            JsonSaveInt     (root,"window.xpos",mySettings.window_xpos);
            JsonSaveInt     (root,"window.ypos",mySettings.window_ypos);
            JsonSaveInt     (root,"window.hsize",mySettings.window_hsize);
            JsonSaveInt     (root,"window.wsize",mySettings.window_wsize);    
}

void JsonLoadSettingsCallback (json_t *root)
{
//     extern settings_t mySettings;
    json_error_t up_error = {0};
    int b1;
    int i1;
    const char *s1;

    if (json_unpack_ex(root, &up_error , 0, "{s:s}","version",&s1) == 0)
        strncpy (mySettings.version,s1,sizeof (mySettings.version) - 1);
    else
        strncpy (mySettings.version,"unknown",sizeof (mySettings.version) - 1);

    // os.windows...
    if (json_unpack_ex(root,&up_error, 0, "{s:b}","os.windows.useColor",&b1) == 0) 
        mySettings.os_windows_usecolor = b1;
    else // default 
        mySettings.os_windows_useansicolor = false;

    if (json_unpack_ex(root,&up_error, 0, "{s:b}","os.windows.useAnsiColor",&b1) == 0) 
        mySettings.os_windows_useansicolor = b1;
    else // default 
        mySettings.os_windows_useansicolor = false;

    // window...
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.xpos",&i1) == 0) 
        mySettings.window_xpos = i1;
    else // default 
        mySettings.window_xpos = 0;
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.ypos",&i1) == 0) 
        mySettings.window_ypos = i1;
    else // default 
        mySettings.window_ypos = 0;
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.hsize",&i1) == 0) 
        mySettings.window_hsize = i1;
    else // default 
        mySettings.window_hsize = 0;
    if (json_unpack_ex(root,&up_error, 0, "{s:i}","window.wsize",&i1) == 0) 
        mySettings.window_wsize = i1;
    else // default 
        mySettings.window_wsize = 0;

}
