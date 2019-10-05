//-----------------------------------------------------------------------------
// Copyright (C) 2013 m h swende <martin at swende.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Some lua scripting glue to proxmark core.
//-----------------------------------------------------------------------------

#include <stdlib.h>
#include <string.h>

#include "cmdparser.h"    // command_t
#include "scripting.h"
#include "comms.h"
#include "cmdscript.h"
#include "cmdhfmf.h"
#include "pm3_binlib.h"
#include "pm3_bitlib.h"
#include "lualib.h"
#include "lauxlib.h"
#include "proxmark3.h"
#include "ui.h"
#include "fileutils.h"

static int CmdHelp(const char *Cmd);

/**
* Generate a sorted list of available commands, what it does is
* generate a file listing of the script-directory for files
* ending with .lua
*/
static int CmdScriptList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    int ret = searchAndList(LUA_SCRIPTS_SUBDIR, ".lua");
    if (ret != PM3_SUCCESS)
        return ret;
    return searchAndList(CMD_SCRIPTS_SUBDIR, ".cmd");
}

/**
 * @brief CmdScriptRun - executes a script file.
 * @param argc
 * @param argv
 * @return
 */
static int CmdScriptRun(const char *Cmd) {

    char preferredName[128] = {0};
    char arguments[256] = {0};

    int name_len = 0;
    int arg_len = 0;
    static uint8_t luascriptfile_idx = 0;
    sscanf(Cmd, "%127s%n %255[^\n\r]%n", preferredName, &name_len, arguments, &arg_len);

    char *script_path;
    if ((!str_endswith(preferredName, ".cmd")) && (searchFile(&script_path, LUA_SCRIPTS_SUBDIR, preferredName, ".lua", true) == PM3_SUCCESS)) {
        int error;
        if (luascriptfile_idx == MAX_NESTED_LUASCRIPT) {
            PrintAndLogEx(ERR, "Too many nested scripts, skipping %s\n", script_path);
            free(script_path);
            return PM3_EMALLOC;
        }
        PrintAndLogEx(SUCCESS, "Executing Lua script: %s, args '%s'\n", script_path, arguments);
        luascriptfile_idx++;

        // create new Lua state
        lua_State *lua_state;
        lua_state = luaL_newstate();

        // load Lua libraries
        luaL_openlibs(lua_state);

        //Sets the pm3 core libraries, that go a bit 'under the hood'
        set_pm3_libraries(lua_state);

        //Add the 'bin' library
        set_bin_library(lua_state);

        //Add the 'bit' library
        set_bit_library(lua_state);

        error = luaL_loadfile(lua_state, script_path);
        free(script_path);
        if (!error) {
            lua_pushstring(lua_state, arguments);
            lua_setglobal(lua_state, "args");

            //Call it with 0 arguments
            error = lua_pcall(lua_state, 0, LUA_MULTRET, 0); // once again, returns non-0 on error,
        }
        if (error) { // if non-0, then an error
            // the top of the stack should be the error string
            if (!lua_isstring(lua_state, lua_gettop(lua_state)))
                PrintAndLogEx(FAILED, "Error - but no error (?!)");

            // get the top of the stack as the error and pop it off
            const char *str = lua_tostring(lua_state, lua_gettop(lua_state));
            lua_pop(lua_state, 1);
            puts(str);
        }

        //luaL_dofile(lua_state, buf);
        // close the Lua state
        lua_close(lua_state);
        luascriptfile_idx--;
        PrintAndLogEx(SUCCESS, "\nFinished %s\n", preferredName);
        return PM3_SUCCESS;
    }
    if ((!str_endswith(preferredName, ".lua")) && (searchFile(&script_path, CMD_SCRIPTS_SUBDIR, preferredName, ".cmd", true) == PM3_SUCCESS)) {
        PrintAndLogEx(SUCCESS, "Executing Cmd script: %s, args '%s'\n", script_path, arguments);
        int ret = push_cmdscriptfile(script_path, true);
        if (ret != PM3_SUCCESS)
            PrintAndLogEx(ERR, "could not open " _YELLOW_("%s") "...", script_path);
        free(script_path);
        return ret;
    }
    // file not found, let's search again to display the error messages
    int ret = PM3_EUNDEF;
    if (!str_endswith(preferredName, ".cmd")) ret = searchFile(&script_path, LUA_SCRIPTS_SUBDIR, preferredName, ".lua", false);
    if (!str_endswith(preferredName, ".lua")) ret = searchFile(&script_path, CMD_SCRIPTS_SUBDIR, preferredName, ".cmd", false);
    return ret;
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,          AlwaysAvailable, "This help"},
    {"list",  CmdScriptList,    AlwaysAvailable, "List available scripts"},
    {"run",   CmdScriptRun,     AlwaysAvailable, "<name> -- Execute a script"},
    {NULL, NULL, NULL, NULL}
};

/**
 * Shows some basic help
 * @brief CmdHelp
 * @param Cmd
 * @return
 */
static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    PrintAndLogEx(NORMAL, "This is a feature to run Lua-scripts. You can place Lua-scripts within the luascripts/-folder. ");
    return 0;
}

/**
 * Finds a matching script-file
 * @brief CmdScript
 * @param Cmd
 * @return
 */
int CmdScript(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

