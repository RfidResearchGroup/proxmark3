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
    return searchAndList(LUA_SCRIPTS_DIRECTORY, ".lua");
}

/**
 * @brief CmdScriptRun - executes a script file.
 * @param argc
 * @param argv
 * @return
 */
static int CmdScriptRun(const char *Cmd) {
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

    char script_name[128] = {0};
    char arguments[256] = {0};

    int name_len = 0;
    int arg_len = 0;
    sscanf(Cmd, "%127s%n %255[^\n\r]%n", script_name, &name_len, arguments, &arg_len);

    char *script_path = searchFile(LUA_SCRIPTS_DIRECTORY, ".lua", script_name);
    if (script_path == NULL) {
        PrintAndLogEx(FAILED, "Error - can't find script %s", script_name);
        return PM3_EFILE;
    }
    int error;
    PrintAndLogEx(SUCCESS, "Executing: %s, args '%s'\n", script_path, arguments);
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
    PrintAndLogEx(SUCCESS, "\nFinished\n");
    return 0;
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

