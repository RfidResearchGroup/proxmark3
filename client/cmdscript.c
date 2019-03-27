//-----------------------------------------------------------------------------
// Copyright (C) 2013 m h swende <martin at swende.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Some lua scripting glue to proxmark core.
//-----------------------------------------------------------------------------

// this define is needed for scandir/alphasort to work
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>

#include "proxmark3.h"
#include "scripting.h"
#include "ui.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmdmain.h"
#include "comms.h"
#include "cmdscript.h"
#include "cmdhfmf.h"
#include "pm3_binlib.h"
#include "pm3_bitlib.h"
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#ifdef _WIN32
#include "scandir.h"
#endif

static int CmdHelp(const char *Cmd);

int str_ends_with(const char *str, const char *suffix) {

    if (str == NULL || suffix == NULL)
        return 0;

    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);

    if (suffix_len > str_len)
        return 0;

    return 0 == strncmp(str + str_len - suffix_len, suffix, suffix_len);
}

/**
 * Utility to check the ending of a string (used to check file suffix)
 */
bool endsWith(char *base, char *str) {
    int blen = strlen(base);
    int slen = strlen(str);
    return (blen >= slen) && (0 == strcmp(base + blen - slen, str));
}

/**
* Generate a sorted list of available commands, what it does is
* generate a file listing of the script-directory for files
* ending with .lua
*/
int CmdScriptList(const char *Cmd) {

    char const *exedir = get_my_executable_directory();
    if (exedir == NULL)
        return 0;
    char script_directory_path[strlen(exedir) + strlen(LUA_SCRIPTS_DIRECTORY) + 1];
    strcpy(script_directory_path, exedir);
    strcpy(script_directory_path, get_my_executable_directory());
    strcat(script_directory_path, LUA_SCRIPTS_DIRECTORY);

    struct dirent **namelist;
    int n;

    n = scandir(script_directory_path, &namelist, NULL, alphasort);
    if (n == -1) {
        PrintAndLogEx(FAILED, "Couldn't open the scripts-directory");
        return 1;
    }

    for (uint16_t i = 0; i < n; i++) {
        if (str_ends_with(namelist[i]->d_name, ".lua"))
            PrintAndLogEx(NORMAL, "%-21s", namelist[i]->d_name);
        free(namelist[i]);
    }
    free(namelist);
    return 0;
}

/**
 * @brief CmdScriptRun - executes a script file.
 * @param argc
 * @param argv
 * @return
 */
int CmdScriptRun(const char *Cmd) {
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

    char *suffix = "";
    if (!endsWith(script_name, ".lua")) {
        suffix = ".lua";
    }

    char script_path[strlen(get_my_executable_directory()) + strlen(LUA_SCRIPTS_DIRECTORY) + strlen(script_name) + strlen(suffix) + 1];
    strcpy(script_path, get_my_executable_directory());
    strcat(script_path, LUA_SCRIPTS_DIRECTORY);
    strcat(script_path, script_name);
    strcat(script_path, suffix);

    PrintAndLogEx(SUCCESS, "Executing: %s%s, args '%s'\n", script_name, suffix, arguments);

    // run the Lua script
    int error = luaL_loadfile(lua_state, script_path);
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
    {"help",  CmdHelp,          1, "This help"},
    {"list",  CmdScriptList,    1, "List available scripts"},
    {"run",   CmdScriptRun,     1, "<name> -- Execute a script"},
    {NULL, NULL, 0, NULL}
};

/**
 * Finds a matching script-file
 * @brief CmdScript
 * @param Cmd
 * @return
 */
int CmdScript(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

/**
 * Shows some basic help
 * @brief CmdHelp
 * @param Cmd
 * @return
 */
int CmdHelp(const char *Cmd) {
    PrintAndLogEx(NORMAL, "This is a feature to run Lua-scripts. You can place lua-scripts within the scripts/-folder. ");
    return 0;
}
