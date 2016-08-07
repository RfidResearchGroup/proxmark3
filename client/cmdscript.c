//-----------------------------------------------------------------------------
// Copyright (C) 2013 m h swende <martin at swende.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Some lua scripting glue to proxmark core.
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>

#include "proxmark3.h"
#include "scripting.h"
#include "data.h"
#include "ui.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmdmain.h"
#include "cmdscript.h"
#include "cmdhfmf.h"
#include "pm3_binlib.h"
#include "pm3_bitlib.h"
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>


static int CmdHelp(const char *Cmd);
static int CmdList(const char *Cmd);
static int CmdRun(const char *Cmd);

command_t CommandTable[] =
{
  {"help",  CmdHelp, 1, "This help"},
  {"list",  CmdList, 1, "List available scripts"},
  {"run",   CmdRun,  1, "<name> -- Execute a script"},
  {NULL, NULL, 0, NULL}
};

int str_ends_with(const char * str, const char * suffix) {

  if( str == NULL || suffix == NULL )
    return 0;

  size_t str_len = strlen(str);
  size_t suffix_len = strlen(suffix);

  if(suffix_len > str_len)
    return 0;

  return 0 == strncmp( str + str_len - suffix_len, suffix, suffix_len );
}
/**
 * Shows some basic help
 * @brief CmdHelp
 * @param Cmd
 * @return
 */
int CmdHelp(const char * Cmd)
{
    PrintAndLog("This is a feature to run Lua-scripts. You can place lua-scripts within the ´client/scripts/´ folder.");
    return 0;
}

/**
* Generate list of available commands, what it does is 
* generate a file listing of the script-directory for files
* ending with .lua
*/
int CmdList(const char *Cmd)
{
    DIR *dp;
    struct dirent *ep;
    dp = opendir ("./scripts/");

    if (dp != NULL)
    {
        while ((ep = readdir (dp)) != NULL)
        {
            if(str_ends_with(ep->d_name, ".lua"))
                PrintAndLog("%-21s %s", ep->d_name, "A script file");
        }
        (void) closedir (dp);
    }
    else
        PrintAndLog ("Couldn't open the scripts-directory");
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
	CmdsParse(CommandTable, Cmd);
	return 0;
}
/**
 * Utility to check the ending of a string (used to check file suffix)
 */
bool endsWith (char* base, char* str) {
    int blen = strlen(base);
    int slen = strlen(str);
    return (blen >= slen) && (0 == strcmp(base + blen - slen, str));
}

/**
 * @brief CmdRun - executes a script file.
 * @param argc
 * @param argv
 * @return
 */
int CmdRun(const char *Cmd)
{
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
    sscanf(Cmd, "%127s%n %255[^\n\r]%n", script_name,&name_len, arguments, &arg_len);

    char *suffix = "";
    if(!endsWith(script_name,".lua"))
    {
        suffix = ".lua";
    }

    char buf[256];
    snprintf(buf, sizeof buf, "./scripts/%s%s", script_name, suffix);

    printf("--- Executing: %s, args'%s'\n", buf, arguments);

    // run the Lua script

    int error = luaL_loadfile(lua_state, buf);
    if(!error)
    {
        lua_pushstring(lua_state, arguments);
        lua_setglobal(lua_state, "args");

        //Call it with 0 arguments
         error = lua_pcall(lua_state, 0, LUA_MULTRET, 0); // once again, returns non-0 on error,
    }
    if(error) // if non-0, then an error
    {
        // the top of the stack should be the error string
        if (!lua_isstring(lua_state, lua_gettop(lua_state)))
            printf( "Error - but no error (?!)");

        // get the top of the stack as the error and pop it off
        const char * str = lua_tostring(lua_state, lua_gettop(lua_state));
        lua_pop(lua_state, 1);
        puts(str);
    }

    //luaL_dofile(lua_state, buf);
    // close the Lua state
    lua_close(lua_state);
    printf("\n-----Finished\n");
    return 0;
}

