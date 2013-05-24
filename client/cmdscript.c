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
    PrintAndLog("This is a feature to run Lua-scripts. You can place lua-scripts within the scripts/-folder. ");
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
        while (ep = readdir (dp))
        {
            if(ep->d_name != NULL && str_ends_with(ep->d_name, ".lua"))
                PrintAndLog("%-16s %s", ep->d_name, "A script file");
        }
        (void) closedir (dp);
    }
    else
        PrintAndLog ("Couldn't open the directory");
    return 0;
}
/**
 * Finds a matching script-file
 * @brief CmdScript
 * @param Cmd
 * @return
 */
int CmdScript(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}
/*
static int l_hfmf (lua_State *L) {
    return CmdHFMF("wohoo");

}
*/
//static int l_CmdHelp(lua_State *L){ return CmdHelp(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfDbg(lua_State *L){ return CmdHF14AMfDbg(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfRdBl(lua_State *L){ return CmdHF14AMfRdBl(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfRdSc(lua_State *L){ return CmdHF14AMfRdSc(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfDump(lua_State *L){ return CmdHF14AMfDump(luaL_checkstring(L, 1));}
static int l_CmdHF14AMifare(lua_State *L){ return CmdHF14AMifare(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfWrBl(lua_State *L){ return CmdHF14AMfWrBl(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfChk(lua_State *L){ return CmdHF14AMfChk(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfNested(lua_State *L){ return CmdHF14AMfNested(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfRestore(lua_State *L){ return CmdHF14AMfRestore(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfSniff(lua_State *L){ return CmdHF14AMfSniff(luaL_checkstring(L, 1));}
static int l_CmdHF14AMf1kSim(lua_State *L){ return CmdHF14AMf1kSim(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfEClear(lua_State *L){ return CmdHF14AMfEClear(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfEGet(lua_State *L){ return CmdHF14AMfEGet(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfESet(lua_State *L){ return CmdHF14AMfESet(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfELoad(lua_State *L){ return CmdHF14AMfELoad(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfESave(lua_State *L){ return CmdHF14AMfESave(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfECFill(lua_State *L){ return CmdHF14AMfECFill(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfEKeyPrn(lua_State *L){ return CmdHF14AMfEKeyPrn(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfCSetUID(lua_State *L){ return CmdHF14AMfCSetUID(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfCSetBlk(lua_State *L){ return CmdHF14AMfCSetBlk(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfCGetBlk(lua_State *L){ return CmdHF14AMfCGetBlk(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfCGetSc(lua_State *L){ return CmdHF14AMfCGetSc(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfCLoad(lua_State *L){ return CmdHF14AMfCLoad(luaL_checkstring(L, 1));}
static int l_CmdHF14AMfCSave(lua_State *L){ return CmdHF14AMfCSave(luaL_checkstring(L, 1));}




static void set_cmdlibraries(lua_State *L)
{
    static const luaL_Reg hfmf_lib[] = {
        {"dbg",     l_CmdHF14AMfDbg},
        {"rdbl",    l_CmdHF14AMfRdBl},
        {"rdsc",    l_CmdHF14AMfRdSc},
        {"dump",    l_CmdHF14AMfDump},
        {"restore", l_CmdHF14AMfRestore},
        {"wrbl",    l_CmdHF14AMfWrBl},
        {"chk",     l_CmdHF14AMfChk},
        {"mifare",  l_CmdHF14AMifare},
        {"nested",  l_CmdHF14AMfNested},
        {"sniff",   l_CmdHF14AMfSniff},
        {"sim",     l_CmdHF14AMf1kSim},
        {"eclr",    l_CmdHF14AMfEClear},
        {"eget",    l_CmdHF14AMfEGet},
        {"eset",    l_CmdHF14AMfESet},
        {"eload",   l_CmdHF14AMfELoad},
        {"esave",   l_CmdHF14AMfESave},
        {"ecfill",  l_CmdHF14AMfECFill},
        {"ekeyprn", l_CmdHF14AMfEKeyPrn},
        {"csetuid", l_CmdHF14AMfCSetUID},
        {"csetblk", l_CmdHF14AMfCSetBlk},
        {"cgetblk", l_CmdHF14AMfCGetBlk},
        {"cgetsc",  l_CmdHF14AMfCGetSc},
        {"cload",   l_CmdHF14AMfCLoad},
        {"csave",   l_CmdHF14AMfCSave},
        {NULL, NULL}
    };

    lua_pushglobaltable(L);
    // Core library is in this table. Contains 'hf'

    //this is 'hf' table
    lua_newtable(L);

    //this is the mf table
    lua_newtable(L);

    //Put the function into the hash table.
    for (int i = 0; hfmf_lib[i].name; i++) {
        lua_pushcfunction(L, hfmf_lib[i].func);
        lua_setfield(L, -2, hfmf_lib[i].name);//set the name, pop stack
    }
    //Name of 'mf'
    lua_setfield(L, -2, "mf");

    //Name of 'hf'
    lua_setfield(L, -2, "hf");

    //-- remove the global environment table from the stack
    lua_pop(L, 1);
    return 1;
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

    //Sets the 'command line' libraries, basically just the commandline stuff
    set_cmdlibraries(lua_state);
    char cmd_name[32];
    int len = 0;
    memset(cmd_name, 0, 32);
    sscanf(Cmd, "%31s%n", cmd_name, &len);

    char buf[256];
    snprintf(buf, sizeof buf, "./scripts/%s", cmd_name);

    printf("-----Executing file '%s'\n" , cmd_name);
    // run the Lua script

    int error = luaL_loadfile(lua_state, buf);
    if(!error)
    {
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
        printf(str);
    }

    //luaL_dofile(lua_state, buf);
    // close the Lua state
    lua_close(lua_state);
    printf("\n-----Finished\n");
}

