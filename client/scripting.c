//-----------------------------------------------------------------------------
// Copyright (C) 2013 m h swende <martin at swende.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Some lua scripting glue to proxmark core.
//-----------------------------------------------------------------------------

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "proxmark3.h"
#include "usb_cmd.h"
#include "cmdmain.h"
#include "scripting.h"
#include "util.h"
#include "nonce2key/nonce2key.h"
#include "../common/iso15693tools.h"
/**
 * The following params expected:
 *  UsbCommand c
 *@brief l_SendCommand
 * @param L
 * @return
 */
static int l_SendCommand(lua_State *L){

    /*
     *
     The SendCommand (native) expects the following structure:

     typedef struct {
      uint64_t cmd; //8 bytes
      uint64_t arg[3]; // 8*3 bytes = 24 bytes
      union {
        uint8_t  asBytes[USB_CMD_DATA_SIZE]; // 1 byte * 512 = 512 bytes (OR)
        uint32_t asDwords[USB_CMD_DATA_SIZE/4]; // 4 byte * 128 = 512 bytes
      } d;
    } PACKED UsbCommand;

    ==> A 544 byte buffer will do.
    **/
    //Pop cmd
    size_t size;
    const char *data = luaL_checklstring(L, 1, &size);
    if(size != sizeof(UsbCommand))
    {
        printf("Got data size %d, expected %d" , (int) size,(int) sizeof(UsbCommand));
        lua_pushstring(L,"Wrong data size");
        return 1;
    }

//    UsbCommand c = (*data);
    SendCommand((UsbCommand* )data);
    return 0; // no return values
}
/**
 * @brief The following params expected:
 * uint32_t cmd
 * size_t ms_timeout
 * @param L
 * @return
 */
static int l_WaitForResponseTimeout(lua_State *L){

    uint32_t cmd = 0;
    size_t ms_timeout = -1;

    //Check number of arguments
    int n = lua_gettop(L);
    if(n == 0)
    {
        //signal error by returning Nil, errorstring
        lua_pushnil(L);
        lua_pushstring(L,"You need to supply at least command to wait for");
        return 2; // two return values
    }
    if(n >= 1)
    {
        //pop cmd
        cmd = luaL_checkunsigned(L,1);
    }
    if(n >= 2)
    {
        //Did the user send a timeout ?
        //Check if the current top of stack is an integer
        ms_timeout = luaL_checkunsigned(L,2);
        //printf("Timeout set to %dms\n" , (int) ms_timeout);
    }

    UsbCommand response;

    if(WaitForResponseTimeout(cmd, &response, ms_timeout))
    {
        //Push it as a string
         lua_pushlstring(L,(const char *)&response,sizeof(UsbCommand));

        return 1;// return 1 to signal one return value
    }else{
        //Push a Nil instead
        lua_pushnil(L);
        return 1;// one return value
    }
}

static int returnToLuaWithError(lua_State *L, const char* fmt, ...)
{
    char buffer[200];
    va_list args;
    va_start(args,fmt);
    vsnprintf(buffer, sizeof(buffer), fmt,args);
    va_end(args);

    lua_pushnil(L);
    lua_pushstring(L,buffer);
    return 2;
}

static int l_nonce2key(lua_State *L){

    size_t size;
    const char *p_uid = luaL_checklstring(L, 1, &size);
    if(size != 4)  return returnToLuaWithError(L,"Wrong size of uid, got %d bytes, expected 4", (int) size);

    const char *p_nt = luaL_checklstring(L, 2, &size);
    if(size != 4)  return returnToLuaWithError(L,"Wrong size of nt, got %d bytes, expected 4", (int) size);

    const char *p_nr = luaL_checklstring(L, 3, &size);
    if(size != 4)  return returnToLuaWithError(L,"Wrong size of nr, got %d bytes, expected 4", (int) size);

    const char *p_par_info = luaL_checklstring(L, 4, &size);
    if(size != 8)  return returnToLuaWithError(L,"Wrong size of par_info, got %d bytes, expected 8", (int) size);

    const char *p_pks_info = luaL_checklstring(L, 5, &size);
    if(size != 8)  return returnToLuaWithError(L,"Wrong size of ks_info, got %d bytes, expected 8", (int) size);


    uint32_t uid = bytes_to_num(( uint8_t *)p_uid,4);
    uint32_t nt = bytes_to_num(( uint8_t *)p_nt,4);

    uint32_t nr = bytes_to_num(( uint8_t*)p_nr,4);
    uint64_t par_info = bytes_to_num(( uint8_t *)p_par_info,8);
    uint64_t ks_info = bytes_to_num(( uint8_t *)p_pks_info,8);

    uint64_t key = 0;

    int retval = nonce2key(uid,nt, nr, par_info,ks_info, &key);

    //Push the retval on the stack
    lua_pushinteger(L,retval);
  
    //Push the key onto the stack
    uint8_t dest_key[8];
    num_to_bytes(key,sizeof(dest_key),dest_key);

    //printf("Pushing to lua stack: %012"llx"\n",key);
    lua_pushlstring(L,(const char *) dest_key,sizeof(dest_key));

    return 2; //Two return values
}
//static int l_PrintAndLog(lua_State *L){ return CmdHF14AMfDump(luaL_checkstring(L, 1));}
static int l_clearCommandBuffer(lua_State *L){
    clearCommandBuffer();
    return 0;
}
/**
 * @brief l_foobar is a dummy function to test lua-integration with
 * @param L
 * @return
 */
static int l_foobar(lua_State *L)
{
    //Check number of arguments
    int n = lua_gettop(L);
    printf("foobar called with %d arguments" , n);
    lua_settop(L, 0);
    printf("Arguments discarded, stack now contains %d elements", lua_gettop(L));
  
    // todo: this is not used, where was it intended for?
    // UsbCommand response =  {CMD_MIFARE_READBL, {1337, 1338, 1339}};
  
    printf("Now returning a uint64_t as a string");
    uint64_t x = 0xDEADBEEF;
    uint8_t destination[8];
    num_to_bytes(x,sizeof(x),destination);
    lua_pushlstring(L,(const char *)&x,sizeof(x));
    lua_pushlstring(L,(const char *)destination,sizeof(destination));

    return 2;
}


/**
 * @brief Utility to check if a key has been pressed by the user. This method does not block.
 * @param L
 * @return boolean, true if kbhit, false otherwise.
 */
static int l_ukbhit(lua_State *L)
{
    lua_pushboolean(L,ukbhit() ? true : false);
    return 1;
}
/**
 * @brief Calls the command line parser to deal with the command. This enables
 * lua-scripts to do stuff like "core.console('hf mf mifare')"
 * @param L
 * @return
 */
static int l_CmdConsole(lua_State *L)
{
    CommandReceived((char *)luaL_checkstring(L, 1));
    return 0;
}

static int l_iso15693_crc(lua_State *L)
{
    //    uint16_t Iso15693Crc(uint8_t *v, int n);
    size_t size;
    const char *v = luaL_checklstring(L, 1, &size);
    uint16_t retval = Iso15693Crc((uint8_t *) v, size);
    lua_pushinteger(L, (int) retval);
    return 1;
}

/**
 * @brief Sets the lua path to include "./lualibs/?.lua", in order for a script to be
 * able to do "require('foobar')" if foobar.lua is within lualibs folder.
 * Taken from http://stackoverflow.com/questions/4125971/setting-the-global-lua-path-variable-from-c-c
 * @param L
 * @param path
 * @return
 */
int setLuaPath( lua_State* L, const char* path )
{
    lua_getglobal( L, "package" );
    lua_getfield( L, -1, "path" ); // get field "path" from table at top of stack (-1)
    const char* cur_path = lua_tostring( L, -1 ); // grab path string from top of stack
    int requiredLength = strlen(cur_path)+ strlen(path)+10; //A few bytes too many, whatever we can afford it
    char * buf = malloc(requiredLength);
    snprintf(buf, requiredLength, "%s;%s", cur_path, path);
    lua_pop( L, 1 ); // get rid of the string on the stack we just pushed on line 5
    lua_pushstring( L, buf ); // push the new one
    lua_setfield( L, -2, "path" ); // set the field "path" in table at -2 with value at top of stack
    lua_pop( L, 1 ); // get rid of package table from top of stack
    return 0; // all done!
}


int set_pm3_libraries(lua_State *L)
{

    static const luaL_Reg libs[] = {
        {"SendCommand",                 l_SendCommand},
        {"WaitForResponseTimeout",      l_WaitForResponseTimeout},
        {"nonce2key",                   l_nonce2key},
        //{"PrintAndLog",                 l_PrintAndLog},
        {"foobar",                      l_foobar},
        {"ukbhit",                      l_ukbhit},
        {"clearCommandBuffer",          l_clearCommandBuffer},
        {"console",                      l_CmdConsole},
        {"iso15693_crc",                 l_iso15693_crc},
        {NULL, NULL}
    };

    lua_pushglobaltable(L);
    // Core library is in this table. Contains '
    //this is 'pm3' table
    lua_newtable(L);

    //Put the function into the hash table.
    for (int i = 0; libs[i].name; i++) {
        lua_pushcfunction(L, libs[i].func);
        lua_setfield(L, -2, libs[i].name);//set the name, pop stack
    }
    //Name of 'core'
    lua_setfield(L, -2, "core");

    //-- remove the global environment table from the stack
    lua_pop(L, 1);

    //-- Last but not least, add to the LUA_PATH (package.path in lua)
    // so we can load libraries from the ./lualib/ - directory
    setLuaPath(L,"./lualibs/?.lua");

    return 1;
}
