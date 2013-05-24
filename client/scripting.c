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
        printf("Got data size %d, expected %d" , size,sizeof(UsbCommand));
        lua_pushstring(L,"Wrong data size");
        return 1;
    }

//    UsbCommand c = (*data);
    SendCommand(data);
    return 0;
    //UsbCommand *c = (UsbCommand *)lua_touserdata(L, 1);
    //luaL_argcheck(L, c != NULL, 1, "'UsbCommand' expected");

    //SendCommand(c);
    //return 0;
}
/**
 * @brief The following params expected:
 * uint32_t cmd
 * size_t ms_timeout
 * @param L
 * @return
 */
static int l_WaitForResponseTimeout(lua_State *L){

    //pop cmd
    uint32_t cmd = luaL_checkunsigned(L,1);
    printf("in l_WaitForResponseTimeout, got cmd 0x%0x\n",(int) cmd);
    //UsbCommand response;

     //We allocate the usbcommand as userdata on the Lua-stack
    size_t nbytes = sizeof(UsbCommand);

    UsbCommand *response = (UsbCommand *)lua_newuserdata(L, nbytes);

    size_t ms_timeout = 2000;
    //Did the user send a timeout ?
    //Check if the current top of stack is an integer

    if(lua_isnumber( L, 2))
    {
        printf("You sent a timout-value\n");
        ms_timeout = luaL_checkunsigned(L,2);
    }
    printf("Timeout set to %dms\n" , (int) ms_timeout);

    if(WaitForResponseTimeout(cmd, response, ms_timeout))
    {
        //Return the UsbCommand as userdata
        //the usbcommand is already on the stack
        // return 1 to signal one return value
        return 1;
    }else
    {
        //Don't return the UsbCommand. Pop it.
        lua_pop(L,-1);
        //Push a Nil instead
        lua_pushnil(L);
        return 1;
    }
}
static int l_nonce2key(lua_State *L){ return CmdHF14AMfRdSc(luaL_checkstring(L, 1));}
static int l_PrintAndLog(lua_State *L){ return CmdHF14AMfDump(luaL_checkstring(L, 1));}

void set_pm3_libraries(lua_State *L)
{
    static const luaL_Reg libs[] = {
        {"SendCommand",                 l_SendCommand},
        {"WaitForResponseTimeout",      l_WaitForResponseTimeout},
        {"nonce2key",                   l_nonce2key},
        {"PrintAndLog",                 l_PrintAndLog},
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
    return 1;
}
