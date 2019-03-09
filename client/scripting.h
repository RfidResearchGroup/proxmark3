//-----------------------------------------------------------------------------
// Copyright (C) 2013 m h swende <martin at swende.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Some lua scripting glue to proxmark core.
//-----------------------------------------------------------------------------
#ifndef SCRIPTING_H__
#define SCRIPTING_H__

#include <stdlib.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "proxmark3.h"
#include "usb_cmd.h"
#include "cmdmain.h"
#include "comms.h"
#include "util.h"
#include "mifare/mifarehost.h"
#include "crc.h"
#include "crc16.h"
#include "crc64.h"
#include "mbedtls/sha1.h"
#include "mbedtls/aes.h"
#include "cmdcrc.h"
#include "cmdhfmfhard.h"
#include "cmdhfmfu.h"
#include "protocols.h"

#define LUA_LIBRARIES_DIRECTORY "lualibs/"
#define LUA_SCRIPTS_DIRECTORY   "scripts/"
#define LUA_LIBRARIES_WILDCARD  "?.lua"

/**
 * @brief set_libraries loads the core components of pm3 into the 'pm3'
 *  namespace within the given lua_State
 * @param L
 */

int set_pm3_libraries(lua_State *L);

#endif
