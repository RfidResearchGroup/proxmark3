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

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "proxmark3.h"
#include "usb_cmd.h"
#include "cmdmain.h"
#include "util.h"
#include "nonce2key/nonce2key.h"
#include "../common/iso15693tools.h"
#include "iso14443crc.h"
#include "../common/crc.h"
#include "../common/crc16.h"
#include "../common/crc64.h"
#include "../common/sha1.h"
#include "aes.h"
#include "cmdcrc.h"

/**
 * @brief set_libraries loads the core components of pm3 into the 'pm3'
 *  namespace within the given lua_State
 * @param L
 */

int set_pm3_libraries(lua_State *L);

#endif
