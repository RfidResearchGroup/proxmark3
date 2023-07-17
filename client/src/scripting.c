//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Some lua scripting glue to proxmark core.
//-----------------------------------------------------------------------------
#include "scripting.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "lauxlib.h"
#include "cmdmain.h"
#include "proxmark3.h"
#include "comms.h"
#include "mifare/mifarehost.h"
#include "crc.h"
#include "crc64.h"
#include "sha1.h"
#include "aes.h"
#include "cmdcrc.h"
#include "cmdhfmfhard.h"
#include "cmdhfmfu.h"
#include "cmdlft55xx.h"   // read t55xx etc
#include "nfc/ndef.h"     // ndef parsing
#include "commonutil.h"
#include "ui.h"

#include "crc16.h"
#include "protocols.h"
#include "fileutils.h"    // searchfile
#include "cmdlf.h"        // lf_config
#include "generator.h"
#include "cmdlfem4x05.h"  // read 4305
#include "cmdlfem4x50.h"  // read 4350
#include "em4x50.h"       // 4x50 structs

static int returnToLuaWithError(lua_State *L, const char *fmt, ...) {
    char buffer[200];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    lua_pushnil(L);
    lua_pushstring(L, buffer);
    return 2;
}

static int l_clearCommandBuffer(lua_State *L) {
    clearCommandBuffer();
    return 0;
}

/**
 * Enable / Disable fast push mode for lua scripts like hf_mf_keycheck
 * The following params expected:
 *
 *@brief l_fast_push_mode
 * @param L
 * @return
 */
static int l_fast_push_mode(lua_State *L) {

    luaL_checktype(L, 1, LUA_TBOOLEAN);

    bool enable = lua_toboolean(L, 1);

    g_conn.block_after_ACK = enable;

    // Disable fast mode and send a dummy command to make it effective
    if (enable == false) {
        SendCommandNG(CMD_PING, NULL, 0);
        if (!WaitForResponseTimeout(CMD_PING, NULL, 1000)) {
            PrintAndLogEx(WARNING, "command execution time out");
            return returnToLuaWithError(L, "command execution time out");
        }
    }

    //Push the retval on the stack
    lua_pushboolean(L, enable);
    return 1;
}

/**
 * The following params expected:
 * @brief l_SendCommandMIX
 * @param L - a lua string with the following five params.
 * @param cmd  must be hexstring, max u64
 * @param arg0  must be hexstring, max u64
 * @param arg1  must be hexstring, max u64
 * @param arg2  must be hexstring, max u64
 * @param data  must be hexstring less than 1024 chars(512bytes)
 * @return
 */
static int l_SendCommandMIX(lua_State *L) {

    uint64_t cmd, arg0, arg1, arg2;
    uint8_t data[PM3_CMD_DATA_SIZE] = {0};
    size_t len = 0, size;

    // check number of arguments
    int n = lua_gettop(L);
    if (n != 5)
        return returnToLuaWithError(L, "You need to supply five parameters");

    // parse input
    cmd = luaL_checknumber(L, 1);
    arg0 = luaL_checknumber(L, 2);
    arg1 = luaL_checknumber(L, 3);
    arg2 = luaL_checknumber(L, 4);

    // data
    const char *p_data = luaL_checklstring(L, 5, &size);
    if (size) {
        if (size > 1024)
            size = 1024;

        uint32_t tmp;
        for (int i = 0; i < size; i += 2) {
            sscanf(&p_data[i], "%02x", &tmp);
            data[i >> 1] = tmp & 0xFF;
            len++;
        }
    }

    clearCommandBuffer();
    SendCommandMIX(cmd, arg0, arg1, arg2, data, len);
    lua_pushboolean(L, true);
    return 1;
}
/**
 * The following params expected:
 * @brief l_SendCommandMIX
 * @param L - a lua string with the following two params.
 * @param cmd  must be hexstring, max u64
 * @param data  must be hexstring less than 1024 chars(512bytes)
 * @return
 */
static int l_SendCommandNG(lua_State *L) {

    uint8_t data[PM3_CMD_DATA_SIZE] = {0};
    size_t len = 0, size;

    // check number of arguments
    int n = lua_gettop(L);
    if (n != 2)
        return returnToLuaWithError(L, "You need to supply two parameters");

    // parse input
    uint16_t cmd = luaL_checknumber(L, 1);

    // data
    const char *p_data = luaL_checklstring(L, 2, &size);
    if (size) {
        if (size > 1024)
            size = 1024;

        uint32_t tmp;
        for (int i = 0; i < size; i += 2) {
            sscanf(&p_data[i], "%02x", &tmp);
            data[i >> 1] = tmp & 0xFF;
            len++;
        }
    }

    clearCommandBuffer();
    SendCommandNG(cmd, data, len);
    lua_pushboolean(L, true);
    return 1;
}


/**
 * @brief The following params expected:
 * uint8_t *dest
 * int bytes
 * int start_index
 * @param L
 * @return
 */
static int l_GetFromBigBuf(lua_State *L) {

    int len = 0, startindex = 0;

    //Check number of arguments
    int n = lua_gettop(L);
    if (n == 0) {
        return returnToLuaWithError(L, "You need to supply number of bytes and startindex");
    }

    if (n >= 2) {
        startindex = luaL_checknumber(L, 1);
        len = luaL_checknumber(L, 2);
    }

    if (len == 0) {
        return returnToLuaWithError(L, "You need to supply number of bytes larger than zero");
    }

    uint8_t *data = calloc(len, sizeof(uint8_t));
    if (!data) {
        return returnToLuaWithError(L, "Allocating memory failed");
    }

    if (!GetFromDevice(BIG_BUF, data, len, startindex, NULL, 0, NULL, 2500, false)) {
        free(data);
        return returnToLuaWithError(L, "command execution time out");
    }

    //Push it as a string
    lua_pushlstring(L, (const char *)data, len);
    free(data);
    return 1; // return 1 to signal one return value
}

/**
 * @brief The following params expected:
 * uint8_t *dest
 * int bytes
 * int start_index
 * @param L
 * @return
 */
static int l_GetFromFlashMem(lua_State *L) {

    if (IfPm3Flash()) {
        int len = 0, startindex = 0;

        int n = lua_gettop(L);
        if (n == 0)
            return returnToLuaWithError(L, "You need to supply number of bytes and startindex");

        if (n >= 2) {
            startindex = luaL_checknumber(L, 1);
            len = luaL_checknumber(L, 2);
        }

        if (len == 0)
            return returnToLuaWithError(L, "You need to supply number of bytes larger than zero");

        uint8_t *data = calloc(len, sizeof(uint8_t));
        if (!data)
            return returnToLuaWithError(L, "Allocating memory failed");

        if (!GetFromDevice(FLASH_MEM, data, len, startindex, NULL, 0, NULL, -1, false)) {
            free(data);
            return returnToLuaWithError(L, "command execution time out");
        }

        lua_pushlstring(L, (const char *)data, len);
        free(data);
        return 1;
    } else {
        return returnToLuaWithError(L, "No FLASH MEM support");
    }
}

/**
 * @brief The following params expected:
 * uint8_t *destfilename
 * @param L
 * @return
 */
static int l_GetFromFlashMemSpiffs(lua_State *L) {

    if (IfPm3Flash() == false) {
        return returnToLuaWithError(L, "No FLASH MEM support");
    }

    uint32_t start_index = 0, len = 0x40000; //FLASH_MEM_MAX_SIZE
    char destfilename[32] = {0};
    size_t size;

    int n = lua_gettop(L);
    if (n == 0)
        return returnToLuaWithError(L, "You need to supply the destination filename");

    if (n >= 1) {
        const char *p_filename = luaL_checklstring(L, 1, &size);
        if (size != 0)
            memcpy(destfilename, p_filename, 31);
    }

    if (destfilename[0] == '\0')
        return returnToLuaWithError(L, "Filename missing or invalid");

    // get size from spiffs itself !
    SendCommandNG(CMD_SPIFFS_STAT, (uint8_t *)destfilename, 32);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_SPIFFS_STAT, &resp, 2000))
        return returnToLuaWithError(L, "No response from the device");

    len = resp.data.asDwords[0];

    if (len == 0)
        return returnToLuaWithError(L, "Filename invalid or empty");

    uint8_t *data = calloc(len, sizeof(uint8_t));
    if (!data)
        return returnToLuaWithError(L, "Allocating memory failed");

    if (!GetFromDevice(SPIFFS, data, len, start_index, (uint8_t *)destfilename, 32, NULL, -1, true)) {
        free(data);
        return returnToLuaWithError(L, "ERROR; downloading from spiffs(flashmemory)");
    }

    lua_pushlstring(L, (const char *)data, len);
    lua_pushunsigned(L, len);
    free(data);
    return 2;
}

/**
 * @brief The following params expected:
 * uint32_t cmd
 * size_t ms_timeout
 * @param L
 * @return struct of PacketResponseNG
 */
static int l_WaitForResponseTimeout(lua_State *L) {

    uint32_t cmd = 0;
    size_t ms_timeout = -1;

    //Check number of arguments
    int n = lua_gettop(L);
    if (n == 0)
        return returnToLuaWithError(L, "You need to supply at least command to wait for");

    // extract first param.  cmd byte to look for
    if (n >= 1)
        cmd = luaL_checkunsigned(L, 1);

    // extract second param. timeout value
    if (n >= 2)
        ms_timeout = luaL_checkunsigned(L, 2);

    PacketResponseNG resp;
    if (WaitForResponseTimeout(cmd, &resp, ms_timeout) == false) {
        return returnToLuaWithError(L, "No response from the device");
    }

    char foo[sizeof(PacketResponseNG)];
    n = 0;

    memcpy(foo + n, &resp.cmd, sizeof(resp.cmd));
    n += sizeof(resp.cmd);

    memcpy(foo + n, &resp.length, sizeof(resp.length));
    n += sizeof(resp.length);

    memcpy(foo + n, &resp.magic, sizeof(resp.magic));
    n += sizeof(resp.magic);

    memcpy(foo + n, &resp.status, sizeof(resp.status));
    n += sizeof(resp.status);

    memcpy(foo + n, &resp.crc, sizeof(resp.crc));
    n += sizeof(resp.crc);

    memcpy(foo + n, &resp.oldarg[0], sizeof(resp.oldarg[0]));
    n += sizeof(resp.oldarg[0]);

    memcpy(foo + n, &resp.oldarg[1], sizeof(resp.oldarg[1]));
    n += sizeof(resp.oldarg[1]);

    memcpy(foo + n, &resp.oldarg[2], sizeof(resp.oldarg[2]));
    n += sizeof(resp.oldarg[2]);

    memcpy(foo + n, resp.data.asBytes, sizeof(resp.data));
    n += sizeof(resp.data);

    memcpy(foo + n, &resp.ng, sizeof(resp.ng));
    n += sizeof(resp.ng);
    (void) n;

    //Push it as a string
    lua_pushlstring(L, (const char *)&foo, sizeof(foo));
    return 1;
}

static int l_mfDarkside(lua_State *L) {

    uint32_t blockno = 0;
    uint32_t keytype = MIFARE_AUTH_KEYA;
    uint64_t key = 0;
    size_t size;

    //Check number of arguments
    int n = lua_gettop(L);
    switch (n) {
        case 2: {
            const char *p_keytype = luaL_checklstring(L, 2, &size);
            if (size != 2)  return returnToLuaWithError(L, "Wrong size of keytype, got %d bytes, expected 1", (int) size);
            sscanf(p_keytype, "%x", &keytype);
        }
        case 1: {
            const char *p_blockno = luaL_checklstring(L, 1, &size);
            if (size != 2)  return returnToLuaWithError(L, "Wrong size of blockno, got %d bytes, expected 2", (int) size);
            sscanf(p_blockno, "%02x", &blockno);
            break;
        }
        default :
            break;
    }

    int retval = mfDarkside(blockno & 0xFF, keytype & 0xFF, &key);

    uint8_t dest_key[8];
    num_to_bytes(key, sizeof(dest_key), dest_key);

    //Push the retval on the stack
    lua_pushinteger(L, retval);
    lua_pushlstring(L, (const char *) dest_key, sizeof(dest_key));
    return 2;
}

/**
 * @brief l_foobar is a dummy function to test lua-integration with
 * @param L
 * @return
 */
static int l_foobar(lua_State *L) {
    //Check number of arguments
    int n = lua_gettop(L);
    PrintAndLogEx(INFO, "foobar called with %d arguments", n);
    lua_settop(L, 0);
    PrintAndLogEx(INFO, "Arguments discarded, stack now contains %d elements", lua_gettop(L));

    // todo: this is not used, where was it intended for?
    // PacketCommandOLD response =  {CMD_HF_MIFARE_READBL, {1337, 1338, 1339}, {{0}}};

    PrintAndLogEx(INFO, "Now returning a uint64_t as a string");
    uint64_t x = 0xDEADC0DE;
    uint8_t destination[8];
    num_to_bytes(x, sizeof(x), destination);
    lua_pushlstring(L, (const char *)&x, sizeof(x));
    lua_pushlstring(L, (const char *)destination, sizeof(destination));
    return 2;
}

/**
 * @brief Utility to check if a key has been pressed by the user. This method does not block.
 * @param L
 * @return boolean, true if kbhit, false otherwise.
 */
static int l_kbd_enter_pressed(lua_State *L) {
    lua_pushboolean(L, kbd_enter_pressed() ? true : false);
    return 1;
}

/**
 * @brief Calls the command line parser to deal with the command. This enables
 * lua-scripts to do stuff like "core.console('hf mf mifare')"
 * @param L
 * @return
 */
static int l_CmdConsole(lua_State *L) {
    CommandReceived((char *)luaL_checkstring(L, 1));
    return 0;
}

static int l_iso15693_crc(lua_State *L) {
    uint32_t tmp;
    unsigned char buf[PM3_CMD_DATA_SIZE] = {0x00};
    size_t size = 0;
    const char *data = luaL_checklstring(L, 1, &size);

    for (int i = 0; i < size; i += 2) {
        sscanf(&data[i], "%02x", &tmp);
        buf[i / 2] = tmp & 0xFF;
    }

    size /= 2;
    compute_crc(CRC_15693, buf, size, &buf[size], &buf[size + 1]);
    lua_pushlstring(L, (const char *)&buf, size + 2);
    return 1;
}

static int l_iso14443b_crc(lua_State *L) {
    uint32_t tmp;
    unsigned char buf[PM3_CMD_DATA_SIZE] = {0x00};
    size_t size = 0;
    const char *data = luaL_checklstring(L, 1, &size);

    for (int i = 0; i < size; i += 2) {
        sscanf(&data[i], "%02x", &tmp);
        buf[i / 2] = tmp & 0xFF;
    }

    size /= 2;
    compute_crc(CRC_14443_B, buf, size, &buf[size], &buf[size + 1]);
    lua_pushlstring(L, (const char *)&buf, size + 2);
    return 1;
}

/*
 Simple AES 128 cbc hook up to OpenSSL.
 params:  key, input
*/
static int l_aes128decrypt_cbc(lua_State *L) {
    //Check number of arguments
    int i;
    uint32_t tmp;
    size_t size;
    const char *p_key = luaL_checklstring(L, 1, &size);
    if (size != 32)
        return returnToLuaWithError(L, "Wrong size of key, got %d bytes, expected 32", (int) size);

    const char *p_encTxt = luaL_checklstring(L, 2, &size);

    unsigned char indata[16] = {0x00};
    unsigned char outdata[16] = {0x00};
    unsigned char aes_key[16] = {0x00};
    unsigned char iv[16] = {0x00};

    // convert key to bytearray and convert input to bytearray
    for (i = 0; i < 32; i += 2) {
        sscanf(&p_encTxt[i], "%02x", &tmp);
        indata[i / 2] = tmp & 0xFF;
        sscanf(&p_key[i], "%02x", &tmp);
        aes_key[i / 2] = tmp & 0xFF;
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_dec(&ctx, aes_key, 128);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, sizeof(indata), iv, indata, outdata);
    //Push decrypted array as a string
    lua_pushlstring(L, (const char *)&outdata, sizeof(outdata));
    return 1;// return 1 to signal one return value
}
static int l_aes128decrypt_ecb(lua_State *L) {
    //Check number of arguments
    int i;
    uint32_t tmp;
    size_t size;
    const char *p_key = luaL_checklstring(L, 1, &size);
    if (size != 32)
        return returnToLuaWithError(L, "Wrong size of key, got %d bytes, expected 32", (int) size);

    const char *p_encTxt = luaL_checklstring(L, 2, &size);

    unsigned char indata[16] = {0x00};
    unsigned char outdata[16] = {0x00};
    unsigned char aes_key[16] = {0x00};

    // convert key to bytearray and convert input to bytearray
    for (i = 0; i < 32; i += 2) {
        sscanf(&p_encTxt[i], "%02x", &tmp);
        indata[i / 2] = tmp & 0xFF;
        sscanf(&p_key[i], "%02x", &tmp);
        aes_key[i / 2] = tmp & 0xFF;
    }
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_dec(&ctx, aes_key, 128);
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, indata, outdata);

    //Push decrypted array as a string
    lua_pushlstring(L, (const char *)&outdata, sizeof(outdata));
    return 1;// return 1 to signal one return value
}

static int l_aes128encrypt_cbc(lua_State *L) {
    //Check number of arguments
    int i;
    uint32_t tmp;
    size_t size;
    const char *p_key = luaL_checklstring(L, 1, &size);
    if (size != 32)
        return returnToLuaWithError(L, "Wrong size of key, got %d bytes, expected 32", (int) size);

    const char *p_txt = luaL_checklstring(L, 2, &size);

    unsigned char indata[16] = {0x00};
    unsigned char outdata[16] = {0x00};
    unsigned char aes_key[16] = {0x00};
    unsigned char iv[16] = {0x00};

    for (i = 0; i < 32; i += 2) {
        sscanf(&p_txt[i], "%02x", &tmp);
        indata[i / 2] = tmp & 0xFF;
        sscanf(&p_key[i], "%02x", &tmp);
        aes_key[i / 2] = tmp & 0xFF;
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, aes_key, 128);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, sizeof(indata), iv, indata, outdata);
    //Push encrypted array as a string
    lua_pushlstring(L, (const char *)&outdata, sizeof(outdata));
    return 1;// return 1 to signal one return value
}

static int l_aes128encrypt_ecb(lua_State *L) {
    //Check number of arguments
    int i;
    uint32_t tmp;
    size_t size;
    const char *p_key = luaL_checklstring(L, 1, &size);
    if (size != 32)
        return returnToLuaWithError(L, "Wrong size of key, got %d bytes, expected 32", (int) size);

    const char *p_txt = luaL_checklstring(L, 2, &size);

    unsigned char indata[16] = {0x00};
    unsigned char outdata[16] = {0x00};
    unsigned char aes_key[16] = {0x00};

    for (i = 0; i < 32; i += 2) {
        sscanf(&p_txt[i], "%02x", &tmp);
        indata[i / 2] = tmp & 0xFF;
        sscanf(&p_key[i], "%02x", &tmp);
        aes_key[i / 2] = tmp & 0xFF;
    }
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, aes_key, 128);
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, indata, outdata);
    //Push encrypted array as a string
    lua_pushlstring(L, (const char *)&outdata, sizeof(outdata));
    return 1;// return 1 to signal one return value
}

static int l_crc8legic(lua_State *L) {
    size_t size;
    const char *p_hexstr = luaL_checklstring(L, 1, &size);
    uint16_t retval = CRC8Legic((uint8_t *)p_hexstr, size);
    lua_pushunsigned(L, retval);
    return 1;
}

static int l_crc16legic(lua_State *L) {
    size_t hexsize, uidsize;

    // data as hex string
    const char *p_hexstr = luaL_checklstring(L, 1, &hexsize);

    // calc uid crc based on uid hex
    const char *p_uid = luaL_checklstring(L, 2, &uidsize);
    uint16_t uidcrc = CRC8Legic((uint8_t *)p_uid, uidsize);

    init_table(CRC_LEGIC_16);
    uint16_t retval = crc16_legic((uint8_t *)p_hexstr, hexsize, uidcrc);
    lua_pushunsigned(L, retval);
    return 1;
}


static int l_crc16(lua_State *L) {
    size_t size;
    const char *p_str = luaL_checklstring(L, 1, &size);

    uint16_t checksum = Crc16ex(CRC_CCITT, (uint8_t *) p_str, size);
    lua_pushunsigned(L, checksum);
    return 1;
}

static int l_crc64(lua_State *L) {
    size_t size;
    uint64_t crc = 0;
    unsigned char outdata[8] = {0x00};

    const char *p_str = luaL_checklstring(L, 1, &size);

    crc64((uint8_t *) p_str, size, &crc);

    outdata[0] = (uint8_t)(crc >> 56) & 0xff;
    outdata[1] = (uint8_t)(crc >> 48) & 0xff;
    outdata[2] = (uint8_t)(crc >> 40) & 0xff;
    outdata[3] = (uint8_t)(crc >> 32) & 0xff;
    outdata[4] = (uint8_t)(crc >> 24) & 0xff;
    outdata[5] = (uint8_t)(crc >> 16) & 0xff;
    outdata[6] = (uint8_t)(crc >> 8) & 0xff;
    outdata[7] = crc & 0xff;
    lua_pushlstring(L, (const char *)&outdata, sizeof(outdata));
    return 1;
}

// TO BE IMPLEMENTED
static int l_crc64_ecma182(lua_State *L) {
    //size_t size;
    uint64_t crc = 0;
    unsigned char outdata[8] = {0x00};
    //const char *p_str = luaL_checklstring(L, 1, &size);

    //init
    //crc64_ecma182(NULL, 0, &crc);
    crc = 0x338103260CC4;

    // calc hash
    //crc64_ecma182((uint8_t*) p_str, size, &crc);

    outdata[0] = (uint8_t)(crc >> 56) & 0xff;
    outdata[1] = (uint8_t)(crc >> 48) & 0xff;
    outdata[2] = (uint8_t)(crc >> 40) & 0xff;
    outdata[3] = (uint8_t)(crc >> 32) & 0xff;
    outdata[4] = (uint8_t)(crc >> 24) & 0xff;
    outdata[5] = (uint8_t)(crc >> 16) & 0xff;
    outdata[6] = (uint8_t)(crc >> 8) & 0xff;
    outdata[7] = crc & 0xff;
    lua_pushlstring(L, (const char *)&outdata, sizeof(outdata));
    return 1;
}

static int l_sha1(lua_State *L) {
    size_t size;
    const char *p_str = luaL_checklstring(L, 1, &size);
    unsigned char outdata[20] = {0x00};
    mbedtls_sha1((uint8_t *) p_str, size, outdata);
    lua_pushlstring(L, (const char *)&outdata, sizeof(outdata));
    return 1;
}

static int l_reveng_models(lua_State *L) {

// This array needs to be adjusted if RevEng adds more crc-models.
#define NMODELS 106

    int count = 0;
    uint8_t in_width = luaL_checkunsigned(L, 1);
    if (in_width > 89)
        return returnToLuaWithError(L, "Width cannot exceed 89, got %d", in_width);

    uint8_t width[NMODELS];
    memset(width, 0, sizeof(width));
    char *models[NMODELS];

    width[0] = in_width;

    if (!GetModels(models, &count, width))
        return returnToLuaWithError(L, "didn't find any models");

    lua_newtable(L);
    for (int i = 0; i < count; i++) {
        lua_pushstring(L, (const char *)models[i]);
        lua_rawseti(L, -2, i + 1);
        free(models[i]);
    }
    return 1;
}

//Called with 4 parameters.
// inModel   ,string containing the crc model name: 'CRC-8'
// inHexStr  ,string containing the hex representation of the data that will be used for CRC calculations.
// reverse   ,int 0/1  (bool) if 1, calculate the reverse CRC
// endian    ,char,  'B','b','L','l','t','r' describing if Big-Endian or Little-Endian should be used in different combinations.
//
// outputs:  string with hex representation of the CRC result
static int l_reveng_runmodel(lua_State *L) {
    //-c || -v
    //inModel = valid model name string - CRC-8
    //inHexStr = input hex string to calculate crc on
    //reverse = reverse calc option if true
    //endian = {0 = calc default endian input and output, b = big endian input and output, B = big endian output, r = right justified
    //          l = little endian input and output, L = little endian output only, t = left justified}
    //result = calculated crc hex string
    char result[50];
    memset(result, 0x00, sizeof(result));

    const char *inModel = luaL_checkstring(L, 1);
    const char *inHexStr = luaL_checkstring(L, 2);
    bool reverse =  lua_toboolean(L, 3);
    const char endian = luaL_checkstring(L, 4)[0];

    int ans = RunModel((char *)inModel, (char *)inHexStr, reverse, endian, result);
    if (!ans)
        return returnToLuaWithError(L, "Reveng failed");

    lua_pushstring(L, result);
    return 1;
}

static int l_hardnested(lua_State *L) {

    bool haveTarget = true;
    size_t size;
    uint32_t tmp;
    const char *p_blockno = luaL_checklstring(L, 1, &size);
    if (size != 2)
        return returnToLuaWithError(L, "Wrong size of blockNo, got %d bytes, expected 2", (int) size);

    const char *p_keytype = luaL_checklstring(L, 2, &size);
    if (size != 1)
        return returnToLuaWithError(L, "Wrong size of keyType, got %d bytes, expected 1", (int) size);

    const char *p_key = luaL_checklstring(L, 3, &size);
    if (size != 12)
        return returnToLuaWithError(L, "Wrong size of key, got %d bytes, expected 12", (int) size);

    const char *p_trg_blockno = luaL_checklstring(L, 4, &size);
    if (size != 2)
        return returnToLuaWithError(L, "Wrong size of trgBlockNo, got %d bytes, expected 2", (int) size);

    const char *p_trg_keytype = luaL_checklstring(L, 5, &size);
    if (size != 1)
        return returnToLuaWithError(L, "Wrong size of trgKeyType, got %d bytes, expected 1", (int) size);

    const char *p_trgkey = luaL_checklstring(L, 6, &size);
    if (size != 12)
        haveTarget = false;

    const char *p_nonce_file_read = luaL_checklstring(L, 7, &size);
    if (size != 1)
        return returnToLuaWithError(L, "Wrong size of nonce_file_read, got %d bytes, expected 1", (int) size);

    const char *p_nonce_file_write = luaL_checklstring(L, 8, &size);
    if (size != 1)
        return returnToLuaWithError(L, "Wrong size of nonce_file_write, got %d bytes, expected 1", (int) size);

    const char *p_slow = luaL_checklstring(L, 9, &size);
    if (size != 1)
        return returnToLuaWithError(L, "Wrong size of slow, got %d bytes, expected 1", (int) size);

    const char *p_tests = luaL_checklstring(L, 10, &size);
    if (size != 1)
        return returnToLuaWithError(L, "Wrong size of tests, got %d bytes, expected 1", (int) size);

    char filename[FILE_PATH_SIZE] = "nonces.bin";
    const char *p_filename = luaL_checklstring(L, 11, &size);
    if (size != 0)
        memcpy(filename, p_filename, FILE_PATH_SIZE - 1);

    uint32_t blockNo = 0, keyType = 0;
    uint32_t trgBlockNo = 0, trgKeyType = 0;
    uint32_t slow = 0, tests = 0;
    uint32_t nonce_file_read = 0, nonce_file_write = 0;
    sscanf(p_blockno, "%02x", &blockNo);
    sscanf(p_keytype, "%x", &keyType);
    sscanf(p_trg_blockno, "%02x", &trgBlockNo);
    sscanf(p_trg_keytype, "%x", &trgKeyType);
    sscanf(p_nonce_file_read, "%x", &nonce_file_read);
    sscanf(p_nonce_file_write, "%x", &nonce_file_write);

    sscanf(p_slow, "%x", &slow);
    sscanf(p_tests, "%x", &tests);

    uint8_t key[6] = {0, 0, 0, 0, 0, 0};
    uint8_t trgkey[6] = {0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 12; i += 2) {
        sscanf(&p_key[i], "%02x", &tmp);
        key[i / 2] = tmp & 0xFF;
        if (haveTarget) {
            sscanf(&p_trgkey[i], "%02x", &tmp);
            trgkey[i / 2] = tmp & 0xFF;
        }
    }

    uint64_t foundkey = 0;
    int retval = mfnestedhard(blockNo, keyType, key, trgBlockNo, trgKeyType, haveTarget ? trgkey : NULL, nonce_file_read,  nonce_file_write,  slow,  tests, &foundkey, filename);
    DropField();

    //Push the key onto the stack
    uint8_t dest_key[6];
    num_to_bytes(foundkey, sizeof(dest_key), dest_key);

    //Push the retval on the stack
    lua_pushinteger(L, retval);
    lua_pushlstring(L, (const char *) dest_key, sizeof(dest_key));
    return 2; //Two return values
}

/**
 * @brief l_validate_prng is a function to test is a nonce is using the weak PRNG
 * detection =  1 == weak,  0 == hard ,  -1 = failed
 * @param L
 * @return
 */
static int l_detect_prng(lua_State *L) {
    int res = detect_classic_prng();
    lua_pushinteger(L, res);
    return 1;
}
/*
 * @brief l_keygen_algoB is a function to calculate pwd/pack using UID, by algo B
 * @param L
 * @return
 */
static int l_keygen_algoB(lua_State *L) {
    //Check number of arguments
    int n = lua_gettop(L);
    if (n != 1)  {
        return returnToLuaWithError(L, "Only UID");
    }

    size_t size;
    uint32_t tmp;
    const char *p_uid = luaL_checklstring(L, 1, &size);
    if (size != 14)
        return returnToLuaWithError(L, "Wrong size of UID, got %d bytes, expected 14", (int) size);

    uint8_t uid[7] = {0, 0, 0, 0, 0, 0, 0};

    for (int i = 0; i < 14; i += 2) {
        sscanf(&p_uid[i], "%02x", &tmp);
        uid[i / 2] = tmp & 0xFF;
    }

    uint32_t pwd = ul_ev1_pwdgenB(uid);
    uint16_t pack = ul_ev1_packgenB(uid);

    lua_pushunsigned(L, pwd);
    lua_pushunsigned(L, pack);
    return 2;
}

/*
 * @brief l_keygen_algoD is a function to calculate pwd/pack using UID, by algo D
 * @param L
 * @return
 */
static int l_keygen_algoD(lua_State *L) {
    //Check number of arguments
    int n = lua_gettop(L);
    if (n != 1)  {
        return returnToLuaWithError(L, "Only UID");
    }

    size_t size;
    uint32_t tmp;
    const char *p_uid = luaL_checklstring(L, 1, &size);
    if (size != 14)
        return returnToLuaWithError(L, "Wrong size of UID, got %d bytes, expected 14", (int) size);

    uint8_t uid[7] = {0, 0, 0, 0, 0, 0, 0};

    for (int i = 0; i < 14; i += 2) {
        sscanf(&p_uid[i], "%02x", &tmp);
        uid[i / 2] = tmp & 0xFF;
    }

    uint32_t pwd = ul_ev1_pwdgenD(uid);
    uint16_t pack = ul_ev1_packgenD(uid);

    lua_pushunsigned(L, pwd);
    lua_pushunsigned(L, pack);
    return 2;
}

/*
Read T55Xx block.
param1 uint8_t block
param2 bool page1
param3 bool override
param4 uint32_t password
*/
static int l_T55xx_readblock(lua_State *L) {

    //Check number of arguments
    int n = lua_gettop(L);
    if (n != 4)
        return returnToLuaWithError(L, "Wrong number of arguments, got %d bytes, expected 4", n);

    uint32_t block, usepage1, override, password = 0;
    bool usepwd;
    size_t size;

    const char *p_blockno = luaL_checklstring(L, 1, &size);
    if (size < 1 || size > 2)
        return returnToLuaWithError(L, "Wrong size of blockNo, got %d, expected 1 or 2", (int) size);

    sscanf(p_blockno, "%x", &block);

    const char *p_usepage1 = luaL_checklstring(L, 2, &size);
    if (size != 1)
        return returnToLuaWithError(L, "Wrong size of usePage1, got %d, expected 1", (int) size);

    sscanf(p_usepage1, "%x", &usepage1);

    const char *p_override = luaL_checklstring(L, 3, &size);
    if (size != 1)
        return returnToLuaWithError(L, "Wrong size of override, got %d, expected 1", (int) size);

    sscanf(p_override, "%x", &override);

    const char *p_pwd = luaL_checklstring(L, 4, &size);
    if (size == 0) {
        usepwd = false;
    } else {

        if (size != 8)
            return returnToLuaWithError(L, "Wrong size of pwd, got %d , expected 8", (int) size);

        sscanf(p_pwd, "%08x", &password);
        usepwd = true;
    }

    //Password mode
    if (usepwd) {
        // try reading the config block and verify that PWD bit is set before doing this!
        if (!override) {

            if (!AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, false, 0, 0)) {
                return returnToLuaWithError(L, "Failed to read config block");
            }

            if (!t55xxTryDetectModulation(0, true)) { // Default to prev. behaviour (default dl mode and print config)
                PrintAndLogEx(NORMAL, "Safety Check: Could not detect if PWD bit is set in config block. Exits.");
                return 0;
            } else {
                PrintAndLogEx(NORMAL, "Safety Check: PWD bit is NOT set in config block. Reading without password...");
                usepwd = false;
                usepage1 = false;
            }
        } else {
            PrintAndLogEx(NORMAL, "Safety Check Overridden - proceeding despite risk");
        }
    }

    if (!AcquireData(usepage1, block, usepwd, password, 0)) {
        return returnToLuaWithError(L, "Failed to acquire data from card");
    }

    if (!DecodeT55xxBlock()) {
        return returnToLuaWithError(L, "Failed to decode signal");
    }

    uint32_t blockData = 0;
    if (GetT55xxBlockData(&blockData) == false) {
        return returnToLuaWithError(L, "Failed to get actual data");
    }

    lua_pushunsigned(L, blockData);
    return 1;
}

// arg 1 = pwd
// arg 2 = use GB
static int l_T55xx_detect(lua_State *L) {
    bool useGB = false, usepwd = false, isok;
    uint32_t gb, password = 0;
    size_t size;

    //Check number of arguments
    int n = lua_gettop(L);

    switch (n) {
        case 2: {
            const char *p_gb = luaL_checklstring(L, 2, &size);
            if (size != 1)
                return returnToLuaWithError(L, "Wrong size of useGB, got %d , expected 1", (int) size);

            sscanf(p_gb, "%u", &gb);
            useGB = (gb) ? true : false;
            PrintAndLogEx(INFO, "p_gb size  %zu | %c", size, useGB ? 'Y' : 'N');
        }
        case 1: {
            const char *p_pwd = luaL_checklstring(L, 1, &size);
            if (size == 0) {
                usepwd = false;
            } else {

                if (size != 8)
                    return returnToLuaWithError(L, "Wrong size of pwd, got %d , expected 8", (int) size);

                sscanf(p_pwd, "%08x", &password);
                usepwd = true;
            }
            break;
        }
        default :
            break;
    }

    if (!useGB) {

        isok = AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, usepwd, password, 0);
        if (isok == false) {
            return returnToLuaWithError(L, "Failed to acquire LF signal data");
        }
    }

    isok = t55xxTryDetectModulation(0, true); // Default to prev. behaviour (default dl mode and print config)
    if (isok == false) {
        return returnToLuaWithError(L, "Could not detect modulation automatically. Try setting it manually with \'lf t55xx config\'");
    }

    lua_pushinteger(L, isok);
    lua_pushstring(L, "Success");
    return 2;
}

// 4305
static int l_em4x05_read(lua_State *L) {

    bool use_pwd = false;
    uint32_t addr, password = 0;

    //Check number of arguments
    //int n = lua_gettop(L);

    // get addr
    size_t size = 0;
    const char *p_addr = luaL_checklstring(L, 1, &size);
    sscanf(p_addr, "%u", &addr);

    // get password
    const char *p_pwd = luaL_checkstring(L, 2);
    if (p_pwd == NULL || strlen(p_pwd) == 0) {
        use_pwd = false;
    } else {
        if (strlen(p_pwd) != 8)
            return returnToLuaWithError(L, "Wrong size of password, got %zu , expected 8", strlen(p_pwd));

        sscanf(p_pwd, "%08x", &password);
        use_pwd = true;
    }

    PrintAndLogEx(DEBUG, "Addr %u", addr);
    if (use_pwd)
        PrintAndLogEx(DEBUG, " Pwd %08X", password);

    uint32_t word = 0;
    int res = em4x05_read_word_ext(addr, password, use_pwd, &word);
    if (res != PM3_SUCCESS) {
        return returnToLuaWithError(L, "Failed to read EM4x05 data");
    }

    lua_pushinteger(L, word);
    return 1;
}

// 4350
static int l_em4x50_read(lua_State *L) {

    // get addr
    size_t size = 0;
    const char *p_addr = luaL_checklstring(L, 1, &size);
    uint32_t addr = 0;
    sscanf(p_addr, "%u", &addr);

    if (addr > 31)
        return returnToLuaWithError(L, "Address out-of-range (0..31) got %u", addr);

    // setting up structures
    em4x50_data_t etd;
    memset(&etd, 0x00, sizeof(em4x50_data_t));
    etd.addr_given = true;
    etd.addresses = addr & 0xFF;

    // get password
    const char *p_pwd = luaL_checkstring(L, 2);
    if (p_pwd == NULL || strlen(p_pwd) == 0) {
        etd.pwd_given = false;
    } else {
        if (strlen(p_pwd) != 8)
            return returnToLuaWithError(L, "Wrong size of password, got %zu , expected 8", strlen(p_pwd));

        uint32_t pwd = 0;
        sscanf(p_pwd, "%08x", &pwd);

        PrintAndLogEx(DEBUG, " Pwd %08X", pwd);

        etd.password1 = pwd;
        etd.pwd_given = true;
    }

    PrintAndLogEx(DEBUG, "Addr %u", etd.addresses & 0xFF);
    if (etd.pwd_given)
        PrintAndLogEx(DEBUG, " Pwd %08x", etd.password1);

    em4x50_word_t words[EM4X50_NO_WORDS];

    int res = em4x50_read(&etd, words);
    if (res != PM3_SUCCESS) {
        return returnToLuaWithError(L, "Failed to read EM4x50 data");
    }

    uint32_t word = (
                        words[etd.addresses & 0xFF].byte[0] << 24 |
                        words[etd.addresses & 0xFF].byte[1] << 16 |
                        words[etd.addresses & 0xFF].byte[2] << 8 |
                        words[etd.addresses & 0xFF].byte[3]
                    );
    lua_pushinteger(L, word);

    return 1;
}

//
static int l_ndefparse(lua_State *L) {

    size_t size;

    //Check number of arguments
    int n = lua_gettop(L);
    if (n != 3)  {
        return returnToLuaWithError(L, "You need to supply three parameters");
    }

    size_t datalen = luaL_checknumber(L, 1);
    bool verbose = luaL_checknumber(L, 2);

    uint8_t *data = calloc(datalen, sizeof(uint8_t));
    if (data == 0) {
        return returnToLuaWithError(L, "Allocating memory failed");
    }

    // data
    const char *p_data = luaL_checklstring(L, 3, &size);
    if (size) {
        if (size > (datalen << 1))
            size = (datalen << 1);

        uint32_t tmp;
        for (int i = 0; i < size; i += 2) {
            sscanf(&p_data[i], "%02x", &tmp);
            data[i >> 1] = tmp & 0xFF;
        }
    }

    int res = NDEFDecodeAndPrint(data, datalen, verbose);
    lua_pushinteger(L, res);
    return 1;
}

static int l_ul_read_uid(lua_State *L) {
    uint8_t uid[7] = { 0, 0, 0, 0, 0, 0, 0 };
    int res = ul_read_uid(uid);
    if (res != PM3_SUCCESS) {
        return returnToLuaWithError(L, "Failed to read Ultralight/NTAG UID");
    }
    char buf[15];
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%02X%02X%02X%02X%02X%02X%02X", uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6]);
    lua_pushstring(L, buf);
    return 1;
}

static int l_remark(lua_State *L) {
    //Check number of arguments
    int n = lua_gettop(L);
    if (n != 1)  {
        return returnToLuaWithError(L, "Only one string allowed");
    }

    size_t size;
    const char *s = luaL_checklstring(L, 1, &size);
    int res = CmdRem(s);
    lua_pushinteger(L, res);
    return 1;
}

// 1. filename
// 2. extension
// output: full search path to file
static int l_searchfile(lua_State *L) {
    //Check number of arguments
    int n = lua_gettop(L);
    if (n != 2)  {
        return returnToLuaWithError(L, "Only filename and extension");
    }

    size_t size;
    // data
    const char *filename = luaL_checklstring(L, 1, &size);
    if (size == 0) {
        return returnToLuaWithError(L, "Must specify filename");
    }

    const char *suffix =  luaL_checklstring(L, 2, &size);
    char *path;
    int res = searchFile(&path, "", filename, suffix, false);
    if (res != PM3_SUCCESS) {
        return returnToLuaWithError(L, "Failed to find file");
    }

    lua_pushstring(L, path);
    free(path);
    return 1;
}

static int l_ud(lua_State *L) {
    const char *ud = get_my_user_directory();
    lua_pushstring(L, ud);
    return 1;
}
static int l_ewd(lua_State *L) {
    const char *ewd = get_my_executable_directory();
    lua_pushstring(L, ewd);
    return 1;
}
static int l_cwd(lua_State *L) {

    uint16_t path_len = FILENAME_MAX; // should be a good starting point
    char *cwd = (char *)calloc(path_len, sizeof(uint8_t));
    if (cwd == NULL) {
        return returnToLuaWithError(L, "Failed to allocate memory");
    }

    while (GetCurrentDir(cwd, path_len) == NULL) {
        if (errno == ERANGE) {  // Need bigger buffer
            path_len += 10;      // if buffer was too small add 10 characters and try again
            cwd = realloc(cwd, path_len);
            if (cwd == NULL) {
                free(cwd);
                return returnToLuaWithError(L, "Failed to allocate memory");
            }
        } else {
            free(cwd);
            return returnToLuaWithError(L, "Failed to get current working directory");
        }
    }
    lua_pushstring(L, cwd);
    free(cwd);
    return 1;
}

// ref:  https://github.com/RfidResearchGroup/proxmark3/issues/891
// redirect LUA's print to Proxmark3 PrintAndLogEx
static int l_printandlogex(lua_State *L) {
    int n = lua_gettop(L);
    for (int i = 1; i <= n; i++) {
        if (lua_isstring(L, i)) {
            PrintAndLogEx(NORMAL, "%s\t" NOLF, lua_tostring(L, i));
        }
    }
    PrintAndLogEx(NORMAL, "");
    return 0;
}

/**
 * @brief Sets the lua path to include "./lualibs/?.lua", in order for a script to be
 * able to do "require('foobar')" if foobar.lua is within lualibs folder.
 * Taken from http://stackoverflow.com/questions/4125971/setting-the-global-lua-path-variable-from-c-c
 * @param L
 * @param path
 * @return
 */
static int setLuaPath(lua_State *L, const char *path) {
    lua_getglobal(L, "package");
    lua_getfield(L, -1, "path");   // get field "path" from table at top of stack (-1)
    const char *cur_path = lua_tostring(L, -1);   // grab path string from top of stack
    int requiredLength = strlen(cur_path) + strlen(path) + 10; //A few bytes too many, whatever we can afford it
    char *buf = calloc(requiredLength, sizeof(char));
    snprintf(buf, requiredLength, "%s;%s", cur_path, path);
    lua_pop(L, 1);   // get rid of the string on the stack we just pushed on line 5
    lua_pushstring(L, buf);   // push the new one
    lua_setfield(L, -2, "path");   // set the field "path" in table at -2 with value at top of stack
    lua_pop(L, 1);   // get rid of package table from top of stack
    free(buf);
    return 0; // all done!
}

int set_pm3_libraries(lua_State *L) {
    static const luaL_Reg libs[] = {
        {"SendCommandMIX",              l_SendCommandMIX},
        {"SendCommandNG",               l_SendCommandNG},
        {"GetFromBigBuf",               l_GetFromBigBuf},
        {"GetFromFlashMem",             l_GetFromFlashMem},
        {"GetFromFlashMemSpiffs",       l_GetFromFlashMemSpiffs},
        {"WaitForResponseTimeout",      l_WaitForResponseTimeout},
        {"mfDarkside",                  l_mfDarkside},
        {"foobar",                      l_foobar},
        {"kbd_enter_pressed",           l_kbd_enter_pressed},
        {"clearCommandBuffer",          l_clearCommandBuffer},
        {"console",                     l_CmdConsole},
        {"iso15693_crc",                l_iso15693_crc},
        {"iso14443b_crc",               l_iso14443b_crc},
        {"aes128_decrypt",              l_aes128decrypt_cbc},
        {"aes128_decrypt_ecb",          l_aes128decrypt_ecb},
        {"aes128_encrypt",              l_aes128encrypt_cbc},
        {"aes128_encrypt_ecb",          l_aes128encrypt_ecb},
        {"crc8legic",                   l_crc8legic},
        {"crc16legic",                  l_crc16legic},
        {"crc16",                       l_crc16},
        {"crc64",                       l_crc64},
        {"crc64_ecma182",               l_crc64_ecma182},
        {"sha1",                        l_sha1},
        {"reveng_models",               l_reveng_models},
        {"reveng_runmodel",             l_reveng_runmodel},
        {"hardnested",                  l_hardnested},
        {"detect_prng",                 l_detect_prng},
//        {"keygen.algoA",                l_keygen_algoA},
        {"keygen_algo_b",               l_keygen_algoB},
//        {"keygen.algoC",                l_keygen_algoC},
        {"keygen_algo_d",               l_keygen_algoD},
        {"t55xx_readblock",             l_T55xx_readblock},
        {"t55xx_detect",                l_T55xx_detect},
        {"ndefparse",                   l_ndefparse},
        {"fast_push_mode",              l_fast_push_mode},
        {"search_file",                 l_searchfile},
        {"cwd",                         l_cwd},
        {"ewd",                         l_ewd},
        {"ud",                          l_ud},
        {"rem",                         l_remark},
        {"em4x05_read",                 l_em4x05_read},
        {"em4x50_read",                 l_em4x50_read},
        {"ul_read_uid",                 l_ul_read_uid},
        {NULL, NULL}
    };

    lua_pushglobaltable(L);
    // Core library is in this table. Contains '
    // this is 'pm3' table
    lua_newtable(L);

    // put the function into the hash table.
    for (int i = 0; libs[i].name; i++) {
        lua_pushcfunction(L, libs[i].func);
        lua_setfield(L, -2, libs[i].name);//set the name, pop stack
    }
    // Name of 'core'
    lua_setfield(L, -2, "core");

    // remove the global environment table from the stack
    lua_pop(L, 1);

    // print redirect here
    lua_register(L, "print", l_printandlogex);

    // add to the LUA_PATH (package.path in lua)
    // so we can load scripts from various places:
    const char *exec_path = get_my_executable_directory();
    if (exec_path != NULL) {
        // from the ./luascripts/ directory
        char scripts_path[strlen(exec_path) + strlen(LUA_SCRIPTS_SUBDIR) + strlen(LUA_LIBRARIES_WILDCARD) + 1];
        strcpy(scripts_path, exec_path);
        strcat(scripts_path, LUA_SCRIPTS_SUBDIR);
        strcat(scripts_path, LUA_LIBRARIES_WILDCARD);
        setLuaPath(L, scripts_path);
        // from the ./lualib/ directory
        char libraries_path[strlen(exec_path) + strlen(LUA_LIBRARIES_SUBDIR) + strlen(LUA_LIBRARIES_WILDCARD) + 1];
        strcpy(libraries_path, exec_path);
        strcat(libraries_path, LUA_LIBRARIES_SUBDIR);
        strcat(libraries_path, LUA_LIBRARIES_WILDCARD);
        setLuaPath(L, libraries_path);
    }
    const char *user_path = get_my_user_directory();
    if (user_path != NULL) {
        // from the $HOME/.proxmark3/luascripts/ directory
        char scripts_path[strlen(user_path) + strlen(PM3_USER_DIRECTORY) + strlen(LUA_SCRIPTS_SUBDIR) + strlen(LUA_LIBRARIES_WILDCARD) + 1];
        strcpy(scripts_path, user_path);
        strcat(scripts_path, PM3_USER_DIRECTORY);
        strcat(scripts_path, LUA_SCRIPTS_SUBDIR);
        strcat(scripts_path, LUA_LIBRARIES_WILDCARD);
        setLuaPath(L, scripts_path);

        // from the $HOME/.proxmark3/lualib/ directory
        char libraries_path[strlen(user_path) + strlen(PM3_USER_DIRECTORY) + strlen(LUA_LIBRARIES_SUBDIR) + strlen(LUA_LIBRARIES_WILDCARD) + 1];
        strcpy(libraries_path, user_path);
        strcat(libraries_path, PM3_USER_DIRECTORY);
        strcat(libraries_path, LUA_LIBRARIES_SUBDIR);
        strcat(libraries_path, LUA_LIBRARIES_WILDCARD);
        setLuaPath(L, libraries_path);
    }

    if (exec_path != NULL) {
        // from the $PREFIX/share/proxmark3/luascripts/ directory
        char scripts_path[strlen(exec_path) + strlen(PM3_SHARE_RELPATH) + strlen(LUA_SCRIPTS_SUBDIR) + strlen(LUA_LIBRARIES_WILDCARD) + 1];
        strcpy(scripts_path, exec_path);
        strcat(scripts_path, PM3_SHARE_RELPATH);
        strcat(scripts_path, LUA_SCRIPTS_SUBDIR);
        strcat(scripts_path, LUA_LIBRARIES_WILDCARD);
        setLuaPath(L, scripts_path);
        // from the $PREFIX/share/proxmark3/lualib/ directory
        char libraries_path[strlen(exec_path) + strlen(PM3_SHARE_RELPATH) + strlen(LUA_LIBRARIES_SUBDIR) + strlen(LUA_LIBRARIES_WILDCARD) + 1];
        strcpy(libraries_path, exec_path);
        strcat(libraries_path, PM3_SHARE_RELPATH);
        strcat(libraries_path, LUA_LIBRARIES_SUBDIR);
        strcat(libraries_path, LUA_LIBRARIES_WILDCARD);
        setLuaPath(L, libraries_path);
    }
    return 1;
}
