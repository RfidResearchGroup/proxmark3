//-----------------------------------------------------------------------------
// Copyright (C) 2013 m h swende <martin at swende.se>
// Modified 2015,2016, iceman 
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Some lua scripting glue to proxmark core.
//-----------------------------------------------------------------------------
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
    size_t size;
    const char *data = luaL_checklstring(L, 1, &size);
    if (size != sizeof(UsbCommand)) {
		printf("Got data size %d, expected %d" , (int) size,(int) sizeof(UsbCommand));
        lua_pushstring(L,"Wrong data size");
        return 1;
    }

    SendCommand((UsbCommand* )data);
    return 0; // no return values
}

/**
 * @brief The following params expected:
 * uint8_t *dest
 * int bytes
 * int start_index
 * @param L
 * @return
 */
static int l_GetFromBigBuf(lua_State *L){
	
	int len = 0;
    int startindex = 0;
	
    //Check number of arguments
    int n = lua_gettop(L);
    if(n == 0) {
        //signal error by returning Nil, errorstring
        lua_pushnil(L);
        lua_pushstring(L,"You need to supply number of len and startindex");
        return 2; // two return values
    }
    if(n >= 2) {
        len = luaL_checknumber(L, 1);
        startindex = luaL_checknumber(L, 2);
    }

	uint8_t *data = calloc(len, sizeof(uint8_t));
	if ( !data ) {
        //signal error by returning Nil, errorstring
        lua_pushnil(L);
        lua_pushstring(L,"Allocating memory failed");
        return 2; // two return values
	}
		
	if ( !GetFromDevice(BIG_BUF, data, len, startindex, NULL, 2500, false)) {
		free(data);
		lua_pushnil(L);
        lua_pushstring(L,"command execution time out");		
		return 2;
	}
	
	//Push it as a string
	lua_pushlstring(L,(const char *)data, len);
	free(data);
	return 1;// return 1 to signal one return value
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
    if (n == 0)  {
        //signal error by returning Nil, errorstring
        lua_pushnil(L);
        lua_pushstring(L, "You need to supply at least command to wait for");
        return 2;
    }
	
	// extract first param.  cmd byte to look for
    if (n >= 1) {
        cmd = luaL_checkunsigned(L, 1);
    }
	// extract second param. timeout value
    if(n >= 2){
        ms_timeout = luaL_checkunsigned(L, 2);
    }

    UsbCommand response;
    if (WaitForResponseTimeout(cmd, &response, ms_timeout)) {
        //Push it as a string
        lua_pushlstring(L,(const char *)&response, sizeof(UsbCommand));
        return 1;
    } else {
        //signal error by returning Nil, errorstring
        lua_pushnil(L);
		lua_pushstring(L, "No response from the device");
        return 2;
    }
}

static int returnToLuaWithError(lua_State *L, const char* fmt, ...) {
    char buffer[200];
    va_list args;
    va_start(args,fmt);
    vsnprintf(buffer, sizeof(buffer), fmt,args);
    va_end(args);

    lua_pushnil(L);
    lua_pushstring(L,buffer);
    return 2;
}

static int l_mfDarkside(lua_State *L){

	uint32_t blockno = 0;
	uint32_t keytype = MIFARE_AUTH_KEYA;
	uint64_t key = 0;
	size_t size;

    //Check number of arguments
    int n = lua_gettop(L);
	switch (n) {
		case 2:{
			const char *p_keytype = luaL_checklstring(L, 2, &size);
			if (size != 2)  return returnToLuaWithError(L,"Wrong size of keytype, got %d bytes, expected 1", (int) size);
			sscanf(p_keytype, "%x", &keytype);			
		}
		case 1: {
			const char *p_blockno = luaL_checklstring(L, 1, &size);
			if (size != 2)  return returnToLuaWithError(L,"Wrong size of blockno, got %d bytes, expected 2", (int) size);
			sscanf(p_blockno, "%02x", &blockno);
			break;
		}
		default : break;
	}

	int retval = mfDarkside(blockno & 0xFF, keytype & 0xFF, &key);

    uint8_t dest_key[8];
    num_to_bytes(key, sizeof(dest_key), dest_key);
	
    //Push the retval on the stack
    lua_pushinteger(L, retval);
    lua_pushlstring(L, (const char *) dest_key, sizeof(dest_key));
    return 2;
}

static int l_clearCommandBuffer(lua_State *L){
    clearCommandBuffer();
    return 0;
}
/**
 * @brief l_foobar is a dummy function to test lua-integration with
 * @param L
 * @return
 */
static int l_foobar(lua_State *L) {
    //Check number of arguments
    int n = lua_gettop(L);
    printf("foobar called with %d arguments" , n);
    lua_settop(L, 0);
    printf("Arguments discarded, stack now contains %d elements", lua_gettop(L));

    // todo: this is not used, where was it intended for?
    // UsbCommand response =  {CMD_MIFARE_READBL, {1337, 1338, 1339}};

    printf("Now returning a uint64_t as a string");
    uint64_t x = 0xDEADC0DE;
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
static int l_ukbhit(lua_State *L) {
    lua_pushboolean(L, ukbhit() ? true : false);
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
    size_t size;
    const char *v = luaL_checklstring(L, 1, &size);
	// iceman, should be size / 2 ?!?
    lua_pushunsigned(L, crc( CRC_15693, (uint8_t *) v, size));
    return 1;
}

static int l_iso14443b_crc(lua_State *L) {
	uint32_t tmp;
	unsigned char buf[USB_CMD_DATA_SIZE] = {0x00};
    size_t size = 0;	
    const char *data = luaL_checklstring(L, 1, &size);
	
	for (int i = 0; i < size; i += 2) {
		sscanf(&data[i], "%02x", &tmp);
		buf[i / 2] = tmp & 0xFF;
	}
	
	size /= 2;	
	compute_crc(CRC_14443_B, buf, size, &buf[size], &buf[size+1]);	
    lua_pushlstring(L, (const char *)&buf, size+2);
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
    if (size != 32)  return returnToLuaWithError(L,"Wrong size of key, got %d bytes, expected 32", (int) size);

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

    aes_context ctx;
    aes_init(&ctx);
	aes_setkey_dec(&ctx, aes_key, 128);
	aes_crypt_cbc(&ctx, AES_DECRYPT, sizeof(indata), iv, indata, outdata );
    //Push decrypted array as a string
	lua_pushlstring(L,(const char *)&outdata, sizeof(outdata));
	return 1;// return 1 to signal one return value
}
static int l_aes128decrypt_ecb(lua_State *L) {
	//Check number of arguments
	int i;
	uint32_t tmp;
    size_t size;
    const char *p_key = luaL_checklstring(L, 1, &size);
    if (size != 32)  return returnToLuaWithError(L,"Wrong size of key, got %d bytes, expected 32", (int) size);

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
    aes_context ctx;
    aes_init(&ctx);
	aes_setkey_dec(&ctx, aes_key, 128);
	aes_crypt_ecb(&ctx, AES_DECRYPT, indata, outdata );

    //Push decrypted array as a string
	lua_pushlstring(L,(const char *)&outdata, sizeof(outdata));
	return 1;// return 1 to signal one return value
}

static int l_aes128encrypt_cbc(lua_State *L) {
	//Check number of arguments
	int i;
	uint32_t tmp;
    size_t size;
    const char *p_key = luaL_checklstring(L, 1, &size);
    if (size != 32)  return returnToLuaWithError(L,"Wrong size of key, got %d bytes, expected 32", (int) size);

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

    aes_context ctx;
    aes_init(&ctx);
	aes_setkey_enc(&ctx, aes_key, 128);
	aes_crypt_cbc(&ctx, AES_ENCRYPT, sizeof(indata), iv, indata, outdata );
	//Push encrypted array as a string
	lua_pushlstring(L,(const char *)&outdata, sizeof(outdata));
	return 1;// return 1 to signal one return value
}

static int l_aes128encrypt_ecb(lua_State *L) {
	//Check number of arguments
	int i;
	uint32_t tmp;
    size_t size;
    const char *p_key = luaL_checklstring(L, 1, &size);
    if (size != 32) return returnToLuaWithError(L,"Wrong size of key, got %d bytes, expected 32", (int) size);

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
    aes_context ctx;
    aes_init(&ctx);
	aes_setkey_enc(&ctx, aes_key, 128);
	aes_crypt_ecb(&ctx, AES_ENCRYPT, indata, outdata );
	//Push encrypted array as a string
	lua_pushlstring(L,(const char *)&outdata, sizeof(outdata));
	return 1;// return 1 to signal one return value
}

static int l_crc8legic(lua_State *L) {
	size_t size;
	const char *p_str = luaL_checklstring(L, 1, &size);

	uint16_t retval = CRC8Legic( (uint8_t*) p_str, size);
    lua_pushunsigned(L, retval);
    return 1;
}

static int l_crc16(lua_State *L) {
	size_t size;
	const char *p_str = luaL_checklstring(L, 1, &size);

	uint16_t checksum = crc(CRC_CCITT,  (uint8_t*) p_str, size);
    lua_pushunsigned(L, checksum);
    return 1;
}

static int l_crc64(lua_State *L) {
	size_t size;
	uint64_t crc = 0; 
	unsigned char outdata[8] = {0x00};

	const char *p_str = luaL_checklstring(L, 1, &size);

	crc64( (uint8_t*) p_str, size, &crc);

	outdata[0] = (uint8_t)(crc >> 56) & 0xff;
	outdata[1] = (uint8_t)(crc >> 48) & 0xff;
	outdata[2] = (uint8_t)(crc >> 40) & 0xff;
	outdata[3] = (uint8_t)(crc >> 32) & 0xff;
	outdata[4] = (uint8_t)(crc >> 24) & 0xff;
	outdata[5] = (uint8_t)(crc >> 16) & 0xff;
	outdata[6] = (uint8_t)(crc >> 8) & 0xff;
	outdata[7] = crc & 0xff;
	lua_pushlstring(L,(const char *)&outdata, sizeof(outdata));
	return 1;
}

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
    sha1( (uint8_t*) p_str, size, outdata);                                                                                                                                                                 
    lua_pushlstring(L, (const char *)&outdata, sizeof(outdata));
    return 1;	
}

static int l_reveng_models(lua_State *L){

	int count = 0;
	uint8_t in_width = luaL_checkunsigned(L, 1);
	if ( in_width > 89 ) return returnToLuaWithError(L,"Width cannot exceed 89, got %d", in_width);

	// This array needs to be adjusted if RevEng adds more crc-models.
	uint8_t width[102];
	memset(width, 0, sizeof(width));
	// This array needs to be adjusted if RevEng adds more crc-models.
	char *models[102];

	width[0] = in_width;
	
	if (!GetModels(models, &count, width))
		return returnToLuaWithError(L, "didn't find any models");
	
	lua_newtable(L);	
	for (int i = 0; i < count; i++){
		lua_pushstring(L,  (const char*)models[i]);
		lua_rawseti(L,-2,i+1);
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
static int l_reveng_RunModel(lua_State *L){
	//-c || -v
	//inModel = valid model name string - CRC-8
	//inHexStr = input hex string to calculate crc on
	//reverse = reverse calc option if true
	//endian = {0 = calc default endian input and output, b = big endian input and output, B = big endian output, r = right justified
	//          l = little endian input and output, L = little endian output only, t = left justified}
	//result = calculated crc hex string	
	char result[50];
	
	const char *inModel = luaL_checkstring(L, 1);
	const char *inHexStr = luaL_checkstring(L, 2);
    bool reverse =  lua_toboolean(L, 3);
	const char endian = luaL_checkstring(L, 4)[0];

	int ans = RunModel( (char *)inModel, (char *)inHexStr, reverse, endian, result);
	if (!ans) 	
		return returnToLuaWithError(L,"Reveng failed");

	lua_pushstring(L, (const char*)result); 
	return 1;
}

static int l_hardnested(lua_State *L){

	bool haveTarget = true;
    size_t size;
	uint32_t tmp;
    const char *p_blockno = luaL_checklstring(L, 1, &size);
    if(size != 2)  return returnToLuaWithError(L,"Wrong size of blockNo, got %d bytes, expected 2", (int) size);

    const char *p_keytype = luaL_checklstring(L, 2, &size);
    if(size != 1)  return returnToLuaWithError(L,"Wrong size of keyType, got %d bytes, expected 1", (int) size);

	const char *p_key = luaL_checklstring(L, 3, &size);
    if(size != 12)  return returnToLuaWithError(L,"Wrong size of key, got %d bytes, expected 12", (int) size);
	
    const char *p_trg_blockno = luaL_checklstring(L, 4, &size);
    if(size != 2)  return returnToLuaWithError(L,"Wrong size of trgBlockNo, got %d bytes, expected 2", (int) size);

    const char *p_trg_keytype = luaL_checklstring(L, 5, &size);
    if(size != 1)  return returnToLuaWithError(L,"Wrong size of trgKeyType, got %d bytes, expected 1", (int) size);

    const char *p_trgkey = luaL_checklstring(L, 6, &size);
    if(size != 12)
		haveTarget = false;

	const char *p_nonce_file_read = luaL_checklstring(L, 7, &size);
    if(size != 1)  return returnToLuaWithError(L,"Wrong size of nonce_file_read, got %d bytes, expected 1", (int) size);

	const char *p_nonce_file_write = luaL_checklstring(L, 8, &size);
    if(size != 1)  return returnToLuaWithError(L,"Wrong size of nonce_file_write, got %d bytes, expected 1", (int) size);

	const char *p_slow = luaL_checklstring(L, 9, &size);
    if(size != 1)  return returnToLuaWithError(L,"Wrong size of slow, got %d bytes, expected 1", (int) size);

	const char *p_tests = luaL_checklstring(L, 10, &size);
    if(size != 1)  return returnToLuaWithError(L,"Wrong size of tests, got %d bytes, expected 1", (int) size);
	
	char filename[FILE_PATH_SIZE]="nonces.bin";
	const char *p_filename = luaL_checklstring(L, 11, &size);
	if(size != 0)
		strcpy(filename, p_filename);

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

	uint8_t key[6] = {0,0,0,0,0,0};
    uint8_t trgkey[6] = {0,0,0,0,0,0};
	for (int i = 0; i < 32; i += 2) {
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
    lua_pushinteger(L,retval);
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
 * @brief l_keygen_algoD is a function to calculate pwd/pack using UID, by algo D
 * @param L
 * @return
 */
static int l_keygen_algoD(lua_State *L) {
	size_t size;
	uint32_t tmp;
    const char *p_uid = luaL_checklstring(L, 1, &size);
	if (size != 14) return returnToLuaWithError(L,"Wrong size of UID, got %d bytes, expected 14", (int) size);

	uint8_t uid[7] = {0,0,0,0,0,0,0};

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

/**
 * @brief Sets the lua path to include "./lualibs/?.lua", in order for a script to be
 * able to do "require('foobar')" if foobar.lua is within lualibs folder.
 * Taken from http://stackoverflow.com/questions/4125971/setting-the-global-lua-path-variable-from-c-c
 * @param L
 * @param path
 * @return
 */
int setLuaPath( lua_State* L, const char* path ) {
    lua_getglobal( L, "package" );
    lua_getfield( L, -1, "path" ); // get field "path" from table at top of stack (-1)
    const char* cur_path = lua_tostring( L, -1 ); // grab path string from top of stack
    int requiredLength = strlen(cur_path)+ strlen(path)+10; //A few bytes too many, whatever we can afford it
    char * buf = calloc(requiredLength, sizeof(char));
    snprintf(buf, requiredLength, "%s;%s", cur_path, path);
    lua_pop( L, 1 ); // get rid of the string on the stack we just pushed on line 5
    lua_pushstring( L, buf ); // push the new one
    lua_setfield( L, -2, "path" ); // set the field "path" in table at -2 with value at top of stack
    lua_pop( L, 1 ); // get rid of package table from top of stack
	free(buf);
	return 0; // all done!
}

int set_pm3_libraries(lua_State *L) {
    static const luaL_Reg libs[] = {
        {"SendCommand",                 l_SendCommand},
		{"GetFromBigBuf",               l_GetFromBigBuf},
        {"WaitForResponseTimeout",      l_WaitForResponseTimeout},
		{"mfDarkside",                  l_mfDarkside},
        {"foobar",                      l_foobar},
        {"ukbhit",                      l_ukbhit},
        {"clearCommandBuffer",          l_clearCommandBuffer},
		{"console",                     l_CmdConsole},
		{"iso15693_crc",                l_iso15693_crc},
		{"iso14443b_crc",				l_iso14443b_crc},
		{"aes128_decrypt",              l_aes128decrypt_cbc},
		{"aes128_decrypt_ecb",          l_aes128decrypt_ecb},
		{"aes128_encrypt",              l_aes128encrypt_cbc},		
		{"aes128_encrypt_ecb",          l_aes128encrypt_ecb},
		{"crc8legic",					l_crc8legic},
		{"crc16",                       l_crc16},
		{"crc64",                       l_crc64},
		{"crc64_ecma182",				l_crc64_ecma182},
		{"sha1",						l_sha1},
		{"reveng_models",				l_reveng_models},
		{"reveng_runmodel",				l_reveng_RunModel},
		{"hardnested",					l_hardnested},
		{"detect_prng",					l_detect_prng},
//		{"keygen.algoA",				l_keygen_algoA},
//		{"keygen.algoB",				l_keygen_algoB},
//		{"keygen.algoC",				l_keygen_algoC},
		{"keygen_algo_d",				l_keygen_algoD},
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
	char libraries_path[strlen(get_my_executable_directory()) + strlen(LUA_LIBRARIES_DIRECTORY) + strlen(LUA_LIBRARIES_WILDCARD) + 1];
	strcpy(libraries_path, get_my_executable_directory());
	strcat(libraries_path, LUA_LIBRARIES_DIRECTORY);
	strcat(libraries_path, LUA_LIBRARIES_WILDCARD);
	setLuaPath(L, libraries_path);

    return 1;
}