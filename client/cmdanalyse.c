//-----------------------------------------------------------------------------
// Copyright (C) 2016 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Analyse bytes commands
//-----------------------------------------------------------------------------
#include "cmdanalyse.h"

static int CmdHelp(const char *Cmd);

int usage_analyse_lcr(void) {
	PrintAndLog("Specifying the bytes of a UID with a known LRC will find the last byte value");
	PrintAndLog("needed to generate that LRC with a rolling XOR. All bytes should be specified in HEX.");
	PrintAndLog("");
	PrintAndLog("Usage:  analyse lcr [h] <bytes>");
	PrintAndLog("Options:");
	PrintAndLog("           h          This help");
	PrintAndLog("           <bytes>    bytes to calc missing XOR in a LCR");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("           analyse lcr 04008064BA");
	PrintAndLog("expected output: Target (BA) requires final LRC XOR byte value: 5A");
	return 0;
}

int usage_analyse_checksum(void) {
	PrintAndLog("The bytes will be added with eachother and than limited with the applied mask");
	PrintAndLog("Finally compute ones' complement of the least significant bytes");
	PrintAndLog("");
	PrintAndLog("Usage:  analyse chksum [h] b <bytes> m <mask>");
	PrintAndLog("Options:");
	PrintAndLog("           h          This help");
	PrintAndLog("           b <bytes>  bytes to calc missing XOR in a LCR");
	PrintAndLog("           m <mask>   bit mask to limit the outpuyt");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("           analyse chksum b 137AF00A0A0D m FF");
	PrintAndLog("expected output: 0x61");
	return 0;
}

int usage_analyse_crc(void){
	PrintAndLog("A stub method to test different crc implementations inside the PM3 sourcecode. Just because you figured out the poly, doesn't mean you get the desired output");
	PrintAndLog("");
	PrintAndLog("Usage:  analyse crc [h] <bytes>");
	PrintAndLog("Options:");
	PrintAndLog("           h          This help");
	PrintAndLog("           <bytes>    bytes to calc crc");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("           analyse crc 137AF00A0A0D");
	return 0;
}

static uint8_t calculateLRC( uint8_t* bytes, uint8_t len) {
    uint8_t LRC = 0;
    for (uint8_t i = 0; i < len; i++)
        LRC ^= bytes[i];
    return LRC;
}

static uint8_t calcSumCrumbAdd( uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum += CRUMB(bytes[i], 0);
		sum += CRUMB(bytes[i], 2);
		sum += CRUMB(bytes[i], 4);
		sum += CRUMB(bytes[i], 6);
	}
	sum &= mask;	
    return sum;
}
static uint8_t calcSumCrumbAddOnes( uint8_t* bytes, uint8_t len, uint32_t mask) {
	return ~calcSumCrumbAdd(bytes, len, mask);
}
static uint8_t calcSumNibbleAdd( uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum += NIBBLE_LOW(bytes[i]);
		sum += NIBBLE_HIGH(bytes[i]);
	}
	sum &= mask;	
    return sum;
}
static uint8_t calcSumNibbleAddOnes( uint8_t* bytes, uint8_t len, uint32_t mask){
	return ~calcSumNibbleAdd(bytes, len, mask);
}

static uint8_t calcSumByteAdd( uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < len; i++)
        sum += bytes[i];
	sum &= mask;	
    return sum;
}
// Ones complement
static uint8_t calcSumByteAddOnes( uint8_t* bytes, uint8_t len, uint32_t mask) {
	return ~calcSumByteAdd(bytes, len, mask);
}

static uint8_t calcSumByteSub( uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < len; i++)
        sum -= bytes[i];
	sum &= mask;	
    return sum;
}
static uint8_t calcSumByteSubOnes( uint8_t* bytes, uint8_t len, uint32_t mask){
	return ~calcSumByteSub(bytes, len, mask);
}
static uint8_t calcSumNibbleSub( uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum -= NIBBLE_LOW(bytes[i]);
		sum -= NIBBLE_HIGH(bytes[i]);
	}
	sum &= mask;	
    return sum;
}
static uint8_t calcSumNibbleSubOnes( uint8_t* bytes, uint8_t len, uint32_t mask) {
	return ~calcSumNibbleSub(bytes, len, mask);
}

int CmdAnalyseLCR(const char *Cmd) {
	uint8_t data[50];
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0|| cmdp == 'h' || cmdp == 'H') return usage_analyse_lcr();
	
	int len = 0;
	param_gethex_ex(Cmd, 0, data, &len);
	if ( len%2 ) return usage_analyse_lcr();
	len >>= 1;	
	uint8_t finalXor = calculateLRC(data, len);
	PrintAndLog("Target [%02X] requires final LRC XOR byte value: 0x%02X",data[len-1] ,finalXor);
	return 0;
}
int CmdAnalyseCRC(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_analyse_crc();
	
	int len = strlen(Cmd);
	if ( len & 1 ) return usage_analyse_crc();
	
	// add 1 for null terminator.
	uint8_t *data = malloc(len+1);
	if ( data == NULL ) return 1;

	if ( param_gethex(Cmd, 0, data, len)) {
		free(data);
		return usage_analyse_crc();
	}
	len >>= 1;	

	//PrintAndLog("\nTests with '%s' hex bytes", sprint_hex(data, len));
	
	PrintAndLog("\nTests of reflection. Two current methods in source code");	
	PrintAndLog("   reflect(0x3e23L,3) is %04X == 0x3e26", reflect(0x3e23L,3) );
	PrintAndLog("  SwapBits(0x3e23L,3) is %04X == 0x3e26", SwapBits(0x3e23L,3) );
	PrintAndLog("  0xB400 == %04X", reflect( (1 << 16 | 0xb400),16) );

	//
	// Test of CRC16,  '123456789' string.
	//
	PrintAndLog("\nTests with '123456789' string");
	uint8_t dataStr[] = { 0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39 };
	uint8_t legic8 = CRC8Legic(dataStr, sizeof(dataStr));
	
	PrintAndLog("LEGIC: CRC16: %X", CRC16Legic(dataStr, sizeof(dataStr), legic8));

	//these below has been tested OK.
	PrintAndLog("Confirmed CRC Implementations");
	PrintAndLog("LEGIC: CRC8 : %X (0xC6 expected)", legic8);
	PrintAndLog("MAXIM: CRC8 : %X (0xA1 expected)", CRC8Maxim(dataStr, sizeof(dataStr)));
	PrintAndLog("DNP  : CRC16: %X (0x82EA expected)", CRC16_DNP(dataStr, sizeof(dataStr)));	
	PrintAndLog("CCITT: CRC16: %X (0xE5CC expected)", CRC16_CCITT(dataStr, sizeof(dataStr)));

	PrintAndLog("ICLASS org: CRC16: %X (0x expected)",iclass_crc16( (char*)dataStr, sizeof(dataStr)));
	PrintAndLog("ICLASS ice: CRC16: %X (0x expected)",CRC16_ICLASS(dataStr, sizeof(dataStr)));



	uint8_t dataStr1234[] = { 0x1,0x2,0x3,0x4};
	PrintAndLog("ISO15693 org:  : CRC16: %X (0xF0B8 expected)", Iso15693Crc(dataStr1234, sizeof(dataStr1234)));
	PrintAndLog("ISO15693 ice:  : CRC16: %X (0xF0B8 expected)", CRC16_Iso15693(dataStr1234, sizeof(dataStr1234)));

	free(data);
	return 0;
}
int CmdAnalyseCHKSUM(const char *Cmd){
	
	uint8_t data[50];
	uint8_t cmdp = 0;
	uint32_t mask = 0xFF;
	bool errors = false;
	int len = 0;
	memset(data, 0x0, sizeof(data));
	
	while(param_getchar(Cmd, cmdp) != 0x00) {
		switch(param_getchar(Cmd, cmdp)) {
		case 'b':
		case 'B':
			param_gethex_ex(Cmd, cmdp+1, data, &len);
			if ( len%2 ) errors = true;
			len >>= 1;	
			cmdp += 2;
			break;
		case 'm':
		case 'M':		 
			mask = param_get32ex(Cmd, cmdp+1, 0, 16);
			cmdp += 2;
			break;
		case 'h':
		case 'H':
			return usage_analyse_checksum();
		default:
			PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
		if(errors) break;
	}
	//Validations
	if(errors) return usage_analyse_checksum();
	
	PrintAndLog("\nByte Add        | 0x%X", calcSumByteAdd(data, len, mask));
	PrintAndLog("Nibble Add      | 0x%X", calcSumNibbleAdd(data, len, mask));
	PrintAndLog("Crumb Add       | 0x%X", calcSumCrumbAdd(data, len, mask));
	
	PrintAndLog("\nByte Subtract   | 0x%X", calcSumByteSub(data, len, mask));
	PrintAndLog("Nibble Subtract | 0x%X", calcSumNibbleSub(data, len, mask));
	
	PrintAndLog("\nCHECKSUM - One's complement");
	PrintAndLog("Byte Add        | 0x%X", calcSumByteAddOnes(data, len, mask));
	PrintAndLog("Nibble Add      | 0x%X", calcSumNibbleAddOnes(data, len, mask));
	PrintAndLog("Crumb Add       | 0x%X", calcSumCrumbAddOnes(data, len, mask));

	PrintAndLog("Byte Subtract   | 0x%X", calcSumByteSubOnes(data, len, mask));
	PrintAndLog("Nibble Subtract | 0x%X", calcSumNibbleSubOnes(data, len, mask));
	
	return 0;
}

int CmdAnalyseDates(const char *Cmd){
	// look for datestamps in a given array of bytes
	PrintAndLog("To be implemented. Feel free to contribute!");
	return 0;
}
int CmdAnalyseTEASelfTest(const char *Cmd){
	
	uint8_t v[8], v_le[8];
	memset(v, 0x00, sizeof(v));
	memset(v_le, 0x00, sizeof(v_le));
	uint8_t* v_ptr = v_le;

	uint8_t cmdlen = strlen(Cmd);
	cmdlen = ( sizeof(v)<<2 < cmdlen ) ? sizeof(v)<<2 : cmdlen;
	
	if ( param_gethex(Cmd, 0, v, cmdlen) > 0 ){
		PrintAndLog("can't read hex chars, uneven? :: %u", cmdlen);
		return 1;
	}
	
	SwapEndian64ex(v , 8, 4, v_ptr);
	
	// ENCRYPTION KEY:	
	uint8_t key[16] = {0x55,0xFE,0xF6,0x30,0x62,0xBF,0x0B,0xC1,0xC9,0xB3,0x7C,0x34,0x97,0x3E,0x29,0xFB };
	uint8_t keyle[16];
	uint8_t* key_ptr = keyle;
	SwapEndian64ex(key , sizeof(key), 4, key_ptr);
	
	PrintAndLog("TEST LE enc| %s", sprint_hex(v_ptr, 8));
	
	tea_decrypt(v_ptr, key_ptr);	
	PrintAndLog("TEST LE dec | %s", sprint_hex_ascii(v_ptr, 8));
	
	tea_encrypt(v_ptr, key_ptr);	
	tea_encrypt(v_ptr, key_ptr);
	PrintAndLog("TEST enc2 | %s", sprint_hex_ascii(v_ptr, 8));

	return 0;
}

static command_t CommandTable[] = {
	{"help",	CmdHelp,            1, "This help"},
	{"lcr",		CmdAnalyseLCR,		1, "Generate final byte for XOR LRC"},
	{"crc",		CmdAnalyseCRC,		1, "Stub method for CRC evaluations"},
	{"chksum",	CmdAnalyseCHKSUM,	1, "Checksum with adding, masking and one's complement"},
	{"dates",	CmdAnalyseDates,	1, "Look for datestamps in a given array of bytes"},
	{"tea",   	CmdAnalyseTEASelfTest,	1, "Crypto TEA test"},
	{NULL, NULL, 0, NULL}
};

int CmdAnalyse(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
