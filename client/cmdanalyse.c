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
	PrintAndLog("      analyse lcr 04008064BA");
	PrintAndLog("expected output: Target (BA) requires final LRC XOR byte value: 5A");
	return 0;
}
int usage_analyse_checksum(void) {
	PrintAndLog("The bytes will be added with eachother and than limited with the applied mask");
	PrintAndLog("Finally compute ones' complement of the least significant bytes");
	PrintAndLog("");
	PrintAndLog("Usage:  analyse chksum [h] [v] b <bytes> m <mask>");
	PrintAndLog("Options:");
	PrintAndLog("           h          This help");
	PrintAndLog("           v          supress header");
	PrintAndLog("           b <bytes>  bytes to calc missing XOR in a LCR");
	PrintAndLog("           m <mask>   bit mask to limit the outpuyt");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      analyse chksum b 137AF00A0A0D m FF");
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
	PrintAndLog("      analyse crc 137AF00A0A0D");
	return 0;
}
int usage_analyse_hid(void){
	PrintAndLog("Permute function from 'heart of darkness' paper.");
	PrintAndLog("");
	PrintAndLog("Usage:  analyse hid [h] <r|f> <bytes>");
	PrintAndLog("Options:");
	PrintAndLog("           h          This help");
	PrintAndLog("           r          reverse permuted key");
	PrintAndLog("           f          permute key");
	PrintAndLog("           <bytes>    input bytes");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      analyse hid r 0123456789abcdef");
	return 0;
}
int usage_analyse_nuid(void){
	PrintAndLog("Generate 4byte NUID from 7byte UID");
	PrintAndLog("");
	PrintAndLog("Usage:  analyse hid [h] <bytes>");
	PrintAndLog("Options:");
	PrintAndLog("           h          This help");
	PrintAndLog("           <bytes>  input bytes (14 hexsymbols)");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("      analyse nuid 11223344556677");
	return 0;
}

static uint8_t calculateLRC( uint8_t* bytes, uint8_t len) {
    uint8_t LRC = 0;
    for (uint8_t i = 0; i < len; i++)
        LRC ^= bytes[i];
    return LRC;
}
/*
static uint16_t matrixadd ( uint8_t* bytes, uint8_t len){
      -----------
 0x9c | 1001 1100
 0x97 | 1001 0111
 0x72 | 0111 0010
 0x5e | 0101 1110
 -----------------
        C32F 9d74 

	return 0;
}
*/
/*
static uint16_t shiftadd ( uint8_t* bytes, uint8_t len){
	return 0;
}
*/
static uint16_t calcSumCrumbAdd( uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum += CRUMB(bytes[i], 0);
		sum += CRUMB(bytes[i], 2);
		sum += CRUMB(bytes[i], 4);
		sum += CRUMB(bytes[i], 6);
	}
	sum &= mask;	
    return sum;
}
static uint16_t calcSumCrumbAddOnes( uint8_t* bytes, uint8_t len, uint32_t mask) {
	return (~calcSumCrumbAdd(bytes, len, mask) & mask);
}
static uint16_t calcSumNibbleAdd( uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum += NIBBLE_LOW(bytes[i]);
		sum += NIBBLE_HIGH(bytes[i]);
	}
	sum &= mask;	
    return sum;
}
static uint16_t calcSumNibbleAddOnes( uint8_t* bytes, uint8_t len, uint32_t mask){
	return (~calcSumNibbleAdd(bytes, len, mask) & mask);
}
static uint16_t calcSumCrumbXor(  uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum ^= CRUMB(bytes[i], 0);
		sum ^= CRUMB(bytes[i], 2);
		sum ^= CRUMB(bytes[i], 4);
		sum ^= CRUMB(bytes[i], 6);
	}	
	sum &= mask;
    return sum;
}
static uint16_t calcSumNibbleXor( uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum ^= NIBBLE_LOW(bytes[i]);
		sum ^= NIBBLE_HIGH(bytes[i]);
	}
	sum &= mask;
    return sum;
}
static uint16_t calcSumByteXor( uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++)
        sum ^= bytes[i];
	sum &= mask;	
    return sum;
}
static uint16_t calcSumByteAdd( uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++)
        sum += bytes[i];
	sum &= mask;	
    return sum;
}
// Ones complement
static uint16_t calcSumByteAddOnes( uint8_t* bytes, uint8_t len, uint32_t mask) {
	return (~calcSumByteAdd(bytes, len, mask) & mask);
}

static uint16_t calcSumByteSub( uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < len; i++)
        sum -= bytes[i];
	sum &= mask;	
    return sum;
}
static uint16_t calcSumByteSubOnes( uint8_t* bytes, uint8_t len, uint32_t mask){
	return (~calcSumByteSub(bytes, len, mask) & mask);
}
static uint16_t calcSumNibbleSub( uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum -= NIBBLE_LOW(bytes[i]);
		sum -= NIBBLE_HIGH(bytes[i]);
	}
	sum &= mask;	
    return sum;
}
static uint16_t calcSumNibbleSubOnes( uint8_t* bytes, uint8_t len, uint32_t mask) {
	return (~calcSumNibbleSub(bytes, len, mask) & mask);
}

// BSD shift checksum 8bit version
static uint16_t calcBSDchecksum8( uint8_t* bytes, uint8_t len, uint32_t mask){
	uint16_t sum = 0;
	for(uint8_t i = 0; i < len; i++){
		sum = ((sum & 0xFF) >> 1) | ((sum & 0x1) << 7);   // rotate accumulator
		sum += bytes[i];  // add next byte
		sum &= 0xFF;  // 
	}
	sum &= mask;
	return sum;
}
// BSD shift checksum 4bit version
static uint16_t calcBSDchecksum4( uint8_t* bytes, uint8_t len, uint32_t mask){
	uint16_t sum = 0;
	for(uint8_t i = 0; i < len; i++){
		sum = ((sum & 0xF) >> 1) | ((sum & 0x1) << 3);   // rotate accumulator
		sum += NIBBLE_HIGH(bytes[i]);  // add high nibble
		sum &= 0xF;  // 
		sum = ((sum & 0xF) >> 1) | ((sum & 0x1) << 3);   // rotate accumulator
		sum += NIBBLE_LOW(bytes[i]);  // add low nibble
		sum &= 0xF;  // 
	}
	sum &= mask;
	return sum;
}

// measuring LFSR maximum length
int CmdAnalyseLfsr(const char *Cmd){

    uint16_t start_state = 0;  /* Any nonzero start state will work. */
    uint16_t lfsr = start_state;
    //uint32_t period = 0;

	uint8_t iv = param_get8ex(Cmd, 0, 0, 16);
	uint8_t find = param_get8ex(Cmd, 1, 0, 16);
	
	printf("LEGIC LFSR IV 0x%02X: \n", iv);
	printf(" bit# | lfsr | ^0x40 |  0x%02X ^ lfsr \n",find);
	
	for (uint8_t i = 0x01; i < 0x30; i += 1) {
		//period = 0;
		legic_prng_init(iv);
		legic_prng_forward(i);
		lfsr = legic_prng_get_bits(12);

		printf(" %02X | %03X | %03X | %03X \n",i, lfsr, 0x40 ^ lfsr, find ^ lfsr);
	}
	return 0;
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
	uint32_t mask = 0xFFFF;
	bool errors = false;
	bool useHeader = false;
	int len = 0;
	memset(data, 0x0, sizeof(data));
	
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
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
		case 'v':
		case 'V':
			useHeader = true;
			cmdp++;
			break;
		case 'h':
		case 'H':
			return usage_analyse_checksum();
		default:
			PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
	//Validations
	if (errors || cmdp == 0 ) return usage_analyse_checksum();
	
	if (useHeader) {
		PrintAndLog("     add          | sub         | add 1's compl    | sub 1's compl   | xor");
		PrintAndLog("byte nibble crumb | byte nibble | byte nibble cumb | byte nibble     | byte nibble cumb |  BSD       |");
		PrintAndLog("------------------+-------------+------------------+-----------------+--------------------");
	}
	PrintAndLog("0x%X 0x%X   0x%X  | 0x%X 0x%X   | 0x%X 0x%X   0x%X | 0x%X 0x%X       | 0x%X 0x%X   0x%X  | 0x%X  0x%X |\n",	
				  calcSumByteAdd(data, len, mask)
				, calcSumNibbleAdd(data, len, mask)
				, calcSumCrumbAdd(data, len, mask)
				, calcSumByteSub(data, len, mask)
				, calcSumNibbleSub(data, len, mask)
				, calcSumByteAddOnes(data, len, mask)
				, calcSumNibbleAddOnes(data, len, mask)
				, calcSumCrumbAddOnes(data, len, mask)
				, calcSumByteSubOnes(data, len, mask)
				, calcSumNibbleSubOnes(data, len, mask)
				, calcSumByteXor(data, len, mask)
				, calcSumNibbleXor(data, len, mask)
				, calcSumCrumbXor(data, len, mask)
				, calcBSDchecksum8(data, len, mask)
				, calcBSDchecksum4(data, len, mask)
			);	
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

int CmdAnalyseA(const char *Cmd){
/*	
piwi
// uid(2e086b1a) nt(230736f6) ks(0b0008000804000e) nr(000000000)
// uid(2e086b1a) nt(230736f6) ks(0e0b0e0b090c0d02) nr(000000001)
// uid(2e086b1a) nt(230736f6) ks(0e05060e01080b08) nr(000000002)
uint64_t d1[] = {0x2e086b1a, 0x230736f6, 0x0000001, 0x0e0b0e0b090c0d02};
uint64_t d2[] = {0x2e086b1a, 0x230736f6, 0x0000002, 0x0e05060e01080b08};
	
// uid(17758822) nt(c0c69e59) ks(080105020705040e) nr(00000001)
// uid(17758822) nt(c0c69e59) ks(01070a05050c0705) nr(00000002)
uint64_t d1[] = {0x17758822, 0xc0c69e59, 0x0000001, 0x080105020705040e};
uint64_t d2[] = {0x17758822, 0xc0c69e59, 0x0000002, 0x01070a05050c0705};
	
// uid(6e442129) nt(8f699195) ks(090d0b0305020f02) nr(00000001)
// uid(6e442129) nt(8f699195) ks(03030508030b0c0e) nr(00000002)
// uid(6e442129) nt(8f699195) ks(02010f030c0d050d) nr(00000003)
// uid(6e442129) nt(8f699195) ks(00040f0f0305030e) nr(00000004)
uint64_t d1[] = {0x6e442129, 0x8f699195, 0x0000001, 0x090d0b0305020f02};
uint64_t d2[] = {0x6e442129, 0x8f699195, 0x0000004, 0x00040f0f0305030e};
	
uid(3e172b29) nt(039b7bd2) ks(0c0e0f0505080800) nr(00000001)
uid(3e172b29) nt(039b7bd2) ks(0e06090d03000b0f) nr(00000002)
*/
	// uint64_t key = 0;
	// uint64_t d1[] = {0x3e172b29, 0x039b7bd2, 0x0000001, 0x0c0e0f0505080800};
	// uint64_t d2[] = {0x3e172b29, 0x039b7bd2, 0x0000002, 0x0e06090d03000b0f};
	
	// nonce2key_ex(0, 0 , d1[0], d1[1], d1[2], d1[3], &key);
	// nonce2key_ex(0, 0 , d2[0], d2[1], d2[2], d2[3], &key);
	return 0;
}

static void permute(uint8_t *data, uint8_t len, uint8_t *output){	
#define KEY_SIZE 8

	if ( len > KEY_SIZE ) {
		for(uint8_t m = 0; m < len; m += KEY_SIZE){
			permute(data+m, KEY_SIZE, output+m);
		}
		return;
	}
	if ( len != KEY_SIZE ) {
		printf("wrong key size\n");
		return;
	}
	uint8_t i,j,p, mask;
	for( i=0; i < KEY_SIZE; ++i){
		p = 0;
		mask = 0x80 >> i;
		for( j=0; j < KEY_SIZE; ++j){
			p >>= 1;
			if (data[j] & mask) 
				p |= 0x80;
		}
		output[i] = p;
	}
}
static void permute_rev(uint8_t *data, uint8_t len, uint8_t *output){
	permute(data, len, output);
	permute(output, len, data);
	permute(data, len, output);
}
static void simple_crc(uint8_t *data, uint8_t len, uint8_t *output){
	uint8_t crc = 0;
	for( uint8_t i=0; i < len; ++i){
		// seventh byte contains the crc.
		if ( (i & 0x7) == 0x7 ) {
			output[i] = crc ^ 0xFF;
			crc = 0;
		} else {
			output[i] = data[i];
			crc ^= data[i];
		}
	}
}
// DES doesn't use the MSB.
static void shave(uint8_t *data, uint8_t len){
	for (uint8_t i=0; i<len; ++i)
		data[i] &= 0xFE;
}
static void generate_rev(uint8_t *data, uint8_t len) {
	uint8_t *key = calloc(len,1);	
	printf("input permuted key | %s \n", sprint_hex(data, len));
	permute_rev(data, len, key);
	printf("    unpermuted key | %s \n", sprint_hex(key, len));
	shave(key, len);
	printf("               key | %s \n", sprint_hex(key, len));
	free(key);	
}
static void generate(uint8_t *data, uint8_t len) {
	uint8_t *key = calloc(len,1);
	uint8_t *pkey = calloc(len,1);	
	printf("    input key | %s \n", sprint_hex(data, len));
	permute(data, len, pkey);
	printf(" permuted key | %s \n", sprint_hex(pkey, len));
	simple_crc(pkey, len, key );
	printf("   CRC'ed key | %s \n", sprint_hex(key, len));
	free(key);
	free(pkey);
}
int CmdAnalyseHid(const char *Cmd){

	uint8_t key[8] = {0};	
	uint8_t key_std_format[8] = {0};
	uint8_t key_iclass_format[8] = {0};
	uint8_t data[16] = {0};
	bool isReverse = false;
	int len = 0;
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0|| cmdp == 'h' || cmdp == 'H') return usage_analyse_hid();
		
	if ( cmdp == 'r' || cmdp == 'R' ) 
		isReverse = true;
	
	param_gethex_ex(Cmd, 1, data, &len);
	if ( len%2 ) return usage_analyse_hid();
	
	len >>= 1;	

	memcpy(key, data, 8);

	if ( isReverse ) {
		generate_rev(data, len);
		permutekey_rev(key, key_std_format);
		printf(" holiman iclass key | %s \n", sprint_hex(key_std_format, 8));
	}
	else {
		generate(data, len);
		permutekey(key, key_iclass_format);		
		printf(" holiman std key | %s \n", sprint_hex(key_iclass_format, 8));
	}
	return 0;
}

void generate4bNUID(uint8_t *uid, uint8_t *nuid){
	uint16_t crc;
	uint8_t first, second;
		
	ComputeCrc14443(CRC_14443_A, uid, 3, &first, &second);
	nuid[0] |= (second & 0xE0) | 0xF;
	nuid[1] = first;
	
	crc = first;
	crc |= second << 8;
	
	UpdateCrc14443(uid[3], &crc);
	UpdateCrc14443(uid[4], &crc);
	UpdateCrc14443(uid[5], &crc);
	UpdateCrc14443(uid[6], &crc);
		
	nuid[2] = (crc >> 8) & 0xFF ;
	nuid[3] = crc & 0xFF;
}

int CmdAnalyseNuid(const char *Cmd){
	uint8_t nuid[4] = {0};	
	uint8_t uid[7] = {0};
	int len = 0;
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0|| cmdp == 'h' || cmdp == 'H') return usage_analyse_nuid();

	/* selftest  UID 040D681AB52281  -> NUID 8F430FEF */
	if (cmdp == 't' || cmdp == 'T') {
		memcpy(uid, "\x04\x0d\x68\x1a\xb5\x22\x81", 7);
		generate4bNUID(uid, nuid);
		if ( 0 == memcmp(nuid, "\x8f\x43\x0f\xef", 4))
			printf("Selftest OK\n");
		else
			printf("Selftest Failed\n");
		return 0;
	}

	param_gethex_ex(Cmd, 0, uid, &len);
	if ( len%2  || len != 14) return usage_analyse_nuid();

	generate4bNUID(uid, nuid);
	
	printf("UID  | %s \n", sprint_hex(uid, 7));
	printf("NUID | %s \n", sprint_hex(nuid, 4));
	return 0;
}
static command_t CommandTable[] = {
	{"help",	CmdHelp,            1, "This help"},
	{"lcr",		CmdAnalyseLCR,		1, "Generate final byte for XOR LRC"},
	{"crc",		CmdAnalyseCRC,		1, "Stub method for CRC evaluations"},
	{"chksum",	CmdAnalyseCHKSUM,	1, "Checksum with adding, masking and one's complement"},
	{"dates",	CmdAnalyseDates,	1, "Look for datestamps in a given array of bytes"},
	{"tea",   	CmdAnalyseTEASelfTest,	1, "Crypto TEA test"},
	{"lfsr",	CmdAnalyseLfsr,		1,	"LFSR tests"},
	{"a",		CmdAnalyseA,		1,	"num bits test"},
	{"hid",		CmdAnalyseHid,		1,	"Permute function from 'heart of darkness' paper"},
	{"nuid",	CmdAnalyseNuid,		1,	"create NUID from 7byte UID"},
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
