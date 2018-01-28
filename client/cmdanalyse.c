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
#include "iso15693tools.h"
#include "util_posix.h" // msclock

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
    for (uint8_t i = 0; i < len; i++) {
		sum ^= bytes[i];
	}
	sum &= mask;	
    return sum;
}
static uint16_t calcSumByteAdd( uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint16_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
		sum += bytes[i];
	}
	sum &= mask;	
    return sum;
}
// Ones complement
static uint16_t calcSumByteAddOnes( uint8_t* bytes, uint8_t len, uint32_t mask) {
	return (~calcSumByteAdd(bytes, len, mask) & mask);
}

static uint16_t calcSumByteSub( uint8_t* bytes, uint8_t len, uint32_t mask) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
		sum -= bytes[i];
	}
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

	PrintAndLog("\nTests with | %s", sprint_hex(data, len));
	
	PrintAndLog("\nTests of reflection. Current methods in source code");	
	PrintAndLog("   reflect(0x3e23L,3) is %04X == 0x3e26", reflect(0x3e23L,3) );
	PrintAndLog("       reflect8(0x80) is %02X == 0x01", reflect8(0x80));
	PrintAndLog("    reflect16(0x8000) is %04X == 0x0001", reflect16(0x8000));
	//
	// Test of CRC16,  '123456789' string.
	//
	uint8_t b1, b2;
	
	PrintAndLog("\nTests with '123456789' string");
	uint8_t dataStr[] = { 0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39 };
	uint8_t legic8 = CRC8Legic(dataStr, sizeof(dataStr));
	
	PrintAndLog("LEGIC: CRC16: %X", CRC16Legic(dataStr, sizeof(dataStr), legic8));

	//these below has been tested OK.
	PrintAndLog("Confirmed CRC Implementations");
	printf("\n");
	PrintAndLog("LEGIC: CRC8 : %X (0xC6 expected)", legic8);
	PrintAndLog("MAXIM: CRC8 : %X (0xA1 expected)", CRC8Maxim(dataStr, sizeof(dataStr)));
	PrintAndLog("DNP  : CRC16: %X (0x82EA expected)", CRC16_DNP(dataStr, sizeof(dataStr)));	
	PrintAndLog("CCITT: CRC16: %X (0xE5CC expected)", CRC16_CCITT(dataStr, sizeof(dataStr)));
	PrintAndLog("ICLASS org: CRC16: %X (0x expected)", iclass_crc16( dataStr, sizeof(dataStr)));
	
	// ISO14443 crc A
	uint16_t crcA = crc16_a(dataStr, sizeof(dataStr));
	ComputeCrc14443(CRC_14443_A, dataStr, sizeof(dataStr), &b1, &b2);
	uint16_t crcAA = b1 << 8 | b2;
	printf("ISO14443 crc A   | %04x == %04x\n", crcA, crcAA);
	
	// ISO14443 crc B
	uint16_t crcB = crc16_a(dataStr, sizeof(dataStr));
	ComputeCrc14443(CRC_14443_B, dataStr, sizeof(dataStr)-2, &b1, &b2);	
	uint16_t crcBB = b1 << 8 | b2;
	printf("ISO14443 crc B   | %04x == %04x\n", crcB, crcBB);

	// ISO15693 crc  (x.25)
	uint16_t x25 = crc16_x25(dataStr, sizeof(dataStr));
	uint16_t iso = Iso15693Crc(dataStr, sizeof(dataStr));
	printf("ISO15693 crc X25 | %04x == %04x\n", iso, x25 );

	// ICLASS (
	uint16_t iclass = crc16_iclass(dataStr, sizeof(dataStr));
	uint16_t iclass_org = iclass_crc16(dataStr, sizeof(dataStr));
	printf("ICLASS crc       | %04x == %04x\n", iclass, iclass_org);
	
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

	uint8_t b1, b2;

	// 14 a
	uint8_t halt[] = {0x50 , 0x00, 0x57, 0xcd }; //halt w crc
	uint8_t atqs[] = {0x09, 0x78, 0x00, 0x92, 0x02, 0x54, 0x13, 0x02, 0x04, 0x2d, 0xe8 }; // atqs w crc	
	ComputeCrc14443(CRC_14443_A, halt, sizeof(halt), &b1, &b2);
	printf("14a crc halt == 0  [%s]\n", (b1==0 && b2==0) ? "YES": "NO" );
	ComputeCrc14443(CRC_14443_A, atqs, sizeof(atqs), &b1, &b2);
	printf("14a crc ATQS == 0  [%s]\n", (b1==0 && b2==0) ? "YES": "NO" );
	
	// 14b
	uint8_t u14b[] = {0x05,0x00,0x08,0x39,0x73};
	ComputeCrc14443(CRC_14443_B, u14b, sizeof(u14b), &b1, &b2);
	printf("14b crc u14b == 0  [%s] %02x %02x\n", (b1==0 && b2==0) ? "YES": "NO" , b1,b2);	
	ComputeCrc14443(CRC_14443_B, u14b, sizeof(u14b)-2, &b1, &b2);
	printf("14b crc u14b == 0  [%s] %02x %02x\n", (b1==0 && b2==0) ? "YES": "NO" , b1,b2);	
	
	uint8_t data[] = {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39};
	uint16_t kermit = crc16_kermit(data, sizeof(data));
	uint16_t xmodem = crc16_xmodem(data, sizeof(data));


	printf(">>>  KERMIT 5F6E | XMODEM 9C58 <<<\n");
	printf("            %04X | XMODEM %04X \n", kermit, xmodem);

	printf("\n\n");	
	return 0;
	
	time_t t;
	srand((unsigned) time(&t));
	uint64_t t1 = msclock();
	// test CRC-A etc
	for (int foo=0; foo < 10000000; foo++) {
		crc16_a(data, sizeof(data));
		data[1] = rand();
		data[2] = rand();
		data[3] = rand();
		data[4] = rand();
	}
	t1 = msclock() - t1; printf("ticks crc_a  %" PRIu64 "\n", t1);
	
	t1 = msclock();
	for (int foo=0; foo < 10000000; foo++) {
		ComputeCrc14443(CRC_14443_A, data, sizeof(data), &b1, &b2);
		data[1] = rand();
		data[2] = rand();
		data[3] = rand();
		data[4] = rand();	}
	t1 = msclock() - t1; printf("ticks curr CRC-a  %" PRIu64 "\n", t1);
	
	// test ISO15693 crc
	t1 = msclock();
	for (int foo=0; foo < 10000000; foo++) {
		crc16_x25(data, sizeof(data));
		data[1] = rand();
		data[2] = rand();
		data[3] = rand();
		data[4] = rand();
	}
	t1 = msclock() - t1; printf("ticks x25  %" PRIu64 "\n", t1);
	
	t1 = msclock();
	for (int foo=0; foo < 10000000; foo++) {
		Iso15693Crc(data, sizeof(data));
		data[1] = rand();
		data[2] = rand();
		data[3] = rand();
		data[4] = rand();	}
	t1 = msclock() - t1; printf("ticks curr iso15 (x25)  %" PRIu64 "\n", t1);	

	return 0;
	
	uint16_t v = 1;
	for(uint8_t i = 0; i < 16; i++) {
		
		uint16_t r = reflect16(v);		
		
		printf(" 0x%04x <-> 0x%04x  | ", v, r);
		for(uint8_t i = 0; i < 16; i++) {
			printf("%c", (v & (1 << i) ) ? '1':'0');
		}
		printf("  |  ");
		for(uint8_t i = 0; i < 16; i++) {
			printf("%c", (r & (1 << i) ) ? '1':'0');
		}
		printf("\n");
		v <<= 1;
	}
	uint8_t b = 1;
	for(uint8_t i = 0; i < 8; i++) {
		uint8_t r = reflect8(b);
		printf(" 0x%02x <-> 0x%02x  | ", b, r);
		for(uint8_t i = 0; i < 8; i++) {
			printf("%c", (b & (1 << i) ) ? '1':'0');
		}
		printf("  |  ");
		for(uint8_t i = 0; i < 8; i++) {
			printf("%c", (r & (1 << i) ) ? '1':'0');
		}
		printf("\n");
		b <<= 1;		
	}

	// 16bit test

	uint8_t md;
	uint32_t mb, mc;

	// reflect
	t1 = msclock();
	for (int foo=0; foo < 10000000; foo++) {
		mb = rand();
		reflect(mb, 16);
	}
	t1 = msclock() - t1; printf("ticks reflect  %" PRIu64 "\n", t1);
	
	// reflect16
	t1 = msclock();
	for (int foo=0; foo < 10000000; foo++) {
		mc = rand();
		reflect16(mc);	
	}
	t1 = msclock() - t1; printf("ticks reflect16  %" PRIu64 "\n", t1);
	//---------------------------------------------------------
	
	// reflect
	t1 = msclock();
	for (int foo=0; foo < 10000000; foo++) {
		md = rand();
		reflect(md, 8);
	}
	t1 = msclock() - t1; printf("ticks reflect _8_ %" PRIu64 "\n", t1);
	
	// reflect8
	t1 = msclock();
	for (int foo=0; foo < 10000000; foo++) {
		md = rand();
		reflect8(md);	
	}
	t1 = msclock() - t1; printf("ticks reflect8  %" PRIu64 "\n", t1);

	return 0;
	/*
	bool term = !isatty(STDIN_FILENO);
	if (!term) {
		char star[4];
		star[0] = '-';
		star[1] = '\\';
		star[2] = '|';
		star[3] = '/';
		
		for (uint8_t k=0; k<4; k = (k+1) % 4 ) {
			printf("\e[s%c\e[u", star[k]);
			fflush(stdout);
			if (ukbhit()) {
				int gc = getchar(); (void)gc;
				break;
			}
		}
	}
	*/
	
//piwi
// uid(2e086b1a) nt(230736f6) ks(0b0008000804000e) nr(000000000)
// uid(2e086b1a) nt(230736f6) ks(0e0b0e0b090c0d02) nr(000000001)
// uid(2e086b1a) nt(230736f6) ks(0e05060e01080b08) nr(000000002)
//uint64_t d1[] = {0x2e086b1a, 0x230736f6, 0x0000001, 0x0e0b0e0b090c0d02};
//uint64_t d2[] = {0x2e086b1a, 0x230736f6, 0x0000002, 0x0e05060e01080b08};
	
// uid(17758822) nt(c0c69e59) ks(080105020705040e) nr(00000001)
// uid(17758822) nt(c0c69e59) ks(01070a05050c0705) nr(00000002)
//uint64_t d1[] = {0x17758822, 0xc0c69e59, 0x0000001, 0x080105020705040e};
//uint64_t d2[] = {0x17758822, 0xc0c69e59, 0x0000002, 0x01070a05050c0705};
	
// uid(6e442129) nt(8f699195) ks(090d0b0305020f02) nr(00000001)
// uid(6e442129) nt(8f699195) ks(03030508030b0c0e) nr(00000002)
// uid(6e442129) nt(8f699195) ks(02010f030c0d050d) nr(00000003)
// uid(6e442129) nt(8f699195) ks(00040f0f0305030e) nr(00000004)
//uint64_t d1[] = {0x6e442129, 0x8f699195, 0x0000001, 0x090d0b0305020f02};
//uint64_t d2[] = {0x6e442129, 0x8f699195, 0x0000004, 0x00040f0f0305030e};

/*	
uid(3e172b29) nt(039b7bd2) ks(0c0e0f0505080800) nr(00000001)
uid(3e172b29) nt(039b7bd2) ks(0e06090d03000b0f) nr(00000002)
*/
	uint64_t *keylistA = NULL, *keylistB = NULL;
	uint32_t keycountA = 0, keycountB = 0;
//	uint64_t d1[] = {0x3e172b29, 0x039b7bd2, 0x0000001, 0, 0x0c0e0f0505080800};
//	uint64_t d2[] = {0x3e172b29, 0x039b7bd2, 0x0000002, 0, 0x0e06090d03000b0f};
uint64_t d1[] = {0x6e442129, 0x8f699195, 0x0000001, 0, 0x090d0b0305020f02};
uint64_t d2[] = {0x6e442129, 0x8f699195, 0x0000004, 0, 0x00040f0f0305030e};
	
	keycountA = nonce2key(d1[0], d1[1], d1[2], d1[3], d1[4] ,&keylistA);
	keycountB = nonce2key(d2[0], d2[1], d2[2], d2[3], d2[4], &keylistB);

	switch (keycountA) {
		case 0: printf("Key test A failed\n"); break;
		case 1: printf("KEY A | %012" PRIX64 " ", keylistA[0]); break;
	}
	switch (keycountB) {
		case 0: printf("Key test B failed\n"); break;
		case 1: printf("KEY B | %012" PRIX64 " ", keylistB[0]); break;
	}	
	
	free(keylistA);
	free(keylistB);
	
//	qsort(keylist, keycount, sizeof(*keylist), compare_uint64);
//	keycount = intersection(last_keylist, keylist);

	/*
	uint64_t keys[] = {
		0x7b5b8144a32f, 0x76b46ccc461e, 0x03c3c36ea7a2, 0x171414d31961,
		0xe2bfc7153eea, 0x48023d1d1985, 0xff7e1a410953, 0x49a3110249d3,
		0xe3515546d015, 0x667c2ac86f85, 0x5774a8d5d6a9, 0xe401c2ca602c,
		0x3be7e5020a7e, 0x66dbec3cf90b, 0x4e13f1534605, 0x5c172e1e78c9,
		0xeafe51411fbf, 0xc579f0fcdd8f, 0x2146a0d745c3, 0xab31ca60171a,
		0x3169130a5035, 0xde5e11ea4923, 0x96fe2aeb9924, 0x828b61e6fcba,
		0x8211b0607367, 0xe2936b320f76, 0xaff501e84378, 0x82b31cedb21b,
		0xb725d31d4cd3, 0x3b984145b2f1, 0x3b4adb3e82ba, 0x8779075210fe
	};
	
	uint64_t keya[] = {
		0x7b5b8144a32f, 0x76b46ccc461e, 0x03c3c36ea7a2, 0x171414d31961,
		0xe2bfc7153eea, 0x48023d1d1985, 0xff7e1a410953, 0x49a3110249d3,
		0xe3515546d015, 0x667c2ac86f85, 0x5774a8d5d6a9, 0xe401c2ca602c,
		0x3be7e5020a7e, 0x66dbec3cf90b, 0x4e13f1534605, 0x5c172e1e78c9
	};
	uint64_t keyb[] = {
		0xeafe51411fbf, 0xc579f0fcdd8f, 0x2146a0d745c3, 0xab31ca60171a,
		0x3169130a5035, 0xde5e11ea4923, 0x96fe2aeb9924, 0x828b61e6fcba,
		0x8211b0607367, 0xe2936b320f76, 0xaff501e84378, 0x82b31cedb21b,
		0xb725d31d4cd3, 0x3b984145b2f1, 0x3b4adb3e82ba, 0x8779075210fe
	};
	
	*/
	
	/*
	uint64_t xor[] = {
		0x0DEFED88E531,	0x7577AFA2E1BC,	0x14D7D7BDBEC3,	0xF5ABD3C6278B,
		0xAABDFA08276F,	0xB77C275C10D6,	0xB6DD0B434080,	0xAAF2444499C6,
		0x852D7F8EBF90,	0x3108821DB92C,	0xB3756A1FB685,	0xDFE627C86A52,
		0x5D3C093EF375,	0x28C81D6FBF0E,	0x1204DF4D3ECC, 0xB6E97F5F6776,
		0x2F87A1BDC230, 0xE43F502B984C,	0x8A776AB752D9,	0x9A58D96A472F,
		0xEF3702E01916, 0x48A03B01D007, 0x14754B0D659E, 0x009AD1868FDD,
		0x6082DB527C11, 0x4D666ADA4C0E, 0x2D461D05F163, 0x3596CFF0FEC8,
		0x8CBD9258FE22, 0x00D29A7B304B, 0xBC33DC6C9244
	};
	

	uint64_t xorA[] = {
		0x0DEFED88E531,	0x7577AFA2E1BC,	0x14D7D7BDBEC3,	0xF5ABD3C6278B,
		0xAABDFA08276F,	0xB77C275C10D6,	0xB6DD0B434080,	0xAAF2444499C6,
		0x852D7F8EBF90,	0x3108821DB92C,	0xB3756A1FB685,	0xDFE627C86A52,
		0x5D3C093EF375,	0x28C81D6FBF0E,	0x1204DF4D3ECC
	};
	uint64_t xorB[] = {
		0x2F87A1BDC230, 0xE43F502B984C,	0x8A776AB752D9,	0x9A58D96A472F,
		0xEF3702E01916, 0x48A03B01D007, 0x14754B0D659E, 0x009AD1868FDD,
		0x6082DB527C11, 0x4D666ADA4C0E, 0x2D461D05F163, 0x3596CFF0FEC8,
		0x8CBD9258FE22, 0x00D29A7B304B, 0xBC33DC6C9244
	};
	*/
	/*	
	// xor key A      | xor key B
	1  | 0DEFED88E531 | 2F87A1BDC230
	2  | 7577AFA2E1BC | E43F502B984C
	3  | 14D7D7BDBEC3 | 8A776AB752D9
	4  | F5ABD3C6278B | 9A58D96A472F
	5  | AABDFA08276F | EF3702E01916
	6  | B77C275C10D6 | 48A03B01D007
	7  | B6DD0B434080 | 14754B0D659E
	8  | AAF2444499C6 | 009AD1868FDD
	9  | 852D7F8EBF90 | 6082DB527C11
	10 | 3108821DB92C | 4D666ADA4C0E
	11 | B3756A1FB685 | 2D461D05F163
	12 | DFE627C86A52 | 3596CFF0FEC8
	13 | 5D3C093EF375 | 8CBD9258FE22
	14 | 28C81D6FBF0E | 00D29A7B304B
	15 | 1204DF4D3ECC | BC33DC6C9244
	*/

	// generate xor table :)
	/*
	for (uint8_t i=0; i<31; i++){
		uint64_t a = keys[i] ^ keys[i+1];
		printf("%u | %012" PRIX64 " | \n", i, a);
	}
	*/
	
	/*
	uint32_t id = param_get32ex(Cmd, 0, 0x93290142, 16);	
	uint8_t uid[6] = {0};
	num_to_bytes(id,4,uid);
	
	uint8_t key_s0a[] = {
		uid[1] ^ uid[2] ^ uid[3] ^ 0x11,
		uid[1] ^ 0x72,
		uid[2] ^ 0x80,
		(uid[0] + uid[1] + uid[2] + uid[3] ) ^ uid[3] ^ 0x19,
		0xA3,
		0x2F
	};

	printf("UID   | %s\n", sprint_hex(uid,4 ));
	printf("KEY A | %s\n", sprint_hex(key_s0a, 6));
	
	// arrays w all keys
	uint64_t foo[32] = {0};
	
	//A
	foo[0] = bytes_to_num(key_s0a, 6);
	//B
	//foo[16] = 0xcafe71411fbf;
	foo[16] = 0xeafe51411fbf;
	
	for (uint8_t i=0; i<15; i++){	
		foo[i+1] = foo[i] ^ xorA[i];
		foo[i+16+1] = foo[i+16] ^ xorB[i];
		
	}
	for (uint8_t i=0; i<15; i++){
		uint64_t a = foo[i];
		uint64_t b = foo[i+16];

		printf("%02u | %012" PRIX64 " %s | %012" PRIX64 " %s\n",
			i,
			a,
			( a == keya[i])?"ok":"err",
			b,
			( b == keyb[i])?"ok":"err" 
		);
	}
	*/
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
