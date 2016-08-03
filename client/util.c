//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// utilities
//-----------------------------------------------------------------------------

#include "util.h"
#define MAX_BIN_BREAK_LENGTH   (3072+384+1)

#ifndef _WIN32
#include <termios.h>
#include <sys/ioctl.h> 

int ukbhit(void) {
  int cnt = 0;
  int error;
  static struct termios Otty, Ntty;

  if ( tcgetattr( 0, &Otty) == -1) return -1;
  Ntty = Otty;

  Ntty.c_iflag		= 0;       /* input mode                */
  Ntty.c_oflag		= 0;       /* output mode               */
  Ntty.c_lflag		&= ~ICANON; /* raw mode */
  Ntty.c_cc[VMIN]	= CMIN;    /* minimum time to wait      */
  Ntty.c_cc[VTIME]	= CTIME;   /* minimum characters to wait for */

  if (0 == (error = tcsetattr(0, TCSANOW, &Ntty))) {
    error += ioctl(0, FIONREAD, &cnt);
    error += tcsetattr(0, TCSANOW, &Otty);
  }

  return ( error == 0 ? cnt : -1 );
}

#else
#include <conio.h>
int ukbhit(void) {
	return kbhit();
}
#endif

// log files functions
void AddLogLine(char *file, char *extData, char *c) {
	FILE *f = NULL;
    char filename[FILE_PATH_SIZE] = {0x00};
    int len = 0;

    len = strlen(file);
    if (len > FILE_PATH_SIZE) len = FILE_PATH_SIZE;
    memcpy(filename, file, len);
   
	f = fopen(filename, "a");
	if (!f) {
		printf("Could not append log file %s", filename);
		return;
	}

	fprintf(f, "%s", extData);
	fprintf(f, "%s\n", c);
	fflush(f);
	fclose(f);
}

void AddLogHex(char *fileName, char *extData, const uint8_t * data, const size_t len){
	AddLogLine(fileName, extData, sprint_hex(data, len));
}

void AddLogUint64(char *fileName, char *extData, const uint64_t data) {
	char buf[20] = {0};
	memset(buf, 0x00, sizeof(buf));
	//sprintf(buf, "%X%X", (unsigned int)((data & 0xFFFFFFFF00000000) >> 32), (unsigned int)(data & 0xFFFFFFFF));
	sprintf(buf, "%012"llx"", data);
	AddLogLine(fileName, extData, buf);
}

void AddLogCurrentDT(char *fileName) {
	char buf[20];
	memset(buf, 0x00, sizeof(buf));
	struct tm *curTime;
	time_t now = time(0);
	curTime = gmtime(&now);
	strftime (buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", curTime);
	AddLogLine(fileName, "\nanticollision: ", buf);
}

void FillFileNameByUID(char *fileName, uint8_t *uid, char *ext, int byteCount) {
	if ( fileName == NULL || uid == NULL || ext == NULL ){
		printf("error: parameter is NULL\n");
		return;
	}
	char * fnameptr = fileName;
	memset(fileName, 0x00, FILE_PATH_SIZE);
	
	for (int j = 0; j < byteCount; j++, fnameptr += 2)
		sprintf(fnameptr, "%02X", uid[j]); 
	sprintf(fnameptr, "%s", ext); 
}

// printing and converting functions
void print_hex(const uint8_t * data, const size_t len) {
	size_t i;
	for (i=0; i < len; ++i)
		printf("%02x ", data[i]);
	printf("\n");
}

void print_hex_break(const uint8_t *data, const size_t len, uint8_t breaks) {

	int rownum = 0;
	printf("[%02d] | ", rownum);
	for (int i = 0; i < len; ++i) {

		printf("%02X ", data[i]);
		
		// check if a line break is needed
		if ( breaks > 0 && !((i+1) % breaks) && (i+1 < len) ) {
			++rownum;
			printf("\n[%02d] | ", rownum);
		}
	}
	printf("\n");
}

char *sprint_hex(const uint8_t *data, const size_t len) {
	
	int maxLen = ( len > 1024/3) ? 1024/3 : len;
	static char buf[1024];
	memset(buf, 0x00, 1024);
	char * tmp = buf;
	size_t i;

	for (i=0; i < maxLen; ++i, tmp += 3)
		sprintf(tmp, "%02X ", data[i]);
	return buf;
}

char *sprint_bin_break(const uint8_t *data, const size_t len, const uint8_t breaks) {
	
	// make sure we don't go beyond our char array memory
	size_t in_index = 0, out_index = 0;
	int max_len;	
	if (breaks==0)
		max_len = ( len > MAX_BIN_BREAK_LENGTH ) ? MAX_BIN_BREAK_LENGTH : len;
	else
		max_len = ( len+(len/breaks) > MAX_BIN_BREAK_LENGTH ) ? MAX_BIN_BREAK_LENGTH : len+(len/breaks);

	static char buf[MAX_BIN_BREAK_LENGTH]; // 3072 + end of line characters if broken at 8 bits
	//clear memory
	memset(buf, 0x00, sizeof(buf));
	char *tmp = buf;

	// loop through the out_index to make sure we don't go too far
	for (out_index=0; out_index < max_len-2; out_index++) {
		// set character
		sprintf(tmp++, "%u", (unsigned int) data[in_index]);
		// check if a line break is needed and we have room to print it in our array
		if ( (breaks > 0) && !((in_index+1) % breaks) && (out_index+1 != max_len) ) {
			// increment and print line break
			out_index++;
			sprintf(tmp++, "%s","\n");
		}
		in_index++;
	}
	// last char.
	sprintf(tmp++, "%u", (unsigned int) data[in_index]);
	return buf;
}

char *sprint_bin(const uint8_t *data, const size_t len) {
	return sprint_bin_break(data, len, 0);
}

char *sprint_hex_ascii(const uint8_t *data, const size_t len) {
	static char buf[1024];
	char *tmp = buf;
	memset(buf, 0x00, 1024);
	size_t max_len = (len > 1010) ? 1010 : len;
	sprintf(tmp, "%s| %s", sprint_hex(data, max_len) , data);	
	return buf;
}

void num_to_bytes(uint64_t n, size_t len, uint8_t* dest) {
	while (len--) {
		dest[len] = (uint8_t) n;
		n >>= 8;
	}
}

uint64_t bytes_to_num(uint8_t* src, size_t len) {
	uint64_t num = 0;
	while (len--) {
		num = (num << 8) | (*src);
		src++;
	}
	return num;
}

// takes a number (uint64_t) and creates a binarray in dest.
void num_to_bytebits(uint64_t n, size_t len, uint8_t *dest) {
	while (len--) {
		dest[len] = n & 1;
		n >>= 1;
	}
}

//least significant bit first
void num_to_bytebitsLSBF(uint64_t n, size_t len, uint8_t *dest) {
	for(int i = 0 ; i < len ; ++i) {
		dest[i] =  n & 1;
		n >>= 1;
	}
}

// aa,bb,cc,dd,ee,ff,gg,hh, ii,jj,kk,ll,mm,nn,oo,pp
// to
// hh,gg,ff,ee,dd,cc,bb,aa, pp,oo,nn,mm,ll,kk,jj,ii
// up to 64 bytes or 512 bits
uint8_t *SwapEndian64(const uint8_t *src, const size_t len, const uint8_t blockSize){
	static uint8_t buf[64];
	memset(buf, 0x00, 64);
	uint8_t *tmp = buf;
	for (uint8_t block=0; block < (uint8_t)(len/blockSize); block++){
		for (size_t i = 0; i < blockSize; i++){
			tmp[i+(blockSize*block)] = src[(blockSize-1-i)+(blockSize*block)];
		}
	}
	return buf;
}

// takes a uint8_t src array, for len items and reverses the byte order in blocksizes (8,16,32,64), 
// returns: the dest array contains the reordered src array.
void SwapEndian64ex(const uint8_t *src, const size_t len, const uint8_t blockSize, uint8_t *dest){
	for (uint8_t block=0; block < (uint8_t)(len/blockSize); block++){
		for (size_t i = 0; i < blockSize; i++){
			dest[i+(blockSize*block)] = src[(blockSize-1-i)+(blockSize*block)];
		}
	}
}

//  -------------------------------------------------------------------------
//  string parameters lib
//  -------------------------------------------------------------------------

//  -------------------------------------------------------------------------
//  line     - param line
//  bg, en   - symbol numbers in param line of beginning an ending parameter
//  paramnum - param number (from 0)
//  -------------------------------------------------------------------------
int param_getptr(const char *line, int *bg, int *en, int paramnum)
{
	int i;
	int len = strlen(line);
	
	*bg = 0;
	*en = 0;
	
  // skip spaces
	while (line[*bg] ==' ' || line[*bg]=='\t') (*bg)++;
	if (*bg >= len) {
		return 1;
	}

	for (i = 0; i < paramnum; i++) {
		while (line[*bg]!=' ' && line[*bg]!='\t' && line[*bg] != '\0') (*bg)++;
		while (line[*bg]==' ' || line[*bg]=='\t') (*bg)++;
		
		if (line[*bg] == '\0') return 1;
	}
	
	*en = *bg;
	while (line[*en] != ' ' && line[*en] != '\t' && line[*en] != '\0') (*en)++;
	
	(*en)--;

	return 0;
}


char param_getchar(const char *line, int paramnum)
{
	int bg, en;
	
	if (param_getptr(line, &bg, &en, paramnum)) return 0x00;

	return line[bg];
}

uint8_t param_get8(const char *line, int paramnum)
{
	return param_get8ex(line, paramnum, 0, 10);
}

/**
 * @brief Reads a decimal integer (actually, 0-254, not 255)
 * @param line
 * @param paramnum
 * @return -1 if error
 */
uint8_t param_getdec(const char *line, int paramnum, uint8_t *destination)
{
	uint8_t val =  param_get8ex(line, paramnum, 255, 10);
	if( (int8_t) val == -1) return 1;
	(*destination) = val;
	return 0;
}
/**
 * @brief Checks if param is decimal
 * @param line
 * @param paramnum
 * @return
 */
uint8_t param_isdec(const char *line, int paramnum)
{
	int bg, en;
	//TODO, check more thorougly
	if (!param_getptr(line, &bg, &en, paramnum)) return 1;
		//		return strtoul(&line[bg], NULL, 10) & 0xff;

	return 0;
}

uint8_t param_get8ex(const char *line, int paramnum, int deflt, int base)
{
	int bg, en;

	if (!param_getptr(line, &bg, &en, paramnum)) 
		return strtoul(&line[bg], NULL, base) & 0xff;
	else
		return deflt;
}

uint32_t param_get32ex(const char *line, int paramnum, int deflt, int base)
{
	int bg, en;

	if (!param_getptr(line, &bg, &en, paramnum)) 
		return strtoul(&line[bg], NULL, base);
	else
		return deflt;
}

uint64_t param_get64ex(const char *line, int paramnum, int deflt, int base)
{
	int bg, en;

	if (!param_getptr(line, &bg, &en, paramnum)) 
		return strtoull(&line[bg], NULL, base);
	else
		return deflt;
}

int param_gethex(const char *line, int paramnum, uint8_t * data, int hexcnt)
{
	int bg, en, temp, i;

	if (hexcnt & 1) return 1;
	
	if (param_getptr(line, &bg, &en, paramnum)) return 1;

	if (en - bg + 1 != hexcnt) return 1;

	for(i = 0; i < hexcnt; i += 2) {
		if (!(isxdigit(line[bg + i]) && isxdigit(line[bg + i + 1])) )	return 1;
		
		sscanf((char[]){line[bg + i], line[bg + i + 1], 0}, "%X", &temp);
		data[i / 2] = temp & 0xff;
	}	

	return 0;
}
int param_gethex_ex(const char *line, int paramnum, uint8_t * data, int *hexcnt)
{
	int bg, en, temp, i;

	//if (hexcnt % 2)
	//	return 1;
	
	if (param_getptr(line, &bg, &en, paramnum)) return 1;

	*hexcnt = en - bg + 1;
	if (*hexcnt % 2) //error if not complete hex bytes
		return 1;

	for(i = 0; i < *hexcnt; i += 2) {
		if (!(isxdigit(line[bg + i]) && isxdigit(line[bg + i + 1])) ) return 1;
		
		sscanf((char[]){line[bg + i], line[bg + i + 1], 0}, "%X", &temp);
		data[i / 2] = temp & 0xff;
	}	

	return 0;
}
int param_getstr(const char *line, int paramnum, char * str)
{
	int bg, en;

	if (param_getptr(line, &bg, &en, paramnum)) return 0;
	
	memcpy(str, line + bg, en - bg + 1);
	str[en - bg + 1] = 0;
	
	return en - bg + 1;
}

/*
The following methods comes from Rfidler sourcecode.
https://github.com/ApertureLabsLtd/RFIDler/blob/master/firmware/Pic32/RFIDler.X/src/
*/

// convert hex to sequence of 0/1 bit values
// returns number of bits converted
int hextobinarray(char *target, char *source)
{
    int length, i, count= 0;
    char x;

    length = strlen(source);
    // process 4 bits (1 hex digit) at a time
    while(length--)
    {
        x= *(source++);
        // capitalize
        if (x >= 'a' && x <= 'f')
            x -= 32;
        // convert to numeric value
        if (x >= '0' && x <= '9')
            x -= '0';
        else if (x >= 'A' && x <= 'F')
            x -= 'A' - 10;
        else
            return 0;
        // output
        for(i= 0 ; i < 4 ; ++i, ++count)
            *(target++)= (x >> (3 - i)) & 1;
    }
    
    return count;
}

// convert hex to human readable binary string
int hextobinstring(char *target, char *source)
{
    int length;

    if(!(length= hextobinarray(target, source)))
        return 0;
    binarraytobinstring(target, target, length);
    return length;
}

// convert binary array of 0x00/0x01 values to hex (safe to do in place as target will always be shorter than source)
// return number of bits converted
int binarraytohex(char *target, char *source, int length)
{
    unsigned char i, x;
    int j = length;

    if(j % 4)
        return 0;

    while(j)
    {
        for(i= x= 0 ; i < 4 ; ++i)
            x +=  ( source[i] << (3 - i));
        sprintf(target,"%X", x);
        ++target;
        source += 4;
        j -= 4;
    }
    return length;
}

// convert binary array to human readable binary
void binarraytobinstring(char *target, char *source,  int length)
{
    int i;

    for(i= 0 ; i < length ; ++i)
        *(target++)= *(source++) + '0';
    *target= '\0';
}

// return parity bit required to match type
uint8_t GetParity( uint8_t *bits, uint8_t type, int length)
{
    int x;
    for( x = 0 ; length > 0 ; --length)
        x += bits[length - 1];
    x %= 2;
    return x ^ type;
}

// add HID parity to binary array: EVEN prefix for 1st half of ID, ODD suffix for 2nd half
void wiegand_add_parity(uint8_t *target, uint8_t *source, uint8_t length)
{
    *(target++)= GetParity(source, EVEN, length / 2);
    memcpy(target, source, length);
    target += length;
    *(target)= GetParity(source + length / 2, ODD, length / 2);
}

// xor two arrays together for len items.  The dst array contains the new xored values.
void xor(unsigned char * dst, unsigned char * src, size_t len) {
   for( ; len > 0; len--,dst++,src++)
       *dst ^= *src;
}

int32_t le24toh (uint8_t data[3]) {
    return (data[2] << 16) | (data[1] << 8) | data[0];
}
uint32_t le32toh (uint8_t *data) {
	return (uint32_t)( (data[3]<<24) | (data[2]<<16) | (data[1]<<8) | data[0]);
}
// Pack a bitarray into a uint32_t.  
uint32_t PackBits(uint8_t start, uint8_t len, uint8_t* bits) {

	if (len > 32) return 0;
	
	int i = start;
	int j = len-1;
	uint32_t tmp = 0;

	for (; j >= 0; --j, ++i)
		tmp	|= bits[i] << j;

	return tmp;
}

// RotateLeft - Ultralight, Desfire, works on byte level
// 00-01-02  >> 01-02-00
void rol(uint8_t *data, const size_t len){	
    uint8_t first = data[0];
    for (size_t i = 0; i < len-1; i++) {
        data[i] = data[i+1];
    }
    data[len-1] = first;
}

// Swap bit order on a uint32_t value.  Can be limited by nrbits just use say 8bits reversal
// And clears the rest of the bits.
uint32_t SwapBits(uint32_t value, int nrbits) {
	uint32_t newvalue = 0;
	for(int i = 0; i < nrbits; i++) {
		newvalue ^= ((value >> i) & 1) << (nrbits - 1 - i);
	}
	return newvalue;
}
/*
 ref  http://www.csm.ornl.gov/~dunigan/crc.html
 Returns the value v with the bottom b [0,32] bits reflected. 
 Example: reflect(0x3e23L,3) == 0x3e26
*/
uint32_t reflect(uint32_t v, int b) {
	uint32_t t = v;
	for ( int i = 0; i < b; ++i) {
		if (t & 1)
			v |=  BITMASK((b-1)-i);
		else
			v &= ~BITMASK((b-1)-i);
		t>>=1;
	}
	return v;
}

uint64_t HornerScheme(uint64_t num, uint64_t divider, uint64_t factor) {
   uint64_t remainder=0, quotient=0, result=0;
   remainder = num % divider;
   quotient = num / divider;
   if(!(quotient == 0 && remainder == 0))
   result += HornerScheme(quotient, divider, factor) * factor + remainder;
   return result;
}