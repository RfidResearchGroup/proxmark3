//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Generic CRC calculation code.
//-----------------------------------------------------------------------------
// the Check value below in the comments is CRC of the string '123456789' 
//
#include "crc.h"

void crc_init_ref(crc_t *crc, int order, uint32_t polynom, uint32_t initial_value, uint32_t final_xor, bool refin, bool refout) {
	crc_init(crc, order, polynom, initial_value, final_xor);
	crc->refin = refin;
	crc->refout = refout;
	crc_clear(crc);
}

void crc_init(crc_t *crc, int order, uint32_t polynom, uint32_t initial_value, uint32_t final_xor) {
	crc->order = order;
	crc->topbit = BITMASK( order-1 );
	crc->polynom = polynom;
	crc->initial_value = initial_value;
	crc->final_xor = final_xor;
	crc->mask = (1L<<order)-1;
	crc->refin = false;
	crc->refout = false;
	crc_clear(crc);
}

void crc_clear(crc_t *crc) {
	
	crc->state = crc->initial_value & crc->mask;
	if (crc->refin) 
		crc->state = reflect(crc->state, crc->order);
}

void crc_update2(crc_t *crc, uint32_t data, int data_width){
	
	if (crc->refin) 
		data = reflect(data, data_width);
	
	// Bring the next byte into the remainder.
	crc->state ^= data << (crc->order - data_width);
	
	for( uint8_t bit = data_width; bit > 0; --bit) {		

		if (crc->state & crc->topbit)
			crc->state = (crc->state << 1) ^ crc->polynom;
		else
			crc->state = (crc->state << 1);
	}
}

void crc_update(crc_t *crc, uint32_t data, int data_width)
{
	if (crc->refin) 
		data = reflect(data, data_width);
	
	int i;
	for(i=0; i<data_width; i++) {
		int oldstate = crc->state;
		crc->state = crc->state >> 1;
		if( (oldstate^data) & 1 ) {
			crc->state ^= crc->polynom;
		}
		data >>= 1;
	}
}

uint32_t crc_finish(crc_t *crc) {
	uint32_t val = crc->state;
	if (crc->refout) val = reflect(val, crc->order);
	return ( val ^ crc->final_xor ) & crc->mask;
}

/*
static void print_crc(crc_t *crc) {
	printf(" Order  %d\n Poly   %x\n Init   %x\n Final  %x\n Mask   %x\n topbit %x\n RefIn  %s\n RefOut %s\n State  %x\n",
		crc->order,
		crc->polynom,
		crc->initial_value,
		crc->final_xor,
		crc->mask,
		crc->topbit,
		(crc->refin) ? "TRUE":"FALSE",
		(crc->refout) ? "TRUE":"FALSE",
		crc->state
	);
}
*/

// width=8  poly=0x31  init=0x00  refin=true  refout=true  xorout=0x00  check=0xA1  name="CRC-8/MAXIM"
uint32_t CRC8Maxim(uint8_t *buff, size_t size) {
	crc_t crc;
	crc_init_ref(&crc, 8, 0x31, 0, 0, true, true);	
	for ( int i=0; i < size; ++i)
		crc_update2(&crc, buff[i], 8);
	return crc_finish(&crc);
}
// width=8  poly=0x1d, reversed poly=0x??  init=0xe3  refin=true  refout=true  xorout=0x0000  check=0xC6  name="CRC-8/MAD"
// the CRC needs to be reversed before returned.
uint32_t CRC8Mad(uint8_t *buff, size_t size) {
	crc_t crc;
	crc_init_ref(&crc, 8, 0x1d, 0xe3, 0, true, true);
	for ( int i = 0; i < size; ++i)
		crc_update2(&crc, buff[i], 8);
	return reflect(crc_finish(&crc), 8);
}
// width=4  poly=0xC, reversed poly=0x7  init=0x5   refin=true  refout=true  xorout=0x0000  check=  name="CRC-4/LEGIC"
uint32_t CRC4Legic(uint8_t *cmd, size_t size) {
 	crc_t crc;
 	crc_init_ref(&crc, 4, 0x19 >> 1, 0x5, 0, true, true);
	crc_update2(&crc, 1, 1); /* CMD_READ */
	crc_update2(&crc, cmd[0], 8);
	crc_update2(&crc, cmd[1], 8);
	return reflect(crc_finish(&crc), 4);	
}
// width=8  poly=0x63, reversed poly=0x8D  init=0x55  refin=true  refout=true  xorout=0x0000  check=0xC6  name="CRC-8/LEGIC"
// the CRC needs to be reversed before returned.
uint32_t CRC8Legic(uint8_t *buff, size_t size) {
	crc_t crc;
	crc_init_ref(&crc, 8, 0x63, 0x55, 0, true, true);
	for ( int i = 0; i < size; ++i)
		crc_update2(&crc, buff[i], 8);
	return reflect(crc_finish(&crc), 8);
}

// This CRC-16 is used in Legic Advant systems. 
// width=8  poly=0xB400, reversed poly=0x  init=depends  refin=true  refout=true  xorout=0x0000  check=  name="CRC-16/LEGIC"
uint32_t CRC16Legic(uint8_t *buff, size_t size, uint8_t uidcrc) {

	#define CRC16_POLY_LEGIC 0xB400
	uint16_t initial = reflect(uidcrc, 8);
	//uint16_t initial = uidcrc;
	initial |= initial << 8;
	crc_t crc;
	crc_init_ref(&crc, 16, CRC16_POLY_LEGIC, initial, 0, true, true);
	for ( int i=0; i < size; ++i)
		crc_update(&crc, buff[i], 8);
	return reflect(crc_finish(&crc), 16);
}

//w=16  poly=0x3d65  init=0x0000  refin=true  refout=true  xorout=0xffff  check=0xea82  name="CRC-16/DNP"
uint32_t CRC16_DNP(uint8_t *buff, size_t size) {
	crc_t crc;
	crc_init_ref(&crc, 16, 0x3d65, 0, 0xffff, true, true);
	for ( int i=0; i < size; ++i)
		crc_update2(&crc, buff[i], 8);
	
	return BSWAP_16(crc_finish(&crc));
}

//width=16  poly=0x1021  init=0x1d0f  refin=false  refout=false  xorout=0x0000  check=0xe5cc  name="CRC-16/AUG-CCITT"
uint32_t CRC16_CCITT(uint8_t *buff, size_t size) {
	crc_t crc;
	crc_init(&crc, 16, 0x1021, 0x1d0f, 0);	
	for ( int i=0; i < size; ++i)
		crc_update(&crc, buff[i], 8);
	return  crc_finish(&crc);
}
//width=16  poly=0x8408  init=0xffff  refin=false  refout=true  xorout=0xffff  check=0xF0B8  name="CRC-16/ISO/IEC 13239"
uint32_t CRC16_Iso15693(uint8_t *buff, size_t size) {
	crc_t crc;
	crc_init_ref(&crc, 16, 0x8408, 0xFFFF, 0xFFFF, true, false);	
	for ( int i=0; i < size; ++i)
		crc_update(&crc, buff[i], 8);
	return reflect(crc_finish(&crc), 16);
}
//width=16  poly=0x8408  init=0xffff  refin=true  refout=true  xorout=0x0BC3  check=0xF0B8  name="CRC-16/ICLASS"
uint32_t CRC16_ICLASS(uint8_t *buff, size_t size) {

	crc_t crc;
	crc_init_ref(&crc, 16, 0x8408, 0xFFFF, 0x0BC3, false, false);	
	for ( int i=0; i < size; ++i)
		crc_update(&crc, buff[i], 8);
	return  crc_finish(&crc);
}