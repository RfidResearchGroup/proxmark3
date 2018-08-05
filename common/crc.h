//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Generic CRC calculation code.
//-----------------------------------------------------------------------------

#ifndef __CRC_H
#define __CRC_H

#include "common.h"	//stdint, stddef, stdbool
#include "util.h"	// reflect, bswap_16

typedef struct crc {
	uint32_t state;
	int order;
	uint32_t polynom;
	uint32_t initial_value;
	uint32_t final_xor;
	uint32_t mask;
	int topbit;
	bool refin;    /* Parameter: Reflect input bytes?        */
	bool refout;   /* Parameter: Reflect output CRC?         */
} crc_t;

/* Initialize a crc structure. order is the order of the polynom, e.g. 32 for a CRC-32
 * polynom is the CRC polynom. initial_value is the initial value of a clean state.
 * final_xor is XORed onto the state before returning it from crc_result(). 
 * refin is the setting for reversing (bitwise) the bytes during crc
 * refot is the setting for reversing (bitwise) the crc byte before returning it.
 */
extern void crc_init_ref(crc_t *crc, int order, uint32_t polynom, uint32_t initial_value, uint32_t final_xor, bool refin, bool refout);
	
/* Initialize a crc structure. order is the order of the polynom, e.g. 32 for a CRC-32
 * polynom is the CRC polynom. initial_value is the initial value of a clean state.
 * final_xor is XORed onto the state before returning it from crc_result(). */
extern void crc_init(crc_t *crc, int order, uint32_t polynom, uint32_t initial_value, uint32_t final_xor);


/* Update the crc state. data is the data of length data_width bits (only the
 * data_width lower-most bits are used).
 */
extern void crc_update(crc_t *crc, uint32_t data, int data_width);
extern void crc_update2(crc_t *crc, uint32_t data, int data_width);

/* Clean the crc state, e.g. reset it to initial_value */
extern void crc_clear(crc_t *crc);

/* Get the result of the crc calculation */
extern uint32_t crc_finish(crc_t *crc);

// Calculate CRC-8/Maxim checksum
uint32_t CRC8Maxim(uint8_t *buff, size_t size);

// Calculate CRC-8 Mifare MAD checksum
uint32_t CRC8Mad(uint8_t *buff, size_t size);

// Calculate CRC-4/Legic checksum
uint32_t CRC4Legic(uint8_t *buff, size_t size);

// Calculate CRC-8/Legic checksum
uint32_t CRC8Legic(uint8_t *buff, size_t size);

/* Static initialization of a crc structure */
#define CRC_INITIALIZER(_order, _polynom, _initial_value, _final_xor) { \
	.state = ((_initial_value) & ((1L<<(_order))-1)), \
	.order = (_order), \
	.polynom = (_polynom), \
	.initial_value = (_initial_value), \
	.final_xor = (_final_xor), \
	.mask = ((1L<<(_order))-1) \
	.refin = false, \
	.refout = false \
	}

#endif /* __CRC_H */
