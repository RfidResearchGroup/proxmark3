//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Generic CRC calculation code.
//-----------------------------------------------------------------------------

#ifndef __CRC_H
#define __CRC_H

#include <stdint.h>

typedef struct crc {
	uint32_t state;
	int order;
	uint32_t polynom;
	uint32_t initial_value;
	uint32_t final_xor;
	uint32_t mask;
} crc_t;

/* Initialize a crc structure. order is the order of the polynom, e.g. 32 for a CRC-32
 * polynom is the CRC polynom. initial_value is the initial value of a clean state.
 * final_xor is XORed onto the state before returning it from crc_result(). */
extern void crc_init(crc_t *crc, int order, uint32_t polynom, uint32_t initial_value, uint32_t final_xor);

/* Update the crc state. data is the data of length data_width bits (only the the
 * data_width lower-most bits are used).
 */
extern void crc_update(crc_t *crc, uint32_t data, int data_width);

/* Clean the crc state, e.g. reset it to initial_value */
extern void crc_clear(crc_t *crc);

/* Get the result of the crc calculation */
extern uint32_t crc_finish(crc_t *crc);

/* Static initialization of a crc structure */
#define CRC_INITIALIZER(_order, _polynom, _initial_value, _final_xor) { \
	.state = ((_initial_value) & ((1L<<(_order))-1)), \
	.order = (_order), \
	.polynom = (_polynom), \
	.initial_value = (_initial_value), \
	.final_xor = (_final_xor), \
	.mask = ((1L<<(_order))-1) }

#endif /* __CRC_H */
