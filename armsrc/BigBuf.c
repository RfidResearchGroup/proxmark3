//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
// Gerhard de Koning Gans, April 2008, May 2011
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// BigBuf and functions to allocate/free parts of it.
//-----------------------------------------------------------------------------

#include <stdint.h>
#include "proxmark3.h"
#include "apps.h"
#include "string.h"

// BigBuf is the large multi-purpose buffer, typically used to hold A/D samples or traces.
// Also used to hold various smaller buffers and the Mifare Emulator Memory.

// declare it as uint32_t to achieve alignment to 4 Byte boundary
static uint32_t BigBuf[BIGBUF_SIZE/sizeof(uint32_t)];

// High memory mark
static uint16_t BigBuf_hi = BIGBUF_SIZE;

// pointer to the emulator memory.
static uint8_t *emulator_memory = NULL;

// trace related global variables
// (only one left). ToDo: make this static as well?
uint16_t traceLen = 0;


// get the address of BigBuf
uint8_t *BigBuf_get_addr(void)
{
	return (uint8_t *)BigBuf;
}


// get the address of the emulator memory. Allocate part of Bigbuf for it, if not yet done
uint8_t *BigBuf_get_EM_addr(void)
{
	if (emulator_memory == NULL) {		// not yet allocated
		emulator_memory = BigBuf_malloc(CARD_MEMORY_SIZE);
	}
	
	return emulator_memory;
}


// clear ALL of BigBuf
void BigBuf_Clear(void)
{
	memset(BigBuf,0,BIGBUF_SIZE);
	Dbprintf("Buffer cleared (%i bytes)",BIGBUF_SIZE);
}


// allocate a chunk of memory from BigBuf. We allocate high memory first. The unallocated memory
// at the beginning of BigBuf is always for traces/samples
uint8_t *BigBuf_malloc(uint16_t chunksize)
{
	if (BigBuf_hi - chunksize < 0) { 
		return NULL;							// no memory left
	} else {
		chunksize = (chunksize + 3) & 0xfffc;	// round to next multiple of 4
		BigBuf_hi -= chunksize; 		  		// aligned to 4 Byte boundary 
		return (uint8_t *)BigBuf + BigBuf_hi;
	}
}


// free ALL allocated chunks. The whole BigBuf is available for traces or samples again.
void BigBuf_free(void)
{
	BigBuf_hi = BIGBUF_SIZE;
	emulator_memory = NULL;
}


// free allocated chunks EXCEPT the emulator memory
void BigBuf_free_keep_EM(void)
{
	if (emulator_memory != NULL) {
		BigBuf_hi = emulator_memory - (uint8_t *)BigBuf;
	} else {
		BigBuf_hi = BIGBUF_SIZE;
	}
}


// return the maximum trace length (i.e. the unallocated size of BigBuf)
uint16_t BigBuf_max_traceLen(void)
{
	return BigBuf_hi;
}
