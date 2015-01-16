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

// The large multi-purpose buffer, typically used to hold A/D samples or traces,
// may be processed in some way. Also used to hold various smaller buffers.
static uint8_t BigBuf[BIGBUF_SIZE];

// High memory mark
static uint16_t BigBuf_hi = BIGBUF_SIZE;

// trace related global variables. Change to function calls?
//uint8_t *trace = BigBuf;
uint16_t traceLen;


// get the address of BigBuf
uint8_t *BigBuf_get_addr(void)
{
	return BigBuf;
}


// clear ALL of BigBuf
void BigBuf_Clear(void)
{
	memset(BigBuf,0,BIGBUF_SIZE);
	Dbprintf("Buffer cleared (%i bytes)",BIGBUF_SIZE);
}


// allocate a chunk of memory from BigBuf. We allocate high memory first. Low memory
// is always for traces/samples
uint8_t *BigBuf_malloc(uint16_t chunksize)
{
	if (BigBuf_hi - chunksize < 0) { 
		return NULL;						// no memory left
	} else {
		BigBuf_hi -= chunksize; 		  	// aligned to 4 Byte boundary 
		return BigBuf + BigBuf_hi;
	}
}


// free ALL allocated chunks. The whole BigBuf is available for traces again.
void BigBuf_free(void)
{
	BigBuf_hi = BIGBUF_SIZE;
}


// return the maximum trace length (i.e. the unallocated size of BigBuf)
uint16_t BigBuf_max_trace_len(void)
{
	return BigBuf_hi;
}