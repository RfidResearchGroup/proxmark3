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

// trace related variables
static uint16_t traceLen = 0;
int tracing = 1; //Last global one.. todo static?

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
	BigBuf_Clear_ext(true);
}
// clear ALL of BigBuf
void BigBuf_Clear_ext(bool verbose)
{
	memset(BigBuf,0,BIGBUF_SIZE);
	if (verbose) 
		Dbprintf("Buffer cleared (%i bytes)",BIGBUF_SIZE);
}

void BigBuf_Clear_keep_EM(void)
{
	memset(BigBuf,0,BigBuf_hi);
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

void BigBuf_print_status(void)
{
	Dbprintf("Memory");
	Dbprintf("  BIGBUF_SIZE.............%d", BIGBUF_SIZE);
	Dbprintf("  BigBuf_hi  .............%d", BigBuf_hi);
	Dbprintf("Tracing");
	Dbprintf("  tracing ................%d", tracing);
	Dbprintf("  traceLen ...............%d", traceLen);
}


// return the maximum trace length (i.e. the unallocated size of BigBuf)
uint16_t BigBuf_max_traceLen(void)
{
	return BigBuf_hi;
}

void clear_trace() {
	traceLen = 0;
}

void set_tracing(bool enable) {
	tracing = enable;
}

/**
 * Get the number of bytes traced
 * @return
 */
uint16_t BigBuf_get_traceLen(void)
{
	return traceLen;
}

/**
  This is a function to store traces. All protocols can use this generic tracer-function.
  The traces produced by calling this function can be fetched on the client-side
  by 'hf list raw', alternatively 'hf list <proto>' for protocol-specific
  annotation of commands/responses.

**/
bool RAMFUNC LogTrace(const uint8_t *btBytes, uint16_t iLen, uint32_t timestamp_start, uint32_t timestamp_end, uint8_t *parity, bool readerToTag)
{
	if (!tracing) return FALSE;

	uint8_t *trace = BigBuf_get_addr();

	uint16_t num_paritybytes = (iLen-1)/8 + 1;	// number of valid paritybytes in *parity
	uint16_t duration = timestamp_end - timestamp_start;

	// Return when trace is full
	uint16_t max_traceLen = BigBuf_max_traceLen();

	if (traceLen + sizeof(iLen) + sizeof(timestamp_start) + sizeof(duration) + num_paritybytes + iLen >= max_traceLen) {
		tracing = FALSE;	// don't trace any more
		return FALSE;
	}
	// Traceformat:
	// 32 bits timestamp (little endian)
	// 16 bits duration (little endian)
	// 16 bits data length (little endian, Highest Bit used as readerToTag flag)
	// y Bytes data
	// x Bytes parity (one byte per 8 bytes data)

	// timestamp (start)
	trace[traceLen++] = ((timestamp_start >> 0) & 0xff);
	trace[traceLen++] = ((timestamp_start >> 8) & 0xff);
	trace[traceLen++] = ((timestamp_start >> 16) & 0xff);
	trace[traceLen++] = ((timestamp_start >> 24) & 0xff);

	// duration
	trace[traceLen++] = ((duration >> 0) & 0xff);
	trace[traceLen++] = ((duration >> 8) & 0xff);

	// data length
	trace[traceLen++] = ((iLen >> 0) & 0xff);
	trace[traceLen++] = ((iLen >> 8) & 0xff);

	// readerToTag flag
	if (!readerToTag) {
		trace[traceLen - 1] |= 0x80;
	}

	// data bytes
	if (btBytes != NULL && iLen != 0) {
		memcpy(trace + traceLen, btBytes, iLen);
	}
	traceLen += iLen;

	// parity bytes
	if (num_paritybytes != 0) {
		if (parity != NULL) {
			memcpy(trace + traceLen, parity, num_paritybytes);
		} else {
			memset(trace + traceLen, 0x00, num_paritybytes);
		}
	}
	traceLen += num_paritybytes;

	return TRUE;
}


int LogTraceHitag(const uint8_t * btBytes, int iBits, int iSamples, uint32_t dwParity, int readerToTag)
{
	/**
	  Todo, rewrite the logger to use the generic functionality instead. It should be noted, however,
	  that this logger takes number of bits as argument, not number of bytes.
	  **/

	if (!tracing) return FALSE;

	uint8_t *trace = BigBuf_get_addr();
	uint16_t iLen = nbytes(iBits);
	// Return when trace is full
	if (traceLen + sizeof(rsamples) + sizeof(dwParity) + sizeof(iBits) + iLen > BigBuf_max_traceLen()) return FALSE;

	//Hitag traces appear to use this traceformat:
	// 32 bits timestamp (little endian,Highest Bit used as readerToTag flag)
	// 32 bits parity
	// 8 bits size (number of bits in the trace entry, not number of bytes)
	// y Bytes data

	rsamples += iSamples;
	trace[traceLen++] = ((rsamples >> 0) & 0xff);
	trace[traceLen++] = ((rsamples >> 8) & 0xff);
	trace[traceLen++] = ((rsamples >> 16) & 0xff);
	trace[traceLen++] = ((rsamples >> 24) & 0xff);

	if (!readerToTag) {
		trace[traceLen - 1] |= 0x80;
	}

	trace[traceLen++] = ((dwParity >> 0) & 0xff);
	trace[traceLen++] = ((dwParity >> 8) & 0xff);
	trace[traceLen++] = ((dwParity >> 16) & 0xff);
	trace[traceLen++] = ((dwParity >> 24) & 0xff);
	trace[traceLen++] = iBits;

	memcpy(trace + traceLen, btBytes, iLen);
	traceLen += iLen;

	return TRUE;
}


// Emulator memory
uint8_t emlSet(uint8_t *data, uint32_t offset, uint32_t length){
	uint8_t* mem = BigBuf_get_EM_addr();
	if(offset+length < CARD_MEMORY_SIZE)
	{
		memcpy(mem+offset, data, length);
		return 0;
	}else
	{
		Dbprintf("Error, trying to set memory outside of bounds! %d  > %d", (offset+length), CARD_MEMORY_SIZE);
		return 1;
	}
}
