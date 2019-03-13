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
#include "BigBuf.h"

// BigBuf is the large multi-purpose buffer, typically used to hold A/D samples or traces.
// Also used to hold various smaller buffers and the Mifare Emulator Memory.
// declare it as uint32_t to achieve alignment to 4 Byte boundary
static uint32_t BigBuf[BIGBUF_SIZE / sizeof(uint32_t)];

/* BigBuf memory layout:
Pointer to highest available memory: BigBuf_hi

    high BIGBUF_SIZE
    reserved = BigBuf_malloc()  subtracts amount from BigBuf_hi,
    low  0x00
*/

// High memory mark
static uint16_t BigBuf_hi = BIGBUF_SIZE;

// pointer to the emulator memory.
static uint8_t *emulator_memory = NULL;

// trace related variables
static uint32_t traceLen = 0;
static bool tracing = true; //todo static?

// get the address of BigBuf
uint8_t *BigBuf_get_addr(void) {
    return (uint8_t *)BigBuf;
}

// get the address of the emulator memory. Allocate part of Bigbuf for it, if not yet done
uint8_t *BigBuf_get_EM_addr(void) {
    // not yet allocated
    if (emulator_memory == NULL)
        emulator_memory = BigBuf_malloc(CARD_MEMORY_SIZE);

    return emulator_memory;
}

// clear ALL of BigBuf
void BigBuf_Clear(void) {
    BigBuf_Clear_ext(true);
}

// clear ALL of BigBuf
void BigBuf_Clear_ext(bool verbose) {
    memset(BigBuf, 0, BIGBUF_SIZE);
    if (verbose)
        Dbprintf("Buffer cleared (%i bytes)", BIGBUF_SIZE);
}

void BigBuf_Clear_EM(void) {
    memset(BigBuf_get_EM_addr(), 0, CARD_MEMORY_SIZE);
}

void BigBuf_Clear_keep_EM(void) {
    memset(BigBuf, 0, BigBuf_hi);
}

// allocate a chunk of memory from BigBuf. We allocate high memory first. The unallocated memory
// at the beginning of BigBuf is always for traces/samples
uint8_t *BigBuf_malloc(uint16_t chunksize) {
    if (BigBuf_hi - chunksize < 0)
        return NULL; // no memory left

    chunksize = (chunksize + 3) & 0xfffc; // round to next multiple of 4
    BigBuf_hi -= chunksize;  // aligned to 4 Byte boundary
    return (uint8_t *)BigBuf + BigBuf_hi;
}

// free ALL allocated chunks. The whole BigBuf is available for traces or samples again.
void BigBuf_free(void) {
    BigBuf_hi = BIGBUF_SIZE;
    emulator_memory = NULL;
    // shouldn't this empty BigBuf also?
}

// free allocated chunks EXCEPT the emulator memory
void BigBuf_free_keep_EM(void) {
    if (emulator_memory != NULL)
        BigBuf_hi = emulator_memory - (uint8_t *)BigBuf;
    else
        BigBuf_hi = BIGBUF_SIZE;

    // shouldn't this empty BigBuf also?
}

void BigBuf_print_status(void) {
    Dbprintf("Memory");
    Dbprintf("  BIGBUF_SIZE.............%d", BIGBUF_SIZE);
    Dbprintf("  Available memory........%d", BigBuf_hi);
    Dbprintf("Tracing");
    Dbprintf("  tracing ................%d", tracing);
    Dbprintf("  traceLen ...............%d", traceLen);
}

// return the maximum trace length (i.e. the unallocated size of BigBuf)
uint16_t BigBuf_max_traceLen(void) {
    return BigBuf_hi;
}

void clear_trace(void) {
    traceLen = 0;
}
void set_tracelen(uint32_t value) {
    traceLen = value;
}
void set_tracing(bool enable) {
    tracing = enable;
}

bool get_tracing(void) {
    return tracing;
}

/**
 * Get the number of bytes traced
 * @return
 */
uint32_t BigBuf_get_traceLen(void) {
    return traceLen;
}

/**
  This is a function to store traces. All protocols can use this generic tracer-function.
  The traces produced by calling this function can be fetched on the client-side
  by 'hf list raw', alternatively 'hf list <proto>' for protocol-specific
  annotation of commands/responses.
**/
bool RAMFUNC LogTrace(const uint8_t *btBytes, uint16_t iLen, uint32_t timestamp_start, uint32_t timestamp_end, uint8_t *parity, bool readerToTag) {
    if (!tracing) return false;

    uint8_t *trace = BigBuf_get_addr();

    uint32_t num_paritybytes = (iLen - 1) / 8 + 1; // number of valid paritybytes in *parity
    uint32_t duration = timestamp_end - timestamp_start;

    // Return when trace is full
    if (traceLen + sizeof(iLen) + sizeof(timestamp_start) + sizeof(duration) + num_paritybytes + iLen >= BigBuf_max_traceLen()) {
        tracing = false; // don't trace any more
        return false;
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

    return true;
}

// Emulator memory
uint8_t emlSet(uint8_t *data, uint32_t offset, uint32_t length) {
    uint8_t *mem = BigBuf_get_EM_addr();
    if (offset + length < CARD_MEMORY_SIZE) {
        memcpy(mem + offset, data, length);
        return 0;
    }
    Dbprintf("Error, trying to set memory outside of bounds! %d  > %d", (offset + length), CARD_MEMORY_SIZE);
    return 1;
}
