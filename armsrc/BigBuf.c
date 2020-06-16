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

#include "string.h"
#include "dbprint.h"
#include "pm3_cmd.h"

extern uint8_t _stack_start, __bss_end__;

// BigBuf is the large multi-purpose buffer, typically used to hold A/D samples or traces.
// Also used to hold various smaller buffers and the Mifare Emulator Memory.
// We know that bss is aligned to 4 bytes.
static uint8_t* BigBuf = &__bss_end__;

/* BigBuf memory layout:
Pointer to highest available memory: BigBuf_hi
    high BigBuf_size
    reserved = BigBuf_malloc()  subtracts amount from BigBuf_hi,
    low  0x00
*/

static uint32_t BigBuf_size = 0;

// High memory mark
static uint32_t BigBuf_hi = 0;

// pointer to the emulator memory.
static uint8_t *emulator_memory = NULL;

// trace related variables
static uint32_t traceLen = 0;
static bool tracing = true;

// compute the available size for BigBuf
void BigBuf_initialize(void) {
    BigBuf_size = (uint32_t)&_stack_start - (uint32_t)&__bss_end__;
    BigBuf_hi = BigBuf_size;
    traceLen = 0;
}

// get the address of BigBuf
uint8_t *BigBuf_get_addr(void) {
    return (uint8_t *)BigBuf;
}

uint32_t BigBuf_get_size(void) {
    return BigBuf_size;
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
    memset(BigBuf, 0, BigBuf_size);
    if (verbose)
        Dbprintf("Buffer cleared (%i bytes)", BigBuf_size);
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
    if (BigBuf_hi < chunksize)
        return NULL; // no memory left

    chunksize = (chunksize + 3) & 0xfffc; // round to next multiple of 4
    BigBuf_hi -= chunksize;  // aligned to 4 Byte boundary
    return (uint8_t *)BigBuf + BigBuf_hi;
}

// free ALL allocated chunks. The whole BigBuf is available for traces or samples again.
void BigBuf_free(void) {
    BigBuf_hi = BigBuf_size;
    emulator_memory = NULL;
    // shouldn't this empty BigBuf also?
}

// free allocated chunks EXCEPT the emulator memory
void BigBuf_free_keep_EM(void) {
    if (emulator_memory != NULL)
        BigBuf_hi = emulator_memory - (uint8_t *)BigBuf;
    else
        BigBuf_hi = BigBuf_size;

    // shouldn't this empty BigBuf also?
}

void BigBuf_print_status(void) {
    DbpString(_CYAN_("Memory"));
    Dbprintf("  BigBuf_size.............%d", BigBuf_size);
    Dbprintf("  Available memory........%d", BigBuf_hi);
    DbpString(_CYAN_("Tracing"));
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
    tracelog_hdr_t *hdr = (tracelog_hdr_t *)(trace + traceLen);

    uint32_t num_paritybytes = (iLen - 1) / 8 + 1; // number of valid paritybytes in *parity

    // Return when trace is full
    if (TRACELOG_HDR_LEN + iLen + num_paritybytes >= BigBuf_max_traceLen() - traceLen) {
        tracing = false; // don't trace any more
        return false;
    }

    uint32_t duration;
    if (timestamp_end > timestamp_start) {
        duration = timestamp_end - timestamp_start;
    } else {
        duration = (UINT32_MAX - timestamp_start) + timestamp_end;
    }

    if (duration > 0x7FFF) {
        if (DBGLEVEL >= DBG_DEBUG) {
            Dbprintf("Error in LogTrace: duration too long for 15 bits encoding: 0x%08x start:0x%08x end:0x%08x", duration, timestamp_start, timestamp_end);
            Dbprintf("Forcing duration = 0");
        }
        duration = 0;
    }

    hdr->timestamp = timestamp_start;
    hdr->duration = duration;
    hdr->data_len = iLen;
    hdr->isResponse = !readerToTag;
    traceLen += TRACELOG_HDR_LEN;

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
