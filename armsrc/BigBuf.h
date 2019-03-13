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

#ifndef __BIGBUF_H
#define __BIGBUF_H

#include <stdbool.h> // for bool
#include "proxmark3.h"
#include "string.h"
#include "ticks.h"

#define BIGBUF_SIZE             40000
#define MAX_FRAME_SIZE          256 // maximum allowed ISO14443 frame
#define MAX_PARITY_SIZE         ((MAX_FRAME_SIZE + 7) / 8)
#define MAX_MIFARE_FRAME_SIZE   18  // biggest Mifare frame is answer to a read (one block = 16 Bytes) + 2 Bytes CRC
#define MAX_MIFARE_PARITY_SIZE  3   // need 18 parity bits for the 18 Byte above. 3 Bytes are enough to store these
#define CARD_MEMORY_SIZE        4096
#define DMA_BUFFER_SIZE         256 //128  (how big is the dma?!?

extern uint8_t *BigBuf_get_addr(void);
extern uint8_t *BigBuf_get_EM_addr(void);
extern uint16_t BigBuf_max_traceLen(void);
extern void BigBuf_Clear(void);
extern void BigBuf_Clear_ext(bool verbose);
extern void BigBuf_Clear_keep_EM(void);
extern void BigBuf_Clear_EM(void);
extern uint8_t *BigBuf_malloc(uint16_t);
extern void BigBuf_free(void);
extern void BigBuf_free_keep_EM(void);
extern void BigBuf_print_status(void);
extern uint32_t BigBuf_get_traceLen(void);
extern void clear_trace(void);
extern void set_tracing(bool enable);
extern void set_tracelen(uint32_t value);
extern bool get_tracing(void);
extern bool RAMFUNC LogTrace(const uint8_t *btBytes, uint16_t iLen, uint32_t timestamp_start, uint32_t timestamp_end, uint8_t *parity, bool readerToTag);
extern uint8_t emlSet(uint8_t *data, uint32_t offset, uint32_t length);
#endif /* __BIGBUF_H */
