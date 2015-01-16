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


#define BIGBUF_SIZE				40000
#define TRACE_OFFSET			0
#define TRACE_SIZE				3000
#define RECV_CMD_OFFSET			(TRACE_OFFSET + TRACE_SIZE)
#define MAX_FRAME_SIZE			256
#define MAX_PARITY_SIZE			((MAX_FRAME_SIZE + 1)/ 8)
#define RECV_CMD_PAR_OFFSET		(RECV_CMD_OFFSET + MAX_FRAME_SIZE)
#define RECV_RESP_OFFSET		(RECV_CMD_PAR_OFFSET + MAX_PARITY_SIZE)
#define RECV_RESP_PAR_OFFSET 	(RECV_RESP_OFFSET + MAX_FRAME_SIZE)
#define CARD_MEMORY_OFFSET		(RECV_RESP_PAR_OFFSET + MAX_PARITY_SIZE)
#define CARD_MEMORY_SIZE		4096	
#define DMA_BUFFER_OFFSET  		CARD_MEMORY_OFFSET
#define DMA_BUFFER_SIZE    		CARD_MEMORY_SIZE
#define FREE_BUFFER_OFFSET 		(CARD_MEMORY_OFFSET + CARD_MEMORY_SIZE)
#define FREE_BUFFER_SIZE   		(BIGBUF_SIZE - FREE_BUFFER_OFFSET - 1)

extern uint8_t *BigBuf_get_addr(void);
extern uint16_t BigBuf_max_trace_len(void);
void BigBuf_Clear(void);
extern uint8_t *BigBuf_malloc(uint16_t);
extern void BigBuf_free(void);

extern uint16_t traceLen;

#endif /* __BIGBUF_H */
