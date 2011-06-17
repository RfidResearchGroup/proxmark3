//-----------------------------------------------------------------------------
// Merlok - June 2011
// Gerhard de Koning Gans - May 2008
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 14443 type A.
//-----------------------------------------------------------------------------

#ifndef __ISO14443A_H
#define __ISO14443A_H
#include "common.h"

// BIG CHANGE - UNDERSTAND THIS BEFORE WE COMMIT
#define RECV_CMD_OFFSET    3032
#define RECV_RES_OFFSET    3096
#define DMA_BUFFER_OFFSET  3160
#define DMA_BUFFER_SIZE    4096
#define TRACE_LENGTH       3000
// mifare reader                      over DMA buffer (SnoopIso14443a())!!!
#define MIFARE_BUFF_OFFSET 3560  //              \/   \/   \/
// card emulator memory
#define EML_RESPONSES      4000
#define CARD_MEMORY        6000
#define CARD_MEMORY_LEN    1024

typedef struct nestedVector { uint32_t nt, ks1; } nestedVector;

extern byte_t oddparity (const byte_t bt);
extern uint32_t GetParity(const uint8_t * pbtCmd, int iLen);
extern void AppendCrc14443a(uint8_t* data, int len);

extern void ReaderTransmitShort(const uint8_t* bt);
extern void ReaderTransmit(uint8_t* frame, int len);
extern void ReaderTransmitPar(uint8_t* frame, int len, uint32_t par);
extern int ReaderReceive(uint8_t* receivedAnswer);
extern int ReaderReceivePar(uint8_t* receivedAnswer, uint32_t * parptr);

extern void iso14443a_setup();
extern int iso14443a_select_card(uint8_t * uid_ptr, iso14a_card_select_t * resp_data, uint32_t * cuid_ptr);
extern void iso14a_set_trigger(int enable);

extern void iso14a_clear_tracelen(void);
extern void iso14a_set_tracing(int enable);
extern int LogTrace(const uint8_t * btBytes, int iLen, int iSamples, uint32_t dwParity, int bReader);

#endif /* __ISO14443A_H */
