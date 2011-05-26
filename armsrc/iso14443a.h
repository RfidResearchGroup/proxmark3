#ifndef __ISO14443A_H
#define __ISO14443A_H
#include "common.h"

extern byte_t oddparity (const byte_t bt);
extern uint32_t GetParity(const uint8_t * pbtCmd, int iLen);
extern void AppendCrc14443a(uint8_t* data, int len);

extern void ReaderTransmitShort(const uint8_t* bt);
extern void ReaderTransmit(uint8_t* frame, int len);
extern void ReaderTransmitPar(uint8_t* frame, int len, uint32_t par);
extern int ReaderReceive(uint8_t* receivedAnswer);

extern void iso14443a_setup();
extern int iso14443a_select_card(uint8_t * uid_ptr, iso14a_card_select_t * resp_data, uint32_t * cuid_ptr);
extern void iso14a_set_trigger(int enable);

#endif /* __ISO14443A_H */
