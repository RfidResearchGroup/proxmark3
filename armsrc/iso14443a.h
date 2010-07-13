#ifndef __ISO14443A_H
#define __ISO14443A_H
#include "common.h"

extern void AppendCrc14443a(uint8_t* data, int len);
extern void ReaderTransmitShort(const uint8_t* bt);
extern void ReaderTransmit(uint8_t* frame, int len);
extern int ReaderReceive(uint8_t* receivedAnswer);
extern void iso14443a_setup();
extern int iso14443a_select_card(uint8_t * uid_ptr, iso14a_card_select_t * card_info);
extern void iso14a_set_trigger(int enable);

#endif /* __ISO14443A_H */
