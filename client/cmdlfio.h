// Low frequency Kantech IOProx commands
//-----------------------------------------------------------------------------

#ifndef CMDLFIO_H__
#define CMDLFIO_H__

#include "common.h"

int CmdLFIO(const char *Cmd);

int demodIOProx(void);
int getIOProxBits(uint8_t version, uint8_t fc, uint16_t cn, uint8_t *bits);

#endif
