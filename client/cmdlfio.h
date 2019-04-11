// Low frequency Kantech IOProx commands
//-----------------------------------------------------------------------------

#ifndef CMDLFIO_H__
#define CMDLFIO_H__

#include <stdio.h>      // sscanf
#include <stdlib.h>
#include <string.h>
#include "proxmark3.h"  // Definitions, USB controls, etc
#include "ui.h"         // PrintAndLog
#include "cmdparser.h"  // CmdsParse, CmdsHelp
#include "lfdemod.h"    // parityTest, bitbytes_to_byte
#include "util.h"       // weigandparity
#include "protocols.h"  // for T55xx config register definitions
#include "cmdmain.h"
#include "cmddata.h"

int CmdLFIO(const char *Cmd);

int demodIOProx(void);
int getIOProxBits(uint8_t version, uint8_t fc, uint16_t cn, uint8_t *bits);

#endif
