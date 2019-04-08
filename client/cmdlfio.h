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
int CmdIOProxDemod(const char *Cmd);
int CmdIOProxRead(const char *Cmd);
int CmdIOProxSim(const char *Cmd);
int CmdIOProxClone(const char *Cmd);

int getIOProxBits(uint8_t version, uint8_t fc, uint16_t cn, uint8_t *bits);

int usage_lf_io_read(void);
int usage_lf_io_clone(void);
int usage_lf_io_sim(void);
#endif
