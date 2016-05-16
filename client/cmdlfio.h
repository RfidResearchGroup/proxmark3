// Low frequency Kantech IOProx commands
//-----------------------------------------------------------------------------

#ifndef CMDLFIO_H__
#define CMDLFIO_H__

#include <stdio.h>      // sscanf
#include "proxmark3.h"  // Definitions, USB controls, etc
#include "ui.h"         // PrintAndLog
#include "cmdparser.h"  // CmdsParse, CmdsHelp
#include "cmdlfawid.h"  // AWID function declarations
#include "lfdemod.h"    // parityTest
#include "util.h"       // weigandparity
#include "protocols.h"  // for T55xx config register definitions

#include <stdlib.h>
#include <string.h>
#include "data.h"
#include "cmdmain.h"
#include "cmddata.h"
#include "lfdemod.h"    // bitbytes_to_byte
int CmdLFIO(const char *Cmd);
int CmdIODemodFSK(const char *Cmd);
int CmdIOClone(const char *Cmd);

int getIOProxBits(uint8_t version, uint8_t fc, uint16_t cn, uint8_t *bits);
int usage_lf_io_fskdemod(void);
int usage_lf_io_clone(void);
int usage_lf_io_sim(void);
#endif
