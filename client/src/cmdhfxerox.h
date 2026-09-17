//-----------------------------------------------------------------------------
// High frequency Xerox commands (ISO14443B)
//-----------------------------------------------------------------------------

#ifndef CMDHFXEROX_H__
#define CMDHFXEROX_H__

#include "common.h"

int CmdHFXerox(const char *Cmd);
int read_xerox_uid(bool loop, bool verbose);

#endif
