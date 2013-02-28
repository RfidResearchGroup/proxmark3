//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency T55xx commands
//-----------------------------------------------------------------------------

#ifndef CMDLFT55XX_H__
#define CMDLFT55XX_H__

int CmdLFT55XX(const char *Cmd);

int CmdReadBlk(const char *Cmd);
int CmdReadBlkPWD(const char *Cmd);
int CmdWriteBlk(const char *Cmd);
int CmdWriteBLkPWD(const char *Cmd);
int CmdReadTrace(const char *Cmd);

#endif
