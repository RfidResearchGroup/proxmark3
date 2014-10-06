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
int CmdInfo(const char *Cmd);
char * GetBitRateStr(uint32_t id);
char * GetSaferStr(uint32_t id);
char * GetModulationStr( uint32_t id);
uint32_t PackBits(uint8_t start, uint8_t len, uint8_t* bitstream);
#endif
