//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Securakey tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFSECURAKEY_H__
#define CMDLFSECURAKEY_H__

extern int CmdLFSecurakey(const char *Cmd);
extern int CmdSecurakeyClone(const char *Cmd);
extern int CmdSecurakeySim(const char *Cmd);
extern int CmdSecurakeyRead(const char *Cmd);
extern int CmdSecurakeyDemod(const char *Cmd);

#endif

