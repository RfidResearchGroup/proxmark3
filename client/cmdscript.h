//-----------------------------------------------------------------------------
// Copyright (C) 2013 m h swende <martin at swende.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Some lua scripting glue to proxmark core.
//-----------------------------------------------------------------------------

#ifndef CMDSCRIPT_H__
#define CMDSCRIPT_H__

extern int CmdScript(const char *Cmd);

extern int CmdScriptList(const char *Cmd);
extern int CmdScriptRun(const char *Cmd);
#endif
