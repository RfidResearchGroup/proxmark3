//-----------------------------------------------------------------------------
// Copyright (C) X41 D-Sec GmbH, Yasar Klawohn, Markus Vervier
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443A commands
//-----------------------------------------------------------------------------

#ifndef CMDHFMFDESBRUTE_H__
#define CMDHFMFDESBRUTE_H__

//static int CmdHelp(const char *Cmd);
int CmdHfMfDesBrute(const char *Cmd);
int CmdHfMfDesBruteGetChallenge(const char *Cmd);
int CmdHfMfDesBruteOpenDoor(const char *Cmd);

#endif
