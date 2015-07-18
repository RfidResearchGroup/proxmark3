//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency AWID commands
//-----------------------------------------------------------------------------

#ifndef CMDLFAWID_H__
#define CMDLFAWID_H__

int CmdLFAWID(const char *Cmd);
//int CmdAWIDDemod(const char *Cmd);
int CmdAWIDDemodFSK(const char *Cmd);
int CmdAWIDSim(const char *Cmd);
int CmdAWIDClone(const char *Cmd);
int getAWIDBits(unsigned int fc, unsigned int cn, uint8_t *AWIDBits);
int usage_lf_awid_fskdemod(void);
int usage_lf_awid_clone(void);
int usage_lf_awid_sim(void);

#endif
