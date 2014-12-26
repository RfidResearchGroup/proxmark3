//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency AWID 26 commands
//-----------------------------------------------------------------------------

#ifndef CMDLFAWID26_H__
#define CMDLFAWID26_H__

int CmdLFAWID26(const char *Cmd);

int CmdClone(const char *Cmd);
bool awid26_hex_to_uid(unsigned char *response, char *awid26);
bool bcd_to_awid26_bin(unsigned char *awid26, unsigned char *bcd);
#endif
