//-----------------------------------------------------------------------------
// Copyright (C) 2014 Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE Desfire commands
//-----------------------------------------------------------------------------

int CmdHFMFDes(const char *Cmd);
int CmdHF14ADesAuth(const char* cmd);
int CmdHF14ADesRb(const char* cmd);
int CmdHF14ADesWb(const char* cmd);
int CmdHF14ADesInfo(const char *Cmd);
int CmdHF14ADesEnumApplications(const char *Cmd);
int CmdHF14ADesNonces(const char *Cmd);
char * GetCardSizeStr( uint8_t fsize );
char * GetVendorStr( uint8_t id);
char * GetProtocolStr(uint8_t id);
