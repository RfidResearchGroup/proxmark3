//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// FIDO2 authenticators core data and commands
// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html
//-----------------------------------------------------------------------------
//
#ifndef __FIDOCORE_H__
#define __FIDOCORE_H__

#include <stddef.h>
#include <stdint.h>

enum fido2Commands {
	fido2CmdMakeCredential		= 0x01,
	fido2CmdGetAssertion		= 0x02,
	fido2CmdCancel				= 0x03,
	fido2CmdGetInfo				= 0x04,
	fido2CmdClientPIN			= 0x06,
	fido2CmdReset				= 0x07,
	fido2CmdGetNextAssertion	= 0x08,
};



extern char *fido2GetCmdMemberDescription(uint8_t cmdCode, uint8_t memberNum);

#endif /* __FIDOCORE_H__ */
