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

#include "fidocore.h"

typedef struct {
	uint8_t ErrorCode;
	char *ShortDescription;
	char *Description;
} fido2Error_t;

fido2Error_t fido2Errors[] = {
	{0xFF, "n/a",									"n/a"},
	{0x00, "CTAP1_ERR_SUCCESS",					"Indicates successful response."},
	{0x01, "CTAP1_ERR_INVALID_COMMAND",			"The command is not a valid CTAP command."},
	{0x02, "CTAP1_ERR_INVALID_PARAMETER",		"The command included an invalid parameter."},
	{0x03, "CTAP1_ERR_INVALID_LENGTH",			"Invalid message or item length."},
	{0x04, "CTAP1_ERR_INVALID_SEQ",				"Invalid message sequencing."},
	{0x05, "CTAP1_ERR_TIMEOUT",					"Message timed out."},
	{0x06, "CTAP1_ERR_CHANNEL_BUSY",			"Channel busy."},
	{0x0A, "CTAP1_ERR_LOCK_REQUIRED",			"Command requires channel lock."},
	{0x0B, "CTAP1_ERR_INVALID_CHANNEL",			"Command not allowed on this cid."},
	{0x10, "CTAP2_ERR_CBOR_PARSING",			"Error while parsing CBOR."},
	{0x11, "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",	"Invalid/unexpected CBOR error."},
	{0x12, "CTAP2_ERR_INVALID_CBOR",			"Error when parsing CBOR."},
	{0x13, "CTAP2_ERR_INVALID_CBOR_TYPE",		"Invalid or unexpected CBOR type."},
	{0x14, "CTAP2_ERR_MISSING_PARAMETER",		"Missing non-optional parameter."},
	{0x15, "CTAP2_ERR_LIMIT_EXCEEDED",			"Limit for number of items exceeded."},
	{0x16, "CTAP2_ERR_UNSUPPORTED_EXTENSION",	"Unsupported extension."},
	{0x17, "CTAP2_ERR_TOO_MANY_ELEMENTS",		"Limit for number of items exceeded."},
	{0x18, "CTAP2_ERR_EXTENSION_NOT_SUPPORTED",	"Unsupported extension."},
	{0x19, "CTAP2_ERR_CREDENTIAL_EXCLUDED",		"Valid credential found in the exludeList."},
	{0x20, "CTAP2_ERR_CREDENTIAL_NOT_VALID",	"Credential not valid for authenticator."},
	{0x21, "CTAP2_ERR_PROCESSING",				"Processing (Lengthy operation is in progress)."},
	{0x22, "CTAP2_ERR_INVALID_CREDENTIAL",		"Credential not valid for the authenticator."},
	{0x23, "CTAP2_ERR_USER_ACTION_PENDING",		"Authentication is waiting for user interaction."},
	{0x24, "CTAP2_ERR_OPERATION_PENDING",		"Processing, lengthy operation is in progress."},
	{0x25, "CTAP2_ERR_NO_OPERATIONS",			"No request is pending."},
	{0x26, "CTAP2_ERR_UNSUPPORTED_ALGORITHM",	"Authenticator does not support requested algorithm."},
	{0x27, "CTAP2_ERR_OPERATION_DENIED",		"Not authorized for requested operation."},
	{0x28, "CTAP2_ERR_KEY_STORE_FULL",			"Internal key storage is full."},
	{0x29, "CTAP2_ERR_NOT_BUSY",				"Authenticator cannot cancel as it is not busy."},
	{0x2A, "CTAP2_ERR_NO_OPERATION_PENDING",	"No outstanding operations."},
	{0x2B, "CTAP2_ERR_UNSUPPORTED_OPTION",		"Unsupported option."},
	{0x2C, "CTAP2_ERR_INVALID_OPTION",			"Unsupported option."},
	{0x2D, "CTAP2_ERR_KEEPALIVE_CANCEL",		"Pending keep alive was cancelled."},
	{0x2E, "CTAP2_ERR_NO_CREDENTIALS",			"No valid credentials provided."},
	{0x2F, "CTAP2_ERR_USER_ACTION_TIMEOUT",		"Timeout waiting for user interaction."},
	{0x30, "CTAP2_ERR_NOT_ALLOWED",				"Continuation command, such as, authenticatorGetNextAssertion not allowed."},
	{0x31, "CTAP2_ERR_PIN_INVALID",				"PIN Blocked."},
	{0x32, "CTAP2_ERR_PIN_BLOCKED",				"PIN Blocked."},
	{0x33, "CTAP2_ERR_PIN_AUTH_INVALID",		"PIN authentication,pinAuth, verification failed."},
	{0x34, "CTAP2_ERR_PIN_AUTH_BLOCKED",		"PIN authentication,pinAuth, blocked. Requires power recycle to reset."},
	{0x35, "CTAP2_ERR_PIN_NOT_SET",				"No PIN has been set."},
	{0x36, "CTAP2_ERR_PIN_REQUIRED",			"PIN is required for the selected operation."},
	{0x37, "CTAP2_ERR_PIN_POLICY_VIOLATION",	"PIN policy violation. Currently only enforces minimum length."},
	{0x38, "CTAP2_ERR_PIN_TOKEN_EXPIRED",		"pinToken expired on authenticator."},
	{0x39, "CTAP2_ERR_REQUEST_TOO_LARGE",		"Authenticator cannot handle this request due to memory constraints."},
	{0x7F, "CTAP1_ERR_OTHER",					"Other unspecified error."},
	{0xDF, "CTAP2_ERR_SPEC_LAST", 				"CTAP 2 spec last error."},
};

typedef struct {
	fido2Commands Command;
	fido2PacketType PckType;
	uint8_t MemberNumber;
	char *Description;
} fido2Desc_t;

fido2Desc_t fido2CmdGetInfoRespDesc[] = {
	{fido2CmdMakeCredential, 	ptResponse, 0x01, "fmt"},
	{fido2CmdMakeCredential, 	ptResponse, 0x02, "authData"},
	{fido2CmdMakeCredential, 	ptResponse, 0x03, "attStmt"},
	
	{fido2CmdGetAssertion, 		ptResponse, 0x01, "credential"},
	{fido2CmdGetAssertion, 		ptResponse, 0x02, "authData"},
	{fido2CmdGetAssertion, 		ptResponse, 0x03, "signature"},
	{fido2CmdGetAssertion, 		ptResponse, 0x04, "publicKeyCredentialUserEntity"},
	{fido2CmdGetAssertion, 		ptResponse, 0x05, "numberOfCredentials"},
	
	{fido2CmdGetNextAssertion, 	ptResponse, 0x01, "credential"},
	{fido2CmdGetNextAssertion, 	ptResponse, 0x02, "authData"},
	{fido2CmdGetNextAssertion, 	ptResponse, 0x03, "signature"},
	{fido2CmdGetNextAssertion, 	ptResponse, 0x04, "publicKeyCredentialUserEntity"},
	
	{fido2CmdGetInfo, 			ptResponse, 0x01, "versions"},
	{fido2CmdGetInfo, 			ptResponse, 0x02, "extensions"},
	{fido2CmdGetInfo, 			ptResponse, 0x03, "aaguid"},
	{fido2CmdGetInfo, 			ptResponse, 0x04, "options"},
	{fido2CmdGetInfo, 			ptResponse, 0x05, "maxMsgSize"},
	{fido2CmdGetInfo, 			ptResponse, 0x06, "pinProtocols"},

	{fido2CmdClientPIN, 		ptResponse, 0x06, "keyAgreement"},
	{fido2CmdClientPIN, 		ptResponse, 0x06, "pinToken"},
	{fido2CmdClientPIN, 		ptResponse, 0x06, "retries"},
};

char *fido2GetCmdErrorDescription(uint8_t errorCode) {
	for (int i = 0; i < sizeof(fido2Errors) / sizeof(fido2Error_t); i++)
		if (fido2Errors[i].ErrorCode == errorCode)
			return fido2Errors[i].Description;
		
	return fido2Errors[0].Description;
}

char *fido2GetCmdMemberDescription(uint8_t cmdCode, uint8_t memberNum) {
	for (int i = 0; i < sizeof(fido2CmdGetInfoRespDesc) / sizeof(fido2Desc_t); i++)
		if (fido2CmdGetInfoRespDesc[i].Command == cmdCode &&
			fido2CmdGetInfoRespDesc[i].PckType == ptResponse &&
			fido2CmdGetInfoRespDesc[i].MemberNumber == memberNum )
			return fido2CmdGetInfoRespDesc[i].Description;

	return NULL;
}

