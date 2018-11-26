//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE  Plus commands
//-----------------------------------------------------------------------------
//
//  Documentation here:
//
// FIDO Alliance specifications
// https://fidoalliance.org/download/
// FIDO NFC Protocol Specification v1.0
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-nfc-protocol-v1.2-ps-20170411.html
// FIDO U2F Raw Message Formats
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
//-----------------------------------------------------------------------------


#include "cmdhffido.h"

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <jansson.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509.h>
#include <mbedtls/pk.h>
#include "comms.h"
#include "cmdmain.h"
#include "util.h"
#include "ui.h"
#include "proxmark3.h"
#include "mifare.h"
#include "emv/emvcore.h"
#include "emv/emvjson.h"
#include "emv/dump.h"
#include "cliparser/cliparser.h"
#include "crypto/asn1utils.h"
#include "crypto/libpcrypto.h"
#include "fido/cbortools.h"
#include "fido/fidocore.h"
#include "fido/cose.h"

static int CmdHelp(const char *Cmd);

int CmdHFFidoInfo(const char *cmd) {
	
	if (cmd && strlen(cmd) > 0)
		PrintAndLog("WARNING: command don't have any parameters.\n");
	
	// info about 14a part
	CmdHF14AInfo("");

	// FIDO info
	PrintAndLog("--------------------------------------------"); 
	SetAPDULogging(false);
	
	uint8_t buf[APDU_RES_LEN] = {0};
	size_t len = 0;
	uint16_t sw = 0;
	int res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);

	if (res) {
		DropField();
		return res;
	}
	
	if (sw != 0x9000) {
		if (sw)
			PrintAndLog("Not a FIDO card! APDU response: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff)); 
		else
			PrintAndLog("APDU exchange error. Card returns 0x0000."); 
		
		DropField();
		return 0;
	}
	
	if (!strncmp((char *)buf, "U2F_V2", 7)) {
		if (!strncmp((char *)buf, "FIDO_2_0", 8)) {
			PrintAndLog("FIDO2 authenricator detected. Version: %.*s", len, buf); 
		} else {
			PrintAndLog("FIDO authenricator detected (not standard U2F)."); 
			PrintAndLog("Non U2F authenticator version:"); 
			dump_buffer((const unsigned char *)buf, len, NULL, 0);
		}
	} else {
		PrintAndLog("FIDO U2F authenricator detected. Version: %.*s", len, buf); 
	}

	res = FIDO2GetInfo(buf, sizeof(buf), &len, &sw);
	DropField();
	if (res) {
		return res;
	}
	if (sw != 0x9000) {
		PrintAndLog("FIDO2 version not exists (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff)); 
		
		return 0;
	}
	
	if(buf[0]) {
		PrintAndLog("FIDO2 ger version error: %d - %s", buf[0], fido2GetCmdErrorDescription(buf[0])); 
		return 0;
	}

	if (len > 1) {
//		if (false) {
//			PrintAndLog("FIDO2 version: (len=%d)", len); 
//			dump_buffer((const unsigned char *)buf, len, NULL, 0);
//		}

		PrintAndLog("FIDO2 version CBOR decoded:"); 
		TinyCborPrintFIDOPackage(fido2CmdGetInfo, true, &buf[1], len - 1);
	} else {
		PrintAndLog("FIDO2 version length error"); 
	}
		
	return 0;
}

json_t *OpenJson(int paramnum, char *fname, void* argtable[], bool *err) {	
	json_t *root = NULL;
	json_error_t error;
	*err = false;

	uint8_t jsonname[250] ={0};
	char *cjsonname = (char *)jsonname;
	int jsonnamelen = 0;
	
	// CLIGetStrWithReturn(paramnum, jsonname, &jsonnamelen);
	if (CLIParamStrToBuf(arg_get_str(paramnum), jsonname, sizeof(jsonname), &jsonnamelen))  {
		CLIParserFree();
		return NULL;
	}
	
	// current path + file name
	if (!strstr(cjsonname, ".json"))
		strcat(cjsonname, ".json");
	
	if (jsonnamelen) {
		strcpy(fname, get_my_executable_directory());
		strcat(fname, cjsonname);
		if (access(fname, F_OK) != -1) {
			root = json_load_file(fname, 0, &error);
			if (!root) {
				PrintAndLog("ERROR: json error on line %d: %s", error.line, error.text);
				*err = true;
				return NULL; 
			}
			
			if (!json_is_object(root)) {
				PrintAndLog("ERROR: Invalid json format. root must be an object.");
				json_decref(root);
				*err = true;
				return NULL; 
			}
			
		} else {
			root = json_object();
		}
	}
	return root;
}

int CmdHFFidoRegister(const char *cmd) {
	uint8_t data[64] = {0};
	int chlen = 0;
	uint8_t cdata[250] = {0};
	int applen = 0;
	uint8_t adata[250] = {0};
	json_t *root = NULL;
	
	CLIParserInit("hf fido reg", 
		"Initiate a U2F token registration. Needs two 32-byte hash number. \nchallenge parameter (32b) and application parameter (32b).", 
		"Usage:\n\thf fido reg -> execute command with 2 parameters, filled 0x00\n"
			"\thf fido reg 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f -> execute command with parameters"
			"\thf fido reg -p s0 s1 -> execute command with plain parameters");

	void* argtable[] = {
		arg_param_begin,
		arg_lit0("aA",  "apdu",     "show APDU reqests and responses"),
		arg_litn("vV",  "verbose",  0, 2, "show technical data. vv - show full certificates data"),
		arg_lit0("pP",  "plain",    "send plain ASCII to challenge and application parameters instead of HEX"),
		arg_lit0("tT",  "tlv",      "Show DER certificate contents in TLV representation"),
		arg_str0("jJ",  "json",		"fido.json", "JSON input / output file name for parameters."),
		arg_str0(NULL,  NULL,       "<HEX/ASCII challenge parameter (32b HEX/1..16 chars)>", NULL),
		arg_str0(NULL,  NULL,       "<HEX/ASCII application parameter (32b HEX/1..16 chars)>", NULL),
		arg_param_end
	};
	CLIExecWithReturn(cmd, argtable, true);
	
	bool APDULogging = arg_get_lit(1);
	bool verbose = arg_get_lit(2);
	bool verbose2 = arg_get_lit(2) > 1;
	bool paramsPlain = arg_get_lit(3);
	bool showDERTLV = arg_get_lit(4);

	char fname[250] = {0};
	bool err;
	root = OpenJson(5, fname, argtable, &err);
	if(err)
		return 1;
	if (root) {	
		size_t jlen;
		JsonLoadBufAsHex(root, "$.ChallengeParam", data, 32, &jlen);
		JsonLoadBufAsHex(root, "$.ApplicationParam", &data[32], 32, &jlen);
	}
	
	if (paramsPlain) {
		memset(cdata, 0x00, 32);
		CLIGetStrWithReturn(6, cdata, &chlen);
		if (chlen && chlen > 16) {
			PrintAndLog("ERROR: challenge parameter length in ASCII mode must be less than 16 chars instead of: %d", chlen);
			return 1;
		}
	} else {
		CLIGetHexWithReturn(6, cdata, &chlen);
		if (chlen && chlen != 32) {
			PrintAndLog("ERROR: challenge parameter length must be 32 bytes only.");
			return 1;
		}
	}
	if (chlen)
		memmove(data, cdata, 32);
	
	
	if (paramsPlain) {
		memset(adata, 0x00, 32);
		CLIGetStrWithReturn(7, adata, &applen);
		if (applen && applen > 16) {
			PrintAndLog("ERROR: application parameter length in ASCII mode must be less than 16 chars instead of: %d", applen);
			return 1;
		}
	} else {
		CLIGetHexWithReturn(7, adata, &applen);
		if (applen && applen != 32) {
			PrintAndLog("ERROR: application parameter length must be 32 bytes only.");
			return 1;
		}
	}
	if (applen)
		memmove(&data[32], adata, 32);
	
	CLIParserFree();	
	
	SetAPDULogging(APDULogging);

	// challenge parameter [32 bytes] - The challenge parameter is the SHA-256 hash of the Client Data, a stringified JSON data structure that the FIDO Client prepares
	// application parameter [32 bytes] - The application parameter is the SHA-256 hash of the UTF-8 encoding of the application identity
	
	uint8_t buf[2048] = {0};
	size_t len = 0;
	uint16_t sw = 0;

	DropField();
	int res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);

	if (res) {
		PrintAndLog("Can't select authenticator. res=%x. Exit...", res);
		DropField();
		return res;
	}
	
	if (sw != 0x9000) {
		PrintAndLog("Can't select FIDO application. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff)); 
		DropField();
		return 2;
	}

	res = FIDORegister(data, buf,  sizeof(buf), &len, &sw);
	DropField();
	if (res) {
		PrintAndLog("Can't execute register command. res=%x. Exit...", res);
		return res;
	}
	
	if (sw != 0x9000) {
		PrintAndLog("ERROR execute register command. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff)); 
		return 3;
	}
	
	PrintAndLog("");
	if (APDULogging)
		PrintAndLog("---------------------------------------------------------------");
	PrintAndLog("data len: %d", len);
	if (verbose2) {
		PrintAndLog("--------------data----------------------");
		dump_buffer((const unsigned char *)buf, len, NULL, 0);
		PrintAndLog("--------------data----------------------");
	}

	if (buf[0] != 0x05) {
		PrintAndLog("ERROR: First byte must be 0x05, but it %2x", buf[0]);
		return 5;
	}
	PrintAndLog("User public key: %s", sprint_hex(&buf[1], 65));
	
	uint8_t keyHandleLen = buf[66];
	PrintAndLog("Key handle[%d]: %s", keyHandleLen, sprint_hex(&buf[67], keyHandleLen));
	
	int derp = 67 + keyHandleLen;
	int derLen = (buf[derp + 2] << 8) + buf[derp + 3] + 4;
	if (verbose2) {
		PrintAndLog("DER certificate[%d]:\n------------------DER-------------------", derLen);
		dump_buffer_simple((const unsigned char *)&buf[derp], derLen, NULL);
		PrintAndLog("\n----------------DER---------------------");
	} else {
		if (verbose)
			PrintAndLog("------------------DER-------------------");
		PrintAndLog("DER certificate[%d]: %s...", derLen, sprint_hex(&buf[derp], 20));
	}
	
	// check and print DER certificate
	uint8_t public_key[65] = {0};
	
	// print DER certificate in TLV view
	if (showDERTLV) {
		PrintAndLog("----------------DER TLV-----------------");
		asn1_print(&buf[derp], derLen, "  ");
		PrintAndLog("----------------DER TLV-----------------");
	}
	
    FIDOCheckDERAndGetKey(&buf[derp], derLen, verbose, public_key, sizeof(public_key));
	
	// get hash
	int hashp = 1 + 65 + 1 + keyHandleLen + derLen;
	PrintAndLog("Hash[%d]: %s", len - hashp, sprint_hex(&buf[hashp], len - hashp));

	// check ANSI X9.62 format ECDSA signature (on P-256)
	uint8_t rval[300] = {0}; 
	uint8_t sval[300] = {0}; 
	res = ecdsa_asn1_get_signature(&buf[hashp], len - hashp, rval, sval);
	if (!res) {
		if (verbose) {
			PrintAndLog("  r: %s", sprint_hex(rval, 32));
			PrintAndLog("  s: %s", sprint_hex(sval, 32));
		}

		uint8_t xbuf[4096] = {0};
		size_t xbuflen = 0;
		res = FillBuffer(xbuf, sizeof(xbuf), &xbuflen,
			"\x00", 1,
			&data[32], 32,           // application parameter  
			&data[0], 32,            // challenge parameter
			&buf[67], keyHandleLen,  // keyHandle
			&buf[1], 65,             // user public key
			NULL, 0);
		//PrintAndLog("--xbuf(%d)[%d]: %s", res, xbuflen, sprint_hex(xbuf, xbuflen));
		res = ecdsa_signature_verify(public_key, xbuf, xbuflen, &buf[hashp], len - hashp);
		if (res) {
			if (res == -0x4e00) {
				PrintAndLog("Signature is NOT VALID.");
			} else {
				PrintAndLog("Other signature check error: %x %s", (res<0)?-res:res, ecdsa_get_error(res));
			}
		} else {
			PrintAndLog("Signature is OK.");
		}
		
	} else {
		PrintAndLog("Invalid signature. res=%d.", res);
	}
	
	PrintAndLog("\nauth command: ");
	printf("hf fido auth %s%s", paramsPlain?"-p ":"", sprint_hex_inrow(&buf[67], keyHandleLen));
	if(chlen || applen)
		printf(" %s", paramsPlain?(char *)cdata:sprint_hex_inrow(cdata, 32));
	if(applen)
		printf(" %s", paramsPlain?(char *)adata:sprint_hex_inrow(adata, 32));
	printf("\n");
	
	if (root) {
		JsonSaveBufAsHex(root, "ChallengeParam", data, 32);
		JsonSaveBufAsHex(root, "ApplicationParam", &data[32], 32);
		JsonSaveBufAsHexCompact(root, "PublicKey", &buf[1], 65);
		JsonSaveInt(root, "KeyHandleLen", keyHandleLen);
		JsonSaveBufAsHexCompact(root, "KeyHandle", &buf[67], keyHandleLen);
		JsonSaveBufAsHexCompact(root, "DER", &buf[67 + keyHandleLen], derLen);
	
		res = json_dump_file(root, fname, JSON_INDENT(2));
		if (res) {
			PrintAndLog("ERROR: can't save the file: %s", fname);
			return 200;
		}
		PrintAndLog("File `%s` saved.", fname);
		
		// free json object
		json_decref(root);
	}
	
	return 0;
};

int CmdHFFidoAuthenticate(const char *cmd) {
	uint8_t data[512] = {0};
	uint8_t hdata[250] = {0};
	bool public_key_loaded = false;
	uint8_t public_key[65] = {0}; 
	int hdatalen = 0;
	uint8_t keyHandleLen = 0;
	json_t *root = NULL;
	
	CLIParserInit("hf fido auth", 
		"Initiate a U2F token authentication. Needs key handle and two 32-byte hash number. \nkey handle(var 0..255), challenge parameter (32b) and application parameter (32b).", 
		"Usage:\n\thf fido auth 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f -> execute command with 2 parameters, filled 0x00 and key handle\n"
			"\thf fido auth 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f "
				"000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f -> execute command with parameters");

	void* argtable[] = {
		arg_param_begin,
		arg_lit0("aA",  "apdu",     "show APDU reqests and responses"),
		arg_lit0("vV",  "verbose",  "show technical data"),
		arg_lit0("pP",  "plain",    "send plain ASCII to challenge and application parameters instead of HEX"),
		arg_rem("default mode:",    "dont-enforce-user-presence-and-sign"),
		arg_lit0("uU",  "user",     "mode: enforce-user-presence-and-sign"),
		arg_lit0("cC",  "check",    "mode: check-only"),
		arg_str0("jJ",  "json",		"fido.json", "JSON input / output file name for parameters."),
		arg_str0("kK",  "key",		"public key to verify signature", NULL),
		arg_str0(NULL,  NULL,       "<HEX key handle (var 0..255b)>", NULL),
		arg_str0(NULL,  NULL,       "<HEX/ASCII challenge parameter (32b HEX/1..16 chars)>", NULL),
		arg_str0(NULL,  NULL,       "<HEX/ASCII application parameter (32b HEX/1..16 chars)>", NULL),
		arg_param_end
	};
	CLIExecWithReturn(cmd, argtable, true);
	
	bool APDULogging = arg_get_lit(1);
	bool verbose = arg_get_lit(2);
	bool paramsPlain = arg_get_lit(3);
	uint8_t controlByte = 0x08;
	if (arg_get_lit(5))
		controlByte = 0x03;
	if (arg_get_lit(6))
		controlByte = 0x07;

	char fname[250] = {0};
	bool err;
	root = OpenJson(7, fname, argtable, &err);
	if(err)
		return 1;
	if (root) {	
		size_t jlen;
		JsonLoadBufAsHex(root, "$.ChallengeParam", data, 32, &jlen);
		JsonLoadBufAsHex(root, "$.ApplicationParam", &data[32], 32, &jlen);
		JsonLoadBufAsHex(root, "$.KeyHandle", &data[65], 512 - 67, &jlen);
		keyHandleLen = jlen & 0xff;
		data[64] = keyHandleLen;
		JsonLoadBufAsHex(root, "$.PublicKey", public_key, 65, &jlen);
		public_key_loaded = (jlen > 0);
	} 

	// public key
	CLIGetHexWithReturn(8, hdata, &hdatalen);
	if (hdatalen && hdatalen != 130) {
		PrintAndLog("ERROR: public key length must be 65 bytes only.");
		return 1;
	}
	if (hdatalen) {
		memmove(public_key, hdata, hdatalen);
		public_key_loaded = true;
	}	
	
	CLIGetHexWithReturn(9, hdata, &hdatalen);
	if (hdatalen > 255) {
		PrintAndLog("ERROR: application parameter length must be less than 255.");
		return 1;
	}
	if (hdatalen) {
		keyHandleLen = hdatalen;
		data[64] = keyHandleLen;
		memmove(&data[65], hdata, keyHandleLen);
	}

	if (paramsPlain) {
		memset(hdata, 0x00, 32);
		CLIGetStrWithReturn(9, hdata, &hdatalen);
		if (hdatalen && hdatalen > 16) {
			PrintAndLog("ERROR: challenge parameter length in ASCII mode must be less than 16 chars instead of: %d", hdatalen);
			return 1;
		}
	} else {
		CLIGetHexWithReturn(10, hdata, &hdatalen);
		if (hdatalen && hdatalen != 32) {
			PrintAndLog("ERROR: challenge parameter length must be 32 bytes only.");
			return 1;
		}
	}
	if (hdatalen)
		memmove(data, hdata, 32);

	if (paramsPlain) {
		memset(hdata, 0x00, 32);
		CLIGetStrWithReturn(11, hdata, &hdatalen);
		if (hdatalen && hdatalen > 16) {
			PrintAndLog("ERROR: application parameter length in ASCII mode must be less than 16 chars instead of: %d", hdatalen);
			return 1;
		}
	} else {
		CLIGetHexWithReturn(10, hdata, &hdatalen);
		if (hdatalen && hdatalen != 32) {
			PrintAndLog("ERROR: application parameter length must be 32 bytes only.");
			return 1;
		}
	}
	if (hdatalen)
		memmove(&data[32], hdata, 32);

	CLIParserFree();	
	
	SetAPDULogging(APDULogging);

	// (in parameter) conrtol byte 0x07 - check only, 0x03 - user presense + cign. 0x08 - sign only
 	// challenge parameter [32 bytes]
	// application parameter [32 bytes]
	// key handle length [1b] = N
	// key handle [N]

	uint8_t datalen = 32 + 32 + 1 + keyHandleLen;
	
	uint8_t buf[2048] = {0};
	size_t len = 0;
	uint16_t sw = 0;

	DropField();
	int res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);

	if (res) {
		PrintAndLog("Can't select authenticator. res=%x. Exit...", res);
		DropField();
		return res;
	}
	
	if (sw != 0x9000) {
		PrintAndLog("Can't select FIDO application. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff)); 
		DropField();
		return 2;
	}

	res = FIDOAuthentication(data, datalen, controlByte,  buf,  sizeof(buf), &len, &sw);
	DropField();
	if (res) {
		PrintAndLog("Can't execute authentication command. res=%x. Exit...", res);
		return res;
	}
	
	if (sw != 0x9000) {
		PrintAndLog("ERROR execute authentication command. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff)); 
		return 3;
	}
	
	PrintAndLog("---------------------------------------------------------------");
	PrintAndLog("User presence: %s", (buf[0]?"verified":"not verified"));
	uint32_t cntr =  (uint32_t)bytes_to_num(&buf[1], 4);
	PrintAndLog("Counter: %d", cntr);
	PrintAndLog("Hash[%d]: %s", len - 5, sprint_hex(&buf[5], len - 5));

	// check ANSI X9.62 format ECDSA signature (on P-256)
	uint8_t rval[300] = {0}; 
	uint8_t sval[300] = {0}; 
	res = ecdsa_asn1_get_signature(&buf[5], len - 5, rval, sval);
	if (!res) {
		if (verbose) {
			PrintAndLog("  r: %s", sprint_hex(rval, 32));
			PrintAndLog("  s: %s", sprint_hex(sval, 32));
		}
		if (public_key_loaded) {
			uint8_t xbuf[4096] = {0};
			size_t xbuflen = 0;
			res = FillBuffer(xbuf, sizeof(xbuf), &xbuflen,
				&data[32], 32, // application parameter
				&buf[0], 1,    // user presence
				&buf[1], 4,    // counter
				data, 32,      // challenge parameter
				NULL, 0);
			//PrintAndLog("--xbuf(%d)[%d]: %s", res, xbuflen, sprint_hex(xbuf, xbuflen));
			res = ecdsa_signature_verify(public_key, xbuf, xbuflen, &buf[5], len - 5);
			if (res) {
				if (res == -0x4e00) {
					PrintAndLog("Signature is NOT VALID.");
				} else {
					PrintAndLog("Other signature check error: %x %s", (res<0)?-res:res, ecdsa_get_error(res));
				}
			} else {
				PrintAndLog("Signature is OK.");
			}
		} else {		
			PrintAndLog("No public key provided. can't check signature.");
		}
	} else {
		PrintAndLog("Invalid signature. res=%d.", res);
	}
	
	if (root) {
		JsonSaveBufAsHex(root, "ChallengeParam", data, 32);
		JsonSaveBufAsHex(root, "ApplicationParam", &data[32], 32);
		JsonSaveInt(root, "KeyHandleLen", keyHandleLen);
		JsonSaveBufAsHexCompact(root, "KeyHandle", &data[65], keyHandleLen);
		JsonSaveInt(root, "Counter", cntr);
	
		res = json_dump_file(root, fname, JSON_INDENT(2));
		if (res) {
			PrintAndLog("ERROR: can't save the file: %s", fname);
			return 200;
		}
		PrintAndLog("File `%s` saved.", fname);
		
		// free json object
		json_decref(root);
	}
	return 0;
};

void CheckSlash(char *fileName) {
	if ((fileName[strlen(fileName) - 1] != '/') && 
		(fileName[strlen(fileName) - 1] != '\\'))
		strcat(fileName, "/");
}

int GetExistsFileNameJson(char *prefixDir, char *reqestedFileName, char *fileName) {
	fileName[0] = 0x00;
	strcpy(fileName, get_my_executable_directory());
	CheckSlash(fileName);
	
	strcat(fileName, prefixDir);
	CheckSlash(fileName);
	
	strcat(fileName, reqestedFileName);
	if (!strstr(fileName, ".json"))
		strcat(fileName, ".json");
	
	if (access(fileName, F_OK) < 0) {
		strcpy(fileName, get_my_executable_directory());
		CheckSlash(fileName);
		
		strcat(fileName, reqestedFileName);
		if (!strstr(fileName, ".json"))
			strcat(fileName, ".json");
		
		if (access(fileName, F_OK) < 0) {
			return 1; // file not found
		}
	}
	return 0;
}

bool CheckrpIdHash(json_t *json, uint8_t *hash) {
	char hashval[300] = {0};
	uint8_t hash2[32] = {0};
	
	JsonLoadStr(json, "$.RelyingPartyEntity.id", hashval);
	sha256hash((uint8_t *)hashval, strlen(hashval), hash2);

	return !memcmp(hash, hash2, 32);
}

int MakeCredentionalParseRes(json_t *root, uint8_t *data, size_t dataLen, bool verbose, bool showCBOR, bool showDERTLV) {
	CborParser parser;
	CborValue map, mapsmt;
	int res;
	char *buf;
	uint8_t *ubuf;
	size_t n;
	
	// fmt
	res = CborMapGetKeyById(&parser, &map, data, dataLen, 1);
	if (res)
		return res;
	
	res = cbor_value_dup_text_string(&map, &buf, &n, &map);
	cbor_check(res);
	PrintAndLog("format: %s", buf);
	free(buf);

	// authData
	uint8_t authDataStatic[37] = {0};
	res = CborMapGetKeyById(&parser, &map, data, dataLen, 2);
	if (res)
		return res;
	res = cbor_value_dup_byte_string(&map, &ubuf, &n, &map);
	cbor_check(res);
	
	if (n >= 37)
		memcpy(authDataStatic, ubuf, 37);
	
	PrintAndLog("authData: %s", sprint_hex(ubuf, n));
	
	PrintAndLog("RP ID Hash: %s", sprint_hex(ubuf, 32));
	
	// check RP ID Hash
	if (CheckrpIdHash(root, ubuf)) {
		PrintAndLog("rpIdHash OK.");
	} else {
		PrintAndLog("rpIdHash ERROR!");
	}

	PrintAndLog("Flags 0x%02x:", ubuf[32]);
	if (!ubuf[32])
		PrintAndLog("none");
	if (ubuf[32] & 0x01)
		PrintAndLog("up - user presence result");
	if (ubuf[32] & 0x04)
		PrintAndLog("uv - user verification (fingerprint scan or a PIN or ...) result");
	if (ubuf[32] & 0x40)
		PrintAndLog("at - attested credential data included");
	if (ubuf[32] & 0x80)
		PrintAndLog("ed - extension data included");

	uint32_t cntr =  (uint32_t)bytes_to_num(&ubuf[33], 4);
	PrintAndLog("Counter: %d", cntr);
	
	// attestation data
	PrintAndLog("AAGUID: %s", sprint_hex(&ubuf[37], 16));
	
	// Credential ID
	uint8_t cridlen = (uint16_t)bytes_to_num(&ubuf[53], 2);
	PrintAndLog("Credential id[%d]: %s", cridlen, sprint_hex(&ubuf[55], cridlen));
	
	//Credentional public key (COSE_KEY)
	uint8_t coseKey[65] = {0};
	uint16_t cplen = n - 55 - cridlen;
	PrintAndLog("Credentional public key (COSE_KEY)[%d]: %s", cplen, sprint_hex(&ubuf[55 + cridlen], cplen));
	if (showCBOR) {
		TinyCborPrintFIDOPackage(fido2COSEKey, true, &ubuf[55 + cridlen], cplen);		
	}
	res = COSEGetECDSAKey(&ubuf[55 + cridlen], cplen, verbose, coseKey);
	if (res)
		PrintAndLog("ERROR: Can't get COSE_KEY.");

	free(ubuf);
	
	// attStmt - we are check only as DER certificate
	int64_t alg = 0;
	uint8_t sign[128] = {0};
	size_t signLen = 0;
	uint8_t der[4097] = {0};
	size_t derLen = 0;
	
	res = CborMapGetKeyById(&parser, &map, data, dataLen, 3);
	if (res)
		return res;

	res = cbor_value_enter_container(&map, &mapsmt);
	cbor_check(res);
	
	while (!cbor_value_at_end(&mapsmt)) {
		char key[100] = {0};
		res = CborGetStringValue(&mapsmt, key, sizeof(key), &n);
		cbor_check(res);
		if (!strcmp(key, "alg")) {
			cbor_value_get_int64(&mapsmt, &alg);    
			PrintAndLog("Alg [%lld] %s", (long long)alg, GetCOSEAlgDescription(alg));
			res = cbor_value_advance_fixed(&mapsmt);
			cbor_check(res);
		}

		if (!strcmp(key, "sig")) {
			res = CborGetBinStringValue(&mapsmt, sign, sizeof(sign), &signLen);
			cbor_check(res);
			PrintAndLog("signature [%d]: %s", signLen, sprint_hex(sign, signLen));
		}

		if (!strcmp(key, "x5c")) {
			res = CborGetArrayBinStringValue(&mapsmt, der, sizeof(der), &derLen);
			cbor_check(res);
			PrintAndLog("DER [%d]: %s", derLen, sprint_hex(der, derLen));
		}		
	}
	res = cbor_value_leave_container(&map, &mapsmt);
	cbor_check(res);
	
	uint8_t public_key[65] = {0};

	// print DER certificate in TLV view
	if (showDERTLV) {
		PrintAndLog("----------------DER TLV-----------------");
		asn1_print(der, derLen, "  ");
		PrintAndLog("----------------DER TLV-----------------");
	}
    FIDOCheckDERAndGetKey(der, derLen, verbose, public_key, sizeof(public_key));

	// check ANSI X9.62 format ECDSA signature (on P-256)
	uint8_t rval[300] = {0}; 
	uint8_t sval[300] = {0}; 
	res = ecdsa_asn1_get_signature(sign, signLen, rval, sval);
	if (!res) {
		if (verbose) {
			PrintAndLog("  r: %s", sprint_hex(rval, 32));
			PrintAndLog("  s: %s", sprint_hex(sval, 32));
		}

		uint8_t clientDataHash[32] = {0};
		size_t clientDataHashLen = 0;
		res = JsonLoadBufAsHex(root, "$.ClientDataHash", clientDataHash, sizeof(clientDataHash), &clientDataHashLen);
		if (res || clientDataHashLen != 32) {
			PrintAndLog("ERROR: Can't get clientDataHash from json!");
			return 2;
		}			
		
		uint8_t xbuf[4096] = {0};
		size_t xbuflen = 0;
		res = FillBuffer(xbuf, sizeof(xbuf), &xbuflen,
			authDataStatic, 37,  // rpIdHash[32] + flags[1] + signCount[4]
			clientDataHash, 32,  // Hash of the serialized client data. "$.ClientDataHash" from json
			NULL, 0);
		PrintAndLog("--xbuf(%d)[%d]: %s", res, xbuflen, sprint_hex(xbuf, xbuflen));
		res = ecdsa_signature_verify(public_key, xbuf, xbuflen, sign, signLen);
		if (res) {
			if (res == -0x4e00) {
				PrintAndLog("Signature is NOT VALID.");
			} else {
				PrintAndLog("Other signature check error: %x %s", (res<0)?-res:res, ecdsa_get_error(res));
			}
		} else {
			PrintAndLog("Signature is OK.");
		}	
	} else {
		PrintAndLog("Invalid signature. res=%d.", res);
	}
	
	return 0;
}

int CmdHFFido2MakeCredential(const char *cmd) {
	json_error_t error;
	json_t *root = NULL;
	char fname[300] = {0};
	bool verbose = true;
	bool showDERTLV = true;
	bool showCBOR = true;

	int res = GetExistsFileNameJson("fido", "fido2", fname);
	if(res) {
		PrintAndLog("ERROR: Can't found the json file.");
		return res;
	}
	PrintAndLog("fname: %s\n", fname);
	root = json_load_file(fname, 0, &error);	
	if (!root) {
		PrintAndLog("ERROR: json error on line %d: %s", error.line, error.text);
		return 1;
	}
	
	uint8_t data[2048] = {0};
	size_t datalen = 0;
	uint8_t buf[2048] = {0};
	size_t len = 0;
	uint16_t sw = 0;

	DropField();
	res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);

	if (res) {
		PrintAndLog("Can't select authenticator. res=%x. Exit...", res);
		DropField();
		return res;
	}
	
	if (sw != 0x9000) {
		PrintAndLog("Can't select FIDO application. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff)); 
		DropField();
		return 2;
	}

	res = FIDO2CreateMakeCredentionalReq(root, data, sizeof(data), &datalen);
	if (res)
		return res;
	
	if (showCBOR) {
		PrintAndLog("CBOR make credentional request:");
		TinyCborPrintFIDOPackage(fido2CmdMakeCredential, false, data, datalen);
	}
	
	res = FIDO2MakeCredential(data, datalen, buf,  sizeof(buf), &len, &sw);
	DropField();
	if (res) {
		PrintAndLog("Can't execute make credential command. res=%x. Exit...", res);
		return res;
	}
	
	if (sw != 0x9000) {
		PrintAndLog("ERROR execute make credential command. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff)); 
		return 3;
	}
	
	if(buf[0]) {
		PrintAndLog("FIDO2 make credential error: %d - %s", buf[0], fido2GetCmdErrorDescription(buf[0])); 
		return 0;
	}

	PrintAndLog("MakeCredential result (%d b) OK.", len);
	if (showCBOR) {
		PrintAndLog("CBOR make credentional response:");
		TinyCborPrintFIDOPackage(fido2CmdMakeCredential, true, &buf[1], len - 1);
	}

	// parse returned cbor
	MakeCredentionalParseRes(root, &buf[1], len - 1, verbose, showCBOR, showDERTLV);
	
	if (root) {
		res = json_dump_file(root, fname, JSON_INDENT(2));
		if (res) {
			PrintAndLog("ERROR: can't save the file: %s", fname);
			return 200;
		}
		PrintAndLog("File `%s` saved.", fname);
	}
	
	json_decref(root);

	return 0;
};

int CmdHFFido2GetAssertion(const char *cmd) {

	return 0;
};

static command_t CommandTable[] =
{
  {"help",             CmdHelp,						1, "This help."},
  {"info",  	       CmdHFFidoInfo,				0, "Info about FIDO tag."},
  {"reg",  	  	 	   CmdHFFidoRegister,			0, "FIDO U2F Registration Message."},
  {"auth",  	       CmdHFFidoAuthenticate,		0, "FIDO U2F Authentication Message."},
  {"make",  	       CmdHFFido2MakeCredential,	0, "FIDO2 MakeCredential command."},
  {"accert",  	       CmdHFFido2GetAssertion,		0, "FIDO2 GetAssertion command."},
  {NULL,               NULL,						0, NULL}
};

int CmdHFFido(const char *Cmd) {
	(void)WaitForResponseTimeout(CMD_ACK,NULL,100);
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
  CmdsHelp(CommandTable);
  return 0;
}
