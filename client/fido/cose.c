//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Tools for work with COSE (CBOR Object Signing and Encryption) rfc8152
// https://tools.ietf.org/html/rfc8152
//-----------------------------------------------------------------------------
//

#include "cose.h"
#include "util.h"

static const char COSEEmptyStr[] = "";

typedef struct {
	int Value;
	char *Name;
	char *Description;
} COSEValueNameDesc_t;
 
typedef struct {
	int Value;
	char *Type;
	char *Name;
	char *Description;
} COSEValueTypeNameDesc_t; 

// kty - Key Type Values
COSEValueNameDesc_t COSEKeyTypeValueDesc[] = {
	{0, "Reserved",  "Reserved"},
	{1, "OKP",       "Octet Key Pair"},
	{2, "EC2",       "Elliptic Curve Key w/ x- and y-coordinate pair"},
	{4, "Symmetric", "Symmetric Key"},
};

// keys
COSEValueTypeNameDesc_t COSEKeyTypeDesc[] = {
	{1, "EC2", "P-256",    "NIST P-256 also known as secp256r1"},
	{2, "EC2", "P-384",    "NIST P-384 also known as secp384r1"},
	{3, "EC2", "P-521",    "NIST P-521 also known as secp521r1"},
	{4, "OKP", "X25519",   "X25519 for use w/ ECDH only"},
	{5, "OKP", "X448",     "X448 for use w/ ECDH only"},
	{6, "OKP", "Ed25519",  "Ed25519 for use w/ EdDSA only"},
	{7, "OKP", "Ed448",    "Ed448 for use w/ EdDSA only"},
};

// RFC8152 https://www.iana.org/assignments/cose/cose.xhtml#algorithms
COSEValueNameDesc_t COSEAlg[] = {
	{-65536,	"Unassigned",				"Unassigned"},
	{-65535,	"RS1", 						"RSASSA-PKCS1-v1_5 w/ SHA-1"},
	{-259,		"RS512", 					"RSASSA-PKCS1-v1_5 w/ SHA-512"},
	{-258,		"RS384", 					"RSASSA-PKCS1-v1_5 w/ SHA-384"},
	{-257,		"RS256", 					"RSASSA-PKCS1-v1_5 w/ SHA-256"},
	{-42,		"RSAES-OAEP w/ SHA-512",	"RSAES-OAEP w/ SHA-512"},
	{-41,		"RSAES-OAEP w/ SHA-256",	"RSAES-OAEP w/ SHA-256"},
	{-40,		"RSAES-OAEP w/ RFC 8017 def param",	"RSAES-OAEP w/ SHA-1"},
	{-39,		"PS512",					"RSASSA-PSS w/ SHA-512"},
	{-38,		"PS384",					"RSASSA-PSS w/ SHA-384"},
	{-37,		"PS256",					"RSASSA-PSS w/ SHA-256"},
	{-36,		"ES512",					"ECDSA w/ SHA-512"},
	{-35,		"ES384",					"ECDSA w/ SHA-384"},
	{-34,		"ECDH-SS + A256KW",			"ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key"},
	{-33,		"ECDH-SS + A192KW",			"ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key"},
	{-32,		"ECDH-SS + A128KW",			"ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key"},
	{-31,		"ECDH-ES + A256KW",			"ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key"},
	{-30,		"ECDH-ES + A192KW",			"ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key"},
	{-29,		"ECDH-ES + A128KW",			"ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key"},
	{-28,		"ECDH-SS + HKDF-512",		"ECDH SS w/ HKDF - generate key directly"},
	{-27,		"ECDH-SS + HKDF-256",		"ECDH SS w/ HKDF - generate key directly"},
	{-26,		"ECDH-ES + HKDF-512",		"ECDH ES w/ HKDF - generate key directly"},
	{-25,		"ECDH-ES + HKDF-256",		"ECDH ES w/ HKDF - generate key directly"},
	{-13,		"direct+HKDF-AES-256",		"Shared secret w/ AES-MAC 256-bit key"},
	{-12,		"direct+HKDF-AES-128",		"Shared secret w/ AES-MAC 128-bit key"},
	{-11,		"direct+HKDF-SHA-512",		"Shared secret w/ HKDF and SHA-512"},
	{-10,		"direct+HKDF-SHA-256",		"Shared secret w/ HKDF and SHA-256"},
	{-8,		"EdDSA",					"EdDSA"},
	{-7,		"ES256",					"ECDSA w/ SHA-256"},
	{-6,		"direct",					"Direct use of CEK"},
	{-5,		"A256KW",					"AES Key Wrap w/ 256-bit key"},
	{-4,		"A192KW",					"AES Key Wrap w/ 192-bit key"},
	{-3,		"A128KW",					"AES Key Wrap w/ 128-bit key"},
	{0,			"Reserved",					"Reserved"},
	{1,			"A128GCM",					"AES-GCM mode w/ 128-bit key, 128-bit tag"},
	{2,			"A192GCM",					"AES-GCM mode w/ 192-bit key, 128-bit tag"},
	{3,			"A256GCM",					"AES-GCM mode w/ 256-bit key, 128-bit tag"},
	{4,			"HMAC 256/64",				"HMAC w/ SHA-256 truncated to 64 bits"},
	{5,			"HMAC 256/256",				"HMAC w/ SHA-256"},
	{6,			"HMAC 384/384",				"HMAC w/ SHA-384"},
	{7,			"HMAC 512/512",				"HMAC w/ SHA-512"},
	{10,		"AES-CCM-16-64-128",		"AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce"},
	{11,		"AES-CCM-16-64-256",		"AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce"},
	{12,		"AES-CCM-64-64-128",		"AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce"},
	{13,		"AES-CCM-64-64-256",		"AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce"},
	{14,		"AES-MAC 128/64",			"AES-MAC 128-bit key, 64-bit tag"},
	{15,		"AES-MAC 256/64",			"AES-MAC 256-bit key, 64-bit tag"},
	{24,		"ChaCha20/Poly1305",		"ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag"},
	{25,		"AES-MAC 128/128",			"AES-MAC 128-bit key, 128-bit tag"},
	{26,		"AES-MAC 256/128",			"AES-MAC 256-bit key, 128-bit tag"},
	{30,		"AES-CCM-16-128-128",		"AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce"},
	{31,		"AES-CCM-16-128-256",		"AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce"},
	{32,		"AES-CCM-64-128-128",		"AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce"},
	{33,		"AES-CCM-64-128-256",		"AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce"}
};

COSEValueNameDesc_t *GetCOSEAlgElm(int id) {
	for (int i = 0; i < ARRAYLEN(COSEAlg); i++)
		if (COSEAlg[i].Value == id)
			return &COSEAlg[i];
	return NULL;
}
	
const char *GetCOSEAlgName(int id) {
	COSEValueNameDesc_t *elm = GetCOSEAlgElm(id);
	if (elm)
		return elm->Name;
	return COSEEmptyStr;
}

const char *GetCOSEAlgDescription(int id) {
	COSEValueNameDesc_t *elm = GetCOSEAlgElm(id);
	if (elm)
		return elm->Description;
	return COSEEmptyStr;
}

int COSEGetECDSAKey(uint8_t *data, size_t datalen, bool verbose, uint8_t *public_key) {
	
	
	return 0;
}


