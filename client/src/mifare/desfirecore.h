//-----------------------------------------------------------------------------
// Copyright (C) 2010 Romain Tartiere.
// Copyright (C) 2014 Iceman
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Desfire core functions
//-----------------------------------------------------------------------------

#ifndef __DESFIRECORE_H
#define __DESFIRECORE_H

#include "common.h"
#include "cliparser.h"
#include "mifare/desfirecrypto.h"
#include "mifare/desfire_crypto.h"
#include "mifare/mifare4.h"

typedef struct {
    const uint8_t id;
    const char *text;
    const uint8_t cmd;
    const uint8_t len;
    const uint8_t createlen;
    const bool mayHaveISOfid;
} DesfireCreateFileCommandsS;

typedef enum {
    RFTAuto,
    RFTData,
    RFTValue,
    RFTRecord,
    RFTMAC,
} DesfireReadOpFileType;

extern const CLIParserOption DesfireAlgoOpts[];
extern const CLIParserOption DesfireKDFAlgoOpts[];
extern const CLIParserOption DesfireCommunicationModeOpts[];
extern const CLIParserOption DesfireCommandSetOpts[];
extern const CLIParserOption DesfireSecureChannelOpts[];
extern const CLIParserOption DesfireFileAccessModeOpts[];
extern const CLIParserOption DesfireValueFileOperOpts[];
extern const CLIParserOption DesfireReadFileTypeOpts[];

const char *DesfireGetErrorString(int res, uint16_t *sw);
uint32_t DesfireAIDByteToUint(uint8_t *data);
void DesfireAIDUintToByte(uint32_t aid, uint8_t *data);

void DesfirePrintContext(DesfireContext *ctx);

int DesfireExchange(DesfireContext *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *respcode, uint8_t *resp, size_t *resplen);
int DesfireExchangeEx(bool activate_field, DesfireContext *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *respcode, uint8_t *resp, size_t *resplen, bool enable_chaining, size_t splitbysize);

int DesfireSelectAID(DesfireContext *ctx, uint8_t *aid1, uint8_t *aid2);
int DesfireSelectAIDHex(DesfireContext *ctx, uint32_t aid1, bool select_two, uint32_t aid2);

int DesfireSelectAndAuthenticate(DesfireContext *dctx, DesfireSecureChannel secureChannel, uint32_t aid, bool verbose);
int DesfireAuthenticate(DesfireContext *dctx, DesfireSecureChannel secureChannel, bool verbose);

int DesfireFormatPICC(DesfireContext *dctx);
int DesfireGetFreeMem(DesfireContext *dctx, uint32_t *freemem);
int DesfireGetUID(DesfireContext *dctx, uint8_t *resp, size_t *resplen);
int DesfireGetAIDList(DesfireContext *dctx, uint8_t *resp, size_t *resplen);
int DesfireGetDFList(DesfireContext *dctx, uint8_t *resp, size_t *resplen);

int DesfireCreateApplication(DesfireContext *dctx, uint8_t *appdata, size_t appdatalen);
int DesfireDeleteApplication(DesfireContext *dctx, uint32_t aid);

int DesfireGetKeyVersion(DesfireContext *dctx, uint8_t *data, size_t len, uint8_t *resp, size_t *resplen);
int DesfireGetKeySettings(DesfireContext *dctx, uint8_t *resp, size_t *resplen);
int DesfireChangeKeySettings(DesfireContext *dctx, uint8_t *data, size_t len);
void PrintKeySettings(uint8_t keysettings, uint8_t numkeys, bool applevel, bool print2ndbyte);
uint8_t DesfireKeyAlgoToType(DesfireCryptoAlgorythm keyType);

int DesfireChangeKeyCmd(DesfireContext *dctx, uint8_t *data, size_t datalen, uint8_t *resp, size_t *resplen);
int DesfireChangeKey(DesfireContext *dctx, bool change_master_key, uint8_t newkeynum, DesfireCryptoAlgorythm newkeytype, uint32_t newkeyver, uint8_t *newkey, DesfireCryptoAlgorythm oldkeytype, uint8_t *oldkey, bool verbose);

int DesfireSetConfigurationCmd(DesfireContext *dctx, uint8_t *data, size_t len, uint8_t *resp, size_t *resplen);
int DesfireSetConfiguration(DesfireContext *dctx, uint8_t paramid, uint8_t *param, size_t paramlen);

int DesfireGetFileIDList(DesfireContext *dctx, uint8_t *resp, size_t *resplen);
int DesfireGetFileISOIDList(DesfireContext *dctx, uint8_t *resp, size_t *resplen);

int DesfireGetFileSettings(DesfireContext *dctx, uint8_t fileid, uint8_t *resp, size_t *resplen);
int DesfireChangeFileSettings(DesfireContext *dctx, uint8_t *data, size_t datalen);

const DesfireCreateFileCommandsS *GetDesfireFileCmdRec(uint8_t type);
const char *GetDesfireAccessRightStr(uint8_t right);
void DesfireEncodeFileAcessMode(uint8_t *mode, uint8_t r, uint8_t w, uint8_t rw, uint8_t ch);
void DesfireDecodeFileAcessMode(uint8_t *mode, uint8_t *r, uint8_t *w, uint8_t *rw, uint8_t *ch);
void DesfirePrintAccessRight(uint8_t *data);
void DesfirePrintFileSettings(uint8_t *data, size_t len);
void DesfirePrintSetFileSettings(uint8_t *data, size_t len);
void DesfirePrintCreateFileSettings(uint8_t filetype, uint8_t *data, size_t len);

const char *GetDesfireFileType(uint8_t type);
int DesfireCreateFile(DesfireContext *dctx, uint8_t ftype, uint8_t *fdata, size_t fdatalen, bool checklen);
int DesfireDeleteFile(DesfireContext *dctx, uint8_t fnum);
int DesfireCommitTransaction(DesfireContext *dctx, bool enable_options, uint8_t options);
int DesfireAbortTransaction(DesfireContext *dctx);

int DesfireValueFileOperations(DesfireContext *dctx, uint8_t fid, uint8_t operation, uint32_t *value);
int DesfireClearRecordFile(DesfireContext *dctx, uint8_t fnum);

int DesfireReadFile(DesfireContext *dctx, uint8_t fnum, uint32_t offset, uint32_t len, uint8_t *resp, size_t *resplen);
int DesfireWriteFile(DesfireContext *dctx, uint8_t fnum, uint32_t offset, uint32_t len, uint8_t *data);

#endif // __DESFIRECORE_H
