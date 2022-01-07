//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/nfc-tools/libfreefare
// Copyright (C) 2010, Romain Tartiere.
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
// High frequency Desfire core functions
//-----------------------------------------------------------------------------

#ifndef __DESFIRECORE_H
#define __DESFIRECORE_H

#include "common.h"
#include "cliparser.h"
#include "mifare/desfirecrypto.h"

#define DESFIRE_TX_FRAME_MAX_LEN 54
#define DESFIRE_BUFFER_SIZE 65538

enum DesfireISOSelectControlEnum {
    ISSMFDFEF     = 0x00,
    ISSChildDF    = 0x01,
    ISSEFByFileID = 0x02,
    ISSParentDF   = 0x03,
    ISSDFName     = 0x04
};
typedef enum DesfireISOSelectControlEnum DesfireISOSelectControl;

enum DesfireISOSelectWayEnum {
    ISW6bAID,
    ISWMF,
    ISWIsoID,
    ISWDFName
};
typedef enum DesfireISOSelectWayEnum DesfireISOSelectWay;

typedef struct {
    const uint8_t id;
    const char *text;
    const uint8_t cmd;
    const uint8_t len;
    const uint8_t createlen;
    const bool mayHaveISOfid;
} DesfireCreateFileCommands_t;

typedef struct {
    // all
    uint8_t fileType;
    uint8_t fileOption;
    uint8_t fileCommMode;
    DesfireCommunicationMode commMode;
    bool additionalAccessRightsEn;
    uint16_t rawAccessRights;
    uint8_t rAccess;
    uint8_t wAccess;
    uint8_t rwAccess;
    uint8_t chAccess;

    // data
    uint32_t fileSize;

    //value
    uint32_t lowerLimit;
    uint32_t upperLimit;
    uint32_t value;
    uint8_t limitedCredit;

    // record
    uint32_t recordSize;
    uint32_t maxRecordCount;
    uint32_t curRecordCount;

    //mac
    uint8_t keyType;
    uint8_t key[16];
    uint8_t keyVersion;

    // additional rights
    uint8_t additionalAccessRightsLength;
    uint16_t additionalAccessRights[16];

} FileSettings_t;

typedef struct {
    uint8_t fileNum;
    uint16_t fileISONum;
    FileSettings_t fileSettings;
} FileListElm_t;

typedef FileListElm_t FileList_t[32];

typedef struct {
    bool checked;
    bool auth;
    bool authISO;
    bool authAES;
    bool authEV2;
    bool authISONative;
    bool authLRP;
} AuthCommandsChk_t;

typedef struct {
    uint32_t appNum;
    uint16_t appISONum;
    char appDFName[16];
    AuthCommandsChk_t authCmdCheck;

    uint8_t keySettings;
    uint8_t numKeysRaw;
    bool isoFileIDEnabled;          // from numKeysRaw
    uint8_t numberOfKeys;           // from numKeysRaw
    DesfireCryptoAlgorithm keyType; // from numKeysRaw

    uint8_t keyVersions[16];

    bool filesReaded;
    size_t filesCount;
    bool isoPresent;
    FileList_t fileList;
} AppListElm_t;
typedef AppListElm_t AppListS[64];

typedef struct {
    size_t appCount;
    uint32_t freemem;
    AuthCommandsChk_t authCmdCheck;

    uint8_t keySettings;
    uint8_t numKeysRaw;
    uint8_t numberOfKeys; // from numKeysRaw

    uint8_t keyVersion0;
} PICCInfo_t;

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
uint32_t DesfireAIDByteToUint(const uint8_t *data);
void DesfireAIDUintToByte(uint32_t aid, uint8_t *data);

void DesfirePrintContext(DesfireContext_t *ctx);

int DesfireExchange(DesfireContext_t *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *respcode, uint8_t *resp, size_t *resplen);
int DesfireExchangeEx(bool activate_field, DesfireContext_t *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *respcode, uint8_t *resp, size_t *resplen, bool enable_chaining, size_t splitbysize);

int DesfireReadSignature(DesfireContext_t *dctx, uint8_t sid, uint8_t *resp, size_t *resplen);

int DesfireAnticollision(bool verbose);
int DesfireSelectAID(DesfireContext_t *ctx, uint8_t *aid1, uint8_t *aid2);
int DesfireSelectAIDHex(DesfireContext_t *ctx, uint32_t aid1, bool select_two, uint32_t aid2);
int DesfireSelectAIDHexNoFieldOn(DesfireContext_t *ctx, uint32_t aid);
void DesfirePrintAIDFunctions(uint32_t appid);
void DesfirePrintMADAID(uint32_t appid, bool verbose);

int DesfireGetCardUID(DesfireContext_t *ctx);

const char *DesfireSelectWayToStr(DesfireISOSelectWay way);
char *DesfireWayIDStr(DesfireISOSelectWay way, uint32_t id);
bool DesfireMFSelected(DesfireISOSelectWay way, uint32_t id);
int DesfireSelectEx(DesfireContext_t *ctx, bool fieldon, DesfireISOSelectWay way, uint32_t id, const char *dfname);
int DesfireSelect(DesfireContext_t *ctx, DesfireISOSelectWay way, uint32_t id, char *dfname);

const char *DesfireAuthErrorToStr(int error);
int DesfireSelectAndAuthenticate(DesfireContext_t *dctx, DesfireSecureChannel secureChannel, uint32_t aid, bool verbose);
int DesfireSelectAndAuthenticateEx(DesfireContext_t *dctx, DesfireSecureChannel secureChannel, uint32_t aid, bool noauth, bool verbose);
int DesfireSelectAndAuthenticateW(DesfireContext_t *dctx, DesfireSecureChannel secureChannel, DesfireISOSelectWay way, uint32_t id, bool selectfile, uint16_t isofileid, bool noauth, bool verbose);
int DesfireSelectAndAuthenticateAppW(DesfireContext_t *dctx, DesfireSecureChannel secureChannel, DesfireISOSelectWay way, uint32_t id, bool noauth, bool verbose);
int DesfireSelectAndAuthenticateISO(DesfireContext_t *dctx, DesfireSecureChannel secureChannel, bool useaid, uint32_t aid, uint16_t isoappid, bool selectfile, uint16_t isofileid, bool noauth, bool verbose);
int DesfireAuthenticate(DesfireContext_t *dctx, DesfireSecureChannel secureChannel, bool verbose);

bool DesfireCheckAuthCmd(DesfireISOSelectWay way, uint32_t appID, uint8_t keyNum, uint8_t authcmd, bool checklrp);
void DesfireCheckAuthCommands(DesfireISOSelectWay way, uint32_t appID, char *dfname, uint8_t keyNum,  AuthCommandsChk_t *authCmdCheck);
void DesfireCheckAuthCommandsPrint(AuthCommandsChk_t *authCmdCheck);

int DesfireFormatPICC(DesfireContext_t *dctx);
int DesfireGetFreeMem(DesfireContext_t *dctx, uint32_t *freemem);
int DesfireGetUID(DesfireContext_t *dctx, uint8_t *resp, size_t *resplen);
int DesfireGetAIDList(DesfireContext_t *dctx, uint8_t *resp, size_t *resplen);
int DesfireGetDFList(DesfireContext_t *dctx, uint8_t *resp, size_t *resplen);
int DesfireFillPICCInfo(DesfireContext_t *dctx, PICCInfo_t *PICCInfo, bool deepmode);
int DesfireFillAppList(DesfireContext_t *dctx, PICCInfo_t *PICCInfo, AppListS appList, bool deepmode, bool readFiles, bool fillAppSettings);
void DesfirePrintPICCInfo(DesfireContext_t *dctx, PICCInfo_t *PICCInfo);
void DesfirePrintAppList(DesfireContext_t *dctx, PICCInfo_t *PICCInfo, AppListS appList);

int DesfireCreateApplication(DesfireContext_t *dctx, uint8_t *appdata, size_t appdatalen);
int DesfireDeleteApplication(DesfireContext_t *dctx, uint32_t aid);

int DesfireGetKeyVersion(DesfireContext_t *dctx, uint8_t *data, size_t len, uint8_t *resp, size_t *resplen);
int DesfireGetKeySettings(DesfireContext_t *dctx, uint8_t *resp, size_t *resplen);
int DesfireChangeKeySettings(DesfireContext_t *dctx, uint8_t *data, size_t len);
void PrintKeySettings(uint8_t keysettings, uint8_t numkeys, bool applevel, bool print2ndbyte);

int DesfireChangeKeyCmd(DesfireContext_t *dctx, uint8_t *data, size_t datalen, uint8_t *resp, size_t *resplen);
int DesfireChangeKey(DesfireContext_t *dctx, bool change_master_key, uint8_t newkeynum, DesfireCryptoAlgorithm newkeytype, uint32_t newkeyver, uint8_t *newkey, DesfireCryptoAlgorithm oldkeytype, uint8_t *oldkey, bool verbose);

int DesfireSetConfigurationCmd(DesfireContext_t *dctx, uint8_t *data, size_t len, uint8_t *resp, size_t *resplen);
int DesfireSetConfiguration(DesfireContext_t *dctx, uint8_t paramid, uint8_t *param, size_t paramlen);

int DesfireFillFileList(DesfireContext_t *dctx, FileList_t FileList, size_t *filescount, bool *isopresent);
int DesfireGetFileIDList(DesfireContext_t *dctx, uint8_t *resp, size_t *resplen);
int DesfireGetFileISOIDList(DesfireContext_t *dctx, uint8_t *resp, size_t *resplen);

void DesfireFillFileSettings(uint8_t *data, size_t datalen, FileSettings_t *fsettings);
void DesfirePrintFileSettingsOneLine(FileSettings_t *fsettings);
void DesfirePrintFileSettingsTable(bool printheader, uint8_t id, bool isoidavail, uint16_t isoid, FileSettings_t *fsettings);
void DesfirePrintFileSettingsExtended(FileSettings_t *fsettings);
int DesfireGetFileSettings(DesfireContext_t *dctx, uint8_t fileid, uint8_t *resp, size_t *resplen);
int DesfireFileSettingsStruct(DesfireContext_t *dctx, uint8_t fileid, FileSettings_t *fsettings);
int DesfireChangeFileSettings(DesfireContext_t *dctx, uint8_t *data, size_t datalen);

const DesfireCreateFileCommands_t *GetDesfireFileCmdRec(uint8_t type);
const char *GetDesfireAccessRightStr(uint8_t right);
const char *GetDesfireAccessRightShortStr(uint8_t right);
void DesfireEncodeFileAcessMode(uint8_t *mode, uint8_t r, uint8_t w, uint8_t rw, uint8_t ch);
void DesfireDecodeFileAcessMode(const uint8_t *mode, uint8_t *r, uint8_t *w, uint8_t *rw, uint8_t *ch);
void DesfirePrintAccessRight(uint8_t *data);
void DesfirePrintFileSettings(uint8_t *data, size_t len);
void DesfirePrintSetFileSettings(uint8_t *data, size_t len);
void DesfirePrintCreateFileSettings(uint8_t filetype, uint8_t *data, size_t len);

const char *GetDesfireFileType(uint8_t type);
int DesfireCreateFile(DesfireContext_t *dctx, uint8_t ftype, uint8_t *fdata, size_t fdatalen, bool checklen);
int DesfireDeleteFile(DesfireContext_t *dctx, uint8_t fnum);
int DesfireCommitReaderID(DesfireContext_t *dctx, uint8_t *readerid, size_t readeridlen, uint8_t *resp, size_t *resplen);
int DesfireCommitTransactionEx(DesfireContext_t *dctx, bool enable_options, uint8_t options, uint8_t *resp, size_t *resplen);
int DesfireCommitTransaction(DesfireContext_t *dctx, bool enable_options, uint8_t options);
int DesfireAbortTransaction(DesfireContext_t *dctx);

int DesfireValueFileOperations(DesfireContext_t *dctx, uint8_t fid, uint8_t operation, uint32_t *value);
int DesfireClearRecordFile(DesfireContext_t *dctx, uint8_t fnum);

int DesfireReadFile(DesfireContext_t *dctx, uint8_t fnum, uint32_t offset, uint32_t len, uint8_t *resp, size_t *resplen);
int DesfireWriteFile(DesfireContext_t *dctx, uint8_t fnum, uint32_t offset, uint32_t len, uint8_t *data);
int DesfireReadRecords(DesfireContext_t *dctx, uint8_t fnum, uint32_t recnum, uint32_t reccount, uint8_t *resp, size_t *resplen);
int DesfireWriteRecord(DesfireContext_t *dctx, uint8_t fnum, uint32_t offset, uint32_t len, uint8_t *data);
int DesfireUpdateRecord(DesfireContext_t *dctx, uint8_t fnum, uint32_t recnum, uint32_t offset, uint32_t len, uint8_t *data);

int DesfireISOSelectDF(DesfireContext_t *dctx, char *dfname, uint8_t *resp, size_t *resplen);
int DesfireISOSelect(DesfireContext_t *dctx, DesfireISOSelectControl cntr, uint8_t *data, uint8_t datalen, uint8_t *resp, size_t *resplen);
int DesfireISOSelectFile(DesfireContext_t *dctx, char *appdfname, uint16_t appid, uint16_t fileid);
int DesfireISOSelectEx(DesfireContext_t *dctx, bool fieldon, DesfireISOSelectControl cntr, uint8_t *data, uint8_t datalen, uint8_t *resp, size_t *resplen);
int DesfireISOGetChallenge(DesfireContext_t *dctx, DesfireCryptoAlgorithm keytype, uint8_t *resp, size_t *resplen);
int DesfireISOExternalAuth(DesfireContext_t *dctx, bool app_level, uint8_t keynum, DesfireCryptoAlgorithm keytype, uint8_t *data);
int DesfireISOInternalAuth(DesfireContext_t *dctx, bool app_level, uint8_t keynum, DesfireCryptoAlgorithm keytype, uint8_t *data, uint8_t *resp, size_t *resplen);

int DesfireISOReadBinary(DesfireContext_t *dctx, bool use_file_id, uint8_t fileid, uint16_t offset, uint8_t length, uint8_t *resp, size_t *resplen);
int DesfireISOUpdateBinary(DesfireContext_t *dctx, bool use_file_id, uint8_t fileid, uint16_t offset, uint8_t *data, size_t datalen);
int DesfireISOReadRecords(DesfireContext_t *dctx, uint8_t recordnum, bool read_all_records, uint8_t fileid, uint8_t length, uint8_t *resp, size_t *resplen);
int DesfireISOAppendRecord(DesfireContext_t *dctx, uint8_t fileid, uint8_t *data, size_t datalen);

#endif // __DESFIRECORE_H
