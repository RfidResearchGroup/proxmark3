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

#define DESFIRE_TX_FRAME_MAX_LEN 54

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
} DesfireCreateFileCommandsS;

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

} FileSettingsS;

typedef struct {
    uint8_t fileNum;
    uint16_t fileISONum;
    FileSettingsS fileSettings;
} FileListElmS;

typedef FileListElmS FileListS[32];

typedef struct {
    bool checked;
    bool auth;
    bool authISO;
    bool authAES;
    bool authEV2;
    bool authISONative;
} AuthCommandsChk;

typedef struct {
    uint32_t appNum;
    uint16_t appISONum;
    char appDFName[16];
    AuthCommandsChk authCmdCheck;

    uint8_t keySettings;
    uint8_t numKeysRaw;
    bool isoFileIDEnabled;          // from numKeysRaw
    uint8_t numberOfKeys;           // from numKeysRaw
    DesfireCryptoAlgorythm keyType; // from numKeysRaw

    uint8_t keyVersions[16];

    bool filesReaded;
    size_t filesCount;
    bool isoPresent;
    FileListS fileList;
} AppListElmS;
typedef AppListElmS AppListS[64];

typedef struct {
    size_t appCount;
    uint32_t freemem;
    AuthCommandsChk authCmdCheck;

    uint8_t keySettings;
    uint8_t numKeysRaw;
    uint8_t numberOfKeys; // from numKeysRaw

    uint8_t keyVersion0;
} PICCInfoS;

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

int DesfireReadSignature(DesfireContext *dctx, uint8_t sid, uint8_t *resp, size_t *resplen);

int DesfireSelectAID(DesfireContext *ctx, uint8_t *aid1, uint8_t *aid2);
int DesfireSelectAIDHex(DesfireContext *ctx, uint32_t aid1, bool select_two, uint32_t aid2);
int DesfireSelectAIDHexNoFieldOn(DesfireContext *ctx, uint32_t aid);
void DesfirePrintAIDFunctions(uint32_t appid);
void DesfirePrintMADAID(uint32_t appid, bool verbose);

int DesfireGetCardUID(DesfireContext *ctx);

int DesfireSelectEx(DesfireContext *ctx, bool fieldon, DesfireISOSelectWay way, uint32_t id, char *dfname);
int DesfireSelect(DesfireContext *ctx, DesfireISOSelectWay way, uint32_t id, char *dfname);

const char *DesfireAuthErrorToStr(int error);
int DesfireSelectAndAuthenticate(DesfireContext *dctx, DesfireSecureChannel secureChannel, uint32_t aid, bool verbose);
int DesfireSelectAndAuthenticateEx(DesfireContext *dctx, DesfireSecureChannel secureChannel, uint32_t aid, bool noauth, bool verbose);
int DesfireSelectAndAuthenticateISO(DesfireContext *dctx, DesfireSecureChannel secureChannel, bool useaid, uint32_t aid, uint16_t isoappid, uint16_t isofileid, bool noauth, bool verbose);
int DesfireAuthenticate(DesfireContext *dctx, DesfireSecureChannel secureChannel, bool verbose);
void DesfireCheckAuthCommands(uint32_t appAID, char *dfname, uint8_t keyNum,  AuthCommandsChk *authCmdCheck);
void DesfireCheckAuthCommandsPrint(AuthCommandsChk *authCmdCheck);

int DesfireFormatPICC(DesfireContext *dctx);
int DesfireGetFreeMem(DesfireContext *dctx, uint32_t *freemem);
int DesfireGetUID(DesfireContext *dctx, uint8_t *resp, size_t *resplen);
int DesfireGetAIDList(DesfireContext *dctx, uint8_t *resp, size_t *resplen);
int DesfireGetDFList(DesfireContext *dctx, uint8_t *resp, size_t *resplen);
int DesfireFillPICCInfo(DesfireContext *dctx, PICCInfoS *PICCInfo, bool deepmode);
int DesfireFillAppList(DesfireContext *dctx, PICCInfoS *PICCInfo, AppListS appList, bool deepmode, bool readFiles, bool fillAppSettings);
void DesfirePrintPICCInfo(DesfireContext *dctx, PICCInfoS *PICCInfo);
void DesfirePrintAppList(DesfireContext *dctx, PICCInfoS *PICCInfo, AppListS appList);

int DesfireCreateApplication(DesfireContext *dctx, uint8_t *appdata, size_t appdatalen);
int DesfireDeleteApplication(DesfireContext *dctx, uint32_t aid);

int DesfireGetKeyVersion(DesfireContext *dctx, uint8_t *data, size_t len, uint8_t *resp, size_t *resplen);
int DesfireGetKeySettings(DesfireContext *dctx, uint8_t *resp, size_t *resplen);
int DesfireChangeKeySettings(DesfireContext *dctx, uint8_t *data, size_t len);
void PrintKeySettings(uint8_t keysettings, uint8_t numkeys, bool applevel, bool print2ndbyte);

int DesfireChangeKeyCmd(DesfireContext *dctx, uint8_t *data, size_t datalen, uint8_t *resp, size_t *resplen);
int DesfireChangeKey(DesfireContext *dctx, bool change_master_key, uint8_t newkeynum, DesfireCryptoAlgorythm newkeytype, uint32_t newkeyver, uint8_t *newkey, DesfireCryptoAlgorythm oldkeytype, uint8_t *oldkey, bool verbose);

int DesfireSetConfigurationCmd(DesfireContext *dctx, uint8_t *data, size_t len, uint8_t *resp, size_t *resplen);
int DesfireSetConfiguration(DesfireContext *dctx, uint8_t paramid, uint8_t *param, size_t paramlen);

int DesfireFillFileList(DesfireContext *dctx, FileListS FileList, size_t *filescount, bool *isopresent);
int DesfireGetFileIDList(DesfireContext *dctx, uint8_t *resp, size_t *resplen);
int DesfireGetFileISOIDList(DesfireContext *dctx, uint8_t *resp, size_t *resplen);

void DesfireFillFileSettings(uint8_t *data, size_t datalen, FileSettingsS *fsettings);
void DesfirePrintFileSettingsOneLine(FileSettingsS *fsettings);
void DesfirePrintFileSettingsTable(bool printheader, uint8_t id, bool isoidavail, uint16_t isoid, FileSettingsS *fsettings);
void DesfirePrintFileSettingsExtended(FileSettingsS *fsettings);
int DesfireGetFileSettings(DesfireContext *dctx, uint8_t fileid, uint8_t *resp, size_t *resplen);
int DesfireGetFileSettingsStruct(DesfireContext *dctx, uint8_t fileid, FileSettingsS *fsettings);
int DesfireChangeFileSettings(DesfireContext *dctx, uint8_t *data, size_t datalen);

const DesfireCreateFileCommandsS *GetDesfireFileCmdRec(uint8_t type);
const char *GetDesfireAccessRightStr(uint8_t right);
const char *GetDesfireAccessRightShortStr(uint8_t right);
void DesfireEncodeFileAcessMode(uint8_t *mode, uint8_t r, uint8_t w, uint8_t rw, uint8_t ch);
void DesfireDecodeFileAcessMode(uint8_t *mode, uint8_t *r, uint8_t *w, uint8_t *rw, uint8_t *ch);
void DesfirePrintAccessRight(uint8_t *data);
void DesfirePrintFileSettings(uint8_t *data, size_t len);
void DesfirePrintSetFileSettings(uint8_t *data, size_t len);
void DesfirePrintCreateFileSettings(uint8_t filetype, uint8_t *data, size_t len);

const char *GetDesfireFileType(uint8_t type);
int DesfireCreateFile(DesfireContext *dctx, uint8_t ftype, uint8_t *fdata, size_t fdatalen, bool checklen);
int DesfireDeleteFile(DesfireContext *dctx, uint8_t fnum);
int DesfireCommitReaderID(DesfireContext *dctx, uint8_t *readerid, size_t readeridlen, uint8_t *resp, size_t *resplen);
int DesfireCommitTransactionEx(DesfireContext *dctx, bool enable_options, uint8_t options, uint8_t *resp, size_t *resplen);
int DesfireCommitTransaction(DesfireContext *dctx, bool enable_options, uint8_t options);
int DesfireAbortTransaction(DesfireContext *dctx);

int DesfireValueFileOperations(DesfireContext *dctx, uint8_t fid, uint8_t operation, uint32_t *value);
int DesfireClearRecordFile(DesfireContext *dctx, uint8_t fnum);

int DesfireReadFile(DesfireContext *dctx, uint8_t fnum, uint32_t offset, uint32_t len, uint8_t *resp, size_t *resplen);
int DesfireWriteFile(DesfireContext *dctx, uint8_t fnum, uint32_t offset, uint32_t len, uint8_t *data);
int DesfireReadRecords(DesfireContext *dctx, uint8_t fnum, uint32_t recnum, uint32_t reccount, uint8_t *resp, size_t *resplen);
int DesfireWriteRecord(DesfireContext *dctx, uint8_t fnum, uint32_t offset, uint32_t len, uint8_t *data);
int DesfireUpdateRecord(DesfireContext *dctx, uint8_t fnum, uint32_t recnum, uint32_t offset, uint32_t len, uint8_t *data);

int DesfireISOSelectDF(DesfireContext *dctx, char *dfname, uint8_t *resp, size_t *resplen);
int DesfireISOSelect(DesfireContext *dctx, DesfireISOSelectControl cntr, uint8_t *data, uint8_t datalen, uint8_t *resp, size_t *resplen);
int DesfireISOSelectFile(DesfireContext *dctx, char *appdfname, uint16_t appid, uint16_t fileid);
int DesfireISOSelectEx(DesfireContext *dctx, bool fieldon, DesfireISOSelectControl cntr, uint8_t *data, uint8_t datalen, uint8_t *resp, size_t *resplen);
int DesfireISOGetChallenge(DesfireContext *dctx, DesfireCryptoAlgorythm keytype, uint8_t *resp, size_t *resplen);
int DesfireISOExternalAuth(DesfireContext *dctx, bool app_level, uint8_t keynum, DesfireCryptoAlgorythm keytype, uint8_t *data);
int DesfireISOInternalAuth(DesfireContext *dctx, bool app_level, uint8_t keynum, DesfireCryptoAlgorythm keytype, uint8_t *data, uint8_t *resp, size_t *resplen);

int DesfireISOReadBinary(DesfireContext *dctx, bool use_file_id, uint8_t fileid, uint16_t offset, uint8_t length, uint8_t *resp, size_t *resplen);
int DesfireISOUpdateBinary(DesfireContext *dctx, bool use_file_id, uint8_t fileid, uint16_t offset, uint8_t *data, size_t datalen);
int DesfireISOReadRecords(DesfireContext *dctx, uint8_t recordnum, bool read_all_records, uint8_t fileid, uint8_t length, uint8_t *resp, size_t *resplen);
int DesfireISOAppendRecord(DesfireContext *dctx, uint8_t fileid, uint8_t *data, size_t datalen);

#endif // __DESFIRECORE_H
