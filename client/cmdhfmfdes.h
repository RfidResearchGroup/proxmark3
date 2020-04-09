//-----------------------------------------------------------------------------
// Iceman, 2014
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE Desfire commands
//-----------------------------------------------------------------------------
#ifndef __MFDESFIRE_H
#define __MFDESFIRE_H

#include "common.h"

int CmdHFMFDes(const char *Cmd);

char *getCardSizeStr(uint8_t fsize);
char *getProtocolStr(uint8_t id);
char *getVersionStr(uint8_t major, uint8_t minor);
void getKeySettings(uint8_t *aid);

// Ev1 card limits
#define MAX_NUM_KEYS                0x0F
#define MAX_APPLICATION_COUNT       28
#define MAX_FILE_COUNT              32
#define MAX_FRAME_SIZE              60
#define FRAME_PAYLOAD_SIZE          (MAX_FRAME_SIZE - 5)

#define NOT_YET_AUTHENTICATED       0xFF

// status- and error codes                                                     |
#define OPERATION_OK                0x00 // Successful operation
#define NO_CHANGES                  0x0C //  No changes done to backup files
//  ,CommitTransaction/
//  AbortTransaction not necessary
#define OUT_OF_EEPROM_ERROR         0x0E // Insufficient NV-Memory to
//  complete command
#define ILLEGAL_COMMAND_CODE        0x1C // Command code not supported
#define INTEGRITY_ERROR             0x1E // CRC or MAC does not match data
//  Padding bytes not valid
#define NO_SUCH_KEY                 0x40 // Invalid key number specified
#define LENGTH_ERROR                0x7E // Length of command string invalid
#define PERMISSION_DENIED           0x9D // Current configuration status
//  does not allow the requested
//  command
#define PARAMETER_ERROR             0x9E // Value of the parameter(s) inval.
#define APPLICATION_NOT_FOUND       0xA0 // Requested AID not present on PIC
#define APPL_INTEGRITY_ERROR        0xA1 // [1] // Unrecoverable error within app-
//  lication, app will be disabled
#define AUTHENTICATION_ERROR        0xAE // Current authentication status
//  does not allow the requested
//  command
#define ADDITIONAL_FRAME            0xAF // Additional data frame is
//  expected to be sent
#define BOUNDARY_ERROR              0xBE // Attempt to read/write data from/
//  to beyond the file's/record's
//  limits. Attempt to exceed the
//  limits of a value file.
#define PICC_INTEGRITY_ERROR        0xC1 // [1] // Unrecoverable error within PICC
//  ,PICC will be disabled
#define COMMAND_ABORTED             0xCA // Previous Command was not fully
//  completed Not all Frames were
//  requested or provided by PCD
#define PICC_DISABLED_ERROR         0xCD // [1] // PICC was disabled by an unrecoverable error
#define COUNT_ERROR                 0xCE // Number of Applications limited
//  to 28, no additional
//  CreateApplication possible
#define DUPLICATE_ERROR             0xDE // Creation of file/application
//  failed because file/application
//  with same number already exists
#define EEPROM_ERROR                0xEE // [1]    // Could not complete NV-write
//  operation due to loss of power,
//  internal backup/rollback
//  mechanism activated
#define FILE_NOT_FOUND_ERROR        0xF0 // Specified file number does not
//  exist
#define FILE_INTEGRITY_ERROR        0xF1 // [1]    // Unrecoverable error within file,
//  file will be disabled
//
// [1] These errors are not expected to appear during normal operation

#endif
