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

int CmdHFMFDes(const char *Cmd);
int CmdHF14ADesAuth(const char* cmd);
int CmdHF14ADesRb(const char* cmd);
int CmdHF14ADesWb(const char* cmd);
int CmdHF14ADesInfo(const char *Cmd);
int CmdHF14ADesEnumApplications(const char *Cmd);

char * GetCardSizeStr( uint8_t fsize );
char * GetProtocolStr( uint8_t id );
char * GetVersionStr( uint8_t major, uint8_t minor );
void GetKeySettings( uint8_t * aid );

// Command options for Desfire behavior.
enum  {
 NONE		= 	0x00,
 INIT 		=	0x01,
 DISCONNECT =	0x02,
 CLEARTRACE	= 	0x04,
 BAR		= 	0x08,
} CmdOptions ;


#define  CREATE_APPLICATION 		 0xca
#define  DELETE_APPLICATION 		 0xda
#define  GET_APPLICATION_IDS 		 0x6a
#define  SELECT_APPLICATION 		 0x5a
#define  FORMAT_PICC 				 0xfc
#define  GET_VERSION 				 0x60
#define  READ_DATA 					 0xbd
#define  WRITE_DATA					 0x3d
#define  GET_VALUE 					 0x6c
#define  CREDIT 					 0x0c
#define  DEBIT 						 0xdc
#define  LIMITED_CREDIT 			 0x1c
#define  WRITE_RECORD 				 0x3b
#define  READ_RECORDS 				 0xbb
#define  CLEAR_RECORD_FILE 			 0xeb
#define  COMMIT_TRANSACTION 		 0xc7
#define  ABORT_TRANSACTION 			 0xa7
#define  GET_FREE_MEMORY             0x6e
#define  GET_FILE_IDS 				 0x6f
#define  GET_ISOFILE_IDS 			 0x61
#define  GET_FILE_SETTINGS 			 0xf5
#define  CHANGE_FILE_SETTINGS 		 0x5f
#define  CREATE_STD_DATA_FILE 		 0xcd
#define  CREATE_BACKUP_DATA_FILE 	 0xcb
#define  CREATE_VALUE_FILE 			 0xcc
#define  CREATE_LINEAR_RECORD_FILE 	 0xc1
#define  CREATE_CYCLIC_RECORD_FILE 	 0xc0
#define  DELETE_FILE 				 0xdf
#define  AUTHENTICATE	 			 0x0a  // AUTHENTICATE_NATIVE
#define  AUTHENTICATE_ISO 			 0x1a  // AUTHENTICATE_STANDARD
#define  AUTHENTICATE_AES 			 0xaa
#define  CHANGE_KEY_SETTINGS 		 0x54
#define  GET_KEY_SETTINGS 			 0x45
#define  CHANGE_KEY 				 0xc4
#define  GET_KEY_VERSION 			 0x64
#define  AUTHENTICATION_FRAME 		 0xAF

#define MAX_NUM_KEYS 0x0F
#define MAX_APPLICATION_COUNT 28
#define MAX_FILE_COUNT 32
#define MAX_FRAME_SIZE 60
#define NOT_YET_AUTHENTICATED 255
#define FRAME_PAYLOAD_SIZE (MAX_FRAME_SIZE - 5)


// status- and error codes                                                     |
#define OPERATION_OK			0x00		// Successful operation
#define NO_CHANGES				0x0C		//  No changes done to backup files
											//  ,CommitTransaction/
											//  AbortTransaction not necessary
#define OUT_OF_EEPROM_ERROR		0x0E		// Insufficient NV-Memory to 
											//  complete command
#define ILLEGAL_COMMAND_CODE	0x1C		// Command code not supported
#define INTEGRITY_ERROR			0x1E		// CRC or MAC does not match data
											//  Padding bytes not valid
#define NO_SUCH_KEY				0x40		// Invalid key number specified
#define LENGTH_ERROR			0x7E		// Length of command string invalid
#define PERMISSION_DENIED		0x9D		// Current configuration status
											//  does not allow the requested
											//  command
#define PARAMETER_ERROR			0x9E		// Value of the parameter(s) inval.
#define APPLICATION_NOT_FOUND	0xA0		// Requested AID not present on PIC
#define APPL_INTEGRITY_ERROR	0xA1 // [1] // Unrecoverable error within app-
											//  lication, app will be disabled
#define AUTHENTICATION_ERROR	0xAE		// Current authentication status
											//  does not allow the requested
											//  command
#define ADDITIONAL_FRAME		0xAF		// Additional data frame is
											//  expected to be sent
#define BOUNDARY_ERROR			0xBE		// Attempt to read/write data from/
											//  to beyond the file's/record's
											//  limits. Attempt to exceed the
											//  limits of a value file.
#define PICC_INTEGRITY_ERROR	0xC1 // [1] // Unrecoverable error within PICC
											//  ,PICC will be disabled
#define COMMAND_ABORTED			0xCA		// Previous Command was not fully
											//  completed Not all Frames were
											//  requested or provided by PCD
#define PICC_DISABLED_ERROR		0xCD // [1] // PICC was disabled by an unrecoverable error
#define COUNT_ERROR				0xCE		// Number of Applications limited
											//  to 28, no additional
											//  CreateApplication possible
#define DUPLICATE_ERROR			0xDE		// Creation of file/application
											//  failed because file/application
											//  with same number already exists
#define EEPROM_ERROR			0xEE // [1]	// Could not complete NV-write
											//  operation due to loss of power,
											//  internal backup/rollback 
											//  mechanism activated
#define FILE_NOT_FOUND_ERROR	0xF0		// Specified file number does not
											//  exist
#define FILE_INTEGRITY_ERROR	0xF1 // [1]	// Unrecoverable error within file,
											//  file will be disabled
//
// [1] These errors are not expected to appear during normal operation

#endif