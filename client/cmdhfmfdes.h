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

char * GetCardSizeStr( uint8_t fsize );
char * GetProtocolStr(uint8_t id);
void GetKeySettings( uint8_t * aid);

// Command options for Desfire behavior.
enum  {
 NONE		= 	0x00,
 INIT 		=	0x01,
 DISCONNECT =	0x02,
 CLEARTRACE	= 	0x04,
 BAR		= 	0x08,
} CmdOptions ;


#define  CREATE_APPLICATION 			 0xca
#define  DELETE_APPLICATION 			 0xda
#define  GET_APPLICATION_IDS 			 0x6a
#define      SELECT_APPLICATION 		 0x5a
#define      FORMAT_PICC 				 0xfc
#define      GET_VERSION 				 0x60
#define      READ_DATA 					 0xbd
#define      WRITE_DATA					 0x3d
#define      GET_VALUE 					 0x6c
#define      CREDIT 					 0x0c
#define      DEBIT 						 0xdc
#define      LIMITED_CREDIT 			 0x1c
#define      WRITE_RECORD 				 0x3b
#define      READ_RECORDS 				 0xbb
#define     CLEAR_RECORD_FILE 			 0xeb
#define      COMMIT_TRANSACTION 		 0xc7
#define      ABORT_TRANSACTION 			 0xa7
#define      GET_FREE_MEMORY             0x6e
#define  	GET_FILE_IDS 				 0x6f
#define  	GET_ISOFILE_IDS 			 0x61
#define     GET_FILE_SETTINGS 			 0xf5
#define     CHANGE_FILE_SETTINGS 		 0x5f
#define     CREATE_STD_DATA_FILE 		 0xcd
#define     CREATE_BACKUP_DATA_FILE 	 0xcb
#define     CREATE_VALUE_FILE 			 0xcc
#define     CREATE_LINEAR_RECORD_FILE 	 0xc1
#define     CREATE_CYCLIC_RECORD_FILE 	 0xc0
#define     DELETE_FILE 				 0xdf
#define     AUTHENTICATE	 			 0x0a  // AUTHENTICATE_NATIVE
#define  	AUTHENTICATE_ISO 			 0x1a  // AUTHENTICATE_STANDARD
#define  	AUTHENTICATE_AES 			 0xaa
#define     CHANGE_KEY_SETTINGS 		 0x54
#define     GET_KEY_SETTINGS 			 0x45
#define     CHANGE_KEY 					 0xc4
#define     GET_KEY_VERSION 			 0x64
#define     AUTHENTICATION_FRAME 		 0xAF

#define MAX_NUM_KEYS 0x0F
#define MAX_APPLICATION_COUNT 28
#define MAX_FILE_COUNT 32
#define MAX_FRAME_SIZE 60
#define NOT_YET_AUTHENTICATED 255
#define FRAME_PAYLOAD_SIZE (MAX_FRAME_SIZE - 5)