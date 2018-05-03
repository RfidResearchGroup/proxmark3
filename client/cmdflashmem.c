//-----------------------------------------------------------------------------
// Copyright (C) 2018 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Proxmark3 RDV40 Flash memory commands
//-----------------------------------------------------------------------------
#include "cmdflashmem.h"

#define FLASH_MEM_BLOCK_SIZE   256
#define FLASH_MEM_MAX_SIZE     0x3FFFF

static int CmdHelp(const char *Cmd);

int usage_flashmem_load(void){
	PrintAndLogEx(NORMAL, "Loads binary file into flash memory on device");
	PrintAndLogEx(NORMAL, "Usage:  mem load o <offset> f <file name>");
	PrintAndLogEx(NORMAL, "  o <offset>    :      offset in memory");
	PrintAndLogEx(NORMAL, "  f <filename>  :      file name");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        mem load f myfile");			// upload file myfile at default offset 0
	PrintAndLogEx(NORMAL, "        mem load f myfile o 1024");	// upload file myfile at offset 1024
	return 0;
}
int usage_flashmem_save(void){
	PrintAndLogEx(NORMAL, "Saves flash memory on device into the file");
	PrintAndLogEx(NORMAL, " Usage:  mem save o <offset> l <length> f <file name>");
	PrintAndLogEx(NORMAL, "  o <offset>    :      offset in memory");
	PrintAndLogEx(NORMAL, "  l <length>    :      length");
	PrintAndLogEx(NORMAL, "  f <filename>  :      file name");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        mem save f myfile");					// download whole flashmem to file myfile
	PrintAndLogEx(NORMAL, "        mem save f myfile l 4096");			// download 4096 bytes from default offset 0 to file myfile
	PrintAndLogEx(NORMAL, "        mem save f myfile o 1024 l 4096");		// downlowd 4096 bytes from offset 1024 to file myfile
	return 0;
}
int usage_flashmem_wipe(void){
	
	PrintAndLogEx(WARNING, "[OBS] use with caution.");
	PrintAndLogEx(NORMAL, "Wipe flash memory on device, which fills memory with 0xFF\n");

	PrintAndLogEx(NORMAL, " Usage:  mem save p <page>");
	PrintAndLogEx(NORMAL, "  p <page>    :      0,1,2 page memory");
//	PrintAndLogEx(NORMAL, "  i			 :      inital total wipe");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        mem wipe ");		// wipe page 0,1,2
	PrintAndLogEx(NORMAL, "        mem wipe p 0");  // wipes first page.
	return 0;
}
int CmdFlashMemLoad(const char *Cmd){

	FILE *f;
	char filename[FILE_PATH_SIZE] = {0};	
	uint8_t cmdp = 0;
	bool errors = false;
	uint32_t start_index = 0;
	
	while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch (tolower(param_getchar(Cmd, cmdp))) {
		case 'o':
			start_index = param_get32ex(Cmd, cmdp+1, 0, 10);
			cmdp += 2;
			break;
		case 'f':
			//File handling and reading
			if ( param_getstr(Cmd, cmdp+1, filename, FILE_PATH_SIZE) >= FILE_PATH_SIZE ) {
				PrintAndLogEx(FAILED, "Filename too long");
				errors = true;
				break;
			}			
			cmdp += 2;			
			break;
		case 'h':
			return usage_flashmem_load();
		default:
			PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
	
	//Validations
	if (errors || cmdp == 0 ) return usage_flashmem_load();			

	// load file
	f = fopen(filename, "rb");
	if ( !f ){
		PrintAndLogEx(FAILED, "File: %s: not found or locked.", filename);
		return 1;
	}	
	
	// get filesize in order to malloc memory
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (fsize < 0) 	{
		PrintAndLogDevice(WARNING, "error, when getting filesize");
		fclose(f);
		return 1;
	}
	
	if (fsize > FLASH_MEM_MAX_SIZE) {
		PrintAndLogDevice(WARNING, "error, filesize is larger than available memory");
		fclose(f);
		return 1;
	}

	uint8_t *dump = calloc(fsize, sizeof(uint8_t));
	if (!dump) {
		PrintAndLogDevice(WARNING, "error, cannot allocate memory ");
		fclose(f);
		return 1;
	}
	
	size_t bytes_read = fread(dump, 1, fsize, f);
	if (f)
		fclose(f);
	
	//Send to device
	uint32_t bytes_sent = 0;
	uint32_t bytes_remaining = bytes_read;

	while (bytes_remaining > 0){
		uint32_t bytes_in_packet = MIN(FLASH_MEM_BLOCK_SIZE, bytes_remaining);
		
		UsbCommand c = {CMD_WRITE_FLASH_MEM, {start_index + bytes_sent, bytes_in_packet, 0}};
				
		memcpy(c.d.asBytes, dump + bytes_sent, bytes_in_packet);
		clearCommandBuffer();
		SendCommand(&c);

		bytes_remaining -= bytes_in_packet;
		bytes_sent += bytes_in_packet;
		
		UsbCommand resp;
		if ( !WaitForResponseTimeout(CMD_ACK, &resp, 2000) ) {
			PrintAndLogEx(WARNING, "timeout while waiting for reply.");
			free(dump);
			return 1;
		}
		
		uint8_t isok  = resp.arg[0] & 0xFF;
		if (!isok)
			PrintAndLogEx(FAILED, "Flash write fail [offset %u]", bytes_sent);
		
	}
	free(dump);
	
	PrintAndLogEx(SUCCESS, "Wrote %u bytes to offset %u", bytes_read, start_index);
	return 0;
}
int CmdFlashMemSave(const char *Cmd){

	char filename[FILE_PATH_SIZE] = {0};	
	uint8_t cmdp = 0;
	bool errors = false;
	uint32_t start_index = 0, len = FLASH_MEM_MAX_SIZE;
	
	while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch (tolower(param_getchar(Cmd, cmdp))) {
		case 'h': return usage_flashmem_save();
		case 'l':
			len = param_get32ex(Cmd, cmdp+1, FLASH_MEM_MAX_SIZE, 10);
			cmdp += 2;
			break;
		case 'o':
			start_index = param_get32ex(Cmd, cmdp+1, 0, 10);
			cmdp += 2;
			break;
		case 'f':
			//File handling
			if ( param_getstr(Cmd, cmdp+1, filename, FILE_PATH_SIZE) >= FILE_PATH_SIZE ) {
				PrintAndLogEx(FAILED, "Filename too long");
				errors = true;
				break;
			}				
			cmdp += 2;			
			break;
		default:
			PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
	
	//Validations
	if (errors || cmdp == 0 ) return usage_flashmem_save();

	uint8_t* dump = calloc(len, sizeof(uint8_t));
	if (!dump) {
		PrintAndLogDevice(WARNING, "error, cannot allocate memory ");
		return 1;
	}
	
	PrintAndLogEx(NORMAL, "downloading %u bytes from flashmem", len);
	if ( !GetFromDevice(FLASH_MEM, dump, len, start_index, NULL, -1, true) ) {
		PrintAndLogEx(FAILED, "ERROR; downloading flashmem");
		free(dump);
		return 1;
	}

	saveFile(filename, "bin", dump, len);
	saveFileEML(filename, "eml", dump, len, 16);
	free(dump);
	return 0;
}
int CmdFlashMemWipe(const char *Cmd){

	uint8_t cmdp = 0;
	bool errors = false;
	bool initalwipe = false;
	uint8_t page = 0;	
	while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch (tolower(param_getchar(Cmd, cmdp))) {
		case 'h': return usage_flashmem_wipe();			
		case 'p':
			page = param_get8ex(Cmd, cmdp+1, 0, 10);
			if ( page > 2 ) {
				PrintAndLogEx(WARNING, "page must be 0, 1 or 2");
				errors = true;
				break;
			}
			cmdp += 2;
			break;
		case 'i':
			initalwipe = true;
			cmdp++;
			break;
		default:
			PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
		
	//Validations
	if (errors || cmdp == 0 ) return usage_flashmem_wipe();			
			
	UsbCommand c = {CMD_WIPE_FLASH_MEM, {page, initalwipe, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	if ( !WaitForResponseTimeout(CMD_ACK, &resp, 8000) ) {
		PrintAndLogEx(WARNING, "timeout while waiting for reply.");
		return 1;
	}
	uint8_t isok  = resp.arg[0] & 0xFF;
	if (isok)
		PrintAndLogEx(SUCCESS, "Flash WIPE ok");
	else 
		PrintAndLogEx(FAILED, "Flash WIPE failed");

	return 0;
}

static command_t CommandTable[] = {
	{"help",	CmdHelp,            1, "This help"},
	{"load",	CmdFlashMemLoad,	1, "Load data into flash memory [rdv40]"},
	{"save",	CmdFlashMemSave,	1, "Save data from flash memory [rdv40]"},
	{"wipe",	CmdFlashMemWipe,	1, "Wipe data from flash memory [rdv40]"},
	{NULL, NULL, 0, NULL}
};

int CmdFlashMem(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
