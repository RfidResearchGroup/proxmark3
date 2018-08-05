//-----------------------------------------------------------------------------
// Copyright (C) 2014 Peter Fillmore
// 2017 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency EMV commands
//-----------------------------------------------------------------------------
#include "cmdhfemv.h"

static int CmdHelp(const char *Cmd);

int usage_hf_emv_test(void){
	PrintAndLogEx(NORMAL, "EMV test ");
	PrintAndLogEx(NORMAL, "Usage:  hf emv test [h]");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "      h             : this help");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "      hf emv test");	
	return 0;
}
int usage_hf_emv_readrecord(void){
	PrintAndLogEx(NORMAL, "Read a EMV record ");
	PrintAndLogEx(NORMAL, "Usage:  hf emv readrecord [h] <records> <sfi>");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "      h             : this help");
	PrintAndLogEx(NORMAL, "      <records>     : number of records");
	PrintAndLogEx(NORMAL, "      <sfi>         : number of SFI records");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "      hf emv readrecord 1 1");	
	return 0;
}
int usage_hf_emv_clone(void){
	PrintAndLogEx(NORMAL, "Usage:  hf emv clone [h] <records> <SFI> ");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "      h             : this help");
	PrintAndLogEx(NORMAL, "      <records>     : number of records");
	PrintAndLogEx(NORMAL, "      <sfi>         : number of SFI records");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "      hf emv clone 10 10");	
	return 0;
}
int usage_hf_emv_transaction(void){
	PrintAndLogEx(NORMAL, "Performs EMV reader transaction");
	PrintAndLogEx(NORMAL, "Usage:  hf emv trans [h]");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "      h             : this help");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "      hf emv trans");
	return 0;
}
int usage_hf_emv_getrnd(void){
	PrintAndLogEx(NORMAL, "retrieve the UN number from a terminal");
	PrintAndLogEx(NORMAL, "Usage:  hf emv getrnd [h]");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "      h             : this help");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "      hf emv getrnd");
	return 0;
}
int usage_hf_emv_eload(void){
	PrintAndLogEx(NORMAL, "set EMV tags in the device to use in a transaction");
	PrintAndLogEx(NORMAL, "Usage:  hf emv eload [h] o <filename w/o .bin>");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "      h             : this help");
	PrintAndLogEx(NORMAL, "      o <filename>  : filename w/o '.bin'");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "      hf emv eload o myfile");
	return 0;
}
int usage_hf_emv_dump(void){
	PrintAndLogEx(NORMAL, "Gets EMV contactless tag values.");
	PrintAndLogEx(NORMAL, "and saves binary dump into the file `filename.bin` or `cardUID.bin`");
	PrintAndLogEx(NORMAL, "Usage:  hf emv dump [h] o <filename w/o .bin>");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "      h             : this help");
	PrintAndLogEx(NORMAL, "      o <filename>  : filename w/o '.bin' to dump bytes");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "      hf emv dump");
	PrintAndLogEx(NORMAL, "      hf emv dump o myfile");
	return 0;
}
int usage_hf_emv_sim(void){
	PrintAndLogEx(NORMAL, "Simulates a EMV contactless card");
	PrintAndLogEx(NORMAL, "Usage:  hf emv sim [h]");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "      h             : this help");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "      hf emv sim");
	return 0;
}

int CmdHfEmvTest(const char *Cmd) {
	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'h' || cmdp == 'H') return usage_hf_emv_test();

	UsbCommand c = {CMD_EMV_TEST, {0, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
		PrintAndLogEx(WARNING, "Command execute time-out");
		return 1;
	}
	uint8_t isOK  = resp.arg[0] & 0xff;
	PrintAndLogEx(NORMAL, "isOk: %02x", isOK);	
	return 0;
}
											 
int CmdHfEmvReadRecord(const char *Cmd) {
	char cmdp = param_getchar(Cmd, 0);
	if ((strlen(Cmd)<3) || cmdp == 'h' || cmdp == 'H') return usage_hf_emv_readrecord();

	uint8_t record = param_get8(Cmd, 0);
	uint8_t sfi = param_getchar(Cmd, 1);
    if(record > 32){
        PrintAndLogEx(WARNING, "Record must be less than 32"); 
		return 1;
    }
	PrintAndLogEx(NORMAL, "--record no:%02x SFI:%02x ", record, sfi);

	UsbCommand c = {CMD_EMV_READ_RECORD, {record, sfi, 0}};
	clearCommandBuffer();  
	SendCommand(&c);
	UsbCommand resp;
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
		PrintAndLogEx(WARNING, "Command execute timeout");
		return 1;
	}
	uint8_t isOK  = resp.arg[0] & 0xff;
	PrintAndLogEx(NORMAL, "isOk:%02x", isOK);	
	return 0;
}												   

int CmdHfEmvClone(const char *Cmd) {
	char cmdp = param_getchar(Cmd, 0);
	if ((strlen(Cmd)<3) || cmdp == 'h' || cmdp == 'H') return usage_hf_emv_clone();

	uint8_t record = param_get8(Cmd, 0);
	uint8_t sfi = param_get8(Cmd, 1);
    if(record > 32){
        PrintAndLogEx(WARNING, "Record must be less than 32"); 
		return 1;
    }	
	UsbCommand c = {CMD_EMV_CLONE, {sfi, record, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
		PrintAndLogEx(WARNING, "Command execute timeout");
		return 1;
	}
	uint8_t isOK  = resp.arg[0] & 0xff;
	PrintAndLogEx(NORMAL, "isOk:%02x", isOK);
	return 0;
}

int CmdHfEmvTrans(const char *Cmd) {
	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'h' || cmdp == 'H') return usage_hf_emv_transaction();

	UsbCommand c = {CMD_EMV_TRANSACTION, {0, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 5000)) {
		PrintAndLogEx(WARNING, "Command execute time-out");
		return 1;
	}
	uint8_t isOK  = resp.arg[0] & 0xff;
	PrintAndLogEx(NORMAL, "isOk: %02x", isOK);
	print_hex_break(resp.d.asBytes, 512, 32);
	return 0;
}
//retrieve the UN number from a terminal
int CmdHfEmvGetrng(const char *Cmd) {
	char cmdp = param_getchar(Cmd, 0);
	if ( cmdp == 'h' || cmdp == 'H') return usage_hf_emv_getrnd();
    UsbCommand c = {CMD_EMV_GET_RANDOM_NUM, {0, 0, 0}};
	clearCommandBuffer();
    SendCommand(&c);
    return 0;
}
//Load a dumped EMV tag on to emulator memory
int CmdHfEmvELoad(const char *Cmd) {
	FILE * f;
	char filename[FILE_PATH_SIZE];
	char *fnameptr = filename;
	int len;
	bool errors = false;
	uint8_t cmdp = 0;

	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch(param_getchar(Cmd, cmdp)) {
			case 'h':
			case 'H':
				return usage_hf_emv_eload();
			case 'o':
			case 'O':
				len = param_getstr(Cmd, cmdp+1, filename, FILE_PATH_SIZE);
				if (!len) 
					errors = true; 
				if (len > FILE_PATH_SIZE-5) 
					len = FILE_PATH_SIZE-5;				
				sprintf(fnameptr + len,".bin");		
				cmdp += 2;
				break;				
			default:
				PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
				errors = true;
				break;
		}
	}
	//Validations
	if (errors || cmdp == 0) return usage_hf_emv_eload();

	// open file
	f = fopen(filename,"r");
	if (!f) { 
		PrintAndLogEx(WARNING, "File %s not found or locked", filename);
		return 1;
	}
	
    char line[512];
    char *token;    
    uint16_t tag;
	
    UsbCommand c = {CMD_EMV_LOAD_VALUE, {0,0,0}};  
	
	// transfer to device
    while (fgets(line, sizeof (line), f)) {
        PrintAndLogEx(NORMAL, "LINE = %s\n", line);
		
        token = strtok(line, ":"); 
        tag = (uint16_t)strtol(token, NULL, 0);  
        token = strtok(NULL,""); 
		
        c.arg[0] = tag;
        memcpy(c.d.asBytes, token, strlen(token));

		clearCommandBuffer();
        SendCommand(&c);

        PrintAndLogEx(NORMAL, "Loaded TAG   = %04x\n", tag);
        PrintAndLogEx(NORMAL, "Loaded VALUE = %s\n", token); 
    }
	
	fclose(f);
	PrintAndLogEx(NORMAL, "loaded %s", filename);
	//PrintAndLogEx(NORMAL, "\nLoaded %d bytes from file: %s  to emulator memory", numofbytes, filename);
	return 0;
}

int CmdHfEmvDump(const char *Cmd){

	bool errors = false;
	uint8_t cmdp = 0;
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch(param_getchar(Cmd, cmdp)) {
			case 'h':
			case 'H':
				return usage_hf_emv_dump();
			default:
				PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
				errors = true;
				break;
		}
	}
	//Validations
	if (errors) return usage_hf_emv_dump();
	
    UsbCommand c = {CMD_EMV_DUMP_CARD, {0, 0, 0}};
	clearCommandBuffer();
    SendCommand(&c);
	UsbCommand resp;
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 3000)) {
		PrintAndLogEx(WARNING, "Command execute time-out");
		return 1;
	}
	return 0;
}	

int CmdHfEmvSim(const char *Cmd) {
	
	bool errors = false;	
	uint8_t cmdp = 0;
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch(param_getchar(Cmd, cmdp)) {
			case 'h':
			case 'H':
				return usage_hf_emv_sim();
			default:
				PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
				errors = true;
				break;
		}
	}
	//Validations
	if (errors) return usage_hf_emv_sim();	
	
	UsbCommand c = {CMD_EMV_SIM, {0,0,0}};
	clearCommandBuffer();
	SendCommand(&c);	
	UsbCommand resp;
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
		PrintAndLogEx(WARNING, "Command execute time-out");
		return 1;
	}	
	uint8_t isOK  = resp.arg[0] & 0xff;
	PrintAndLogEx(NORMAL, "isOk:%02x", isOK);
	return 0;
}

int CmdHfEmvList(const char *Cmd) {
	return CmdTraceList("7816");
}

static command_t CommandTable[] =  {
	{"help",		CmdHelp,		  1, "This help"},
	{"readrecord",	CmdHfEmvReadRecord, 0, "EMV Read Record"},
	{"transaction",	CmdHfEmvTrans, 	  0, "Perform EMV Transaction"}, 
	{"getrng",		CmdHfEmvGetrng,	  0, "get random number from terminal"}, 
	{"eload",		CmdHfEmvELoad, 	  0, "load EMV tag into device"},
	{"dump",		CmdHfEmvDump,	  0, "dump EMV tag values"},
	{"sim",			CmdHfEmvSim,	  0, "simulate EMV tag"},
	{"clone",		CmdHfEmvClone,	  0, "clone an EMV tag"}, 
	{"list",		CmdHfEmvList,	  0, "[Deprecated] List ISO7816 history"}, 
    {"test",		CmdHfEmvTest,	  0, "Test Function"}, 	
	{NULL, NULL, 0, NULL}
};

int CmdHFEmv(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}