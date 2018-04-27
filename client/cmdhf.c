//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// Merlok - 2017
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency commands
//-----------------------------------------------------------------------------
#include "cmdhf.h"

static int CmdHelp(const char *Cmd);

int usage_hf_search(){
	PrintAndLogEx(NORMAL, "Usage: hf search");
	PrintAndLogEx(NORMAL, "Will try to find a HF read out of the unknown tag. Stops when found.");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "       h	- This help");
	PrintAndLogEx(NORMAL, "");
	return 0;
}
int usage_hf_snoop(){
	PrintAndLogEx(NORMAL, "Usage: hf snoop <skip pairs> <skip triggers>");
	PrintAndLogEx(NORMAL, "The high frequence snoop will assign all available memory on device for snooped data");
	PrintAndLogEx(NORMAL, "User the 'data samples' command to download from device,  and 'data plot' to look at it");
	PrintAndLogEx(NORMAL, "Press button to quit the snooping.");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "       h				- This help");
	PrintAndLogEx(NORMAL, "       <skip pairs>	- skip sample pairs");
	PrintAndLogEx(NORMAL, "       <skip triggers>	- skip number of triggers");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "           hf snoop");
	PrintAndLogEx(NORMAL, "           hf snoop 1000 0");
	return 0;
}

int CmdHFSearch(const char *Cmd){

	char cmdp = param_getchar(Cmd, 0);	
	if (cmdp == 'h' || cmdp == 'H') return usage_hf_search();
	
	int ans = CmdHF14AInfo("s");
	if (ans > 0) {
		PrintAndLogEx(SUCCESS, "\nValid ISO14443-A Tag Found\n");
		return ans;
	} 
	ans = HF15Reader("", false);
	if (ans) {
		PrintAndLogEx(SUCCESS, "\nValid ISO15693 Tag Found\n");
		return ans;
	}
	ans = HFLegicReader("", false);
	if ( ans == 0) {
		PrintAndLogEx(SUCCESS, "\nValid LEGIC Tag Found\n");
		return 1;
	}
	ans = CmdHFTopazReader("s");
	if (ans == 0) {
		PrintAndLogEx(SUCCESS, "\nValid Topaz Tag Found\n");
		return 1;
	}
	// 14b and iclass is the longest test (put last)
	ans = HF14BReader(false); //CmdHF14BReader("s");
	if (ans) {
		PrintAndLogEx(SUCCESS, "\nValid ISO14443-B Tag Found\n");
		return ans;
	}
	ans = HFiClassReader("", false, false);
	if (ans) {
		PrintAndLogEx(SUCCESS, "\nValid iClass Tag (or PicoPass Tag) Found\n");
		return ans;
	}

	/*
	ans = CmdHFFelicaReader("s");
	if (ans) {
		PrintAndLogEx(NORMAL, "\nValid ISO18092 / FeliCa Found\n");
		return ans;
	}
	*/
	
	PrintAndLogEx(FAILED, "\nno known/supported 13.56 MHz tags found\n");
	return 0;
}

int CmdHFTune(const char *Cmd) {
	PrintAndLogEx(SUCCESS, "Measuring HF antenna, press button to exit");
	UsbCommand c = {CMD_MEASURE_ANTENNA_TUNING_HF};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdHFSnoop(const char *Cmd) {
	char cmdp = param_getchar(Cmd, 0);	
	if (cmdp == 'h' || cmdp == 'H') return usage_hf_snoop();
	
	int skippairs =  param_get32ex(Cmd, 0, 0, 10);
	int skiptriggers =  param_get32ex(Cmd, 1, 0, 10);
	
	UsbCommand c = {CMD_HF_SNIFFER, {skippairs, skiptriggers, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

static command_t CommandTable[] = {
	{"help",        CmdHelp,          1, "This help"},
	{"14a",         CmdHF14A,         1, "{ ISO14443A RFIDs...            }"},
	{"14b",         CmdHF14B,         1, "{ ISO14443B RFIDs...            }"},
	{"15",          CmdHF15,          1, "{ ISO15693 RFIDs...             }"},
	{"epa",         CmdHFEPA,         1, "{ German Identification Card... }"},
	{"emv",         CmdHFEMV,         1, "{ EMV RFIDs...                  }"},
	{"felica",      CmdHFFelica,      1, "{ ISO18092 / Felica RFIDs...    }"},
	{"legic",       CmdHFLegic,       1, "{ LEGIC RFIDs...                }"},
	{"iclass",      CmdHFiClass,      1, "{ ICLASS RFIDs...               }"},
	{"mf",      	CmdHFMF,		  1, "{ MIFARE RFIDs...               }"},
	{"mfu",         CmdHFMFUltra,     1, "{ MIFARE Ultralight RFIDs...    }"},
	{"mfdes",		CmdHFMFDes,		  1, "{ MIFARE Desfire RFIDs...       }"},
	{"topaz",		CmdHFTopaz,		  1, "{ TOPAZ (NFC Type 1) RFIDs...   }"},
	{"list", 		CmdTraceList,	  0, "List protocol data in trace buffer"},	
	{"tune",		CmdHFTune,	      0, "Continuously measure HF antenna tuning"},
	{"search",      CmdHFSearch,      1, "Search for known HF tags [preliminary]"},
	{"snoop",       CmdHFSnoop,       0, "<samples to skip (10000)> <triggers to skip (1)> Generic HF Snoop"},
	{NULL, NULL, 0, NULL}
};

int CmdHF(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0; 
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
