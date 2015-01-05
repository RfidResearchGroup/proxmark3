//-----------------------------------------------------------------------------
// Copyright (C) 2012 Frederik Möllers
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Commands related to the German electronic Identification Card
//-----------------------------------------------------------------------------

#include "util.h"
//#include "proxusb.h"
#include "proxmark3.h"
#include "ui.h"
#include "cmdparser.h"
#include "../include/common.h"
#include "cmdmain.h"
#include "sleep.h"
#include "cmdhfepa.h"

static int CmdHelp(const char *Cmd);

// Perform (part of) the PACE protocol
int CmdHFEPACollectPACENonces(const char *Cmd)
{
	// requested nonce size
	unsigned int m = 0;
	// requested number of Nonces
	unsigned int n = 0;
	// delay between requests
	unsigned int d = 0;
	
	sscanf(Cmd, "%u %u %u", &m, &n, &d);
	
	// values are expected to be > 0
	m = m > 0 ? m : 1;
	n = n > 0 ? n : 1;

	PrintAndLog("Collecting %u %"hhu"-byte nonces", n, m);
	PrintAndLog("Start: %u", time(NULL));
	// repeat n times
	for (unsigned int i = 0; i < n; i++) {
		// execute PACE
		UsbCommand c = {CMD_EPA_PACE_COLLECT_NONCE, {(int)m, 0, 0}};
		SendCommand(&c);
		UsbCommand resp;
    
		WaitForResponse(CMD_ACK,&resp);

		// check if command failed
		if (resp.arg[0] != 0) {
			PrintAndLog("Error in step %d, Return code: %d",resp.arg[0],(int)resp.arg[1]);
		} else {
			size_t nonce_length = resp.arg[1];
			char *nonce = (char *) malloc(2 * nonce_length + 1);
			for(int j = 0; j < nonce_length; j++) {
				sprintf(nonce + (2 * j), "%02X", resp.d.asBytes[j]);
			}
			// print nonce
			PrintAndLog("Length: %d, Nonce: %s", nonce_length, nonce);
		}
		if (i < n - 1) {
			sleep(d);
		}
	}
	PrintAndLog("End: %u", time(NULL));

	return 1;
}

// UI-related stuff

static const command_t CommandTable[] = 
{
  {"help",    CmdHelp,                   1, "This help"},
  {"cnonces", CmdHFEPACollectPACENonces, 0,
              "<m> <n> <d> Acquire n>0 encrypted PACE nonces of size m>0 with d sec pauses"},
  {NULL, NULL, 0, NULL}
};

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}

int CmdHFEPA(const char *Cmd)
{
	// flush
	WaitForResponseTimeout(CMD_ACK,NULL,100);

	// parse
  CmdsParse(CommandTable, Cmd);
  return 0;
}