//-----------------------------------------------------------------------------
// Copyright (C) 2012 Roel Verdult
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Hitag support
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "data.h"
#include "proxusb.h"
#include "ui.h"
#include "cmdparser.h"
#include "common.h"
#include "util.h"
#include "hitag2.h"

static int CmdHelp(const char *Cmd);

int CmdLFHitagList(const char *Cmd)
{
  uint8_t got[3000];
  GetFromBigBuf(got,sizeof(got),0);
  char filename[256];
  FILE* pf;

  param_getstr(Cmd,0,filename);
  
  if (strlen(filename) > 0) {
      if ((pf = fopen(filename,"w")) == NULL) {
	    PrintAndLog("Error: Could not open file [%s]",filename);
	    return 1;
	  }
  }

  PrintAndLog("recorded activity:");
  PrintAndLog(" ETU     :rssi: who bytes");
  PrintAndLog("---------+----+----+-----------");

  int i = 0;
  int prev = -1;

  for (;;) {
    if(i >= 1900) {
      break;
    }

    bool isResponse;
    int timestamp = *((uint32_t *)(got+i));
    if (timestamp & 0x80000000) {
      timestamp &= 0x7fffffff;
      isResponse = 1;
    } else {
      isResponse = 0;
    }

    int metric = 0;
    int parityBits = *((uint32_t *)(got+i+4));
    // 4 bytes of additional information...
    // maximum of 32 additional parity bit information
    //
    // TODO:
    // at each quarter bit period we can send power level (16 levels)
    // or each half bit period in 256 levels.

    int len = got[i+8];

    if (len > 100) {
      break;
    }
    if (i + len >= 1900) {
      break;
    }

    uint8_t *frame = (got+i+9);

    // Break and stick with current result if buffer was not completely full
    if (frame[0] == 0x44 && frame[1] == 0x44 && frame[3] == 0x44) { break; }

    char line[1000] = "";
    int j;
    for (j = 0; j < len; j++) {
      int oddparity = 0x01;
      int k;

      for (k=0;k<8;k++) {
        oddparity ^= (((frame[j] & 0xFF) >> k) & 0x01);
      }

      //if((parityBits >> (len - j - 1)) & 0x01) {
      if (isResponse && (oddparity != ((parityBits >> (len - j - 1)) & 0x01))) {
        sprintf(line+(j*4), "%02x!  ", frame[j]);
      }
      else {
        sprintf(line+(j*4), "%02x   ", frame[j]);
      }
    }

    char metricString[100];
    if (isResponse) {
      sprintf(metricString, "%3d", metric);
    } else {
      strcpy(metricString, "   ");
    }

    PrintAndLog(" +%7d: %s: %s %s",
      (prev < 0 ? 0 : (timestamp - prev)),
      metricString,
      (isResponse ? "TAG" : "   "),
      line);


	if (strlen(filename) > 0) {
      fprintf(pf," +%7d: %s: %s %s %s",
					(prev < 0 ? 0 : (timestamp - prev)),
					metricString,
					(isResponse ? "TAG" : "   "),
					line,
					"\n");
    }
	
    prev = timestamp;
    i += (len + 9);
  }
  
  if (strlen(filename) > 0) {
	  PrintAndLog("Recorded activity succesfully written to file: %s", filename);
    fclose(pf);
  }
	
  return 0;
}

int CmdLFHitagSnoop(const char *Cmd) {
  UsbCommand c = {CMD_SNOOP_HITAG};
  SendCommand(&c);
  return 0;
}

int CmdLFHitagSim(const char *Cmd) {
  UsbCommand c = {CMD_SIMULATE_HITAG};
	char filename[256] = { 0x00 };
	FILE* pf;
	bool tag_mem_supplied;

	param_getstr(Cmd,0,filename);
	
	if (strlen(filename) > 0) {
		if ((pf = fopen(filename,"rb+")) == NULL) {
			PrintAndLog("Error: Could not open file [%s]",filename);
			return 1;
		}
		tag_mem_supplied = true;
		fread(c.d.asBytes,48,1,pf);
		fclose(pf);
	} else {
		tag_mem_supplied = false;
	}
	
	// Does the tag comes with memory
	c.arg[0] = (uint32_t)tag_mem_supplied;

  SendCommand(&c);
  return 0;
}

int CmdLFHitagReader(const char *Cmd) {
//  UsbCommand c = {CMD_READER_HITAG};
	
//	param_get32ex(Cmd,1,0,16);
	UsbCommand c = {CMD_READER_HITAG};//, {param_get32ex(Cmd,0,0,10),param_get32ex(Cmd,1,0,16),param_get32ex(Cmd,2,0,16),param_get32ex(Cmd,3,0,16)}};
	hitag_data* htd = (hitag_data*)c.d.asBytes;
	hitag_function htf = param_get32ex(Cmd,0,0,10);
	
	switch (htf) {
		case RHT2F_PASSWORD: {
			num_to_bytes(param_get32ex(Cmd,1,0,16),4,htd->pwd.password);
		} break;
		case RHT2F_AUTHENTICATE: {
			num_to_bytes(param_get32ex(Cmd,1,0,16),4,htd->auth.NrAr);
			num_to_bytes(param_get32ex(Cmd,2,0,16),4,htd->auth.NrAr+4);
		} break;
		case RHT2F_CRYPTO: {
			num_to_bytes(param_get64ex(Cmd,1,0,16),6,htd->crypto.key);
//			num_to_bytes(param_get32ex(Cmd,2,0,16),4,htd->auth.NrAr+4);
		} break;
		case RHT2F_TEST_AUTH_ATTEMPTS: {
			// No additional parameters needed
		} break;
		default: {
			PrintAndLog("Error: unkown reader function %d",htf);
			PrintAndLog("Hitag reader functions",htf);
			PrintAndLog(" HitagS (0*)",htf);
			PrintAndLog(" Hitag1 (1*)",htf);
			PrintAndLog(" Hitag2 (2*)",htf);
			PrintAndLog("  21 <password> (password mode)",htf);
			PrintAndLog("  22 <nr> <ar> (authentication)",htf);
			PrintAndLog("  23 <key> (authentication) key is in format: ISK high + ISK low",htf);
			PrintAndLog("  25 (test recorded authentications)",htf);
			return 1;
		} break;
	}

	// Copy the hitag2 function into the first argument
	c.arg[0] = htf;

  SendCommand(&c);
  return 0;
}

static command_t CommandTableHitag[] = 
{
  {"help",    CmdHelp,           1, "This help"},
  {"list",    CmdLFHitagList,    1, "List Hitag trace history"},
  {"reader",  CmdLFHitagReader,  1, "Act like a Hitag Reader"},
  {"sim",     CmdLFHitagSim,     1, "Simulate Hitag transponder"},
  {"snoop",   CmdLFHitagSnoop,   1, "Eavesdrop Hitag communication"},
		{NULL, NULL, 0, NULL}
};

int CmdLFHitag(const char *Cmd)
{
  CmdsParse(CommandTableHitag, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTableHitag);
  return 0;
}
