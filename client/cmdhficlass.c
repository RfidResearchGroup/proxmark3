//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>, Hagen Fritsch
// Copyright (C) 2011 Gerhard de Koning Gans
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency iClass commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "iso14443crc.h" // Can also be used for iClass, using 0xE012 as CRC-type
#include "data.h"
//#include "proxusb.h"
#include "proxmark3.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhficlass.h"
#include "common.h"
#include "util.h"
#include "cmdmain.h"

static int CmdHelp(const char *Cmd);

int xorbits_8(uint8_t val)
{
	uint8_t res = val ^ (val >> 1); //1st pass
	res = res ^ (res >> 1); 		// 2nd pass
	res = res ^ (res >> 2); 		// 3rd pass
	res = res ^ (res >> 4); 			// 4th pass
	return res & 1;
}

int CmdHFiClassList(const char *Cmd)
{

	bool ShowWaitCycles = false;
	char param = param_getchar(Cmd, 0);

	if (param != 0) {
		PrintAndLog("List data in trace buffer.");
		PrintAndLog("Usage:  hf iclass list");
		PrintAndLog("h - help");
		PrintAndLog("sample: hf iclass list");
		return 0;
	}

	uint8_t got[1920];
	GetFromBigBuf(got,sizeof(got),0);
	WaitForResponse(CMD_ACK,NULL);

	PrintAndLog("Recorded Activity");
	PrintAndLog("");
	PrintAndLog("Start = Start of Start Bit, End = End of last modulation. Src = Source of Transfer");
	PrintAndLog("All times are in carrier periods (1/13.56Mhz)");
	PrintAndLog("");
	PrintAndLog("     Start |       End | Src | Data");
	PrintAndLog("-----------|-----------|-----|--------");

	int i;
	uint32_t first_timestamp = 0;
	uint32_t timestamp;
	bool tagToReader;
	uint32_t parityBits;
	uint8_t len;
	uint8_t *frame;
	uint32_t EndOfTransmissionTimestamp = 0;


	for( i=0; i < 1900;)
	{
		//First 32 bits contain
		// isResponse (1 bit)
		// timestamp (remaining)
		//Then paritybits
		//Then length
		timestamp = *((uint32_t *)(got+i));
		parityBits = *((uint32_t *)(got+i+4));
		len = got[i+8];
		frame = (got+i+9);
		uint32_t next_timestamp = (*((uint32_t *)(got+i+9))) & 0x7fffffff;

		tagToReader = timestamp & 0x80000000;
		timestamp &= 0x7fffffff;

		if(i==0) {
			first_timestamp = timestamp;
		}

		// Break and stick with current result if buffer was not completely full
		if (frame[0] == 0x44 && frame[1] == 0x44 && frame[2] == 0x44 && frame[3] == 0x44) break;

		char line[1000] = "";

		if(len)//We have some data to display
		{
			int j,oddparity;

			for(j = 0; j < len ; j++)
			{
				oddparity = 0x01 ^ xorbits_8(frame[j] & 0xFF);

				if (tagToReader && (oddparity != ((parityBits >> (len - j - 1)) & 0x01))) {
					sprintf(line+(j*4), "%02x!  ", frame[j]);
				} else {
					sprintf(line+(j*4), "%02x   ", frame[j]);
				}
			}
		}else
		{
			if (ShowWaitCycles) {
				sprintf(line, "fdt (Frame Delay Time): %d", (next_timestamp - timestamp));
			}
		}

		char *crc = "";

		if(len > 2)
		{
			uint8_t b1, b2;
			if(!tagToReader && len == 4) {
				// Rough guess that this is a command from the reader
				// For iClass the command byte is not part of the CRC
					ComputeCrc14443(CRC_ICLASS, &frame[1], len-3, &b1, &b2);
			}
			else {
				  // For other data.. CRC might not be applicable (UPDATE commands etc.)
				ComputeCrc14443(CRC_ICLASS, frame, len-2, &b1, &b2);
			}

			if (b1 != frame[len-2] || b2 != frame[len-1]) {
				crc = (tagToReader & (len < 8)) ? "" : " !crc";
			}
		}

		i += (len + 9);
		EndOfTransmissionTimestamp = (*((uint32_t *)(got+i))) & 0x7fffffff;

		// Not implemented for iclass on the ARM-side
		//if (!ShowWaitCycles) i += 9;

		PrintAndLog(" %9d | %9d | %s | %s %s",
			(timestamp - first_timestamp),
			(EndOfTransmissionTimestamp - first_timestamp),
			(len?(tagToReader ? "Tag" : "Rdr"):"   "),
			line, crc);
	}
	return 0;
}

int CmdHFiClassListOld(const char *Cmd)
{
  uint8_t got[1920];
  GetFromBigBuf(got,sizeof(got),0);

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

    char *crc;
    crc = "";
    if (len > 2) {
      uint8_t b1, b2;
      for (j = 0; j < (len - 1); j++) {
        // gives problems... search for the reason..
        /*if(frame[j] == 0xAA) {
          switch(frame[j+1]) {
            case 0x01:
              crc = "[1] Two drops close after each other";
            break;
            case 0x02:
              crc = "[2] Potential SOC with a drop in second half of bitperiod";
              break;
            case 0x03:
              crc = "[3] Segment Z after segment X is not possible";
              break;
            case 0x04:
              crc = "[4] Parity bit of a fully received byte was wrong";
              break;
            default:
              crc = "[?] Unknown error";
              break;
          }
          break;
        }*/
      }

      if (strlen(crc)==0) {
	if(!isResponse && len == 4) {
		// Rough guess that this is a command from the reader
		// For iClass the command byte is not part of the CRC
	        ComputeCrc14443(CRC_ICLASS, &frame[1], len-3, &b1, &b2);
	}
	else {
		// For other data.. CRC might not be applicable (UPDATE commands etc.)
	        ComputeCrc14443(CRC_ICLASS, frame, len-2, &b1, &b2);
	}
	//printf("%1x %1x",(unsigned)b1,(unsigned)b2);
        if (b1 != frame[len-2] || b2 != frame[len-1]) {
          crc = (isResponse & (len < 8)) ? "" : " !crc";
        } else {
          crc = "";
        }
      }
    } else {
      crc = ""; // SHORT
    }

    char metricString[100];
    if (isResponse) {
      sprintf(metricString, "%3d", metric);
    } else {
      strcpy(metricString, "   ");
    }

    PrintAndLog(" +%7d: %s: %s %s %s",
      (prev < 0 ? 0 : (timestamp - prev)),
      metricString,
      (isResponse ? "TAG" : "   "), line, crc);

    prev = timestamp;
    i += (len + 9);
  }
  return 0;
}

/*void iso14a_set_timeout(uint32_t timeout) {
	UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_SET_TIMEOUT, 0, timeout}};
	SendCommand(&c);
}*/

int CmdHFiClassSnoop(const char *Cmd)
{
  UsbCommand c = {CMD_SNOOP_ICLASS};
  SendCommand(&c);
  return 0;
}

int CmdHFiClassSim(const char *Cmd)
{
  uint8_t simType = 0;
  uint8_t CSN[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  if (strlen(Cmd)<1) {
	PrintAndLog("Usage:  hf iclass sim [0 <CSN>] | x");
	PrintAndLog("        options");
	PrintAndLog("                0 <CSN> simulate the given CSN");
	PrintAndLog("                1       simulate default CSN");
	PrintAndLog("                2       iterate CSNs, gather MACs");
	PrintAndLog("        sample: hf iclass sim 0 031FEC8AF7FF12E0");
	PrintAndLog("        sample: hf iclass sim 2");
	return 0;
  }	

  simType = param_get8(Cmd, 0);

  if(simType == 0)
  {
	  if (param_gethex(Cmd, 1, CSN, 16)) {
		  PrintAndLog("A CSN should consist of 16 HEX symbols");
		  return 1;
	  }
	  PrintAndLog("--simtype:%02x csn:%s", simType, sprint_hex(CSN, 8));

  }
  if(simType > 2)
  {
	  PrintAndLog("Undefined simptype %d", simType);
	  return 1;
  }
  uint8_t numberOfCSNs=0;

  UsbCommand c = {CMD_SIMULATE_TAG_ICLASS, {simType,numberOfCSNs}};
  memcpy(c.d.asBytes, CSN, 8);

  if(simType == 2)
  {
	  c.arg[1] = 10;//10 CSNs
	  uint8_t csns[] ={
			  /* Order    Simulated CSN                               HASH1           Recovered key bytes */
			  /*   1   */ 0x00,0x0B,0x0F,0xFF,0xF7,0xFF,0x12,0xE0,// 0101000045014545 00,01 45
			  /*   2   */  0x03,0x0B,0x0E,0xFE,0xF7,0xFF,0x12,0xE0,// 0202000045014545 02
			  /*   3   */  0x04,0x0D,0x0D,0xFD,0xF7,0xFF,0x12,0xE0,// 0303000045014545 03
			  /*   4   */  0x04,0x0F,0x0F,0xF7,0xF7,0xFF,0x12,0xE0,// 0901000045014545 09
			  /*   5   */  0x01,0x13,0x10,0xF4,0xF7,0xFF,0x12,0xE0,// 0C00000045014545 0C
			  /*   6   */  0x02,0x14,0x10,0xF2,0xF7,0xFF,0x12,0xE0,// 0E00000045014545 0E
			  /*   7   */  0x05,0x17,0x10,0xEC,0xF7,0xFF,0x12,0xE0,// 1400000045014545 14
			  /*   8   */  0x00,0x6B,0x6F,0xDF,0xF7,0xFF,0x12,0xE0,// 2121000045014545 21
			  /*   9   */  0x03,0x6B,0x6E,0xDE,0xF7,0xFF,0x12,0xE0,// 2222000045014545 22
			  /*   10  */  0x04,0x6D,0x6D,0xDD,0xF7,0xFF,0x12,0xE0,// 2323000045014545 23
			  /*   11  */  0x00,0x4F,0x4B,0x43,0xF7,0xFF,0x12,0xE0,// 3D45000045014545 3D
			  /*   12  */  0x00,0x4B,0x4F,0x3F,0xF7,0xFF,0x12,0xE0,// 4141000045014545 41
			  /*   13  */  0x03,0x4B,0x4E,0x3E,0xF7,0xFF,0x12,0xE0,// 4242000045014545 42
			  /*   14  */  0x04,0x4D,0x4D,0x3D,0xF7,0xFF,0x12,0xE0,// 4343000045014545 43
			  /*   15  */  0x04,0x37,0x37,0x7F,0xF7,0xFF,0x12,0xE0,// 0159000045014545 59
			  /*   16  */  0x00,0x2B,0x2F,0x9F,0xF7,0xFF,0x12,0xE0,// 6161000045014545 61
			  /*   17  */  0x03,0x2B,0x2E,0x9E,0xF7,0xFF,0x12,0xE0,// 6262000045014545 62
			  /*   18  */  0x04,0x2D,0x2D,0x9D,0xF7,0xFF,0x12,0xE0,// 6363000045014545 63
			  /*   19  */  0x00,0x27,0x23,0xBB,0xF7,0xFF,0x12,0xE0,// 456D000045014545 6D
			  /*   20  */  0x02,0x52,0xAA,0x80,0xF7,0xFF,0x12,0xE0,// 0066000045014545 66
			  /*   21  */  0x00,0x5C,0xA6,0x80,0xF7,0xFF,0x12,0xE0,// 006A000045014545 6A
			  /*   22  */  0x01,0x5F,0xA4,0x80,0xF7,0xFF,0x12,0xE0,// 006C000045014545 6C
			  /*   23  */  0x06,0x5E,0xA2,0x80,0xF7,0xFF,0x12,0xE0,// 006E000045014545 6E
			  /*   24  */  0x02,0x0E,0x0E,0xFC,0xF7,0xFF,0x12,0xE0,// 0402000045014545 04
			  /*   25  */  0x05,0x0D,0x0E,0xFA,0xF7,0xFF,0x12,0xE0,// 0602000045014545 06
			  /*   26  */  0x06,0x0F,0x0D,0xF9,0xF7,0xFF,0x12,0xE0,// 0703000045014545 07
			  /*   27  */  0x00,0x01,0x05,0x1D,0xF7,0xFF,0x12,0xE0,// 630B000045014545 0B
			  /*   28  */  0x02,0x07,0x01,0x1D,0xF7,0xFF,0x12,0xE0,// 630F000045014545 0F
			  /*   29  */  0x04,0x7F,0x7F,0xA7,0xF7,0xFF,0x12,0xE0,// 5911000045014545 11
			  /*   30  */  0x04,0x60,0x6E,0xE8,0xF7,0xFF,0x12,0xE0,// 1822000045014545 18
			};
	  memcpy(c.d.asBytes, csns, sizeof(c.d.asBytes));

  }

  SendCommand(&c);

  /*UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 1500);
  if (resp != NULL) {
	uint8_t                isOK  = resp->arg[0] & 0xff;
	PrintAndLog("isOk:%02x", isOK);
  } else {
	PrintAndLog("Command execute timeout");
  }*/

  return 0;
}

int CmdHFiClassReader(const char *Cmd)
{
  uint8_t readerType = 0;

  if (strlen(Cmd)<1) {
	PrintAndLog("Usage:  hf iclass reader    <reader type>");
	PrintAndLog("        sample: hf iclass reader 0");
	return 0;
  }	

  readerType = param_get8(Cmd, 0);
  PrintAndLog("--readertype:%02x", readerType);

  UsbCommand c = {CMD_READER_ICLASS, {readerType}};
  //memcpy(c.d.asBytes, CSN, 8);
  SendCommand(&c);

  /*UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 1500);
  if (resp != NULL) {
	uint8_t                isOK  = resp->arg[0] & 0xff;
	PrintAndLog("isOk:%02x", isOK);
  } else {
	PrintAndLog("Command execute timeout");
  }*/

  return 0;
}

static command_t CommandTable[] = 
{
  {"help",    CmdHelp,        1, "This help"},
  {"list",    CmdHFiClassList,   0, "List iClass history"},
  {"snoop",   CmdHFiClassSnoop,  0, "Eavesdrop iClass communication"},
  {"sim",     CmdHFiClassSim,    0, "Simulate iClass tag"},
  {"reader",  CmdHFiClassReader, 0, "Read an iClass tag"},
  {NULL, NULL, 0, NULL}
};

int CmdHFiClass(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
