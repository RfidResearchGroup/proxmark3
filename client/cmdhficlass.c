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
#include <sys/stat.h>
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

	if(simType == 2)
	{
		UsbCommand c = {CMD_SIMULATE_TAG_ICLASS, {simType,63}};
		UsbCommand resp = {0};

		uint8_t csns[64] = {
			 0x00,0x0B,0x0F,0xFF,0xF7,0xFF,0x12,0xE0 ,
			 0x00,0x13,0x94,0x7e,0x76,0xff,0x12,0xe0 ,
			 0x2a,0x99,0xac,0x79,0xec,0xff,0x12,0xe0 ,
			 0x17,0x12,0x01,0xfd,0xf7,0xff,0x12,0xe0 ,
			 0xcd,0x56,0x01,0x7c,0x6f,0xff,0x12,0xe0 ,
			 0x4b,0x5e,0x0b,0x72,0xef,0xff,0x12,0xe0 ,
			 0x00,0x73,0xd8,0x75,0x58,0xff,0x12,0xe0 ,
			 0x0c,0x90,0x32,0xf3,0x5d,0xff,0x12,0xe0 };

		memcpy(c.d.asBytes, csns, 64);

		SendCommand(&c);
		if (!WaitForResponseTimeout(CMD_ACK, &resp, -1)) {
			PrintAndLog("Command timed out");
			return 0;
		}

		uint8_t num_mac_responses  = resp.arg[1];
		PrintAndLog("Mac responses: %d MACs obtained (should be 8)", num_mac_responses);

		size_t datalen = 8*24;
		/*
		 * Now, time to dump to file. We'll use this format:
		 * <8-byte CSN><8-byte CC><4 byte NR><4 byte MAC>....
		 * So, it should wind up as
		 * 8 * 24 bytes.
		 *
		 * The returndata from the pm3 is on the following format
		 * <4 byte NR><4 byte MAC>
		 * CC are all zeroes, CSN is the same as was sent in
		 **/
		void* dump = malloc(datalen);
		memset(dump,0,datalen);//<-- Need zeroes for the CC-field
		uint8_t i = 0;
		for(i = 0 ; i < 8 ; i++)
		{
			memcpy(dump+i*24, csns+i*8,8); //CSN
			//8 zero bytes here...
			//Then comes NR_MAC (eight bytes from the response)
			memcpy(dump+i*24+16,resp.d.asBytes+i*8,8);

		}
		/** Now, save to dumpfile **/
		saveFile("iclass_mac_attack", "bin", dump,datalen);
		free(dump);
	}else
	{
		UsbCommand c = {CMD_SIMULATE_TAG_ICLASS, {simType,numberOfCSNs}};
		memcpy(c.d.asBytes, CSN, 8);
		SendCommand(&c);
	}
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

/**
 * @brief checks if a file exists
 * @param filename
 * @return
 */
int fileExists(const char *filename) {
	struct stat st;
	int result = stat(filename, &st);
	return result == 0;
}
/**
 * @brief Utility function to save data to a file. This method takes a preferred name, but if that
 * file already exists, it tries with another name until it finds something suitable.
 * E.g. dumpdata-15.txt
 * @param preferredName
 * @param suffix the file suffix. Leave out the ".".
 * @param data The binary data to write to the file
 * @param datalen the length of the data
 * @return 0 for ok, 1 for failz
 */
int saveFile(const char *preferredName, const char *suffix, const void* data, size_t datalen)
{
	FILE *f = fopen(preferredName, "wb");
	int size = sizeof(char) * (strlen(preferredName)+strlen(suffix)+5);
	char * fileName = malloc(size);

	memset(fileName,0,size);
	int num = 1;
	sprintf(fileName,"%s.%s", preferredName, suffix);
	while(fileExists(fileName))
	{
		sprintf(fileName,"%s-%d.%s", preferredName, num, suffix);
		num++;
	}
	/* We should have a valid filename now, e.g. dumpdata-3.bin */

	/*Opening file for writing in binary mode*/
	FILE *fileHandle=fopen(fileName,"wb");
	if(!f) {
		PrintAndLog("Failed to write to file '%s'", fileName);
		return 0;
	}
	fwrite(data, 1,	datalen, fileHandle);
	fclose(fileHandle);
	PrintAndLog("Saved data to '%s'", fileName);

	free(fileName);
	return 0;
}
