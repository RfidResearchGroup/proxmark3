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
  if(simType > 5)
  {
	  PrintAndLog("Undefined simptype %d", simType);
	  return 1;
  }
  uint8_t numberOfCSNs=0;

	if(simType == 2)
	{
		UsbCommand c = {CMD_SIMULATE_TAG_ICLASS, {simType,63}};
		UsbCommand resp = {0};

		uint8_t csns1[] ={
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
			  /*31*/ 0x04,0x77,0x77,0xBF,0xF7,0xFF,0x12,0xE0, // 4119000045014545 19
			  /*32*/ 0x00,0x69,0x6D,0xE5,0xF7,0xFF,0x12,0xE0, // 1B23000045014545 1B
			  /*33*/ 0x01,0x69,0x6E,0xE2,0xF7,0xFF,0x12,0xE0, // 1E22000045014545 1E
			  /*34*/ 0x02,0x6B,0x6D,0xE1,0xF7,0xFF,0x12,0xE0, // 1F23000045014545 1F
			  /*35*/ 0x01,0x3F,0x04,0xE0,0xF7,0xFF,0x12,0xE0, // 200C000045014545 20
			  /*36*/ 0x02,0x6E,0x6E,0xDC,0xF7,0xFF,0x12,0xE0, // 2422000045014545 24
			  /*37*/ 0x05,0x6D,0x6E,0xDA,0xF7,0xFF,0x12,0xE0, // 2622000045014545 26
			  /*38*/ 0x06,0x6F,0x6D,0xD9,0xF7,0xFF,0x12,0xE0, // 2723000045014545 27
			  /*39*/ 0x01,0x6B,0x68,0xEC,0xF7,0xFF,0x12,0xE0, // 1428000045014545 28
			  /*40*/ 0x04,0x6F,0x6F,0xD7,0xF7,0xFF,0x12,0xE0, // 2921000045014545 29
			  /*41*/ 0x02,0x66,0x66,0xF4,0xF7,0xFF,0x12,0xE0, // 0C2A000045014545 2A
			  /*42*/ 0x00,0x61,0x65,0xFD,0xF7,0xFF,0x12,0xE0, // 032B000045014545 2B
			  /*43*/ 0x00,0x62,0x64,0xFE,0xF7,0xFF,0x12,0xE0, // 022C000045014545 2C
			  /*44*/ 0x01,0x65,0x62,0xFE,0xF7,0xFF,0x12,0xE0, // 022E000045014545 2E
			  /*45*/ 0x02,0x67,0x61,0xFD,0xF7,0xFF,0x12,0xE0, // 032F000045014545 2F
			  /*46*/ 0x00,0x5F,0x5B,0x13,0xF7,0xFF,0x12,0xE0, // 6D35000045014545 35
			  /*47*/ 0x00,0x44,0x4E,0x48,0xF7,0xFF,0x12,0xE0, // 3842000045014545 38
			  /*48*/ 0x00,0x53,0x57,0x27,0xF7,0xFF,0x12,0xE0, // 5939000045014545 39
			  /*49*/ 0x00,0x49,0x4D,0x45,0xF7,0xFF,0x12,0xE0, // 3B43000045014545 3B
			  /*50*/ 0x01,0x49,0x4E,0x42,0xF7,0xFF,0x12,0xE0, // 3E42000045014545 3E
			  /*51*/ 0x02,0x4B,0x4D,0x41,0xF7,0xFF,0x12,0xE0, // 3F43000045014545 3F
			  /*52*/ 0x02,0x4E,0x4E,0x3C,0xF7,0xFF,0x12,0xE0, // 4442000045014545 44
			  /*53*/ 0x05,0x4D,0x4E,0x3A,0xF7,0xFF,0x12,0xE0, // 4642000045014545 46
			  /*54*/ 0x06,0x4F,0x4D,0x39,0xF7,0xFF,0x12,0xE0, // 4743000045014545 47
			  /*55*/ 0x01,0x77,0x7C,0xB8,0xF7,0xFF,0x12,0xE0, // 4814000045014545 48
			  /*56*/ 0x04,0x4F,0x4F,0x37,0xF7,0xFF,0x12,0xE0, // 4941000045014545 49
			  /*57*/ 0x00,0x7A,0x7C,0xB6,0xF7,0xFF,0x12,0xE0, // 4A14000045014545 4A
			  /*58*/ 0x00,0x41,0x45,0x5D,0xF7,0xFF,0x12,0xE0, // 234B000045014545 4B
			  /*59*/ 0x00,0x42,0x44,0x5E,0xF7,0xFF,0x12,0xE0, // 224C000045014545 4C
			  /*60*/ 0x01,0x45,0x42,0x5E,0xF7,0xFF,0x12,0xE0, // 224E000045014545 4E
			  /*61*/ 0x02,0x47,0x41,0x5D,0xF7,0xFF,0x12,0xE0, // 234F000045014545 4F
			  /*62*/ 0x04,0x7E,0x7C,0xAE,0xF7,0xFF,0x12,0xE0, // 5214000045014545 52
			  /*63*/ 0x00,0x57,0x53,0x2B,0xF7,0xFF,0x12,0xE0, // 553D000045014545 55
			  };
		memcpy(c.d.asBytes, csns1, sizeof(c.d.asBytes));

		SendCommand(&c);
		if (!WaitForResponseTimeout(CMD_ACK, &resp, -1)) {
			PrintAndLog("Command timed out");
			return 0;
		}

		uint8_t num_mac_responses_1  = resp.arg[1];
		PrintAndLog("Mac responses, first part : %d MACs obtained (should be 63)", num_mac_responses_1);

		UsbCommand c2 = {CMD_SIMULATE_TAG_ICLASS, {simType,63}};
		UsbCommand resp2 = {0};

		uint8_t csns2[] ={
			/*64*/ 0x04,0x3C,0x3A,0x74,0xF7,0xFF,0x12,0xE0, // 0C56000045014545 56
			/*65*/ 0x00,0x24,0x2E,0xA8,0xF7,0xFF,0x12,0xE0, // 5862000045014545 58
			/*66*/ 0x00,0x29,0x2D,0xA5,0xF7,0xFF,0x12,0xE0, // 5B63000045014545 5B
			/*67*/ 0x00,0x00,0x02,0x24,0xF7,0xFF,0x12,0xE0, // 5C0E000045014545 5C
			/*68*/ 0x01,0x29,0x2E,0xA2,0xF7,0xFF,0x12,0xE0, // 5E62000045014545 5E
			/*69*/ 0x02,0x2B,0x2D,0xA1,0xF7,0xFF,0x12,0xE0, // 5F63000045014545 5F
			/*70*/ 0x02,0x2E,0x2E,0x9C,0xF7,0xFF,0x12,0xE0, // 6462000045014545 64
			/*71*/ 0x02,0x0A,0x02,0x18,0xF7,0xFF,0x12,0xE0, // 680E000045014545 68
			/*72*/ 0x00,0x03,0x07,0x17,0xF7,0xFF,0x12,0xE0, // 6909000045014545 69
			/*73*/ 0x00,0x21,0x25,0xBD,0xF7,0xFF,0x12,0xE0, // 436B000045014545 6B
			/*74*/ 0x02,0x27,0x21,0xBD,0xF7,0xFF,0x12,0xE0, // 436F000045014545 6F
			/*75*/ 0x04,0x07,0x07,0x0F,0xF7,0xFF,0x12,0xE0, // 7109000045014545 71
			/*76*/ 0x00,0x04,0x0E,0x08,0xF7,0xFF,0x12,0xE0, // 7802000045014545 78
			/*77*/ 0x00,0x33,0x37,0x87,0xF7,0xFF,0x12,0xE0, // 7959000045014545 79
			/*78*/ 0x00,0x09,0x0D,0x05,0xF7,0xFF,0x12,0xE0, // 7B03000045014545 7B
			/*79*/ 0x01,0x09,0x0E,0x02,0xF7,0xFF,0x12,0xE0, // 7E02000045014545 7E
			/*80*/ 0x02,0x0B,0x0D,0x01,0xF7,0xFF,0x12,0xE0, // 7F03000045014545 7F
			/*81*/ 0x00,0x34,0x3E,0x78,0xF7,0xFF,0x12,0xE0, // 0852000045014545 08
			/*82*/ 0x04,0x66,0x64,0xF6,0xF7,0xFF,0x12,0xE0, // 0A2C000045014545 0A
			/*83*/ 0x00,0x3F,0x3B,0x73,0xF7,0xFF,0x12,0xE0, // 0D55000045014545 0D
			/*84*/ 0x03,0x3B,0x3E,0x6E,0xF7,0xFF,0x12,0xE0, // 1252000045014545 12
			/*85*/ 0x00,0x11,0x15,0xED,0xF7,0xFF,0x12,0xE0, // 137B000045014545 13
			/*86*/ 0x00,0x6E,0x68,0xEA,0xF7,0xFF,0x12,0xE0, // 1628000045014545 16
			/*87*/ 0x00,0x6D,0x69,0xE9,0xF7,0xFF,0x12,0xE0, // 1727000045014545 17
			/*88*/ 0x00,0x6A,0x6C,0xE6,0xF7,0xFF,0x12,0xE0, // 1A24000045014545 1A
			/*89*/ 0x00,0x40,0x42,0x64,0xF7,0xFF,0x12,0xE0, // 1C4E000045014545 1C
			/*90*/ 0x00,0x77,0x73,0xCB,0xF7,0xFF,0x12,0xE0, // 351D000045014545 1D
			/*91*/ 0x06,0x6E,0x72,0xD0,0xF7,0xFF,0x12,0xE0, // 301E000045014545 30
			/*92*/ 0x00,0x1B,0x1F,0xCF,0xF7,0xFF,0x12,0xE0, // 3171000045014545 31
			/*93*/ 0x01,0x75,0x72,0xCE,0xF7,0xFF,0x12,0xE0, // 321E000045014545 32
			/*94*/ 0x00,0x71,0x75,0xCD,0xF7,0xFF,0x12,0xE0, // 331B000045014545 33
			/*95*/ 0x00,0x48,0x4A,0x4C,0xF7,0xFF,0x12,0xE0, // 3446000045014545 34
			/*96*/ 0x00,0x4E,0x48,0x4A,0xF7,0xFF,0x12,0xE0, // 3648000045014545 36
			/*97*/ 0x00,0x4D,0x49,0x49,0xF7,0xFF,0x12,0xE0, // 3747000045014545 37
			/*98*/ 0x00,0x4A,0x4C,0x46,0xF7,0xFF,0x12,0xE0, // 3A44000045014545 3A
			/*99*/ 0x00,0x20,0x22,0xC4,0xF7,0xFF,0x12,0xE0, // 3C6E000045014545 3C
			/*100*/ 0x00,0x1C,0x66,0x40,0xF7,0xFF,0x12,0xE0, // 402A000045014545 40
			/*101*/ 0x06,0x4E,0x52,0x30,0xF7,0xFF,0x12,0xE0, // 503E000045014545 50
			/*102*/ 0x00,0x7B,0x7F,0xAF,0xF7,0xFF,0x12,0xE0, // 5111000045014545 51
			/*103*/ 0x00,0x51,0x55,0x2D,0xF7,0xFF,0x12,0xE0, // 533B000045014545 53
			/*104*/ 0x00,0x28,0x2A,0xAC,0xF7,0xFF,0x12,0xE0, // 5466000045014545 54
			/*105*/ 0x02,0x53,0x55,0x29,0xF7,0xFF,0x12,0xE0, // 573B000045014545 57
			/*106*/ 0x00,0x2A,0x2C,0xA6,0xF7,0xFF,0x12,0xE0, // 5A64000045014545 5A
			/*107*/ 0x00,0x7C,0x46,0x20,0xF7,0xFF,0x12,0xE0, // 604A000045014545 60
			/*108*/ 0x02,0x03,0x05,0x19,0xF7,0xFF,0x12,0xE0, // 670B000045014545 67
			/*109*/ 0x01,0x2F,0x34,0x90,0xF7,0xFF,0x12,0xE0, // 705C000045014545 70
			/*110*/ 0x00,0x32,0x34,0x8E,0xF7,0xFF,0x12,0xE0, // 725C000045014545 72
			/*111*/ 0x00,0x31,0x35,0x8D,0xF7,0xFF,0x12,0xE0, // 735B000045014545 73
			/*112*/ 0x00,0x08,0x0A,0x0C,0xF7,0xFF,0x12,0xE0, // 7406000045014545 74
			/*113*/ 0x03,0x37,0x32,0x8A,0xF7,0xFF,0x12,0xE0, // 765E000045014545 76
			/*114*/ 0x00,0x0D,0x09,0x09,0xF7,0xFF,0x12,0xE0, // 7707000045014545 77
			/*115*/ 0x00,0x0A,0x0C,0x06,0xF7,0xFF,0x12,0xE0, // 7A04000045014545 7A
			/*116*/ 0x00,0x60,0x62,0x04,0xF7,0xFF,0x12,0xE0, // 7C2E000045014545 7C
			/*117*/ 0x00,0x07,0x03,0x1B,0xF7,0xFF,0x12,0xE0, // 650D000045014545 65
			/*118*/ 0x00,0x0C,0x16,0xF0,0xF7,0xFF,0x12,0xE0, // 107A000045014545 10
			/*119*/ 0x00,0x6F,0x6B,0xE3,0xF7,0xFF,0x12,0xE0, // 1D25000045014545 25
			/*120*/ 0x00,0x2F,0x2B,0xA3,0xF7,0xFF,0x12,0xE0, // 5D65000045014545 5D
			/*121*/ 0x00,0x47,0x43,0x5B,0xF7,0xFF,0x12,0xE0, // 254D000045014545 4D
			/*122*/ 0x00,0x37,0x33,0x8B,0xF7,0xFF,0x12,0xE0, // 755D000045014545 75
			/*123*/ 0x00,0x1F,0x1B,0xD3,0xF7,0xFF,0x12,0xE0, // 2D75000045014545 2D
			/*124*/ 0x00,0x67,0x63,0xFB,0xF7,0xFF,0x12,0xE0, // 052D000045014545 05
			/*125*/ 0x00,0x0F,0x0B,0x03,0xF7,0xFF,0x12,0xE0, // 7D05000045014545 7D
			/*126*/ 0x00,0x17,0x13,0xEB,0xF7,0xFF,0x12,0xE0, // 157D000045014545 15
		};

		memcpy(c2.d.asBytes, csns2, sizeof(c2.d.asBytes));

		SendCommand(&c);
		if (!WaitForResponseTimeout(CMD_ACK, &resp2, -1)) {
			PrintAndLog("Command timed out");
			return 0;
		}
		uint8_t num_mac_responses_2  = resp2.arg[1];
		PrintAndLog("Mac responses, second part : %d MACs obtained (should be 63)", num_mac_responses_2);
		size_t datalen = 126 * 16;
		/*
		 * Now, time to dump to file. We'll use this format:
		 * <8-byte CSN><8-byte MAC>....
		 * So, it should wind up as
		 * (63+63) * (8 + 8 ) bytes.
		 **/
		void* macs = malloc(datalen);
		uint8_t i = 0;
		while(i < 63)
		{
			memcpy(macs+i*16, csns1+i*8,8);
			memcpy(macs+i*16+8, resp.d.asBytes+i*8,8);

			memcpy(macs+i*16+63*16, csns2+i*8,8);
			memcpy(macs+i*16+8+63*16, resp2.d.asBytes+i*8,8);
			i++;
		}
		/** Now, save to dumpfile **/
		saveFile("iclass_mac_attack", "bin", macs,datalen);
		free(macs);
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
 * @return
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
