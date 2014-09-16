//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency T55xx commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "proxmark3.h"
#include "ui.h"
#include "graph.h"
#include "cmdmain.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "cmdlft55xx.h"
#include "util.h"
#include "data.h"

#define LF_TRACE_BUFF_SIZE 16000
static int CmdHelp(const char *Cmd);


int CmdReadBlk(const char *Cmd)
{
	//default to invalid block
	int Block = -1;
	UsbCommand c;

	sscanf(Cmd, "%d", &Block);

	if ((Block > 7) | (Block < 0)) {
		PrintAndLog("Block must be between 0 and 7");
		return 1;
	}	

	PrintAndLog(" Reading page 0 block : %d", Block);

	// this command fills up BigBuff
	// 
	c.cmd = CMD_T55XX_READ_BLOCK;
	c.d.asBytes[0] = 0x00;
	c.arg[0] = 0;
	c.arg[1] = Block;
	c.arg[2] = 0;
	SendCommand(&c);
	WaitForResponse(CMD_ACK, NULL);
	
	uint8_t data[LF_TRACE_BUFF_SIZE];
	memset(data, 0x00, LF_TRACE_BUFF_SIZE);
	
	GetFromBigBuf(data,LF_TRACE_BUFF_SIZE,3560);  //3560 -- should be offset..
	WaitForResponseTimeout(CMD_ACK,NULL, 1500);

	for (int j = 0; j < LF_TRACE_BUFF_SIZE; j++) {
		GraphBuffer[j] = ((int)data[j]) - 128;
	}
	GraphTraceLen = LF_TRACE_BUFF_SIZE;
	  
	// BiDirectional
	//CmdDirectionalThreshold("70 60");
	
	// Askdemod
	//Cmdaskdemod("1");
	
	uint8_t bits[1000];
	uint8_t * bitstream = bits;
	memset(bitstream, 0x00, sizeof(bits));
	
	manchester_decode(GraphBuffer, LF_TRACE_BUFF_SIZE, bitstream);
	
  return 0;
}


int CmdReadBlkPWD(const char *Cmd)
{
	int Block = -1; //default to invalid block
	int Password = 0xFFFFFFFF; //default to blank Block 7
	UsbCommand c;

	sscanf(Cmd, "%d %x", &Block, &Password);

	if ((Block > 7) | (Block < 0)) {
		PrintAndLog("Block must be between 0 and 7");
		return 1;
	}	

	PrintAndLog("Reading page 0 block %d pwd %08X", Block, Password);

	c.cmd = CMD_T55XX_READ_BLOCK;
	c.d.asBytes[0] = 0x1; //Password mode
	c.arg[0] = 0;
	c.arg[1] = Block;
	c.arg[2] = Password;
	SendCommand(&c);
	WaitForResponse(CMD_ACK, NULL);
		
	uint8_t data[LF_TRACE_BUFF_SIZE];
	memset(data, 0x00, LF_TRACE_BUFF_SIZE);

	GetFromBigBuf(data,LF_TRACE_BUFF_SIZE,3560);  //3560 -- should be offset..
	WaitForResponseTimeout(CMD_ACK,NULL, 1500);

	for (int j = 0; j < LF_TRACE_BUFF_SIZE; j++) {
		GraphBuffer[j] = ((int)data[j]) - 128;
	}
	GraphTraceLen = LF_TRACE_BUFF_SIZE;

	// BiDirectional
	//CmdDirectionalThreshold("70 -60");	
	
	// Askdemod
	//Cmdaskdemod("1");
		
	uint8_t bits[1000];
	uint8_t * bitstream = bits;
	memset(bitstream, 0x00, sizeof(bits));
	
	manchester_decode(GraphBuffer, LF_TRACE_BUFF_SIZE, bitstream);
  return 0;
}


int CmdWriteBlk(const char *Cmd)
{
  int Block = 8; //default to invalid block
  int Data = 0xFFFFFFFF; //default to blank Block 
  UsbCommand c;

  sscanf(Cmd, "%x %d", &Data, &Block);

  if (Block > 7) {
  	PrintAndLog("Block must be between 0 and 7");
  	return 1;
  }	

  PrintAndLog("Writting block %d with data %08X", Block, Data);

  c.cmd = CMD_T55XX_WRITE_BLOCK;
  c.d.asBytes[0] = 0x0; //Normal mode
  c.arg[0] = Data;
  c.arg[1] = Block;
  c.arg[2] = 0;
  SendCommand(&c);
  return 0;
}

int CmdWriteBlkPWD(const char *Cmd)
{
  int Block = 8; //default to invalid block
  int Data = 0xFFFFFFFF; //default to blank Block 
  int Password = 0xFFFFFFFF; //default to blank Block 7
  UsbCommand c;

  sscanf(Cmd, "%x %d %x", &Data, &Block, &Password);

  if (Block > 7) {
  	PrintAndLog("Block must be between 0 and 7");
  	return 1;
  }	

  PrintAndLog("Writting block %d with data %08X and password %08X", Block, Data, Password);

  c.cmd = CMD_T55XX_WRITE_BLOCK;
  c.d.asBytes[0] = 0x1; //Password mode
  c.arg[0] = Data;
  c.arg[1] = Block;
  c.arg[2] = Password;
  SendCommand(&c);
  return 0;
}

int CmdReadTrace(const char *Cmd)
{
	PrintAndLog(" Reading page 1 - tracedata");

  UsbCommand c = {CMD_T55XX_READ_TRACE, {0, 0, 0}};
  SendCommand(&c);
	WaitForResponse(CMD_ACK, NULL);

	uint8_t data[LF_TRACE_BUFF_SIZE];
	memset(data, 0x00, LF_TRACE_BUFF_SIZE);

	GetFromBigBuf(data,LF_TRACE_BUFF_SIZE,3560);  //3560 -- should be offset..
	WaitForResponseTimeout(CMD_ACK,NULL, 1500);

	for (int j = 0; j < LF_TRACE_BUFF_SIZE; j++) {
		GraphBuffer[j] = ((int)data[j]) - 128;
	}
	GraphTraceLen = LF_TRACE_BUFF_SIZE;
	
	// BiDirectional
	//CmdDirectionalThreshold("70 -60");	
	
	// Askdemod
	//Cmdaskdemod("1");


	uint8_t bits[1000];
	uint8_t * bitstream = bits;
	memset(bitstream, 0x00, sizeof(bits));
	
	manchester_decode(GraphBuffer, LF_TRACE_BUFF_SIZE, bitstream);
		
  return 0;
}

static command_t CommandTable[] =
{
  {"help",   CmdHelp,        1, "This help"},
  {"rd",     CmdReadBlk,     0, "<Block> -- Read T55xx block data (page 0)"},
  {"rdPWD",  CmdReadBlkPWD,  0, "<Block> <Password> -- Read T55xx block data in password mode(page 0)"},
  {"wr",     CmdWriteBlk,    0, "<Data> <Block> -- Write T55xx block data (page 0)"},
  {"wrPWD",  CmdWriteBlkPWD, 0, "<Data> <Block> <Password> -- Write T55xx block data in password mode(page 0)"},
  {"trace",  CmdReadTrace,   0, "Read T55xx traceability data (page 1)"},
  {NULL, NULL, 0, NULL}
};

int CmdLFT55XX(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
