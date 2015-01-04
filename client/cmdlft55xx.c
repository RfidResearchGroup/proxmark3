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


#define LF_TRACE_BUFF_SIZE 20000 // 32 x 32 x 10  (32 bit times numofblock (7), times clock skip..)
#define LF_BITSSTREAM_LEN 1000 // more then 1000 bits shouldn't happend..  8block * 4 bytes * 8bits = 
static int CmdHelp(const char *Cmd);


int CmdReadBlk(const char *Cmd)
{
	int block = -1;
	sscanf(Cmd, "%d", &block);

	if ((block > 7) | (block < 0)) {
		PrintAndLog("Block must be between 0 and 7");
		return 1;
	}	

	UsbCommand c;
	c.cmd = CMD_T55XX_READ_BLOCK;
	c.d.asBytes[0] = 0x00;
	c.arg[0] = 0;
	c.arg[1] = block;
	c.arg[2] = 0;
	SendCommand(&c);
	WaitForResponse(CMD_ACK, NULL);
	
	uint8_t data[LF_TRACE_BUFF_SIZE] = {0x00};
	
	GetFromBigBuf(data,LF_TRACE_BUFF_SIZE,0);  //3560 -- should be offset..
	WaitForResponseTimeout(CMD_ACK,NULL, 1500);

	for (int j = 0; j < LF_TRACE_BUFF_SIZE; j++) {
		GraphBuffer[j] = (int)data[j];
	}
	GraphTraceLen = LF_TRACE_BUFF_SIZE;
	ManchesterDemod(block);
	RepaintGraphWindow();
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
		
	uint8_t data[LF_TRACE_BUFF_SIZE] = {0x00};

	GetFromBigBuf(data,LF_TRACE_BUFF_SIZE,0);  //3560 -- should be offset..
	WaitForResponseTimeout(CMD_ACK,NULL, 1500);

	for (int j = 0; j < LF_TRACE_BUFF_SIZE; j++) {
		GraphBuffer[j] = ((int)data[j]);
	}
	GraphTraceLen = LF_TRACE_BUFF_SIZE;
	ManchesterDemod(Block);	
	RepaintGraphWindow();
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
	char cmdp = param_getchar(Cmd, 0);

	if (strlen(Cmd) > 1 || cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Usage:  lf t55xx trace  [use data from Graphbuffer]");
		PrintAndLog("     [use data from Graphbuffer], if not set, try reading data from tag.");
		PrintAndLog("");
		PrintAndLog("     sample: lf t55xx trace");
		PrintAndLog("     sample: lf t55xx trace 1");
		return 0;
	}

	if ( strlen(Cmd)==0){
		UsbCommand c = {CMD_T55XX_READ_TRACE, {0, 0, 0}};
		SendCommand(&c);
		WaitForResponse(CMD_ACK, NULL);

		uint8_t data[LF_TRACE_BUFF_SIZE] = {0x00};

		GetFromBigBuf(data,LF_TRACE_BUFF_SIZE,0);  //3560 -- should be offset..
		WaitForResponseTimeout(CMD_ACK,NULL, 1500);

		for (int j = 0; j < LF_TRACE_BUFF_SIZE; j++) {
			GraphBuffer[j] = ((int)data[j]);
		}
		GraphTraceLen = LF_TRACE_BUFF_SIZE;
	}
	
	uint8_t bits[LF_BITSSTREAM_LEN] = {0x00};
	uint8_t * bitstream = bits;
	
	manchester_decode(GraphBuffer, LF_TRACE_BUFF_SIZE, bitstream, LF_BITSSTREAM_LEN);
	RepaintGraphWindow();

	uint8_t si = 5;
	uint32_t bl0     = PackBits(si, 32, bitstream);
	uint32_t bl1     = PackBits(si+32, 32, bitstream);
	
	uint32_t acl     = PackBits(si,  8, bitstream); si += 8;
	uint32_t mfc     = PackBits(si, 8, bitstream); si += 8;
	uint32_t cid     = PackBits(si, 5, bitstream); si += 5;
	uint32_t icr     = PackBits(si, 3, bitstream); si += 3;
	uint32_t year    = PackBits(si, 4, bitstream); si += 4;
	uint32_t quarter = PackBits(si, 2, bitstream); si += 2;
	uint32_t lotid    = PackBits(si, 12, bitstream); si += 12;
	uint32_t wafer   = PackBits(si, 5, bitstream); si += 5;
	uint32_t dw      = PackBits(si, 15, bitstream); 
	
	PrintAndLog("");
	PrintAndLog("-- T55xx Trace Information ----------------------------------");
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog(" ACL Allocation class (ISO/IEC 15963-1)  : 0x%02X (%d)", acl, acl);
	PrintAndLog(" MFC Manufacturer ID (ISO/IEC 7816-6)    : 0x%02X (%d)", mfc, mfc);
	PrintAndLog(" CID                                     : 0x%02X (%d)", cid, cid);
	PrintAndLog(" ICR IC Revision                         : %d",icr );
	PrintAndLog(" Manufactured");
	PrintAndLog("     Year/Quarter : %d/%d",2000+year, quarter );
	PrintAndLog("     Lot ID       : %d", lotid );
	PrintAndLog("     Wafer number : %d", wafer);
	PrintAndLog("     Die Number   : %d", dw);
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog(" Raw Data - Page 1");
	PrintAndLog("     Block 0  : 0x%08X  %s", bl0, sprint_bin(bitstream+5,32) );
	PrintAndLog("     Block 0  : 0x%08X  %s", bl1, sprint_bin(bitstream+37,32) );
	PrintAndLog("-------------------------------------------------------------");
	/*
	TRACE - BLOCK O
		Bits	Definition								HEX
		1-8		ACL Allocation class (ISO/IEC 15963-1)	0xE0 
		9-16	MFC Manufacturer ID (ISO/IEC 7816-6)	0x15 Atmel Corporation
		17-21	CID										0x1 = Atmel ATA5577M1  0x2 = Atmel ATA5577M2 
		22-24	ICR IC revision
		25-28	YEAR (BCD encoded) 						9 (= 2009)
		29-30	QUARTER									1,2,3,4 
		31-32	LOT ID
	
	TRACE - BLOCK 1
		1-12	LOT ID  
		13-17	Wafer number
		18-32	DW,  die number sequential
	*/
	
  return 0;
}

int CmdInfo(const char *Cmd){
	/*
		Page 0 Block 0 Configuration data.
		Normal mode
		Extended mode
	*/
	char cmdp = param_getchar(Cmd, 0);

	if (strlen(Cmd) > 1 || cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Usage:  lf t55xx info  [use data from Graphbuffer]");
		PrintAndLog("     [use data from Graphbuffer], if not set, try reading data from tag.");
		PrintAndLog("");
		PrintAndLog("    sample: lf t55xx info");
		PrintAndLog("    sample: lf t55xx info 1");
		return 0;
	}

	if ( strlen(Cmd) == 0 ){
		CmdReadBlk("0");
	}	

	uint8_t bits[LF_BITSSTREAM_LEN] = {0x00};

	manchester_decode(GraphBuffer, LF_TRACE_BUFF_SIZE, bits, LF_BITSSTREAM_LEN);
	
	uint8_t si = 5;
	uint32_t bl0      = PackBits(si, 32, bits);
	
	uint32_t safer    = PackBits(si, 4, bits); si += 4;	
	uint32_t resv     = PackBits(si, 7, bits); si += 7;
	uint32_t dbr      = PackBits(si, 3, bits); si += 3;
	uint32_t extend   = PackBits(si, 1, bits); si += 1;
	uint32_t datamodulation   = PackBits(si, 5, bits); si += 5;
	uint32_t pskcf    = PackBits(si, 2, bits); si += 2;
	uint32_t aor      = PackBits(si, 1, bits); si += 1;	
	uint32_t otp      = PackBits(si, 1, bits); si += 1;	
	uint32_t maxblk   = PackBits(si, 3, bits); si += 3;
	uint32_t pwd      = PackBits(si, 1, bits); si += 1;	
	uint32_t sst      = PackBits(si, 1, bits); si += 1;	
	uint32_t fw       = PackBits(si, 1, bits); si += 1;
	uint32_t inv      = PackBits(si, 1, bits); si += 1;	
	uint32_t por      = PackBits(si, 1, bits); si += 1;
		
	PrintAndLog("");
	PrintAndLog("-- T55xx Configuration --------------------------------------");
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog(" Safer key                 : %s", GetSaferStr(safer));
	PrintAndLog(" reserved                  : %d", resv);
	PrintAndLog(" Data bit rate             : %s", GetBitRateStr(dbr));
	PrintAndLog(" eXtended mode             : %s", (extend) ? "Yes - Warning":"No");
	PrintAndLog(" Modulation                : %s", GetModulationStr(datamodulation) );
	PrintAndLog(" PSK clock freq            : %d", pskcf);
	PrintAndLog(" AOR - Answer on Request   : %s", (aor) ? "Yes":"No");
	PrintAndLog(" OTP - One Time Pad        : %s", (otp) ? "Yes - Warning":"No" );
	PrintAndLog(" Max block                 : %d", maxblk);
	PrintAndLog(" Password mode             : %s", (pwd) ? "Yes":"No");
	PrintAndLog(" Sequence Start Terminator : %s", (sst) ? "Yes":"No");
	PrintAndLog(" Fast Write                : %s", (fw) ? "Yes":"No");
	PrintAndLog(" Inverse data              : %s", (inv) ? "Yes":"No");
	PrintAndLog(" POR-Delay                 : %s", (por) ? "Yes":"No");
	PrintAndLog("-------------------------------------------------------------");
	PrintAndLog(" Raw Data - Page 0");
	PrintAndLog("     Block 0  : 0x%08X  %s", bl0, sprint_bin(bits+5,32) );
	PrintAndLog("-------------------------------------------------------------");
	
	return 0;
}

int CmdDump(const char *Cmd){

	char cmdp = param_getchar(Cmd, 0);
	char s[20];
	uint8_t pwd[4] = {0x00};
	bool hasPwd = ( strlen(Cmd) > 0);
	
	if ( cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Usage:  lf t55xx dump <password>");
		PrintAndLog("        sample: lf t55xx dump FFFFFFFF");
		return 0;
	}
	
	if ( hasPwd ){
		if (param_gethex(Cmd, 0, pwd, 8)) {
			PrintAndLog("password must include 8 HEX symbols");
			return 0;
		}
	}
	
	for ( int i = 0; i <8; ++i){
		memset(s,0,sizeof(s));
		if ( hasPwd ) {
			sprintf(s,"%d %02x%02x%02x%02x", i, pwd[0],pwd[1],pwd[2],pwd[3]);
			CmdReadBlkPWD(s);
		} else {
			sprintf(s,"%d", i);
			CmdReadBlk(s);
		}
	}
	return 0;
}

int CmdIceFsk(const char *Cmd){

	if (!HasGraphData()) return 0;

	iceFsk3(GraphBuffer, LF_TRACE_BUFF_SIZE);
	RepaintGraphWindow();
	return 0;
}
int CmdIceManchester(const char *Cmd){
	ManchesterDemod( -1);
	return 0;
}
int ManchesterDemod(int blockNum){

	if (!HasGraphData()) return 0;
		
	uint8_t sizebyte = 32;
	// the value 5 was selected during empirical studies of the decoded data. Some signal noise to skip.
	uint8_t offset = 5;
	uint32_t blockData;
	uint8_t  bits[LF_BITSSTREAM_LEN] = {0x00};
	uint8_t * bitstream = bits;
	
	//manchester_decode(GraphBuffer, LF_TRACE_BUFF_SIZE, bitstream, LF_BITSSTREAM_LEN);	
	manchester_decode(GraphBuffer, LF_TRACE_BUFF_SIZE, bits, LF_BITSSTREAM_LEN);	
    //blockData = PackBits(offset, sizebyte, bitstream);
	blockData = PackBits(offset, sizebyte, bits);

	if ( blockNum < 0)
		PrintAndLog(" Decoded     : 0x%08X  %s", blockData, sprint_bin(bitstream+offset,sizebyte) );
		else
		PrintAndLog(" Block %d    : 0x%08X  %s", blockNum, blockData, sprint_bin(bitstream+offset,sizebyte) );
	
	return 0;
} 

char * GetBitRateStr(uint32_t id){
 	static char buf[40];
	char *retStr = buf;
		switch (id){
		case 0: 
			sprintf(retStr,"%d - RF/8",id);
			break;
		case 1:
			sprintf(retStr,"%d - RF/16",id);
			break;
		case 2:		
			sprintf(retStr,"%d - RF/32",id);
			break;
		case 3:
			sprintf(retStr,"%d - RF/40",id);
			break;
		case 4:
			sprintf(retStr,"%d - RF/50",id);
			break;
		case 5:
			sprintf(retStr,"%d - RF/64",id);
			break;
		case 6:
			sprintf(retStr,"%d - RF/100",id);
			break;
		case 7:
			sprintf(retStr,"%d - RF/128",id);
			break;
		default:
			sprintf(retStr,"%d - (Unknown)",id);
			break;
		}

	return buf;
}

char * GetSaferStr(uint32_t id){
 	static char buf[40];
	char *retStr = buf;
	
	sprintf(retStr,"%d",id);
	if (id == 6) {
		sprintf(retStr,"%d - pasdwd",id);
	}
	if (id == 9 ){
		sprintf(retStr,"%d - testmode ",id);
	}
	
	return buf;
}
char * GetModulationStr( uint32_t id){
 	static char buf[40];
	char *retStr = buf;
	
	switch (id){
		case 0: 
			sprintf(retStr,"%d - DIRECT (ASK/NRZ)",id);
			break;
		case 1:
			sprintf(retStr,"%d - PSK 1 phase change when input changes",id);
			break;
		case 2:		
			sprintf(retStr,"%d - PSK 2 phase change on bitclk if input high",id);
			break;
		case 3:
			sprintf(retStr,"%d - PSK 3 phase change on rising edge of input",id);
			break;
		case 4:
			sprintf(retStr,"%d - FSK 1 RF/8  RF/5",id);
			break;
		case 5:
			sprintf(retStr,"%d - FSK 2 RF/8  RF/10",id);
			break;
		case 6:
			sprintf(retStr,"%d - FSK 1a RF/5  RF/8",id);
			break;
		case 7:
			sprintf(retStr,"%d - FSK 2a RF/10  RF/8",id);
			break;
		case 8:
			sprintf(retStr,"%d - Manschester",id);
			break;
		case 16:
			sprintf(retStr,"%d - Biphase",id);
			break;
		case 17:
			sprintf(retStr,"%d - Reserved",id);
			break;
		default:
			sprintf(retStr,"0x%02X (Unknown)",id);
			break;
		}
	return buf;
}


uint32_t PackBits(uint8_t start, uint8_t len, uint8_t* bits){
	
	int i = start;
	int j = len-1;
	if (len > 32) {
		return 0;
	}
 	uint32_t tmp = 0;
	for (; j >= 0; --j, ++i){
		tmp	|= bits[i] << j;
	}
	return tmp;
}

static command_t CommandTable[] =
{
  {"help",   CmdHelp,        1, "This help"},
  {"rd",     CmdReadBlk,     0, "<block> -- Read T55xx block data (page 0)"},
  {"rdpwd",  CmdReadBlkPWD,  0, "<block> <password> -- Read T55xx block data with password mode"},
  {"wr",     CmdWriteBlk,    0, "<data> <block> -- Write T55xx block data (page 0)"},
  {"wrpwd",  CmdWriteBlkPWD, 0, "<data> <block> <password> -- Write T55xx block data with password"},
  {"trace",  CmdReadTrace,   0, "[1] Read T55xx traceability data (page 1/ blk 0-1)"},
  {"info",   CmdInfo,        0, "[1] Read T55xx configuration data (page 0/ blk 0)"},
  {"dump",   CmdDump,        0, "[password] Dump T55xx card block 0-7. optional with password"},
  {"fsk",    CmdIceFsk,      0, "FSK demod"},
  {"man",    CmdIceManchester,      0, "Manchester demod (with SST)"},
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
